// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cisco Systems, Inc. */

#include <linux/bpf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xattr.h>

static int bpf_xattrs_used(const struct lsm_xattrs *ctx)
{
	const size_t prefix_len = sizeof(XATTR_BPF_LSM_SUFFIX) - 1;
	unsigned int i, n = 0;

	for (i = 0; i < ctx->xattr_count; i++) {
		const char *name = ctx->xattrs[i].name;

		if (name && !strncmp(name, XATTR_BPF_LSM_SUFFIX, prefix_len))
			n++;
	}
	return n;
}

__bpf_kfunc_start_defs();

/**
 * bpf_init_inode_xattr - set an xattr on a new inode from inode_init_security
 * @xattrs: inode_init_security xattr state from the hook context
 * @name__str: xattr name (e.g., "bpf.file_label")
 * @value_p: dynptr containing the xattr value
 *
 * Only callable from lsm/inode_init_security programs; the verifier enforces
 * this because no other hook exposes a struct lsm_xattrs argument.
 *
 * Return: 0 on success, negative error on failure.
 */
__bpf_kfunc int bpf_init_inode_xattr(struct lsm_xattrs *xattrs,
				     const char *name__str,
				     const struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	size_t name_len;
	void *xattr_value;
	struct xattr *xattr;
	const void *value;
	u32 value_len;

	if (!xattrs || !xattrs->xattrs || !name__str)
		return -EINVAL;
	if (bpf_xattrs_used(xattrs) >= BPF_LSM_INODE_INIT_XATTRS)
		return -ENOSPC;

	name_len = strlen(name__str);
	if (name_len == 0 || name_len > XATTR_NAME_MAX)
		return -EINVAL;
	if (strncmp(name__str, XATTR_BPF_LSM_SUFFIX,
		    sizeof(XATTR_BPF_LSM_SUFFIX) - 1))
		return -EPERM;

	value_len = __bpf_dynptr_size(value_ptr);
	if (value_len == 0 || value_len > XATTR_SIZE_MAX)
		return -EINVAL;

	value = __bpf_dynptr_data(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	/*
	 * Combine xattr value + name into one allocation. Use GFP_NOFS to
	 * match security_inode_init_security(): this runs during inode
	 * creation, so reclaim must not recurse back into the filesystem.
	 */
	xattr_value = kmalloc(value_len + name_len + 1, GFP_NOFS);
	if (!xattr_value)
		return -ENOMEM;

	memcpy(xattr_value, value, value_len);
	memcpy(xattr_value + value_len, name__str, name_len);
	((char *)xattr_value)[value_len + name_len] = '\0';

	xattr = lsm_get_xattr_slot(xattrs);
	if (!xattr) {
		kfree(xattr_value);
		return -ENOSPC;
	}

	xattr->value = xattr_value;
	xattr->name = (const char *)xattr_value + value_len;
	xattr->value_len = value_len;

	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_lsm_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_init_inode_xattr, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_lsm_kfunc_set_ids)

static const struct btf_kfunc_id_set bpf_lsm_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_lsm_kfunc_set_ids,
};

static int __init bpf_lsm_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_lsm_kfunc_set);
}

late_initcall(bpf_lsm_kfuncs_init);
