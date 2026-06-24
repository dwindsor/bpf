// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cisco Systems, Inc. */

#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <test_progs.h>
#include "test_init_inode_xattr.skel.h"

static void test_init_inode_xattr(void)
{
	struct test_init_inode_xattr *skel = NULL;
	int fd = -1, err;
	char value_out[64];
	const char *testfile_new = "/tmp/test_progs_lsm_kfuncs_new";

	skel = test_init_inode_xattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_init_inode_xattr__open_and_load"))
		return;

	skel->bss->monitored_pid = getpid();
	err = test_init_inode_xattr__attach(skel);
	if (!ASSERT_OK(err, "test_init_inode_xattr__attach"))
		goto out;

	/* Trigger inode_init_security */
	fd = open(testfile_new, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		goto out;

	ASSERT_EQ(skel->data->init_result, 0, "init_result");

	/* initxattrs prepends "security." to the name. */
	err = getxattr(testfile_new, "security.bpf.test_label", value_out,
		       sizeof(value_out));
	if (err < 0 && errno == ENODATA) {
		printf("%s:SKIP:filesystem did not apply LSM xattrs\n",
		       __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_GE(err, 0, "getxattr"))
		goto out;

	ASSERT_EQ(err, (int)sizeof(skel->data->xattr_value), "xattr_size");
	ASSERT_EQ(strncmp(value_out, "unconfined_u:object_r:user_home_t:s0",
			  sizeof("unconfined_u:object_r:user_home_t:s0")), 0,
		  "xattr_value");

out:
	close(fd);
	test_init_inode_xattr__destroy(skel);
	remove(testfile_new);
}

/* Keep in sync with BPF_LSM_INODE_INIT_XATTRS in include/linux/bpf_lsm.h. */
#define INIT_INODE_XATTR_MAX 4

/*
 * Programs may attach to inode_init_security without an attach-time limit, but
 * the kfunc only lets BPF claim INIT_INODE_XATTR_MAX xattr slots per inode.
 * Calls beyond that budget are rejected at runtime with -ENOSPC.
 */
static void test_init_inode_xattr_slot_limit(void)
{
	struct test_init_inode_xattr *skel[INIT_INODE_XATTR_MAX + 1] = {};
	struct bpf_link *link[INIT_INODE_XATTR_MAX + 1] = {};
	const char *testfile = "/tmp/test_progs_lsm_kfuncs_slot";
	int ok = 0, nospc = 0, other = 0;
	int i, fd = -1;

	/* All programs attach successfully; there is no attach-time cap. */
	for (i = 0; i <= INIT_INODE_XATTR_MAX; i++) {
		skel[i] = test_init_inode_xattr__open_and_load();
		if (!ASSERT_OK_PTR(skel[i], "open_and_load"))
			goto out;

		skel[i]->bss->monitored_pid = getpid();

		link[i] = bpf_program__attach_lsm(skel[i]->progs.test_init_inode_xattr);
		if (!ASSERT_OK_PTR(link[i], "attach"))
			goto out;
	}

	/* Trigger inode_init_security once with all programs attached. */
	fd = open(testfile, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		goto out;

	/*
	 * Exactly INIT_INODE_XATTR_MAX programs claim a slot; the program past
	 * the budget gets -ENOSPC. The order in which programs run is not
	 * guaranteed, so count results instead of indexing.
	 */
	for (i = 0; i <= INIT_INODE_XATTR_MAX; i++) {
		int res = skel[i]->data->init_result;

		if (res == 0)
			ok++;
		else if (res == -ENOSPC)
			nospc++;
		else
			other++;
	}

	ASSERT_EQ(ok, INIT_INODE_XATTR_MAX, "slots_within_budget");
	ASSERT_EQ(nospc, 1, "slot_over_budget");
	ASSERT_EQ(other, 0, "unexpected_result");

out:
	if (fd >= 0)
		close(fd);
	for (i = 0; i <= INIT_INODE_XATTR_MAX; i++) {
		bpf_link__destroy(link[i]);
		test_init_inode_xattr__destroy(skel[i]);
	}
	remove(testfile);
}

void test_lsm_kfuncs(void)
{
	if (test__start_subtest("init_inode_xattr"))
		test_init_inode_xattr();

	if (test__start_subtest("init_inode_xattr_slot_limit"))
		test_init_inode_xattr_slot_limit();
}
