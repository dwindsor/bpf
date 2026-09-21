// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define BPF_FS_MAGIC 0xcafe4a11

char _license[] SEC("license") = "GPL";

/* The link under protection and the one process allowed to detach it. */
__u32 guarded_link_id;
__u32 trusted_tgid;

/* How often each hook was consulted for the guarded link (or for bpffs). */
__u64 detach_hook_calls;
__u64 free_hook_calls;
__u64 umount_hook_calls;
__u64 unlink_hook_calls;

/* The "security policy" whose link is being protected. */
SEC("lsm/file_open")
int BPF_PROG(policy, struct file *file)
{
	return 0;
}

/* Only the trusted loader may detach the guarded link. */
SEC("lsm/bpf_link_detach")
int BPF_PROG(guard_detach, struct bpf_link *link)
{
	if (link->id != guarded_link_id)
		return 0;

	__sync_fetch_and_add(&detach_hook_calls, 1);
	if ((bpf_get_current_pid_tgid() >> 32) == trusted_tgid)
		return 0;
	return -EPERM;
}

/* Observe the guarded link being torn down. This hook is void: it cannot
 * stop the teardown, only witness it.
 */
SEC("lsm/bpf_link_free")
int BPF_PROG(observe_free, struct bpf_link *link)
{
	if (link->id == guarded_link_id)
		__sync_fetch_and_add(&free_hook_calls, 1);
	return 0;
}

/* The "protected pin" alternative: instead of a kernel-owned reference, a
 * bpffs pin holds the link and policy forbids removing the pin. Set to the
 * pin's inode number to arm it; also arms the bpffs umount denial.
 */
__u64 protected_pin_ino;
__u64 pin_denials;

/* The init mount namespace has a fixed nsfs inode number (uapi nsfs.h). */
#define MNT_NS_INIT_INO 0xEFFFFFF8U

static bool in_init_mntns(void)
{
	struct task_struct *cur = bpf_get_current_task_btf();

	return cur->nsproxy->mnt_ns->ns.inum == MNT_NS_INIT_INO;
}

static bool is_protected_pin(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	return protected_pin_ino && inode &&
	       inode->i_sb->s_magic == BPF_FS_MAGIC &&
	       inode->i_ino == protected_pin_ino;
}

/* The three VFS requests that could drop a bpffs pin from user space. Each
 * is counted for bpffs and, once armed, denied for the protected pin.
 */
SEC("lsm/sb_umount")
int BPF_PROG(guard_umount, struct vfsmount *mnt, int flags)
{
	if (mnt->mnt_sb->s_magic != BPF_FS_MAGIC)
		return 0;
	__sync_fetch_and_add(&umount_hook_calls, 1);

	/* Denying every bpffs umount would break container runtimes, which
	 * unmount their copy of the host mount tree after pivot_root(); only
	 * the init mount namespace holds the pin that matters.
	 */
	if (!protected_pin_ino || !in_init_mntns())
		return 0;
	__sync_fetch_and_add(&pin_denials, 1);
	return -EPERM;
}

SEC("lsm/inode_unlink")
int BPF_PROG(guard_unlink, struct inode *dir, struct dentry *dentry)
{
	if (dir->i_sb->s_magic != BPF_FS_MAGIC)
		return 0;
	__sync_fetch_and_add(&unlink_hook_calls, 1);

	if (!is_protected_pin(dentry))
		return 0;
	__sync_fetch_and_add(&pin_denials, 1);
	return -EPERM;
}

SEC("lsm/inode_rename")
int BPF_PROG(guard_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	/* moving the pin away, or renaming something over it */
	if (!is_protected_pin(old_dentry) && !is_protected_pin(new_dentry))
		return 0;
	__sync_fetch_and_add(&pin_denials, 1);
	return -EPERM;
}
