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

/* The two VFS paths that could drop a bpffs pin from user space. */
SEC("lsm/sb_umount")
int BPF_PROG(observe_umount, struct vfsmount *mnt, int flags)
{
	if (mnt->mnt_sb->s_magic == BPF_FS_MAGIC)
		__sync_fetch_and_add(&umount_hook_calls, 1);
	return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(observe_unlink, struct inode *dir, struct dentry *dentry)
{
	if (dir->i_sb->s_magic == BPF_FS_MAGIC)
		__sync_fetch_and_add(&unlink_hook_calls, 1);
	return 0;
}
