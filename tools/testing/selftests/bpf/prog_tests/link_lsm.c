// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#define _GNU_SOURCE
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <test_progs.h>
#include "test_link_lsm.skel.h"

/* A BPF LSM policy protects the link of another BPF LSM program: only one
 * trusted process may BPF_LINK_DETACH it. These tests check that the
 * bpf_link_detach hook enforces that, and then show which teardown paths
 * the hook does not see at all.
 */

static int link_id(int link_fd)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);

	if (bpf_link_get_info_by_fd(link_fd, &info, &len))
		return -1;
	return info.id;
}

static bool link_alive(__u32 id)
{
	int fd = bpf_link_get_fd_by_id(id);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

/* Links are torn down asynchronously, so poll for the ID to disappear. */
static bool wait_link_gone(__u32 id)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (!link_alive(id))
			return true;
		usleep(10000);
	}
	return false;
}

static bool wait_counter(__u64 *ctr, __u64 want)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (*ctr == want)
			return true;
		usleep(10000);
	}
	return *ctr == want;
}

static int policy_link_create(struct test_link_lsm *skel)
{
	return bpf_link_create(bpf_program__fd(skel->progs.policy), 0,
			       BPF_LSM_MAC, NULL);
}

/* Detach the guarded link from a process that is not the trusted loader. */
static int detach_from_untrusted(__u32 id)
{
	int fd, err;

	fd = bpf_link_get_fd_by_id(id);
	if (fd < 0)
		return fd;
	err = bpf_link_detach(fd);
	close(fd);
	return err;
}

/* The hook works: an untrusted process is denied, the trusted loader is
 * allowed, and after detach the program is really unlinked.
 */
static void test_detach_mediated(struct test_link_lsm *skel)
{
	int link_fd, fd2, err, status;
	pid_t pid;
	__u32 id;

	skel->bss->trusted_tgid = getpid();

	link_fd = policy_link_create(skel);
	if (!ASSERT_GE(link_fd, 0, "create"))
		return;
	id = link_id(link_fd);
	skel->bss->guarded_link_id = id;

	/* the program is linked, so attaching it again must fail */
	fd2 = policy_link_create(skel);
	ASSERT_EQ(fd2, -EBUSY, "reattach_while_linked");

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (pid == 0)
		_exit(detach_from_untrusted(id) == -EPERM ? 0 : 1);
	waitpid(pid, &status, 0);
	ASSERT_EQ(WEXITSTATUS(status), 0, "untrusted_detach_denied");
	ASSERT_EQ(skel->bss->detach_hook_calls, 1, "hook_seen_untrusted");

	err = bpf_link_detach(link_fd);
	ASSERT_OK(err, "trusted_detach");
	ASSERT_EQ(skel->bss->detach_hook_calls, 2, "hook_seen_trusted");
	/* the link object survives a detach, defunct */
	ASSERT_TRUE(link_alive(id), "link_alive_after_detach");

	/* the program is no longer linked, so it can be attached again */
	fd2 = policy_link_create(skel);
	if (ASSERT_GE(fd2, 0, "reattach_after_detach"))
		close(fd2);
out:
	skel->bss->guarded_link_id = 0;
	close(link_fd);
}

/* Fork a "trusted loader" that creates the guarded link and reports its
 * ID, then blocks until killed or told to exit. With @bpffs_dir set it
 * first mounts bpffs there in a private mount namespace, pins the link and
 * closes its fd, so the pin is the only reference.
 */
struct loader {
	pid_t pid;
	int to_child;
	int from_child;
	__u32 id;
};

static void loader_child(struct test_link_lsm *skel, int rd, int wr,
			 const char *bpffs_dir)
{
	char path[PATH_MAX];
	int link_fd;
	char go;
	__u32 id;

	if (read(rd, &go, 1) != 1)
		_exit(10);

	if (bpffs_dir) {
		if (unshare(CLONE_NEWNS))
			_exit(11);
		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
			_exit(12);
		if (mount("bpffs", bpffs_dir, "bpf", 0, NULL))
			_exit(13);
	}

	link_fd = policy_link_create(skel);
	if (link_fd < 0)
		_exit(14);
	id = link_id(link_fd);

	if (bpffs_dir) {
		snprintf(path, sizeof(path), "%s/policy", bpffs_dir);
		if (bpf_obj_pin(link_fd, path))
			_exit(15);
		/* the pin is now the only reference */
		close(link_fd);
	}

	if (write(wr, &id, sizeof(id)) != sizeof(id))
		_exit(16);

	/* wait to be killed, or told to exit cleanly */
	if (read(rd, &go, 1) != 1)
		_exit(17);
	_exit(0);
}

static int loader_start(struct test_link_lsm *skel, struct loader *ld,
			const char *bpffs_dir)
{
	int to_child[2], from_child[2];
	char go = 'g';

	if (pipe(to_child) || pipe(from_child))
		return -errno;

	ld->pid = fork();
	if (ld->pid < 0)
		return -errno;
	if (ld->pid == 0) {
		close(to_child[1]);
		close(from_child[0]);
		loader_child(skel, to_child[0], from_child[1], bpffs_dir);
	}
	close(to_child[0]);
	close(from_child[1]);
	ld->to_child = to_child[1];
	ld->from_child = from_child[0];

	/* the child is the only process allowed to detach the link */
	skel->bss->trusted_tgid = ld->pid;
	if (write(ld->to_child, &go, 1) != 1)
		return -errno;
	if (read(ld->from_child, &ld->id, sizeof(ld->id)) != sizeof(ld->id))
		return -EIO;
	skel->bss->guarded_link_id = ld->id;
	return 0;
}

static void loader_end(struct loader *ld, bool kill_it)
{
	char go = 'x';
	int status;

	if (kill_it)
		kill(ld->pid, SIGKILL);
	else if (write(ld->to_child, &go, 1) != 1)
		kill(ld->pid, SIGKILL);
	waitpid(ld->pid, &status, 0);
	close(ld->to_child);
	close(ld->from_child);
}

/* Check the policy is in force right now: the link exists and we, not
 * being the trusted loader, cannot detach it.
 */
static void check_guarded(struct test_link_lsm *skel, __u32 id)
{
	ASSERT_TRUE(link_alive(id), "link_alive");
	ASSERT_EQ(detach_from_untrusted(id), -EPERM, "our_detach_denied");
	ASSERT_EQ(skel->bss->detach_hook_calls, 1, "hook_seen_our_detach");
	ASSERT_EQ(skel->bss->free_hook_calls, 0, "not_freed_yet");
}

/* SIGKILL the trusted loader. Nothing asked to detach the link, so the
 * detach hook is never consulted, yet the link is torn down when the
 * loader's fd table is destroyed.
 */
static void test_loader_killed(struct test_link_lsm *skel)
{
	struct loader ld;

	if (!ASSERT_OK(loader_start(skel, &ld, NULL), "loader_start"))
		return;
	check_guarded(skel, ld.id);

	loader_end(&ld, true);

	ASSERT_TRUE(wait_link_gone(ld.id), "link_gone_after_kill");
	ASSERT_TRUE(wait_counter(&skel->bss->free_hook_calls, 1),
		    "free_hook_saw_teardown");
	ASSERT_EQ(skel->bss->detach_hook_calls, 1, "detach_hook_not_consulted");
	skel->bss->guarded_link_id = 0;
}

/* Pin the link in bpffs instead of relying on an fd, in a mount namespace
 * that dies with the loader. The loader exits cleanly. Neither umount nor
 * unlink is requested, so neither the sb_umount nor the inode_unlink hook
 * fires, and the detach hook is not consulted, yet the pin goes away with
 * the namespace and takes the link with it.
 */
static void test_pinned_in_dying_mntns(struct test_link_lsm *skel)
{
	char dir[] = "/tmp/link_lsm_XXXXXX";
	struct loader ld;

	if (!ASSERT_OK_PTR(mkdtemp(dir), "mkdtemp"))
		return;
	if (!ASSERT_OK(loader_start(skel, &ld, dir), "loader_start"))
		goto out;
	check_guarded(skel, ld.id);

	loader_end(&ld, false);

	ASSERT_TRUE(wait_link_gone(ld.id), "link_gone_after_mntns_exit");
	ASSERT_TRUE(wait_counter(&skel->bss->free_hook_calls, 1),
		    "free_hook_saw_teardown");
	ASSERT_EQ(skel->bss->detach_hook_calls, 1, "detach_hook_not_consulted");
	ASSERT_EQ(skel->bss->umount_hook_calls, 0, "umount_hook_not_consulted");
	ASSERT_EQ(skel->bss->unlink_hook_calls, 0, "unlink_hook_not_consulted");
	skel->bss->guarded_link_id = 0;
out:
	rmdir(dir);
}

static void reset_counters(struct test_link_lsm *skel)
{
	skel->bss->guarded_link_id = 0;
	skel->bss->trusted_tgid = 0;
	skel->bss->detach_hook_calls = 0;
	skel->bss->free_hook_calls = 0;
	skel->bss->umount_hook_calls = 0;
	skel->bss->unlink_hook_calls = 0;
}

void test_link_lsm(void)
{
	struct test_link_lsm *skel;

	skel = test_link_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	/* the policy link is created by hand in each subtest */
	bpf_program__set_autoattach(skel->progs.policy, false);
	if (!ASSERT_OK(test_link_lsm__load(skel), "load"))
		goto out;
	if (!ASSERT_OK(test_link_lsm__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("detach_mediated")) {
		reset_counters(skel);
		test_detach_mediated(skel);
	}
	if (test__start_subtest("loader_killed")) {
		reset_counters(skel);
		test_loader_killed(skel);
	}
	if (test__start_subtest("pinned_in_dying_mntns")) {
		reset_counters(skel);
		test_pinned_in_dying_mntns(skel);
	}
out:
	test_link_lsm__destroy(skel);
}
