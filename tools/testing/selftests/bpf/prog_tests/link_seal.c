// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include <test_progs.h>
#include "test_link_seal.skel.h"

static int link_id(int link_fd)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);

	if (bpf_link_get_info_by_fd(link_fd, &info, &len))
		return -1;
	return info.id;
}

/* links are freed from a workqueue, so poll for the ID to disappear */
static bool link_gone(__u32 id)
{
	int i, fd = -1;

	for (i = 0; i < 100; i++) {
		fd = bpf_link_get_fd_by_id(id);
		if (fd < 0)
			break;
		close(fd);
		usleep(10000);
	}
	return fd == -ENOENT;
}

/* Drop the self-reference held by a sealed link through a bpf_testmod kfunc
 * so the test does not leak a link until reboot on every run.
 */
static int force_unseal(struct test_link_seal *skel, int link_fd)
{
	struct { int link_fd; } args = { .link_fd = link_fd };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.unseal_link),
				     &opts);
	return err ?: opts.retval;
}

/* An unsealed link is torn down when its last fd is closed. */
static void test_unsealed_link(struct test_link_seal *skel)
{
	int link_fd;
	__u32 id;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.fentry_prog), 0,
				  BPF_TRACE_FENTRY, NULL);
	if (!ASSERT_GE(link_fd, 0, "create"))
		return;
	id = link_id(link_fd);
	close(link_fd);
	ASSERT_TRUE(link_gone(id), "freed_after_close");
}

/* A sealed link rejects update and detach, and survives its last fd. */
static void test_sealed_link(struct test_link_seal *skel)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_LINK_SEALED);
	int link_fd, err;
	__u32 id;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.fentry_prog), 0,
				  BPF_TRACE_FENTRY, &opts);
	if (!ASSERT_GE(link_fd, 0, "create_sealed"))
		return;

	err = bpf_link_update(link_fd, bpf_program__fd(skel->progs.fentry_prog),
			      NULL);
	ASSERT_EQ(err, -EPERM, "update_rejected");
	err = bpf_link_detach(link_fd);
	ASSERT_EQ(err, -EPERM, "detach_rejected");

	id = link_id(link_fd);
	close(link_fd);

	/* closing the last fd must not tear the link down */
	link_fd = bpf_link_get_fd_by_id(id);
	if (!ASSERT_GE(link_fd, 0, "alive_after_close"))
		return;
	err = bpf_link_detach(link_fd);
	ASSERT_EQ(err, -EPERM, "detach_rejected_after_close");

	if (ASSERT_OK(force_unseal(skel, link_fd), "force_unseal")) {
		close(link_fd);
		ASSERT_TRUE(link_gone(id), "freed_after_unseal");
	} else {
		close(link_fd);
	}
}

/* Link types that do not honor BPF_F_LINK_SEALED must reject it instead of
 * silently handing back an unsealed link.
 */
static void test_seal_unsupported(struct test_link_seal *skel)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_LINK_SEALED);
	int link_fd;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.raw_tp_prog), 0,
				  BPF_TRACE_RAW_TP, &opts);
	if (!ASSERT_EQ(link_fd, -EOPNOTSUPP, "raw_tp_seal_rejected"))
		close(link_fd);
}

void test_link_seal(void)
{
	struct test_link_seal *skel;

	skel = test_link_seal__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (test__start_subtest("unsealed"))
		test_unsealed_link(skel);
	if (test__start_subtest("sealed"))
		test_sealed_link(skel);
	if (test__start_subtest("unsupported"))
		test_seal_unsupported(skel);

	test_link_seal__destroy(skel);
}
