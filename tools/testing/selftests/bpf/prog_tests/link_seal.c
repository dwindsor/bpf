// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include <test_progs.h>
#include "test_link_seal.skel.h"

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
	return err ?: (int)opts.retval;
}

void test_link_seal(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, sealed_opts, .flags = BPF_F_SEALED);
	struct test_link_seal *skel;
	int prog_fd, alt_fd, link_fd, new_fd, err, i;
	struct bpf_link_info info = {};
	__u32 len = sizeof(info), id;

	skel = test_link_seal__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.dump_task);
	alt_fd = bpf_program__fd(skel->progs.dump_task_alt);

	/* control: an unsealed iter link can be updated */
	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, NULL);
	if (!ASSERT_GE(link_fd, 0, "create_unsealed"))
		goto out;
	err = bpf_link_update(link_fd, alt_fd, NULL);
	ASSERT_OK(err, "update_unsealed");
	close(link_fd);

	/* a sealed link rejects BPF_LINK_UPDATE and BPF_LINK_DETACH */
	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, &sealed_opts);
	if (!ASSERT_GE(link_fd, 0, "create_sealed"))
		goto out;
	err = bpf_link_update(link_fd, alt_fd, NULL);
	ASSERT_EQ(err, -EPERM, "update_sealed");
	err = bpf_link_detach(link_fd);
	ASSERT_EQ(err, -EPERM, "detach_sealed");

	err = bpf_link_get_info_by_fd(link_fd, &info, &len);
	if (!ASSERT_OK(err, "get_info"))
		goto out;
	id = info.id;

	/* a sealed link survives closing its last fd */
	close(link_fd);
	new_fd = bpf_link_get_fd_by_id(id);
	if (!ASSERT_GE(new_fd, 0, "alive_after_close"))
		goto out;
	err = bpf_link_detach(new_fd);
	ASSERT_EQ(err, -EPERM, "detach_after_close");

	/* test-only cleanup: drop the sealing self-reference via bpf_testmod,
	 * then verify the link goes away with its last fd
	 */
	err = force_unseal(skel, new_fd);
	if (!ASSERT_OK(err, "force_unseal"))
		goto out;
	close(new_fd);
	/* link freeing is deferred, poll for the id to disappear */
	for (i = 0; i < 100; i++) {
		new_fd = bpf_link_get_fd_by_id(id);
		if (new_fd < 0)
			break;
		close(new_fd);
		usleep(10000);
	}
	ASSERT_EQ(new_fd, -ENOENT, "gone_after_unseal");
out:
	test_link_seal__destroy(skel);
}
