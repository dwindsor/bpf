// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	return 0;
}

SEC("iter/task")
int dump_task_alt(struct bpf_iter__task *ctx)
{
	return 0;
}

struct unseal_args {
	int link_fd;
};

/* Test-only cleanup: unseal a sealed link via the bpf_testmod kfunc. */
SEC("syscall")
int unseal_link(struct unseal_args *ctx)
{
	return bpf_kfunc_link_force_unseal(ctx->link_fd);
}
