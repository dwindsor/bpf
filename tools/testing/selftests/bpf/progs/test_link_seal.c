// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(fentry_prog, int a)
{
	return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(raw_tp_prog, struct pt_regs *regs, long id)
{
	return 0;
}

struct unseal_args {
	int link_fd;
};

SEC("syscall")
int unseal_link(struct unseal_args *ctx)
{
	return bpf_kfunc_link_force_unseal(ctx->link_fd);
}
