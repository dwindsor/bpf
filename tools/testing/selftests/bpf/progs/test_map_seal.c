// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

struct lock_value {
	struct bpf_spin_lock lock;
	int data;
};

/* A map with a spin lock in its value is not freezable, and so must not be
 * sealable either. Declared here so the test can reuse its BTF ids.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct lock_value);
} lock_map SEC(".maps");

struct unseal_args {
	int map_fd;
};

/* Test only: drop the self-reference a sealed map holds so the test can
 * release the map instead of pinning it until the VM reboots.
 */
SEC("syscall")
int unseal_map(struct unseal_args *ctx)
{
	return bpf_kfunc_map_force_unseal(ctx->map_fd);
}
