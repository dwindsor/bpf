// SPDX-License-Identifier: GPL-2.0
/*
 * BPF mmap placement policy (struct_ops) selftest program.
 *
 * For a single tagged test process it routes writable/data mappings
 * (VM_WRITE) into a dedicated DATA arena and executable mappings (VM_EXEC)
 * into a disjoint EXEC arena, adding per-mapping ASLR entropy and a fixed
 * guard gap between mappings.  A trigger flag makes it return a deliberately
 * invalid address so the kernel re-validation / safe-fallback path can be
 * exercised.  All other processes get the untouched baseline.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif

/* vm_flags bits (uapi-stable kernel internal values) */
#define VM_WRITE 0x00000002
#define VM_EXEC  0x00000004

/* Distinct arenas, far apart, well below TASK_SIZE (~128 TiB on x86_64)
 * and above where libraries / heap / program text normally land.
 * Exposed as rodata so the userspace test reads the exact values.
 */
const volatile __u64 data_arena_base = 0x100000000000ULL; /* 16 TiB */
const volatile __u64 exec_arena_base = 0x200000000000ULL; /* 32 TiB */

/* Fixed guard gap placed after every policy-directed mapping. */
#define GUARD_GAP (64UL * PAGE_SIZE)	/* 256 KiB */

/* Set by userspace to its own tgid; 0 disables the policy for everyone. */
__u32 target_tgid;

/* When set, return a deliberately invalid address to exercise fallback. */
bool trigger_fallback;

/* Running bump offsets within each arena (advance monotonically). */
__u64 data_bump;
__u64 exec_bump;

/* Observability: last chosen addresses (read back by the test / logged). */
__u64 last_data_addr;
__u64 last_exec_addr;
__u64 nr_data_maps;
__u64 nr_exec_maps;

SEC("struct_ops/get_unmapped_area")
unsigned long BPF_PROG(mmap_policy_place, struct mmap_policy_args *args)
{
	unsigned long len = args->len;
	unsigned long vm_flags = args->vm_flags;
	__u64 base, slot, addr, rnd;
	__u64 *bump;

	/* Only act for the tagged test process; everyone else gets baseline. */
	if (!target_tgid || (bpf_get_current_pid_tgid() >> 32) != target_tgid)
		return 0;

	/* Exercise the kernel re-validation / safe-fallback path. */
	if (trigger_fallback)
		return 0xdead1; /* misaligned + garbage -> kernel falls back */

	if (vm_flags & VM_EXEC) {
		base = exec_arena_base;
		bump = &exec_bump;
	} else if (vm_flags & VM_WRITE) {
		base = data_arena_base;
		bump = &data_bump;
	} else {
		/* Neither clearly exec nor data: accept the baseline. */
		return 0;
	}

	/* Per-mapping entropy: a random 0..15 page leading gap. */
	rnd = bpf_get_prandom_u32() & 0xf;

	slot = *bump + (rnd << PAGE_SHIFT);
	addr = base + slot;

	/* Advance past this mapping plus a fixed guard gap. */
	*bump = slot + len + GUARD_GAP;

	if (vm_flags & VM_EXEC) {
		last_exec_addr = addr;
		nr_exec_maps++;
	} else {
		last_data_addr = addr;
		nr_data_maps++;
	}

	return addr;
}

SEC(".struct_ops.link")
struct mmap_policy_ops test_policy = {
	.get_unmapped_area = (void *)mmap_policy_place,
};
