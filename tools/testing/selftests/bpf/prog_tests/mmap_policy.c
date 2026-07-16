// SPDX-License-Identifier: GPL-2.0
/*
 * Selftest for the BPF mmap placement policy (mmap_policy_ops struct_ops).
 *
 * Attaches a struct_ops policy that routes the tagged test process's data
 * (VM_WRITE) mappings into one arena and exec (VM_EXEC) mappings into a
 * disjoint arena, with a guard gap and per-mapping entropy.  Verifies the
 * placement took effect, that the safe-fallback path works for a bad policy
 * return, that MAP_FIXED is left untouched, and that detaching restores the
 * default arch layout.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <test_progs.h>
#include "mmap_policy.skel.h"

#define MAP_LEN		(64 * 1024)		/* 64 KiB */
#define NR_MAPS		8
#define PAGE_SZ		4096UL
#define GUARD_GAP	(64UL * PAGE_SZ)	/* must match the BPF prog */
#define ARENA_WINDOW	(1UL << 30)		/* 1 GiB range for checks */

static bool in_range(unsigned long a, unsigned long base, unsigned long window)
{
	return a >= base && a < base + window;
}

static void *do_map(int prot)
{
	void *p = mmap(NULL, MAP_LEN, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	return p == MAP_FAILED ? NULL : p;
}

void test_mmap_policy(void)
{
	unsigned long data_base, exec_base;
	unsigned long data[NR_MAPS], exec[NR_MAPS];
	struct mmap_policy *skel;
	struct bpf_link *link;
	bool entropy_seen;
	void *p;
	int i;

	skel = mmap_policy__open_and_load();
	if (!ASSERT_OK_PTR(skel, "mmap_policy__open_and_load"))
		return;

	data_base = skel->rodata->data_arena_base;
	exec_base = skel->rodata->exec_arena_base;

	/* Tag this process so only our mappings are affected. */
	skel->bss->target_tgid = getpid();

	link = bpf_map__attach_struct_ops(skel->maps.test_policy);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto out_skel;

	/* --- Phase 1: data (VM_WRITE) mappings land in the data arena --- */
	for (i = 0; i < NR_MAPS; i++) {
		p = do_map(PROT_READ | PROT_WRITE);
		if (!ASSERT_OK_PTR(p, "data mmap"))
			goto out_link;
		data[i] = (unsigned long)p;
		printf("MMAP_POLICY_DATA data[%d]=0x%lx\n", i, data[i]);
		ASSERT_TRUE(in_range(data[i], data_base, ARENA_WINDOW),
			    "data in data arena");
		ASSERT_EQ(data[i] & (PAGE_SZ - 1), 0, "data page aligned");
	}

	/* --- Phase 2: exec (VM_EXEC) mappings land in the exec arena --- */
	for (i = 0; i < NR_MAPS; i++) {
		p = do_map(PROT_READ | PROT_EXEC);
		if (!ASSERT_OK_PTR(p, "exec mmap"))
			goto out_link;
		exec[i] = (unsigned long)p;
		printf("MMAP_POLICY_EXEC exec[%d]=0x%lx\n", i, exec[i]);
		ASSERT_TRUE(in_range(exec[i], exec_base, ARENA_WINDOW),
			    "exec in exec arena");
		ASSERT_EQ(exec[i] & (PAGE_SZ - 1), 0, "exec page aligned");
	}

	/* Arenas are disjoint: no exec map fell into the data arena. */
	for (i = 0; i < NR_MAPS; i++) {
		ASSERT_FALSE(in_range(exec[i], data_base, ARENA_WINDOW),
			     "exec not in data arena");
		ASSERT_FALSE(in_range(data[i], exec_base, ARENA_WINDOW),
			     "data not in exec arena");
	}

	/* Guard gap + entropy: consecutive maps are separated by at least
	 * MAP_LEN + GUARD_GAP, and the separations are not all identical.
	 */
	entropy_seen = false;
	for (i = 1; i < NR_MAPS; i++) {
		unsigned long d = data[i] - data[i - 1];

		ASSERT_GE(d, MAP_LEN + GUARD_GAP, "data guard gap present");
		ASSERT_GE(data[i], data[i - 1] + MAP_LEN, "no data overlap");
		if (d != (data[1] - data[0]))
			entropy_seen = true;
	}
	ASSERT_TRUE(entropy_seen, "per-mapping entropy present");

	/* --- Phase 3: safe fallback on a bad policy return --- */
	skel->bss->trigger_fallback = true;
	p = do_map(PROT_READ | PROT_WRITE);
	if (!ASSERT_OK_PTR(p, "fallback mmap succeeds"))
		goto out_link;
	printf("MMAP_POLICY_FALLBACK addr=0x%lx\n", (unsigned long)p);
	ASSERT_FALSE(in_range((unsigned long)p, data_base, ARENA_WINDOW),
		     "fallback not in data arena");
	ASSERT_FALSE(in_range((unsigned long)p, exec_base, ARENA_WINDOW),
		     "fallback not in exec arena");
	munmap(p, MAP_LEN);
	skel->bss->trigger_fallback = false;

	/* --- Phase 4: MAP_FIXED is left untouched by the policy --- */
	p = mmap(NULL, MAP_LEN, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ASSERT_OK_PTR(p == MAP_FAILED ? NULL : p, "reserve for MAP_FIXED")) {
		void *want = p;
		void *got;

		munmap(p, MAP_LEN);
		got = mmap(want, MAP_LEN, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (ASSERT_OK_PTR(got == MAP_FAILED ? NULL : got, "MAP_FIXED mmap")) {
			ASSERT_EQ(got, want, "MAP_FIXED placed verbatim");
			ASSERT_FALSE(in_range((unsigned long)got, data_base, ARENA_WINDOW),
				     "MAP_FIXED not relocated to arena");
			munmap(got, MAP_LEN);
		}
	}

	/* --- Phase 5: detach restores the default layout --- */
	bpf_link__destroy(link);
	link = NULL;
	p = do_map(PROT_READ | PROT_WRITE);
	if (ASSERT_OK_PTR(p, "post-detach mmap")) {
		printf("MMAP_POLICY_DETACHED addr=0x%lx\n", (unsigned long)p);
		ASSERT_FALSE(in_range((unsigned long)p, data_base, ARENA_WINDOW),
			     "post-detach not in data arena");
		munmap(p, MAP_LEN);
	}

	/* Clean up the arena mappings. */
	for (i = 0; i < NR_MAPS; i++) {
		munmap((void *)data[i], MAP_LEN);
		munmap((void *)exec[i], MAP_LEN);
	}

out_link:
	if (link)
		bpf_link__destroy(link);
out_skel:
	mmap_policy__destroy(skel);
}
