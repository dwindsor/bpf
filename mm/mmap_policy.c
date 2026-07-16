// SPDX-License-Identifier: GPL-2.0
/*
 * Programmable mmap placement policy via BPF struct_ops.
 *
 * A single, global, RCU-protected mmap_policy_ops vtable can be installed by
 * a verified BPF program.  It is consulted inside __get_unmapped_area() after
 * the arch/file allocator has produced a baseline address (and the baseline
 * has passed the addr-validity checks) but before security_mmap_addr().
 *
 * The policy *transforms* the address: it returns the base address it would
 * like the mapping to land at (or 0 to accept the baseline).  Unlike an
 * fmod_ret/BPF-LSM hook -- whose return value is clamped to the errno range
 * and can therefore only veto -- a struct_ops callback can return a full
 * unsigned-long address.
 *
 * The kernel owns every safety invariant.  Any address returned by the policy
 * is re-validated under the caller-held mmap write lock (page alignment,
 * mmap_min_addr <= addr <= TASK_SIZE - len, and non-overlap with existing
 * VMAs via find_vma_intersection()).  On any failure -- or for MAP_FIXED
 * requests, or when no policy is installed -- the baseline is used unchanged.
 * A buggy or hostile policy can thus never make a mapping fail, land out of
 * bounds, or overlap an existing mapping.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/mman.h>	/* MAP_FIXED */
#include <linux/rcupdate.h>
#include <linux/security.h>	/* mmap_min_addr */
#include <linux/types.h>

#include <linux/mmap_policy.h>

/*
 * The single active policy.  Installed by .reg via cmpxchg, cleared by .unreg
 * followed by synchronize_rcu().  Readers hold rcu_read_lock() across the
 * callback so the vtable (owned by the struct_ops map) stays alive.
 */
static struct mmap_policy_ops __rcu *mmap_active_policy;

/**
 * mmap_policy_get_unmapped_area - let an installed policy transform @addr
 *
 * Returns the (possibly rewritten) base address for the mapping.  Falls back
 * to @addr for MAP_FIXED, when no policy is active, or whenever the policy
 * returns an address that fails re-validation.
 */
unsigned long mmap_policy_get_unmapped_area(unsigned long addr, unsigned long len,
					    unsigned long pgoff, unsigned long flags,
					    vm_flags_t vm_flags)
{
	struct mmap_policy_ops *policy;
	struct mmap_policy_args args;
	unsigned long ret;

	/* MAP_FIXED requests cannot be relocated. */
	if (flags & MAP_FIXED)
		return addr;

	rcu_read_lock();
	policy = rcu_dereference(mmap_active_policy);
	if (!policy || !policy->get_unmapped_area) {
		rcu_read_unlock();
		return addr;
	}

	args.addr = addr;
	args.len = len;
	args.pgoff = pgoff;
	args.flags = flags;
	args.vm_flags = vm_flags;

	ret = policy->get_unmapped_area(&args);
	rcu_read_unlock();

	/* 0 means "accept the baseline". */
	if (!ret)
		return addr;

	/*
	 * Re-validate the policy-chosen address with exactly the same
	 * invariants the core placement path guarantees.  Any violation ->
	 * silently fall back to the baseline.
	 */
	if (offset_in_page(ret))
		return addr;
	if (ret < mmap_min_addr)
		return addr;
	if (len > TASK_SIZE || ret > TASK_SIZE - len)
		return addr;
	/*
	 * The caller holds the mmap write lock (do_mmap() asserts it, and the
	 * baseline search we just ran needs it too), so the maple tree is
	 * stable here.
	 */
	if (find_vma_intersection(current->mm, ret, ret + len))
		return addr;

	return ret;
}

/* ------------------------------------------------------------------ */
/* BPF struct_ops provider glue                                       */
/* ------------------------------------------------------------------ */

static struct bpf_struct_ops bpf_mmap_policy_ops;

static int bpf_mmap_policy_init(struct btf *btf)
{
	return 0;
}

static int bpf_mmap_policy_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	/*
	 * The only member is the get_unmapped_area function pointer, which the
	 * generic struct_ops loader wires up.  Return 0 so it does the work.
	 */
	return 0;
}

static bool bpf_mmap_policy_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	/*
	 * The callback receives a single pointer argument (struct
	 * mmap_policy_args *).  bpf_tracing_btf_ctx_access() validates the
	 * context slot; reads of the (scalar) fields of mmap_policy_args are
	 * then handled by the generic btf_struct_access() path.  Writes into
	 * the struct are rejected there by default.
	 */
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_mmap_policy_verifier_ops = {
	.get_func_proto		= bpf_base_func_proto,
	.is_valid_access	= bpf_mmap_policy_is_valid_access,
};

static int bpf_mmap_policy_reg(void *kdata, struct bpf_link *link)
{
	struct mmap_policy_ops *ops = kdata;

	/* Only one active policy system-wide. */
	if (cmpxchg(&mmap_active_policy, NULL, ops))
		return -EBUSY;

	return 0;
}

static void bpf_mmap_policy_unreg(void *kdata, struct bpf_link *link)
{
	struct mmap_policy_ops *ops = kdata;

	/* Clear only if we are the installed policy, then wait for readers. */
	(void)cmpxchg(&mmap_active_policy, ops, NULL);
	synchronize_rcu();
}

/* CFI stubs: one nop per function member (mandatory). */
static unsigned long bpf_mmap_policy_stub_get_unmapped_area(struct mmap_policy_args *args)
{
	return 0;
}

static struct mmap_policy_ops __bpf_ops_mmap_policy_ops = {
	.get_unmapped_area = bpf_mmap_policy_stub_get_unmapped_area,
};

static struct bpf_struct_ops bpf_mmap_policy_ops = {
	.verifier_ops	= &bpf_mmap_policy_verifier_ops,
	.reg		= bpf_mmap_policy_reg,
	.unreg		= bpf_mmap_policy_unreg,
	.init		= bpf_mmap_policy_init,
	.init_member	= bpf_mmap_policy_init_member,
	.name		= "mmap_policy_ops",
	.cfi_stubs	= &__bpf_ops_mmap_policy_ops,
	.owner		= THIS_MODULE,
};

static int __init bpf_mmap_policy_init_reg(void)
{
	return register_bpf_struct_ops(&bpf_mmap_policy_ops, mmap_policy_ops);
}
late_initcall(bpf_mmap_policy_init_reg);
