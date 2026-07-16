/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Programmable mmap placement policy (BPF struct_ops).
 *
 * Defines the struct_ops vtable consulted by the mmap placement path
 * (__get_unmapped_area) to let a verified BPF program *transform* the
 * baseline address chosen by the arch/file allocator.  The kernel owns
 * all safety invariants: the returned address is re-validated and the
 * baseline is used on any failure, so a buggy or hostile policy can
 * never make a mapping unmappable or overlap an existing VMA.
 */
#ifndef _LINUX_MMAP_POLICY_H
#define _LINUX_MMAP_POLICY_H

#include <linux/types.h>
#include <linux/mm_types.h>	/* vm_flags_t */

/**
 * struct mmap_policy_args - context handed to an mmap placement policy
 * @addr:	baseline address chosen by the arch/file allocator (already
 *		validated: page aligned, within [mmap_min_addr, TASK_SIZE - len))
 * @len:	length of the requested mapping in bytes (page aligned)
 * @pgoff:	page offset of the mapping (0 for anonymous memory)
 * @flags:	MAP_* flags for the request (MAP_FIXED requests never reach here)
 * @vm_flags:	fully computed VMA flags, including VM_EXEC / VM_WRITE, so the
 *		policy can distinguish executable from data mappings
 *
 * Only scalars are exposed to keep the verifier access surface trivial.
 */
struct mmap_policy_args {
	unsigned long	addr;
	unsigned long	len;
	unsigned long	pgoff;
	unsigned long	flags;
	vm_flags_t	vm_flags;
};

/**
 * struct mmap_policy_ops - programmable mmap placement vtable
 * @get_unmapped_area:	return the desired base address for the mapping, or 0
 *			to accept the baseline (@args->addr).  The kernel
 *			re-validates any non-zero return and silently falls
 *			back to the baseline if it is unusable.
 */
struct mmap_policy_ops {
	unsigned long (*get_unmapped_area)(struct mmap_policy_args *args);
};

#ifdef CONFIG_BPF_MMAP_POLICY
unsigned long mmap_policy_get_unmapped_area(unsigned long addr, unsigned long len,
					    unsigned long pgoff, unsigned long flags,
					    vm_flags_t vm_flags);
#else
static inline unsigned long
mmap_policy_get_unmapped_area(unsigned long addr, unsigned long len,
			      unsigned long pgoff, unsigned long flags,
			      vm_flags_t vm_flags)
{
	return addr;
}
#endif /* CONFIG_BPF_MMAP_POLICY */

#endif /* _LINUX_MMAP_POLICY_H */
