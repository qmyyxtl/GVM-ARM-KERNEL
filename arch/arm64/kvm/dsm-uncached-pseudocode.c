/*
 * DSM / KVM_MEM_UNCACHED integration pseudocode.
 *
 * This file is deliberately not built.  It records the intended changes for
 * a DSM-enabled KVM tree.  KVM_MEM_UNCACHED memslots remain normal KVM RAM,
 * but DSM must neither track nor acquire them.  This lets a dedicated kdata
 * memslot use a Normal-NC stage-2 mapping without entering DSM coherence.
 */

/*
 * In arch/arm64/kvm/dsm-util.h:
 *
 * static inline bool kvm_dsm_memslot_is_coherent_ram(
 *                 const struct kvm_memory_slot *slot)
 * {
 *         return kvm_dsm_memslot_is_ram(slot) &&
 *                !(slot->flags & KVM_MEM_UNCACHED);
 * }
 */

/*
 * In kvm_dsm_register_memslot_hva(), kvm_dsm_add_memslot(), and
 * kvm_dsm_remove_memslot():
 *
 *         if (!kvm_dsm_memslot_is_coherent_ram(slot))
 *                 return 0;
 *
 * This prevents an uncached kdata slot from receiving a DSM hvaslot, DSM
 * state allocation, or rmap entries.  The slot is still visible to ordinary
 * KVM gfn-to-pfn lookup and normal stage-2 mapping.
 */

/*
 * In __kvm_dsm_acquire_page() and kvm_dsm_release_page():
 *
 *         if (!kvm_dsm_memslot_is_coherent_ram(slot))
 *                 return KVM_PGTABLE_PROT_RWX; // acquire
 *
 *         if (!kvm_dsm_memslot_is_coherent_ram(slot))
 *                 return;                      // release
 *
 * Do not take a DSM lock, call the DSM page-fault protocol, or issue any
 * remote coherence request for KVM_MEM_UNCACHED memory.
 */

/*
 * In user_mem_abort():
 *
 *         dsm_active = dsm_enabled &&
 *                 kvm_dsm_memslot_is_coherent_ram(memslot);
 *
 *         if (dsm_active) {
 *                 force_pte = true;
 *                 vma_shift = PAGE_SHIFT;
 *         }
 *
 *         if (dsm_active) {
 *                 dsm_access = kvm_dsm_vcpu_acquire_page(vcpu, &memslot,
 *                                                        gfn, write_fault);
 *                 if (dsm_access < 0)
 *                         return dsm_access;
 *                 dsm_acquired = true;
 *         }
 *
 *         // Existing __gfn_to_pfn_memslot() is used for both slot types.
 *         // Existing KVM_MEM_UNCACHED handling selects Normal-NC for kdata.
 *
 *         if (dsm_active && !device)
 *                 prot = dsm_access | (prot & KVM_PGTABLE_PROT_X);
 *
 *         if (dsm_acquired)
 *                 kvm_dsm_vcpu_release_page(vcpu, memslot, gfn);
 *
 * The important detail is dsm_active, not dsm_enabled: an uncached slot must
 * not inherit DSM's force-4K policy, otherwise it loses the normal hugepage
 * mapping path even though it bypasses acquire/release.
 */

/*
 * In kvm_arch_commit_memory_region(), handle KVM_MR_FLAGS_ONLY as well as
 * CREATE/MOVE/DELETE:
 *
 *         old_dsm = old && kvm_dsm_memslot_is_coherent_ram(old);
 *         new_dsm = new && kvm_dsm_memslot_is_coherent_ram(new);
 *
 *         if (old_dsm && !new_dsm)
 *                 kvm_dsm_remove_memslot(kvm, old);
 *         if (!old_dsm && new_dsm) {
 *                 kvm_dsm_register_memslot_hva(kvm, new, new->npages);
 *                 kvm_dsm_add_memslot(kvm, new, as_id);
 *         }
 *
 * A flags-only change from normal RAM to KVM_MEM_UNCACHED must remove old DSM
 * rmap/state.  The reverse transition must register DSM state again.
 */
