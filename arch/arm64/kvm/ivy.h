#ifndef ARCH_ARM_KVM_IVY_H
#define ARCH_ARM_KVM_IVY_H

void clean_couter(void);
void ivy_kvm_dsm_dump_stats(struct kvm *kvm);
int ivy_kvm_dsm_handle_req(void *data);
int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);
	

#endif /* ARCH_X86_ARM_IVY_H */