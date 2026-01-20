// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Demo

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/kvm_mmu.h>
#include <asm/pvdemo-abi.h>

#include <kvm/arm_hypercalls.h>

gpa_t kvm_init_demo_data(struct kvm_vcpu *vcpu)
{
	struct pvclock_vcpu_demo_data init_values = {};
	struct kvm *kvm = vcpu->kvm;
	u64 base = vcpu->arch.demo.base;
	printk("kvm_init_demo_data: base=0x%llx\n", base);
	if (base == INVALID_GPA)
		return base;

	/* Initialize the demo data structure */
	init_values.revision = 0;
	init_values.attributes = 0;
	/* message field is already zeroed by {} initialization */

	/* Write initial values to guest memory */
	kvm_write_guest_lock(kvm, base, &init_values, sizeof(init_values));

	return base;
}

int kvm_arm_pvdemo_set_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	struct kvm *kvm = vcpu->kvm;
	u64 ipa;
	int ret = 0;
	int idx;

	if (attr->attr != KVM_ARM_VCPU_PVDEMO_IPA)
		return -ENXIO;

	if (get_user(ipa, user))
		return -EFAULT;
	if (!IS_ALIGNED(ipa, 64))
		return -EINVAL;
	if (vcpu->arch.demo.base != INVALID_GPA)
		return -EEXIST;

	/* Check the address is in a valid memslot */
	idx = srcu_read_lock(&kvm->srcu);
	if (kvm_is_error_hva(gfn_to_hva(kvm, ipa >> PAGE_SHIFT)))
		ret = -EINVAL;
	srcu_read_unlock(&kvm->srcu, idx);

	if (!ret)
		vcpu->arch.demo.base = ipa;

	return ret;
}

int kvm_arm_pvdemo_get_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	u64 ipa;

	if (attr->attr != KVM_ARM_VCPU_PVDEMO_IPA)
		return -ENXIO;

	ipa = vcpu->arch.demo.base;

	if (put_user(ipa, user))
		return -EFAULT;
	return 0;
}

int kvm_arm_pvdemo_has_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_ARM_VCPU_PVDEMO_IPA:
		return 0;
	}
	return -ENXIO;
}