// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/cca_base.h>

static int cca_cvm_type;
static struct cca_operations *g_cca_operations[CCA_CVM_MAX];

/* please use 'cca_cvm_type=$type' to enable cca cvm feature */
static int __init setup_cca_cvm_type(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cca cvm_type.\n");
	} else {
		if (val >= ARMCCA_CVM && val < CCA_CVM_MAX)
			cca_cvm_type = val;
	}
	return ret;
}
early_param("cca_cvm_type", setup_cca_cvm_type);

int __init cca_operations_register(enum cca_cvm_type type, struct cca_operations *ops)
{
	if (type >= CCA_CVM_MAX)
		return -EINVAL;

	g_cca_operations[type] = ops;
	return 0;
}

int kvm_get_cvm_type(void)
{
	return cca_cvm_type;
}

void set_cca_cvm_type(int type)
{
	cca_cvm_type = type;
}
EXPORT_SYMBOL_GPL(set_cca_cvm_type);

int kvm_realm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (g_cca_operations[cca_cvm_type]->enable_cap)
		return g_cca_operations[cca_cvm_type]->enable_cap(kvm, cap);
	return 0;
}

int kvm_init_realm_vm(struct kvm *kvm)
{
	if (g_cca_operations[cca_cvm_type]->init_realm_vm)
		return g_cca_operations[cca_cvm_type]->init_realm_vm(kvm);
	return 0;
}

int kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	if (g_cca_operations[cca_cvm_type]->realm_vm_enter)
		return g_cca_operations[cca_cvm_type]->realm_vm_enter(vcpu);
	return 0;
}

int kvm_rec_pre_enter(struct kvm_vcpu *vcpu)
{
	if (g_cca_operations[cca_cvm_type]->realm_vm_pre_enter)
		return g_cca_operations[cca_cvm_type]->realm_vm_pre_enter(vcpu);
	return 1;
}

int handle_rec_exit(struct kvm_vcpu *vcpu, int rec_run_ret)
{
	if (g_cca_operations[cca_cvm_type]->realm_vm_exit)
		return g_cca_operations[cca_cvm_type]->realm_vm_exit(vcpu, rec_run_ret);
	return 0;
}

void kvm_destroy_realm(struct kvm *kvm)
{
	if (g_cca_operations[cca_cvm_type]->destroy_vm)
		g_cca_operations[cca_cvm_type]->destroy_vm(kvm);
}

int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	if (g_cca_operations[cca_cvm_type]->create_vcpu)
		return g_cca_operations[cca_cvm_type]->create_vcpu(vcpu);
	return 0;
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	if (g_cca_operations[cca_cvm_type]->destroy_vcpu)
		g_cca_operations[cca_cvm_type]->destroy_vcpu(vcpu);
}

void kvm_init_rme(void)
{
	if (g_cca_operations[cca_cvm_type]->init_sel2_hypervisor)
		g_cca_operations[cca_cvm_type]->init_sel2_hypervisor();
}

int realm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target, unsigned long status)
{
	if (g_cca_operations[cca_cvm_type]->psci_complete)
		return g_cca_operations[cca_cvm_type]->psci_complete(calling, target, status);
	return 0;
}

u32 kvm_realm_vgic_nr_lr(void)
{
	if (g_cca_operations[cca_cvm_type]->vgic_nr_lr)
		return g_cca_operations[cca_cvm_type]->vgic_nr_lr();
	return 0;
}
