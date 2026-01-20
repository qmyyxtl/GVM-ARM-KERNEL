// SPDX-License-Identifier: GPL-2.0-only
/*
 * PV demo for VM-to-Host communication
 */

#define pr_fmt(fmt) "arm-pv-demo: " fmt

#include <linux/arm-smccc.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kvm_types.h>
#include <linux/io.h>

#include <asm/paravirt-demo.h>
#include <asm/pvdemo-abi.h>

static struct pvclock_vcpu_demo_data *demo_data = NULL;

int __init pv_demo_init(void)
{
	struct arm_smccc_res res;

	pr_info("Initializing PV demo\n");

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_DEMO_GET, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_warn("Host doesn't support PV demo (ARCH_FEATURES check failed)\n");
		return -EINVAL;
	}
	pr_info("Host supports PV demo\n");
	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_DEMO_GET, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_warn("Host doesn't support PV demo\n");
		return -EINVAL;
	}
	
	if (res.a0 == INVALID_GPA || res.a0 == 0) {
		pr_err("Host returned invalid IPA\n");
		return -EINVAL;
	}

	/* Map the IPA returned by host */
	demo_data = memremap(res.a0,
			     sizeof(struct pvclock_vcpu_demo_data),
			     MEMREMAP_WB);

	if (!demo_data) {
		pr_err("Failed to map demo data structure\n");
		return -ENOMEM;
	}

	pr_info("Mapped demo page at IPA 0x%llx, virtual addr %p\n", 
		res.a0, demo_data);

	pr_info("PV demo initialized successfully\n");

	return 0;
}