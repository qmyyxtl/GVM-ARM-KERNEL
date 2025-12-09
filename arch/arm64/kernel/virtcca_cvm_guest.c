// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/swiotlb.h>
#include <linux/pci.h>
#include <linux/virtcca_cvm_domain.h>

#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/virtcca_cvm_smc.h>

#define CVM_PTE_NS_BIT   5
#define CVM_PTE_NS_MASK  (1 << CVM_PTE_NS_BIT)

static bool cvm_guest_enable __read_mostly;
DEFINE_STATIC_KEY_FALSE_RO(cvm_tsi_present);

/* please use 'virtcca_cvm_guest=1' to enable cvm guest feature */
static int __init setup_cvm_guest(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cvm_guest.\n");
	} else {
		if (val)
			cvm_guest_enable = true;
	}
	return ret;
}
early_param("virtcca_cvm_guest", setup_cvm_guest);

static bool tsi_version_matches(void)
{
	unsigned long ver = tsi_get_version();

	if (ver == SMCCC_RET_NOT_SUPPORTED)
		return false;

	pr_info("RME: TSI version %lu.%lu advertised\n",
		TSI_ABI_VERSION_GET_MAJOR(ver),
		TSI_ABI_VERSION_GET_MINOR(ver));

	return (ver >= TSI_ABI_VERSION &&
		TSI_ABI_VERSION_GET_MAJOR(ver) == TSI_ABI_VERSION_MAJOR);
}

void __init virtcca_cvm_tsi_init(void)
{
	if (!cvm_guest_enable)
		return;

	if (!tsi_version_matches())
		return;

	static_branch_enable(&cvm_tsi_present);
}

bool is_virtcca_cvm_world(void)
{
	return cvm_guest_enable && static_branch_likely(&cvm_tsi_present);
}
EXPORT_SYMBOL_GPL(is_virtcca_cvm_world);

struct cpumask cvm_spin_cpumask;
static DEFINE_SPINLOCK(ipi_passthrough_lock);
DEFINE_PER_CPU(unsigned int, virtcca_unpark_idle_notify);
DEFINE_PER_CPU(unsigned int, virtcca_park_idle_state);

bool virtcca_spin_cpumask_test_cpu(int cpu)
{
	return cpumask_test_cpu(cpu, &cvm_spin_cpumask);
}

static ssize_t soft_ipi_passthrough_store(struct kobject *kobj,
						struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	spin_lock(&ipi_passthrough_lock);
	if (cpumask_parse(buf, &cvm_spin_cpumask) < 0)
		return -EINVAL;

	spin_unlock(&ipi_passthrough_lock);

	return count;
}

static ssize_t soft_ipi_passthrough_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int ret;

	ret = scnprintf(buf, PAGE_SIZE, "%*pb\n", cpumask_pr_args(&cvm_spin_cpumask));

	return ret;
}

static struct kobj_attribute soft_ipi_passthrough_attr = __ATTR_RW(soft_ipi_passthrough);

static int __init soft_ipi_passthrough_init(void)
{
	unsigned int cpu;
	unsigned int max_nr_cpus = num_possible_cpus();

	cpumask_clear(&cvm_spin_cpumask);
	for (cpu = 0; cpu < max_nr_cpus; cpu++)
		virtcca_clear_unpark_idle_notify(cpu);


	return sysfs_create_file(kernel_kobj, &soft_ipi_passthrough_attr.attr);
}
late_initcall(soft_ipi_passthrough_init);

static int change_page_range_cvm(pte_t *ptep, unsigned long addr, void *data)
{
	bool encrypt = (bool)data;
	pte_t pte = READ_ONCE(*ptep);

	if (encrypt) {
		if (!(pte.pte & CVM_PTE_NS_MASK))
			return 0;
		pte.pte = pte.pte & (~CVM_PTE_NS_MASK);
	} else {
		if (pte.pte & CVM_PTE_NS_MASK)
			return 0;
		/* Set NS BIT */
		pte.pte = pte.pte | CVM_PTE_NS_MASK;
	}
	set_pte(ptep, pte);

	return 0;
}

static int __change_memory_common_cvm(unsigned long start, unsigned long size, bool encrypt)
{
	int ret;

	ret = apply_to_page_range(&init_mm, start, size, change_page_range_cvm, (void *)encrypt);
	flush_tlb_kernel_range(start, start + size);
	return ret;
}

static int __set_memory_encrypted(unsigned long addr,
			int numpages,
			bool encrypt)
{
	if (!is_virtcca_cvm_world())
		return 0;

	WARN_ON(!__is_lm_address(addr));
	return __change_memory_common_cvm(addr, PAGE_SIZE * numpages, encrypt);
}

int set_cvm_memory_encrypted(unsigned long addr, int numpages)
{
	return __set_memory_encrypted(addr, numpages, true);
}

int set_cvm_memory_decrypted(unsigned long addr, int numpages)
{
	return __set_memory_encrypted(addr, numpages, false);
}

/*
 * struct io_tlb_no_swiotlb_mem - whether use the
 * bounce buffer mechanism or not
 * @for_alloc: %true if the pool is used for memory allocation.
 *	Here it is set to %false, to force devices to use direct dma operations.
 *
 * @force_bounce: %true if swiotlb bouncing is forced.
 *	Here it is set to %false, to force devices to use direct dma operations.
 */
static struct io_tlb_mem io_tlb_no_swiotlb_mem = {
	.for_alloc = false,
	.force_bounce = false,
};

void enable_swiotlb_for_cvm_dev(struct device *dev, bool enable)
{
	if (!is_virtcca_cvm_world())
		return;

	if (enable)
		swiotlb_dev_init(dev);
	else
		dev->dma_io_tlb_mem = &io_tlb_no_swiotlb_mem;
}
EXPORT_SYMBOL_GPL(enable_swiotlb_for_cvm_dev);

void swiotlb_unmap_notify(unsigned long paddr, unsigned long size)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_SEC_MEM_UNMAP, paddr, size, &res);
}

static struct device cvm_alloc_device;

void __init virtcca_its_init(void)
{
	if (is_virtcca_cvm_world()) {
		device_initialize(&cvm_alloc_device);
		enable_swiotlb_for_cvm_dev(&cvm_alloc_device, true);
	}
}

struct page *virtcca_its_alloc_shared_pages_node(int node, gfp_t gfp,
			unsigned int order)
{
	return swiotlb_alloc(&cvm_alloc_device, (1 << order) * PAGE_SIZE);
}

void virtcca_its_free_shared_pages(void *addr, int order)
{
	if (order < 0)
		return;

	swiotlb_free(&cvm_alloc_device, (struct page *)addr, (1 << order) * PAGE_SIZE);
}
