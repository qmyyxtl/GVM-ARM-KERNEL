/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_ARM64_PARAVIRT_DEMO_H
#define _ASM_ARM64_PARAVIRT_DEMO_H

#include <linux/arm-smccc.h>

#ifdef CONFIG_PARAVIRT
int __init pv_demo_init(void);
#else
static inline int __init pv_demo_init(void)
{
	return 0;
}
#endif

#endif /* _ASM_ARM64_PARAVIRT_DEMO_H */