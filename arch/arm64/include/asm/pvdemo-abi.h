#ifndef __ASM_PVDEMO_ABI_H
#define __ASM_PVDEMO_ABI_H

/* Demo structure for VM-to-Host communication */

struct pvclock_vcpu_demo_data {
	__le32 revision;
	__le32 attributes;
	char message[48];  /* VM writes message here, Host reads */
	/* Structure must be 64 byte aligned, pad to that size */
	u8 padding[8];
} __packed;

#endif