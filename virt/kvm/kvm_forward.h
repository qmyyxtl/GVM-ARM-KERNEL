#ifndef KERNEL_KVM_FORWARD_H
#define KERNEL_KVM_FORWARD_H

#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include "../../arch/arm64/kvm/ivy.h"

int kvm_create_msg_forward_eventfd(struct kvm *kvm, int eventfd);
int kvm_create_msg_forward_shared_mem(struct kvm *kvm, unsigned long user_addr);

int kvm_forward_msg_sync(struct kvm *kvm, struct kvm_forward_message *forward_msg, struct dsm_request *dsm_req);
int kvm_forward_msg_async(struct kvm *kvm, struct kvm_forward_message *forward_msg);

void kvm_cleanup_resources(struct kvm *kvm);

long long __get_duration_ns(struct timespec64 *start, struct timespec64 *end);

#endif /* KERNEL_KVM_FORWARD_H */