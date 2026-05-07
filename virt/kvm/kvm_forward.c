#include <linux/delay.h>
#include <linux/eventfd.h>
#include <linux/time64.h>

#include "kvm_forward.h"

// 等待指定状态
int kvm_trigger_event_wait_target_state(struct kvm *kvm, enum message_status)
{
    struct timespec64 start, end;
    long long duration_ns;
    ktime_get_ts64(&start);
    if (!kvm->forward_eventfd) {
        printk(KERN_ERR "[UVVM] No forward eventfd found\n");
        return -EINVAL;
    }

    if (!kvm->forward_message) {
        printk(KERN_ERR "[UVVM] No forward message buffer found\n");
        return -ENXIO;
    }

    // 发送事件到QEMU
    eventfd_signal(kvm->forward_eventfd, 1);

    // 使用原子操作和短暂件检查，避免长时间忙等待
    int max_retries = 10000;
    int retry_count = 0;

    // 内存屏障确保读取最新状态
    smp_rmb();

    while (kvm->forward_message && kvm->forward_message->status != status && retry_count < max_retries) {
        cpu_relax(); // 轻量级的等待，避免过度占用CPU
        retry_count++;

        // 定期检查状态，避免长时间忙等待
        if (retry_count % 100 == 0) {
            smp_rmb(); // 再次确保读取最新状态
        }
    }

    if (kvm->forward_message && kvm->forward_message->status != status) {
        int retry_times = 0;

        while (kvm->forward_message && kvm->forward_message->status != status) {
            usleep_range(50, 1000); // 适当的睡眠，避免过度占用CPU

            smp_rmb(); // 确保读取最新状态
            retry_times++;
            if (retry_times > 1000) {
                printk(KERN_ERR "[UVVM] Waited too long for target state %d, current status: %d\n",
                       status, kvm->forward_message ? kvm->forward_message->status : -1);
                retry_times = 0; // 重置计数器，继续等待
            }
        }
    }

    BUG_ON(!kvm->forward_message); // 确保forward_message不为NULL
    ktime_get_ts64(&end);
    printk(KERN_INFO "[UVVM] Waited for target state %d, current status: %d, duration: %lld ns\n",
           status, kvm->forward_message->status, __get_duration_ns(&start, &end));
    
    return 0;
}

// 等待非指定状态
int kvm_trigger_event_wait_non_target_state(struct kvm *kvm, enum message_status status)
{
    printk(KERN_INFO "[UVVM] Waiting for non-target state %d\n", status);
    
    if (!kvm->forward_eventfd) {
        printk(KERN_ERR "[UVVM] No forward eventfd found\n");
        return -EINVAL;
    }

    if (!kvm->forward_message) {
        printk(KERN_ERR "[UVVM] No forward message buffer found\n");
        return -ENXIO;
    }

    // 发送事件到QEMU
    eventfd_signal(kvm->forward_eventfd, 1);

    // 使用原子操作和短暂件检查，避免长时间忙等待
    int max_retries = 10000;
    int retry_count = 0;

    smp_rmb(); // 内存屏障确保读取最新状态

    while (kvm->forward_message && kvm->forward_message->status == status && retry_count < max_retries) {
        cpu_relax(); // 轻量级的等待，避免过度占用CPU
        retry_count++;

        // 定期检查状态，避免长时间忙等待
        if (retry_count % 100 == 0) {
            smp_rmb(); // 再次确保读取最新状态
        }
    }

    if (kvm->forward_message->status == status) {
        int timeout_retries = 10;

        while (timeout_retries-- && kvm->forward_message->status == status) {
            usleep_range(50, 1000); // 适当的睡眠，避免过度占用CPU
            smp_rmb(); // 确保读取最新状态
        }

        if (kvm->forward_message->status == status) {
            printk(KERN_ERR "[UVVM] Waited too long for non-target state %d, current status: %d\n",
                   status, kvm->forward_message->status);
            return -ETIMEDOUT;
        }
    }

    printk(KERN_INFO "[UVVM] Detected non-target state %d, current status: %d\n",
           status, kvm->forward_message->status);
    return 0;
}

int kvm_write_msg(struct kvm *kvm, struct kvm_forward_message *in_msg)
{
    struct kvm_forward_message *msg = kvm->forward_message;

    if (!msg) {
        printk(KERN_ERR "[UVVM] No forward message buffer found\n");
        return -ENXIO;
    }

    if (!in_msg) {
        printk(KERN_ERR "[UVVM] Input message is NULL\n");
        return -EINVAL;
    }

    // 等待QEMU读取完成
    int timeout = 1000;
    while (msg->status != KVM_MSG_WRITTEN && timeout-- > 0) {
        cpu_relax();
        smp_rmb(); // 确保读取最新状态
    }

    if (msg->status == KVM_MSG_WRITTEN) {
        printk(KERN_ERR "[UVVM] Previous message not read by QEMU, current status: %d\n", msg->status);
        return -EBUSY;
    }

    // 检查数据长度
    uint16_t copy_len =  (in_msg->data_len < sizeof(msg->data)) ? in_msg->data_len : sizeof(msg->data);

    // 设置消息
    msg->is_unicast = in_msg->is_unicast;
    msg->target_vcpu_id = in_msg->target_vcpu_id;
    msg->data_type = in_msg->data_type;
    msg->data_len = copy_len;

    // 复制消息内容
    if (copy_len > 0) {
        memcpy(msg->data, in_msg->data, copy_len);
    }
    if (copy_len < sizeof(msg->data)) {
        msg->data[copy_len] = '\0'; // 确保字符串结束
    } else {
        msg->data[copy_len - 1] = '\0'; 
    }

    smp_wmb(); // 确保消息内容写入完成后再更新状态
    mb(); // 全内存屏障，确保所有写入完成
    
    msg->status = KVM_MSG_WRITTEN; // 更新状态，通知QEMU有新消息
    printk(KERN_INFO "[UVVM] Message written, type: %u, target_vcpu_id: %d, data_len: %u\n",
           msg->data_type, msg->target_vcpu_id, msg->data_len);
    return 0;
}   

// 同步接口
uint16_t index_lihongjie = 0;
int kvm_forward_msg_sync(struct kvm *kvm, struct kvm_forward_message *forward_msg, struct dsm_request *dsm_req)
{
    int ret;
    struct timespec64 start,get_lock, write_end, handle_end,end;
    long long duration_ns;
    ktime_get_ts64(&start);

    // 加锁
    mutex_lock(&kvm->kvm_send_mag_lock);
    ktime_get_ts64(&get_lock);
    dsm_req->request_index = index_lihongjie;
    memcpy(forward_msg->data, (const char *)dsm_req, forward_msg->data_len);

    ret = kvm_write_msg(kvm, forward_msg);
    ktime_get_ts64(&write_end);
    if (ret != 0) {
        printk(KERN_ERR "[UVVM] Failed to write message, ret = %d\n", ret);
        mutex_unlock(&kvm->kvm_send_mag_lock);
        return ret;
    }
    printk(KERN_INFO "[UVVM] Message written successfully, waiting for response...\n");

    ret = kvm_trigger_event_wait_target_state(kvm, KVM_MSG_IDLE);
    if (ret == 0) {
        ret = kvm->forward_message
        forwarding_msg->return_code = kvm->forward_message->return_code;
        if (forward_msg->return_data_len > sizeof(forward_msg->return_data)) {
            printk(KERN_WARNING "[UVVM] Return data length %u exceeds buffer size, truncating\n", forward_msg->return_data_len);
            forward_msg->return_data_len = sizeof(forward_msg->return_data);
        }
        if (forward_msg->return_data_len > 0) {
            memcpy(forward_msg->return_data, kvm->forward_message->return_data, kvm->forward_message->return_data_len);
        }
    }

    index_lihongjie++;
    ktime_get_ts64(&handle_end);
    mutex_unlock(&kvm->kvm_send_mag_lock);
    ktime_get_ts64(&end);
    printk(KERN_INFO "[UVVM] Message handled, return_code: %d, return_data_len: %u, duration: %lld ns\n",
           forward_msg->return_code, forward_msg->return_data_len, __get_duration_ns(&start, &end));
    return ret;
}

// 不感知结果的接口
int kvm_create_msg_forward_eventfd(struct kvm *kvm, int eventfd)
{
    printk(KERN_INFO "[UVVM] Creating message forward eventfd with fd: %d\n", eventfd);

    struct eventfd_ctx *ctx = eventfd_ctx_fdget(eventfd);
    if (IS_ERR(ctx)) {
        printk(KERN_ERR "[UVVM] Failed to get eventfd context for fd %d, error: %ld\n", eventfd, PTR_ERR(ctx));
        return PTR_ERR(ctx);  
    }

    kvm->forward_eventfd = ctx;
    return 0;
}

// 创建消息转发共享内存
int kvm_create_msg_forward_shared_mem(struct kvm *kvm, unsigned long user_addr)
{
    printk(KERN_INFO "[UVVM] Creating message forward shared memory at user address: 0x%lx\n", user_addr);

    // 校验
    if (user_addr & (PAGE_SIZE - 1)) {
        printk(KERN_ERR "[UVVM] User address 0x%lx is not page-aligned\n", user_addr);
        return -EINVAL;
    }

    struct vm_area_struct *vma = find_vma(current->mm, user_addr);
    if (!vma) {
        printk(KERN_ERR "[UVVM] No VMA found for user address 0x%lx\n", user_addr);
        return -EFAULT;
    }

    struct page *page = NULL;
    page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!page) {
        printk(KERN_ERR "[UVVM] Failed to allocate page for message forward shared memory\n");
        return -ENOMEM;
    }

    // 保存到kvm
    kvm->forward_page = page;
    kvm->forward_gfn = page_to_pfn(page);

    // 映射到内核空间
    kvm->forward_message = page_address(page);
    memset(kvm->forward_message, 0, sizeof(struct kvm_forward_message));

    // 添加边界检查
    if (vma->vm_end - user_addr < PAGE_SIZE) {
        printk(KERN_ERR "[UVVM] VMA size is too small for shared memory, required: %lu, available: %lu\n",
               PAGE_SIZE, vma->vm_end - user_addr);
        __free_page(page);
        kvm->forward_page = NULL;
        kvm->forward_message = NULL;
        return -EFAULT;
    }

    // 使用remap_pfn_range映射到用户空间
    int ret = remap_pfn_range(vma, user_addr, kvm->forward_gfn, PAGE_SIZE, vma->vm_page_prot);
    if (ret != 0) {
        printk(KERN_ERR "[UVVM] Failed to remap page to user space, error: %d\n", ret);
        __free_page(page);
        kvm->forward_page = NULL;
        kvm->forward_message = NULL;
        kvm->forward_gfn = 0;
        return ret;
    }

    mutex_init(&kvm->kvm_send_mag_lock);
    mutex_init(&kvm->kvm_handle_msg_lock);
    printk(KERN_INFO "[UVVM] Message forward shared memory created successfully, gfn: %lu\n", kvm->forward_gfn);

    return 0;
}

// 释放资源
void kvm_cleanup_msg_forward(struct kvm *kvm)
{
    //释放eventfd
    if (kvm->forward_eventfd) {
        eventfd_ctx_put(kvm->forward_eventfd);
        kvm->forward_eventfd = NULL;
    }
    printk(KERN_INFO "[UVVM] Message forward eventfd cleaned up\n");

    // 释放共享内存
    if (kvm->forward_page) {
        put_page(kvm->forward_page);
        kvm->forward_page = NULL;
        kvm->forward_message = NULL;
        kvm->forward_gfn = 0;
    }
    mutex_destroy(&kvm->kvm_send_mag_lock);
    mutex_destroy(&kvm->kvm_handle_msg_lock);
    pr_info("[UVVM] Message forward shared memory cleaned up\n");
}