// SPDX-License-Identifier: GPL-2.0+
/*
 * Bandwidth provisioning for XPU device
 *
 * Copyright (C) 2025-2026 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/timer.h>
#include <linux/xsched.h>

static struct workqueue_struct *quota_workqueue;

static void xsched_group_unthrottle(struct xsched_group *xg)
{
	uint32_t id;
	struct xsched_cu *xcu;

	for_each_active_xcu(xcu, id) {
		mutex_lock(&xcu->xcu_lock);
		if (!READ_ONCE(xg->perxcu_priv[id].xse.on_rq)) {
			enqueue_ctx(&xg->perxcu_priv[id].xse, xcu);
			wake_up_interruptible(&xcu->wq_xcu_idle);

			if (xg->perxcu_priv[id].start_throttled_time != 0) {
				xg->perxcu_priv[id].throttled_time +=
					ktime_to_ns(ktime_sub(ktime_get(),
					xg->perxcu_priv[id].start_throttled_time));

				xg->perxcu_priv[id].start_throttled_time = 0;
			}
		}
		mutex_unlock(&xcu->xcu_lock);
	}
}

void xsched_quota_refill(struct work_struct *work)
{
	struct xsched_group *xg;

	xg = container_of(work, struct xsched_group, refill_work);

	spin_lock(&xg->lock);
	xg->runtime = max((xg->runtime - xg->quota), (s64)0);
	hrtimer_start(&xg->quota_timeout, ns_to_ktime(xg->period), HRTIMER_MODE_REL_SOFT);
	spin_unlock(&xg->lock);

	if (xg->runtime >= xg->quota) {
		XSCHED_DEBUG("xcu_cgroup [css=0x%lx] is still be throttled @ %s\n",
			(uintptr_t)&xg->css, __func__);
		return;
	}

	xsched_group_unthrottle(xg);
}

static enum hrtimer_restart quota_timer_cb(struct hrtimer *hrtimer)
{
	struct xsched_group *xg;

	xg = container_of(hrtimer, struct xsched_group, quota_timeout);
	queue_work(quota_workqueue, &xg->refill_work);

	return HRTIMER_NORESTART;
}

void xsched_quota_account(struct xsched_group *xg, s64 exec_time)
{
	spin_lock(&xg->lock);
	xg->runtime += exec_time;
	spin_unlock(&xg->lock);
}

bool xsched_quota_exceed(struct xsched_group *xg)
{
	bool ret;

	spin_lock(&xg->lock);
	ret = (xg->quota > 0) ? (xg->runtime >= xg->quota) : false;
	spin_unlock(&xg->lock);

	return ret;
}

void xsched_quota_init(void)
{
	quota_workqueue = create_singlethread_workqueue("xsched_quota_workqueue");
}

void xsched_quota_timeout_init(struct xsched_group *xg)
{
	hrtimer_init(&xg->quota_timeout, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
	xg->quota_timeout.function = quota_timer_cb;
}

void xsched_quota_timeout_update(struct xsched_group *xg)
{
	struct hrtimer *t = &xg->quota_timeout;

	hrtimer_cancel(t);

	if (xg->quota > 0 && xg->period > 0)
		hrtimer_start(t, ns_to_ktime(xg->period), HRTIMER_MODE_REL_SOFT);
	else
		xsched_group_unthrottle(xg);
}
