// SPDX-License-Identifier: GPL-2.0+
/*
 * Real-Time Scheduling Class for XPU device
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

#include <uapi/linux/sched/types.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/xsched.h>
#include <linux/vstream.h>

#define XSCHED_RT_TIMESLICE	(10 * NSEC_PER_MSEC)

static inline void
xse_rt_add(struct xsched_entity *xse, struct xsched_cu *xcu)
{
	list_add_tail(&xse->rt.list_node, &xcu->xrq.rt.rq[xse->rt.prio]);
}

static inline void xse_rt_del(struct xsched_entity *xse)
{
	list_del_init(&xse->rt.list_node);
}

static inline void xse_rt_move_tail(struct xsched_entity *xse)
{
	struct xsched_cu *xcu = xse->xcu;

	list_move_tail(&xse->rt.list_node, &xcu->xrq.rt.rq[xse->rt.prio]);
}

/* Increase RT runqueue total and per prio nr_running stat. */
static inline void xrq_inc_nr_running(struct xsched_entity *xse,
					struct xsched_cu *xcu)
{
	xcu->xrq.rt.nr_running++;
}

/* Decrease RT runqueue total and per prio nr_running stat
 * and raise a bug if nr_running decrease beyond zero.
 */
static inline void xrq_dec_nr_running(struct xsched_entity *xse)
{
	struct xsched_cu *xcu = xse->xcu;

	xcu->xrq.rt.nr_running--;
}

static void dequeue_ctx_rt(struct xsched_entity *xse)
{
	xse_rt_del(xse);
	xrq_dec_nr_running(xse);
}

static void enqueue_ctx_rt(struct xsched_entity *xse, struct xsched_cu *xcu)
{
	xse_rt_add(xse, xcu);
	xrq_inc_nr_running(xse, xcu);
}

static inline struct xsched_entity *xrq_next_xse(struct xsched_cu *xcu,
						int prio)
{
	return list_first_entry(&xcu->xrq.rt.rq[prio], struct xsched_entity,
				rt.list_node);
}

/* Return the next priority for pick_next_ctx taking into
 * account if there are pending kicks on certain priority.
 */
static inline uint32_t get_next_prio_rt(struct xsched_rq *xrq)
{
	unsigned int curr_prio;

	for_each_xse_prio(curr_prio) {
		if (!list_empty(&xrq->rt.rq[curr_prio]))
			return curr_prio;
	}
	return NR_XSE_PRIO;
}

static struct xsched_entity *pick_next_ctx_rt(struct xsched_cu *xcu)
{
	struct xsched_entity *result;
	int next_prio;

	next_prio = get_next_prio_rt(&xcu->xrq);
	if (next_prio >= NR_XSE_PRIO) {
		XSCHED_DEBUG("No pending kicks in RT class @ %s\n", __func__);
		return NULL;
	}

	result = xrq_next_xse(xcu, next_prio);
	if (!result)
		XSCHED_ERR("Next XSE not found @ %s\n", __func__);
	else
		XSCHED_DEBUG("Next XSE %u at prio %u @ %s\n", result->tgid, next_prio, __func__);

	return result;
}

static void put_prev_ctx_rt(struct xsched_entity *xse)
{
	xse->rt.timeslice -= xse->last_exec_runtime;
	XSCHED_DEBUG(
		"Update XSE=%d timeslice=%lld, XSE submitted=%lld in RT class @ %s\n",
		xse->tgid, xse->rt.timeslice,
		xse->last_exec_runtime, __func__);

	if (xse->rt.timeslice <= 0) {
		xse->rt.timeslice = XSCHED_RT_TIMESLICE;
		XSCHED_DEBUG("Refill XSE=%d kick_slice=%lld in RT class @ %s\n",
			    xse->tgid, xse->rt.timeslice, __func__);
		xse_rt_move_tail(xse);
	}
}

static bool check_preempt_ctx_rt(struct xsched_entity *xse)
{
	return true;
}

void rq_init_rt(struct xsched_cu *xcu)
{
	int prio = 0;

	xcu->xrq.rt.nr_running = 0;

	for_each_xse_prio(prio) {
		INIT_LIST_HEAD(&xcu->xrq.rt.rq[prio]);
	}
}

void xse_init_rt(struct xsched_entity *xse)
{
	struct task_struct *p;

	p = find_task_by_vpid(xse->tgid);
	xse->rt.prio = p->_resvd->xse_attr.xsched_priority;
	XSCHED_DEBUG("Xse init: set priority=%d.\n", xse->rt.prio);
	xse->rt.timeslice = XSCHED_RT_TIMESLICE;
	INIT_LIST_HEAD(&xse->rt.list_node);
}

void xse_deinit_rt(struct xsched_entity *xse) { }

struct xsched_class rt_xsched_class = {
	.class_id = XSCHED_TYPE_RT,
	.kick_slice = XSCHED_RT_KICK_SLICE,
	.rq_init = rq_init_rt,
	.xse_init = xse_init_rt,
	.xse_deinit = xse_deinit_rt,
	.dequeue_ctx = dequeue_ctx_rt,
	.enqueue_ctx = enqueue_ctx_rt,
	.pick_next_ctx = pick_next_ctx_rt,
	.put_prev_ctx = put_prev_ctx_rt,
	.check_preempt = check_preempt_ctx_rt
};

void xsched_rt_prio_set(pid_t tgid, unsigned int prio)
{
	unsigned int id;
	struct xsched_cu *xcu;
	struct xsched_context *ctx;
	struct xsched_entity *xse;

	for_each_active_xcu(xcu, id) {
		mutex_lock(&xcu->ctx_list_lock);
		mutex_lock(&xcu->xcu_lock);

		ctx = ctx_find_by_tgid_and_xcu(tgid, xcu);
		if (ctx) {
			xse = &ctx->xse;
			xse->rt.prio = clamp_t(unsigned int, prio, XSE_PRIO_HIGH, XSE_PRIO_LOW);
			if (xse->on_rq) {
				xse_rt_del(xse);
				xse_rt_add(xse, xcu);
			}
		}

		mutex_unlock(&xcu->xcu_lock);
		mutex_unlock(&xcu->ctx_list_lock);
	}
}

