// SPDX-License-Identifier: GPL-2.0+
/*
 * Completely Fair Scheduling (CFS) Class for XPU device
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
#include <linux/xsched.h>

#define CFS_INNER_RQ_EMPTY(cfs_xse)                                            \
	((cfs_xse)->xruntime == XSCHED_TIME_INF)

void xs_rq_add(struct xsched_entity_cfs *xse)
{
	struct xsched_rq_cfs *cfs_rq = xse->cfs_rq;
	struct rb_node **link = &cfs_rq->ctx_timeline.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct xsched_entity_cfs *entry;
	bool leftmost = true;

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct xsched_entity_cfs, run_node);
		if (xse->xruntime <= entry->xruntime) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&xse->run_node, parent, link);
	rb_insert_color_cached(&xse->run_node, &cfs_rq->ctx_timeline, leftmost);
}

void xs_rq_remove(struct xsched_entity_cfs *xse)
{
	struct xsched_rq_cfs *cfs_rq = xse->cfs_rq;

	rb_erase_cached(&xse->run_node, &cfs_rq->ctx_timeline);
}

/**
 * xs_cfs_rq_update() - Update entity's runqueue position with new xruntime
 */
static void xs_cfs_rq_update(struct xsched_entity_cfs *xse_cfs, u64 new_xrt)
{
	xs_rq_remove(xse_cfs);
	xse_cfs->xruntime = new_xrt;
	xs_rq_add(xse_cfs);
}

static inline struct xsched_entity_cfs *
xs_pick_first(struct xsched_rq_cfs *cfs_rq)
{
	struct xsched_entity_cfs *xse_cfs;
	struct rb_node *left = rb_first_cached(&cfs_rq->ctx_timeline);

	if (!left)
		return NULL;

	xse_cfs = rb_entry(left, struct xsched_entity_cfs, run_node);
	return xse_cfs;
}

/**
 * xs_update() - Account xruntime and runtime metrics.
 * @xse_cfs: Point to CFS scheduling entity.
 * @delta: Execution time in last period
 */
static void xs_update(struct xsched_entity_cfs *xse_cfs, u64 delta)
{
	struct xsched_group_xcu_priv *xg = xse_parent_grp_xcu(xse_cfs);

	for (; xg; xse_cfs = &xg->xse.cfs, xg = &xcg_parent_grp_xcu(xg)) {
		u64 new_xrt = xse_cfs->xruntime + delta * xse_cfs->weight;

		xs_cfs_rq_update(xse_cfs, new_xrt);
		xse_cfs->sum_exec_runtime += delta;

		if (xg->self->parent == NULL)
			break;
	}
}

/**
 * xg_update() - Update container group's xruntime
 * @gxcu: Descendant xsched group's private xcu control structure
 *
 * No locks required to access xsched_group_xcu_priv members,
 * because only one worker thread works for one XCU.
 */
static void xg_update(struct xsched_group_xcu_priv *xg, int task_delta)
{
	u64 new_xrt;
	struct xsched_entity_cfs *entry;

	for (; xg; xg = &xcg_parent_grp_xcu(xg)) {
		xg->cfs_rq->nr_running += task_delta;
		entry = xs_pick_first(xg->cfs_rq);
		if (entry)
			new_xrt = xg->xse.cfs.sum_exec_runtime * xg->xse.cfs.weight;
		else
			new_xrt = XSCHED_TIME_INF;

		xg->cfs_rq->min_xruntime = new_xrt;
		xg->xse.cfs.xruntime = new_xrt;

		if (!xg->xse.on_rq)
			break;
		if (!xg->self->parent)
			break;

		xs_cfs_rq_update(&xg->xse.cfs, new_xrt);
	}
}

/*
 * Xsched Fair class methods
 * For rq manipulation we rely on root runqueue lock already acquired in core.
 * Access xsched_group_xcu_priv requires no locks because one thread per XCU.
 */
static void dequeue_ctx_fair(struct xsched_entity *xse)
{
	int task_delta;
	struct xsched_cu *xcu = xse->xcu;
	struct xsched_entity_cfs *first;
	struct xsched_entity_cfs *xse_cfs = &xse->cfs;

	task_delta =
		(xse->is_group) ? -(xse_this_grp_xcu(xse_cfs)->cfs_rq->nr_running) : -1;

	xs_rq_remove(xse_cfs);
	xg_update(xse_parent_grp_xcu(xse_cfs), task_delta);

	first = xs_pick_first(&xcu->xrq.cfs);
	xcu->xrq.cfs.min_xruntime = (first) ? first->xruntime : XSCHED_TIME_INF;
}

/**
 * enqueue_ctx_fair() - Add context to the runqueue
 * @xse: xsched entity of context
 * @xcu: executor
 *
 * In contrary to enqueue_task it is called once on context init.
 * Although groups reside in tree, their nodes not counted in nr_running.
 * The xruntime of a group xsched entitry represented by min xruntime inside.
 */
static void enqueue_ctx_fair(struct xsched_entity *xse, struct xsched_cu *xcu)
{
	int task_delta;
	struct xsched_entity_cfs *first;
	struct xsched_rq_cfs *rq;
	struct xsched_entity_cfs *xse_cfs = &xse->cfs;

	rq = xse_cfs->cfs_rq = xse_parent_grp_xcu(xse_cfs)->cfs_rq;
	task_delta =
		(xse->is_group) ? xse_this_grp_xcu(xse_cfs)->cfs_rq->nr_running : 1;

	/* If no XSE or only empty groups */
	if (xs_pick_first(rq) == NULL || rq->min_xruntime == XSCHED_TIME_INF)
		rq->min_xruntime = xse_cfs->xruntime;
	else
		xse_cfs->xruntime = max(xse_cfs->xruntime, rq->min_xruntime);

	xs_rq_add(xse_cfs);
	xg_update(xse_parent_grp_xcu(xse_cfs), task_delta);

	first = xs_pick_first(&xcu->xrq.cfs);
	xcu->xrq.cfs.min_xruntime = (first) ? first->xruntime : XSCHED_TIME_INF;
}

static struct xsched_entity *pick_next_ctx_fair(struct xsched_cu *xcu)
{
	struct xsched_entity_cfs *xse;
	struct xsched_rq_cfs *rq = &xcu->xrq.cfs;

	xse = xs_pick_first(rq);
	if (!xse)
		return NULL;

	for (; XSCHED_SE_OF(xse)->is_group; xse = xs_pick_first(rq)) {
		if (!xse || CFS_INNER_RQ_EMPTY(xse))
			return NULL;
		rq = xse_this_grp_xcu(xse)->cfs_rq;
	}

	return container_of(xse, struct xsched_entity, cfs);
}

static inline bool
xs_should_preempt_fair(struct xsched_entity *xse)
{
	return (atomic_read(&xse->submitted_one_kick) >= XSCHED_CFS_KICK_SLICE);
}

static void put_prev_ctx_fair(struct xsched_entity *xse)
{
	struct xsched_entity_cfs *prev = &xse->cfs;

	xsched_quota_account(xse->parent_grp, (s64)xse->last_exec_runtime);
	xs_update(prev, xse->last_exec_runtime);
}

void rq_init_fair(struct xsched_cu *xcu)
{
	xcu->xrq.cfs.ctx_timeline = RB_ROOT_CACHED;
}

void xse_init_fair(struct xsched_entity *xse)
{
	xse->cfs.weight = XSCHED_CFS_WEIGHT_DFLT;
}

void xse_deinit_fair(struct xsched_entity *xse)
{
	/* TODO Cgroup exit */
}

struct xsched_class fair_xsched_class = {
	.class_id = XSCHED_TYPE_CFS,
	.kick_slice = XSCHED_CFS_KICK_SLICE,
	.rq_init = rq_init_fair,
	.xse_init = xse_init_fair,
	.xse_deinit = xse_deinit_fair,
	.dequeue_ctx = dequeue_ctx_fair,
	.enqueue_ctx = enqueue_ctx_fair,
	.pick_next_ctx = pick_next_ctx_fair,
	.put_prev_ctx = put_prev_ctx_fair,
	.check_preempt = xs_should_preempt_fair,
};
