// SPDX-License-Identifier: GPL-2.0-only
/*
 * GMEM statistics.
 *
 * Copyright (C) 2025- Huawei, Inc.
 * Author: Bin Wang
 *
 */

#include <linux/mm.h>
#include <linux/kobject.h>
#include <linux/slab.h>

#include "gmem-internal.h"

static struct kobject *gm_kobj;

struct hnode_kobject {
	struct kobject kobj;
	unsigned int hnid;
};

#define HNODE_NAME_LEN	32

static struct hnode *get_hnode_kobj(struct kobject *kobj)
{
	struct hnode *hnode;
	struct hnode_kobject *hnode_kobj;

	hnode_kobj = container_of(kobj, struct hnode_kobject, kobj);
	hnode = get_hnode(hnode_kobj->hnid);
	if (!hnode)
		gmem_err("%s: failed to get hnode from kobject", __func__);

	return hnode;
}


static ssize_t max_memsize_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct hnode *hnode = get_hnode_kobj(kobj);

	if (!hnode)
		return -EINVAL;

	return sprintf(buf, "%lu\n", hnode->max_memsize);
}

static ssize_t max_memsize_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct hnode *hnode = get_hnode_kobj(kobj);

	if (!hnode)
		return -EINVAL;

	hnode->max_memsize = memparse(buf, NULL) & (~(HPAGE_SIZE - 1));
	return count;
}

static struct kobj_attribute max_memsize_attr =
	__ATTR(max_memsize, 0640, max_memsize_show, max_memsize_store);

static ssize_t nr_freepages_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct hnode *hnode = get_hnode_kobj(kobj);

	if (!hnode)
		return -EINVAL;

	return sprintf(buf, "%u\n", atomic_read(&hnode->nr_free_pages));
}

static struct kobj_attribute nr_freepages_attr =
	__ATTR(nr_freepages, 0440, nr_freepages_show, NULL);

static ssize_t nr_activepages_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	struct hnode *hnode = get_hnode_kobj(kobj);

	if (!hnode)
		return -EINVAL;

	return sprintf(buf, "%u\n", atomic_read(&hnode->nr_active_pages));
}

static struct kobj_attribute nr_activepages_attr =
	__ATTR(nr_activepages, 0444, nr_activepages_show, NULL);

static ssize_t nr_freelist_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	unsigned int nr_freelist = 0;
	struct gm_page *gm_page;
	struct hnode *hnode = get_hnode_kobj(kobj);

	if (!hnode)
		return -EINVAL;

	spin_lock(&hnode->freelist_lock);
	list_for_each_entry(gm_page, &hnode->freelist, gm_page_list) {
		nr_freelist++;
	}
	spin_unlock(&hnode->freelist_lock);
	return sprintf(buf, "%u\n", nr_freelist);
}

static struct kobj_attribute nr_freelist_attr =
		__ATTR(nr_freelist, 0444, nr_freelist_show, NULL);

static ssize_t nr_activelist_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	unsigned int nr_activelist = 0;
	struct gm_page *gm_page;
	struct hnode *hnode = get_hnode_kobj(kobj);

	if (!hnode)
		return -EINVAL;

	spin_lock(&hnode->activelist_lock);
	list_for_each_entry(gm_page, &hnode->activelist, gm_page_list) {
		nr_activelist++;
	}
	spin_unlock(&hnode->activelist_lock);
	return sprintf(buf, "%u\n", nr_activelist);
}

static struct kobj_attribute nr_activelist_attr =
		__ATTR(nr_activelist, 0444, nr_activelist_show, NULL);

static struct attribute *hnode_attrs[] = {
	&max_memsize_attr.attr,
	&nr_freepages_attr.attr,
	&nr_activepages_attr.attr,
	&nr_freelist_attr.attr,
	&nr_activelist_attr.attr,
	NULL,
};

static struct attribute_group hnode_attr_group = {
	.attrs = hnode_attrs,
};

static void hnode_kobj_release(struct kobject *kobj)
{
	struct hnode_kobject *hnode_kobj =
		container_of(kobj, struct hnode_kobject, kobj);
	kfree(hnode_kobj);
}

static const struct kobj_type hnode_kobj_ktype = {
	.release = hnode_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
};

int hnode_init_sysfs(unsigned int hnid)
{
	int ret;
	struct hnode_kobject *hnode_kobj;

	hnode_kobj = kzalloc(sizeof(struct hnode_kobject), GFP_KERNEL);
	if (!hnode_kobj)
		return -ENOMEM;

	ret = kobject_init_and_add(&hnode_kobj->kobj, &hnode_kobj_ktype,
				   gm_kobj, "hnode%u", hnid);
	if (ret) {
		gmem_err("%s: failed to init hnode object", __func__);
		goto free_hnode_kobj;
	}

	ret = sysfs_create_group(&hnode_kobj->kobj, &hnode_attr_group);
	if (ret) {
		gmem_err("%s: failed to register hnode group", __func__);
		goto delete_hnode_kobj;
	}

	hnode_kobj->hnid = hnid;
	return 0;

delete_hnode_kobj:
	kobject_put(&hnode_kobj->kobj);
free_hnode_kobj:
	kfree(hnode_kobj);
	return ret;
}
EXPORT_SYMBOL(hnode_init_sysfs);

int __init gm_init_sysfs(void)
{
	gm_kobj = kobject_create_and_add("gmem", mm_kobj);
	if (!gm_kobj) {
		gmem_err("%s: failed to create gmem object", __func__);
		return -ENOMEM;
	}

	return 0;
}

void gm_deinit_sysfs(void)
{
	kobject_put(gm_kobj);
}
