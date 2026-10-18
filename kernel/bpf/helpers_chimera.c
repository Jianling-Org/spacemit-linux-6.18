// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Institute of Software Chinese Academy of Sciences (ISCAS) */
/* Chimera cross-architecture migration BPF helpers.
 *
 * Note that it is allowed to break compatibility for these functions since the
 * interface they are exposed through to BPF programs is explicitly unstable.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/vector.h>

#include <asm/cacheflush.h>

#include <linux/mman.h>

#include <linux/personality.h>
#include <linux/mmu_notifier.h>
#include <asm/tlb.h>

#include <linux/pkeys.h>
#include <linux/security.h>

#include <linux/namei.h>

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h> /* ksys_close */

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/mount.h>

#include <linux/soc/spacemit/spacemit-hmp.h>
#include <linux/usb/ch9.h>

#include <asm/vector.h>
#include <asm/ptrace.h>

#include <linux/task_work.h>
#include <linux/sched/signal.h>

// #define ENABLE_CHIMERA_WARN_LOG
// #define ENABLE_CHIMERA_INFO_LOG

#ifdef ENABLE_CHIMERA_WARN_LOG
#define chimera_warn(fmt, ...) pr_warn_ratelimited(fmt, ##__VA_ARGS__)

#else
#define chimera_warn(fmt, ...)                                                 \
	do {                                                                   \
	} while (0)
#endif

#ifdef ENABLE_CHIMERA_INFO_LOG
#define chimera_info(fmt, ...) pr_info_ratelimited(fmt, ##__VA_ARGS__)
#else
#define chimera_info(fmt, ...)                                                 \
	do {                                                                   \
	} while (0)
#endif

static DECLARE_WAIT_QUEUE_HEAD(map_worker_wq);

struct chimera_target_entry {
	struct path path;
	struct list_head list;
};

static LIST_HEAD(chimera_target_list);
static DEFINE_MUTEX(chimera_target_list_mutex);

static pid_t target_pid = -1;

/* Migration target file information supplied by userspace through a BPF map. */
#define CHIMERA_MAX_TARGET_OFFSETS 20
struct chimera_migration_target_info {
	__u64 inode;
	__u64 offsets[CHIMERA_MAX_TARGET_OFFSETS];
	int offset_cnt;
	bool is_attached;
};

#define INO_PATH_BUF 256

/* Kernel-side path lookup context for a migration target file. */
struct chimera_migration_target_ctx {
	struct chimera_migration_target_info *target_info;
	char *kern_path;
	struct dentry *dentry;
	struct inode *inode;
};

int chimera_execv_compare(struct file *file);

static void chimera_sb_callback(struct super_block *sb, void *info)
{
	struct chimera_migration_target_ctx *target_ctx =
		(struct chimera_migration_target_ctx *)info;
	struct chimera_migration_target_info *target_info =
		target_ctx->target_info;

	if (target_ctx->inode)
		return;

	/*
	 * ilookup() performs the inode hash lookup and reference acquisition
	 * with the VFS locking required for concurrent inode teardown.  Walking
	 * sb->s_inodes while nesting every inode's i_lock can hold a global
	 * spinlock for an unbounded time and creates an avoidable lock-order
	 * hazard in this asynchronous registration path.
	 */
	target_ctx->inode = ilookup(sb, target_info->inode);
}

static int chimera_register_migration_target(
	struct chimera_migration_target_ctx *target_ctx)
{
	struct chimera_target_entry *target_entry;
	struct chimera_target_entry *existing;
	struct chimera_migration_target_info *target_info =
		target_ctx->target_info;
	bool register_file = target_info->offset_cnt == 0;
	int err, i;

	if (target_info->offset_cnt < 0 ||
	    target_info->offset_cnt > CHIMERA_MAX_TARGET_OFFSETS)
		return -EINVAL;
	for (i = 0; i < target_info->offset_cnt; i++)
		register_file |= target_info->offsets[i] == 0;
	if (!register_file)
		return -EINVAL;

	target_entry = kzalloc(sizeof(*target_entry), GFP_KERNEL);
	if (!target_entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&target_entry->list);
	err = kern_path(target_ctx->kern_path, LOOKUP_FOLLOW,
			&target_entry->path);
	if (err) {
		kfree(target_entry);
		return err;
	}

	mutex_lock(&chimera_target_list_mutex);
	list_for_each_entry(existing, &chimera_target_list, list) {
		if (path_equal(&existing->path, &target_entry->path)) {
			path_put(&target_entry->path);
			kfree(target_entry);
			goto out_unlock;
		}
	}
	list_add_tail(&target_entry->list, &chimera_target_list);
out_unlock:
	mutex_unlock(&chimera_target_list_mutex);
	return 0;
}

/*
 * ino_to_path - 通过迁移目标文件的 inode number 反查路径
 * @target_ctx: 包含用户态目标文件信息和内核侧路径解析结果的上下文
 *
 * 遍历所有已挂载的 super_block，在 inode cache 中查找匹配的 inode，
 * 然后通过 dentry 反推路径，并登记目标文件。
 *
 * 成功登记返回 0；未找到 inode/dentry 或路径解析失败时返回负 errno。
 */
static int chimera_register_target_inode(
	struct chimera_migration_target_ctx *target_ctx)
{
	char *path = ERR_PTR(-ENOENT);
	char buf[INO_PATH_BUF];
	int ret = -ENOENT;

	iterate_supers(chimera_sb_callback, target_ctx);
	if (target_ctx->inode != NULL) {
		target_ctx->dentry = d_find_alias(target_ctx->inode);
		iput(target_ctx->inode);

		if (!target_ctx->dentry)
			return -ENOENT;

		path = dentry_path_raw(target_ctx->dentry, buf, INO_PATH_BUF);
		dput(target_ctx->dentry);
		if (IS_ERR(path))
			return PTR_ERR(path);
		target_ctx->kern_path = path;
		ret = chimera_register_migration_target(target_ctx);
	}

	return ret;
}

static struct task_struct *map_worker;
static struct bpf_map *map_worker_map;

static bool map_worker_has_key(struct bpf_map *map, void *next_key)
{
	int ret;

	rcu_read_lock();
	ret = map->ops->map_get_next_key(map, NULL, next_key);
	rcu_read_unlock();
	return ret == 0;
}

#ifdef CONFIG_SPACEMIT_HMP
bool chimera_task_is_target(struct task_struct *p)
{
	return READ_ONCE(target_pid) == p->tgid;
}
#endif

int chimera_execv_compare(struct file *file)
{
	struct chimera_target_entry *target_entry;
	bool matched = false;

	if (!file)
		return -EINVAL;

	mutex_lock(&chimera_target_list_mutex);
	list_for_each_entry(target_entry, &chimera_target_list, list) {
		if (path_equal(&file->f_path, &target_entry->path)) {
			matched = true;
			break;
		}
	}
	mutex_unlock(&chimera_target_list_mutex);
	if (!matched)
		return 1;

	WRITE_ONCE(target_pid, current->tgid);
#ifdef CONFIG_SPACEMIT_HMP
	WRITE_ONCE(current->prefer_a100, true);
	hmp_prefer_register(current);
	hmp_prefer_task_hint(current);
	hmp_prefer_exec(current);
#endif
	return 0;
}
EXPORT_SYMBOL(chimera_execv_compare);

static int kthread_map_worker(void *data)
{
	struct chimera_migration_target_info value;
	struct bpf_map *map;
	u32 next_key;
	void *val_ptr;
	long wait_ret;
	bool found;
	int ret;

	wait_ret = wait_event_interruptible(
		map_worker_wq,
		kthread_should_stop() || READ_ONCE(map_worker_map));
	if (wait_ret || kthread_should_stop())
		return wait_ret;

	map = READ_ONCE(map_worker_map);
	if (!map)
		return -ENODEV;
	if (map->key_size != sizeof(next_key) ||
	    map->value_size != sizeof(value))
		return -EINVAL;

	while (!kthread_should_stop()) {
		struct chimera_migration_target_ctx target_ctx = { NULL };

		wait_ret = wait_event_interruptible_timeout(
			map_worker_wq,
			kthread_should_stop(),
			msecs_to_jiffies(100));
		if (kthread_should_stop())
			break;
		if (wait_ret < 0)
			continue;
		if (!map_worker_has_key(map, &next_key))
			continue;

		found = false;
		rcu_read_lock();
		val_ptr = map->ops->map_lookup_elem(map, &next_key);
		if (val_ptr) {
			memcpy(&value, val_ptr, sizeof(value));
			found = true;
		}
		rcu_read_unlock();
		if (!found)
			continue;

		target_ctx.target_info = &value;
		ret = chimera_register_target_inode(&target_ctx);
		if (ret)
			pr_warn_ratelimited("failed to register migration target inode %llu: %d\n",
					    value.inode, ret);
		rcu_read_lock();
		ret = map->ops->map_delete_elem(map, &next_key);
		rcu_read_unlock();
		if (ret)
			pr_warn_ratelimited("failed to consume migration target inode %llu: %d\n",
					    value.inode, ret);
		if (ret)
			break;
		cond_resched();
	}

	return 0;
}

static int map_worker_start(void)
{
	map_worker = kthread_run(kthread_map_worker, NULL, "map_worker");
	if (IS_ERR(map_worker)) {
		int err = PTR_ERR(map_worker);

		map_worker = NULL;
		return err;
	}

	return 0;
}

static void map_worker_stop(void)
{
	struct bpf_map *map;

	if (map_worker) {
		kthread_stop(map_worker);
		map_worker = NULL;
	}
	map = xchg(&map_worker_map, NULL);
	if (map)
		bpf_map_put(map);
}

static int __init map_worker_init(void)
{
	return map_worker_start();
}
late_initcall(map_worker_init);

static void __exit map_worker_exit(void)
{
	struct chimera_target_entry *entry, *tmp;

	map_worker_stop();
	mutex_lock(&chimera_target_list_mutex);
	list_for_each_entry_safe(entry, tmp, &chimera_target_list, list) {
		list_del(&entry->list);
		path_put(&entry->path);
		kfree(entry);
	}
	mutex_unlock(&chimera_target_list_mutex);
}
module_exit(map_worker_exit);

static inline uint32_t pack(unsigned int vlenb, unsigned int vl)
{
	return (vlenb & 0x3fff) | ((vl & 0x1ffff) << 14);
}

struct send_signal_work {
	struct work_struct work;
	pid_t pid;
	u64 payload;
};

static void send_signal_workfn(struct work_struct *work)
{
	struct send_signal_work *sw;
	struct task_struct *task;
	struct kernel_siginfo info;

	sw = container_of(work, struct send_signal_work, work);

	rcu_read_lock();
	task = find_task_by_vpid(sw->pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task)
		goto out_free;
	if (task->flags & PF_EXITING)
		goto out_put;

	clear_siginfo(&info);
	info.si_signo = 41;
	info.si_errno = 0;
	info.si_code = SI_QUEUE;
	info.si_value.sival_ptr = (void __user *)(uintptr_t)sw->payload;
	send_sig_info(41, &info, task);

out_put:
	put_task_struct(task);

out_free:
	kfree(sw);
}

__bpf_kfunc_start_defs();
// bpf_chimera_request_migration
__bpf_kfunc pid_t bpf_xdp_get_xfrm_state_chimera(pid_t pid, void *p__map,
					    int dst_cpu)
{
	struct bpf_map *map = p__map;
	struct bpf_map *worker_map;

	if (!map || map->map_type != BPF_MAP_TYPE_HASH ||
	    map->key_size != sizeof(u32) ||
	    map->value_size != sizeof(struct chimera_migration_target_info) ||
	    !map->ops->map_get_next_key || !map->ops->map_lookup_elem ||
	    !map->ops->map_delete_elem)
		return pid;

	if (unlikely(!READ_ONCE(map_worker_map))) {
		struct bpf_map *old;

		bpf_map_inc(map);
		old = cmpxchg(&map_worker_map, NULL, map);
		if (old)
			bpf_map_put(map);
		else
			wake_up_interruptible(&map_worker_wq);
	}
	worker_map = READ_ONCE(map_worker_map);
	if (worker_map != map)
		return pid;

	struct task_struct *task;

	rcu_read_lock();
	task = find_task_by_pid_ns(pid, &init_pid_ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task) {
		return pid;
	}

	int src_cpu = task_cpu(task);

	if (READ_ONCE(target_pid) != task->tgid) {
		goto out_put_task;
	}

	/* Managed migrations prepare the vector state before the scheduler
	 * commit.  A second post-migration signal would race rt_sigreturn in the
	 * destination VLEN domain. */
#ifdef CONFIG_SPACEMIT_HMP
	if (READ_ONCE(task->prefer_a100))
		goto out_put_task;
#endif

	if (!((src_cpu > 7 && dst_cpu < 8) || (src_cpu < 8 && dst_cpu > 7))) {
		goto out_put_task;
	}

	struct send_signal_work *sw;
	sw = kzalloc(sizeof(*sw), GFP_ATOMIC);
	if (!sw) {
		chimera_warn("kzalloc(sizeof(*sw), GFP_ATOMIC) failed \n");
		goto out_put_task;
	}

	INIT_WORK(&sw->work, send_signal_workfn);
	sw->pid = pid;
	sw->payload = pack(task->thread.vstate.vlenb, task->thread.vstate.vl);

	if (!schedule_work_on(dst_cpu, &sw->work)) {
		kfree(sw);
		chimera_warn("schedule_work_on EBUSY\n");
		goto out_put_task;
	}

out_put_task:
	put_task_struct(task);
	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(chimera_state_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_get_xfrm_state_chimera)
BTF_KFUNCS_END(chimera_state_kfunc_set)

static const struct btf_kfunc_id_set chimera_state_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &chimera_state_kfunc_set,
};

static int __init register_chimera_state_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT,
					 &chimera_state_xdp_kfunc_set);
}

late_initcall(register_chimera_state_bpf);
