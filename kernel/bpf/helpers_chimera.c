// SPDX-License-Identifier: GPL-2.0-only
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
#include <linux/completion.h>

#include <linux/usb/ch9.h>
#include <linux/xarray.h>

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

static DECLARE_COMPLETION(work_ready);
static DECLARE_WAIT_QUEUE_HEAD(map_worker_wq);

struct chimera_target_entry {
	struct path path;
	struct list_head list;
};

static LIST_HEAD(chimera_target_list);
static DEFINE_MUTEX(chimera_target_list_mutex);

static pid_t target_pid = -1;
static pid_t target_tgid = -1;
static long target_pid_init_cpu = -1;

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

char *ino_to_path(struct chimera_migration_target_ctx *target_ctx);
int chimera_execv_compare(struct file *file);
int map_worker_start(void);
void map_worker_stop(void);

static void chimera_sb_callback(struct super_block *sb, void *info)
{
	struct inode *inode = NULL;
	struct chimera_migration_target_ctx *target_ctx =
		(struct chimera_migration_target_ctx *)info;
	struct chimera_migration_target_info *target_info =
		target_ctx->target_info;

	spin_lock(&sb->s_inode_list_lock);

	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);

		if (inode->i_ino == target_info->inode) {
			target_ctx->inode = inode;
			spin_unlock(&inode->i_lock);
			break;
		}
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	return;
}

static int chimera_register_migration_target(
	struct chimera_migration_target_ctx *target_ctx)
{
	struct chimera_target_entry *target_entry;
	struct chimera_migration_target_info *target_info =
		target_ctx->target_info;
	int err = -EBUSY;

	mutex_lock(&chimera_target_list_mutex);
	if (target_info->offset_cnt == 0) {
		target_entry = kvcalloc(1, sizeof(*target_entry), GFP_KERNEL);
		INIT_LIST_HEAD(&target_entry->list);

		err = kern_path(target_ctx->kern_path, LOOKUP_FOLLOW,
				&target_entry->path);
		if (err) {
			kfree(target_entry);
			goto out;
		}

		list_add(&target_entry->list, &chimera_target_list);
	}

	for (int i = 0; i < target_info->offset_cnt; i++) {
		if (target_info->offsets[i] == 0) {
			target_entry =
				kvcalloc(1, sizeof(*target_entry), GFP_KERNEL);
			INIT_LIST_HEAD(&target_entry->list);

			err = kern_path(target_ctx->kern_path, LOOKUP_FOLLOW,
					&target_entry->path);
			if (err) {
				kfree(target_entry);
				goto out;
			}

			list_add(&target_entry->list, &chimera_target_list);
			continue;
		}
	}
out:
	mutex_unlock(&chimera_target_list_mutex);
	return err;
}

/*
 * ino_to_path - 通过迁移目标文件的 inode number 反查路径
 * @target_ctx: 包含用户态目标文件信息和内核侧路径解析结果的上下文
 *
 * 遍历所有已挂载的 super_block，在 inode cache 中查找匹配的 inode，
 * 然后通过 dentry 反推路径，并登记目标文件。
 *
 * 返回路径指针；未找到 inode 时返回 ERR_PTR(-ENOENT)，
 * 未找到 dentry 时返回 NULL，也可能返回路径解析产生的 ERR_PTR。
 */
char *ino_to_path(struct chimera_migration_target_ctx *target_ctx)
{
	char *path = ERR_PTR(-ENOENT);
	char buf[INO_PATH_BUF];

	iterate_supers(chimera_sb_callback, target_ctx);
	if (target_ctx->inode != NULL) {
		target_ctx->dentry = d_find_alias(target_ctx->inode);
		iput(target_ctx->inode);

		if (!target_ctx->dentry) {
			return NULL;
		}

		path = dentry_path_raw(target_ctx->dentry, buf, INO_PATH_BUF);
		dput(target_ctx->dentry);
		target_ctx->kern_path = path;

		chimera_register_migration_target(target_ctx);
	}

	return path;
}

static struct task_struct *map_worker;
static struct bpf_map *map_worker_map;

int chimera_execv_compare(struct file *file)
{
	struct chimera_target_entry *target_entry;

	if (!file) {
		pr_err("struct file  empty \n");
		return -ENOMEM;
	}

	char *p, *pathname;
	pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname) {
		pr_err("Failed allocate pathname \n");
		return -ENOMEM;
	}

	p = d_path(&file->f_path, pathname, PATH_MAX);
	if (IS_ERR(p)) {
		kfree(pathname);
		return 1;
	}

	char *path = ERR_PTR(-ENOENT);
	char buf[INO_PATH_BUF];

	mutex_lock(&chimera_target_list_mutex);
	list_for_each_entry(target_entry, &chimera_target_list, list) {
		path = dentry_path_raw(target_entry->path.dentry, buf,
				       INO_PATH_BUF);
		if (IS_ERR(path)) {
			kfree(pathname);
			mutex_unlock(&chimera_target_list_mutex);
			return 1;
		}

		if (strcmp(p, path) == 0) {
			target_pid = current->pid;
			target_tgid = current->tgid;
			target_pid_init_cpu = task_cpu(current);
			kfree(pathname);
			mutex_unlock(&chimera_target_list_mutex);
			return 0;
		}
	}

	mutex_unlock(&chimera_target_list_mutex);
	kfree(pathname);

	return 1;
}
EXPORT_SYMBOL(chimera_execv_compare);

static int kthread_map_worker(void *data)
{
	long wake_return_value = 0;
	struct bpf_map **map_p = (struct bpf_map **)data;

	while (!kthread_should_stop()) {
		if (*map_p != NULL)
			break;
		msleep(1000);
		reinit_completion(&work_ready);
		wait_for_completion_interruptible(&work_ready);
	}

	struct bpf_map *map = *(struct bpf_map **)data;
	void *cur_key = kzalloc(map->key_size, GFP_KERNEL);
	void *next_key = kzalloc(map->key_size, GFP_KERNEL);
	void *val_ptr;

	if (!cur_key || !next_key) {
		kfree(cur_key);
		kfree(next_key);
		return -ENOMEM;
	}

	while (!kthread_should_stop()) {
		struct chimera_migration_target_ctx target_ctx = { NULL };
		void *cur = NULL;

		wake_return_value = wait_event_interruptible_timeout(
			map_worker_wq,
			kthread_should_stop() ||
				(map->ops->map_get_next_key(map, cur, next_key) == 0),
			msecs_to_jiffies(100));

		if (wake_return_value > 0) {
		} else {
			continue;
		}

		val_ptr = map->ops->map_lookup_elem(map, next_key);
		if (val_ptr) {
			target_ctx.target_info =
				(struct chimera_migration_target_info *)val_ptr;
			ino_to_path(&target_ctx);

			map->ops->map_delete_elem(map, next_key);
		}
		cond_resched();
	}

	kfree(cur_key);
	kfree(next_key);
	return 0;
}

int map_worker_start(void)
{
	map_worker =
		kthread_run(kthread_map_worker, &map_worker_map, "map_worker");
	if (IS_ERR(map_worker)) {
		return PTR_ERR(map_worker);
	}

	return 0;
}

void map_worker_stop(void)
{
	if (!map_worker)
		return;

	kthread_stop(map_worker);
	map_worker = NULL;
	map_worker_map = NULL;
}

static int __init map_worker_init(void)
{
	return map_worker_start();
}
late_initcall(map_worker_init);

static inline uint32_t pack(unsigned int vlenb, unsigned int vl)
{
	return (vlenb & 0x3fff) | ((vl & 0x1ffff) << 14);
}

static inline unsigned int get_vlenb(uint32_t v)
{
	return v & 0x3fff;
}

static inline unsigned int get_vl(uint32_t v)
{
	return (v >> 14) & 0x1ffff;
}

struct send_signal_work {
	struct work_struct work;

	int cpu;
	pid_t pid;
	u64 payload;
	unsigned long pc;
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

static DECLARE_WORK(send_signal_work, send_signal_workfn);

__bpf_kfunc_start_defs();
// bpf_chimera_request_migration
__bpf_kfunc pid_t bpf_xdp_get_xfrm_state_chimera(pid_t pid, void *p__map,
					    int dst_cpu)
{
	struct bpf_map *map = p__map;

	if (unlikely(NULL == map_worker_map)) {
		map_worker_map = map;
		complete(&work_ready);
	}

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

	if (target_pid != task->tgid) {
		goto out_put_task;
	}

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
	sw->cpu = dst_cpu;
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
