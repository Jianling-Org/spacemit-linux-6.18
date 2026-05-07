// SPDX-License-Identifier: GPL-2.0-only
/* Unstable XFRM state BPF helpers.
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
#include <linux/syscalls.h>   /* ksys_close */


#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/mount.h>

#include <linux/soc/spacemit/spacemit-hmp.h>
#include <linux/completion.h>

static DECLARE_COMPLETION(work_ready);

static inline unsigned long vma_iter_end(struct vma_iterator *vmi)
{
	return vmi->mas.last + 1;
}

static LIST_HEAD(chimera_uprobe_list);
#define MAX_UPROBE_OFFSETS 20

struct testmod_uprobe {
	struct path path;
	struct uprobe *uprobe[MAX_UPROBE_OFFSETS];
	struct uprobe_consumer consumer[MAX_UPROBE_OFFSETS];
	struct list_head list;
};

static DEFINE_MUTEX(testmod_uprobe_mutex);

static pid_t	target_pid = -1;
static long     target_pid_init_cpu = -1;
static bool     traget_migration_direction = false;

void notify_userspace_with_data(struct task_struct *task, struct pt_regs *regs)
{
    struct kernel_siginfo info;

    clear_siginfo(&info);
    info.si_signo           = 40;
    info.si_code            = SI_QUEUE;
    info.si_value.sival_ptr = (void __user *) regs->epc;

    send_sig_info(40, &info, task);
}

static int
uprobe_handler(struct uprobe_consumer *self, struct pt_regs *regs, __u64 *data)
{
	struct testmod_uprobe *testmod_uprobe;

	long cpu = task_cpu(current);

	if(target_pid == (current->tgid << 32 | current->pid))
	{
		if(cpu <= 7 && target_pid_init_cpu >= 8)
		{
			notify_userspace_with_data(current, regs);
			regs->epc  += 1;
			pr_warn("target_pid %d in target_pid_init_cpu %d uprobe_handler [send_sig_info] in cpu %d epc: %016lx \n", target_pid, target_pid_init_cpu, cpu, regs->epc);
		}
	}
	else
	{
		pr_warn("[ERROR] src_pid %d uprobe_handler [XOL] in cpu %d epc: %016lx \n", (current->tgid << 32 | current->pid) ,cpu, regs->epc);
	}

	return 0;
}

static int
uprobe_ret_handler(struct uprobe_consumer *self, unsigned long func,
		   struct pt_regs *regs, __u64 *data)
{
	pr_warn("uprobe_ret_handler '%d'\n", regs);
	return 0;
}

struct uprobe_info {
    __u64 inode;
    __u64 offsets[MAX_UPROBE_OFFSETS];
    int  offset_cnt;
    bool is_attached;
};

#define INO_PATH_BUF 256

struct kernel_uprobe_info {
    struct uprobe_info *user_uprobe_info;
     char  *kern_path;
	 struct dentry  *dentry;
	 struct inode *inode;
};

static void chimera_sb_callback(struct super_block *sb, void *info)
{
	struct inode *inode, *toput_inode = NULL;

    struct dentry      *dentry;
    char               *path = ERR_PTR(-ENOENT);

    char buf[INO_PATH_BUF];
	struct kernel_uprobe_info *kernel_uprobe_info_p = (struct kernel_uprobe_info *) info;
	struct uprobe_info *user_uprobe_info_p = kernel_uprobe_info_p->user_uprobe_info;

	spin_lock(&sb->s_inode_list_lock);

	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);

		if (inode->i_ino == user_uprobe_info_p->inode)
		{
			kernel_uprobe_info_p->inode = inode;
			spin_unlock(&inode->i_lock);
			break;

			dentry = d_find_alias(inode);
			iput(inode);

			if (!dentry)
			{
				spin_unlock(&inode->i_lock);
				break;
			}

			path = dentry_path_raw(dentry, buf, INO_PATH_BUF);
			dput(dentry);
			kernel_uprobe_info_p->kern_path = path;
			kernel_uprobe_info_p->dentry = dentry;

			spin_unlock(&inode->i_lock);
			break;
		}
break_ret:
continue_unlock:
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	return;
}

static int chimera_register_uprobe(struct kernel_uprobe_info *uprobe_info)
{
	struct testmod_uprobe *chimera_uprobe;
	struct uprobe_info *user_uprobe_info_p = uprobe_info->user_uprobe_info;
	chimera_uprobe = kvcalloc(1, sizeof(*chimera_uprobe), GFP_KERNEL);
	INIT_LIST_HEAD(&chimera_uprobe->list);

	int err = -EBUSY;

	mutex_lock(&testmod_uprobe_mutex);

	err = kern_path(uprobe_info->kern_path, LOOKUP_FOLLOW, &chimera_uprobe->path);
	if (err)
		goto out;

	pr_info("chimera_register_uprobe offset_cnt  %d \n", user_uprobe_info_p->offset_cnt);
	for(int i = 0; i < user_uprobe_info_p->offset_cnt ; i++)
	{
		chimera_uprobe->consumer[i].handler = uprobe_handler;
		chimera_uprobe->consumer[i].ret_handler = NULL;
		chimera_uprobe->uprobe[i] = uprobe_register(d_real_inode(chimera_uprobe->path.dentry),
						user_uprobe_info_p->offsets[i], 0, &chimera_uprobe->consumer[i]);

		if (IS_ERR(chimera_uprobe->uprobe[i])) {
			err = PTR_ERR(chimera_uprobe->uprobe[i]);
			path_put(&chimera_uprobe->path);
			chimera_uprobe->uprobe[i] = NULL;
			pr_info("uprobe installed [%d] at %lx failed \n", i, user_uprobe_info_p->offsets[i]);
		}
		else
		{
			pr_info("uprobe installed [%d]  at %lx success \n", i, user_uprobe_info_p->offsets[i]);
		}
	}

	list_add(&chimera_uprobe->list, &chimera_uprobe_list);

out:
	mutex_unlock(&testmod_uprobe_mutex);
	return err;
}

/*
 * ino_to_path - 通过 inode number 反查文件路径
 * @ino:    用户态传入的 inode number
 * @buf:    调用方提供的输出缓冲区
 * @buflen: 缓冲区长度
 *
 * 遍历所有已挂载的 super_block，在 inode cache 中查找匹配的 inode，
 * 然后通过 dentry 反推完整路径。
 *
 * 返回指向 buf 内路径字符串的指针，失败返回 ERR_PTR。
 */
char *ino_to_path(struct kernel_uprobe_info *uprobe_info_p)
{
    struct super_block *sb;
    struct inode       *inode = NULL;
    struct dentry      *dentry;
    char               *path = ERR_PTR(-ENOENT);
    char buf[INO_PATH_BUF];

	iterate_supers(chimera_sb_callback, uprobe_info_p);
	if(uprobe_info_p->inode != NULL)
	{
		uprobe_info_p->dentry = d_find_alias(uprobe_info_p->inode);
		iput(uprobe_info_p->inode);

		if (!uprobe_info_p->dentry)
		{
			return NULL;
		}
		/* dentry → 完整路径，从挂载根往上拼接 */
		path = dentry_path_raw(uprobe_info_p->dentry, buf, INO_PATH_BUF);
		dput(uprobe_info_p->dentry);
		uprobe_info_p->kern_path = path;

		pr_info("ino_to_path: ino=%llu -> %s\n", uprobe_info_p->user_uprobe_info->inode, path);

		chimera_register_uprobe(uprobe_info_p);
	}

    return path;
}

static struct task_struct *map_worker;
static struct bpf_map     *map_worker_map;
static u64     htab_map_mem_init_usage;

static void chimera_report_status(struct list_head *uprobe_list)
{
	struct testmod_uprobe *chimera_uprobe;

	char               *path = ERR_PTR(-ENOENT);
	char buf[INO_PATH_BUF];


	list_for_each_entry(chimera_uprobe, uprobe_list, list) {

		pr_info("chimera_uprobe %p \n", chimera_uprobe );

		for(int i = 0; i < 20 ; i++)
		{
			path = dentry_path_raw(chimera_uprobe->path.dentry, buf, INO_PATH_BUF);
			pr_info("uprobe [%d]  in %s \n", i, path );
		}
	}
}

int chimera_execv_compare(struct file *file)
{
	struct testmod_uprobe *chimera_uprobe;

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

	char  *path = ERR_PTR(-ENOENT);
	char buf[INO_PATH_BUF];

	list_for_each_entry(chimera_uprobe, &chimera_uprobe_list, list) {

		path = dentry_path_raw(chimera_uprobe->path.dentry, buf, INO_PATH_BUF);
		if (IS_ERR(path))
		{
			kfree(pathname);
			return 1;
		}

		if(strcmp(p, path) == 0)
		{
			pr_info("[found] uprobe_file %s  execv_file %s\n",  path, p);

			target_pid = current->tgid << 32 | current->pid;
			target_pid_init_cpu = task_cpu(current);
			kfree(pathname);

			current->thread_type = HMP_REGULAR;
			cpumask_copy(&current->cpus_mask, cpu_online_mask);
			current->nr_cpus_allowed = cpumask_weight(&current->cpus_mask);
			current->cpus_ptr = &current->cpus_mask;

			pr_info("[chimera_execv_compare] cpu_device_up p->cpus_mask : %*pb\n", cpumask_pr_args(current->cpus_ptr));
			return 0;
		}
	}
	kfree(pathname);

	return 1;
}
EXPORT_SYMBOL(chimera_execv_compare);

int chimera_is_target_task(pid_t pid)
{
	if(pid == target_pid)
	{
		return 0;
	}
	return 1;

}
EXPORT_SYMBOL(chimera_is_target_task);

/* -------------------------------------------------------
 * 内核线程：loop 遍历所有 key/value
 * ------------------------------------------------------- */
static int kthread_map_worker(void *data)
{
    struct bpf_map **map_p = (struct bpf_map **)data;

    while (!kthread_should_stop()) {
		if (*map_p != NULL)
			break;
        msleep(1000);
		reinit_completion(&work_ready);
		wait_for_completion_interruptible(&work_ready);
    }

    struct bpf_map *map = *(struct bpf_map **)data;
    void *cur_key  = kzalloc(map->key_size, GFP_KERNEL);
    void *next_key = kzalloc(map->key_size, GFP_KERNEL);
    void *val_ptr;

    if (!cur_key || !next_key) {
        kfree(cur_key);
        kfree(next_key);
        return -ENOMEM;
    }

	pr_info("enter kthread_map_worker loop\n");

    while (!kthread_should_stop()) {

		struct kernel_uprobe_info kernel_info = {NULL};
        void *cur = NULL;

		pr_info("ready to enter map_get_next_key loop waiting.....\n");
        reinit_completion(&work_ready);
		wait_for_completion_interruptible(&work_ready);

        while (map->ops->map_get_next_key(map, cur, next_key) == 0) {
			pr_info("enter map_get_next_key while loop\n");
            val_ptr = map->ops->map_lookup_elem(map, next_key);
            if (val_ptr)
			{
                pr_info("map_worker: key=%u val=%llu\n",
                        *(u32 *)next_key, ((struct uprobe_info *)val_ptr)->inode);

				kernel_info.user_uprobe_info = (struct uprobe_info *)val_ptr;
				kernel_info.kern_path = NULL;
				kernel_info.dentry = NULL;
				kernel_info.inode = NULL;
				ino_to_path(&kernel_info);

				map->ops->map_delete_elem(map, next_key);
			}

			if(NULL != cur)
			{
				map->ops->map_delete_elem(map, cur);
				cur = NULL;
			}
        }

		target_pid = current->tgid << 32 | current->pid;
		target_pid_init_cpu = task_cpu(current);

		chimera_report_status(&chimera_uprobe_list);
    }

    kfree(cur_key);
    kfree(next_key);
    return 0;
}

/* -------------------------------------------------------
 * 对外接口：创建 map、pin 到路径、启动线程
 * ------------------------------------------------------- */
int map_worker_start(const char *pin_path, u32 max_entries)
{
    struct bpf_map *map;
    int ret;

    map_worker = kthread_run(kthread_map_worker, &map_worker_map, "map_worker");
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
    bpf_map_put(map_worker_map);
    map_worker     = NULL;
    map_worker_map = NULL;
}

#define MAP_PIN_PATH "/sys/fs/bpf/pid_uprobe_map"

static int __init map_worker_init(void)
{
    return map_worker_start(MAP_PIN_PATH,1024);
}

late_initcall(map_worker_init);

__bpf_kfunc_start_defs();

__bpf_kfunc pid_t
bpf_xdp_get_xfrm_state_chimera(pid_t pid, void *p__map, int dst_cpu)
{
	unsigned int vector_data;
	unsigned long vl;

	struct pt_regs *regs;
	void *ptr;
	void *addr;
	unsigned long key = 1;
	unsigned long long out = 0;

	struct bpf_map *map = p__map;

	if(NULL == map_worker_map)
	{
		map_worker_map = map;
		complete(&work_ready);
	}
	else
	{
		u64 next_key;
		if(map_worker_map->ops->map_get_next_key(map_worker_map, NULL, &next_key)  == 0 )
		{
			complete(&work_ready);
		}
	}

	if(pid == target_pid)
	{
		if(task_cpu(current) > 7 && dst_cpu < 8)
		{
			traget_migration_direction = true;
		}
		else if(task_cpu(current) > 7 && dst_cpu > 7)
		{
			traget_migration_direction = false;
		}
	}

	struct riscv_cpuinfo *ci = per_cpu_ptr(&riscv_cpuinfo, dst_cpu);

	if(ci == NULL )
		return pid;

	return (pid_t)ci->mimpid;
}

__bpf_kfunc int bpf_xdp_xfrm_state_release_chimera(int orig_cpu)
{
	return orig_cpu;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(chimera_state_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_get_xfrm_state_chimera)
BTF_ID_FLAGS(func, bpf_xdp_xfrm_state_release_chimera)
BTF_KFUNCS_END(chimera_state_kfunc_set)

static const struct btf_kfunc_id_set chimera_state_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &chimera_state_kfunc_set,
};

static int __init register_chimera_state_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT,
					 &chimera_state_xdp_kfunc_set);
}

late_initcall(register_chimera_state_bpf);
