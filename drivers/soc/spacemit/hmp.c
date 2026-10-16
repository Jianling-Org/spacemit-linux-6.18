// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 Spacemit */

#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/capability.h>
#include <asm/vector.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/suspend.h>
#include <linux/rcupdate.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/of.h>
#include <linux/cpuset.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/irq_work.h>
#include <linux/sched/signal.h>
#include <trace/events/sched.h>
#include <linux/soc/spacemit/spacemit-hmp.h>


#include <linux/file.h>

#define ENABLE_CHIMERA_WARN_LOG

#ifdef ENABLE_CHIMERA_WARN_LOG
// #define chimera_warn(fmt, ...) pr_warn(fmt, ##__VA_ARGS__)
#define chimera_warn(fmt, ...) pr_warn_ratelimited(fmt, ##__VA_ARGS__)

#else
#define chimera_warn(fmt, ...) do { } while (0)
#endif

#ifdef ENABLE_CHIMERA_INFO_LOG
// #define chimera_info(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define chimera_info(fmt, ...) pr_info_ratelimited(fmt, ##__VA_ARGS__)
#else
#define chimera_info(fmt, ...) do { } while (0)
#endif


static atomic_t system_suspending = ATOMIC_INIT(0);

static struct cpumask	regular_cpu_mask __read_mostly;
static struct cpumask	ai_cpu_mask __read_mostly;
static bool prefer_service_ready;

bool hmp_cpu_is_ai(int cpu)
{
	return cpu >= 0 && cpu < nr_cpu_ids &&
		cpumask_test_cpu(cpu, &ai_cpu_mask);
}

bool hmp_cpu_is_regular(int cpu)
{
	return cpu >= 0 && cpu < nr_cpu_ids &&
		cpumask_test_cpu(cpu, &regular_cpu_mask);
}

bool hmp_prefer_can_migrate(void)
{
	return READ_ONCE(prefer_service_ready) &&
		!atomic_read(&system_suspending);
}

int hmp_get_cpumask(struct cpumask *mask, hmp_type_e type)
{
	int	ret = 0;

	if (!mask) {
		return -EINVAL;
	}

	switch (type) {
	case HMP_REGULAR:
		cpumask_copy(mask, &regular_cpu_mask);
		break;

	case HMP_AI:
		cpumask_copy(mask, &ai_cpu_mask);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int hmp_map_ai_to_regular(struct cpumask *mask)
{
	unsigned int ai_first, reg_first;

	ai_first = cpumask_first(&ai_cpu_mask);
	reg_first = cpumask_first(&regular_cpu_mask);

	if (ai_first > reg_first) {
		cpumask_shift_right(mask, mask, ai_first - reg_first);
	} else {
		cpumask_shift_left(mask, mask, reg_first - ai_first);
	}

	cpumask_and(mask, mask, &regular_cpu_mask);

	return cpumask_weight(mask);
}

int hmp_cpu_affinity_restrict(struct task_struct *p, const struct cpumask *new_mask)
{
	const struct cpumask *allowed_mask;

	if (atomic_read(&system_suspending)) {
		/* should not bind thread when systemm suspending */
		return -EINVAL;
	}

	if (cpumask_empty(new_mask))
		return -EINVAL;

	/* prefer_A100 keeps the user's requested mask in user_cpus_ptr, while
	 * __set_cpus_allowed_ptr() clamps the effective mask to the task's current
	 * HMP group.  This lets runtimes such as OpenMP request a cross-group mask
	 * without changing groups outside the validated HMP migration path. */
	if (READ_ONCE(p->prefer_a100))
		return 0;

	allowed_mask = (p->thread_type == HMP_REGULAR) ?
					&regular_cpu_mask : &ai_cpu_mask;

	if (!cpumask_subset(new_mask, allowed_mask))
		return -EINVAL;

	return 0;
}

/**
 * hmp_cpu_can_offline - Check the restriction when try offline a cpu core.
 * @cpu: cpu id which will be offline
 *
 * This function check the cpu offline restriction:
 *  1. If some ai thread is exist, the last cpu of ai_cpu_mask offline should
 *     be rejected;
 *  2. The last cpu of regular_cpu_mask offline should be rejected, because there
 *     should be some regulater tasks running.
 *  3. If the offline request is under system suspend processing, user tasks
 *     should be frozen already, so, any offline request is allowed.
 *
 * Returns: true if the offline request is allowed, otherwise, return false.
 */
bool hmp_cpu_can_offline(unsigned int cpu)
{
	/* reuse existing logic from cpu_hotplug_callback for CPU_DOWN_PREPARE */
	cpumask_t online_ai_cpus, online_regular_cpu_mask;
	struct task_struct *g, *p;

	if (atomic_read(&system_suspending))
		return true;

	cpumask_and(&online_regular_cpu_mask, &regular_cpu_mask, cpu_online_mask);
	cpumask_and(&online_ai_cpus, &ai_cpu_mask, cpu_online_mask);

	if (cpumask_test_cpu(cpu, &regular_cpu_mask)) {
		if (cpumask_weight(&online_regular_cpu_mask) <= 1) {
			pr_err("Cannot offline the last Regular cpu\n");
			return false;
		}
	} else {
		if (cpumask_weight(&online_ai_cpus) <= 1) {
			for_each_process_thread(g, p) {
				if (p->thread_type == HMP_AI) {
					pr_err("Cannot offline the last AI cpu\n");
					return false;
				}
			}
		}
	}

	return true;
}

/**
 * hmp_cpumask_init - Try to init hybrid multi-processor cpumask
 *
 * This function try to get the cpumask information from dts, if the
 * 'cpu-ai' property is set as 'true', it will be set to the ai_cpu_mask,
 * otherwise, it will be set to the regular_cpu_mask.
 */
void hmp_cpumask_init(void)
{
	struct device_node *node;
	const char *cpu_ai;
	unsigned long hartid;
	int rc;

	cpumask_clear(&ai_cpu_mask);
	cpumask_clear(&regular_cpu_mask);

	for_each_of_cpu_node(node) {
		rc = riscv_of_processor_hartid(node, &hartid);
		if (rc < 0) {
			pr_warn("Failed to get hartid for CPU node\n");
			continue;
		}

		if (of_property_read_string(node, "cpu-ai", &cpu_ai)) {
			cpumask_set_cpu(hartid, &regular_cpu_mask);
			continue;
		}

		if (!strcmp(cpu_ai, "true"))
			cpumask_set_cpu(hartid, &ai_cpu_mask);
	}
}

/**
 * is_per_cpu_kthread - Check if a kernel thread is a critical per-CPU thread
 * @p: task_struct pointer
 *
 * This function checks if a kernel thread is a critical per-CPU thread that
 * must be bound to its specific CPU core (including AI cores).
 * Only essential per-CPU threads are allowed to bind to AI cores.
 *
 * Returns: true if the thread is a critical per-CPU thread, false otherwise
 */
static bool is_per_cpu_kthread(struct task_struct *p)
{
	if (!(p->flags & PF_KTHREAD))
		return false;

	/* Check if it's a per-CPU thread with bound to single CPU*/
	if (p->nr_cpus_allowed == 1)
		return true;

	return false;
}

/**
 * hmp_set_default_cpumask - Set the default cpumask
 * @p: task_struct pointer
 *
 * This function set the default cpumask which allowed running the thread.
 * If the thread is not a per-cpu thread:
 * Set p->cpus_mask to ai_cpu_mask if the thread is an AI thread,
 * otherwise, set p->cpus_mask to regular_cpu_mask
 *
 * Returns: true if set cpumask set to ai_cpumask
 */

bool hmp_set_default_cpumask(struct task_struct *p)
{
	/* Preserve the validated affinity of managed tasks, including cpusets. */
	if (READ_ONCE(p->prefer_a100)) {
		const struct cpumask *group = p->thread_type == HMP_AI ?
			&ai_cpu_mask : &regular_cpu_mask;

		if (cpumask_intersects(&p->cpus_mask, group)) {
			cpumask_and(&p->cpus_mask, &p->cpus_mask, group);
			p->nr_cpus_allowed = cpumask_weight(&p->cpus_mask);
			return true;
		}
		/* A cpuset update may leave no CPU in the current HMP group.  Keep
		 * the caller's effective mask; falling through would expand it to
		 * the whole group and let the task escape its cpuset. */
		return !cpumask_empty(&p->cpus_mask);
	}

    /* check if called from set ai task */
    if (p->thread_type == HMP_AI) {
		cpumask_copy(&p->cpus_mask, &ai_cpu_mask);
		p->nr_cpus_allowed = cpumask_weight(&p->cpus_mask);
		p->cpus_ptr = &p->cpus_mask;

       return !cpumask_empty(&p->cpus_mask);
    }

    /* Check if this is a per-CPU kernel thread that should keep its binding */
    if ((p->flags & PF_KTHREAD) && is_per_cpu_kthread(p))
        return true;

    /* All new threads default to regular cores unless it's a per-CPU kthread
	 * AI thread property will be set explicitly via /proc/ai_threads
	 */

	/* enable one ai cpu core if none ai core enabled */
	cpumask_t online_regular_cpus;

	p->thread_type = HMP_REGULAR;
	cpumask_and(&online_regular_cpus, &regular_cpu_mask, cpu_online_mask);
	cpumask_copy(&p->cpus_mask, &online_regular_cpus);

	p->nr_cpus_allowed = cpumask_weight(&p->cpus_mask);
	p->cpus_ptr = &p->cpus_mask;

	// pr_info_ratelimited("cpu_device_up p->cpus_mask : %*pb\n", cpumask_pr_args(p->cpus_ptr));
    return !cpumask_empty(&p->cpus_mask);
}

static int pm_callback(struct notifier_block *nb, unsigned long action, void *data)
{
	switch (action) {
	case PM_SUSPEND_PREPARE:
		/* setup system suspending flag */
		atomic_set(&system_suspending, 1);
		return NOTIFY_OK;

	case PM_POST_SUSPEND:
		/* clear system suspending flag */
		atomic_set(&system_suspending, 0);
		return NOTIFY_OK;

	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block pm_notifier = {
	.notifier_call = pm_callback,
	.priority = INT_MAX,
};

static DEFINE_MUTEX(hmp_migration_mutex);
static atomic64_t prefer_initial = ATOMIC64_INIT(0);
static atomic64_t prefer_attempts = ATOMIC64_INIT(0);
static atomic64_t prefer_proposals = ATOMIC64_INIT(0);
static atomic64_t prefer_migrations = ATOMIC64_INIT(0);
static atomic64_t prefer_overflow_migrations = ATOMIC64_INIT(0);
static atomic64_t prefer_failures = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_runtime = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_task_state = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_target = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_ledger = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_cpu_reservation = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_signal = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_nack = ATOMIC64_INIT(0);
static atomic64_t prefer_same_group_skipped = ATOMIC64_INIT(0);
static atomic64_t prefer_nack_translated = ATOMIC64_INIT(0);
static atomic64_t prefer_nack_missing_route = ATOMIC64_INIT(0);
static atomic64_t prefer_nack_prepare = ATOMIC64_INIT(0);
static atomic64_t prefer_cooldown_suppressed = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_timeout = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_cpuset = ATOMIC64_INIT(0);
static atomic64_t prefer_fail_stopper = ATOMIC64_INIT(0);

/* Account logical allocation, so a sleeping task keeps its assigned slot. */
static DEFINE_RAW_SPINLOCK(prefer_account_lock);
static unsigned int prefer_ai_tasks;
static unsigned int prefer_regular_tasks;
static unsigned int prefer_pending_to_ai;
static unsigned int prefer_pending_to_regular;
static struct task_struct *prefer_reassign_task;

/* A proposal leaves its target idle until ACK, so idle_cpu() alone cannot
 * keep another proposal from choosing the same CPU.  The owner is only
 * compared, never dereferenced; exit/exec cancel its proposal. */
struct hmp_prefer_cpu_reservation {
	struct task_struct *owner;
	u32 generation;
	unsigned long deadline;
};
static DEFINE_RAW_SPINLOCK(prefer_cpu_reservation_lock);
static struct hmp_prefer_cpu_reservation prefer_cpu_reservations[NR_CPUS];
static int prefer_cpu_cursor[2] = { -1, -1 };

/* One event in flight globally; no timer and no polling thread. */
static atomic_t prefer_pending = ATOMIC_INIT(0);
/* Failed idle scans must not spin while userspace declines a proposal. */
static unsigned long prefer_scan_after[2];
/* A nonzero generation means that at least one preferred candidate may exist.
 * Workers clear it only after a complete no-candidate scan. */
static atomic64_t prefer_candidate_generation[2] = {
	ATOMIC64_INIT(0), ATOMIC64_INIT(0),
};
static atomic64_t prefer_balance_generation = ATOMIC64_INIT(1);
static atomic_t prefer_retry_groups = ATOMIC_INIT(0);
static struct workqueue_struct *prefer_wq;
static struct task_struct *prefer_task;
static int prefer_cpu;
static enum hmp_migration_reason prefer_reason;
static unsigned int prefer_cursor;
void hmp_prefer_task_hint(struct task_struct *p);
static bool hmp_prefer_queue(struct task_struct *p, int cpu,
			     enum hmp_migration_reason reason, bool reset_cursor);
static void hmp_prefer_kick_rebalance(void);
static int hmp_idle_group_cpu_for_task(struct task_struct *p, hmp_type_e type);
static void hmp_prefer_release_cpu(struct task_struct *p);
static void hmp_prefer_workfn(struct work_struct *work);
static DECLARE_WORK(prefer_work, hmp_prefer_workfn);
static void hmp_prefer_irqfn(struct irq_work *work);
static DEFINE_IRQ_WORK(prefer_irq_work, hmp_prefer_irqfn);
static void hmp_prefer_timeout_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(prefer_timeout_work, hmp_prefer_timeout_workfn);
static void hmp_prefer_retry_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(prefer_retry_work, hmp_prefer_retry_workfn);

static void hmp_prefer_release_reassign(struct task_struct *p, bool commit,
					hmp_type_e type);

static u64 hmp_prefer_cpu_cookie(struct task_struct *p)
{
	cpumask_t allowed;
	u64 cookie = 0;
	int cpu;

	cpuset_cpus_allowed(p, &allowed);
	for_each_cpu(cpu, &allowed)
		cookie ^= rol64((u64)(cpu + 1) * GOLDEN_RATIO_64, cpu & 63);
	for_each_cpu(cpu, cpu_active_mask)
		cookie ^= rol64((u64)(cpu + 1) * GOLDEN_RATIO_64, (cpu + 29) & 63);
	return cookie;
}

static bool hmp_prefer_nack_suppressed(struct task_struct *p,
				       int source_group, int target_group)
{
	if (!time_before(jiffies, READ_ONCE(p->prefer_nack_retry_after)))
		return false;
	if (READ_ONCE(p->prefer_nack_assignment_seq) !=
	    READ_ONCE(p->prefer_assignment_seq) ||
	    READ_ONCE(p->prefer_nack_balance_generation) !=
	    atomic64_read(&prefer_balance_generation) ||
	    READ_ONCE(p->prefer_nack_capability_generation) !=
	    READ_ONCE(p->prefer_capability_generation) ||
	    READ_ONCE(p->prefer_nack_source_group) != source_group ||
	    READ_ONCE(p->prefer_nack_target_group) != target_group ||
	    READ_ONCE(p->prefer_nack_cpu_cookie) != hmp_prefer_cpu_cookie(p))
		return false;
	atomic64_inc(&prefer_cooldown_suppressed);
	return true;
}

static void hmp_prefer_record_nack(struct task_struct *p, int source_group,
				   int target_group, u64 cpu_cookie)
{
	unsigned long retry = jiffies + msecs_to_jiffies(100);

	WRITE_ONCE(p->prefer_nack_assignment_seq,
		   READ_ONCE(p->prefer_assignment_seq));
	WRITE_ONCE(p->prefer_nack_balance_generation,
		   atomic64_read(&prefer_balance_generation));
	WRITE_ONCE(p->prefer_nack_capability_generation,
		   READ_ONCE(p->prefer_capability_generation));
	WRITE_ONCE(p->prefer_nack_cpu_cookie, cpu_cookie);
	WRITE_ONCE(p->prefer_nack_source_group, source_group);
	WRITE_ONCE(p->prefer_nack_target_group, target_group);
	WRITE_ONCE(p->prefer_nack_retry_after, retry);
	atomic_or(BIT(target_group == HMP_PREFER_GROUP_AI ? HMP_AI :
		      HMP_REGULAR), &prefer_retry_groups);
	mod_delayed_work(prefer_wq, &prefer_retry_work,
			 msecs_to_jiffies(100));
}

static void hmp_prefer_clear_nack(struct task_struct *p)
{
	WRITE_ONCE(p->prefer_nack_retry_after, 0);
}

static unsigned int hmp_prefer_active_cpus(bool ai)
{
	cpumask_t active;

	cpumask_and(&active, ai ? &ai_cpu_mask : &regular_cpu_mask,
		    cpu_active_mask);
	return max_t(unsigned int, cpumask_weight(&active), 1);
}

/* Return the group that is below its layered share after pending transfers.
 * Each layer fills all AI slots first, then all regular slots. */
static bool hmp_prefer_reassign_target(hmp_type_e *target)
{
	unsigned int ai_cap = hmp_prefer_active_cpus(true);
	unsigned int regular_cap = hmp_prefer_active_cpus(false);
	unsigned int ai = prefer_ai_tasks + prefer_pending_to_ai -
		prefer_pending_to_regular;
	unsigned int regular = prefer_regular_tasks + prefer_pending_to_regular -
		prefer_pending_to_ai;
	unsigned int total = ai + regular;
	unsigned int width = ai_cap + regular_cap;
	unsigned int desired_ai = total / width * ai_cap +
		min(total % width, ai_cap);

	lockdep_assert_held(&prefer_account_lock);
	if (ai < desired_ai) {
		*target = HMP_AI;
		return true;
	}
	if (regular < total - desired_ai) {
		*target = HMP_REGULAR;
		return true;
	}
	return false;
}

static bool hmp_prefer_task_reassign_target(struct task_struct *p,
					    hmp_type_e *target)
{
	unsigned long flags;
	int assigned;
	bool needed;

	raw_spin_lock_irqsave(&prefer_account_lock, flags);
	needed = hmp_prefer_reassign_target(target);
	assigned = p->prefer_assigned_group;
	if (needed && assigned == (*target == HMP_AI ? HMP_PREFER_GROUP_AI :
						HMP_PREFER_GROUP_REGULAR))
		needed = false;
	raw_spin_unlock_irqrestore(&prefer_account_lock, flags);
	return needed;
}

static bool hmp_prefer_user_mask(struct task_struct *p, cpumask_t *mask)
{
	unsigned long flags;
	bool present;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	present = p->user_cpus_ptr != NULL;
	if (present)
		cpumask_copy(mask, p->user_cpus_ptr);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);
	return present;
}

static void hmp_prefer_task_allowed_groups(struct task_struct *p,
					   bool *ai_allowed,
					   bool *regular_allowed)
{
	cpumask_t allowed, ai_mask, regular_mask;

	cpuset_cpus_allowed(p, &allowed);
	cpumask_and(&ai_mask, &allowed, &ai_cpu_mask);
	cpumask_and(&regular_mask, &allowed, &regular_cpu_mask);
	*ai_allowed = !cpumask_empty(&ai_mask);
	*regular_allowed = !cpumask_empty(&regular_mask);
}

static void __hmp_prefer_cancel_proposal(struct task_struct *p)
{
	struct sighand_struct *sighand;
	unsigned long flags;

	sighand = lock_task_sighand(p, &flags);
	if (!sighand) {
		/*
		 * No signal handler can ACK after the sighand has gone away.  The
		 * migration mutex still excludes the manual/ACK paths, so release
		 * reservations here instead of leaving a task reference behind.
		 */
		if (p->prefer_proposal_reassign)
			hmp_prefer_release_reassign(p, false,
				p->prefer_pending_group == HMP_PREFER_GROUP_AI ?
				HMP_AI : HMP_REGULAR);
		hmp_prefer_release_cpu(p);
		p->prefer_proposal_generation++;
		if (!p->prefer_proposal_generation)
			p->prefer_proposal_generation++;
		p->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
		p->prefer_proposal_reason = 0;
		p->prefer_proposal_reassign = 0;
		p->prefer_pending_group = HMP_PREFER_GROUP_NONE;
		p->prefer_proposal_assignment_seq = 0;
		p->prefer_target_cpu = -1;
		p->prefer_proposal_deadline = 0;
		return;
	}
	if (p->prefer_proposal_reassign)
		hmp_prefer_release_reassign(p, false,
			p->prefer_pending_group == HMP_PREFER_GROUP_AI ?
			HMP_AI : HMP_REGULAR);
	hmp_prefer_release_cpu(p);
	p->prefer_proposal_generation++;
	if (!p->prefer_proposal_generation)
		p->prefer_proposal_generation++;
	p->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
	p->prefer_proposal_reason = 0;
	p->prefer_proposal_reassign = 0;
	p->prefer_pending_group = HMP_PREFER_GROUP_NONE;
	p->prefer_proposal_assignment_seq = 0;
	p->prefer_target_cpu = -1;
	p->prefer_proposal_deadline = 0;
	flush_chimera_signal_locked(p, CHIMERA_HMP_SIGNAL);
	unlock_task_sighand(p, &flags);
}

static void hmp_prefer_cancel_proposal(struct task_struct *p)
{
	mutex_lock(&hmp_migration_mutex);
	__hmp_prefer_cancel_proposal(p);
	mutex_unlock(&hmp_migration_mutex);
}

void hmp_prefer_register(struct task_struct *p)
{
	unsigned long flags, pi_flags;
	int group;
	bool ai_allowed, regular_allowed, registered = false;

	hmp_prefer_task_allowed_groups(p, &ai_allowed, &regular_allowed);
	raw_spin_lock_irqsave(&p->pi_lock, pi_flags);
	if (!READ_ONCE(p->prefer_a100) || (p->flags & (PF_KTHREAD | PF_EXITING)) ||
	    READ_ONCE(p->prefer_assigned_group) != HMP_PREFER_GROUP_NONE) {
		raw_spin_unlock_irqrestore(&p->pi_lock, pi_flags);
		return;
	}
	raw_spin_lock_irqsave(&prefer_account_lock, flags);
	if (READ_ONCE(p->prefer_a100) && !(READ_ONCE(p->flags) & PF_EXITING) &&
	    p->prefer_assigned_group == HMP_PREFER_GROUP_NONE) {
		unsigned int ai_level = prefer_ai_tasks /
			hmp_prefer_active_cpus(true);
		unsigned int regular_level = prefer_regular_tasks /
			hmp_prefer_active_cpus(false);

		if (!regular_allowed)
			group = HMP_PREFER_GROUP_AI;
		else if (!ai_allowed)
			group = HMP_PREFER_GROUP_REGULAR;
		else
			group = ai_level <= regular_level ? HMP_PREFER_GROUP_AI :
				HMP_PREFER_GROUP_REGULAR;
		WRITE_ONCE(p->prefer_assigned_group, group);
		p->prefer_assignment_seq++;
		if (group == HMP_PREFER_GROUP_AI)
			prefer_ai_tasks++;
		else
			prefer_regular_tasks++;
		registered = true;
	}
	raw_spin_unlock_irqrestore(&prefer_account_lock, flags);
	raw_spin_unlock_irqrestore(&p->pi_lock, pi_flags);
	if (registered)
		atomic64_inc(&prefer_balance_generation);
}
EXPORT_SYMBOL_GPL(hmp_prefer_register);

/* copy_process has passed its last failure point and the child is still
 * TASK_NEW. Assign a cpuset-valid logical slot here; physical migration
 * happens after the first wakeup. */
void hmp_prefer_inherit_fork(struct task_struct *p)
{
	unsigned long flags, pi_flags;
	unsigned int ai_level, regular_level;
	int group;
	bool ai_allowed, regular_allowed, registered = false;

	hmp_prefer_task_allowed_groups(p, &ai_allowed, &regular_allowed);
	raw_spin_lock_irqsave(&p->pi_lock, pi_flags);
	if (!READ_ONCE(p->prefer_a100) || (p->flags & PF_KTHREAD)) {
		raw_spin_unlock_irqrestore(&p->pi_lock, pi_flags);
		return;
	}
	raw_spin_lock_irqsave(&prefer_account_lock, flags);
	if (READ_ONCE(p->prefer_a100) &&
	    p->prefer_assigned_group == HMP_PREFER_GROUP_NONE) {
		ai_level = prefer_ai_tasks / hmp_prefer_active_cpus(true);
		regular_level = prefer_regular_tasks /
			hmp_prefer_active_cpus(false);
		if (!regular_allowed)
			group = HMP_PREFER_GROUP_AI;
		else if (!ai_allowed)
			group = HMP_PREFER_GROUP_REGULAR;
		else
			group = ai_level <= regular_level ? HMP_PREFER_GROUP_AI :
				HMP_PREFER_GROUP_REGULAR;
		WRITE_ONCE(p->prefer_assigned_group, group);
		p->prefer_assignment_seq++;
		if (group == HMP_PREFER_GROUP_AI)
			prefer_ai_tasks++;
		else
			prefer_regular_tasks++;
		registered = true;
	}
	raw_spin_unlock_irqrestore(&prefer_account_lock, flags);
	raw_spin_unlock_irqrestore(&p->pi_lock, pi_flags);
	if (registered)
		atomic64_inc(&prefer_balance_generation);
}
EXPORT_SYMBOL_GPL(hmp_prefer_inherit_fork);

void hmp_prefer_unregister(struct task_struct *p)
{
	unsigned long flags;
	int group;

	hmp_prefer_cancel_proposal(p);
	raw_spin_lock_irqsave(&prefer_account_lock, flags);
	group = p->prefer_assigned_group;
	if (group == HMP_PREFER_GROUP_AI && prefer_ai_tasks)
		prefer_ai_tasks--;
	else if (group == HMP_PREFER_GROUP_REGULAR && prefer_regular_tasks)
		prefer_regular_tasks--;
	if (group != HMP_PREFER_GROUP_NONE) {
		WRITE_ONCE(p->prefer_assigned_group, HMP_PREFER_GROUP_NONE);
		p->prefer_assignment_seq++;
	}
	raw_spin_unlock_irqrestore(&prefer_account_lock, flags);
	if (group != HMP_PREFER_GROUP_NONE) {
		atomic64_inc(&prefer_balance_generation);
		atomic64_inc(&prefer_candidate_generation[HMP_REGULAR]);
		atomic64_inc(&prefer_candidate_generation[HMP_AI]);
	}
	if (group != HMP_PREFER_GROUP_NONE)
		hmp_prefer_kick_rebalance();
}
EXPORT_SYMBOL_GPL(hmp_prefer_unregister);

static void hmp_prefer_manual_assign(struct task_struct *p, hmp_type_e type)
{
	unsigned long flags;
	int old_group, new_group = type == HMP_AI ?
		HMP_PREFER_GROUP_AI : HMP_PREFER_GROUP_REGULAR;

	if (!READ_ONCE(p->prefer_a100))
		return;
	raw_spin_lock_irqsave(&prefer_account_lock, flags);
	if (!READ_ONCE(p->prefer_a100))
		goto out_unlock;
	old_group = p->prefer_assigned_group;
	if (old_group != new_group) {
		if (old_group == HMP_PREFER_GROUP_AI && prefer_ai_tasks)
			prefer_ai_tasks--;
		else if (old_group == HMP_PREFER_GROUP_REGULAR && prefer_regular_tasks)
			prefer_regular_tasks--;
		if (new_group == HMP_PREFER_GROUP_AI)
			prefer_ai_tasks++;
		else
			prefer_regular_tasks++;
		WRITE_ONCE(p->prefer_assigned_group, new_group);
		p->prefer_assignment_seq++;
	}
out_unlock:
	raw_spin_unlock_irqrestore(&prefer_account_lock, flags);
}

/* Reserve capacity for a ledger transfer without changing committed totals. */
static bool hmp_prefer_reserve_reassign(struct task_struct *p, hmp_type_e type)
{
	hmp_type_e target;
	int old_group, new_group = type == HMP_AI ? HMP_PREFER_GROUP_AI :
		HMP_PREFER_GROUP_REGULAR;
	bool reserved = false;

	get_task_struct(p);
	raw_spin_lock(&prefer_account_lock);
	old_group = p->prefer_assigned_group;
	if (prefer_reassign_task || old_group == new_group ||
	    old_group == HMP_PREFER_GROUP_NONE)
		goto out;
	if (!hmp_prefer_reassign_target(&target) || target != type)
		goto out;
	if (type == HMP_AI)
		prefer_pending_to_ai++;
	else
		prefer_pending_to_regular++;
	p->prefer_proposal_assignment_seq = p->prefer_assignment_seq;
	prefer_reassign_task = p;
	reserved = true;
out:
	raw_spin_unlock(&prefer_account_lock);
	if (!reserved)
		put_task_struct(p);
	return reserved;
}

static void hmp_prefer_release_reassign(struct task_struct *p, bool commit,
					hmp_type_e type)
{
	int old_group, new_group = type == HMP_AI ? HMP_PREFER_GROUP_AI :
		HMP_PREFER_GROUP_REGULAR;
	bool held = false;

	raw_spin_lock(&prefer_account_lock);
	if (WARN_ON_ONCE(prefer_reassign_task != p))
		goto out;
	prefer_reassign_task = NULL;
	held = true;
	if (type == HMP_AI) {
		if (WARN_ON_ONCE(!prefer_pending_to_ai))
			prefer_pending_to_ai = 0;
		else
			prefer_pending_to_ai--;
	} else {
		if (WARN_ON_ONCE(!prefer_pending_to_regular))
			prefer_pending_to_regular = 0;
		else
			prefer_pending_to_regular--;
	}
	old_group = p->prefer_assigned_group;
	if (commit && p->prefer_assignment_seq ==
			p->prefer_proposal_assignment_seq && old_group != new_group) {
		if (old_group == HMP_PREFER_GROUP_AI && prefer_ai_tasks)
			prefer_ai_tasks--;
		else if (old_group == HMP_PREFER_GROUP_REGULAR && prefer_regular_tasks)
			prefer_regular_tasks--;
		if (new_group == HMP_PREFER_GROUP_AI)
			prefer_ai_tasks++;
		else
			prefer_regular_tasks++;
		WRITE_ONCE(p->prefer_assigned_group, new_group);
		p->prefer_assignment_seq++;
	}
out:
	raw_spin_unlock(&prefer_account_lock);
	if (held)
		put_task_struct(p);
}

static bool hmp_prefer_cpu_unreserved(int cpu)
{
	struct hmp_prefer_cpu_reservation *reservation;
	unsigned long flags;
	bool available;

	raw_spin_lock_irqsave(&prefer_cpu_reservation_lock, flags);
	reservation = &prefer_cpu_reservations[cpu];
	available = !reservation->owner ||
		time_after(jiffies, reservation->deadline);
	raw_spin_unlock_irqrestore(&prefer_cpu_reservation_lock, flags);
	return available;
}

static bool hmp_prefer_reserve_cpu(struct task_struct *p, int cpu,
				  u32 generation, unsigned long deadline,
				  hmp_type_e type)
{
	struct hmp_prefer_cpu_reservation *reservation;
	unsigned long flags;
	bool reserved = false;

	raw_spin_lock_irqsave(&prefer_cpu_reservation_lock, flags);
	reservation = &prefer_cpu_reservations[cpu];
	if (!reservation->owner || time_after(jiffies, reservation->deadline)) {
		reservation->owner = p;
		reservation->generation = generation;
		reservation->deadline = deadline;
		WRITE_ONCE(prefer_cpu_cursor[type], cpu);
		reserved = true;
	}
	raw_spin_unlock_irqrestore(&prefer_cpu_reservation_lock, flags);
	return reserved;
}

static void hmp_prefer_release_cpu(struct task_struct *p)
{
	struct hmp_prefer_cpu_reservation *reservation;
	unsigned long flags;
	int cpu = p->prefer_target_cpu;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;
	raw_spin_lock_irqsave(&prefer_cpu_reservation_lock, flags);
	reservation = &prefer_cpu_reservations[cpu];
	if (reservation->owner == p &&
	    reservation->generation == p->prefer_proposal_generation) {
		reservation->owner = NULL;
		reservation->generation = 0;
		reservation->deadline = 0;
	}
	raw_spin_unlock_irqrestore(&prefer_cpu_reservation_lock, flags);
}

static unsigned int hmp_prefer_reserved_cpu_count(void)
{
	unsigned long flags;
	unsigned int count = 0;
	int cpu;

	raw_spin_lock_irqsave(&prefer_cpu_reservation_lock, flags);
	for_each_possible_cpu(cpu) {
		if (prefer_cpu_reservations[cpu].owner &&
		    !time_after(jiffies, prefer_cpu_reservations[cpu].deadline))
			count++;
	}
	raw_spin_unlock_irqrestore(&prefer_cpu_reservation_lock, flags);
	return count;
}

static int hmp_idle_group_cpu(const struct cpumask *allowed, hmp_type_e type)
{
	int cpu, pass, cursor = READ_ONCE(prefer_cpu_cursor[type]);
	const struct cpumask *group = type == HMP_AI ?
		&ai_cpu_mask : &regular_cpu_mask;

	for (pass = 0; pass < 2; pass++)
		for_each_cpu_and(cpu, group, cpu_active_mask) {
			if ((pass == 0 && cpu <= cursor) ||
			    (pass == 1 && cpu > cursor))
				continue;
			if ((!allowed || cpumask_test_cpu(cpu, allowed)) &&
			    hmp_prefer_cpu_unreserved(cpu) && idle_cpu(cpu))
				return cpu;
		}
	return -1;
}

static int hmp_idle_ai_cpu(const struct cpumask *allowed)
{
	return hmp_idle_group_cpu(allowed, HMP_AI);
}

/* A group may already be idle when an exit changes the layer counts, so no
 * new idle edge is guaranteed to arrive. Kick reconciliation immediately. */
static void hmp_prefer_kick_rebalance(void)
{
	unsigned long flags;
	hmp_type_e target;
	bool needed;
	int cpu;

	if (!READ_ONCE(prefer_service_ready))
		return;
	raw_spin_lock_irqsave(&prefer_account_lock, flags);
	needed = hmp_prefer_reassign_target(&target);
	raw_spin_unlock_irqrestore(&prefer_account_lock, flags);
	if (!needed)
		return;
	/* Make a rebalance request observable even when the single worker slot is
	 * currently occupied. The active worker compares this generation before
	 * releasing the slot and will replay a missed queue attempt. */
	atomic64_inc(&prefer_candidate_generation[target]);
	cpu = hmp_idle_group_cpu(NULL, target);
	if (cpu >= 0)
		hmp_prefer_queue(NULL, cpu, HMP_IDLE_PULL, true);
}

void hmp_prefer_post_fork(struct task_struct *p)
{
	int cpu;

	if (!READ_ONCE(p->prefer_a100) || (p->flags & PF_EXITING))
		return;
	if (READ_ONCE(p->prefer_assigned_group) == HMP_PREFER_GROUP_NONE)
		return;
	hmp_prefer_task_hint(p);
	if (READ_ONCE(p->prefer_assigned_group) != HMP_PREFER_GROUP_REGULAR ||
	    READ_ONCE(p->thread_type) != HMP_AI)
		return;
	cpu = hmp_idle_group_cpu_for_task(p, HMP_REGULAR);
	if (cpu >= 0)
		hmp_prefer_queue(p, cpu, HMP_INITIAL, true);
}

bool hmp_prefer_task_allowed_cpu(struct task_struct *p, int cpu)
{
	cpumask_t allowed, preferred, user;
	const struct cpumask *group = hmp_cpu_is_ai(cpu) ?
		&ai_cpu_mask : &regular_cpu_mask;
	cpuset_cpus_allowed(p, &allowed);
	if (hmp_prefer_user_mask(p, &user) &&
	    cpumask_and(&preferred, &allowed, &user) &&
	    cpumask_intersects(&preferred, group))
		cpumask_copy(&allowed, &preferred);
	return cpumask_test_cpu(cpu, &allowed);
}

/* Callers use this after making a task eligible for a future idle pull. */
void hmp_prefer_task_hint(struct task_struct *p)
{
	(void)p;
	atomic64_inc(&prefer_candidate_generation[HMP_REGULAR]);
	atomic64_inc(&prefer_candidate_generation[HMP_AI]);
}
EXPORT_SYMBOL_GPL(hmp_prefer_task_hint);

static int hmp_idle_ai_cpu_for_task(struct task_struct *p)
{
	return hmp_idle_group_cpu_for_task(p, HMP_AI);
}

static int hmp_idle_group_cpu_for_task(struct task_struct *p, hmp_type_e type)
{
	cpumask_t allowed, preferred, user;
	const struct cpumask *group = type == HMP_AI ?
		&ai_cpu_mask : &regular_cpu_mask;

	cpuset_cpus_allowed(p, &allowed);
	if (hmp_prefer_user_mask(p, &user) &&
	    cpumask_and(&preferred, &allowed, &user) &&
	    cpumask_intersects(&preferred, group))
		cpumask_copy(&allowed, &preferred);
	cpumask_and(&allowed, &allowed, group);
	return hmp_idle_group_cpu(&allowed, type);
}

/* select_task_rq_fair() calls this with p->pi_lock already held. */
static int hmp_idle_group_cpu_for_task_locked(struct task_struct *p,
					      hmp_type_e type)
{
	cpumask_t allowed, preferred;
	const struct cpumask *group = type == HMP_AI ?
		&ai_cpu_mask : &regular_cpu_mask;

	lockdep_assert_held(&p->pi_lock);
	/* The wakeup caller holds pi_lock. Do not take cpuset callback_lock here;
	 * the worker recomputes and validates the authoritative cpuset mask. */
	cpumask_copy(&allowed, task_cpu_possible_mask(p));
	if (p->user_cpus_ptr &&
	    cpumask_and(&preferred, &allowed, p->user_cpus_ptr) &&
	    cpumask_intersects(&preferred, group))
		cpumask_copy(&allowed, &preferred);
	cpumask_and(&allowed, &allowed, group);
	return hmp_idle_group_cpu(&allowed, type);
}

/* Caller supplies a task reference. This is the common proc/automatic entry. */
static int hmp_move_task_to_group(struct task_struct *p, hmp_type_e type,
				enum hmp_migration_reason reason, int cpu)
{
	cpumask_var_t mask;
	cpumask_t user, preferred;
	const struct cpumask *group = type == HMP_AI ?
		&ai_cpu_mask : &regular_cpu_mask;
	bool has_user_mask;
	int ret = -EAGAIN;

	if (!alloc_cpumask_var(&mask, GFP_KERNEL))
		return -ENOMEM;
	mutex_lock(&hmp_migration_mutex);
	if (reason == HMP_MANUAL)
		__hmp_prefer_cancel_proposal(p);
	/* user_cpus_ptr is replaced under pi_lock; use only this stable copy. */
	has_user_mask = hmp_prefer_user_mask(p, &user);
	/* Only the existing manual path may power up an offline AI CPU. */
	if (reason == HMP_MANUAL && type == HMP_AI &&
	    !cpumask_intersects(group, cpu_online_mask)) {
		int first = cpumask_first(group);

		if (first >= nr_cpu_ids) {
			ret = -ENODEV;
			goto out_mutex;
		}
		ret = cpu_device_up(get_cpu_device(first));
		if (ret)
			goto out_mutex;
	}

	cpus_read_lock();
	cpuset_lock();
	cpuset_cpus_allowed(p, mask);
	if (has_user_mask) {
		cpumask_and(&preferred, mask, &user);
		if (cpumask_intersects(&preferred, group))
			cpumask_copy(mask, &preferred);
	}
	cpumask_and(mask, mask, group);
	if (atomic_read(&system_suspending) ||
	    !cpumask_intersects(mask, cpu_active_mask))
		goto out;
	if (reason != HMP_MANUAL) {
		if (!READ_ONCE(p->prefer_a100) ||
		    !cpu_active(cpu) ||
		    (type == HMP_AI ? !hmp_cpu_is_ai(cpu) : !hmp_cpu_is_regular(cpu)) ||
		    !cpumask_test_cpu(cpu, mask) || !idle_cpu(cpu))
			goto out;
	}
	/* Automatic and exec placement both recheck the same idle CPU in the
	 * stopper. Only the explicit manual interface uses the affinity path. */
	ret = sched_hmp_set_group(p, mask, type,
				 reason == HMP_MANUAL ? -1 : cpu, reason);
	if (!ret && reason == HMP_MANUAL)
		hmp_prefer_manual_assign(p, type);
out:
	cpuset_unlock();
	cpus_read_unlock();
out_mutex:
	mutex_unlock(&hmp_migration_mutex);
	free_cpumask_var(mask);
	return ret;
}

int hmp_set_ai_thread(pid_t raw_pid)
{
	struct task_struct *p;
	pid_t pid;
	int ret;

	if (raw_pid == INT_MIN)
		return -EINVAL;
	pid = raw_pid < 0 ? -raw_pid : raw_pid;
	rcu_read_lock();
	p = pid ? pid_task(find_vpid(pid), PIDTYPE_PID) : current;
	if (p)
		get_task_struct(p);
	rcu_read_unlock();
	if (!p)
		return -ESRCH;
	ret = hmp_move_task_to_group(p, raw_pid < 0 ? HMP_REGULAR : HMP_AI,
					 HMP_MANUAL, -1);
	put_task_struct(p);
	return ret;
}
EXPORT_SYMBOL_GPL(hmp_set_ai_thread);

static bool hmp_runtime_ready(struct task_struct *p)
{
	struct sighand_struct *sighand;
	unsigned long flags;
	bool ready = false;

	if (!READ_ONCE(p->hmp_prefer_ready) && !chimera_task_is_target(p))
		return false;
	sighand = lock_task_sighand(p, &flags);
	if (sighand) {
		__sighandler_t handler =
			sighand->action[CHIMERA_HMP_SIGNAL - 1].sa.sa_handler;

		ready = handler != SIG_DFL && handler != SIG_IGN &&
			!sigismember(&p->blocked, CHIMERA_HMP_SIGNAL);
		unlock_task_sighand(p, &flags);
	}
	return ready;
}

static u32 hmp_prefer_next_generation(struct task_struct *p)
{
	u32 generation = p->prefer_proposal_generation + 1;

	return generation ? generation : 1;
}

/* Queue a source-side preparation request. No scheduling state is changed. */
static int hmp_prefer_propose(struct task_struct *p, hmp_type_e type,
			      enum hmp_migration_reason reason, int cpu,
			      bool reassign)
{
	struct sighand_struct *sighand;
	struct kernel_siginfo info;
	unsigned long flags;
	u32 generation, packed;
	u64 payload;
	int source_group = READ_ONCE(p->prefer_assigned_group);
	int target_group = type == HMP_AI ? HMP_PREFER_GROUP_AI :
		HMP_PREFER_GROUP_REGULAR;
	int retry_type = -1;
	int ret = -EAGAIN;

	if (cpu < 0) {
		atomic64_inc(&prefer_fail_target);
		return -EAGAIN;
	}
	if (!hmp_runtime_ready(p)) {
		atomic64_inc(&prefer_fail_runtime);
		return -EAGAIN;
	}
	/*
	 * Enforce the per-task, per-direction NACK cooldown at the common
	 * proposal boundary so wakeup and manual requests cannot bypass it.
	 */
	if (hmp_prefer_nack_suppressed(p, source_group, target_group))
		return -EAGAIN;
	sighand = lock_task_sighand(p, &flags);
	if (!sighand)
		return -ESRCH;
	if (p->prefer_proposal_state == HMP_PREFER_PROPOSAL_PENDING &&
	    time_after(jiffies, p->prefer_proposal_deadline)) {
		retry_type = p->prefer_pending_group == HMP_PREFER_GROUP_AI ?
			HMP_AI : HMP_REGULAR;
		atomic64_inc(&prefer_fail_timeout);
		if (p->prefer_proposal_reassign)
			hmp_prefer_release_reassign(p, false,
				p->prefer_pending_group == HMP_PREFER_GROUP_AI ?
				HMP_AI : HMP_REGULAR);
		hmp_prefer_release_cpu(p);
		p->prefer_proposal_generation = hmp_prefer_next_generation(p);
		p->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
		p->prefer_proposal_reassign = 0;
		p->prefer_pending_group = HMP_PREFER_GROUP_NONE;
		p->prefer_proposal_assignment_seq = 0;
		p->prefer_target_cpu = -1;
		p->prefer_proposal_deadline = 0;
		flush_chimera_signal_locked(p, CHIMERA_HMP_SIGNAL);
		atomic_or(BIT(retry_type), &prefer_retry_groups);
	}
	if (!p->prefer_a100 ||
	    p->prefer_proposal_state != HMP_PREFER_PROPOSAL_NONE ||
	    (p->flags & (PF_EXITING | PF_KTHREAD)) || p->in_execve ||
	    sighand->action[CHIMERA_HMP_SIGNAL - 1].sa.sa_handler == SIG_DFL ||
	    sighand->action[CHIMERA_HMP_SIGNAL - 1].sa.sa_handler == SIG_IGN ||
	    sigismember(&p->blocked, CHIMERA_HMP_SIGNAL)) {
		atomic64_inc(&prefer_fail_task_state);
		goto out;
	}
	if (!cpu_active(cpu) || !idle_cpu(cpu) ||
	    (type == HMP_AI ? !hmp_cpu_is_ai(cpu) : !hmp_cpu_is_regular(cpu))) {
		atomic64_inc(&prefer_fail_target);
		goto out;
	}
	if (reassign && !hmp_prefer_reserve_reassign(p, type)) {
		atomic64_inc(&prefer_fail_ledger);
		goto out;
	}

	generation = hmp_prefer_next_generation(p);
	p->prefer_proposal_deadline = jiffies +
		msecs_to_jiffies(CHIMERA_HMP_PROPOSAL_TIMEOUT_MS);
	if (!hmp_prefer_reserve_cpu(p, cpu, generation,
				    p->prefer_proposal_deadline, type)) {
		atomic64_inc(&prefer_fail_cpu_reservation);
		if (reassign)
			hmp_prefer_release_reassign(p, false, type);
		p->prefer_proposal_deadline = 0;
		goto out;
	}
	packed = (READ_ONCE(p->thread.vstate.vlenb) & 0x3fff) |
		 ((READ_ONCE(p->thread.vstate.vl) & 0x1ffff) << 14) |
		 CHIMERA_HMP_PAYLOAD_MARKER;
	payload = ((u64)generation << 32) | packed;
	clear_siginfo(&info);
	info.si_signo = CHIMERA_HMP_SIGNAL;
	info.si_code = SI_QUEUE;
	info.si_value.sival_ptr = (void __user *)(uintptr_t)payload;

	p->prefer_proposal_generation = generation;
	p->prefer_proposal_state = HMP_PREFER_PROPOSAL_PENDING;
	p->prefer_proposal_reason = reason;
	p->prefer_proposal_reassign = reassign;
	p->prefer_pending_group = type == HMP_AI ?
		HMP_PREFER_GROUP_AI : HMP_PREFER_GROUP_REGULAR;
	p->prefer_target_cpu = cpu;
	ret = send_chimera_signal_locked(CHIMERA_HMP_SIGNAL, &info, p,
					 PIDTYPE_PID);
	if (ret) {
		atomic64_inc(&prefer_fail_signal);
		hmp_prefer_release_cpu(p);
		if (reassign)
			hmp_prefer_release_reassign(p, false, type);
		p->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
		p->prefer_proposal_reassign = 0;
		p->prefer_pending_group = HMP_PREFER_GROUP_NONE;
		p->prefer_proposal_assignment_seq = 0;
		p->prefer_target_cpu = -1;
		p->prefer_proposal_deadline = 0;
	}
out:
	unlock_task_sighand(p, &flags);
	if (retry_type >= 0)
		mod_delayed_work(prefer_wq, &prefer_retry_work,
				 msecs_to_jiffies(100));
	/*
	 * Every proposal needs a timeout.  Initial placement does not reserve a
	 * ledger transfer, but an unhandled signal must still release its CPU and
	 * leave PENDING so a later idle event can retry it.  Queue an immediate scan
	 * unconditionally: it cannot postpone an earlier deadline and also closes
	 * the race where the timeout worker has finished its last scan but has not
	 * returned yet.  That scan will arm the exact earliest deadline.
	 */
	if (!ret)
		mod_delayed_work(prefer_wq, &prefer_timeout_work, 0);
	return ret;
}

static struct task_struct *hmp_prefer_find_expired_proposal(
						unsigned long *next_delay)
{
	struct task_struct *g, *p, *found = NULL;
	unsigned long deadline, earliest = 0;

	*next_delay = 0;
	rcu_read_lock();
	for_each_process_thread(g, p) {
		if (READ_ONCE(p->prefer_proposal_state) !=
		    HMP_PREFER_PROPOSAL_PENDING)
			continue;
		deadline = READ_ONCE(p->prefer_proposal_deadline);
		if (!deadline)
			continue;
		if (time_after_eq(jiffies, deadline)) {
			get_task_struct(p);
			found = p;
			break;
		}
		if (!earliest || time_before(deadline, earliest))
			earliest = deadline;
	}
	rcu_read_unlock();
	if (!found && earliest)
		*next_delay = time_after_eq(jiffies, earliest) ? 1 :
			earliest - jiffies + 1;
	return found;
}

static void hmp_prefer_timeout_workfn(struct work_struct *work)
{
	struct task_struct *p;
	struct sighand_struct *sighand;
	unsigned long flags;
	unsigned long delay = 0;
	bool expired = false;

	while ((p = hmp_prefer_find_expired_proposal(&delay))) {
		mutex_lock(&hmp_migration_mutex);
		sighand = lock_task_sighand(p, &flags);
		if (sighand) {
			if (p->prefer_proposal_state == HMP_PREFER_PROPOSAL_PENDING &&
			    p->prefer_proposal_deadline &&
			    time_after_eq(jiffies, p->prefer_proposal_deadline)) {
				atomic64_inc(&prefer_fail_timeout);
				if (p->prefer_proposal_reassign)
					hmp_prefer_release_reassign(p, false,
						p->prefer_pending_group ==
						HMP_PREFER_GROUP_AI ? HMP_AI : HMP_REGULAR);
				atomic_or(BIT(p->prefer_pending_group ==
					      HMP_PREFER_GROUP_AI ? HMP_AI : HMP_REGULAR),
					  &prefer_retry_groups);
				hmp_prefer_release_cpu(p);
				p->prefer_proposal_generation = hmp_prefer_next_generation(p);
				p->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
				p->prefer_proposal_reason = 0;
				p->prefer_proposal_reassign = 0;
				p->prefer_pending_group = HMP_PREFER_GROUP_NONE;
				p->prefer_proposal_assignment_seq = 0;
				p->prefer_target_cpu = -1;
				p->prefer_proposal_deadline = 0;
				flush_chimera_signal_locked(p, CHIMERA_HMP_SIGNAL);
				expired = true;
			}
			unlock_task_sighand(p, &flags);
		} else if (p->prefer_proposal_state == HMP_PREFER_PROPOSAL_PENDING &&
			   p->prefer_proposal_deadline &&
			   time_after_eq(jiffies, p->prefer_proposal_deadline)) {
			/* The exiting task has no sighand, hence cannot concurrently ACK. */
			if (p->prefer_proposal_reassign)
				hmp_prefer_release_reassign(p, false,
					p->prefer_pending_group == HMP_PREFER_GROUP_AI ?
					HMP_AI : HMP_REGULAR);
			hmp_prefer_release_cpu(p);
			p->prefer_proposal_generation = hmp_prefer_next_generation(p);
			p->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
			p->prefer_proposal_reassign = 0;
			p->prefer_pending_group = HMP_PREFER_GROUP_NONE;
			p->prefer_proposal_assignment_seq = 0;
			p->prefer_target_cpu = -1;
			p->prefer_proposal_deadline = 0;
			expired = true;
		}
		mutex_unlock(&hmp_migration_mutex);
		put_task_struct(p);
	}
	if (delay)
		mod_delayed_work(prefer_wq, &prefer_timeout_work, delay);
	if (expired) {
		mod_delayed_work(prefer_wq, &prefer_retry_work,
				 msecs_to_jiffies(100));
		hmp_prefer_kick_rebalance();
	}
}

static void hmp_prefer_retry_workfn(struct work_struct *work)
{
	int groups = atomic_xchg(&prefer_retry_groups, 0);
	int type;

	for (type = HMP_REGULAR; type <= HMP_AI; type++) {
		int cpu;

		if (!(groups & BIT(type)))
			continue;
		atomic64_inc(&prefer_candidate_generation[type]);
		cpu = hmp_idle_group_cpu(NULL, type);
		if (cpu >= 0 && atomic_read(&prefer_pending)) {
			atomic_or(BIT(type), &prefer_retry_groups);
			mod_delayed_work(prefer_wq, &prefer_retry_work, 1);
		} else if (cpu >= 0 &&
			   !hmp_prefer_queue(NULL, cpu, HMP_IDLE_PULL, true)) {
			atomic_or(BIT(type), &prefer_retry_groups);
			mod_delayed_work(prefer_wq, &prefer_retry_work,
					 msecs_to_jiffies(10));
		}
	}
	hmp_prefer_kick_rebalance();
}

static ssize_t hmp_prefer_ack_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct hmp_prefer_ack ack;
	struct sighand_struct *sighand;
	cpumask_var_t mask;
	unsigned long flags;
	enum hmp_migration_reason reason;
	hmp_type_e type;
	bool reassign = false, nack, record_nack = false;
	int source_group = HMP_PREFER_GROUP_NONE;
	int target_group = HMP_PREFER_GROUP_NONE;
	u64 cpu_cookie = 0;
	int cpu, ret;

	if (count != sizeof(ack))
		return -EINVAL;
	if (copy_from_user(&ack, buf, sizeof(ack)))
		return -EFAULT;
	if (ack.action > HMP_PREFER_ACK_CAPABILITY_CHANGED)
		return -EINVAL;
	nack = ack.action != HMP_PREFER_ACK_COMMIT &&
		ack.action <= HMP_PREFER_ACK_NACK_SAFEPOINT;
	if (nack)
		cpu_cookie = hmp_prefer_cpu_cookie(current);

	/* Serialize ACK commit with the existing arbitrary-PID manual path. */
	mutex_lock(&hmp_migration_mutex);
	sighand = lock_task_sighand(current, &flags);
	if (!sighand) {
		ret = -ESRCH;
		goto out_mutex;
	}
	if (ack.action == HMP_PREFER_ACK_STATE_ORIGINAL ||
	    ack.action == HMP_PREFER_ACK_CAPABILITY_CHANGED) {
		if (!READ_ONCE(current->prefer_a100) &&
		    !READ_ONCE(current->hmp_prefer_ready)) {
			ret = -EPERM;
			goto out_unlock;
		}
		hmp_prefer_clear_nack(current);
		if (ack.action == HMP_PREFER_ACK_CAPABILITY_CHANGED)
			current->prefer_capability_generation++;
		unlock_task_sighand(current, &flags);
		atomic64_inc(&prefer_candidate_generation[HMP_REGULAR]);
		atomic64_inc(&prefer_candidate_generation[HMP_AI]);
		hmp_prefer_kick_rebalance();
		ret = count;
		goto out_mutex;
	}
	if (current->prefer_proposal_state != HMP_PREFER_PROPOSAL_PENDING ||
	    current->prefer_proposal_generation != ack.generation) {
		ret = -ESTALE;
		goto out_unlock;
	}
	if (nack ||
	    time_after(jiffies, current->prefer_proposal_deadline)) {
		if (nack) {
			atomic64_inc(&prefer_fail_nack);
			if (ack.action == HMP_PREFER_ACK_NACK_TRANSLATED)
				atomic64_inc(&prefer_nack_translated);
			else if (ack.action == HMP_PREFER_ACK_NACK_MISSING_ROUTE)
				atomic64_inc(&prefer_nack_missing_route);
			else
				atomic64_inc(&prefer_nack_prepare);
			source_group = current->prefer_assigned_group;
			target_group = current->prefer_pending_group;
			record_nack = true;
		} else {
			atomic64_inc(&prefer_fail_timeout);
		}
		if (current->prefer_proposal_reassign)
			hmp_prefer_release_reassign(current, false,
				current->prefer_pending_group == HMP_PREFER_GROUP_AI ?
				HMP_AI : HMP_REGULAR);
		hmp_prefer_release_cpu(current);
		current->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
		current->prefer_proposal_reassign = 0;
		current->prefer_pending_group = HMP_PREFER_GROUP_NONE;
		current->prefer_proposal_assignment_seq = 0;
		current->prefer_target_cpu = -1;
		current->prefer_proposal_deadline = 0;
		ret = nack ? 0 : -ETIMEDOUT;
		goto out_unlock;
	}
	type = current->prefer_pending_group == HMP_PREFER_GROUP_AI ?
		HMP_AI : HMP_REGULAR;
	reassign = current->prefer_proposal_reassign;
	cpu = current->prefer_target_cpu;
	reason = current->prefer_proposal_reason;
	current->prefer_proposal_state = HMP_PREFER_PROPOSAL_COMMITTING;
	unlock_task_sighand(current, &flags);

	if (!alloc_cpumask_var(&mask, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto out_finish;
	}
	cpus_read_lock();
	cpuset_lock();
	cpuset_cpus_allowed(current, mask);
	cpumask_and(mask, mask, type == HMP_AI ? &ai_cpu_mask : &regular_cpu_mask);
	if (!cpumask_test_cpu(cpu, mask)) {
		atomic64_inc(&prefer_fail_cpuset);
		ret = -EPERM;
	} else {
		ret = sched_hmp_ack_current(mask, type, cpu, reason,
					    ack.generation);
		if (ret)
			atomic64_inc(&prefer_fail_stopper);
	}
	cpuset_unlock();
	cpus_read_unlock();
	free_cpumask_var(mask);

out_finish:
	sighand = lock_task_sighand(current, &flags);
	if (!sighand) {
		ret = ret ?: -ESRCH;
		goto out_mutex;
	}
	if (current->prefer_proposal_generation == ack.generation &&
	    current->prefer_proposal_state == HMP_PREFER_PROPOSAL_COMMITTING) {
		if (reassign)
			hmp_prefer_release_reassign(current, !ret, type);
		hmp_prefer_release_cpu(current);
		current->prefer_proposal_state = HMP_PREFER_PROPOSAL_NONE;
		current->prefer_proposal_reassign = 0;
		current->prefer_pending_group = HMP_PREFER_GROUP_NONE;
		current->prefer_proposal_assignment_seq = 0;
		current->prefer_target_cpu = -1;
		current->prefer_proposal_deadline = 0;
	}
out_unlock:
	unlock_task_sighand(current, &flags);
	if (record_nack)
		hmp_prefer_record_nack(current, source_group, target_group,
				       cpu_cookie);
	if (reassign && !nack)
		hmp_prefer_kick_rebalance();
	if (ret)
		goto out_mutex;
	if (nack)
		goto out_success;
	if (!reassign)
		hmp_prefer_manual_assign(current, type);
	riscv_v_chimera_reset_current();
	if (type == HMP_AI)
		atomic64_inc(&prefer_migrations);
	else
		atomic64_inc(&prefer_overflow_migrations);
	if (reason == HMP_INITIAL)
		atomic64_inc(&prefer_initial);
out_success:
	ret = count;
out_mutex:
	mutex_unlock(&hmp_migration_mutex);
	return ret;
}

static void hmp_prefer_workfn(struct work_struct *work)
{
	struct task_struct *tasks[16];
	enum hmp_migration_reason reason = READ_ONCE(prefer_reason);
	int cpu = READ_ONCE(prefer_cpu);
	unsigned int i, count, budget = ARRAY_SIZE(tasks);
	unsigned int cursor = READ_ONCE(prefer_cursor);
	unsigned int proposed = 0;
	hmp_type_e idle_type = hmp_cpu_is_ai(cpu) ? HMP_AI : HMP_REGULAR;
	u64 hint = atomic64_read(&prefer_candidate_generation[idle_type]);
	bool complete_scan = false;

	/* Own and clear the queued reference before another request can start. */
	if (READ_ONCE(prefer_task)) {
		tasks[0] = xchg(&prefer_task, NULL);
		count = 1;
	} else {
		count = 0;
	}
	if (count) {
		hmp_type_e type = reason == HMP_IDLE_PULL ? idle_type :
			(READ_ONCE(tasks[0]->prefer_assigned_group) ==
			 HMP_PREFER_GROUP_AI ? HMP_AI : HMP_REGULAR);
		int target_group = type == HMP_AI ? HMP_PREFER_GROUP_AI :
			HMP_PREFER_GROUP_REGULAR;
		int assigned_group = READ_ONCE(tasks[0]->prefer_assigned_group);
		bool reassign = assigned_group != target_group;
		cpu = hmp_idle_group_cpu_for_task(tasks[0], type);
		if (assigned_group == target_group &&
		    READ_ONCE(tasks[0]->thread_type) == type) {
			atomic64_inc(&prefer_same_group_skipped);
		} else if (cpu >= 0 &&
		    !hmp_prefer_propose(tasks[0], type, reason, cpu, reassign)) {
			proposed++;
		}
		put_task_struct(tasks[0]);
	} else if (reason == HMP_IDLE_PULL && hint) {
		hmp_type_e type = idle_type;
		while (budget-- && cpu >= 0) {
			bool moved = false;
			bool eligible = false;

			count = sched_hmp_candidates(tasks, ARRAY_SIZE(tasks), cpu,
							     &cursor);
			for (i = 0; i < count; i++) {
				int target_group = type == HMP_AI ?
					HMP_PREFER_GROUP_AI : HMP_PREFER_GROUP_REGULAR;
				int assigned_group =
					READ_ONCE(tasks[i]->prefer_assigned_group);
				int candidate_cpu = hmp_idle_group_cpu_for_task(tasks[i], type);

				if (assigned_group == target_group &&
				    READ_ONCE(tasks[i]->thread_type) == type) {
					atomic64_inc(&prefer_same_group_skipped);
					put_task_struct(tasks[i]);
					continue;
				}
				if (!moved && candidate_cpu >= 0 &&
				    hmp_prefer_task_allowed_cpu(tasks[i], candidate_cpu) &&
				    hmp_runtime_ready(tasks[i])) {
					eligible = assigned_group != HMP_PREFER_GROUP_NONE;
					if (!moved && eligible &&
					    !hmp_prefer_propose(tasks[i], type,
							     reason, candidate_cpu,
							     assigned_group != target_group)) {
						moved = true;
						proposed++;
					}
				}
				put_task_struct(tasks[i]);
			}
			if (!moved) {
				complete_scan = !eligible && count < ARRAY_SIZE(tasks);
				break;
			}
			/* A proposal does not occupy the rq yet. Do not hand the same
			 * idle CPU to another in-flight generation. */
			break;
		}
	}

	if (complete_scan)
		atomic64_cmpxchg(&prefer_candidate_generation[idle_type], hint, 0);
	if (proposed)
		atomic64_add(proposed, &prefer_proposals);
	else {
		atomic64_inc(&prefer_failures);
		if (reason == HMP_IDLE_PULL)
			WRITE_ONCE(prefer_scan_after[idle_type],
				jiffies + msecs_to_jiffies(10));
	}
	if (reason == HMP_IDLE_PULL)
		WRITE_ONCE(prefer_cursor, proposed ? 0 : cursor);
	/* No shared request fields may be touched after releasing this slot. */
	atomic_set_release(&prefer_pending, 0);
	if (reason == HMP_IDLE_PULL) {
		int next = hmp_idle_group_cpu(NULL, idle_type);
		u64 current_hint =
			atomic64_read(&prefer_candidate_generation[idle_type]);

		/* A proposal leaves the destination idle until userspace ACKs it.
		 * Requeueing merely because one was sent spins on that same idle CPU
		 * while the task is still preparing (or NACKing) the request. ACK,
		 * exit, and new candidate events advance the generation instead. */
		if (next >= 0 && current_hint && current_hint != hint)
			hmp_prefer_queue(NULL, next, HMP_IDLE_PULL,
				 true);
	} else if (atomic64_read(&prefer_candidate_generation[idle_type])) {
		/* A hint arriving while the single request slot was occupied may have
		 * missed its direct queue attempt. Give it an idle-pull event now. */
		int next = hmp_idle_group_cpu(NULL, idle_type);

		if (next >= 0)
			hmp_prefer_queue(NULL, next, HMP_IDLE_PULL, true);
	}
}

/* Defer worker wakeup until the scheduler's rq/PI locks have been released. */
static void hmp_prefer_irqfn(struct irq_work *work)
{
	if (!queue_work(prefer_wq, &prefer_work)) {
		struct task_struct *p = xchg(&prefer_task, NULL);

		if (p)
			put_task_struct(p);
		atomic_set_release(&prefer_pending, 0);
	}
}

static bool hmp_prefer_queue(struct task_struct *p, int cpu,
			     enum hmp_migration_reason reason, bool reset_cursor)
{
	if (!READ_ONCE(prefer_service_ready))
		return false;
	if (reason == HMP_IDLE_PULL &&
	    time_before(jiffies,
		READ_ONCE(prefer_scan_after[hmp_cpu_is_ai(cpu) ? HMP_AI :
							HMP_REGULAR])))
		return false;
	if (atomic_cmpxchg_acquire(&prefer_pending, 0, 1))
		return false;
	if (reset_cursor)
		WRITE_ONCE(prefer_cursor, 0);
	if (p)
		get_task_struct(p);
	prefer_task = p;
	prefer_cpu = cpu;
	prefer_reason = reason;
	if (reason == HMP_IDLE_PULL)
		atomic64_inc(&prefer_attempts);
	if (!irq_work_queue(&prefer_irq_work)) {
		p = xchg(&prefer_task, NULL);
		if (p)
			put_task_struct(p);
		atomic_set_release(&prefer_pending, 0);
		return false;
	}
	return true;
}

void hmp_prefer_idle(int cpu)
{
	hmp_type_e type = hmp_cpu_is_ai(cpu) ? HMP_AI : HMP_REGULAR;

	if (READ_ONCE(prefer_service_ready) &&
	    (hmp_cpu_is_ai(cpu) || hmp_cpu_is_regular(cpu)) && cpu_active(cpu) &&
	    atomic64_read(&prefer_candidate_generation[type]))
		hmp_prefer_queue(NULL, cpu, HMP_IDLE_PULL, true);
}

int hmp_prefer_wakeup(struct task_struct *p, bool is_fork)
{
	cpumask_t allowed, ai_allowed, regular_allowed;
	hmp_type_e target, reassign_target;
	int cpu;

	if (!READ_ONCE(p->prefer_a100) ||
	    p->in_execve)
		return -1;

	/* The fork path is the only path where the task is not yet on a runqueue, so
	 * its inherited affinity can be switched before select_task_rq commits
	 * the first CPU. */
	if (is_fork) {
		cpumask_copy(&allowed, p->cpus_ptr);
		cpumask_and(&ai_allowed, &allowed, &ai_cpu_mask);
		if (!cpumask_empty(&ai_allowed)) {
			p->thread_type = HMP_AI;
			cpumask_copy(&p->cpus_mask, &ai_allowed);
			p->nr_cpus_allowed = cpumask_weight(&ai_allowed);
			p->cpus_ptr = &p->cpus_mask;
			return hmp_idle_ai_cpu(&ai_allowed);
		}
		cpumask_and(&regular_allowed, &allowed, &regular_cpu_mask);
		if (!cpumask_empty(&regular_allowed)) {
			p->thread_type = HMP_REGULAR;
			cpumask_copy(&p->cpus_mask, &regular_allowed);
			p->nr_cpus_allowed = cpumask_weight(&regular_allowed);
			p->cpus_ptr = &p->cpus_mask;
		}
		return -1;
	}

	if (READ_ONCE(p->prefer_assigned_group) == HMP_PREFER_GROUP_AI)
		target = HMP_AI;
	else if (READ_ONCE(p->prefer_assigned_group) == HMP_PREFER_GROUP_REGULAR)
		target = HMP_REGULAR;
	else
		return -1;
	if (READ_ONCE(p->thread_type) == target) {
		if (hmp_prefer_task_reassign_target(p, &reassign_target)) {
			hmp_prefer_task_hint(p);
			cpu = hmp_idle_group_cpu_for_task_locked(p,
							      reassign_target);
			if (cpu >= 0)
				hmp_prefer_queue(p, cpu, HMP_IDLE_PULL, true);
		}
		return -1;
	}
	hmp_prefer_task_hint(p);
	cpu = hmp_idle_group_cpu_for_task_locked(p, target);
	if (cpu >= 0)
		hmp_prefer_queue(p, cpu, HMP_INITIAL, true);
	return -1;
}

void hmp_prefer_exec(struct task_struct *p)
{
	/* The old image's handler cannot safely prepare the new image.  Runtime
	 * registration after exec will queue the initial proposal. */
	hmp_prefer_cancel_proposal(p);
}

static int hmp_prefer_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "regular_cpus %*pbl\nai_cpus %*pbl\n",
		   cpumask_pr_args(&regular_cpu_mask),
		   cpumask_pr_args(&ai_cpu_mask));
	seq_printf(m, "prefer_assigned_regular %u\nprefer_assigned_ai %u\n",
		   READ_ONCE(prefer_regular_tasks), READ_ONCE(prefer_ai_tasks));
	seq_printf(m, "prefer_pending_to_regular %u\nprefer_pending_to_ai %u\n",
		   READ_ONCE(prefer_pending_to_regular),
		   READ_ONCE(prefer_pending_to_ai));
	seq_printf(m, "prefer_a100_initial_placements %lld\n",
		   atomic64_read(&prefer_initial));
	seq_printf(m, "prefer_a100_idle_pull_attempts %lld\n",
		   atomic64_read(&prefer_attempts));
	seq_printf(m, "prefer_a100_proposals %lld\n",
		   atomic64_read(&prefer_proposals));
	seq_printf(m, "prefer_a100_x100_to_a100_migrations %lld\n",
		   atomic64_read(&prefer_migrations));
	seq_printf(m, "prefer_a100_a100_to_x100_migrations %lld\n",
		   atomic64_read(&prefer_overflow_migrations));
	seq_printf(m, "prefer_a100_pull_failures %lld\n",
		   atomic64_read(&prefer_failures));
	seq_printf(m, "prefer_a100_fail_runtime %lld\n",
		   atomic64_read(&prefer_fail_runtime));
	seq_printf(m, "prefer_a100_fail_task_state %lld\n",
		   atomic64_read(&prefer_fail_task_state));
	seq_printf(m, "prefer_a100_fail_target %lld\n",
		   atomic64_read(&prefer_fail_target));
	seq_printf(m, "prefer_a100_fail_ledger %lld\n",
		   atomic64_read(&prefer_fail_ledger));
	seq_printf(m, "prefer_a100_fail_cpu_reservation %lld\n",
		   atomic64_read(&prefer_fail_cpu_reservation));
	seq_printf(m, "prefer_a100_fail_signal %lld\n",
		   atomic64_read(&prefer_fail_signal));
	seq_printf(m, "prefer_a100_fail_nack %lld\n",
		   atomic64_read(&prefer_fail_nack));
	seq_printf(m, "prefer_a100_same_group_skipped %lld\n",
		   atomic64_read(&prefer_same_group_skipped));
	seq_printf(m, "prefer_a100_nack_translated %lld\n",
		   atomic64_read(&prefer_nack_translated));
	seq_printf(m, "prefer_a100_nack_missing_route %lld\n",
		   atomic64_read(&prefer_nack_missing_route));
	seq_printf(m, "prefer_a100_nack_prepare_or_safepoint %lld\n",
		   atomic64_read(&prefer_nack_prepare));
	seq_printf(m, "prefer_a100_cooldown_suppressed %lld\n",
		   atomic64_read(&prefer_cooldown_suppressed));
	seq_printf(m, "prefer_a100_cpu_reservations %u\n",
		   hmp_prefer_reserved_cpu_count());
	seq_printf(m, "prefer_a100_fail_timeout %lld\n",
		   atomic64_read(&prefer_fail_timeout));
	seq_printf(m, "prefer_a100_fail_cpuset %lld\n",
		   atomic64_read(&prefer_fail_cpuset));
	seq_printf(m, "prefer_a100_fail_stopper %lld\n",
		   atomic64_read(&prefer_fail_stopper));
	return 0;
}

/*
 * Positive TID opts in after userspace has prepared both execution forms.
 * Negative TID disables preference. This interface does not register BPF
 * metadata or replace the Chimera runtime. A scalar test needs neither.
 */
static ssize_t hmp_prefer_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct task_struct *p;
	int tid, cpu;
	unsigned long flags;

	if (kstrtoint_from_user(buf, count, 10, &tid) || !tid || tid == INT_MIN)
		return -EINVAL;
	rcu_read_lock();
	p = pid_task(find_vpid(tid < 0 ? -tid : tid), PIDTYPE_PID);
	if (p)
		get_task_struct(p);
	rcu_read_unlock();
	if (!p)
		return -ESRCH;
	raw_spin_lock_irqsave(&p->pi_lock, flags);
	if ((p->flags & (PF_KTHREAD | PF_EXITING)) || p->in_execve) {
		raw_spin_unlock_irqrestore(&p->pi_lock, flags);
		put_task_struct(p);
		return -EBUSY;
	}
	WRITE_ONCE(p->hmp_prefer_ready, tid > 0);
	WRITE_ONCE(p->prefer_a100, tid > 0);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);
	if (tid > 0) {
		hmp_prefer_register(p);
		hmp_prefer_task_hint(p);
		if (READ_ONCE(p->prefer_assigned_group) == HMP_PREFER_GROUP_AI)
			cpu = hmp_idle_ai_cpu_for_task(p);
		else
			cpu = hmp_idle_group_cpu_for_task(p, HMP_REGULAR);
		if (cpu >= 0 && ((READ_ONCE(p->prefer_assigned_group) ==
				 HMP_PREFER_GROUP_AI && READ_ONCE(p->thread_type) == HMP_REGULAR) ||
				(READ_ONCE(p->prefer_assigned_group) == HMP_PREFER_GROUP_REGULAR &&
				 READ_ONCE(p->thread_type) == HMP_AI)))
			hmp_prefer_queue(p, cpu, HMP_INITIAL, true);
	} else {
		hmp_prefer_unregister(p);
	}
	put_task_struct(p);
	return count;
}

static int hmp_prefer_open(struct inode *inode, struct file *file)
{
	return single_open(file, hmp_prefer_stats_show, NULL);
}

static const struct proc_ops hmp_prefer_ops = {
	.proc_open = hmp_prefer_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = hmp_prefer_write,
};

static const struct proc_ops hmp_prefer_ack_ops = {
	.proc_write = hmp_prefer_ack_write,
};

static ssize_t proc_set_thread_type(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	pid_t pid;
	int ret = 0;

	if (!capable(CAP_SYS_NICE))
		return -EPERM;

	if (kstrtoint_from_user(buf, count, 10, &pid))
		return -EINVAL;

	if (pid < 0)
	{
		chimera_info("%s: pid:%u, set 1024 --- 256 bit!!!\n",
			__func__, -pid);
	}

	ret = hmp_set_ai_thread(pid);
	return ret == 0 ? count : ret;
}

static const struct proc_ops thread_type_proc_ops = {
	.proc_write = proc_set_thread_type,
};


static int __init hmp_service_init(void)
{
	int ret;
	struct workqueue_attrs *attrs;
	struct proc_dir_entry *stats, *prefer, *ack;

	/* A worker on the destination would consume the idle opportunity. */
	prefer_wq = alloc_workqueue("prefer_a100", WQ_UNBOUND, 1);
	if (!prefer_wq)
		return -ENOMEM;
	attrs = alloc_workqueue_attrs();
	if (!attrs) {
		destroy_workqueue(prefer_wq);
		return -ENOMEM;
	}
	cpumask_copy(attrs->cpumask, &regular_cpu_mask);
	ret = apply_workqueue_attrs(prefer_wq, attrs);
	free_workqueue_attrs(attrs);
	if (ret) {
		destroy_workqueue(prefer_wq);
		return ret;
	}

	/* register the platform suspend call-back for migrating
	 * some thread from one type to the boot-core type.
	 */
	atomic_set(&system_suspending, 0);
	ret = register_pm_notifier(&pm_notifier);
	if (ret) {
		pr_err("Failed to register PM notifier: %d\n", ret);
		goto destroy_wq;
	}

	/* create proc fs node for user set thread type */
	stats = proc_create_single("prefer_a100_stats", 0444, NULL,
				   hmp_prefer_stats_show);
	if (!stats) {
		ret = -ENOMEM;
		goto unregister_pm;
	}
	prefer = proc_create("prefer_a100", 0600, NULL, &hmp_prefer_ops);
	if (!prefer) {
		ret = -ENOMEM;
		goto remove_stats;
	}
	ack = proc_create("prefer_a100_ack", 0222, NULL, &hmp_prefer_ack_ops);
	if (!ack) {
		ret = -ENOMEM;
		goto remove_prefer;
	}
	if (!proc_create("set_ai_thread", 0200, NULL, &thread_type_proc_ops)) {
		pr_err("Failed to create proc interface\n");
		ret = -ENOMEM;
		goto remove_ack;
	}

	WRITE_ONCE(prefer_service_ready, true);
	return 0;

remove_ack:
	proc_remove(ack);
remove_prefer:
	proc_remove(prefer);
remove_stats:
	proc_remove(stats);
unregister_pm:
	unregister_pm_notifier(&pm_notifier);
destroy_wq:
	destroy_workqueue(prefer_wq);
	return ret;
}
late_initcall(hmp_service_init);
