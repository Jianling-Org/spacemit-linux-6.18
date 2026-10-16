/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2025 Spacemit */

#ifndef _SPACEMIT_HMP_H_
#define _SPACEMIT_HMP_H_

typedef enum {
	/* regular thread is the default type, should be 0 */
	HMP_REGULAR = 0,
	HMP_AI = 1,
} hmp_type_e;

void hmp_cpumask_init(void);
bool hmp_set_default_cpumask(struct task_struct *p);
bool hmp_cpu_can_offline(unsigned int cpu);
int hmp_cpu_affinity_restrict(struct task_struct *p, const struct cpumask *new_mask);
int hmp_set_ai_thread(pid_t pid);
int hmp_get_cpumask(struct cpumask *mask, hmp_type_e type);
int hmp_map_ai_to_regular(struct cpumask *mask);

#ifdef CONFIG_SPACEMIT_HMP
#define CHIMERA_HMP_SIGNAL 41
#define CHIMERA_HMP_PAYLOAD_MARKER BIT(31)
#define CHIMERA_HMP_PROPOSAL_TIMEOUT_MS 1000

enum hmp_prefer_ack_action {
	HMP_PREFER_ACK_NACK = 0,
	HMP_PREFER_ACK_COMMIT = 1,
};

struct hmp_prefer_ack {
	u32 generation;
	u32 action;
};

enum hmp_prefer_group {
	HMP_PREFER_GROUP_NONE = 0,
	HMP_PREFER_GROUP_AI = 1,
	HMP_PREFER_GROUP_REGULAR = 2,
};

enum hmp_migration_reason {
	HMP_MANUAL,
	HMP_INITIAL,
	HMP_IDLE_PULL,
	HMP_EXEC,
};

enum hmp_prefer_proposal_state {
	HMP_PREFER_PROPOSAL_NONE = 0,
	HMP_PREFER_PROPOSAL_PENDING,
	HMP_PREFER_PROPOSAL_COMMITTING,
};

bool hmp_cpu_is_ai(int cpu);
bool hmp_cpu_is_regular(int cpu);
bool hmp_prefer_can_migrate(void);
void hmp_prefer_exec(struct task_struct *p);
int hmp_prefer_wakeup(struct task_struct *p, bool is_fork);
void hmp_prefer_idle(int cpu);
bool hmp_prefer_task_allowed_cpu(struct task_struct *p, int cpu);
void hmp_prefer_task_hint(struct task_struct *p);
void hmp_prefer_register(struct task_struct *p);
void hmp_prefer_inherit_fork(struct task_struct *p);
void hmp_prefer_unregister(struct task_struct *p);
void hmp_prefer_post_fork(struct task_struct *p);
/* Scheduler implementation; caller holds cpuset and CPU hotplug locks. */
int sched_hmp_set_group(struct task_struct *p, const struct cpumask *mask,
		       hmp_type_e type, int idle_cpu,
		       enum hmp_migration_reason reason);
int sched_hmp_ack_current(const struct cpumask *mask, hmp_type_e type,
			  int target_cpu, enum hmp_migration_reason reason,
			  u32 generation);
unsigned int sched_hmp_candidates(struct task_struct **tasks, unsigned int limit,
				  int target_cpu, unsigned int *cursor);
#ifdef CONFIG_BPF_SYSCALL
bool chimera_task_is_target(struct task_struct *p);
#else
static inline bool chimera_task_is_target(struct task_struct *p) { return false; }
#endif
#endif

#endif /* _SPACEMIT_HMP_H_ */
