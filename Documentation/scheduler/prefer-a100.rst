Prefer A100 idle capacity
========================

This Spacemit HMP policy prefers idle AI CPUs for opted-in fair-class tasks.
It uses the existing device-tree-derived HMP regular/AI masks. It does not
score performance, swap tasks, evict an AI task, or initiate AI-to-regular
migration. Existing explicit group changes remain available.

Userspace interface
-------------------

Root can opt a thread into the policy after preparing it to execute on both
groups::

    echo TID > /proc/prefer_a100

Writing a negative TID disables the policy::

    echo -TID > /proc/prefer_a100

The write acknowledges a preference, not completion of a migration. A task
already on AI stays there when preference is disabled. Kernel threads and
tasks committing exec cannot be opted in through this interface.

For a scalar scheduling experiment, a program compiled without RVV can use
this interface directly. Production Chimera programs must first prepare the
appropriate code, vector state handling, registration and signal handler.
This interface does not create a BPF registration, install a handler, or
perform userspace code conversion.

The existing Chimera executable registration/exec match also sets
``task_struct.prefer_a100``. Preference and explicit readiness are inherited
by fork/clone and cleared at the point of no return of every exec, including
non-ELF exec. A subsequent registered ELF match sets preference again.

Inspection::

    cat /proc/prefer_a100_stats
    grep -E 'Prefer_a100|Hmp_thread_type|Cpus_allowed' /proc/TID/status

``Hmp_thread_type`` is 0 for regular and 1 for AI. The statistics file also
reports the actual HMP CPU masks. The trace event
``sched:sched_prefer_a100_migrate`` reports TID, source CPU, destination CPU
and reason (``INITIAL`` or ``IDLE_PULL``). The ordinary
``sched:sched_migrate_task`` tracepoint remains in the physical migration
path, including the existing BPF/kfunc notification hook.

Placement and idle pull
-----------------------

At a registered ELF exec, an idle allowed AI CPU is selected before the new
image executes userspace instructions. With no such CPU the regular path
continues. A new image has no old-image PC/vector state to convert: the
``hmp_exec_placement`` flag suppresses signal 41 only during this initial
placement. Sending it before the new handler exists could kill the image.

``select_task_rq_fair()`` requests a deferred attempt for a waking opted-in
regular task. It does not sleep or alter affinity in the wakeup selection
path. An irq-work callback waits until scheduler locks have been released
before waking the regular-CPU workqueue. Consequently a wakeup may execute
on regular before this attempt
commits. Initial placement, like ordinary scheduler CPU selection, is
opportunistic; another workload may wake after the idle observation.

``sched_balance_newidle()`` requests an idle pull when an AI runqueue is
about to become idle and ordinary balancing did not find a task. A single
event-driven work item runs on regular CPUs, so it does not consume the
destination idle CPU. There is no timer or polling kthread. It collects at
most 16 referenced candidates from regular CFS runqueues and tries legal
candidates until one succeeds. There is at most one request in flight.

Unregistered tasks require explicit readiness through the proc interface.
Automatically recognized Chimera tasks require the existing target identity
and a signal 41 handler before a post-exec pull. This preserves the existing
single-global-target limitation rather than migrating older targets whose
notifications would be filtered out.

Migration and concurrency
-------------------------

Both ``/proc/set_ai_thread`` and automatic policy requests use
``hmp_move_task_to_group()``. It serializes group changes and holds CPU
hotplug and cpuset locks while deriving the target mask. Only the manual
AI request can online an AI CPU. It retains the existing signed-TID API.

The scheduler implementation changes thread type with affinity. The manual
and exec paths use the existing locked affinity setter. The idle path uses
its affinity update primitive and the existing locked queued-task migration
helper from a CPU stopper. It retains the normal migration bookkeeping and
BPF tracepoint; it does not write task CPU or runqueue linkage directly.

The stopper holds the task PI lock and both runqueue locks. It rechecks
task identity/state, fair class, preference, regular source, runnable state,
exit/exec, migration-disable/pending state, explicit user affinity, active
destination, and destination idle/runnable/pending-wakeup state. The
destination remains locked through enqueue. A previously running source
task can be migrated after the stopper has descheduled it. Tasks that sleep,
exit or change CPU during preparation cause a failed attempt.

The managed-task HMP affinity callback preserves a validated subset of its
group instead of expanding it back to the whole group. Existing platform
fallback handling remains in effect when the requested mask has no member
of the current group. This patch does not repair every pre-existing HMP
hotplug/cpuset fallback behaviour for arbitrary ordinary tasks.

Verification
------------

On K3, build from a separate source tree with its board configuration::

    bash scripts/chimera/build-prefer-a100.sh

After booting that image and mounting tracefs, run::

    python3 tools/testing/selftests/riscv/prefer_a100/run.py /absolute/new/logdir

The harness reads and verifies HMP masks and online CPUs, starts only its
own scalar workloads, exercises seven scheduling cases, and saves task
snapshots, counters, trace and dmesg. Its opt-in initial-placement case tests
the proc interface; it does not test BPF executable registration or ELF
matching. It does not establish correctness of cross-VLEN conversion.

Known limitations
-----------------

* The existing physical-migration-to-signal-41-to-userspace-conversion window
  remains for actual Chimera post-exec migrations. No safepoint protocol is
  added or claimed to have been validated by scalar tests.
* The existing registered-target implementation still has one global target.
* A deferred wakeup attempt can lose its opportunity or find a sleeping task.
  The task then stays on regular until another wakeup or AI idle event.
* Candidate collection is bounded at 16 references per event; it is neither
  a fairness policy nor an exhaustive global assignment.
* Explicit readiness is a trusted userspace promise. Opting unsafe RVV code
  in through the root-only interface does not make it safe to migrate.
