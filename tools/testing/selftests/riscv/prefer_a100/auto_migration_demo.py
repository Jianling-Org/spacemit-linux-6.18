#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Demonstrate an automatic X100 -> idle A100 pull without chimera migrate."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
WORKER = HERE / "scalar"
TRACE = Path("/sys/kernel/tracing/instances") / f"prefer_a100_demo_{os.getpid()}"
children = []


def proc_stats():
    return dict(line.split(maxsplit=1) for line in
                Path("/proc/prefer_a100_stats").read_text().splitlines())


def cpulist(text):
    cpus = []
    for part in text.split(","):
        bounds = [int(value) for value in part.split("-")]
        cpus.extend(range(bounds[0], bounds[-1] + 1))
    return cpus


def task_cpu(pid):
    # Field 39 in /proc/PID/stat, after the final ')' in comm.
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[36])


def start_worker():
    child = subprocess.Popen([str(WORKER)], stdout=subprocess.PIPE, text=True)
    children.append(child)
    if "ready" not in child.stdout.readline():
        raise RuntimeError("scalar worker did not become ready")
    return child


def stop(child):
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
        child.wait(timeout=5)


def wait_for(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def idle_ticks():
    result = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu") and fields[0][3:].isdigit():
            result[int(fields[0][3:])] = int(fields[4])
    return result


def group_is_busy(cpus):
    before = idle_ticks()
    time.sleep(0.3)
    after = idle_ticks()
    return all(after[cpu] - before[cpu] <= 1 for cpu in cpus)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("run as root")
    if not WORKER.exists():
        raise RuntimeError(f"missing {WORKER}; build the prefer_a100 selftest first")

    topology = proc_stats()
    regular = cpulist(topology["regular_cpus"])
    ai = cpulist(topology["ai_cpus"])
    print(f"X100/regular CPUs: {regular}")
    print(f"A100/AI CPUs:      {ai}")
    print("No 'chimera migrate' command is used by this demo.\n")

    TRACE.mkdir()
    (TRACE / "events/sched/sched_prefer_a100_migrate/enable").write_text("1")
    (TRACE / "tracing_on").write_text("1")

    blockers = [start_worker() for _ in ai]
    for child in blockers:
        Path("/proc/set_ai_thread").write_text(str(child.pid))
    if not wait_for(lambda: group_is_busy(ai), 15):
        raise RuntimeError("could not make every A100 CPU busy")
    print(f"1. Occupied all {len(ai)} A100 CPUs with disposable blockers.")

    target = start_worker()
    if not wait_for(lambda: task_cpu(target.pid) in regular, 3):
        raise RuntimeError("target did not start on X100")
    before_cpu = task_cpu(target.pid)
    print(f"2. Target TID {target.pid} started on X100 CPU {before_cpu}.")

    # This registers a policy preference. It does not request a destination or
    # perform a migration; A100 is still full, so the target must remain on X100.
    Path("/proc/prefer_a100").write_text(str(target.pid))
    time.sleep(0.5)
    if task_cpu(target.pid) not in regular:
        raise RuntimeError("target left X100 while A100 was meant to be full")
    before = proc_stats()
    pull_src_cpu = task_cpu(target.pid)
    print("3. Registered prefer_A100 while A100 was full; target stayed on X100.")

    released_cpu = task_cpu(blockers[0].pid)
    stop(blockers[0])
    print(f"4. Released blocker on A100 CPU {released_cpu}; waiting for idle callback...")
    if not wait_for(lambda: task_cpu(target.pid) in ai, 8):
        raise RuntimeError("automatic pull did not move target to A100")

    after_cpu = task_cpu(target.pid)
    after = proc_stats()
    migration_key = "prefer_a100_x100_to_a100_migrations"
    attempt_key = "prefer_a100_idle_pull_attempts"
    print(f"5. PASS: kernel automatically moved target CPU {pull_src_cpu} -> {after_cpu}.")
    print(f"   idle-pull attempts: {before[attempt_key]} -> {after[attempt_key]}")
    print(f"   X100->A100 migrations: {before[migration_key]} -> {after[migration_key]}")

    (TRACE / "tracing_on").write_text("0")
    trace_lines = [line for line in (TRACE / "trace").read_text().splitlines()
                   if "sched_prefer_a100_migrate" in line and
                   f"pid={target.pid}" in line]
    print("6. Trace evidence:")
    print("\n".join(f"   {line.strip()}" for line in trace_lines) or
          "   (counter and CPU transition observed; matching trace line unavailable)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        for process in children:
            try:
                stop(process)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        if TRACE.exists():
            try:
                (TRACE / "tracing_on").write_text("0")
                (TRACE / "events/sched/sched_prefer_a100_migrate/enable").write_text("0")
                TRACE.rmdir()
            except OSError:
                pass
