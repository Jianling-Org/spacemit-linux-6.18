#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate 8-A100/8-X100 layered assignment and managed-task refill."""

import os
from pathlib import Path
import subprocess
import sys
import time


WORKER = Path(__file__).with_name("scalar")
children = []


def stats():
    return dict(line.split(maxsplit=1) for line in
                Path("/proc/prefer_a100_stats").read_text().splitlines())


def cpulist(text):
    result = []
    for part in text.split(","):
        ends = [int(value) for value in part.split("-")]
        result.extend(range(ends[0], ends[-1] + 1))
    return result


def cpu(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[36])


def start():
    child = subprocess.Popen([str(WORKER)], stdout=subprocess.PIPE, text=True)
    children.append(child)
    assert "ready" in child.stdout.readline()
    Path("/proc/prefer_a100").write_text(str(child.pid))
    return child


def stop(child):
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=5)


def wait_for(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def distribution(ai, regular):
    states = {child.pid: cpu(child.pid) for child in children if child.poll() is None}
    return (sum(value in ai for value in states.values()),
            sum(value in regular for value in states.values()), states)


def main():
    topology = stats()
    ai = set(cpulist(topology["ai_cpus"]))
    regular = set(cpulist(topology["regular_cpus"]))
    assert len(ai) == len(regular) == 8
    baseline_ai = int(topology["prefer_assigned_ai"])
    baseline_regular = int(topology["prefer_assigned_regular"])
    assert baseline_ai == baseline_regular == 0, "run with no other preferred tasks"

    for _ in range(16):
        start()
    assert wait_for(lambda: distribution(ai, regular)[:2] == (8, 8), 15)
    ai_count, regular_count, states = distribution(ai, regular)
    snapshot = stats()
    print(f"PASS initial layer: A100={ai_count}, X100={regular_count}")
    print(f"  tasks: {states}")
    print(f"  assigned: A100={snapshot['prefer_assigned_ai']}, "
          f"X100={snapshot['prefer_assigned_regular']}")

    victim = next(child for child in children if cpu(child.pid) in ai)
    old_regular = {child.pid for child in children if child.poll() is None and
                   cpu(child.pid) in regular}
    stop(victim)
    assert wait_for(lambda: distribution(ai, regular)[:2] == (8, 7), 15)
    new_ai = {child.pid for child in children if child.poll() is None and
              cpu(child.pid) in ai}
    pulled = sorted(old_regular & new_ai)
    assert pulled, "no X100 task refilled the released A100 assignment"
    snapshot = stats()
    print(f"PASS managed refill: exited A100 TID {victim.pid}, pulled {pulled}")
    print(f"  assigned: A100={snapshot['prefer_assigned_ai']}, "
          f"X100={snapshot['prefer_assigned_regular']}")
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
