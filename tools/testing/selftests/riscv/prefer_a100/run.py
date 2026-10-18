#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Institute of Software Chinese Academy of Sciences (ISCAS)
"""Native K3 scalar scheduling tests. Does not claim VLEN conversion coverage."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=False)
WORKER = Path(__file__).with_name("scalar").resolve()
children = []
results = []


def stats():
    return dict(line.split(maxsplit=1) for line in
                Path("/proc/prefer_a100_stats").read_text().splitlines())


def cpulist(text):
    out = []
    for part in text.split(","):
        bounds = [int(x) for x in part.split("-")]
        out.extend(range(bounds[0], bounds[-1] + 1))
    return out


def state(p):
    pid = p.pid if hasattr(p, "pid") else p
    text = Path(f"/proc/{pid}/status").read_text()
    fields = dict(line.split(":", 1) for line in text.splitlines())
    # stat field 39 is the last CPU; split only after the closing comm ')'.
    cpu = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[36])
    return {"pid": pid, "cpu": cpu, "prefer": fields["Prefer_a100"].strip(),
            "type": fields["Hmp_thread_type"].strip(),
            "affinity": fields["Cpus_allowed_list"].strip(),
            "returncode": p.poll() if hasattr(p, "poll") else None}


def start():
    p = subprocess.Popen([str(WORKER)], stdout=subprocess.PIPE, text=True)
    children.append(p)
    assert "ready" in p.stdout.readline(), "scalar startup failed"
    return p


def prefer(p):
    Path("/proc/prefer_a100").write_text(str(p.pid))


def wait_for(predicate, seconds=6):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(.05)
    return False


def stop(p):
    if p.poll() is None:
        p.terminate()
        p.wait(timeout=5)


def cleanup():
    for p in children:
        stop(p)
    children.clear()


def idle_ticks():
    counts = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu") and fields[0][3:].isdigit():
            counts[int(fields[0][3:])] = int(fields[4])
    return counts


def full(ai):
    before = idle_ticks()
    time.sleep(.3)
    after = idle_ticks()
    return all(after[c] - before[c] <= 1 for c in ai)


def fill(ai):
    hogs = [start() for _ in ai]
    for p in hogs:
        Path("/proc/set_ai_thread").write_text(str(p.pid))
    assert wait_for(lambda: full(ai), 15), "could not establish full A100 load"
    return hogs


def record(name, ok, **evidence):
    results.append({"test": name, "passed": bool(ok), **evidence})
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results[-1]), flush=True)


trace = Path("/sys/kernel/tracing/instances") / f"prefer_a100_{os.getpid()}"
try:
    topology = stats()
    regular = cpulist(topology["regular_cpus"])
    ai = cpulist(topology["ai_cpus"])
    assert regular and ai and not set(regular) & set(ai)
    online = set(cpulist(Path("/sys/devices/system/cpu/online").read_text().strip()))
    assert set(ai + regular) <= online, "test requires all group CPUs online"
    (OUT / "topology.json").write_text(json.dumps(topology, indent=2))
    for command, name in [(["uname", "-a"], "uname.txt"),
                          (["lscpu"], "lscpu.txt"),
                          (["dmesg"], "dmesg-before.txt")]:
        (OUT / name).write_bytes(subprocess.check_output(command))
    (OUT / "cpuinfo.txt").write_text(Path("/proc/cpuinfo").read_text())
    trace.mkdir()
    (trace / "events/sched/sched_prefer_a100_migrate/enable").write_text("1")
    (trace / "tracing_on").write_text("1")

    p = start()
    time.sleep(.5)
    record("0 baseline", state(p)["cpu"] in regular and state(p)["prefer"] == "0",
           task=state(p))
    cleanup()

    p = start()
    before = state(p)
    prefer(p)
    ok = wait_for(lambda: state(p)["cpu"] in ai)
    record("1 idle A100 opt-in (exec integration deferred)", ok,
           before=before, after=state(p), stats=stats())
    cleanup()

    hogs = fill(ai)
    p = start()
    prefer(p)
    time.sleep(.5)
    record("2 A100 full", state(p)["cpu"] in regular,
           task=state(p), hogs=[state(h) for h in hogs])
    before = state(p)
    stop(hogs[0])
    ok = wait_for(lambda: state(p)["cpu"] in ai)
    record("3 dynamic idle pull", ok, before=before, after=state(p), stats=stats())
    cleanup()

    p = start()
    time.sleep(1)
    record("4 ordinary task", state(p)["cpu"] in regular and state(p)["prefer"] == "0",
           task=state(p))
    cleanup()

    hogs = fill(ai)
    candidates = [start() for _ in range(3)]
    for p in candidates:
        prefer(p)
    time.sleep(.5)
    before = [state(p) for p in candidates]
    stop(hogs[0])
    wait_for(lambda: any(state(p)["cpu"] in ai for p in candidates))
    time.sleep(1)
    after = [state(p) for p in candidates]
    record("5 one idle CPU multiple candidates", sum(s["cpu"] in ai for s in after) == 1,
           before=before, after=after, stats=stats())
    cleanup()

    p = start()
    os.sched_setaffinity(p.pid, {regular[0]})
    prefer(p)
    os.sched_setaffinity(p.pid, {regular[0]})
    time.sleep(1)
    snapshot = state(p)
    record("6 explicit affinity restriction", snapshot["cpu"] == regular[0] and
           os.sched_getaffinity(p.pid) == {regular[0]}, task=snapshot, stats=stats())
    cleanup()

    # A child of a preferred AI task must fall back to regular CPUs while
    # every permitted A100 CPU is occupied. This exercises fork inheritance
    # without requiring the full Chimera runtime.
    hogs = fill(ai)
    prefer_pid = os.getpid()
    Path("/proc/prefer_a100").write_text(str(prefer_pid))
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.write(write_fd, b"ready")
        os.close(write_fd)
        while True:
            pass
    os.close(write_fd)
    assert os.read(read_fd, 5) == b"ready", "fork child startup failed"
    os.close(read_fd)
    child_state = state(child)
    record("7 fork fallback when A100 full", child_state["cpu"] in regular and
           child_state["type"] == "0" and
           set(os.sched_getaffinity(child)) <= set(regular),
           child=child_state, stats=stats())
    os.kill(child, 15)
    os.waitpid(child, 0)
    Path("/proc/prefer_a100").write_text(str(-prefer_pid))
    cleanup()
finally:
    cleanup()
    if trace.exists():
        (trace / "tracing_on").write_text("0")
        (OUT / "trace.txt").write_text((trace / "trace").read_text())
        (trace / "events/sched/sched_prefer_a100_migrate/enable").write_text("0")
        trace.rmdir()
    (OUT / "dmesg-after.txt").write_bytes(subprocess.check_output(["dmesg"]))
    (OUT / "stats-after.json").write_text(json.dumps(stats(), indent=2))

sys.exit(0 if len(results) == 8 and all(r["passed"] for r in results) else 1)
