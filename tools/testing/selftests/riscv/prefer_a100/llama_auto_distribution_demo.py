#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Institute of Software Chinese Academy of Sciences (ISCAS)
"""Observe Chimera llama thread placement and idle pulls without manual migrate."""

import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time


CHIMERA_ROOT = Path(os.environ.get("CHIMERA_ROOT", "/root/kaiwen/chimera-user-full"))
LLAMA_ROOT = CHIMERA_ROOT / "examples/applications/llama-cpp/llama.cpp"
BINARY = LLAMA_ROOT / "build-remediated/bin/llama-perplexity-1024-to-256"
PROFILE = CHIMERA_ROOT / "examples/platforms/k3/linux-riscv64-rvv-1024-to-256.toml"
MODEL = Path(os.environ.get(
    "MODEL", str(CHIMERA_ROOT / "examples/applications/llama-cpp/model/"
                 "tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf")))
PROMPT = Path(os.environ.get(
    "PROMPT_FILE", str(CHIMERA_ROOT / "examples/applications/llama-cpp/prompt/file.txt")))
CHIMERA = CHIMERA_ROOT / ".venv/bin/chimera"
TRACE = Path("/sys/kernel/tracing/instances") / f"llama_auto_{os.getpid()}"
LOG_PATH = Path(os.environ.get("LOG_PATH", "/tmp/llama-auto-distribution.log"))
TRACE_LOG_PATH = Path(os.environ.get("TRACE_LOG_PATH", "/tmp/llama-auto-trace.log"))
child = None


def scheduler_stats():
    return dict(line.split(maxsplit=1) for line in
                Path("/proc/prefer_a100_stats").read_text().splitlines())


def cpulist(text):
    result = []
    for part in text.split(","):
        ends = [int(value) for value in part.split("-")]
        result.extend(range(ends[0], ends[-1] + 1))
    return result


def task_cpus(tgid):
    result = {}
    for stat in Path(f"/proc/{tgid}/task").glob("*/stat"):
        try:
            text = stat.read_text()
            result[int(stat.parent.name)] = int(text.rsplit(")", 1)[1].split()[36])
        except (FileNotFoundError, ProcessLookupError, ValueError):
            pass
    return result


def stream_output(pipe, log, lines):
    for line in iter(pipe.readline, ""):
        log.write(line)
        log.flush()
        lines.append(line)
        # Keep the useful lifecycle and runtime messages visible.
        if any(marker in line for marker in
               ("parent_thread_id=", "calculating perplexity", "source_vlen_bits=",
                "next_body=", "Final estimate", "PPL")):
            print(f"llama: {line.rstrip()}", flush=True)


def place_launcher_on_a100():
    """Run in the child immediately before exec; no workload thread exists yet."""
    Path("/proc/set_ai_thread").write_text(str(os.getpid()))


def main():
    global child
    if os.geteuid() != 0:
        raise RuntimeError("run as root")
    for path in (BINARY, PROFILE, MODEL, PROMPT, CHIMERA):
        if not path.exists():
            raise RuntimeError(f"missing required path: {path}")

    topology = scheduler_stats()
    regular = set(cpulist(topology["regular_cpus"]))
    ai = set(cpulist(topology["ai_cpus"]))
    before_migrations = int(topology["prefer_a100_x100_to_a100_migrations"])
    print(f"X100/256 CPUs:  {sorted(regular)}")
    print(f"A100/1024 CPUs: {sorted(ai)}")
    print("Migration command: NONE (this script never invokes 'chimera migrate')")
    print("The launcher is placed on A100 before exec, matching the official example.")

    env = os.environ.copy()
    env["PATH"] = f"{CHIMERA.parent}:/root/.chimera/bin:" + env.get("PATH", "")
    print("Registering the existing remediated binary...")
    subprocess.run([str(CHIMERA), "--profile", str(PROFILE), "register", "--verify",
                    "--input", str(BINARY)], cwd=CHIMERA_ROOT, env=env, check=True)

    TRACE.mkdir()
    (TRACE / "events/sched/sched_prefer_a100_migrate/enable").write_text("1")
    (TRACE / "tracing_on").write_text("1")
    lines = []
    LOG_PATH.unlink(missing_ok=True)
    log = LOG_PATH.open("w")
    cmd = [str(CHIMERA), "--profile", str(PROFILE), "--debug", "run",
           "--input", str(BINARY), "--", "-m", str(MODEL), "-f", str(PROMPT),
           "-t", os.environ.get("LLAMA_THREADS", "1"),
           "-tb", os.environ.get("LLAMA_BATCH_THREADS", "16")]
    child = subprocess.Popen(cmd, cwd=CHIMERA_ROOT, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1,
                             preexec_fn=place_launcher_on_a100)
    reader = threading.Thread(target=stream_output, args=(child.stdout, log, lines), daemon=True)
    reader.start()

    parent_tid = None
    deadline = time.monotonic() + 30
    pattern = re.compile(r"parent_thread_id=(\d+)")
    while time.monotonic() < deadline and child.poll() is None:
        match = pattern.search("".join(lines))
        if match:
            parent_tid = int(match.group(1))
            break
        time.sleep(0.05)
    if parent_tid is None:
        raise RuntimeError("could not read parent_thread_id from chimera --debug output")
    print(f"Parent TID: {parent_tid}")

    first_balanced = None
    prior = {}
    all_seen_tids = set()
    observed_pulls = []
    peak_threads = peak_regular = peak_ai = 0
    peak_assigned_regular = peak_assigned_ai = 0
    last_sigcgt = "unknown"
    start = time.monotonic()
    while child.poll() is None:
        try:
            current = task_cpus(parent_tid)
        except FileNotFoundError:
            break
        regular_tids = sorted(tid for tid, cpu in current.items() if cpu in regular)
        ai_tids = sorted(tid for tid, cpu in current.items() if cpu in ai)
        all_seen_tids.update(current)
        peak_threads = max(peak_threads, len(current))
        peak_regular = max(peak_regular, len(regular_tids))
        peak_ai = max(peak_ai, len(ai_tids))
        try:
            live_stats = scheduler_stats()
            peak_assigned_regular = max(
                peak_assigned_regular, int(live_stats["prefer_assigned_regular"]))
            peak_assigned_ai = max(
                peak_assigned_ai, int(live_stats["prefer_assigned_ai"]))
            for line in Path(f"/proc/{parent_tid}/status").read_text().splitlines():
                if line.startswith("SigCgt:"):
                    last_sigcgt = line.split()[1]
                    break
        except (FileNotFoundError, ProcessLookupError, KeyError, ValueError):
            pass
        if first_balanced is None and len(regular_tids) >= 8 and len(ai_tids) >= 8:
            first_balanced = (time.monotonic() - start, regular_tids, ai_tids, dict(current))
            print(f"Balanced snapshot: X100={len(regular_tids)}, A100={len(ai_tids)}")
            print(f"  X100 TIDs: {regular_tids}")
            print(f"  A100 TIDs: {ai_tids}")
        for tid, cpu in current.items():
            old_cpu = prior.get(tid)
            if old_cpu in regular and cpu in ai:
                event = (time.monotonic() - start, tid, old_cpu, cpu)
                observed_pulls.append(event)
                print(f"Observed X100->A100 transition: tid={tid} CPU {old_cpu}->{cpu}")
        prior = current
        time.sleep(0.02)

    returncode = child.wait()
    reader.join(timeout=5)
    log.close()
    (TRACE / "tracing_on").write_text("0")
    trace_text = (TRACE / "trace").read_text()
    TRACE_LOG_PATH.write_text(trace_text)
    tids = all_seen_tids | ({parent_tid} if parent_tid else set())
    idle_pull_lines = [line.strip() for line in trace_text.splitlines()
                       if "reason=IDLE_PULL" in line and
                       any(f"pid={tid} " in line for tid in tids)]
    after = scheduler_stats()
    after_migrations = int(after["prefer_a100_x100_to_a100_migrations"])

    print("\nResults")
    print(f"  llama exit code: {returncode}")
    print(f"  peak thread count: {peak_threads}")
    print(f"  peak X100 threads: {peak_regular}")
    print(f"  peak A100 threads: {peak_ai}")
    print(f"  peak logical assignments: X100={peak_assigned_regular}, "
          f"A100={peak_assigned_ai}")
    print(f"  parent SigCgt: {last_sigcgt}")
    print(f"  scheduler migration counter: {before_migrations} -> {after_migrations}")
    print(f"  sampled X100->A100 transitions: {len(observed_pulls)}")
    print(f"  matching IDLE_PULL trace events: {len(idle_pull_lines)}")
    for line in idle_pull_lines[:20]:
        print(f"    {line}")
    print(f"  full llama log: {LOG_PATH}")
    print(f"  full migration trace: {TRACE_LOG_PATH}")

    failures = []
    if returncode != 0:
        failures.append("llama-perplexity failed")
    if first_balanced is None:
        failures.append("never observed at least 8 threads in each CPU group")
    if not idle_pull_lines:
        failures.append("no automatic IDLE_PULL event was observed for llama")
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("PASS: initial two-group placement and later automatic idle pull were both observed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
        if TRACE.exists():
            try:
                (TRACE / "tracing_on").write_text("0")
                (TRACE / "events/sched/sched_prefer_a100_migrate/enable").write_text("0")
                TRACE.rmdir()
            except OSError:
                pass
