#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Institute of Software Chinese Academy of Sciences (ISCAS)
"""Exercise prefer_A100 fork inheritance and repeated sleep/wakeup placement."""

import os
from pathlib import Path
import signal
import time


children = []


def main():
    Path("/proc/prefer_a100").write_text(str(os.getpid()))
    for _ in range(16):
        pid = os.fork()
        if pid == 0:
            end = time.monotonic() + 8
            value = 1
            while time.monotonic() < end:
                time.sleep(0.01)
                busy_end = time.monotonic() + 0.002
                while time.monotonic() < busy_end:
                    value = (value * 6364136223846793005 + 1) & ((1 << 64) - 1)
            os._exit(value & 0)
        children.append(pid)

    for pid in children:
        waited, status = os.waitpid(pid, 0)
        if waited != pid or status != 0:
            raise RuntimeError(f"child {pid} failed: status={status}")
    print("PASS: 16 inherited children completed repeated sleep/wakeup cycles")


if __name__ == "__main__":
    try:
        main()
    finally:
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
