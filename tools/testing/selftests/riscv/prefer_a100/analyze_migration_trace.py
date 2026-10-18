#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Institute of Software Chinese Academy of Sciences (ISCAS)
"""Report per-task spacing between prefer_A100 trace migrations."""

import re
import sys


EVENT = re.compile(
    r"\s(?P<time>\d+\.\d+): sched_prefer_a100_migrate: "
    r"pid=(?P<pid>\d+) src_cpu=(?P<src>\d+) dst_cpu=(?P<dst>\d+)")


def main(paths):
    minimum = None
    minimum_reverse = None
    under_100ms = []
    events = 0
    for path in paths:
        previous = {}
        with open(path, encoding="utf-8") as trace:
            for line in trace:
                match = EVENT.search(line)
                if not match:
                    continue
                events += 1
                timestamp = float(match["time"])
                pid = int(match["pid"])
                src = int(match["src"])
                dst = int(match["dst"])
                old = previous.get(pid)
                if old:
                    delta = timestamp - old[0]
                    minimum = delta if minimum is None else min(minimum, delta)
                    reverse = (src < 8) != (old[1] < 8)
                    if reverse:
                        minimum_reverse = (delta if minimum_reverse is None else
                                           min(minimum_reverse, delta))
                    if delta < 0.1:
                        under_100ms.append((path, pid, delta, old[1], old[2], src, dst))
                previous[pid] = (timestamp, src, dst)
    print(f"events={events}")
    print(f"minimum_same_tid_seconds={minimum if minimum is not None else 'NA'}")
    print("minimum_reverse_seconds=" +
          str(minimum_reverse if minimum_reverse is not None else "NA"))
    print(f"same_tid_under_100ms={len(under_100ms)}")
    for item in under_100ms:
        print(item)
    return 1 if under_100ms else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
