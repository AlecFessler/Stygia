#!/usr/bin/env python3
"""Aggregate `[ipc_pp] sample N CYCLES` lines into summary stats.

Usage: ipc_pp_stats.py [--label TEXT] LOGFILE [LOGFILE...]
"""

import argparse
import re
import statistics
import sys


SAMPLE_RE = re.compile(r"^\[ipc_pp\] sample \d+ (\d+)$")


def stats(label: str, samples: list[int]) -> None:
    if not samples:
        print(f"{label}: no samples")
        return
    samples_sorted = sorted(samples)
    n = len(samples_sorted)

    def pct(p: float) -> int:
        i = max(0, min(n - 1, int(round(p * (n - 1)))))
        return samples_sorted[i]

    mean = sum(samples) / n
    median = samples_sorted[n // 2]
    print(
        f"{label:24s}  N={n:5d}  "
        f"min={samples_sorted[0]:7d}  "
        f"p50={median:7d}  "
        f"p90={pct(0.90):7d}  "
        f"p99={pct(0.99):7d}  "
        f"max={samples_sorted[-1]:7d}  "
        f"mean={mean:7.0f}  "
        f"stdev={statistics.stdev(samples):7.0f}"
    )


def parse(path: str) -> list[int]:
    out = []
    with open(path) as fh:
        for line in fh:
            m = SAMPLE_RE.match(line.strip())
            if m:
                out.append(int(m.group(1)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default=None,
                    help="label override (default: filename stem)")
    ap.add_argument("logs", nargs="+")
    args = ap.parse_args()

    for log in args.logs:
        label = args.label or log.split("/")[-1]
        samples = parse(log)
        stats(label, samples)
    return 0


if __name__ == "__main__":
    sys.exit(main())
