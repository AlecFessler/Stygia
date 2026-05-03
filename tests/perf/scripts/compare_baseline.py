#!/usr/bin/env python3
"""Regression gate for kprof trace JSON output.

Compares a current `parse_kprof.py --json` dump against a baseline
dump and flags scopes whose per-call cost regressed beyond a
threshold. Designed for precommit use: exit 0 means "no regression,
proceed", non-zero means "current is slower, block the commit".

Reports (and gates on) two metrics per scope:

  - median TSC per call   — wall-time-ish cost of a scope invocation
  - median cycles per call — cycles retired per scope invocation

Scopes absent from the baseline but present in current are treated
as informational (printed, not gating) — first-run additions to the
profile shouldn't fail CI. Scopes present in baseline but missing
from current are informational too: either the scope was renamed /
removed, or the workload didn't exercise it this run. Either way
the baseline should be updated explicitly rather than silently
failing the gate.

Low-sample scopes (count below NOISY_FLOOR in either run) are
skipped — noise on a handful of samples dominates any real trend.

Usage:
    compare_baseline.py <baseline.json> <current.json> [--threshold 0.20]
"""

from __future__ import annotations

import argparse
import json
import sys

NOISY_FLOOR = 50


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def scope_map(doc: dict) -> dict[str, dict]:
    return {s["name"]: s for s in doc.get("scopes", [])}


def pct_delta(baseline: int, current: int) -> float:
    if baseline <= 0:
        return 0.0
    return (current - baseline) / baseline


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("current")
    ap.add_argument(
        "--threshold",
        type=float,
        default=0.20,
        help="Fractional regression tolerated on median per-call cost (default 0.20 = 20%%).",
    )
    args = ap.parse_args()

    base = scope_map(load(args.baseline))
    curr = scope_map(load(args.current))

    regressions: list[str] = []
    info: list[str] = []

    for name in sorted(set(base) | set(curr)):
        if name not in base:
            info.append(f"  [new]    {name}")
            continue
        if name not in curr:
            info.append(f"  [gone]   {name} (baseline only)")
            continue

        b, c = base[name], curr[name]
        b_count = b["tsc"]["count"]
        c_count = c["tsc"]["count"]
        if b_count < NOISY_FLOOR or c_count < NOISY_FLOOR:
            info.append(f"  [noisy]  {name} (counts {b_count} → {c_count})")
            continue

        for metric in ("tsc", "cycles"):
            bm = b[metric]["median"]
            cm = c[metric]["median"]
            d = pct_delta(bm, cm)
            if d > args.threshold:
                regressions.append(
                    f"  {name}.{metric}.median  {bm} → {cm}  (+{d * 100:.1f}%)"
                )

    if info:
        print("Informational:")
        for line in info:
            print(line)

    if regressions:
        print(
            f"\nRegressions beyond {args.threshold * 100:.0f}%:",
            file=sys.stderr,
        )
        for line in regressions:
            print(line, file=sys.stderr)
        return 1

    print(f"\nNo regressions beyond {args.threshold * 100:.0f}%.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
