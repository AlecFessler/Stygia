#!/usr/bin/env python3
"""Side-by-side report of two `parse_kprof.py --json` outputs.

Intended for L4 IPC fast-path A/B measurement: one run with the
classifier on (`-Dkernel_fastpath=true`, default) and one with the
classifier disabled (`-Dkernel_fastpath=false` — every syscall takes
the slow Zig dispatch path). Per scope and per metric, prints the
median + total cost side by side and the delta (current vs baseline,
positive = current is more expensive).

Output is a flat readable table — not a gate. Use
`tests/prof/compare_baseline.py` for regression gating.

Usage:
    compare_fastpath.py <baseline.json> <current.json> \
        [--label-baseline NAME] [--label-current NAME]
"""

from __future__ import annotations

import argparse
import json
import sys


METRIC_KEYS = ("tsc", "cycles", "cache_misses", "branch_misses")
METRIC_SHORT = {
    "tsc":            "tsc",
    "cycles":         "cyc",
    "cache_misses":   "cmiss",
    "branch_misses":  "bmiss",
}


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def scope_map(doc: dict) -> dict[str, dict]:
    return {s["name"]: s for s in doc.get("scopes", [])}


def fmt_int(v: int) -> str:
    if v >= 10_000_000:
        return f"{v/1e6:>9.1f}M"
    if v >= 10_000:
        return f"{v/1e3:>9.1f}k"
    return f"{v:>10d}"


def pct(base: int, curr: int) -> str:
    if base <= 0:
        return "    n/a"
    d = (curr - base) / base * 100.0
    sign = "+" if d >= 0 else ""
    return f"{sign}{d:>5.1f}%"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline", help="parse_kprof.py --json output (control)")
    ap.add_argument("current",  help="parse_kprof.py --json output (treatment)")
    ap.add_argument("--label-baseline", default="baseline")
    ap.add_argument("--label-current",  default="current")
    ap.add_argument("--scopes", default="suspend_ec,recv,reply,deliver_event",
                    help="Comma-separated scope names to focus on (default: IPC scopes). "
                         "Pass 'all' to render every scope present in either run.")
    args = ap.parse_args()

    baseline_doc = load(args.baseline)
    current_doc  = load(args.current)
    base = scope_map(baseline_doc)
    curr = scope_map(current_doc)

    if args.scopes == "all":
        names = sorted(set(base) | set(curr))
    else:
        names = [n.strip() for n in args.scopes.split(",") if n.strip()]

    bl = args.label_baseline
    cl = args.label_current

    # Header — session metadata
    print(f"# kprof scope comparison: {bl}  vs  {cl}")
    print()
    print(f"  {bl:>20}: cpus={baseline_doc.get('cpus')} reason={baseline_doc.get('reason','?')} "
          f"records={baseline_doc.get('records','?')} mode={baseline_doc.get('mode','?')}")
    print(f"  {cl:>20}: cpus={current_doc.get('cpus')} reason={current_doc.get('reason','?')} "
          f"records={current_doc.get('records','?')} mode={current_doc.get('mode','?')}")
    print()

    # Per scope, per metric: median + total side-by-side
    for name in names:
        b = base.get(name)
        c = curr.get(name)
        if b is None and c is None:
            print(f"## {name}: absent in both runs")
            print()
            continue
        b_count = b["tsc"]["count"] if b else 0
        c_count = c["tsc"]["count"] if c else 0
        print(f"## {name}")
        print(f"   counts: {bl}={b_count}  {cl}={c_count}")
        print()

        # Per-metric table
        header = (
            f"   {'metric':<14} "
            f"{bl + ' med':>14} {cl + ' med':>14} {'delta':>9}    "
            f"{bl + ' total':>14} {cl + ' total':>14} {'delta':>9}"
        )
        print(header)
        print("   " + "-" * (len(header) - 3))
        for metric in METRIC_KEYS:
            b_med = b[metric]["median"] if b else 0
            c_med = c[metric]["median"] if c else 0
            b_tot = b[metric]["total"]  if b else 0
            c_tot = c[metric]["total"]  if c else 0
            label = METRIC_SHORT[metric]
            print(
                f"   {label:<14} {fmt_int(b_med):>14} {fmt_int(c_med):>14} {pct(b_med, c_med):>9}    "
                f"{fmt_int(b_tot):>14} {fmt_int(c_tot):>14} {pct(b_tot, c_tot):>9}"
            )
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
