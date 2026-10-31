#!/usr/bin/env python3
"""Mutation fixtures for the lifecycle correspondence tripwire."""

import shutil
import tempfile
from pathlib import Path

from check_model_correspondence import check


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "docs/kernel/tla/ThreadLifecycle.tla",
    "kernel/sched/scheduler.zig",
    "kernel/caps/process.zig",
    "kernel/sched/thread.zig",
    "kernel/memory/vmar.zig",
)


def mutate(root: Path, path: str, old: str, new: str) -> None:
    target = root / path
    text = target.read_text()
    if text.count(old) != 1:
        raise AssertionError(f"fixture anchor in {path} occurs {text.count(old)} times")
    target.write_text(text.replace(old, new, 1))


with tempfile.TemporaryDirectory() as temp:
    fixture = Path(temp)
    for path in FILES:
        (fixture / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / path, fixture / path)
    if check(fixture):
        raise AssertionError("unmutated source failed correspondence")

    cases = (
        ("lost parked wake", "kernel/sched/scheduler.zig",
         "if (target_current_ptr == null or target_parked) {",
         "if (target_current_ptr == null) {", "G14 enqueue wake"),
        ("premature restart gate clear", "kernel/caps/process.zig",
         "    if (survivors == 0) return false;\n\n    slot = 3;",
         "    if (survivors == 0) return false;\n    process.restarting.store(false, .release);\n\n    slot = 3;",
         "restartProcess must clear its dispatch gate exactly once"),
        ("missing fallback", "kernel/sched/scheduler.zig",
         "return runProcessTeardownWithoutRestart(fallback);",
         "return;", "restart fallback"),
        ("model gate drift", "docs/kernel/tla/ThreadLifecycle.tla",
         "  /\\ RestartQuiesced(p)\n  /\\ processes[p].snapshotGood",
         "  /\\ processes[p].snapshotGood", "model action RestartApply changed"),
    )
    for title, path, old, new, expected in cases:
        mutate(fixture, path, old, new)
        errors = check(fixture)
        if not any(expected in error for error in errors):
            raise AssertionError(f"{title} escaped: {errors}")
        shutil.copy2(ROOT / path, fixture / path)
        print(f"PASS {title}")
print("RESULT: OK")
