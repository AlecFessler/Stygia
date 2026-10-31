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
    "kernel/arch/x64/vm_runloop.zig",
    "kernel/arch/aarch64/vm_runloop.zig",
)


def mutate(root: Path, path: str, old: str, new: str) -> None:
    target = root / path
    text = target.read_text()
    if text.count(old) != 1:
        raise AssertionError(f"fixture anchor in {path} occurs {text.count(old)} times")
    target.write_text(text.replace(old, new, 1))


X64_PRE_ENTRY_MARKER = "    var exit_info: vm_hw.VmExitInfo = undefined;\n    while (true) {"
X64_RETIREMENT_CHECK = (
    "        if (lifecycle.load(vcpu_thread) == .retired) {\n"
    "            return .{ .subcode = SUBCODE_UNKNOWN, .payload = .{ 0, 0, 0 }, .cancelled = true };\n"
    "        }\n"
)
X64_VM_ENTRY = "exit_info = vm_hw.vmResume("


def mutate_x64_pre_entry(root: Path, old: str, new: str) -> None:
    """Mutate only the retirement guard before the first x64 guest entry."""
    target = root / "kernel/arch/x64/vm_runloop.zig"
    source = target.read_text()
    marker = source.index(X64_PRE_ENTRY_MARKER)
    entry = source.index(X64_VM_ENTRY, marker)
    pre_entry = source[marker:entry]
    if pre_entry.count(old) != 1:
        raise AssertionError(f"x64 pre-entry fixture anchor occurs {pre_entry.count(old)} times")
    target.write_text(source[:marker] + pre_entry.replace(old, new, 1) + source[entry:])


with tempfile.TemporaryDirectory() as temp:
    fixture = Path(temp)
    for path in FILES:
        (fixture / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / path, fixture / path)
    if check(fixture):
        raise AssertionError("unmutated source failed correspondence")

    # A second owner-side check after VM exit is valid. It must not make the
    # fixture ambiguous, and it must not mask loss of the pre-entry check.
    x64_path = "kernel/arch/x64/vm_runloop.zig"
    mutate(fixture, x64_path,
           "        arch_state.last_exit = exit_info;\n",
           "        arch_state.last_exit = exit_info;\n" + X64_RETIREMENT_CHECK)
    if check(fixture):
        raise AssertionError("second x64 retirement check failed correspondence")
    x64_with_second_check = (fixture / x64_path).read_text()

    mutate_x64_pre_entry(fixture, X64_RETIREMENT_CHECK,
                         X64_RETIREMENT_CHECK.replace(".retired", ".running"))
    if not any("x64 retired guest exit" in error for error in check(fixture)):
        raise AssertionError("missing first x64 retirement check escaped")
    (fixture / x64_path).write_text(x64_with_second_check)

    mutate_x64_pre_entry(fixture, X64_RETIREMENT_CHECK, "")
    mutate(fixture, x64_path,
           "        arch_state.last_exit = exit_info;\n",
           "        arch_state.last_exit = exit_info;\n" + X64_RETIREMENT_CHECK)
    if not any("x64 retired guest exit" in error for error in check(fixture)):
        raise AssertionError("reordered first x64 retirement check escaped")
    shutil.copy2(ROOT / x64_path, fixture / x64_path)
    print("PASS second x64 retirement check preserves pre-entry guard detection")

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
        ("x64 missing retired guest exit", "kernel/arch/x64/vm_runloop.zig",
         X64_RETIREMENT_CHECK,
         X64_RETIREMENT_CHECK.replace(".retired", ".running"), "x64 retired guest exit"),
        ("arm missing retired guest exit", "kernel/arch/aarch64/vm_runloop.zig",
         "if (lifecycle.load(vcpu_thread) == .retired) {",
         "if (false) {", "aarch64 retired guest exit"),
        ("cancelled vCPU event leak", "kernel/sched/scheduler.zig",
         "if (!delivery.cancelled) {",
         "if (true) {", "vCPU cancelled dispatch"),
    )
    for title, path, old, new, expected in cases:
        if title == "x64 missing retired guest exit":
            mutate_x64_pre_entry(fixture, old, new)
        else:
            mutate(fixture, path, old, new)
        errors = check(fixture)
        if not any(expected in error for error in errors):
            raise AssertionError(f"{title} escaped: {errors}")
        shutil.copy2(ROOT / path, fixture / path)
        print(f"PASS {title}")
print("RESULT: OK")
