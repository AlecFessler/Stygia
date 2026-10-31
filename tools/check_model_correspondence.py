#!/usr/bin/env python3
"""Check load-bearing lifecycle model/code obligations at source level.

This is a conservative tripwire, not a proof of refinement. Each assertion
checks a control-flow or ordering dependency that the corresponding TLA action
needs. Keep the reviewed transition ledger in docs/kernel/tla/README.md.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def body(source: str, name: str) -> str:
    # The target functions have ordinary Zig bodies. Brace counting excludes
    # comments and string literals so text in a comment cannot satisfy a rule.
    clean = re.sub(r'//[^\n]*|"(?:\\.|[^"\\])*"', lambda m: " " * len(m.group()), source)
    match = re.search(r"\bfn\s+" + re.escape(name) + r"\s*\(", clean)
    if not match:
        raise ValueError(f"function {name} missing")
    start = clean.find("{", match.end())
    if start < 0:
        raise ValueError(f"function {name} has no body")
    depth = 0
    for end in range(start, len(clean)):
        if clean[end] == "{":
            depth += 1
        elif clean[end] == "}":
            depth -= 1
            if depth == 0:
                return clean[start + 1:end]
    raise ValueError(f"function {name} body unclosed")


def ordered(label: str, haystack: str, *patterns: str) -> list[str]:
    errors = []
    pos = 0
    for pattern in patterns:
        match = re.search(pattern, haystack[pos:], re.S)
        if not match:
            errors.append(f"{label}: missing or out of order: {pattern}")
            break
        pos += match.end()
    return errors


def check(root: Path) -> list[str]:
    def read(path: str) -> str:
        return (root / path).read_text()

    model = read("docs/kernel/tla/ThreadLifecycle.tla")
    sched = read("kernel/sched/scheduler.zig")
    proc = read("kernel/caps/process.zig")
    thread = read("kernel/sched/thread.zig")
    vmar = read("kernel/memory/vmar.zig")
    errors = []

    # Fail closed if the model action itself changes: obligations below must
    # then be reviewed against the new relation before the gate can pass.
    for action, fragments in {
        "ParkDecision": [r"cores\[c\]\.q = \{\}", r"parked = TRUE"],
        "WakeIpi": [r"parked /\\ cores\[c\]\.wake", r"parked = FALSE"],
        "QueueTeardown": [r"pending = NULL", r"phase = .queued."],
        "ConsumeTeardown": [r"cur = NULL", r"pending = NULL", r"active = IF G16_DROP_REF"],
        "RestartApply": [r"RestartQuiesced\(p\)", r"snapshotGood", r"snapshotCopied = TRUE"],
        "RestartFallback": [r"RestartQuiesced\(p\)", r"phase = .dead."],
    }.items():
        match = re.search(r"(?m)^" + action + r"\([^\n]*?==(?P<body>.*?)(?=\n[A-Za-z][A-Za-z0-9_]*(?:\([^\n]*?\))?\s*==|\n\(\*|\Z)", model, re.S)
        if not match:
            errors.append(f"model action {action} missing; review correspondence")
            continue
        for fragment in fragments:
            if not re.search(fragment, match.group("body"), re.S):
                errors.append(f"model action {action} changed ({fragment}); review correspondence")

    # G14: the park decision and enqueue snapshot must use the same core
    # lock, and a parked remote target must receive a wake after publication.
    errors += ordered("G14 park under lock", body(sched, "dequeueOrIdle"),
        r"core_locks\[core\]", r"lockIrqSaveOrdered", r"dequeueOrIdleLocked\(core\)", r"unlockIrqRestore")
    errors += ordered("G14 empty queue before park", body(sched, "dequeueOrIdleLocked"),
        r"dequeueLocalReadyLocked", r"tryStealReadyLocked", r"idle_parked\s*=\s*true")
    errors += ordered("G14 enqueue wake", body(sched, "finishEnqueuePublish"),
        r"run_queue\.enqueue\(thread\)", r"target_parked\s*=.*idle_parked", r"unlockIrqRestore\(irq\)",
        r"if\s*\(target_current_ptr\s*==\s*null\s+or\s+target_parked\)", r"sendWakeIpi\(core\)")

    # G16: one pending request is published under the core lock; consumer
    # takes it only on a safe stack and clears the slot before phase 1/2.
    errors += ordered("G16 publish request", body(sched, "queueTeardown"),
        r"lockIrqSaveOrdered", r"teardown_pending", r"slot\.\*\s*=\s*req")
    errors += ordered("G16 consume request", body(sched, "drainTeardown"),
        r"lockIrqSaveOrdered", r"teardown_pending", r"if\s*\(incoming\)",
        r"slot\.\*\s*=\s*null", r"runProcessTeardown\(req\)")
    errors += ordered("G16 park-stack drain", body(sched, "scheduler_run_after_park"),
        r"drainTeardown\(core,\s*null\)", r"run\(\)")

    # Restart: set the dispatch gate before claiming exit; evict and wait
    # before thread/VMAR walks; clear the gate only after all policy walks.
    errors += ordered("restart trigger gate", body(proc, "claimExitLocked"),
        r"if\s*\(decision\s*==\s*\.restart\)\s*process\.restarting\.store\(true",
        r"process\.exit_decision\.store")
    if not re.search(r"!dref\.ptr\.restarting\.load\(\.acquire\)", body(sched, "processRefAlive")):
        errors.append("restart dispatch gate missing from processRefAlive")
    errors += ordered("restart quiescence and publication", body(proc, "restartProcess"),
        r"triggerSchedulerInterrupt\(core\)", r"awaitProcessQuiesced\(",
        r"destroyThreadForRestart\(", r"if\s*\(survivors\s*==\s*0\)\s*return false",
        r"restartDecommit\(", r"restartSnapshot\(", r"restartHandleKept\(",
        r"exit_decision\.store\(0", r"restarting\.store\(false", r"scheduler\.enqueue\(thread\)")
    if len(re.findall(r"process\.restarting\.store\(false", body(proc, "restartProcess"))) != 1:
        errors.append("restartProcess must clear its dispatch gate exactly once, after policy walks")
    errors += ordered("restart fallback", body(sched, "runProcessTeardown"),
        r"restartProcess\(req\.process\)\)\s*return", r"fallback\.caller_thread\s*=\s*null",
        r"runProcessTeardownWithoutRestart\(fallback\)")
    errors += ordered("restart snapshot stability", body(vmar, "restartSnapshotLocked"),
        r"source\.map\s*==\s*\.page_frame", r"mapcnt.*!=\s*1", r"source\.map\s*==\s*\.demand",
        r"target\.map\s*!=\s*\.unmapped", r"allocForDemandPages", r"@memcpy", r"mappingInstall", r"refreshVmarSnapshot")
    if not re.search(r"destroyThreadRefLockedMode\(thread_ref,\s*null,\s*true\)", body(thread, "destroyThreadForRestart")):
        errors.append("restart thread retirement no longer uses restart mode")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        errors = check(args.root)
    except (OSError, ValueError) as error:
        print(f"model correspondence ERROR: {error}")
        return 2
    for error in errors:
        print(f"model correspondence: {error}")
    print("model correspondence RESULT: " + ("FAIL" if errors else "OK"))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
