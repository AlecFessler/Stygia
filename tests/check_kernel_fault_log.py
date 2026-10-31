#!/usr/bin/env python3
"""Report kernel faults in a runner serial log, with one proved test exception."""

import argparse
from pathlib import Path
import re


RUN = re.compile(r"^\[runner\] === run \d+/\d+ ===$")
TERMINAL = re.compile(
    r"^\[pre-report-terminal\] tag=0x([0-9a-f]+) index=([0-9a-f]+) .* "
    r"thread=(0x[0-9a-f]+) reason=unhandled_thread_fault subcode=([0-9a-f]+)$"
)
UNHANDLED = re.compile(
    r"\[UNHANDLED\] thread_fault thread=(0x[0-9a-f]+) "
    r"subcode=([0-9a-f]+)(?: |$)"
)
PASS = "[runner] PASS breakpoint_fault_01"
MODES = {"none": None, "breakpoint_x86": "2", "breakpoint_arm": "0"}


def first_manifest_test() -> str | None:
    manifest = Path(__file__).parent / "suite" / "build.zig"
    body = manifest.read_text()
    entries = body.split("const test_entries = [_]TestEntry{", 1)
    if len(entries) != 2:
        return None
    match = re.search(r'\.name\s*=\s*"([^"]+)"', entries[1])
    return match.group(1) if match else None


def unexpected_faults(body: str, mode: str) -> list[str]:
    # Diagnostic lines can contain runner progress ticks even on a clean run.
    lines = body.replace("~", "").splitlines()
    run = 0
    fault_terminals: list[tuple[int, int, str, str, str, str, str]] = []
    passes: dict[int, list[int]] = {}
    faults: list[tuple[int, int, str]] = []
    bad: list[str] = []

    for number, line in enumerate(lines):
        if RUN.match(line):
            run += 1
        if "KERNEL PANIC" in line or line.startswith("panic: "):
            bad.append(line)
        if line.startswith("[pre-report-terminal]") and "reason=unhandled_thread_fault" in line:
            match = TERMINAL.match(line)
            if match:
                tag, index, thread, subcode = match.groups()
                fault_terminals.append((run, number, line, tag, index, thread, subcode))
            else:
                bad.append(line)
        if line == PASS:
            passes.setdefault(run, []).append(number)
        if "[UNHANDLED]" in line:
            faults.append((run, number, line))

    expected_subcode = MODES[mode]
    manifest_matches = first_manifest_test() == "breakpoint_fault_01"
    matched_faults: set[int] = set()
    for fault_run, number, line, tag, index, thread, subcode in fault_terminals:
        later_passes = [entry for entry in passes.get(fault_run, []) if entry > number]
        if (expected_subcode is None or not manifest_matches or tag != "8000" or index != "0"
                or subcode != expected_subcode or not later_passes):
            bad.append(line)
            continue
        pass_at = later_passes[0]
        # Match an intact fault line to the terminal record by thread,
        # architecture subcode, and position before the test's PASS.
        matching = [
            fault_at for run_at, fault_at, fault_line in faults
            if run_at == fault_run and number < fault_at < pass_at
            and fault_at not in matched_faults
            and (fault := UNHANDLED.search(fault_line)) is not None
            and fault.groups() == (thread, expected_subcode)
        ]
        if matching:
            matched_faults.add(matching[0])
            continue
        # The locked terminal record itself supplies subcode evidence when
        # the raw [UNHANDLED] writer interleaves with another core.

    for _run, number, line in faults:
        if number not in matched_faults:
            bad.append(line)
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--mode", choices=MODES, default="none")
    args = parser.parse_args()
    for line in unexpected_faults(args.log.read_bytes().decode("utf-8", "replace"), args.mode):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
