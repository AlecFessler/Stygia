#!/usr/bin/env python3
"""Report kernel faults in a runner serial log, allowing proved child faults."""

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
PASS = re.compile(r"^\[runner\] PASS ([A-Za-z0-9_]+)$")
MODES = {"none": None, "breakpoint_x86": "2", "breakpoint_arm": "0"}

# These observers deliberately use INT3/BRK in a nested process and report
# PASS only after the parent has witnessed the specified restart or teardown.
# The tag check below binds each fault to its exact manifest test, so a fault
# from any other suite entry still fails the gate.
RESTART_FAULT_TESTS = frozenset({
    "handle_restart_page_frame_drop", "handle_restart_page_frame_keep",
    "handle_restart_device_region_drop", "handle_restart_device_region_keep",
    "handle_restart_port_drop", "handle_restart_port_keep",
    "handle_restart_virtual_machine_drop", "handle_restart_virtual_machine_keep",
    "handle_restart_ipc_drop", "handle_restart_ipc_keep",
    "reply_restart_drop", "reply_restart_keep",
    "process_restart_01", "process_restart_03", "process_restart_04",
    "process_restart_05", "process_restart_06",
    "process_restart_term_before", "process_restart_term_after",
    "process_restart_persist_trigger",
    "vmar_restart_00", "vmar_restart_01", "vmar_restart_02",
    "vmar_restart_03", "vmar_restart_pf_shared",
    "snapshot_07", "snapshot_08", "snapshot_09", "snapshot_10", "snapshot_11",
    "snapshot_multi_page_pf",
})
EXPECTED_FAULT_TESTS = RESTART_FAULT_TESTS | {"breakpoint_fault_01"}


def manifest_test_names() -> list[str]:
    manifest = Path(__file__).parent / "suite" / "build.zig"
    body = manifest.read_text()
    entries = body.split("const test_entries = [_]TestEntry{", 1)
    if len(entries) != 2:
        return []
    return re.findall(r'\.name\s*=\s*"([^"]+)"', entries[1].split("};", 1)[0])


def unexpected_faults(body: str, mode: str) -> list[str]:
    # Diagnostic lines can contain runner progress ticks even on a clean run.
    lines = body.replace("~", "").splitlines()
    run = 0
    fault_terminals: list[tuple[int, int, str, str, str, str, str]] = []
    passes: dict[int, dict[str, list[int]]] = {}
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
        if match := PASS.match(line):
            passes.setdefault(run, {}).setdefault(match.group(1), []).append(number)
        if "[UNHANDLED]" in line:
            faults.append((run, number, line))

    expected_subcode = MODES[mode]
    manifest = manifest_test_names()
    matched_faults: set[int] = set()
    for fault_run, number, line, tag, index, thread, subcode in fault_terminals:
        test_index = int(index, 16)
        test_name = manifest[test_index] if test_index < len(manifest) else None
        later_passes = [entry for entry in passes.get(fault_run, {}).get(test_name, []) if entry > number]
        if (expected_subcode is None or test_name not in EXPECTED_FAULT_TESTS
                or int(tag, 16) != (0x8000 | test_index) or subcode != expected_subcode
                or not later_passes):
            bad.append(line)
            continue
        pass_at = later_passes[0]
        # The locked terminal record supplies identity and subcode evidence.
        # The raw printer can interleave with another core, leaving one
        # malformed [UNHANDLED] line between that record and the test PASS.
        # Claim at most one such line; an intact line with different identity
        # or subcode, or any additional line, remains an unexpected fault.
        interval = [
            (fault_at, fault_line) for run_at, fault_at, fault_line in faults
            if run_at == fault_run and number < fault_at < pass_at
            and fault_at not in matched_faults
        ]
        matching = [
            fault_at for fault_at, fault_line in interval
            if (fault := UNHANDLED.search(fault_line)) is not None
            and fault.groups() == (thread, expected_subcode)
        ]
        if matching:
            matched_faults.add(matching[0])
        elif len(interval) == 1 and UNHANDLED.search(interval[0][1]) is None:
            matched_faults.add(interval[0][0])

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
