#!/usr/bin/env python3
"""Verify spec-v3 assertions against test files and explicit coverage gaps.

Spec source: docs/kernel/specv3.md
Test files:  tests/suite/cases/<section>_<NN>.zig

Spec format:
  Sections are level-3 markdown headings (`### name`). Each section accumulates
  every `[test NN] ...` line that appears between the heading and the next
  `### ` or `## ` heading. Sections without `[test ]` lines are silently empty.

Section name extraction:
  - `### foo_bar`              -> `foo_bar`
  - `### Self handle`          -> `self_handle`        (lowercase, spaces -> _)
  - `### §[anchor] Pretty`     -> `anchor`             (anchor verbatim)

Test number (NN):
  - May contain an alphanumeric suffix, e.g. `[test 16a]` -> file
    `<section>_16a.zig`. Numeric-only is the common case (`01`..`30`).

Test file naming:
  Each spec test `[test NN]` under `### <section>` is expected to have a
  corresponding file at tests/suite/cases/<section>_<NN>.zig.

Cross-checks (both directions):
  - Every spec test entry has a matching test file or an explicit known gap
    (else: MISSING TEST FILE).
  - Every test file has a matching spec entry (else: ORPHAN TEST FILE).

Exits 0 if every assertion is covered or explicitly tracked, 1 otherwise.
"""

import os
import re
import sys
from collections import defaultdict


SPEC_PATH = os.path.join(os.path.dirname(__file__), "../../docs/kernel/specv3.md")
TESTS_DIR = os.path.join(os.path.dirname(__file__), "cases")

# Matches "[test NN]" at the start of a line (after optional whitespace).
# NN is one or more alphanumerics — handles `01`, `30`, `16a`, etc.
TEST_LINE_RE = re.compile(r"^\s*\[test\s+([A-Za-z0-9]+)\]\s*(.*)$")

# `### §[anchor] Pretty Title` -> capture `anchor`.
ANCHOR_HEADING_RE = re.compile(r"^###\s+§\[([A-Za-z0-9_]+)\]")

# `### plain heading` -> capture the rest of the heading.
PLAIN_HEADING_RE = re.compile(r"^###\s+(.+?)\s*$")

# Test file name `<section>_<NN>.zig` where NN is alphanumeric.
TEST_FILE_RE = re.compile(r"^(?P<section>[A-Za-z][A-Za-z0-9_]*?)_(?P<num>[0-9]+[a-z]?)\.zig$")

# Regression/smoke ELFs that are intentionally part of the suite manifest
# but are not one-to-one assertions from docs/kernel/specv3.md.
NON_SPEC_TEST_FILES = {
    "scheduler_balance_01.zig",
}

# Valid assertions with no faithful test in the current suite. Each requires
# fixture design in the
# test-review issue Stygia-o4a.6.4. Keep the spec assertion; reject any
# unlisted gap or stale entry here.
KNOWN_MISSING_TESTS = {
    # Lower target-domain thread ceiling is unavailable in the current fixture.
    "create_thread_04.zig": "lower thread_outer_ceiling fixture",
    "create_thread_05.zig": "lower thread_inner_ceiling fixture",
    "create_vcpu_02.zig": "lower VM-owner thread_inner_ceiling fixture",
    # These observations require a runner-side reporting fixture.
    "map_pf_12.zig": "permission-fault teardown observation fixture",
    "self_01.zig": "self-handle result reporting fixture",
    # Port-I/O fault assertions need an issued device_region and a runner
    # that can observe the child domain's unhandled-fault teardown.
    **{f"port_io_virtualization_{num:02}.zig": "port-I/O fault fixture"
       for num in range(6, 12)},
}


def section_name_from_heading(heading_line: str) -> str | None:
    """Return canonical section name for a `### ...` heading, or None.

    Returns None for anything that isn't a level-3 heading.
    """
    if not heading_line.startswith("###"):
        return None
    if heading_line.startswith("####"):
        return None

    m = ANCHOR_HEADING_RE.match(heading_line)
    if m:
        return m.group(1)

    m = PLAIN_HEADING_RE.match(heading_line)
    if not m:
        return None
    name = m.group(1).strip()
    # Lowercase + spaces -> underscores. Drop characters that can't appear in
    # a file stem (parens, dashes inside parens, etc.). For sections that don't
    # have tests this transformation doesn't matter.
    name = name.lower().replace(" ", "_")
    return name


def parse_spec(path: str) -> tuple[dict[str, dict[str, str]], int]:
    """Parse spec-v3.

    Returns:
      ({ section_name: { test_num: assertion_text } }, warning_count)

    Sections that produce zero tests are omitted from the result.
    """
    sections: dict[str, dict[str, str]] = defaultdict(dict)
    current: str | None = None
    warnings = 0

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")

            # Section boundaries: any `## ` (level 2) ends the current section.
            # `### ` either starts a new one or — if it's something like a
            # `### vreg mapping` heading without tests — produces a section
            # name we'll just never look up.
            if line.startswith("## ") and not line.startswith("### "):
                current = None
                continue

            if line.startswith("### "):
                current = section_name_from_heading(line)
                continue

            if current is None:
                continue

            m = TEST_LINE_RE.match(line)
            if not m:
                continue
            num, text = m.group(1), m.group(2).strip()
            if num in sections[current]:
                # Duplicate within the same section — flag but keep the first.
                print(
                    f"WARNING: duplicate spec test [{num}] under ### {current}",
                    file=sys.stderr,
                )
                warnings += 1
                continue
            sections[current][num] = text

    # Drop any sections that ended up empty (e.g. anchor headings whose body
    # contained no `[test]` lines).
    return ({sec: tests for sec, tests in sections.items() if tests}, warnings)


def parse_tests(tests_dir: str) -> dict[str, set[str]]:
    """Discover test files.

    Returns:
      { section_name: set_of_test_nums }
    """
    files: dict[str, set[str]] = defaultdict(set)
    if not os.path.isdir(tests_dir):
        print(f"FATAL: tests directory not found: {tests_dir}", file=sys.stderr)
        sys.exit(2)

    for fname in sorted(os.listdir(tests_dir)):
        if not fname.endswith(".zig"):
            continue
        if fname in NON_SPEC_TEST_FILES:
            continue
        m = TEST_FILE_RE.match(fname)
        if not m:
            print(
                f"WARNING: ignoring test file with unrecognized name: {fname}",
                file=sys.stderr,
            )
            continue
        section = m.group("section")
        num = m.group("num")
        files[section].add(num)
    return files


def longest_section_match(filename_section: str, spec_sections: set[str]) -> str | None:
    """For a test file's parsed prefix, find the longest spec section that
    is a prefix of it.

    Necessary because the file naming `<section>_<NN>.zig` is greedy: a file
    named `create_capability_domain_16.zig` parses (per the regex) as section
    `create_capability_domain` + num `16`. But for a hypothetical file named
    `foo_bar_baz_01.zig` where the spec section is `foo_bar`, we'd want to
    re-attribute the trailing `_baz` as part of the test number stem... no:
    the spec test ids never contain underscores, so `<section>_<NN>` is
    actually unambiguous given the spec sections we know about.

    This helper exists so we can detect orphans whose section name doesn't
    appear in the spec at all.
    """
    if filename_section in spec_sections:
        return filename_section
    return None


def main() -> int:
    spec, spec_warnings = parse_spec(SPEC_PATH)
    tests = parse_tests(TESTS_DIR)

    spec_total = sum(len(v) for v in spec.values())
    tests_total = sum(len(v) for v in tests.values())

    missing: dict[str, list[str]] = defaultdict(list)   # spec entry, no file
    orphan: dict[str, list[str]] = defaultdict(list)    # file, no spec entry
    known_missing: dict[str, list[str]] = defaultdict(list)
    unknown_sections: list[str] = []                    # file section absent from spec

    spec_section_names = set(spec.keys())

    # Direction 1: every spec test has a matching file.
    for section, tests_in_sec in spec.items():
        file_nums = tests.get(section, set())
        for num in tests_in_sec:
            if num not in file_nums:
                fname = f"{section}_{num}.zig"
                if fname in KNOWN_MISSING_TESTS:
                    known_missing[section].append(num)
                else:
                    missing[section].append(num)

    # Direction 2: every test file has a matching spec entry.
    for section, file_nums in tests.items():
        if section not in spec_section_names:
            # The whole section is unknown to the spec.
            for num in sorted(file_nums):
                unknown_sections.append(f"{section}_{num}.zig")
            continue
        spec_nums = set(spec[section].keys())
        for num in sorted(file_nums):
            if num not in spec_nums:
                orphan[section].append(num)

    # A resolved or removed assertion must not remain hidden by the manifest.
    active_known = {f"{section}_{num}.zig" for section, nums in known_missing.items() for num in nums}
    stale_known = sorted(set(KNOWN_MISSING_TESTS) - active_known)

    # Report.
    mismatch_count = (
        sum(len(v) for v in missing.values())
        + sum(len(v) for v in orphan.values())
        + len(unknown_sections)
        + len(stale_known)
    )

    if missing:
        print("== Missing test files (spec entry exists, file does not) ==")
        for section in sorted(missing):
            for num in sorted(missing[section]):
                text = spec[section][num]
                print(f"  {section}_{num}.zig  --  [test {num}] {text}")

    if known_missing:
        print("== Tracked coverage gaps (Stygia-o4a.6.4) ==")
        for section in sorted(known_missing):
            for num in sorted(known_missing[section]):
                fname = f"{section}_{num}.zig"
                print(f"  {fname}  --  {KNOWN_MISSING_TESTS[fname]}")
        print()

    if stale_known:
        print("== Stale coverage-gap entries (remove after test restoration/spec removal) ==")
        for fname in stale_known:
            print(f"  {fname}")
        print()

    if orphan:
        if missing:
            print()
        print("== Orphan test files (file exists, no matching spec entry) ==")
        for section in sorted(orphan):
            for num in sorted(orphan[section]):
                print(f"  {section}_{num}.zig  --  no [test {num}] under ### {section}")

    if unknown_sections:
        if missing or orphan:
            print()
        print("== Unknown sections (file's section name not in spec) ==")
        for fname in unknown_sections:
            print(f"  {fname}")

    if mismatch_count:
        print()
    print(
        f"Spec has {spec_total} tests; "
        f"{os.path.relpath(TESTS_DIR)}/ has {tests_total} files; "
        f"{len(active_known)} tracked gaps; {mismatch_count} mismatches."
    )

    return 0 if (mismatch_count == 0 and spec_warnings == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
