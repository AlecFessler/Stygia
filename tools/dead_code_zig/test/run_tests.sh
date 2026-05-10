#!/usr/bin/env bash
# Fixture suite for dead_code_zig.
#
# Each fixture lives under tests/fixtures/<NN>_<name>/ with:
#   - kernel/<files>.zig  — a tiny source tree the indexer ingests
#   - expected.txt        — sorted set of "UNUSED <KIND>: <name>" lines
#                           the analyzer should emit (no file/line — only
#                           the kind+name, since line numbers in toy
#                           fixtures are unstable).
#
# We build a fresh DB per fixture using tools/indexer (no IR/ELF — the
# fallback `entry_point` rule kicks in for syscall-style fns; for
# dead_code we don't need entries at all, just `kEntry` as the seed via
# the indexer's existing `main.kEntry` boot rule).

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STYGIA_ROOT="$(cd -- "$HERE/../../.." && pwd)"

INDEXER="$STYGIA_ROOT/tools/indexer/zig-out/bin/indexer"
ANALYZER="$STYGIA_ROOT/tools/dead_code_zig/zig-out/bin/dead_code_zig"

if [[ ! -x "$INDEXER" ]]; then
    (cd "$STYGIA_ROOT/tools/indexer" && zig build) >&2 \
        || { echo "indexer build failed" >&2; exit 2; }
fi
if [[ ! -x "$ANALYZER" ]]; then
    (cd "$STYGIA_ROOT/tools/dead_code_zig" && zig build) >&2 \
        || { echo "analyzer build failed" >&2; exit 2; }
fi

TMP_ROOT="$(mktemp -d -t dead_code_test.XXXXXX)"
trap 'rm -rf "$TMP_ROOT"' EXIT

pass=0
fail=0

for fixture_dir in "$HERE"/fixtures/*/; do
    fixture_name="$(basename "$fixture_dir")"
    expected="$fixture_dir/expected.txt"
    if [[ ! -f "$expected" ]]; then
        echo "SKIP $fixture_name (no expected.txt)"
        continue
    fi

    db="$TMP_ROOT/$fixture_name.db"
    rm -f "$db"

    # Build a per-fixture DB. No --ir / --elf — the analyzer's alive-set
    # fallback handles fixtures (kEntry seeds via the boot rule, alias
    # closure walks via const_alias).
    if ! (cd "$fixture_dir" && "$INDEXER" \
            --kernel-root kernel \
            --out "$db" \
            --arch x86_64 \
            --commit-sha fixture >/dev/null 2>&1); then
        echo "FAIL $fixture_name (indexer failed)"
        fail=$((fail+1))
        continue
    fi

    # Pass --skip when the fixture provides a per-fixture skip file. Two
    # accepted locations: <fixture>/skip.txt (preferred for new fixtures)
    # and <fixture>/kernel/.dead-code-skip.txt (legacy convention). The
    # analyzer's defaultSkipPath resolves against cwd to a location no
    # fixture supplies, so without --skip the skip file is silently
    # ignored — pre-bd-na6c, fixture 02 was passing only because
    # `deadConst` is reported regardless of skip-list state.
    skip_args=()
    if [[ -f "$fixture_dir/skip.txt" ]]; then
        skip_args=(--skip "$fixture_dir/skip.txt")
    elif [[ -f "$fixture_dir/kernel/.dead-code-skip.txt" ]]; then
        skip_args=(--skip "$fixture_dir/kernel/.dead-code-skip.txt")
    fi

    # Run analyzer; strip line numbers + paths, keep only "UNUSED <KIND>: <name>".
    actual="$(cd "$fixture_dir" && "$ANALYZER" --db "$db" --target kernel "${skip_args[@]}" 2>/dev/null \
        | grep '^  UNUSED' \
        | sed -E 's/^  (UNUSED [A-Z]+: [^ ]+).*/\1/' \
        | sort -u)"
    expected_sorted="$(sort -u "$expected")"

    if [[ "$actual" != "$expected_sorted" ]]; then
        echo "FAIL $fixture_name"
        echo "    expected:"
        printf '%s\n' "$expected_sorted" | sed 's/^/      /'
        echo "    got:"
        printf '%s\n' "$actual" | sed 's/^/      /'
        fail=$((fail+1))
        continue
    fi

    # Multi-DB smoke: passing the same DB twice augments the alive-set
    # with itself. Every alive qname is already covered by the primary's
    # alive_named, so the qname-keyed alt filter is a no-op and output
    # must match single-DB. Guards against regressions in the alt-DB
    # plumbing (arg parsing, qname extraction, hash lookup).
    multi="$(cd "$fixture_dir" && "$ANALYZER" --db "$db" --db "$db" --target kernel "${skip_args[@]}" 2>/dev/null \
        | grep '^  UNUSED' \
        | sed -E 's/^  (UNUSED [A-Z]+: [^ ]+).*/\1/' \
        | sort -u)"
    if [[ "$actual" != "$multi" ]]; then
        echo "FAIL $fixture_name (multi-db idempotency)"
        echo "    single-db:"
        printf '%s\n' "$actual" | sed 's/^/      /'
        echo "    multi-db (--db x --db x):"
        printf '%s\n' "$multi" | sed 's/^/      /'
        fail=$((fail+1))
        continue
    fi

    echo "PASS $fixture_name"
    pass=$((pass+1))
done

echo ""
echo "Results: $pass pass, $fail fail"
[[ $fail -eq 0 ]] || exit 1
