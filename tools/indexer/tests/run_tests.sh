#!/usr/bin/env bash
# Fixture harness for the callgraph indexer.
#
# Each fixture is a directory under tests/fixtures/:
#
#   <NN_name>/
#     kernel/…            source tree the indexer ingests as --kernel-root
#     ir.ll               (optional) pre-optimization LLVM IR passed as --ir
#     checks.sql          queries run against the produced DB
#     expected.txt        their exact expected output
#
# The harness builds one DB per fixture, runs `sqlite3 db < checks.sql`, and
# diffs against expected.txt. Regenerate a fixture's expectations after an
# intentional change with:
#
#   BLESS=1 bash tools/indexer/tests/run_tests.sh
#
# Coverage, and why these two shapes are pinned:
#
#   01/02 — LLVM quotes any global whose name falls outside
#           `[A-Za-z0-9._$-]`, which is every monomorphized Zig generic
#           (`@"a.b.SecureSlab(c.T,256).forEachAlive__anon_1234"`). The
#           original ir_pass lexer stopped at the opening quote, produced an
#           empty name, and dropped both the `define` and every call to it —
#           so a reachability query that crossed a generic silently truncated
#           while still looking authoritative.
#   03/04 — entry_point used to be a hand-maintained name list, which knew
#           3 of the 10 live x86-64 interrupt entries. Discovery now derives
#           the set from `registerVector(…)` and from `&handler` inline-asm
#           operands in `callconv(.naked)` functions.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TOOL_DIR="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
INDEXER="$TOOL_DIR/zig-out/bin/indexer"
BLESS="${BLESS:-0}"

if [[ ! -x "$INDEXER" ]]; then
    echo "Indexer not built; running zig build first." >&2
    (cd "$TOOL_DIR" && zig build) >&2
fi

command -v sqlite3 >/dev/null || { echo "sqlite3 not on PATH" >&2; exit 1; }

TMP_ROOT="$(mktemp -d -t indexer_test.XXXXXX)"
trap 'rm -rf "$TMP_ROOT"' EXIT

pass=0
fail=0
fail_list=()

for fixture in "$FIXTURES_DIR"/*/; do
    name="$(basename "$fixture")"
    [[ -d "$fixture/kernel" ]] || { echo "SKIP $name (no kernel/ tree)"; continue; }
    [[ -f "$fixture/checks.sql" ]] || { echo "SKIP $name (no checks.sql)"; continue; }

    work="$TMP_ROOT/$name"
    mkdir -p "$work"
    cp -r "$fixture/kernel" "$work/kernel"
    db="$work/fixture.db"

    args=(--kernel-root kernel --out "$db" --arch x86_64 --commit-sha fixture)
    if [[ -f "$fixture/ir.ll" ]]; then
        cp "$fixture/ir.ll" "$work/ir.ll"
        args+=(--ir ir.ll)
    fi

    if ! (cd "$work" && "$INDEXER" "${args[@]}") > "$work/index.log" 2>&1; then
        echo "FAIL $name (indexer failed)"
        sed 's/^/    /' "$work/index.log"
        fail=$((fail + 1)); fail_list+=("$name"); continue
    fi

    if ! sqlite3 "$db" < "$fixture/checks.sql" > "$work/actual.txt" 2> "$work/sql.err"; then
        echo "FAIL $name (checks.sql failed)"
        sed 's/^/    /' "$work/sql.err"
        fail=$((fail + 1)); fail_list+=("$name"); continue
    fi

    if [[ "$BLESS" == "1" ]]; then
        cp "$work/actual.txt" "$fixture/expected.txt"
        echo "BLESS $name"
        pass=$((pass + 1))
        continue
    fi

    if [[ ! -f "$fixture/expected.txt" ]]; then
        echo "FAIL $name (no expected.txt — run with BLESS=1 to create)"
        sed 's/^/    /' "$work/actual.txt"
        fail=$((fail + 1)); fail_list+=("$name"); continue
    fi

    if diff -u "$fixture/expected.txt" "$work/actual.txt" > "$work/diff.txt"; then
        echo "PASS $name"
        pass=$((pass + 1))
    else
        echo "FAIL $name"
        sed 's/^/    /' "$work/diff.txt"
        fail=$((fail + 1)); fail_list+=("$name")
    fi
done

echo ""
echo "Results: $pass pass, $fail fail"
if (( fail > 0 )); then
    printf '  failed: %s\n' "${fail_list[@]}"
    exit 1
fi
