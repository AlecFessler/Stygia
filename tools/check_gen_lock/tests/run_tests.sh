#!/usr/bin/env bash
# Test harness for check_gen_lock per-path release coverage.
#
# Each fixture file under tests/fixtures/ defines a small slab type and
# one or more `pub fn sys*` entry points exercising a canonical
# leak-or-not-leak pattern. The first comment line of each fixture
# declares the expected outcome:
#
#   // EXPECT: clean
#   // EXPECT: errors=N
#
# We materialize a temp tree shaped like `kernel/syscall/<fixture>.zig`
# plus a `kernel/<slab>.zig`, then run the indexer over it to produce a
# fixture.db, and finally run the analyzer with `--db fixture.db
# --summary`. Per the rewrite, the analyzer reads from SQLite instead of
# walking the source tree directly.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TOOL_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd -- "$TOOL_DIR/../.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
ANALYZER="$TOOL_DIR/zig-out/bin/check_gen_lock"
INDEXER="$REPO_ROOT/tools/indexer/zig-out/bin/indexer"

if [[ ! -x "$ANALYZER" ]]; then
    echo "Analyzer not built; running zig build first." >&2
    (cd "$TOOL_DIR" && zig build) >&2
fi

if [[ ! -x "$INDEXER" ]]; then
    echo "Indexer not built; running zig build in tools/indexer first." >&2
    (cd "$REPO_ROOT/tools/indexer" && zig build) >&2
fi

TMP_ROOT="$(mktemp -d -t check_gen_lock_test.XXXXXX)"
trap 'rm -rf "$TMP_ROOT"' EXIT

mkdir -p "$TMP_ROOT/kernel/syscall"
# Slab-type backing module — every fixture needs at least one
# slab-backed type discoverable by the analyzer (`_gen_lock` field).
cat > "$TMP_ROOT/kernel/slab.zig" <<'EOF'
pub const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};
EOF

pass=0
fail=0
fail_list=()

for fixture in "$FIXTURES_DIR"/*.zig; do
    name="$(basename "$fixture" .zig)"
    expect_line="$(head -n 1 "$fixture")"
    expected=""
    if [[ "$expect_line" =~ ^//[[:space:]]*EXPECT:[[:space:]]*(.*)$ ]]; then
        expected="${BASH_REMATCH[1]}"
    fi
    if [[ -z "$expected" ]]; then
        echo "SKIP $name (no EXPECT directive)"
        continue
    fi

    cp "$fixture" "$TMP_ROOT/kernel/syscall/$name.zig"
    db_path="$TMP_ROOT/$name.db"
    rm -f "$db_path" "$db_path.tmp"
    # Build DB. The indexer expects to be run from the repo root for
    # the `kernel/` path-prefix convention; here we emulate that by
    # cd'ing into TMP_ROOT.
    (cd "$TMP_ROOT" && "$INDEXER" --kernel-root kernel --out "$db_path" --arch x86_64 --commit-sha fixture) >/dev/null 2>&1
    out="$("$ANALYZER" --db "$db_path" --summary 2>&1 || true)"
    rm "$TMP_ROOT/kernel/syscall/$name.zig"
    rm -f "$db_path"

    # Debug a single fixture by uncommenting:
    # echo "$out" | sed 's/^/  >>> /'

    # Per-entry rows print `err= N` (space-padded); the Summary line
    # prints `<N> err,`. Sum both: per-entry covers fn-scoped findings,
    # Summary covers asm/IRQ/etc. that aren't pinned to one entry.
    per_entry="$(echo "$out" | sed -n 's/.*err= *\([0-9]\+\).*/\1/p' | head -n 1)"
    per_entry="${per_entry:-0}"
    summary="$(echo "$out" | sed -n 's/^Summary:.* \([0-9]\+\) err,.*/\1/p' | head -n 1)"
    summary="${summary:-0}"
    # The Summary err count already includes per-entry errors (it's the
    # rolling total). Prefer Summary when present; fall back to per-entry.
    if [[ "$summary" -gt 0 ]]; then
        err_count="$summary"
    else
        err_count="$per_entry"
    fi

    case "$expected" in
        clean)
            if [[ "$err_count" == "0" ]]; then
                echo "PASS $name (clean)"
                pass=$((pass + 1))
            else
                echo "FAIL $name (expected clean, got err=$err_count)"
                echo "$out" | sed 's/^/    /'
                fail=$((fail + 1))
                fail_list+=("$name")
            fi
            ;;
        errors=*)
            want="${expected#errors=}"
            if [[ "$err_count" == "$want" ]]; then
                echo "PASS $name (errors=$want)"
                pass=$((pass + 1))
            else
                echo "FAIL $name (expected errors=$want, got err=$err_count)"
                echo "$out" | sed 's/^/    /'
                fail=$((fail + 1))
                fail_list+=("$name")
            fi
            ;;
        *)
            echo "FAIL $name (unknown EXPECT: $expected)"
            fail=$((fail + 1))
            fail_list+=("$name")
            ;;
    esac
done

echo ""
echo "Results: $pass pass, $fail fail"
if (( fail > 0 )); then
    printf '  failed: %s\n' "${fail_list[@]}"
    exit 1
fi
