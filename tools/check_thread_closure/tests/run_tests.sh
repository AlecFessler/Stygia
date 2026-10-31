#!/usr/bin/env bash
# Fixture harness for check_thread_closure.
#
# Mirrors tools/check_gen_lock/tests/run_tests.sh: each fixture is a small
# self-contained kernel tree, indexed into a fixture.db, then handed to the
# analyzer with `--summary`. The first comment line of each fixture declares
# the expected values as `key=value` pairs matched against the analyzer's
# `Summary[...]:` line:
#
#     // EXPECT: sources=1 async_sources=1 plain_thread_classes=0
#
# Only the keys listed are checked, so a fixture asserts exactly the
# property it is about and stays insensitive to everything else.
#
# Each fixture file becomes `kernel/arch/x64/irq.zig` in the temp tree: that
# is where `registerVector` lives, so a single file can exercise ISR seed
# discovery, the wake closure, lock-class declaration and acquire-site
# classification together. The harness writes the surrounding scaffolding
# (the wake primitives, the SpinLock type, one syscall entry point) that
# every fixture shares.
#
# The fixture DBs are built WITHOUT `--ir`. That is deliberate: it proves
# the syntactic-overlay call graph carries both rules on its own, which is
# the property that lets the analyzer see through monomorphized generics on
# the real tree.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TOOL_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd -- "$TOOL_DIR/../.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
ANALYZER="$TOOL_DIR/zig-out/bin/check_thread_closure"
INDEXER="$REPO_ROOT/tools/indexer/zig-out/bin/indexer"

if [[ ! -x "$ANALYZER" ]]; then
    echo "Analyzer not built; running zig build first." >&2
    (cd "$TOOL_DIR" && zig build) >&2
fi
if [[ ! -x "$INDEXER" ]]; then
    echo "Indexer not built; running zig build in tools/indexer first." >&2
    (cd "$REPO_ROOT/tools/indexer" && zig build) >&2
fi

TMP_ROOT="$(mktemp -d -t check_thread_closure_test.XXXXXX)"
trap 'rm -rf "$TMP_ROOT"' EXIT

mkdir -p "$TMP_ROOT/kernel/sched" \
         "$TMP_ROOT/kernel/utils/sync" \
         "$TMP_ROOT/kernel/syscall" \
         "$TMP_ROOT/kernel/arch/x64" \
         "$TMP_ROOT/kernel/arch/dispatch"

# ── Shared scaffolding ────────────────────────────────────────────────
# The three wake primitives the analyzer resolves by qualified name. If a
# rename ever breaks them the analyzer exits 2, and every fixture fails
# loudly — which is the intended failure mode.
cat > "$TMP_ROOT/kernel/sched/thread.zig" <<'EOF'
pub const State = enum { running, ready, futex_wait };
pub fn tryClaimWake(thread: *u64, expected: State) bool {
    _ = expected;
    return thread.* != 0;
}
EOF

cat > "$TMP_ROOT/kernel/sched/scheduler.zig" <<'EOF'
pub fn enqueue(thread: *u64) void {
    enqueueOnCore(thread, 0);
}
pub fn enqueueOnCore(thread: *u64, core: u8) void {
    _ = thread;
    _ = core;
}
EOF

cat > "$TMP_ROOT/kernel/utils/sync/spin_lock.zig" <<'EOF'
pub const SrcLoc = u64;
pub const SpinLock = struct {
    state: u32 = 0,
    class: [*:0]const u8 = "@unclassified",

    pub fn lock(self: *SpinLock, src: SrcLoc) void {
        _ = self;
        _ = src;
    }
    pub fn lockOrdered(self: *SpinLock, src: SrcLoc, group: u32) void {
        _ = self;
        _ = src;
        _ = group;
    }
    pub fn tryLock(self: *SpinLock, src: SrcLoc) bool {
        _ = self;
        _ = src;
        return true;
    }
    pub fn unlock(self: *SpinLock) void {
        _ = self;
    }
    pub fn lockIrqSave(self: *SpinLock, src: SrcLoc) u64 {
        _ = self;
        _ = src;
        return 0;
    }
    pub fn lockIrqSaveOrdered(self: *SpinLock, src: SrcLoc, group: u32) u64 {
        _ = self;
        _ = src;
        _ = group;
        return 0;
    }
    pub fn unlockIrqRestore(self: *SpinLock, state: u64) void {
        _ = self;
        _ = state;
    }
};
EOF

# `interrupts.registerVector` — the seed-discovery anchor.
cat > "$TMP_ROOT/kernel/arch/x64/interrupts.zig" <<'EOF'
pub const VectorKind = enum { external, exception };
pub const Handler = *const fn (ctx: *u64) void;
pub fn registerVector(vector: u8, handler: Handler, kind: VectorKind) void {
    _ = vector;
    _ = handler;
    _ = kind;
}
EOF

# Fixture 02: a plain generic-kernel wake path.
cat > "$TMP_ROOT/kernel/sched/expiry.zig" <<'EOF'
const thread = @import("thread.zig");
const scheduler = @import("scheduler.zig");

var thread_slot: u64 = 1;

pub fn expireDeadlines() void {
    if (thread.tryClaimWake(&thread_slot, .futex_wait)) {
        scheduler.enqueue(&thread_slot);
    }
}
EOF

# Fixture 03: the monomorphized-generic callback shape. `forEachAlive` is
# a method on a generic type, so the real indexer emits no ir_call edge for
# it and the visitor is reachable only through the address-taken reference.
cat > "$TMP_ROOT/kernel/sched/propagate.zig" <<'EOF'
const thread = @import("thread.zig");

pub fn Slab(comptime T: type) type {
    return struct {
        marker: T = undefined,
        pub fn forEachAlive(self: *@This(), cb: *const fn (*u64) bool) void {
            _ = self;
            var slot: u64 = 1;
            _ = cb(&slot);
        }
    };
}

var slab_instance: Slab(u64) = .{};

fn wakeVisitor(slot: *u64) bool {
    return thread.tryClaimWake(slot, .futex_wait);
}

pub fn propagateAndWake() void {
    slab_instance.forEachAlive(wakeVisitor);
}
EOF

# One syscall entry point so Rule B can tell thread context from IRQ context.
# The indexer's no-`--ir` fallback marks every fn under syscall/ as a
# syscall entry.
cat > "$TMP_ROOT/kernel/syscall/probe.zig" <<'EOF'
const irq = @import("../arch/x64/irq.zig");
pub fn sysProbe() void {
    irq.ecPath();
}
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

    cp "$fixture" "$TMP_ROOT/kernel/arch/x64/irq.zig"
    db_path="$TMP_ROOT/$name.db"
    rm -f "$db_path" "$db_path.tmp" "$db_path-wal" "$db_path-shm"
    (cd "$TMP_ROOT" && "$INDEXER" --kernel-root kernel --out "$db_path" \
        --arch x86_64 --commit-sha fixture) > "$TMP_ROOT/$name.index.log" 2>&1

    out="$("$ANALYZER" --db "$db_path" --summary 2>&1 || true)"
    summary="$(printf '%s\n' "$out" | grep -o 'Summary\[.*' || true)"
    rm -f "$db_path" "$db_path-wal" "$db_path-shm"

    if [[ -z "$summary" ]]; then
        echo "FAIL $name (analyzer produced no Summary line)"
        printf '%s\n' "$out" | sed 's/^/    /'
        fail=$((fail + 1)); fail_list+=("$name"); continue
    fi

    ok=1
    detail=""
    for kv in $expected; do
        key="${kv%%=*}"
        want="${kv#*=}"
        got="$(printf '%s\n' "$summary" | sed -n "s/.*[ []$key=\([0-9]\+\).*/\1/p" | head -n 1)"
        if [[ "$got" != "$want" ]]; then
            ok=0
            detail+=" $key: want=$want got=${got:-<missing>}"
        fi
    done

    if (( ok )); then
        echo "PASS $name ($expected)"
        pass=$((pass + 1))
    else
        echo "FAIL $name —$detail"
        printf '    %s\n' "$summary"
        fail=$((fail + 1)); fail_list+=("$name")
    fi
done

echo ""
echo "Results: $pass pass, $fail fail"
if (( fail > 0 )); then
    printf '  failed: %s\n' "${fail_list[@]}"
    exit 1
fi
