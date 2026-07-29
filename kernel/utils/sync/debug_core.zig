// Pure lockdep logic — host-testable, no kernel deps.
//
// This file owns the data structures (HeldStack, PairRegistry, ClassTable)
// and the three pure check functions (acquireOn, releaseOn, checkIrqModeOn).
// Kernel wiring — global per-core state, IRQ-depth counter, panic-path
// printers, and the `acquire`/`release` wrappers — lives in debug.zig.
//
// Compiles against `std` only and is exercised on the host via
// `zig test kernel/utils/sync/debug_core.zig`.

const builtin = @import("builtin");
const std = @import("std");

pub const SrcLoc = std.builtin.SourceLocation;

pub const HELD_STACK_DEPTH: u8 = 8;
pub const MAX_CORES: usize = 8;
pub const PAIR_REGISTRY_CAPACITY: usize = 512;
pub const CLASS_TABLE_CAPACITY: usize = 256;

/// Spin ceiling for the detector's OWN internal table locks
/// (`PairRegistry.lock`, `ClassTable.lock`). On expiry the caller skips
/// that piece of bookkeeping instead of spinning forever.
///
/// Rationale: these two locks are pure debug instrumentation with no
/// correctness role in the running kernel, so degrading them is sound by
/// construction — losing one lockdep observation is strictly better than
/// losing the machine. Both were previously unbounded, and a core that
/// died or stalled while holding one wedged every other core that
/// subsequently took *any* SpinLock, because every acquire funnels
/// through `checkIrqModeOn`. That amplification turned single-core faults
/// into whole-machine wedges in the stygia-3ys corpses, and it also ate
/// the panic report: a panicking core cannot describe itself while it is
/// blocked on a lock the panic is contending over.
///
/// The ceiling is deliberately far above any healthy contention. The
/// critical sections are a bounded hash probe over a fixed-capacity
/// table with IRQs masked (see `debug.acquire`), so with `MAX_CORES`
/// contenders the true worst case is a few thousand spins; 4M leaves
/// ~1000x headroom and is only reachable when a holder is genuinely
/// never going to release.
///
/// Host tests are exempt: the failure this bounds (a core dying mid-hold)
/// cannot happen under `std.Thread`, whereas OS descheduling of a holder
/// can legitimately exceed any spin count, and a spuriously skipped
/// insertion would make the cycle-detection tests flaky.
pub const TABLE_SPIN_LIMIT: usize = if (builtin.is_test) std.math.maxInt(usize) else 1 << 22;

pub const Entry = struct {
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    ordered_group: u32,
    src: SrcLoc,
};

pub const HeldStack = struct {
    entries: [HELD_STACK_DEPTH]Entry = undefined,
    depth: u8 = 0,
};

pub const CheckResult = enum {
    ok,
    panic_recursive,
    panic_same_class,
    panic_cycle,
    panic_irq_mode_mix,
};

pub const CheckOutcome = struct {
    result: CheckResult = .ok,
    /// For recursive / same-class: the prior held entry that conflicted.
    prior: ?Entry = null,
    /// For cycle: the prior pair-registry entry whose order was reversed.
    cycle_outer: [*:0]const u8 = "",
    cycle_inner: [*:0]const u8 = "",
    cycle_prior_outer_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
    cycle_prior_inner_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
    /// True when the cycle was detected via multi-hop BFS rather than a direct
    /// inverse-pair lookup. In that case the prior srcs are not populated.
    cycle_transitive: bool = false,
    /// For panic_irq_mode_mix: src of the first IRQ-handler-context acquire of
    /// this class. The IRQ handler is the side that imposes the discipline.
    irq_handler_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
    /// For panic_irq_mode_mix: src of the first process-context acquire that
    /// took this class with IRQs *enabled* (i.e. without lockIrqSave). The
    /// pair (irq_handler_src, process_enabled_src) is the deadlock vector.
    process_enabled_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
};

pub const PairEntry = struct {
    outer: ?[*:0]const u8 = null,
    inner: [*:0]const u8 = undefined,
    outer_src: SrcLoc = undefined,
    inner_src: SrcLoc = undefined,
};

pub const PairRegistry = struct {
    entries: [PAIR_REGISTRY_CAPACITY]PairEntry = [_]PairEntry{.{}} ** PAIR_REGISTRY_CAPACITY,
    lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Scratch BFS frontier for `pathExists`. Lives inside the registry so it
    /// shares the registry's spinlock (`pathExists` requires the caller hold
    /// `lock`). Moved off the kernel stack — at 4 KiB it dominated frame size
    /// for any caller of `acquireOn`, and under deep nested-lockdep checks
    /// the cumulative stack pressure was overwriting adjacent frames'
    /// saved-RIP slots, producing cascading downstream panics.
    pathexists_visited: [PAIR_REGISTRY_CAPACITY][*:0]const u8 = undefined,

    /// Bounded acquire. Returns false if `TABLE_SPIN_LIMIT` spins elapse
    /// without the lock coming free — see that constant for why giving up
    /// is the correct behaviour here.
    fn tryAcquireLock(self: *PairRegistry) bool {
        var spins: usize = 0;
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            if (spins >= TABLE_SPIN_LIMIT) return false;
            spins += 1;
            std.atomic.spinLoopHint();
        }
        return true;
    }

    fn releaseLock(self: *PairRegistry) void {
        self.lock.store(0, .release);
    }

    fn hash(outer: [*:0]const u8, inner: [*:0]const u8) usize {
        const a: usize = @intFromPtr(outer);
        const b: usize = @intFromPtr(inner);
        // Mix the two pointers; rotate one to avoid trivial collisions
        // when (A,B) vs (B,A) are queried.
        const rot = (b << 17) | (b >> @as(u6, @intCast((@bitSizeOf(usize) - 17) & 0x3f)));
        return (a ^ rot) % PAIR_REGISTRY_CAPACITY;
    }

    /// Returns true if the pair (outer,inner) is already present.
    fn contains(self: *PairRegistry, outer: [*:0]const u8, inner: [*:0]const u8) bool {
        var idx = hash(outer, inner);
        var probes: usize = 0;
        while (probes < PAIR_REGISTRY_CAPACITY) {
            const e = self.entries[idx];
            if (e.outer == null) return false;
            if (e.outer.? == outer and e.inner == inner) return true;
            idx = (idx + 1) % PAIR_REGISTRY_CAPACITY;
            probes += 1;
        }
        return false;
    }

    /// Look up an entry's source locations. Returns null if absent.
    fn lookup(self: *PairRegistry, outer: [*:0]const u8, inner: [*:0]const u8) ?PairEntry {
        var idx = hash(outer, inner);
        var probes: usize = 0;
        while (probes < PAIR_REGISTRY_CAPACITY) {
            const e = self.entries[idx];
            if (e.outer == null) return null;
            if (e.outer.? == outer and e.inner == inner) return e;
            idx = (idx + 1) % PAIR_REGISTRY_CAPACITY;
            probes += 1;
        }
        return null;
    }

    /// Insert if absent. Silently drops on table overflow.
    fn insert(
        self: *PairRegistry,
        outer: [*:0]const u8,
        inner: [*:0]const u8,
        outer_src: SrcLoc,
        inner_src: SrcLoc,
    ) void {
        var idx = hash(outer, inner);
        var probes: usize = 0;
        while (probes < PAIR_REGISTRY_CAPACITY) {
            const e = self.entries[idx];
            if (e.outer == null) {
                self.entries[idx] = .{
                    .outer = outer,
                    .inner = inner,
                    .outer_src = outer_src,
                    .inner_src = inner_src,
                };
                return;
            }
            if (e.outer.? == outer and e.inner == inner) return;
            idx = (idx + 1) % PAIR_REGISTRY_CAPACITY;
            probes += 1;
        }
    }

    fn clear(self: *PairRegistry) void {
        var i: usize = 0;
        while (i < PAIR_REGISTRY_CAPACITY) {
            self.entries[i] = .{};
            i += 1;
        }
    }

    /// BFS the directed graph (outer -> inner) for a path from `start` to
    /// `target`. Caller must hold the registry lock. Bounded by capacity.
    ///
    /// Uses `self.pathexists_visited` as the BFS frontier so the 4 KiB
    /// working set sits in the registry rather than on the caller's kernel
    /// stack. `pathExists` itself does not recurse, and the caller already
    /// holds `lock` for the duration of this function, so single-buffer
    /// reuse is safe.
    fn pathExists(self: *PairRegistry, start: [*:0]const u8, target: [*:0]const u8) bool {
        const visited = &self.pathexists_visited;
        visited[0] = start;
        var visited_count: usize = 1;
        var head: usize = 0;
        while (head < visited_count) {
            const node = visited[head];
            head += 1;
            var k: usize = 0;
            while (k < PAIR_REGISTRY_CAPACITY) {
                const e = self.entries[k];
                k += 1;
                const outer = e.outer orelse continue;
                if (outer != node) continue;
                if (e.inner == target) return true;
                var seen = false;
                for (visited[0..visited_count]) |v| {
                    if (v == e.inner) {
                        seen = true;
                        break;
                    }
                }
                if (!seen and visited_count < PAIR_REGISTRY_CAPACITY) {
                    visited[visited_count] = e.inner;
                    visited_count += 1;
                }
            }
        }
        return false;
    }
};

/// Per-class IRQ-mode table. Each class is a string-pointer.
///
/// The genuine deadlock vector this catches: a lock class that an *async IRQ
/// handler* takes (CPU auto-masks IRQs on entry, so the handler always runs
/// with IRQs disabled) is *also* taken from process context with IRQs left
/// enabled (i.e. plain `lock()`, not `lockIrqSave`). If an IRQ lands on a
/// core that already holds the lock from process context, the handler will
/// spin forever waiting for the lock the interrupted code can't release.
///
/// We classify each acquire into one of three states using per-core IRQ-
/// handler-depth instrumentation:
///   1. in IRQ handler          → safe to acquire; this side imposes discipline.
///   2. process context, IRQs disabled  → caller used lockIrqSave (or is in a
///                                        nested IRQ-disabled section); safe.
///   3. process context, IRQs enabled   → must NOT mix with state (1).
///
/// A class observed in both (1) and (3) is the bug. Mixing (2) with anything
/// is fine — `lockIrqSave` is the documented escape hatch for "this class
/// might be taken by an IRQ handler too."
pub const ClassEntry = struct {
    class: ?[*:0]const u8 = null,
    seen_in_irq_handler: bool = false,
    seen_in_process_irqs_enabled: bool = false,
    first_irq_handler_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
    first_process_enabled_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
};

pub const ClassTable = struct {
    entries: [CLASS_TABLE_CAPACITY]ClassEntry = [_]ClassEntry{.{}} ** CLASS_TABLE_CAPACITY,
    lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Bounded acquire — see `PairRegistry.tryAcquireLock` and
    /// `TABLE_SPIN_LIMIT`. This one matters most: every `SpinLock`
    /// acquire in the kernel funnels through `checkIrqModeOn`, so an
    /// unbounded wait here is a system-wide serialization point that a
    /// single dead core can turn into a system-wide wedge.
    fn tryAcquireLock(self: *ClassTable) bool {
        var spins: usize = 0;
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            if (spins >= TABLE_SPIN_LIMIT) return false;
            spins += 1;
            std.atomic.spinLoopHint();
        }
        return true;
    }

    fn releaseLock(self: *ClassTable) void {
        self.lock.store(0, .release);
    }

    fn hash(class: [*:0]const u8) usize {
        const a: usize = @intFromPtr(class);
        return (a ^ (a >> 17)) % CLASS_TABLE_CAPACITY;
    }

    /// Record an acquire and return whether this acquire produces a genuine
    /// IRQ-mode mismatch. The mismatch fires only when the class has been
    /// observed BOTH in an async IRQ handler AND in process context with
    /// IRQs enabled — that is the exact deadlock vector.
    ///
    /// Process-context-with-IRQs-disabled (lockIrqSave) is the safe pattern
    /// and is silently ignored.
    fn record(
        self: *ClassTable,
        class: [*:0]const u8,
        in_irq_handler: bool,
        irqs_enabled: bool,
        src: SrcLoc,
    ) struct { mismatch: bool, irq_handler_src: SrcLoc, process_enabled_src: SrcLoc } {
        const empty: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" };

        // Three classifications:
        //   in_irq_handler             → state 1
        //   !in_irq_handler &&  irqs_enabled  → state 3
        //   !in_irq_handler && !irqs_enabled  → state 2 (lockIrqSave) — no-op
        if (!in_irq_handler and !irqs_enabled) {
            return .{ .mismatch = false, .irq_handler_src = empty, .process_enabled_src = empty };
        }

        var idx = hash(class);
        var probes: usize = 0;
        while (probes < CLASS_TABLE_CAPACITY) {
            const e = &self.entries[idx];
            if (e.class == null) {
                e.class = class;
                if (in_irq_handler) {
                    e.seen_in_irq_handler = true;
                    e.first_irq_handler_src = src;
                } else {
                    // process context, IRQs enabled.
                    e.seen_in_process_irqs_enabled = true;
                    e.first_process_enabled_src = src;
                }
                return .{ .mismatch = false, .irq_handler_src = empty, .process_enabled_src = empty };
            }
            if (e.class.? == class) {
                if (in_irq_handler) {
                    if (!e.seen_in_irq_handler) {
                        e.seen_in_irq_handler = true;
                        e.first_irq_handler_src = src;
                    }
                    if (e.seen_in_process_irqs_enabled) {
                        // Both sides now seen → mismatch. Always report the
                        // recorded "first" src so order of detection is stable.
                        return .{
                            .mismatch = true,
                            .irq_handler_src = e.first_irq_handler_src,
                            .process_enabled_src = e.first_process_enabled_src,
                        };
                    }
                } else {
                    // process context, IRQs enabled.
                    if (!e.seen_in_process_irqs_enabled) {
                        e.seen_in_process_irqs_enabled = true;
                        e.first_process_enabled_src = src;
                    }
                    if (e.seen_in_irq_handler) {
                        return .{
                            .mismatch = true,
                            .irq_handler_src = e.first_irq_handler_src,
                            .process_enabled_src = e.first_process_enabled_src,
                        };
                    }
                }
                return .{ .mismatch = false, .irq_handler_src = empty, .process_enabled_src = empty };
            }
            idx = (idx + 1) % CLASS_TABLE_CAPACITY;
            probes += 1;
        }
        return .{ .mismatch = false, .irq_handler_src = empty, .process_enabled_src = empty };
    }

    fn clear(self: *ClassTable) void {
        var i: usize = 0;
        while (i < CLASS_TABLE_CAPACITY) {
            self.entries[i] = .{};
            i += 1;
        }
    }
};

/// Per-core async-IRQ-handler nesting depth. Slot at index `core_id` counts
/// nested IRQ entries on that core. Single-writer per slot — only the local
/// core ever writes its own slot, between IRQ entry and IRQ exit on that
/// same core — so plain `u8` (no atomics) is sufficient.
///
/// Each step method out-of-bounds-guards on `core_id` so callers can pass
/// the raw `arch.smp.coreID()` result without a separate bounds check.
pub const IrqDepth = struct {
    slots: [MAX_CORES]u8 = [_]u8{0} ** MAX_CORES,

    /// Increment the slot at `core_id`. Wraps on overflow.
    pub fn enter(self: *IrqDepth, core_id: usize) void {
        if (core_id >= MAX_CORES) return;
        self.slots[core_id] +%= 1;
    }

    /// Decrement the slot at `core_id`. Must mirror a prior `enter`.
    pub fn exit(self: *IrqDepth, core_id: usize) void {
        if (core_id >= MAX_CORES) return;
        self.slots[core_id] -%= 1;
    }

    /// Reset `core_id`'s slot to 0. The IRQ-driven preemption paths that
    /// `noreturn jmp` to a different thread's stack abandon the deferred
    /// `exit` matching the IRQ-entry's `enter`; without this reset the
    /// counter drifts upward by one for every such preemption.
    pub fn reset(self: *IrqDepth, core_id: usize) void {
        if (core_id >= MAX_CORES) return;
        self.slots[core_id] = 0;
    }

    /// True iff `core_id`'s slot is non-zero.
    pub fn inIrq(self: *const IrqDepth, core_id: usize) bool {
        if (core_id >= MAX_CORES) return false;
        return self.slots[core_id] != 0;
    }
};

/// Pure check + mutate. Returns the outcome rather than panicking so that
/// tests can drive the logic without a real arch.smp.coreID().
pub fn acquireOn(
    stack: *HeldStack,
    registry: *PairRegistry,
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    ordered_group: u32,
    src: SrcLoc,
) CheckOutcome {
    var i: u8 = 0;
    while (i < stack.depth) {
        const held = stack.entries[i];
        if (held.lock_ptr == lock_ptr) {
            return .{ .result = .panic_recursive, .prior = held };
        }
        if (held.class == class and (ordered_group == 0 or held.ordered_group != ordered_group)) {
            return .{ .result = .panic_same_class, .prior = held };
        }
        i += 1;
    }

    // Cycle detection needs the shared registry; the held-stack push
    // below does not (it is per-core state). Keeping them separable is
    // what lets a timed-out registry acquire degrade to "skip cycle
    // detection this once" while still recording the held entry — the
    // recursive and same-class checks above read that stack, so dropping
    // the push would silently disable them too.
    if (registry.tryAcquireLock()) {
        defer registry.releaseLock();

        var j: u8 = 0;
        while (j < stack.depth) {
            const held = stack.entries[j];
            if (held.class != class) {
                // ordered_group escape extends to cross-class cycle
                // detection: when *either* side of the (held, acquiring)
                // pair is opt-in-ordered (non-zero ordered_group), the
                // caller has guaranteed safe ordering across every
                // instance involved in that group. Skip both the cycle
                // check and the edge registration for that pair so the
                // ordered acquisition does not pollute the registry with
                // an edge that contradicts another path's ordering. The
                // futex bucket group, the ipc-reply Thread/Process
                // overlap, and the fault-block Process/Thread overlap
                // all rely on this; without it, every same-class
                // ordered_group acquisition would still register a
                // distinct (held.class, class) pair edge against any
                // non-ordered lock on the held stack and seed AB-BA
                // panics on the inverse class-level pair.
                if (held.ordered_group == 0 and ordered_group == 0) {
                    if (registry.contains(class, held.class)) {
                        const prior = registry.lookup(class, held.class) orelse PairEntry{};
                        return .{
                            .result = .panic_cycle,
                            .cycle_outer = class,
                            .cycle_inner = held.class,
                            .cycle_prior_outer_src = prior.outer_src,
                            .cycle_prior_inner_src = prior.inner_src,
                        };
                    }
                    if (registry.pathExists(class, held.class)) {
                        return .{
                            .result = .panic_cycle,
                            .cycle_outer = class,
                            .cycle_inner = held.class,
                            .cycle_transitive = true,
                        };
                    }
                    registry.insert(held.class, class, held.src, src);
                }
            }
            j += 1;
        }
    }

    if (stack.depth < HELD_STACK_DEPTH) {
        stack.entries[stack.depth] = .{
            .lock_ptr = lock_ptr,
            .class = class,
            .ordered_group = ordered_group,
            .src = src,
        };
        stack.depth += 1;
    }

    return .{};
}

/// Pure check on class IRQ-mode consistency. Returns panic_irq_mode_mix when
/// the class has been observed BOTH from inside an async IRQ handler AND
/// from process context with IRQs enabled — i.e. the genuine deadlock vector.
///
/// `in_irq_handler` is true iff the local core's IRQ-handler depth > 0;
/// see `enterIrqContext` / `exitIrqContext` in debug.zig. `irqs_enabled` is
/// the raw CPU flag, used only to distinguish "lockIrqSave from process
/// context" (safe) from "plain lock() from process context" (the bug side).
pub fn checkIrqModeOn(
    table: *ClassTable,
    class: [*:0]const u8,
    in_irq_handler: bool,
    irqs_enabled: bool,
    src: SrcLoc,
) CheckOutcome {
    // Degrade rather than block — see `TABLE_SPIN_LIMIT`. Skipping one
    // observation can only lose a detection, never manufacture a false
    // one, because a mismatch requires two recorded sightings of the
    // same class.
    if (!table.tryAcquireLock()) return .{};
    defer table.releaseLock();
    const r = table.record(class, in_irq_handler, irqs_enabled, src);
    if (!r.mismatch) return .{};
    return .{
        .result = .panic_irq_mode_mix,
        .irq_handler_src = r.irq_handler_src,
        .process_enabled_src = r.process_enabled_src,
    };
}

/// Pop the matching `lock_ptr` from `stack`. Returns false if no entry
/// matches — typically because the caller migrated cores between acquire
/// and release, leaving the entry on the original core's stack.
///
/// The detector silently tolerates the cross-core-migration miss rather
/// than panicking on it. That is safe ONLY because cross-core migration
/// while holding a SpinLock is structurally prevented upstream: every
/// yield / block / migration entry point in the scheduler calls
/// `assertNoLocksHeld` first (kernel/sched/scheduler.zig:613 in `yield`,
/// :855 in `switchToNextReady`), which panics if any SpinLock sits on
/// the local stack. Migration-with-locks is therefore impossible at the
/// scheduler boundary, and `releaseOn`'s "lock not on this stack" path
/// is only reachable by a release of a lock that was never acquired.
///
/// If the upstream invariant is ever violated, the per-core held-stack
/// integrity collapses and the detector's other panics (recursive,
/// same-class, cycle) become unreliable. The fix is to find the missing
/// `assertNoLocksHeld` call site, not to harden `releaseOn` here.
pub fn releaseOn(stack: *HeldStack, lock_ptr: *const anyopaque) bool {
    var i: u8 = 0;
    while (i < stack.depth) {
        if (stack.entries[i].lock_ptr == lock_ptr) {
            var j: u8 = i;
            while (j + 1 < stack.depth) {
                stack.entries[j] = stack.entries[j + 1];
                j += 1;
            }
            stack.depth -= 1;
            return true;
        }
        i += 1;
    }
    return false;
}

// ---------- Tests ----------

const testing = std.testing;

fn makeSrc(comptime file: [:0]const u8, line: u32) SrcLoc {
    return .{
        .file = file,
        .fn_name = "test",
        .line = line,
        .column = 0,
        .module = "debug",
    };
}

test "acquireOn: simple acquire pushes entry" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    const out = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    try testing.expectEqual(CheckResult.ok, out.result);
    try testing.expectEqual(@as(u8, 1), stack.depth);
}

test "acquireOn: recursive acquire same lock_ptr panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    const out = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.panic_recursive, out.result);
}

test "acquireOn: same-class overlap with ordered_group=0 panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    const out = acquireOn(&stack, &reg, &lock_b, class_a, 0, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.panic_same_class, out.result);
}

test "acquireOn: same-class overlap with matching ordered_group succeeds" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    const out1 = acquireOn(&stack, &reg, &lock_a, class_a, 7, makeSrc("a.zig", 10));
    try testing.expectEqual(CheckResult.ok, out1.result);
    const out2 = acquireOn(&stack, &reg, &lock_b, class_a, 7, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.ok, out2.result);
    try testing.expectEqual(@as(u8, 2), stack.depth);
}

test "acquireOn: same-class overlap with mismatched ordered_group panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 7, makeSrc("a.zig", 10));
    const out = acquireOn(&stack, &reg, &lock_b, class_a, 9, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.panic_same_class, out.result);
}

test "acquireOn: cross-class cycle suppressed when held lock is ordered" {
    // ordered_group on the held side signals manual ordering: skip
    // pair-edge insertion and cycle-check entirely for that pair.
    // Mirrors the kernel pattern of `Process._gen_lock` (held with
    // FAULT_PROCESS_GENLOCK_GROUP) acquiring `Thread._gen_lock` on
    // one site while the inverse Thread→Process appears on another.
    var stack_a: HeldStack = .{};
    var stack_b: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const proc_class: [*:0]const u8 = "Process._gen_lock";
    const thread_class: [*:0]const u8 = "Thread._gen_lock";
    var proc_lock: u32 = 0;
    var thread_lock: u32 = 0;
    var proc_lock_2: u32 = 0;
    var thread_lock_2: u32 = 0;

    // Site 1: ordered Thread held, plain Process acquired.
    // No edge inserted because the held side is ordered.
    _ = acquireOn(&stack_a, &reg, &thread_lock, thread_class, 1, makeSrc("ipc.zig", 678));
    const out1 = acquireOn(&stack_a, &reg, &proc_lock, proc_class, 0, makeSrc("ipc.zig", 151));
    try testing.expectEqual(CheckResult.ok, out1.result);

    // Site 2: ordered Process held, plain Thread acquired.
    // The opposite class ordering would normally panic as a cycle
    // because of site 1's edge — but no edge was inserted.
    _ = acquireOn(&stack_b, &reg, &proc_lock_2, proc_class, 1, makeSrc("process.zig", 638));
    const out2 = acquireOn(&stack_b, &reg, &thread_lock_2, thread_class, 0, makeSrc("process.zig", 717));
    try testing.expectEqual(CheckResult.ok, out2.result);
}

test "acquireOn: cross-class cycle suppressed when acquiring lock is ordered" {
    // Symmetric to the above: even when the held side is plain, an
    // ordered_group on the acquiring side skips edge insertion. The
    // ordered tag signals "the caller manages this lock's ordering"
    // regardless of which side of the pair it's on.
    var stack_a: HeldStack = .{};
    var stack_b: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const a_class: [*:0]const u8 = "A";
    const b_class: [*:0]const u8 = "B";
    var a1: u32 = 0;
    var b1: u32 = 0;
    var a2: u32 = 0;
    var b2: u32 = 0;

    // Site 1: plain A held, ordered B acquired. Skip edge insert.
    _ = acquireOn(&stack_a, &reg, &a1, a_class, 0, makeSrc("x.zig", 1));
    const out1 = acquireOn(&stack_a, &reg, &b1, b_class, 1, makeSrc("x.zig", 2));
    try testing.expectEqual(CheckResult.ok, out1.result);

    // Site 2: plain B held, plain A acquired. Would close cycle if
    // the prior edge had been registered — but it wasn't.
    _ = acquireOn(&stack_b, &reg, &b2, b_class, 0, makeSrc("y.zig", 1));
    const out2 = acquireOn(&stack_b, &reg, &a2, a_class, 0, makeSrc("y.zig", 2));
    try testing.expectEqual(CheckResult.ok, out2.result);
}

test "acquireOn: cross-class cycle still detected when both sides plain" {
    // Regression guard: the ordered-side suppression must not weaken
    // detection when neither side opted in. The classic AB-BA case
    // remains a panic.
    var stack_a: HeldStack = .{};
    var stack_b: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const a_class: [*:0]const u8 = "A";
    const b_class: [*:0]const u8 = "B";
    var a1: u32 = 0;
    var b1: u32 = 0;
    var a2: u32 = 0;
    var b2: u32 = 0;

    _ = acquireOn(&stack_a, &reg, &a1, a_class, 0, makeSrc("x.zig", 1));
    _ = acquireOn(&stack_a, &reg, &b1, b_class, 0, makeSrc("x.zig", 2));
    _ = acquireOn(&stack_b, &reg, &b2, b_class, 0, makeSrc("y.zig", 1));
    const out = acquireOn(&stack_b, &reg, &a2, a_class, 0, makeSrc("y.zig", 2));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

test "acquireOn: AB then release A then BA succeeds (no overlap)" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    const class_b: [*:0]const u8 = "ClassB";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    _ = acquireOn(&stack, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 20));
    try testing.expect(releaseOn(&stack, &lock_b));
    try testing.expect(releaseOn(&stack, &lock_a));

    // Now BA in isolation: the registry has A->B, but no overlap means
    // the cycle check (which only fires against currently-held entries)
    // does not trigger.
    _ = acquireOn(&stack, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 30));
    const out = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 40));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

test "acquireOn: 3-node transitive cycle A->B->C->A" {
    var stacks: [3]HeldStack = .{ .{}, .{}, .{} };
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const c: [*:0]const u8 = "C";
    var locks: [3]u32 = .{ 0, 0, 0 };

    // Core 0: A then B → registers A->B.
    _ = acquireOn(&stacks[0], &reg, &locks[0], a, 0, makeSrc("x.zig", 1));
    _ = acquireOn(&stacks[0], &reg, &locks[1], b, 0, makeSrc("x.zig", 2));

    // Core 1: B then C → registers B->C.
    _ = acquireOn(&stacks[1], &reg, &locks[1], b, 0, makeSrc("x.zig", 3));
    _ = acquireOn(&stacks[1], &reg, &locks[2], c, 0, makeSrc("x.zig", 4));

    // Core 2: C then A → would close cycle A->B->C->A.
    _ = acquireOn(&stacks[2], &reg, &locks[2], c, 0, makeSrc("x.zig", 5));
    const out = acquireOn(&stacks[2], &reg, &locks[0], a, 0, makeSrc("x.zig", 6));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
    try testing.expect(out.cycle_transitive);
}

test "acquireOn: 4-node transitive cycle A->B->C->D->A" {
    var stacks: [4]HeldStack = .{ .{}, .{}, .{}, .{} };
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const c: [*:0]const u8 = "C";
    const d: [*:0]const u8 = "D";
    var locks: [4]u32 = .{ 0, 0, 0, 0 };

    _ = acquireOn(&stacks[0], &reg, &locks[0], a, 0, makeSrc("x.zig", 1));
    _ = acquireOn(&stacks[0], &reg, &locks[1], b, 0, makeSrc("x.zig", 2));
    _ = acquireOn(&stacks[1], &reg, &locks[1], b, 0, makeSrc("x.zig", 3));
    _ = acquireOn(&stacks[1], &reg, &locks[2], c, 0, makeSrc("x.zig", 4));
    _ = acquireOn(&stacks[2], &reg, &locks[2], c, 0, makeSrc("x.zig", 5));
    _ = acquireOn(&stacks[2], &reg, &locks[3], d, 0, makeSrc("x.zig", 6));
    _ = acquireOn(&stacks[3], &reg, &locks[3], d, 0, makeSrc("x.zig", 7));
    const out = acquireOn(&stacks[3], &reg, &locks[0], a, 0, makeSrc("x.zig", 8));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
    try testing.expect(out.cycle_transitive);
}

test "acquireOn: long acyclic chain does not panic" {
    var stacks: [3]HeldStack = .{ .{}, .{}, .{} };
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const c: [*:0]const u8 = "C";
    const d: [*:0]const u8 = "D";
    var locks: [4]u32 = .{ 0, 0, 0, 0 };

    _ = acquireOn(&stacks[0], &reg, &locks[0], a, 0, makeSrc("x.zig", 1));
    _ = acquireOn(&stacks[0], &reg, &locks[1], b, 0, makeSrc("x.zig", 2));
    _ = acquireOn(&stacks[1], &reg, &locks[1], b, 0, makeSrc("x.zig", 3));
    _ = acquireOn(&stacks[1], &reg, &locks[2], c, 0, makeSrc("x.zig", 4));
    _ = acquireOn(&stacks[2], &reg, &locks[2], c, 0, makeSrc("x.zig", 5));
    const out = acquireOn(&stacks[2], &reg, &locks[3], d, 0, makeSrc("x.zig", 6));
    try testing.expectEqual(CheckResult.ok, out.result);
}

test "acquireOn: AB-BA cycle detected" {
    var stack_a: HeldStack = .{};
    var stack_b: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    const class_b: [*:0]const u8 = "ClassB";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    // Core 0 acquires A then B.
    _ = acquireOn(&stack_a, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    _ = acquireOn(&stack_a, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 20));

    // Core 1 acquires B then A — should detect cycle.
    _ = acquireOn(&stack_b, &reg, &lock_b, class_b, 0, makeSrc("b.zig", 10));
    const out = acquireOn(&stack_b, &reg, &lock_a, class_a, 0, makeSrc("b.zig", 20));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

test "releaseOn: pops matching entry" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    try testing.expectEqual(@as(u8, 1), stack.depth);
    try testing.expect(releaseOn(&stack, &lock_a));
    try testing.expectEqual(@as(u8, 0), stack.depth);
}

test "releaseOn: tolerates unknown lock_ptr" {
    var stack: HeldStack = .{};
    var unknown: u32 = 0;
    try testing.expect(!releaseOn(&stack, &unknown));
}

test "releaseOn: pops middle entry preserving order" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    const class_b: [*:0]const u8 = "ClassB";
    const class_c: [*:0]const u8 = "ClassC";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;
    var lock_c: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    _ = acquireOn(&stack, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 20));
    _ = acquireOn(&stack, &reg, &lock_c, class_c, 0, makeSrc("a.zig", 30));

    try testing.expect(releaseOn(&stack, &lock_b));
    try testing.expectEqual(@as(u8, 2), stack.depth);
    try testing.expectEqual(@as(*const anyopaque, &lock_a), stack.entries[0].lock_ptr);
    try testing.expectEqual(@as(*const anyopaque, &lock_c), stack.entries[1].lock_ptr);
}

test "acquireOn: stack overflow degrades but still checks panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    // Fill the stack with HELD_STACK_DEPTH distinct same-group locks so
    // that the same-class-overlap check stays quiet.
    var locks: [HELD_STACK_DEPTH + 1]u32 = undefined;
    const class_a: [*:0]const u8 = "ClassA";
    var i: usize = 0;
    while (i < HELD_STACK_DEPTH) {
        locks[i] = 0;
        const out = acquireOn(&stack, &reg, &locks[i], class_a, 1, makeSrc("a.zig", @intCast(i)));
        try testing.expectEqual(CheckResult.ok, out.result);
        i += 1;
    }
    try testing.expectEqual(@as(u8, HELD_STACK_DEPTH), stack.depth);

    // One more acquire of an existing lock_ptr: stack is full, but the
    // recursive check still fires.
    const out_recursive = acquireOn(&stack, &reg, &locks[0], class_a, 1, makeSrc("a.zig", 99));
    try testing.expectEqual(CheckResult.panic_recursive, out_recursive.result);

    // Fresh extra acquire: ok-result but does not push (depth stays at HELD_STACK_DEPTH).
    locks[HELD_STACK_DEPTH] = 0;
    const out_overflow = acquireOn(&stack, &reg, &locks[HELD_STACK_DEPTH], class_a, 1, makeSrc("a.zig", 100));
    try testing.expectEqual(CheckResult.ok, out_overflow.result);
    try testing.expectEqual(@as(u8, HELD_STACK_DEPTH), stack.depth);
}

// `checkIrqModeOn` is driven by two booleans:
//   `in_irq_handler` — local-core async-IRQ-handler-depth > 0
//   `irqs_enabled`   — raw CPU interrupt-flag state at acquire time
//
// Three classifications:
//   in_irq_handler==true                              → IRQ-handler context
//   in_irq_handler==false && irqs_enabled==false      → lockIrqSave (safe)
//   in_irq_handler==false && irqs_enabled==true       → process-irqs-enabled
//
// Mismatch ⇔ both "IRQ-handler" and "process-irqs-enabled" observed.
test "checkIrqModeOn: only lockIrqSave (process, IRQs disabled) — no panic" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    const out1 = checkIrqModeOn(&table, a, false, false, makeSrc("x.zig", 1));
    const out2 = checkIrqModeOn(&table, a, false, false, makeSrc("x.zig", 2));
    try testing.expectEqual(CheckResult.ok, out1.result);
    try testing.expectEqual(CheckResult.ok, out2.result);
}

test "checkIrqModeOn: IRQ handler then process-IRQs-enabled — panic" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    _ = checkIrqModeOn(&table, a, true, false, makeSrc("handler.zig", 11));
    const out = checkIrqModeOn(&table, a, false, true, makeSrc("proc.zig", 22));
    try testing.expectEqual(CheckResult.panic_irq_mode_mix, out.result);
    try testing.expectEqual(@as(u32, 11), out.irq_handler_src.line);
    try testing.expectEqual(@as(u32, 22), out.process_enabled_src.line);
}

test "checkIrqModeOn: process-IRQs-enabled then IRQ handler — panic" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    _ = checkIrqModeOn(&table, a, false, true, makeSrc("proc.zig", 33));
    const out = checkIrqModeOn(&table, a, true, false, makeSrc("handler.zig", 44));
    try testing.expectEqual(CheckResult.panic_irq_mode_mix, out.result);
    try testing.expectEqual(@as(u32, 44), out.irq_handler_src.line);
    try testing.expectEqual(@as(u32, 33), out.process_enabled_src.line);
}

test "checkIrqModeOn: IRQ handler twice — no panic" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    const out1 = checkIrqModeOn(&table, a, true, false, makeSrc("h.zig", 1));
    const out2 = checkIrqModeOn(&table, a, true, false, makeSrc("h.zig", 2));
    try testing.expectEqual(CheckResult.ok, out1.result);
    try testing.expectEqual(CheckResult.ok, out2.result);
}

test "checkIrqModeOn: lockIrqSave + IRQ handler — no panic (handler-only side)" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    _ = checkIrqModeOn(&table, a, false, false, makeSrc("p.zig", 1));
    const out = checkIrqModeOn(&table, a, true, false, makeSrc("h.zig", 2));
    try testing.expectEqual(CheckResult.ok, out.result);
}

test "checkIrqModeOn: lockIrqSave + process-IRQs-enabled — no panic (no IRQ-handler side)" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    _ = checkIrqModeOn(&table, a, false, false, makeSrc("p.zig", 1));
    const out = checkIrqModeOn(&table, a, false, true, makeSrc("p.zig", 2));
    try testing.expectEqual(CheckResult.ok, out.result);
}

test "checkIrqModeOn: lockIrqSave + handler + process-IRQs-enabled — panic on the third" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    const out1 = checkIrqModeOn(&table, a, false, false, makeSrc("p.zig", 1));
    try testing.expectEqual(CheckResult.ok, out1.result);
    const out2 = checkIrqModeOn(&table, a, true, false, makeSrc("h.zig", 2));
    try testing.expectEqual(CheckResult.ok, out2.result);
    const out3 = checkIrqModeOn(&table, a, false, true, makeSrc("p.zig", 3));
    try testing.expectEqual(CheckResult.panic_irq_mode_mix, out3.result);
    try testing.expectEqual(@as(u32, 2), out3.irq_handler_src.line);
    try testing.expectEqual(@as(u32, 3), out3.process_enabled_src.line);
}

test "checkIrqModeOn: distinct classes do not interfere" {
    var table: ClassTable = .{};
    table.clear();
    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    _ = checkIrqModeOn(&table, a, true, false, makeSrc("x.zig", 1));
    const out = checkIrqModeOn(&table, b, false, true, makeSrc("x.zig", 2));
    try testing.expectEqual(CheckResult.ok, out.result);
}

test "PairRegistry: insert + contains + lookup" {
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const src_a = makeSrc("x.zig", 1);
    const src_b = makeSrc("x.zig", 2);

    try testing.expect(!reg.contains(a, b));
    reg.insert(a, b, src_a, src_b);
    try testing.expect(reg.contains(a, b));
    try testing.expect(!reg.contains(b, a));

    const got = reg.lookup(a, b) orelse return error.MissingEntry;
    try testing.expectEqual(@as(u32, 1), got.outer_src.line);
    try testing.expectEqual(@as(u32, 2), got.inner_src.line);
}

test "PairRegistry: idempotent insert" {
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const src1 = makeSrc("x.zig", 1);
    const src2 = makeSrc("x.zig", 2);
    const src3 = makeSrc("x.zig", 3);
    const src4 = makeSrc("x.zig", 4);

    reg.insert(a, b, src1, src2);
    reg.insert(a, b, src3, src4);
    const got = reg.lookup(a, b) orelse return error.MissingEntry;
    // First insert wins.
    try testing.expectEqual(@as(u32, 1), got.outer_src.line);
}

// ---------- Concurrent / scenario / property tests ----------
//
// These exercise the pure detector under realistic kernel patterns and
// under host-thread concurrency. The file is `std`-only specifically so
// `std.Thread` lets a test play "many cores" sharing one registry.

const Thread = std.Thread;

fn stressWorker(
    reg: *PairRegistry,
    stack: *HeldStack,
    classes: []const [*:0]const u8,
    locks: []const *u32,
    iterations: usize,
    seed: u64,
    saw_panic: *std.atomic.Value(u32),
    forward: bool,
) void {
    var rng = std.Random.DefaultPrng.init(seed);
    const r = rng.random();
    var iter: usize = 0;
    while (iter < iterations) {
        const depth = r.intRangeAtMost(usize, 1, classes.len);
        if (forward) {
            var i: usize = 0;
            while (i < depth) {
                const out = acquireOn(stack, reg, locks[i], classes[i], 0, makeSrc("stress.zig", @intCast(iter)));
                if (out.result != .ok) _ = saw_panic.fetchAdd(1, .monotonic);
                i += 1;
            }
        } else {
            // Reverse order — every (i, i-1) edge is a back-edge against the
            // forward DAG.
            var i: usize = depth;
            while (i > 0) {
                i -= 1;
                const out = acquireOn(stack, reg, locks[i], classes[i], 0, makeSrc("stress_back.zig", @intCast(iter)));
                if (out.result != .ok) _ = saw_panic.fetchAdd(1, .monotonic);
            }
        }
        // Drain whatever did get pushed (panicking acquires don't push).
        while (stack.depth > 0) {
            const top = stack.depth - 1;
            _ = releaseOn(stack, stack.entries[top].lock_ptr);
        }
        iter += 1;
    }
}

test "stress: 4 threads acquiring in fixed order — no false positives" {
    var reg: PairRegistry = .{};
    reg.clear();

    const classes = [_][*:0]const u8{ "A", "B", "C", "D", "E" };
    var lock_storage = [_]u32{ 0, 0, 0, 0, 0 };
    var locks: [5]*u32 = undefined;
    var li: usize = 0;
    while (li < lock_storage.len) {
        locks[li] = &lock_storage[li];
        li += 1;
    }

    var stacks = [_]HeldStack{ .{}, .{}, .{}, .{} };
    var threads: [4]Thread = undefined;
    var saw_panic = std.atomic.Value(u32).init(0);

    var ti: usize = 0;
    while (ti < threads.len) {
        threads[ti] = try Thread.spawn(.{}, stressWorker, .{
            &reg,
            &stacks[ti],
            classes[0..],
            locks[0..],
            @as(usize, 1000),
            @as(u64, 0x1234_0000) + ti,
            &saw_panic,
            true,
        });
        ti += 1;
    }
    var ji: usize = 0;
    while (ji < threads.len) {
        threads[ji].join();
        ji += 1;
    }

    try testing.expectEqual(@as(u32, 0), saw_panic.load(.monotonic));
}

test "stress: forward + inverse threads — cycle reliably caught" {
    var reg: PairRegistry = .{};
    reg.clear();

    const classes = [_][*:0]const u8{ "A", "B", "C", "D", "E" };
    var lock_storage = [_]u32{ 0, 0, 0, 0, 0 };
    var locks: [5]*u32 = undefined;
    var li: usize = 0;
    while (li < lock_storage.len) {
        locks[li] = &lock_storage[li];
        li += 1;
    }

    var stacks = [_]HeldStack{ .{}, .{} };
    var threads: [2]Thread = undefined;
    var saw_panic = std.atomic.Value(u32).init(0);

    threads[0] = try Thread.spawn(.{}, stressWorker, .{
        &reg, &stacks[0], classes[0..], locks[0..], @as(usize, 1000), @as(u64, 0x1111), &saw_panic, true,
    });
    threads[1] = try Thread.spawn(.{}, stressWorker, .{
        &reg, &stacks[1], classes[0..], locks[0..], @as(usize, 1000), @as(u64, 0x2222), &saw_panic, false,
    });
    threads[0].join();
    threads[1].join();

    try testing.expect(saw_panic.load(.monotonic) > 0);
}

test "scenario: rq_lock then ipc_box_lock everywhere — no panic" {
    var reg: PairRegistry = .{};
    reg.clear();
    var stacks = [_]HeldStack{ .{}, .{} };

    const RQ: [*:0]const u8 = "rq_lock";
    const IPC: [*:0]const u8 = "ipc_box_lock";
    var rq0: u32 = 0;
    var ipc0: u32 = 0;
    var rq1: u32 = 0;
    var ipc1: u32 = 0;

    // Core 0: rq -> ipc
    try testing.expectEqual(CheckResult.ok, acquireOn(&stacks[0], &reg, &rq0, RQ, 0, makeSrc("sched.zig", 100)).result);
    try testing.expectEqual(CheckResult.ok, acquireOn(&stacks[0], &reg, &ipc0, IPC, 0, makeSrc("ipc.zig", 200)).result);
    _ = releaseOn(&stacks[0], &ipc0);
    _ = releaseOn(&stacks[0], &rq0);

    // Core 1: same ordering
    try testing.expectEqual(CheckResult.ok, acquireOn(&stacks[1], &reg, &rq1, RQ, 0, makeSrc("sched.zig", 100)).result);
    try testing.expectEqual(CheckResult.ok, acquireOn(&stacks[1], &reg, &ipc1, IPC, 0, makeSrc("ipc.zig", 200)).result);
    _ = releaseOn(&stacks[1], &ipc1);
    _ = releaseOn(&stacks[1], &rq1);
}

test "scenario: rq_lock then ipc_box_lock + inverse site — cycle panic" {
    var reg: PairRegistry = .{};
    reg.clear();
    var stacks = [_]HeldStack{ .{}, .{} };

    const RQ: [*:0]const u8 = "rq_lock";
    const IPC: [*:0]const u8 = "ipc_box_lock";
    var rq0: u32 = 0;
    var ipc0: u32 = 0;
    var rq1: u32 = 0;
    var ipc1: u32 = 0;

    // Core 0: rq -> ipc (the canonical ordering, establishes the edge)
    _ = acquireOn(&stacks[0], &reg, &rq0, RQ, 0, makeSrc("sched.zig", 100));
    _ = acquireOn(&stacks[0], &reg, &ipc0, IPC, 0, makeSrc("ipc.zig", 200));

    // Core 1: ipc -> rq (BUG — one rogue path doing the inverse)
    _ = acquireOn(&stacks[1], &reg, &ipc1, IPC, 0, makeSrc("buggy.zig", 1));
    const out = acquireOn(&stacks[1], &reg, &rq1, RQ, 0, makeSrc("buggy.zig", 2));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

test "scenario: print_lock taken in IRQ handler + plain lock — IRQ-mode-mix panic" {
    var table: ClassTable = .{};
    table.clear();

    const PRINT: [*:0]const u8 = "print_lock";
    // Process context with plain lock() (IRQs left enabled).
    _ = checkIrqModeOn(&table, PRINT, false, true, makeSrc("kprint.zig", 50));
    // Async IRQ handler now tries to take the same class.
    const out = checkIrqModeOn(&table, PRINT, true, false, makeSrc("timer_irq.zig", 10));
    try testing.expectEqual(CheckResult.panic_irq_mode_mix, out.result);
    try testing.expectEqual(@as(u32, 50), out.process_enabled_src.line);
    try testing.expectEqual(@as(u32, 10), out.irq_handler_src.line);
}

test "property: random subsets in topological order — no false positives" {
    var rng = std.Random.DefaultPrng.init(0xdead_beef);
    const r = rng.random();

    const N: usize = 6;
    const classes = [_][*:0]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var lock_storage = [_]u32{ 0, 0, 0, 0, 0, 0 };
    var locks: [N]*u32 = undefined;
    var li: usize = 0;
    while (li < N) {
        locks[li] = &lock_storage[li];
        li += 1;
    }

    // The classes' index in the array IS the topological order. Any
    // contiguous subrange acquired in index order respects the DAG.
    var reg: PairRegistry = .{};
    reg.clear();
    var stack: HeldStack = .{};

    var trial: usize = 0;
    while (trial < 200) {
        const start = r.intRangeLessThan(usize, 0, N);
        const len_max = @min(N - start, @as(usize, HELD_STACK_DEPTH));
        const len = r.intRangeAtMost(usize, 1, len_max);
        var k: usize = 0;
        while (k < len) {
            const idx = start + k;
            const out = acquireOn(&stack, &reg, locks[idx], classes[idx], 0, makeSrc("prop.zig", @intCast(trial)));
            try testing.expectEqual(CheckResult.ok, out.result);
            k += 1;
        }
        while (stack.depth > 0) {
            const top = stack.depth - 1;
            _ = releaseOn(&stack, stack.entries[top].lock_ptr);
        }
        trial += 1;
    }
}

test "property: back-edge after a topo-order DAG is built — cycle" {
    const N: usize = 4;
    const classes = [_][*:0]const u8{ "n0", "n1", "n2", "n3" };
    var lock_storage = [_]u32{ 0, 0, 0, 0 };
    var locks: [N]*u32 = undefined;
    var li: usize = 0;
    while (li < N) {
        locks[li] = &lock_storage[li];
        li += 1;
    }

    var reg: PairRegistry = .{};
    reg.clear();
    var stack: HeldStack = .{};

    // Build forward edges 0->1->2->3.
    var i: usize = 0;
    while (i < N) {
        const out = acquireOn(&stack, &reg, locks[i], classes[i], 0, makeSrc("prop.zig", @intCast(i)));
        try testing.expectEqual(CheckResult.ok, out.result);
        i += 1;
    }
    while (stack.depth > 0) {
        const top = stack.depth - 1;
        _ = releaseOn(&stack, stack.entries[top].lock_ptr);
    }

    // Inject back-edge: hold n3, then try to take n1.
    _ = acquireOn(&stack, &reg, locks[3], classes[3], 0, makeSrc("prop.zig", 100));
    const out = acquireOn(&stack, &reg, locks[1], classes[1], 0, makeSrc("prop.zig", 101));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

// ---------- IrqDepth tests ----------
//
// These exercise the per-core IRQ-handler-depth counter in isolation,
// without needing a real `arch.smp.coreID()` — the wrappers in debug.zig
// cast the coreID and forward to these step methods.

test "IrqDepth: single-core balance — enter then exit returns to 0" {
    var d: IrqDepth = .{};
    try testing.expect(!d.inIrq(0));
    d.enter(0);
    try testing.expect(d.inIrq(0));
    try testing.expectEqual(@as(u8, 1), d.slots[0]);
    d.exit(0);
    try testing.expect(!d.inIrq(0));
    try testing.expectEqual(@as(u8, 0), d.slots[0]);
}

test "IrqDepth: nested IRQs increment and decrement in order" {
    var d: IrqDepth = .{};
    d.enter(0);
    d.enter(0);
    try testing.expectEqual(@as(u8, 2), d.slots[0]);
    try testing.expect(d.inIrq(0));
    d.exit(0);
    try testing.expectEqual(@as(u8, 1), d.slots[0]);
    try testing.expect(d.inIrq(0));
    d.exit(0);
    try testing.expectEqual(@as(u8, 0), d.slots[0]);
    try testing.expect(!d.inIrq(0));
}

test "IrqDepth: per-core isolation — enter on core 0 doesn't touch core 1" {
    var d: IrqDepth = .{};
    d.enter(0);
    try testing.expect(d.inIrq(0));
    try testing.expect(!d.inIrq(1));
    try testing.expectEqual(@as(u8, 1), d.slots[0]);
    try testing.expectEqual(@as(u8, 0), d.slots[1]);
}

test "IrqDepth: reset collapses an unbalanced enter (the noreturn-jmp case)" {
    // Simulate the bug `resetIrqContextOnSwitch` exists to fix: an IRQ
    // entry called `enter`, but the matching `defer exit` never ran
    // because a noreturn jmp abandoned the IRQ-entry's call stack.
    var d: IrqDepth = .{};
    d.enter(0);
    d.reset(0);
    try testing.expectEqual(@as(u8, 0), d.slots[0]);
    try testing.expect(!d.inIrq(0));
}

test "IrqDepth: reset collapses multiple consecutive unbalanced enters" {
    var d: IrqDepth = .{};
    d.enter(0);
    d.enter(0);
    d.enter(0);
    try testing.expectEqual(@as(u8, 3), d.slots[0]);
    d.reset(0);
    try testing.expectEqual(@as(u8, 0), d.slots[0]);
    try testing.expect(!d.inIrq(0));
}

test "IrqDepth: reset only affects the targeted core" {
    var d: IrqDepth = .{};
    d.enter(0);
    d.enter(1);
    d.reset(0);
    try testing.expectEqual(@as(u8, 0), d.slots[0]);
    try testing.expectEqual(@as(u8, 1), d.slots[1]);
    try testing.expect(!d.inIrq(0));
    try testing.expect(d.inIrq(1));
}

test "IrqDepth: out-of-bounds core_id is silent no-op" {
    var d: IrqDepth = .{};
    d.enter(MAX_CORES);
    d.enter(MAX_CORES + 5);
    d.exit(MAX_CORES);
    d.reset(MAX_CORES);
    try testing.expect(!d.inIrq(MAX_CORES));
    try testing.expect(!d.inIrq(MAX_CORES + 100));
    var i: usize = 0;
    while (i < MAX_CORES) {
        try testing.expectEqual(@as(u8, 0), d.slots[i]);
        i += 1;
    }
}
