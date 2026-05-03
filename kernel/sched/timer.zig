//! Timer — kernel object that fires once or periodically and exposes
//! a u64 counter directly in its handle's field0. Userspace observes
//! fires by polling the counter or waiting on it via `futex_wait_val`
//! (the handle table is mapped read-only into the holding domain so
//! the counter's vaddr is a valid futex address). See spec §[timer].
//!
//! Refcount lifetime — total handles keep the timer alive. When the
//! last handle drops the kernel cancels (if armed) and reclaims state.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const futex = zag.sched.futex;
const scheduler = zag.sched.scheduler;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;

/// Cap bits in `Capability.word0[48..63]` for timer handles.
/// Spec §[timer] cap layout.
pub const TimerCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    arm: bool = false,
    cancel: bool = false,
    restart_policy: u1 = 0,
    _reserved: u11 = 0,
};

/// Cancellation sentinel for `Timer.counter`. Reserved value distinct
/// from any real fire-driven value because increments saturate at
/// `u64::MAX − 1`.
pub const CANCELLED: u64 = std.math.maxInt(u64);

/// Saturation ceiling for fire-driven counter increments. One below
/// `CANCELLED` so a real counter value never collides with the
/// cancellation sentinel.
pub const COUNTER_CEILING: u64 = std.math.maxInt(u64) - 1;

/// Spec error codes used by this module. Spec v3 §[error_codes]:
/// errors are positive integers returned in vreg 1; sign is not a
/// success discriminator. Mirror the values from `syscall.errors`
/// rather than re-declaring negatives (which crossed wires with
/// userspace expecting the spec-positive values).
const E_PERM: i64 = zag.syscall.errors.E_PERM;
const E_BADCAP: i64 = zag.syscall.errors.E_BADCAP;
const E_INVAL: i64 = zag.syscall.errors.E_INVAL;
const E_NOMEM: i64 = zag.syscall.errors.E_NOMEM;
const E_FULL: i64 = zag.syscall.errors.E_FULL;

/// Reserved-bit masks for the public ABI.
const TIMER_CAPS_RESERVED_MASK: u64 = 0xFFFF_FFFF_FFFF_0000;
const TIMER_FLAGS_RESERVED_MASK: u64 = ~@as(u64, 1);

pub const Timer = struct {
    /// Slab generation lock + per-instance mutex.
    _gen_lock: GenLock = .{},

    /// Total user-visible handles across all capability domains.
    /// Mutated under `_gen_lock`; the decrementer that brings this to
    /// 0 cancels (if armed) and frees.
    refcount: u32 = 0,

    /// Fire counter. Incremented on each fire, saturating at
    /// `u64::MAX − 1`. Set to `CANCELLED` (u64::MAX) by `timer_cancel`.
    /// Reset to 0 by `timer_rearm`. Mirrors user-visible field0 and
    /// is eagerly propagated to every domain-local copy of the handle
    /// (not atomically across copies — transient divergence between
    /// copies is permitted).
    counter: u64 = 0,

    /// Armed flag. True between arm/rearm and either cancel or one-
    /// shot fire. Mirrors field1 bit 0.
    armed: bool = false,

    /// Periodic flag. True for periodic timers that re-arm after each
    /// fire; false for one-shots. Mirrors field1 bit 1.
    periodic: bool = false,

    /// Period in nanoseconds for periodic timers; one-shot interval
    /// for non-periodic. Set by arm/rearm.
    period_ns: u64 = 0,

    /// Next absolute fire time in monotonic clock nanoseconds. Used
    /// by the timer wheel to fire when the deadline passes.
    deadline_ns: u64 = 0,

    /// Index into the owning core's wheel minheap, or `WHEEL_NOT_QUEUED`
    /// when not currently scheduled. Updated by every heap mutation
    /// (insert, swap-down, swap-up, swap-remove) so cancel can find the
    /// timer's slot in O(1) without a linear scan. Mutated only under
    /// the owning core's `wheel_locks[core_id]`.
    wheel_idx: u32 = WHEEL_NOT_QUEUED,

    /// Core whose per-core wheel currently holds this timer, or 0xFF
    /// when not queued. Set on insert, cleared on remove. Cancel uses
    /// this to route to the right per-core lock + heap.
    wheel_core: u8 = WHEEL_NO_CORE,
};

pub const Allocator = SecureSlab(Timer, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── Per-core timer wheel (min-heap) ──────────────────────────────────
//
// One min-heap per core, keyed on absolute monotonic-clock nanoseconds
// (`Timer.deadline_ns`). Entries live in `.data` — no slab/heap/PMM
// allocation along the timer fast path. The core that arms a timer
// owns it: insert/cancel/expire all run against the local core's heap
// under the local `wheel_locks[core_id]`. Cross-core arming is out of
// scope for the spec-v3 step-8 wheel; callers must arm on the local
// core.
//
// Sizing — `MAX_TIMERS_PER_CORE = 256` matches the global `Timer` slab
// capacity (`Allocator = SecureSlab(Timer, 256)`). At most 256 timers
// can exist kernel-wide, so a single core could hold them all and
// never overflow. `INSERT_FAILED` lets a future cross-core spillover
// path detect a full per-core heap explicitly without panicking.

pub const MAX_TIMERS_PER_CORE: u32 = 256;
pub const WHEEL_NOT_QUEUED: u32 = std.math.maxInt(u32);
pub const WHEEL_NO_CORE: u8 = 0xFF;

pub const HeapEntry = struct {
    deadline_ns: u64,
    /// Wheel-pinned reference to the entry's Timer. Carried as a
    /// `SlabRef` so the type-system invariant "no bare `*Timer` in
    /// kernel storage" holds (per analyzer/spec). The Timer is
    /// wheel-pinned for the duration of heap residency: refcount ≥ 1
    /// while a handle exists, and `destroyTimer` always calls
    /// `wheelRemove` before freeing the slab slot. Heap operations
    /// (siftUp/siftDown/swap) update `wheel_idx`/`wheel_core` directly
    /// through `.ptr` because the wheel-pin invariant guarantees the
    /// slot is alive — locking the per-Timer gen-lock here would
    /// invert the established `t._gen_lock → wheel_locks[core]` order
    /// (see `onFire` / `wheelInsert`) and seed an AB-BA cycle.
    timer: SlabRef(Timer),
};

/// Per-core min-heap of pending timer fires, ordered by absolute
/// `deadline_ns`. Pure data structure — no locking, no IRQ awareness;
/// callers (the wheel surface) hold `wheel_locks[core_id]` across each
/// op. The unit tests at the bottom of this file exercise this struct
/// directly with a synthetic `Timer` array, no kernel state required.
pub const TimerHeap = struct {
    entries: [MAX_TIMERS_PER_CORE]HeapEntry = undefined,
    len: u32 = 0,

    /// Insert `timer` with absolute deadline `deadline_ns`. Returns the
    /// new slot index, or `null` if the heap is full. On success the
    /// timer's `wheel_idx` is updated to the placed index. The timer's
    /// `wheel_core` is *not* touched here — callers set it before/after
    /// to encode which heap owns this entry.
    ///
    /// Caller must hold `wheel_locks[core]`. `timer` is wheel-pinned
    /// across this call (refcount ≥ 1 + insert/remove bracketed by the
    /// caller). The constructed SlabRef captures the timer's current
    /// gen so heap residency carries it back out for any caller that
    /// pops the entry (peekMin/popMin).
    pub fn insert(self: *TimerHeap, timer: *Timer, deadline_ns: u64) ?u32 {
        if (self.len >= MAX_TIMERS_PER_CORE) return null;
        const idx = self.len;
        const ref = SlabRef(Timer).init(timer, timer._gen_lock.currentGen());
        self.entries[idx] = .{ .deadline_ns = deadline_ns, .timer = ref };
        timer.wheel_idx = idx;
        self.len += 1;
        return self.siftUp(idx);
    }

    /// Remove the entry at `idx`. Idempotent against `WHEEL_NOT_QUEUED`
    /// — caller is expected to have a stable index obtained from a
    /// prior `insert` (and stored on the timer). Updates `wheel_idx` /
    /// `wheel_core` of both the removed timer (cleared) and the entry
    /// swapped into its place.
    pub fn removeAt(self: *TimerHeap, idx: u32) void {
        if (idx >= self.len) return;
        // self-alive: heap entries' Timers are wheel-pinned for the
        // duration of residency (see `HeapEntry.timer` doc comment).
        const removed_timer = self.entries[idx].timer.ptr;
        removed_timer.wheel_idx = WHEEL_NOT_QUEUED;
        removed_timer.wheel_core = WHEEL_NO_CORE;

        const last_idx = self.len - 1;
        self.len = last_idx;
        if (idx == last_idx) return;

        // Move the last entry into the hole; restore heap property.
        self.entries[idx] = self.entries[last_idx];
        // self-alive: see above.
        self.entries[idx].timer.ptr.wheel_idx = idx;

        // Either sift up or sift down, depending on parent comparison.
        // Sifting both ways is safe — only one will move the element.
        const after_up = self.siftUp(idx);
        _ = self.siftDown(after_up);
    }

    /// Pop and return the minimum-deadline entry, or `null` if empty.
    /// Updates `wheel_idx`/`wheel_core` on the removed timer (cleared)
    /// and on the entry swapped into the root.
    pub fn popMin(self: *TimerHeap) ?HeapEntry {
        if (self.len == 0) return null;
        const top = self.entries[0];
        // self-alive: heap entries' Timers are wheel-pinned for the
        // duration of residency (see `HeapEntry.timer` doc comment).
        top.timer.ptr.wheel_idx = WHEEL_NOT_QUEUED;
        top.timer.ptr.wheel_core = WHEEL_NO_CORE; // self-alive

        const last_idx = self.len - 1;
        self.len = last_idx;
        if (last_idx > 0) {
            self.entries[0] = self.entries[last_idx];
            // self-alive: see above.
            self.entries[0].timer.ptr.wheel_idx = 0;
            _ = self.siftDown(0);
        }
        return top;
    }

    /// Peek at the minimum-deadline entry, or `null` if empty. The
    /// returned reference is invalidated by any subsequent mutation.
    pub fn peekMin(self: *const TimerHeap) ?HeapEntry {
        if (self.len == 0) return null;
        return self.entries[0];
    }

    pub fn isEmpty(self: *const TimerHeap) bool {
        return self.len == 0;
    }

    fn siftUp(self: *TimerHeap, start_idx: u32) u32 {
        var idx = start_idx;
        while (idx > 0) {
            const parent = (idx - 1) / 2;
            if (self.entries[parent].deadline_ns <= self.entries[idx].deadline_ns) break;
            self.swap(parent, idx);
            idx = parent;
        }
        return idx;
    }

    fn siftDown(self: *TimerHeap, start_idx: u32) u32 {
        var idx = start_idx;
        while (true) {
            const left = 2 * idx + 1;
            const right = 2 * idx + 2;
            var smallest = idx;
            if (left < self.len and
                self.entries[left].deadline_ns < self.entries[smallest].deadline_ns)
                smallest = left;
            if (right < self.len and
                self.entries[right].deadline_ns < self.entries[smallest].deadline_ns)
                smallest = right;
            if (smallest == idx) break;
            self.swap(idx, smallest);
            idx = smallest;
        }
        return idx;
    }

    fn swap(self: *TimerHeap, a: u32, b: u32) void {
        const tmp = self.entries[a];
        self.entries[a] = self.entries[b];
        self.entries[b] = tmp;
        // self-alive: heap entries' Timers are wheel-pinned for the
        // duration of residency (see `HeapEntry.timer` doc comment).
        self.entries[a].timer.ptr.wheel_idx = a;
        // self-alive: see above.
        self.entries[b].timer.ptr.wheel_idx = b;
    }
};

/// Per-core wheel storage. `.data` allocation — at link time. Indexed
/// by `arch.smp.coreID()`. Only the first `arch.smp.coreCount()` slots
/// are populated at runtime; later slots stay empty.
pub var wheels: [scheduler.MAX_CORES]TimerHeap = [_]TimerHeap{.{}} ** scheduler.MAX_CORES;

/// Per-core wheel locks. Held across each insert/remove/expire op.
/// Separate class from `core_locks` so the lockdep checker doesn't
/// confuse them with run-queue locks — the wheel never grabs a run
/// queue lock and vice versa.
pub var wheel_locks: [scheduler.MAX_CORES]SpinLock =
    [_]SpinLock{.{ .class = "sched.timer.wheel_lock" }} ** scheduler.MAX_CORES;

// ── External API ─────────────────────────────────────────────────────

/// `timer_arm` syscall handler. Spec §[timer].
pub fn timerArm(caller: *anyopaque, caps: u64, deadline_ns: u64, flags: u64) i64 {
    if (deadline_ns == 0) return E_INVAL;
    if ((caps & TIMER_CAPS_RESERVED_MASK) != 0) return E_INVAL;
    if ((flags & TIMER_FLAGS_RESERVED_MASK) != 0) return E_INVAL;

    const caller_domain = callerDomain(caller) orelse return E_PERM;
    if (!callerHasTimerCap(caller_domain)) return E_PERM;

    const requested_caps: u16 = @truncate(caps);
    const periodic_flag: bool = (flags & 1) != 0;
    if (!checkRestartPolicyCeiling(caller_domain, requested_caps)) return E_PERM;

    const t = allocTimer(periodic_flag, deadline_ns) catch return E_NOMEM;
    const ref = ErasedSlabRef{
        .ptr = @ptrCast(t),
        .gen = @intCast(t._gen_lock.currentGen()),
    };

    const slot = zag.caps.capability_domain.mintHandle(
        caller_domain,
        ref,
        .timer,
        requested_caps,
        0,
        encodeField1(true, periodic_flag),
    ) catch {
        destroyTimer(t);
        return E_FULL;
    };

    wheelInsert(t, t.deadline_ns);
    // Spec §[error_codes] / §[capabilities]: pack Word0 so the type
    // tag in bits 12..15 disambiguates a real handle word from the
    // small-positive error range 1..15.
    return @intCast(zag.caps.capability.Word0.pack(slot, .timer, requested_caps));
}

/// `timer_rearm` syscall handler. Spec §[timer].
pub fn timerRearm(caller: *anyopaque, handle: u64, deadline_ns: u64, flags: u64) i64 {
    if ((flags & TIMER_FLAGS_RESERVED_MASK) != 0) return E_INVAL;

    const caller_domain = callerDomain(caller) orelse return E_PERM;
    const lookup = resolveTimerHandle(caller_domain, handle, .timer) orelse return E_BADCAP;

    if (deadline_ns == 0) return E_INVAL;
    if (!handleHasArmCap(caller_domain, lookup.slot)) return E_PERM;

    const periodic_flag: bool = (flags & 1) != 0;

    const tlr = lookup.timer_ref.lockIrqSave(@src()) catch return E_BADCAP;
    const t = tlr.ptr;
    if (t.armed) wheelRemove(t);
    t.counter = 0;
    t.armed = true;
    t.periodic = periodic_flag;
    t.period_ns = deadline_ns;
    t.deadline_ns = currentNs() +| deadline_ns;
    const timer_gen = t._gen_lock.currentGen();
    const fire_deadline = t.deadline_ns;
    const counter = t.counter;
    const armed = t.armed;
    const periodic = t.periodic;
    lookup.timer_ref.unlockIrqRestore(tlr.irq_state);

    caller_domain.user_table[lookup.slot].field0 = counter;
    caller_domain.user_table[lookup.slot].field1 = encodeField1(armed, periodic);

    propagateAndWake(t, timer_gen, 0);
    propagateField1(t, timer_gen, encodeField1(true, periodic_flag));
    wheelInsert(t, fire_deadline);
    return 0;
}

/// `timer_cancel` syscall handler. Spec §[timer].
pub fn timerCancel(caller: *anyopaque, handle: u64) i64 {
    const caller_domain = callerDomain(caller) orelse return E_PERM;
    const lookup = resolveTimerHandle(caller_domain, handle, .timer) orelse return E_BADCAP;

    if (!handleHasCancelCap(caller_domain, lookup.slot)) return E_PERM;

    const tlr = lookup.timer_ref.lockIrqSave(@src()) catch return E_BADCAP;
    const t = tlr.ptr;
    if (!t.armed) {
        lookup.timer_ref.unlockIrqRestore(tlr.irq_state);
        return E_INVAL;
    }
    wheelRemove(t);
    t.armed = false;
    t.counter = CANCELLED;
    const timer_gen = t._gen_lock.currentGen();
    const periodic = t.periodic;
    lookup.timer_ref.unlockIrqRestore(tlr.irq_state);

    propagateAndWake(t, timer_gen, CANCELLED);
    propagateField1(t, timer_gen, encodeField1(false, periodic));
    return 0;
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate a Timer (refcount=1, counter=0, armed=true). Spec §[timer].
fn allocTimer(periodic: bool, deadline_ns: u64) !*Timer {
    const ref = try slab_instance.create();
    const t = ref.ptr;
    t.refcount = 1;
    t.counter = 0;
    t.armed = true;
    t.periodic = periodic;
    t.period_ns = deadline_ns;
    t.deadline_ns = currentNs() +| deadline_ns;
    return t;
}

/// Final teardown — cancels (if armed), removes from wheel, frees slab.
fn destroyTimer(t: *Timer) void {
    const gen = t._gen_lock.currentGen();
    if (t.armed) {
        wheelRemove(t);
        t.armed = false;
    }
    slab_instance.destroy(t, gen) catch {};
}

/// Handle delete: decrement under `_gen_lock`; teardown at 0.
pub fn decHandleRef(t: *Timer) void {
    const irq = t._gen_lock.lockIrqSave(@src());
    if (t.refcount > 0) t.refcount -= 1;
    const last = t.refcount == 0;
    t._gen_lock.unlockIrqRestore(irq);
    if (last) destroyTimer(t);
}

/// Disarm every Timer reachable from `cd`'s handle table. Called by
/// `destroyCapabilityDomain` BEFORE the cd struct is destroyed, while
/// the caller still holds `cd._gen_lock` from `lockTyped`. Without this,
/// a periodic timer armed by a test that has since released its
/// self-handle keeps firing indefinitely — its onFire path runs an
/// O(N_domains × MAX_HANDLES_PER_DOMAIN) `forEachAlive` walk every
/// `period_ns` nanoseconds and pins a per-core wheel-heap slot.
///
/// Lock order respected: caller holds `cd._gen_lock`; we acquire each
/// Timer's `_gen_lock` independently (canonical CD → Timer order),
/// then nest `wheel_locks[t.wheel_core]` inside the timer lock — same
/// chain `timerRearm` uses (`t._gen_lock → wheel_locks[c]`). Full
/// chain: `tree_mutex → cd._gen_lock → t._gen_lock → wheel_locks[c]`.
///
/// We remove the timer from the wheel here rather than relying on
/// the next fire to short-circuit on `!t.armed`. Disarmed entries
/// linger in the per-core heap until their scheduled fire, and the
/// cumulative pop+short-circuit cost (combined with the per-fire
/// `propagateAndWake` walk over alive CDs from any concurrent armed
/// periodics in the same heap) starves the test runner past iter
/// ~416 on TCG aarch64. Pulling the entry now keeps the heap clean.
///
/// We do NOT destroy the Timer slab slot or call `decHandleRef` here.
/// Other domains holding a copy of this timer handle still see a live
/// SlabRef; releasing the timer's slab is the responsibility of the
/// existing `decHandleRef` path when the last handle is explicitly
/// deleted.
pub fn disarmTimerHandlesInDomain(cd: *CapabilityDomain) void {
    var slot: u16 = 3;
    while (slot < zag.caps.capability.MAX_HANDLES_PER_DOMAIN) {
        const entry = &cd.kernel_table[slot];
        const obj_ptr = entry.ref.ptr orelse {
            slot += 1;
            continue;
        };

        const tag = capability.Word0.typeTag(cd.user_table[slot].word0);
        if (tag != .timer) {
            slot += 1;
            continue;
        }

        const ref: SlabRef(Timer) = .{
            .ptr = @ptrCast(@alignCast(obj_ptr)),
            .gen = entry.ref.gen,
        };
        const tlr = ref.lockIrqSave(@src()) catch {
            slot += 1;
            continue;
        };
        const t = tlr.ptr;
        if (t.armed) wheelRemove(t);
        t.armed = false;
        ref.unlockIrqRestore(tlr.irq_state);
        slot += 1;
    }
}

/// Insert `t` into the local core's wheel at `deadline_ns`. If the
/// new entry becomes the heap minimum, re-arm the LAPIC deadline so
/// the wheel ISR fires when it expires.
///
/// Cross-core arm is out of scope for spec-v3 step 8 — callers must
/// be running on the core that should own this timer fire. A future
/// patch can extend this to send a "rearm" IPI when arming for a
/// remote core; for now we just take the local heap.
/// TODO: cross-core arm — send IPI to target core to rearm its LAPIC.
fn wheelInsert(t: *Timer, deadline_ns: u64) void {
    const core_id: u8 = @intCast(arch.smp.coreID() & 0xFF);
    // `&wheels[core_id]` / `&wheel_locks[core_id]` (pointer) rather than
    // the direct `wheels[core_id].field` form. Debug-mode Zig codegens
    // the indexed form as a memcpy of the entire `wheels` /
    // `wheel_locks` array onto the caller's stack — `wheels` is
    // `[MAX_CORES]TimerHeap` ≈ 256 KiB at MAX_CORES=64. Three such
    // snapshots in a single function blow the kernel stack on faulting
    // paths. Mirrors the fix in `sched.scheduler.currentEc` for
    // `core_states[]`.
    const lock = &wheel_locks[core_id];
    const heap = &wheels[core_id];
    const irq = lock.lockIrqSave(@src());
    defer lock.unlockIrqRestore(irq);

    if (heap.insert(t, deadline_ns)) |_| {
        t.wheel_core = core_id;
    } else {
        // Heap full. With MAX_TIMERS_PER_CORE = 256 matching the
        // global Timer slab capacity, this is unreachable in practice;
        // leave the timer un-queued so the slab refcount eventually
        // reaps it without firing.
        return;
    }

    // If the new entry sits at the root, the local wheel deadline
    // changed — reprogram the LAPIC, but only when our new deadline
    // is sooner than the running preempt slice. Otherwise we would
    // push out the next preempt tick.
    if (heap.peekMin()) |top| {
        // Identity compare: SlabRef.ptr matches the freshly-inserted
        // Timer when the new entry happens to be the heap minimum.
        if (top.timer.ptr == t) {
            const now_ns = currentNs();
            const preempt_deadline = now_ns +| scheduler.TIMESLICE_NS;
            if (top.deadline_ns < preempt_deadline) {
                arch.time.armWheelDeadline(top.deadline_ns);
            }
        }
    }
}

/// Remove `t` from whichever per-core wheel currently holds it.
/// Idempotent — a no-op if the timer was never inserted or has already
/// fired/been popped. Does NOT reprogram the LAPIC; if the heap-top
/// changed because of this remove the next ISR will re-arm against
/// the new top, which is acceptable (we'd just take one extra spurious
/// timer interrupt at the now-stale earlier deadline).
fn wheelRemove(t: *Timer) void {
    const core_id = t.wheel_core;
    if (core_id == WHEEL_NO_CORE) return;
    if (core_id >= scheduler.MAX_CORES) return;

    // `&wheels[core_id]` / `&wheel_locks[core_id]`: see `wheelInsert`.
    const lock = &wheel_locks[core_id];
    const heap = &wheels[core_id];
    const irq = lock.lockIrqSave(@src());
    defer lock.unlockIrqRestore(irq);

    // Re-check under lock — a concurrent expire on the owning core
    // may have already popped this entry.
    if (t.wheel_core != core_id) return;
    const idx = t.wheel_idx;
    if (idx == WHEEL_NOT_QUEUED) return;
    heap.removeAt(idx);
}

/// Drain every timer on this core's wheel whose `deadline_ns <=
/// now_ns`, invoking `onFire` for each. Called by the LAPIC scheduler
/// ISR (`schedTimerHandler`) every tick — `onFire` re-inserts periodic
/// timers, so this loop terminates when the next-soonest deadline is
/// strictly in the future.
///
/// After draining, re-arms the LAPIC against the new heap top (if any
/// remains). If the heap is empty the LAPIC stays idle until the next
/// preempt tick re-arms it for `TIMESLICE_NS` from now.
pub fn wheelExpireDue() void {
    const now_ns = currentNs();
    const core_id: u8 = @intCast(arch.smp.coreID() & 0xFF);
    // `&wheels[core_id]` / `&wheel_locks[core_id]`: see `wheelInsert`.
    const lock = &wheel_locks[core_id];
    const heap = &wheels[core_id];

    while (true) {
        // Snapshot expired entry under lock, fire outside lock — fire
        // path may take other locks (gen_lock, futex bucket) and even
        // re-enter wheelInsert (periodic re-arm) on this same core,
        // which would deadlock if we held wheel_locks[core_id] across.
        var fire_target: ?*Timer = null;
        {
            const irq = lock.lockIrqSave(@src());
            defer lock.unlockIrqRestore(irq);
            const top = heap.peekMin() orelse break;
            if (top.deadline_ns > now_ns) break;
            const popped = heap.popMin().?;
            // self-alive: popped Timer was wheel-pinned until `popMin`
            // cleared its `wheel_idx`/`wheel_core` under `wheel_locks`.
            // The slab refcount still holds it (handles outlive wheel
            // residency); we hand the raw `*Timer` to `onFire` which
            // takes `t._gen_lock` for the fire-side mutation under the
            // canonical `t._gen_lock → wheel_locks` order.
            fire_target = popped.timer.ptr;
        }
        onFire(fire_target.?);
    }

    // Re-arm to the new top if any timers remain on this core AND
    // that top is sooner than the preemption tick that
    // `schedTimerHandler` already armed for `TIMESLICE_NS` from now
    // — otherwise leave the LAPIC alone so we don't push the next
    // preempt out past the time slice.
    const irq = lock.lockIrqSave(@src());
    defer lock.unlockIrqRestore(irq);
    const top = heap.peekMin() orelse return;
    const post_drain_now = currentNs();
    const preempt_deadline = post_drain_now +| scheduler.TIMESLICE_NS;
    if (top.deadline_ns < preempt_deadline) {
        arch.time.armWheelDeadline(top.deadline_ns);
    }
}

/// Fire callback — invoked from the wheel when `deadline_ns` expires.
/// Increments counter (saturating at `COUNTER_CEILING`), propagates to
/// every domain-local copy of the handle, futex-wakes each copy's
/// `field0` paddr. Re-arms if periodic.
pub fn onFire(t: *Timer) void {
    t._gen_lock.lock(@src());
    if (!t.armed) {
        t._gen_lock.unlock();
        return;
    }
    const new_count = if (t.counter >= COUNTER_CEILING)
        COUNTER_CEILING
    else
        t.counter + 1;
    t.counter = new_count;

    const periodic = t.periodic;
    var next_deadline: u64 = 0;
    if (periodic) {
        next_deadline = t.deadline_ns +| t.period_ns;
        // Periodic catch-up clamp. Spec §[timer] guarantees
        // at-least-once delivery per period but does not require
        // the kernel to replay every missed period when the wheel
        // falls behind. Without this, a periodic timer whose
        // deadline lags many periods (TCG aarch64 with sub-ms
        // `period_ns` — e.g. timer_arm_08's 1 ms periodic — plus
        // the `propagateAndWake` walk over alive CDs taking longer
        // than `period_ns`) re-enters wheelExpireDue's
        // pop-fire-reinsert loop once per missed period. Each fire
        // runs another full walk and the loop body grows with
        // elapsed lag, starving the recv-timeout / scheduler-tick
        // paths past iter ~416 in the spec-v3 test runner. Skip
        // ahead to the next future tick instead. The counter still
        // increments exactly once per real fire — spec only pins
        // the order (1, 2, ...), not the absolute timing.
        if (t.period_ns != 0) {
            const now_ns = arch.time.currentMonotonicNs();
            if (next_deadline <= now_ns) {
                const lag = now_ns - next_deadline;
                const periods_behind = lag / t.period_ns;
                next_deadline +|= (periods_behind + 1) *| t.period_ns;
            }
        }
        t.deadline_ns = next_deadline;
    } else {
        t.armed = false;
    }
    const timer_gen = t._gen_lock.currentGen();
    t._gen_lock.unlock();

    propagateAndWake(t, timer_gen, new_count);
    if (!periodic) {
        propagateField1(t, timer_gen, encodeField1(false, false));
    } else {
        wheelInsert(t, next_deadline);
    }
}

/// Walk every domain-local copy of this Timer's handle, writing
/// `value` into each `Capability.field0`, futex-waking the paddr, and
/// kicking idle remote cores so they re-evaluate the wake. Spec §[timer]
/// (eager but non-atomic propagation across copies).
fn propagateAndWake(t: *Timer, gen: u63, value: u64) void {
    var ctx = PropagateCtx{
        .timer_ref = SlabRef(Timer).init(t, gen),
        .value = value,
    };
    zag.caps.capability_domain.slab_instance.forEachAlive(
        &ctx,
        propagateField0Visitor,
    );
}

/// Mirror updated `field1` (arm/pd bits) into every domain-local copy.
/// No futex wake — userspace observes arm/pd transitions through
/// `sync` or as a side effect of the field0 wake.
fn propagateField1(t: *Timer, gen: u63, value: u64) void {
    var ctx = PropagateCtx{
        .timer_ref = SlabRef(Timer).init(t, gen),
        .value = value,
    };
    zag.caps.capability_domain.slab_instance.forEachAlive(
        &ctx,
        propagateField1Visitor,
    );
}

// ── Helpers ──────────────────────────────────────────────────────────

const TimerLookup = struct {
    timer_ref: SlabRef(Timer),
    slot: u12,
};

const HandleField = enum { field0, field1 };

/// Visitor context for `propagateAndWake` / `propagateField1`. The
/// visitor fires the side effect (memory write + optional futex_wake)
/// inline rather than staging matches into an array on the kernel
/// stack — staging would need worst-case
/// `MAX_DOMAINS * MAX_HANDLES_PER_DOMAIN` slots, which the kernel
/// stack frame cannot afford. Spec §[timer] (eager but non-atomic
/// propagation across copies).
const PropagateCtx = struct {
    timer_ref: SlabRef(Timer),
    value: u64,
};

fn propagateField0Visitor(ctx: *PropagateCtx, cd: *CapabilityDomain, gen: u63) bool {
    _ = gen;
    // self-alive: caller (`propagateAndWake`) holds a live SlabRef — the
    // Timer is wheel-pinned + refcount-pinned for the duration of the
    // visitor walk. We only consume the raw ptr/gen for identity match
    // against `entry.ref` below; we never deref the timer through
    // `timer_ptr`.
    const timer_ptr: *anyopaque = @ptrCast(ctx.timer_ref.ptr);
    const timer_gen: u32 = ctx.timer_ref.gen;
    var slot: u16 = 0;
    while (slot < zag.caps.capability.MAX_HANDLES_PER_DOMAIN) {
        const entry = &cd.kernel_table[slot];
        if (entry.ref.ptr) |obj_ptr| {
            // Identity match requires both ptr and gen — without the
            // gen check, a recycled slab slot at the same address would
            // false-match and we'd write the new (different) timer's
            // data to an unrelated CD's table slot.
            if (obj_ptr == timer_ptr and entry.ref.gen == timer_gen) {
                const tag = capability.Word0.typeTag(cd.user_table[slot].word0);
                if (tag == .timer) {
                    const slot12: u12 = @truncate(slot);
                    const paddr = computeFieldPaddr(cd, slot12, .field0);
                    arch.userio.writeU64ViaPhysmap(paddr, ctx.value);
                    _ = futex.wake(paddr, std.math.maxInt(u32));
                }
            }
        }
        slot += 1;
    }
    return true;
}

fn propagateField1Visitor(ctx: *PropagateCtx, cd: *CapabilityDomain, gen: u63) bool {
    _ = gen;
    // self-alive: same rationale as `propagateField0Visitor` — caller
    // pins the Timer via the wheel + refcount; raw ptr/gen are only
    // consumed for identity match against `entry.ref`.
    const timer_ptr: *anyopaque = @ptrCast(ctx.timer_ref.ptr);
    const timer_gen: u32 = ctx.timer_ref.gen;
    var slot: u16 = 0;
    while (slot < zag.caps.capability.MAX_HANDLES_PER_DOMAIN) {
        const entry = &cd.kernel_table[slot];
        if (entry.ref.ptr) |obj_ptr| {
            if (obj_ptr == timer_ptr and entry.ref.gen == timer_gen) {
                const tag = capability.Word0.typeTag(cd.user_table[slot].word0);
                if (tag == .timer) {
                    const slot12: u12 = @truncate(slot);
                    const paddr = computeFieldPaddr(cd, slot12, .field1);
                    arch.userio.writeU64ViaPhysmap(paddr, ctx.value);
                }
            }
        }
        slot += 1;
    }
    return true;
}

fn callerDomain(caller: *anyopaque) ?*CapabilityDomain {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const dlr = ec.domain.lockIrqSave(@src()) catch return null;
    ec.domain.unlockIrqRestore(dlr.irq_state);
    return dlr.ptr;
}

/// Read the slot-0 self-handle `timer` cap bit. Spec §[capability_domain]
/// self-handle cap layout — `timer` at bit 12 of the cap word — and
/// §[timer_arm] "Self-handle cap required: `timer`".
fn callerHasTimerCap(cd: *CapabilityDomain) bool {
    const caps_word: u16 = capability.Word0.caps(cd.user_table[0].word0);
    return (caps_word & (1 << 12)) != 0;
}

/// Enforce §[restart_semantics] test 08 / §[timer_arm] test 02:
/// when the requested timer caps include `restart_policy = 1`
/// (TimerCaps bit 4) the calling domain's self-handle
/// `restart_policy_ceiling.tm_restart_max` must be 1. The ceiling
/// lives in slot-0's field1 at bit 25 (the 16-bit
/// `restart_policy_ceiling` block occupies field1 bits 16-31, and
/// `tm_restart_max` is bit 9 within that block — i.e., bit 25 of
/// field1). Spec §[capability_domain] field1 layout.
fn checkRestartPolicyCeiling(cd: *CapabilityDomain, requested: u16) bool {
    const requested_keep: bool = (requested & (1 << 4)) != 0;
    if (!requested_keep) return true;
    const f1 = cd.user_table[0].field1;
    const tm_restart_max: u1 = @truncate((f1 >> 25) & 0x1);
    return tm_restart_max == 1;
}

fn resolveTimerHandle(cd: *CapabilityDomain, handle: u64, expected: CapabilityType) ?TimerLookup {
    // Spec §[capabilities]: a handle syscall arg is bits 0-11 (12-bit
    // slot id). The type tag is read from the user table's word0, not
    // from the syscall arg.
    const slot_id = capability.Word0.id(handle);

    const kernel_entry = &cd.kernel_table[slot_id];
    if (kernel_entry.ref.ptr == null) return null;

    const t_tag = capability.Word0.typeTag(cd.user_table[slot_id].word0);
    if (t_tag != expected) return null;

    const typed = capability.typedRef(Timer, kernel_entry.*) orelse return null;
    // Gen-validate by lock+immediately-unlock; real per-op locking
    // happens in the caller via `timer_ref.lock()` / `unlock()`.
    const tlr = typed.lockIrqSave(@src()) catch return null;
    typed.unlockIrqRestore(tlr.irq_state);
    return .{ .timer_ref = typed, .slot = slot_id };
}

fn handleHasArmCap(cd: *CapabilityDomain, slot: u12) bool {
    const caps = capability.Word0.caps(cd.user_table[slot].word0);
    const tc: TimerCaps = @bitCast(caps);
    return tc.arm;
}

fn handleHasCancelCap(cd: *CapabilityDomain, slot: u12) bool {
    const caps = capability.Word0.caps(cd.user_table[slot].word0);
    const tc: TimerCaps = @bitCast(caps);
    return tc.cancel;
}

fn encodeField1(armed: bool, periodic: bool) u64 {
    return (@as(u64, @intFromBool(armed))) |
        (@as(u64, @intFromBool(periodic)) << 1);
}

/// Resolve the physical address backing `field0`/`field1` of the handle
/// in slot `slot` of `cd`'s user table. Per-handle propagation needs
/// the paddr (not vaddr) because the kernel writes into every copy of
/// the read-only user-mapped table via the kernel physmap.
fn computeFieldPaddr(cd: *CapabilityDomain, slot: u12, which: HandleField) PAddr {
    const entry: *capability.Capability = &cd.user_table[slot];
    const field_addr: usize = switch (which) {
        .field0 => @intFromPtr(&entry.field0),
        .field1 => @intFromPtr(&entry.field1),
    };
    return PAddr.fromVAddr(.{ .addr = field_addr }, null);
}

fn currentNs() u64 {
    return arch.time.currentMonotonicNs();
}
