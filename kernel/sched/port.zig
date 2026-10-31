//! Port — rendezvous point between a calling thread and a receiving thread,
//! used for IPC, capability transfer, and thread event delivery.
//! See docs/kernel/specv3.md §[port].
//!
//! Lifecycle invariant: a port is alive iff
//!     recv_refcount > 0.
//! Slab teardown is gated solely on the recv side so the recv-cap holder
//! always has a chance to observe E_CLOSED before the underlying slot is
//! reclaimed. `bind_refcount` aggregates the contributors that fire
//! events on the port (handles with the `bind` cap, vCPU `exit_port` pins);
//! `recv_refcount` counts handles with `recv`. A handle that carries
//! only `copy`/`move`/`restart_policy`/`xfer`/`suspend` authorizes no
//! port-lifetime contribution. When `bind_refcount` hits zero, blocked
//! receivers are woken with E_CLOSED but the port stays alive — recv-
//! cap holders may still call `recv` and observe E_CLOSED until they
//! release. When `recv_refcount` hits zero the port is destroyed:
//! parked senders wake with E_CLOSED and any vCPUs still pinning
//! `exit_port` are cascade-terminated. The dec that observes
//! `.observed_zero` on `recv_refcount` owns teardown.
//!
//! Spec §[recv] tests 04/05 map directly to the bind-side check: recv
//! returns E_CLOSED iff the port has no bind-cap holders, no vCPU exit-port pins, and no queued events.

const std = @import("std");
const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;
const spin_diag = stygia.utils.spin_diag;
const arch_syscall = stygia.arch.dispatch.syscall;
const capability = stygia.caps.capability;
const process_mod = stygia.caps.process;
const errors = stygia.syscall.errors;
const thread_mod = stygia.sched.thread;
const lifecycle = stygia.sched.lifecycle;
const scheduler = stygia.sched.scheduler;

const Process = process_mod.Process;
const ThreadCaps = thread_mod.ThreadCaps;
const ThreadQueue = scheduler.ThreadQueue;
const ErasedSlabRef = capability.ErasedSlabRef;
const EventType = thread_mod.EventType;
const Thread = thread_mod.Thread;
const GenLock = stygia.memory.allocators.secure_slab.GenLock;
const KernelHandle = capability.KernelHandle;
const Refcount = stygia.utils.refcount.Refcount;
const SecureSlab = stygia.memory.allocators.secure_slab.SecureSlab;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const SpinLock = stygia.utils.sync.SpinLock;
const Word0 = capability.Word0;
// ── Timed recv waiters ───────────────────────────────────────────────
//
// Parallel structure to sched.futex.timed_waiters: a fixed array of thread
// pointers blocked in `recv` with a non-zero timeout. The scheduler
// tick (arch.x64.irq.schedTimerHandler) drives `expireTimedRecvWaiters`
// which dequeues expired Threads from their port's receiver queue, sets
// their syscall return to E_TIMEOUT, and re-schedules them.
//
// 256 slots is more than the spec needs (one thread can hold at most one
// recv-with-timeout in flight; concurrent recv-with-timeout count is
// bounded by core count plus user-space concurrency).
pub const MAX_TIMED_RECV_WAITERS: usize = 256;
pub var timed_recv_waiters: [MAX_TIMED_RECV_WAITERS]?*Thread = blk: {
    var arr: [MAX_TIMED_RECV_WAITERS]?*Thread = undefined;
    for (&arr) |*slot| slot.* = null;
    break :blk arr;
};
pub var timed_recv_lock: SpinLock = .{ .class = "port.timed_recv_lock" };

/// Per-core BSS scratch for `expireTimedRecvWaiters` Phase 1 → Phase 2
/// hand-off. At 256 × 16 = 4 KiB the snapshot used to live on the IRQ
/// timer-tick stack frame, sitting on top of whatever kernel/user stack
/// the tick interrupted. That 4 KiB plus the 1 KiB futex-tick snapshot
/// plus the rest of the scheduler chain pushed cumulative IRQ-context
/// stack usage past the point where adjacent frames' saved-RIP slots
/// were getting clobbered. One
/// scratch per core is safe because `schedTimerHandler` runs to
/// completion in IRQ context with IRQs masked, never recurses, and
/// each core has its own timer. Spec §[port] / kernel/arch/x64/irq.zig
/// `schedTimerHandler`.
const RecvSnapshot = struct { thread: SlabRef(Thread), deadline: u64 };
var expire_recv_scratch: [scheduler.MAX_CORES][MAX_TIMED_RECV_WAITERS]RecvSnapshot = undefined;

fn addTimedRecvWaiter(thread: *Thread) bool {
    const irq = timed_recv_lock.lockIrqSave(@src());
    defer timed_recv_lock.unlockIrqRestore(irq);
    for (&timed_recv_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = thread;
            return true;
        }
    }
    return false;
}

/// Public wrapper around `removeTimedRecvWaiter` for `terminate` /
/// `destroyThreadLocked` to drop a recv-timed slot that
/// would otherwise be revisited by the per-core timer tick after the
/// thread's gen has been bumped.
pub fn cancelRecvDeadline(thread: *Thread) void {
    removeTimedRecvWaiter(thread);
    thread.recv_deadline_ns = 0;
}

fn removeTimedRecvWaiter(thread: *Thread) void {
    const irq = timed_recv_lock.lockIrqSave(@src());
    defer timed_recv_lock.unlockIrqRestore(irq);
    for (&timed_recv_waiters) |*slot| {
        if (slot.* == thread) {
            slot.* = null;
            return;
        }
    }
}

/// Called from the scheduler tick to expire any recv-blocked Threads whose
/// `recv_deadline_ns` has passed. Spec §[port].recv test 14.
///
/// Phase 1 snapshots expired Threads under `timed_recv_lock`; Phase 2
/// removes each from its port's receiver queue under that port's
/// `_gen_lock`. The split avoids holding `timed_recv_lock` across a
/// Port lock acquisition (lock-order: Port locks may already be held
/// when timed_recv_lock is taken in `addTimedRecvWaiter`).
pub fn expireTimedRecvWaiters() void {
    const now_ns = arch.time.getMonotonicClock().now();

    const core_id = arch.smp.coreID();
    const expired = &expire_recv_scratch[@intCast(core_id)];
    var expired_count: usize = 0;
    {
        const irq = timed_recv_lock.lockIrqSave(@src());
        defer timed_recv_lock.unlockIrqRestore(irq);
        for (&timed_recv_waiters) |*slot| {
            const thread = slot.* orelse continue;
            if (!lifecycle.tryPinLive(thread)) {
                slot.* = null;
                continue;
            }
            // Cross-core terminate may have rotated this thread's slab gen
            // to even (freed) and left a stale entry here — `terminate`
            // / `destroyThreadLocked` don't reach into this
            // list. Drop dead entries before SlabRef.init's
            // `gen % 2 == 1` assertion fires from the per-core timer
            // tick.
            const gen = thread._gen_lock.currentGen();
            if (gen % 2 == 0) {
                lifecycle.releasePin(thread);
                slot.* = null;
                continue;
            }
            const deadline = thread.recv_deadline_ns;
            if (now_ns < deadline) {
                lifecycle.releasePin(thread);
                continue;
            }
            // caller-pinned: `thread` is pinned by the `timed_recv_waiters`
            // slot we just dequeued; capturing its current gen here
            // gives the phase-2 walk a stale-detector if the slot is
            // freed and reallocated between phases. The deadline
            // re-check below still catches the wake/re-wait race.
            expired[expired_count] = .{
                .thread = SlabRef(Thread).init(thread, gen),
                .deadline = deadline,
            };
            lifecycle.releasePin(thread);
            expired_count += 1;
            slot.* = null;
        }
    }

    for (expired[0..expired_count]) |entry| {
        // caller-pinned: `entry.thread` was captured under timed_recv_lock
        // above and the thread's slot can only be freed after this phase
        // unwinds the recv-waiter from its port queue. The deadline
        // check below catches a sender-wake / fresh-recv race.
        const thread = entry.thread.ptr;
        if (!lifecycle.tryPinLive(thread)) continue;
        if (thread._gen_lock.currentGen() != @as(u63, entry.thread.gen)) {
            lifecycle.releasePin(thread);
            continue;
        }
        // Re-check deadline. If a sender wake ran between phases the
        // deadline is now 0; if the thread was woken and made a fresh recv
        // it'd be a different value. Either way this snapshot is stale.
        if (thread.recv_deadline_ns != entry.deadline) {
            lifecycle.releasePin(thread);
            continue;
        }

        const port_ref = thread.suspend_port orelse {
            lifecycle.releasePin(thread);
            continue;
        };
        const p = port_ref.lock(@src()) catch {
            lifecycle.releasePin(thread);
            continue;
        };

        // Remove from the port's receiver queue if still present.
        // (`waiters.remove` is a no-op if the thread was already dequeued
        // by a sender on a different core.)
        const removed = p.waiters.remove(thread);
        if (removed and p.waiters.isEmpty()) p.waiter_kind = .none;
        port_ref.unlock();

        if (!removed) {
            lifecycle.releasePin(thread);
            continue;
        }

        const claim = lifecycle.beginWaitingClaimPinned(thread);
        if (claim == .none) {
            lifecycle.releasePin(thread);
            continue;
        }
        thread.recv_deadline_ns = 0;
        thread.suspend_port = null;
        thread.event_type = .none;
        // Stash E_TIMEOUT in the syscall return slot. The scheduler's
        // resume path restores the syscall-return register on iretq.
        arch_syscall.setSyscallReturn(thread.ctx, @bitCast(@as(i64, errors.E_TIMEOUT)));
        switch (claim) {
            .claimed => scheduler.enqueue(thread),
            .pended => lifecycle.publishPendedPayload(thread),
            .none => unreachable,
        }
        lifecycle.unpin(thread);
        lifecycle.releasePin(thread);
    }
}

/// Cap bits in `Capability.word0[48..63]` for port handles.
/// Spec §[port] cap layout.
pub const PortCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    xfer: bool = false,
    recv: bool = false,
    bind: bool = false,
    restart_policy: u1 = 0,
    @"suspend": bool = false,
    _reserved: u9 = 0,
};

/// Cap bits in `Capability.word0[48..63]` for reply handles.
/// Spec §[reply] cap layout. `copy` is always 0 by spec.
pub const ReplyCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    xfer: bool = false,
    /// Internal marker (not a user-visible cap): set by `terminate` on
    /// reply handles whose suspended sender was destroyed. Subsequent
    /// `reply` operations on the marked handle return `E_ABANDONED`
    /// per spec §[terminate] test 07. Lives in the caps bitfield so
    /// the existing user_table.word0 carries it without extending the
    /// kernel-side handle struct.
    abandoned: bool = false,
    _reserved: u12 = 0,
};

const pending_port_ref_caps: u16 = @bitCast(PortCaps{ .recv = true });

/// Names which side currently owns `Port.waiters`. A port can never
/// hold both senders and receivers at once: if a sender arrives with
/// receivers queued (or vice versa), the matching pair is consumed
/// before the queue settles. The dequeuer that empties the queue is
/// responsible for resetting this back to `.none`.
pub const WaiterKind = enum {
    /// Queue empty.
    none,
    /// Suspended Threads waiting to be picked up by a `recv`.
    senders,
    /// Threads blocked in `recv` waiting for an event.
    receivers,
};

pub const Port = struct {
    /// Slab generation lock. Validates `SlabRef(Port)` liveness AND
    /// guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Bind-side reference count. Aggregates everything that can fire
    /// an event on this port spontaneously:
    ///   - handles with the `bind` cap (one per handle),
    ///   - vCPU Threads whose `exit_port` references this port (one per vCPU).
    /// `inc → .observed_zero` raises `error.BadCap` so a SlabRef-walking
    /// minter that races a concurrent close aborts the mint instead of
    /// resurrecting a Sticky'd counter. `dec → .observed_zero` wakes
    /// blocked receivers with E_CLOSED but does NOT destroy the port —
    /// the recv-cap holder may still call `recv` and observe E_CLOSED
    /// until they release their handle. Spec §[recv] tests 04/05.
    bind_refcount: Refcount = .{},

    /// Reference count for `recv`-side handles. `dec → .observed_zero`
    /// owns slab teardown: parked senders wake with E_CLOSED, any
    /// vCPUs still pinning `exit_port` are cascade-terminated, and the
    /// slab slot is freed via `destroyPort`.
    recv_refcount: Refcount = .{},

    /// Head of the singly-linked list of vCPU Threads whose `exit_port`
    /// references this port. Each vCPU contributes one to
    /// `bind_refcount`; the cascade walk on `recv_refcount → 0`
    /// terminates each bound vCPU before the slab is freed. Mutated
    /// under `_gen_lock` only.
    /// Each node is a `SlabRef(Thread)` stamped when the vCPU is
    /// published, so port-cascade teardown destroys only the thread generation
    /// that actually held the exit-port pin.
    vcpu_list_head: ?SlabRef(Thread) = null,

    /// Wait queue, holding either suspended senders OR blocked receivers
    /// — never both. `waiter_kind` names which.
    waiters: ThreadQueue = .{},

    /// Which side owns `waiters`. `.none` iff the queue is empty.
    waiter_kind: WaiterKind = .none,
};

// Layout asserts for the L4 IPC fast path. The asm rendezvous in
// `kernel/arch/x64/interrupts.zig::syscallEntry` references
// `_gen_lock`, `waiters`, and `waiter_kind` as immediate
// displacements off `*Port`; these guard against drift.
comptime {
    if (@offsetOf(Port, "waiter_kind") <= @offsetOf(Port, "waiters")) {
        @compileError("Port.waiter_kind must follow Port.waiters (asm fast path)");
    }
    if (@offsetOf(Port, "_gen_lock") >= @offsetOf(Port, "waiters")) {
        @compileError("Port._gen_lock must precede Port.waiters (asm fast path)");
    }
}

pub const Allocator = SecureSlab(Port, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: stygia.utils.range.Range,
    ptrs_range: stygia.utils.range.Range,
    links_range: stygia.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

/// Bit positions used to encode the recv-side syscall return word per
/// §[event_state]: pair_count[12-19], tstart[20-31], reply_handle_id
/// [32-43], event_type[44-48].
const PAIR_COUNT_SHIFT: u6 = 12;
const TSTART_SHIFT: u6 = 20;
const REPLY_HANDLE_SHIFT: u6 = 32;
const EVENT_TYPE_SHIFT: u6 = 44;
const REPORT_TAG_MAGIC: u64 = 0x8000;
const REPORT_PRINT_BUDGET: u32 = 4096;
var report_deliver_prints: u32 = 0;
const UNHANDLED_PRINT_BUDGET: u32 = 64;
var unhandled_prints: u32 = 0;

// ── External API ─────────────────────────────────────────────────────

fn hasContiguousFreeSlots(process: *Process, n: u8) bool {
    if (n == 0) return true;
    if (process.free_count < n) return false;
    var run_len: u16 = 0;
    var i: u16 = 3;
    while (i < capability.MAX_HANDLES_PER_PROCESS) : (i += 1) {
        if (process.kernel_table[i].ref.ptr == null) {
            run_len += 1;
            if (run_len >= n) return true;
        } else {
            run_len = 0;
        }
    }
    return false;
}

fn canFitReplyAndAttachments(process: *Process, pair_count: u8) bool {
    return process.free_count >= 1 + @as(u32, pair_count) and
        hasContiguousFreeSlots(process, pair_count);
}

fn pinReceiver(receiver: *Thread) bool {
    return lifecycle.pinLiveLocked(receiver);
}

fn publishReceiverAndUnpin(receiver: *Thread, claim: lifecycle.ClaimResult) void {
    if (lifecycle.isDestroyMarked(receiver)) {
        switch (claim) {
            .claimed => {},
            .pended => lifecycle.publishPendedPayload(receiver),
            .none => unreachable,
        }
        lifecycle.unpin(receiver);
        return;
    }
    switch (claim) {
        .claimed => scheduler.enqueue(receiver),
        .pended => lifecycle.publishPendedPayload(receiver),
        .none => unreachable,
    }
    lifecycle.unpin(receiver);
}

fn publishFailedReceiverAndUnpin(receiver: *Thread, claim: lifecycle.ClaimResult, err: i64) void {
    const target_ctx = receiver.iret_frame orelse receiver.ctx;
    arch.syscall.setSyscallReturn(target_ctx, @bitCast(err));
    publishReceiverAndUnpin(receiver, claim);
}

fn dropTempRecvRefLocked(p: *Port, irq_state: u64) void {
    var result = decRecvRef(p);
    if (!result.destroyed) {
        p._gen_lock.unlockIrqRestore(irq_state);
    } else {
        arch.cpu.restoreInterrupts(irq_state);
    }
    finalizePendingVcpus(result.pending_vcpus);
    finalizeClosedSenders(&result.pending_senders);
}

fn acquireHandleRefForCaps(entry: thread_mod.PairEntryStashed, caps_word: u16) error{BadCap}!void {
    switch (entry.obj_type) {
        .page_frame => {
            const pf: *stygia.memory.page_frame.PageFrame =
                @ptrCast(@alignCast(entry.obj_ref.ptr.?));
            try stygia.memory.page_frame.incHandleRef(pf);
        },
        .port => {
            const alias_ref = SlabRef(Port){
                .ptr = @ptrCast(@alignCast(entry.obj_ref.ptr.?)),
                .gen = entry.obj_ref.gen,
                ._pad = entry.obj_ref._pad,
            };
            const alias_lr = alias_ref.lockIrqSave(@src()) catch return error.BadCap;
            defer alias_ref.unlockIrqRestore(alias_lr.irq_state);
            try onHandleAcquire(alias_lr.ptr, caps_word);
        },
        .device_region => {
            const dr: *stygia.devices.device_region.DeviceRegion =
                @ptrCast(@alignCast(entry.obj_ref.ptr.?));
            try stygia.devices.device_region.incHandleRef(dr);
        },
        else => {},
    }
}

fn acquireTransferredHandleRef(entry: thread_mod.PairEntryStashed, caps_word: u16) void {
    acquireHandleRefForCaps(entry, caps_word) catch unreachable;
}

pub fn acquirePendingPairEntryRef(entry: thread_mod.PairEntryStashed) error{BadCap}!void {
    try acquireHandleRefForCaps(entry, entry.pending_ref_caps);
}

fn releaseHandleRefForCaps(entry: thread_mod.PairEntryStashed, caps_word: u16, held_port: ?*Port) void {
    switch (entry.obj_type) {
        .page_frame => stygia.memory.page_frame.releaseHandle(@ptrCast(@alignCast(entry.obj_ref.ptr.?))),
        .port => {
            const sp: *Port = @ptrCast(@alignCast(entry.obj_ref.ptr.?));
            if (held_port != null and held_port.? == sp) {
                const result = onHandleRelease(sp, caps_word);
                std.debug.assert(!result.destroyed);
                std.debug.assert(result.pending_vcpus == null);
            } else {
                releaseHandle(sp, caps_word);
            }
        },
        .device_region => {
            const sdr: *stygia.devices.device_region.DeviceRegion =
                @ptrCast(@alignCast(entry.obj_ref.ptr.?));
            stygia.devices.device_region.releaseHandle(sdr);
        },
        else => {},
    }
}

fn releasePendingPairEntryRef(entry: thread_mod.PairEntryStashed, held_port: ?*Port) void {
    releaseHandleRefForCaps(entry, entry.pending_ref_caps, held_port);
}

fn releasePendingPairEntriesMaybeHeldPort(thread: *Thread, held_port: ?*Port) void {
    const count = thread.pending_pair_count;
    thread.pending_pair_count = 0;
    var k: u8 = 0;
    while (k < count) : (k += 1) {
        releasePendingPairEntryRef(thread.pending_pair_entries[k], held_port);
    }
}

pub fn releasePendingPairEntries(thread: *Thread) void {
    releasePendingPairEntriesMaybeHeldPort(thread, null);
}

pub fn pendingRefCapsForEntry(entry: thread_mod.PairEntryStashed) u16 {
    if (entry.obj_type == .port) return pending_port_ref_caps;
    return entry.source_caps;
}

fn clearReplyTransferPendingAndReturn(caller: *Thread, err: i64) i64 {
    releasePendingPairEntries(caller);
    return err;
}

fn disarmSuspendDirectiveForFallback(target_thread: *Thread, arm_word: u32) bool {
    if (!lifecycle.disarmDirectiveWord(target_thread, arm_word)) return false;
    target_thread.directive_port = null;
    target_thread.directive_owner = null;
    target_thread.originating_write_cap = false;
    target_thread.originating_read_cap = false;
    return true;
}

fn waitForSuspendDirectiveFailure(target_thread: *Thread, failed_word: u32) ?i64 {
    if (target_thread.directive_state.load(.acquire) != failed_word) return null;
    const result = target_thread.directive_result.load(.acquire);
    if (!lifecycle.clearFailedDirectiveWord(target_thread, failed_word)) return null;
    return if (result != 0) result else errors.E_BUSY;
}

fn waitForSuspendDirective(
    target_ref: SlabRef(Thread),
    target_thread: *Thread,
    port_ref: SlabRef(Port),
    owner_slot: u24,
) i64 {
    const arm_word = lifecycle.packDirective(.armed, owner_slot);
    const failed_word = lifecycle.packDirective(.failed, owner_slot);
    var spins: u32 = 0;
    while (true) {
        var disarmed_not_running = false;
        var fallback_suspend = false;
        var fallback_owner: ?*Thread = null;
        var fallback_write_cap = false;
        var fallback_read_cap = false;

        while (target_thread.directive_state.load(.acquire) == arm_word) {
            const state = lifecycle.load(target_thread);
            if (state != .running) {
                if (state == .retired and disarmSuspendDirectiveForFallback(target_thread, arm_word)) {
                    disarmed_not_running = true;
                    break;
                }
                if (lifecycle.canSuspendTarget(target_thread)) {
                    fallback_owner = target_thread.directive_owner;
                    fallback_write_cap = target_thread.originating_write_cap;
                    fallback_read_cap = target_thread.originating_read_cap;
                    fallback_suspend = true;
                    break;
                }
                continue;
            }
            spins +%= 1;
            if ((spins & 1023) == 0) {
                const owner_core = target_thread.owner_core;
                if (owner_core < scheduler.MAX_CORES) {
                    arch.smp.triggerSchedulerInterrupt(owner_core);
                }
            }
            spin_diag.note(.directive_spin, @intFromPtr(target_thread));
            std.atomic.spinLoopHint();
        }

        if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;

        const target_lr = target_ref.lockIrqSave(@src()) catch {
            if (disarmSuspendDirectiveForFallback(target_thread, arm_word)) return errors.E_TERM;
            if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;
            return 0;
        };
        const final_state = lifecycle.load(target_lr.ptr);
        target_ref.unlockIrqRestore(target_lr.irq_state);

        if (disarmed_not_running) {
            if (final_state == .retired) return errors.E_TERM;
            return errors.E_INVAL;
        }
        if (final_state == .retired) {
            if (disarmSuspendDirectiveForFallback(target_thread, arm_word)) return errors.E_TERM;
            if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;
            return 0;
        }

        const port_lr = port_ref.lockIrqSave(@src()) catch {
            if (disarmSuspendDirectiveForFallback(target_thread, arm_word)) return errors.E_BADCAP;
            if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;
            return 0;
        };
        port_ref.unlockIrqRestore(port_lr.irq_state);

        if (fallback_suspend) {
            const owner = fallback_owner orelse {
                if (disarmSuspendDirectiveForFallback(target_thread, arm_word)) return errors.E_BUSY;
                if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;
                return 0;
            };
            const port_lr2 = port_ref.lockIrqSave(@src()) catch {
                if (disarmSuspendDirectiveForFallback(target_thread, arm_word)) return errors.E_BADCAP;
                if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;
                return 0;
            };
            const ret = thread_mod.suspendOnPortWithPairHandoffDirectiveGen(
                target_thread,
                owner,
                port_lr2.ptr,
                .suspension,
                0,
                0,
                fallback_write_cap,
                fallback_read_cap,
                port_lr2.irq_state,
                target_ref.gen,
                arm_word,
            );
            if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |failed_ret| return failed_ret;
            if (ret == errors.E_BUSY and target_thread.directive_state.load(.acquire) != arm_word) {
                if (lifecycle.isPortSuspended(target_thread)) return 0;
                return errors.E_BUSY;
            }
            if ((ret == errors.E_INVAL or ret == errors.E_BUSY) and target_thread.directive_state.load(.acquire) == arm_word) {
                const owner_core = target_thread.owner_core;
                if (owner_core < scheduler.MAX_CORES) {
                    arch.smp.triggerSchedulerInterrupt(owner_core);
                }
                spin_diag.note(.directive_spin, @intFromPtr(target_thread));
                std.atomic.spinLoopHint();
                continue;
            }
            if (ret != 0 and disarmSuspendDirectiveForFallback(target_thread, arm_word)) return ret;
            if (ret != 0) {
                if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |failed_ret| return failed_ret;
            }
            return ret;
        }
        if (lifecycle.isPortSuspended(target_thread)) return 0;
        if (target_thread.directive_state.load(.acquire) == arm_word) continue;
        if (waitForSuspendDirectiveFailure(target_thread, failed_word)) |ret| return ret;
        return errors.E_BUSY;
    }
}

/// `create_port` syscall handler. Spec §[port].create_port.
///
/// Caller-side cap-ceiling and `crpt` checks are done in syscall/port.zig
/// before reaching here; this layer mints the slab and the handle.
pub fn createPort(caller: *Thread, caps: u64) i64 {
    const port_caps: PortCaps = @bitCast(@as(u16, @truncate(caps)));

    const process_ref = caller.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    defer process_ref.unlockIrqRestore(lr.irq_state);

    if (process.free_count == 0) return errors.E_FULL;

    const port = allocPort() catch return errors.E_NOMEM;

    // Fresh port: the slab slot was just published with gen=odd and
    // refcounts at 0. observed_zero is impossible here (no concurrent
    // dec can have raced our publish), so propagate the error type
    // for structural completeness but treat it as unreachable.
    onHandleAcquire(port, @bitCast(port_caps)) catch unreachable;

    const obj_ref: ErasedSlabRef = .{
        .ptr = port,
        .gen = @intCast(port._gen_lock.currentGen()),
    };
    const port_caps_word: u16 = @bitCast(port_caps);
    const slot = process_mod.mintHandle(
        process,
        obj_ref,
        .port,
        port_caps_word,
        0,
        0,
    ) catch {
        // mintHandle failed after onHandleAcquire bumped the refcounts.
        // Roll back via onHandleRelease + finalize the cascade snapshot.
        // The caller (createPort) holds the process lock but no port lock;
        // releaseHandle takes the port lock internally.
        releaseHandle(port, port_caps_word);
        return errors.E_FULL;
    };
    // Spec §[error_codes] / §[capabilities]: pack Word0 so the
    // returned value carries the type tag in bits 12..15 and never
    // collides with the small-positive error range 1..15.
    return @intCast(Word0.pack(slot, .port, port_caps_word));
}

/// `suspend` syscall handler. Spec §[port].suspend.
///
/// Slow-path mirror of arch/x64/interrupts.zig fast suspend: on success
/// the caller's thread ends up either suspended on `port` (if no receiver
/// waiting) or still running with the receiver dequeued and event state
/// delivered. State produced here MUST match what the fast path produces
/// so the two are interchangeable.
fn terminalSuspendResult(process_ref: SlabRef(Process), target_slot: u12, target_ref: SlabRef(Thread)) i64 {
    // The thread lock must be released before taking the process lock.
    // Revalidate the slot identity: another caller may have removed and
    // reused it while suspend was resolving the target on this core.
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_TERM;
    if (capability.resolveHandleOnProcess(lr.ptr, target_slot, .thread)) |entry| {
        if (capability.typedRef(Thread, entry.*)) |current_ref| {
            if (current_ref.eql(target_ref)) capability.clearAndFreeSlot(lr.ptr, target_slot, entry);
        }
    }
    process_ref.unlockIrqRestore(lr.irq_state);
    return errors.E_TERM;
}

pub fn suspendThread(caller: *Thread, target: u64, port: u64) i64 {
    const process_ref = caller.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const process_irq_state = lr.irq_state;

    const target_slot: u12 = @truncate(target);
    const port_slot: u12 = @truncate(port);

    const target_entry = capability.resolveHandleOnProcess(process, target_slot, .thread) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };
    const port_entry = capability.resolveHandleOnProcess(process, port_slot, .port) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };

    const thread_caps: ThreadCaps = @bitCast(Word0.caps(process.user_table[target_slot].word0));
    if (!thread_caps.susp) {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_PERM;
    }

    const target_ref = capability.typedRef(Thread, target_entry.*) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };
    const port_ref = capability.typedRef(Port, port_entry.*) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };
    process_ref.unlockIrqRestore(process_irq_state);

    if (!lifecycle.selfMarkSuspending(caller)) return errors.E_BUSY;
    defer lifecycle.clearSelfDirective(caller);

    const SuspendRetry = struct {
        fn fromState(thread: *Thread, state: lifecycle.State) bool {
            return switch (state) {
                .running, .ready, .claimed => true,
                .waiting => thread.wait.kind == .idle,
                // User-mode hlt/wfi parks through a short owner-stack
                // handoff state before becoming `.waiting(.idle)`.
                // The settled idle waiter is suspendable; treating the
                // handoff as final E_INVAL makes suspend race the hlt
                // trap on SMP.
                .parking => thread.wait.kind == .idle,
                else => false,
            };
        }

        fn check(thread: *Thread) bool {
            return fromState(thread, lifecycle.load(thread));
        }
    };

    while (true) {
        var tlr = target_ref.lockIrqSave(@src()) catch
            return terminalSuspendResult(process_ref, target_slot, target_ref);
        var target_thread = tlr.ptr;
        var target_irq_state = tlr.irq_state;
        var target_state = lifecycle.load(target_thread);
        while (true) {
            if (target_thread.vm != null) {
                target_ref.unlockIrqRestore(target_irq_state);
                return errors.E_INVAL;
            }
            if (lifecycle.canSuspendTarget(target_thread)) break;
            if (!SuspendRetry.fromState(target_thread, target_state)) {
                const terminal = target_state == .retired or lifecycle.isDestroyMarked(target_thread);
                target_ref.unlockIrqRestore(target_irq_state);
                return if (terminal) terminalSuspendResult(process_ref, target_slot, target_ref) else errors.E_INVAL;
            }
            target_ref.unlockIrqRestore(target_irq_state);
            spin_diag.note(.suspend_retry, @intFromPtr(target_thread));
            arch.paging.serviceTlbMaintenanceWhileSpinning();
            stygia.sched.fpu.serviceLocalFlushWhileSpinning();
            std.atomic.spinLoopHint();
            tlr = target_ref.lockIrqSave(@src()) catch
                return terminalSuspendResult(process_ref, target_slot, target_ref);
            target_thread = tlr.ptr;
            target_irq_state = tlr.irq_state;
            target_state = lifecycle.load(target_thread);
        }
        // Spec §[handle_attachments]: when the caller is suspending a
        // different thread, the pair entries were validated against the
        // caller's process in `validatePairEntries` and stashed on the
        // caller's thread. The actual move/copy at recv time runs against
        // the suspended thread (which is what `deliverEvent` sees), so we
        // hand the stash off only after the target commits the remote
        // directive into a real port suspension. A self-suspend leaves the
        // stash where it already lives.
        if (target_thread != caller and target_state == .running) {
            if (!lifecycle.tryPinLive(target_thread)) {
                target_ref.unlockIrqRestore(target_irq_state);
                return terminalSuspendResult(process_ref, target_slot, target_ref);
            }
            const owner_slot_u32 = thread_mod.slab_instance.indexOf(caller);
            const owner_slot: u24 = @intCast(owner_slot_u32);
            if (!lifecycle.claimRemoteSuspend(target_thread, owner_slot)) {
                lifecycle.releasePin(target_thread);
                target_ref.unlockIrqRestore(target_irq_state);
                return errors.E_BUSY;
            }
            target_thread.directive_port = port_ref;
            target_thread.directive_owner = caller;
            target_thread.originating_write_cap = thread_caps.write;
            target_thread.originating_read_cap = thread_caps.read;
            if (!lifecycle.armRemoteSuspend(target_thread, owner_slot)) {
                target_thread.directive_port = null;
                target_thread.directive_owner = null;
                target_thread.originating_write_cap = false;
                target_thread.originating_read_cap = false;
                lifecycle.releasePin(target_thread);
                target_ref.unlockIrqRestore(target_irq_state);
                return errors.E_BUSY;
            }
            const owner_core = target_thread.owner_core;
            target_ref.unlockIrqRestore(target_irq_state);
            if (owner_core < scheduler.MAX_CORES) {
                arch.smp.triggerSchedulerInterrupt(owner_core);
            }
            const ret = waitForSuspendDirective(target_ref, target_thread, port_ref, owner_slot);
            const should_retry = (ret == errors.E_BUSY or ret == errors.E_INVAL) and
                SuspendRetry.check(target_thread);
            lifecycle.releasePin(target_thread);
            if (should_retry) {
                spin_diag.note(.suspend_retry, @intFromPtr(target_thread));
                arch.paging.serviceTlbMaintenanceWhileSpinning();
                stygia.sched.fpu.serviceLocalFlushWhileSpinning();
                std.atomic.spinLoopHint();
                continue;
            }
            return if (ret == errors.E_TERM)
                terminalSuspendResult(process_ref, target_slot, target_ref)
            else
                ret;
        }
        const target_pinned = target_thread != caller;
        if (target_pinned and !lifecycle.tryPinLive(target_thread)) {
            target_ref.unlockIrqRestore(target_irq_state);
            return terminalSuspendResult(process_ref, target_slot, target_ref);
        }
        target_ref.unlockIrqRestore(target_irq_state);

        const plr = port_ref.lockIrqSave(@src()) catch {
            if (target_pinned) lifecycle.releasePin(target_thread);
            return errors.E_BADCAP;
        };
        const p = plr.ptr;
        // Re-validate target state under the destination port lock. If a
        // remote ready target won a dispatch race after the thread-side check
        // above, it must be handled by the directive path on its owner core;
        // the generic suspend helper is allowed to park only this core's
        // current running thread.
        if (target_thread != caller and lifecycle.load(target_thread) == .running) {
            port_ref.unlockIrqRestore(plr.irq_state);
            if (target_pinned) lifecycle.releasePin(target_thread);
            spin_diag.note(.suspend_retry, @intFromPtr(target_thread));
            arch.paging.serviceTlbMaintenanceWhileSpinning();
            stygia.sched.fpu.serviceLocalFlushWhileSpinning();
            std.atomic.spinLoopHint();
            continue;
        }
        if (!lifecycle.canSuspendTarget(target_thread)) {
            port_ref.unlockIrqRestore(plr.irq_state);
            const should_retry = SuspendRetry.check(target_thread);
            const terminal = lifecycle.load(target_thread) == .retired or lifecycle.isDestroyMarked(target_thread);
            if (target_pinned) lifecycle.releasePin(target_thread);
            if (should_retry) {
                spin_diag.note(.suspend_retry, @intFromPtr(target_thread));
                arch.paging.serviceTlbMaintenanceWhileSpinning();
                stygia.sched.fpu.serviceLocalFlushWhileSpinning();
                std.atomic.spinLoopHint();
                continue;
            }
            return if (terminal) terminalSuspendResult(process_ref, target_slot, target_ref) else errors.E_INVAL;
        }
        // `suspendOnPort` releases the port lock before returning (directly
        // on the no-receiver path, transitively via `rendezvousWithReceiver`
        // on the success path) so we MUST NOT add `defer port_ref.unlockIrqRestore(...)`.

        // Snapshot the originating thread handle's `write` and `read` caps so
        // reply-time can decide whether receiver mutations apply (Spec
        // §[reply] tests 05/06) and so recv-time gates the suspended thread's
        // §[event_state] vregs 1..13 exposure (Spec §[suspend] test 10).
        // The caps were captured into `thread_caps` above under the process lock.
        const ret = thread_mod.suspendOnPortWithPairHandoffGen(target_thread, caller, p, .suspension, 0, 0, thread_caps.write, thread_caps.read, plr.irq_state, target_ref.gen);
        const should_retry = target_pinned and
            (ret == errors.E_BUSY or ret == errors.E_INVAL) and
            SuspendRetry.check(target_thread);
        if (target_pinned) lifecycle.releasePin(target_thread);
        if (should_retry) {
            spin_diag.note(.suspend_retry, @intFromPtr(target_thread));
            arch.paging.serviceTlbMaintenanceWhileSpinning();
            stygia.sched.fpu.serviceLocalFlushWhileSpinning();
            std.atomic.spinLoopHint();
            continue;
        }
        return if (ret == errors.E_TERM)
            terminalSuspendResult(process_ref, target_slot, target_ref)
        else
            ret;
    }
}

/// `recv` syscall handler. Spec §[port].recv.
///
/// Slow path: if a sender is queued, pair off, mint a reply handle in
/// the caller's process, deliver event state via vregs, and return. If no
/// sender is queued and the port has bind holders or routes, the caller
/// suspends as a receiver; otherwise returns E_CLOSED.
///
/// Lock order: caller's process `_gen_lock` is acquired first, held for the
/// duration of the Port lock acquisition + port-side work, and only
/// dropped after `deliverEvent` finishes (which needs process held to mint
/// the reply slot). The Port lock is released before `deliverEvent` runs
/// so the canonical process → Port order is never inverted — see the lock-
/// order note on `deliverEvent`.
pub fn recv(caller: *Thread, port: u64, timeout_ns: u64) i64 {
    // Wrapper: run the recv body (which holds the caller's process gen-lock
    // throughout, including across `deliverEvent`), then execute the
    // recorded derivation-tree links AFTER the process lock has dropped —
    // `derive` takes `tree_mutex` and must never run under a process
    // gen-lock (see `caps.derivation.tree_mutex`). Safe to defer: the
    // freshly-minted slots belong to `caller`, who is right here in
    // this syscall and cannot race its own handles.
    var deferred: DeferredDerives = .{};
    var moves: DeferredMoveClears = .{};
    const ret = recvInner(caller, port, timeout_ns, &deferred, &moves);
    deferred.run();
    moves.run();
    return ret;
}

fn recvInner(
    caller: *Thread,
    port: u64,
    timeout_ns: u64,
    deferred: *DeferredDerives,
    moves: *DeferredMoveClears,
) i64 {
    const process_ref = caller.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    defer process_ref.unlockIrqRestore(lr.irq_state);

    const port_slot: u12 = @truncate(port);
    const port_entry = capability.resolveHandleOnProcess(process, port_slot, .port) orelse
        return errors.E_BADCAP;
    const port_ref = capability.typedRef(Port, port_entry.*) orelse
        return errors.E_BADCAP;

    const plr = port_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const p = plr.ptr;
    const port_irq_state = plr.irq_state;

    if (p.waiter_kind == .senders) {
        const sender = popHighestPrioritySender(p) orelse {
            port_ref.unlockIrqRestore(port_irq_state);
            return errors.E_CLOSED;
        };
        // Spec §[port].recv test 06: the receiver needs free slots
        // for the reply handle plus every attached handle. Compare
        // against `1 + sender.pending_pair_count` before disturbing
        // the sender's resume state. (The check moved past the pop
        // because the slot count depends on the sender's stash, but
        // we reset and re-enqueue if we bail.)
        if (!canFitReplyAndAttachments(process, sender.pending_pair_count)) {
            // Re-enqueue: the sender was popped from the head; push
            // it back so a future recv can match it.
            p.waiters.enqueueFront(sender);
            p.waiter_kind = .senders;
            port_ref.unlockIrqRestore(port_irq_state);
            return errors.E_FULL;
        }
        // Drop the Port lock before deliverEvent — it needs receiver-process
        // (the caller's process, already held by us). Holding both would
        // re-introduce the Port → process inversion.
        const evt_type = sender.event_type;
        const evt_sub = sender.event_subcode;
        const evt_addr = sender.event_addr;
        const pair_count = sender.pending_pair_count;
        // Spec §[reply]: the minted reply handle inherits `xfer = 1`
        // iff the recv'ing port carried the `xfer` cap. Snapshot the
        // recv'ing port's xfer cap from the caller's table while the
        // process lock is still held; deliverEvent uses it to set the
        // minted reply handle's caps below.
        const port_caps_word: u16 = @truncate(Word0.caps(process.user_table[port_slot].word0));
        const port_caps_typed: PortCaps = @bitCast(port_caps_word);
        const port_xfer = port_caps_typed.xfer;
        port_ref.unlockIrqRestore(port_irq_state);
        return deliverEvent(sender, caller, process, evt_type, evt_sub, evt_addr, pair_count, port_xfer, deferred, moves);
    }

    // No sender ready. Spec §[recv] test 04: if the port has no
    // bind-cap holders, no vCPU exit-port pins, and no queued
    // events, return E_CLOSED rather than blocking forever. Routes
    // and vCPU exit_ports also contribute to `bind_refcount`, so this
    // single check covers the full "no future events possible" set.
    // The `senders` waiter-kind branch above already handled queued
    // events; reaching here means the queue is empty.
    if (p.bind_refcount.snapshot() == 0) {
        port_ref.unlockIrqRestore(port_irq_state);
        return errors.E_CLOSED;
    }

    // Spec §[port].recv test 06: a recv whose handle table is already
    // full cannot mint the reply handle the eventual sender will need,
    // so block-then-fail is observably equivalent to fail-now. Surface
    // E_FULL up front rather than parking and discovering the failure
    // at rendezvous time (which would silently lose the wakeup).
    if (process.free_count == 0) {
        port_ref.unlockIrqRestore(port_irq_state);
        return errors.E_FULL;
    }

    // suspend_port MUST be set before adding the caller to the port's
    // waiter queue. A cross-core `terminate(caller)` reads suspend_port
    // without holding the port lock to decide whether to run the port-
    // queue cleanup arm; if it observed null while the caller was
    // already enqueued here, it would skip cleanup, bump-and-free the
    // thread, and leave a stale `*thread` in the port's waiter queue. The next
    // `popHighest*` walk would then return that pointer (gen now odd
    // again from reallocation, state=.ready from the new owner) as a
    // phantom receiver.
    const caller_core: u8 = @truncate(arch.smp.coreID());
    if (!lifecycle.prepareRunningPark(caller, caller_core, .port_receiver)) {
        port_ref.unlockIrqRestore(port_irq_state);
        return errors.E_INVAL;
    }
    caller.suspend_port = SlabRef(Port).init(p, p._gen_lock.currentGen());
    caller.wait.port = caller.suspend_port;
    caller.event_type = .none;
    enqueueReceiver(p, caller);
    // Spec §[reply]: cache the recv'ing port's xfer cap so the
    // rendezvous-with-receiver wake path can mint the reply handle
    // with `xfer` derived from the recv'ing handle, not from
    // pair_count.
    {
        const port_caps_word: u16 = @truncate(Word0.caps(process.user_table[port_slot].word0));
        const port_caps_typed: PortCaps = @bitCast(port_caps_word);
        caller.recv_port_xfer = port_caps_typed.xfer;
    }
    caller.pending_reply_holder = null;
    caller.pending_reply_process = null;
    caller.pending_reply_slot = 0;
    // Deliberately NO `on_cpu` clear here. The caller keeps executing
    // on this very kstack all the way through the syscall epilogue and
    // into the scheduler (`hopParkRun`); clearing `on_cpu` now lets a
    // sender's wake pass its release spin, enqueue the caller, and
    // dispatch it on another core — which then builds fresh kernel
    // frames down this kstack while we are still running on it (the
    // "Kernel stack overflow" frame-stomp autopsy). The release is
    // stashed below and published by the park-kstack hop, the first
    // instruction after which this core no longer touches the kstack.

    // Timed recv — register before dropping the port lock so the wakeup
    // path can find us. Spec §[port].recv test 14.
    if (timeout_ns != 0) {
        const now_ns = arch.time.getMonotonicClock().now();
        caller.recv_deadline_ns = now_ns + timeout_ns;
        _ = addTimedRecvWaiter(caller);
    }

    port_ref.unlockIrqRestore(port_irq_state);

    return 0;
}

/// Reply-FP atomic-recv-park senders bail. Called from the reply fast
/// path's asm when, having committed the reply portion (R6/R9/R10),
/// the recv portion's port_lock acquire reveals
/// `waiter_kind == .senders` — meaning a peer thread arrived on the
/// recv_port BEFORE the caller's atomic-recv reached this point. The
/// asm cannot enqueue the caller as a receiver (would clobber
/// waiter_kind and strand the sender), so it releases port_lock +
/// caller_gen_lock and routes here to perform the slow-path equivalent
/// of `port.recv` against the now-unlocked port. Slow-path recv sees
/// `.senders`, pops the highest-priority sender, calls `deliverEvent`
/// (mints reply handle, stages event_state in
/// `caller.pending_event_word`), and returns; we then park the caller
/// as a local requeue so the asm's R14 swap to the original replyee can
/// proceed without publishing the caller `.ready` from its own kstack.
/// The scheduler discharges that requeue on a later park-stack entry.
///
/// The asm has already cleared the reply slot (R6) and resumed the
/// replyee (R9/R10 sender state writes), so a true bail to the
/// reply-syscall slow path is impossible — that path would re-resolve
/// the now-cleared reply handle and return E_BADCAP. The
/// reply-half-already-committed shape is what makes this helper
/// necessary in the first place.
pub export fn replyAtomicRecvSendersFallback(
    caller: *Thread,
    recv_port_handle: u64,
) callconv(.c) void {
    // Slow-path recv. Re-acquires the receiver process lock and the port
    // gen-lock, observes `.senders` under lock, runs the rendezvous
    // path. Return value is the §[event_state] word for the rendezvous
    // case or `0` for the (race-window: senders drained between asm
    // observation and here) park case. Either way the data is staged
    // through `pending_event_word` / port wait queue; we don't need
    // the return value here.
    _ = recv(caller, recv_port_handle, 0);

    // After recv:
    //   - Rendezvous case: `caller` is still running (deliverEvent
    //     doesn't transition state — it expects the syscall epilogue
    //     to handle the post-syscall flow). Defer a local requeue so
    //     the asm's R14 swap to the original replyee dispatches a
    //     different thread on this core before the caller becomes ready
    //     with `pending_event_word` ready to flush at iretq.
    //   - Park case: `caller` is parking (recv
    //     parked it on the port wait queue). Nothing more to do.
    if (lifecycle.load(caller) == .running) {
        _ = scheduler.deferLocalRunningRequeue(caller);
    }
}

/// `reply` syscall handler. Spec §[reply].reply.
pub fn reply(caller: *Thread, reply_handle: u64) i64 {
    const process_ref = caller.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const process_irq_state = lr.irq_state;

    const slot: u12 = @truncate(reply_handle);
    const entry = capability.resolveHandleOnProcess(process, slot, .reply) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };

    const sender_ref = capability.typedRef(Thread, entry.*) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };

    // Snapshot the caps on the reply handle and clear the slot under
    // the process lock so a concurrent delete cannot race the resume.
    const reply_caps: ReplyCaps = @bitCast(Word0.caps(process.user_table[slot].word0));

    capability.clearAndFreeSlot(process, slot, entry);

    process_ref.unlockIrqRestore(process_irq_state);

    // Spec §[terminate] test 07: when terminate destroys the suspended
    // sender, it marks the reply handle's `abandoned` bit. Subsequent
    // reply ops on that slot return E_ABANDONED rather than E_TERM.
    if (reply_caps.abandoned) return errors.E_ABANDONED;

    // Spec §[reply] typed routing: the kernel reads the wide
    // §[vm_exit_state] window from the receiver's user stack ONLY for
    // replies typed `vm_exit` (per the originating event_type captured
    // at recv time). Non-vm_exit replies skip the wide read entirely —
    // saves the SMAP bracket + 416-byte stack load on every IPC reply,
    // and avoids faulting on receivers that called the L4-narrow-frame
    // `reply` helper without reserving the wide window. Take a brief
    // sender lock to read `event_type`, drop, then snapshot conditionally
    // OUTSIDE the lock so a fault on the user-stack reads can unwind
    // the syscall without leaking the sender's lock bit.
    const event_type = blk: {
        const sender_lr_peek = sender_ref.lockIrqSave(@src()) catch return errors.E_TERM;
        const et = sender_lr_peek.ptr.event_type;
        sender_ref.unlockIrqRestore(sender_lr_peek.irq_state);
        break :blk et;
    };

    const reply_snap = if (event_type == .vm_exit)
        arch.vm.snapshotReplyVregs(caller)
    else
        arch.vm.ReplyVregSnapshot{};

    // IRQ-saving acquire: `consumeReply` runs with the sender's
    // thread._gen_lock held; masking IRQs across the held window prevents
    // the timer ISR's scheduler dispatch from registering a thread→process
    // edge that would invert the destroy-side process→thread ordering. Spec
    // §[reply] writeback discipline; see also the IRQ-acquired class
    // enforcement in `tools/check_gen_lock`.
    const sender_lr = sender_ref.lockIrqSave(@src()) catch return errors.E_TERM;
    const sender = sender_lr.ptr;
    const sender_irq_state = sender_lr.irq_state;
    defer sender_ref.unlockIrqRestore(sender_irq_state);

    consumeReply(entry, caller, sender, &reply_snap, event_type);
    return 0;
}

/// `reply_transfer` syscall handler. Spec §[reply].reply_transfer.
///
/// The pair entries were validated and stashed onto
/// `caller.pending_pair_entries[0..n]` by the syscall layer
/// (kernel/syscall/reply.zig::replyTransfer); each stashed entry
/// carries the source's `ErasedSlabRef`, type tag, install caps, the
/// `move` flag, and the source slot id in the caller's process.
///
/// Order:
///   1. Resolve the reply handle in caller's process (no clear yet —
///      test 11 demands the caller's table is unchanged on E_FULL).
///      Pull the suspended sender out of the entry's typed ref and
///      surface E_TERM if the sender slab generation moved (test 10).
///   2. Lock the resumed sender's process (== `sender.process`) and
///      reserve N contiguous slots via `allocContiguousFreeSlots`. On
///      failure, drop locks and return E_FULL with the reply handle
///      still in the caller's table (test 11), releasing the
///      validation-time pending object refs.
///   3. With contiguous slots reserved, install each pair entry via
///      `mintHandleAt` at `[tstart, tstart+N)` in the sender's process.
///   4. Drop the sender's process lock; run derivation links and moved-source
///      deletes through the original source processes with no process lock
///      held, then consume the reply slot. The reply handle is consumed
///      last so test 11's "[1] is NOT consumed on E_FULL" stays
///      observably true above.
///   5. Stage the §[event_state] return word (`pair_count`, `tstart`)
///      on the resumed sender's `pending_event_word` so the iretq
///      flush writes it to `[user_rsp + 0]` while CR3 is the sender's.
///   6. Apply receiver-side GPR mods (gated by sender's
///      `originating_write_cap`, mirroring `consumeReply`) and resume
///      the sender via `resumeFromReply`.
pub fn replyTransfer(caller: *Thread, reply_handle: u64, n: u8) i64 {
    const caller_cd_ref = caller.process;
    const slot: u12 = @truncate(reply_handle);

    // Phase 1 — caller's process: resolve the reply handle, capture the
    // sender's typed ref, snapshot reply caps. Drop the process lock before
    // taking the sender's thread lock to honor the canonical process-at-a-time
    // discipline observed by `terminate` (which holds process across a thread
    // lock and so registers the order process → thread with lockdep). Holding
    // process across a thread acquire here would otherwise invert that.
    const lr_phase1 = caller_cd_ref.lockIrqSave(@src()) catch
        return clearReplyTransferPendingAndReturn(caller, errors.E_BADCAP);
    const process_phase1 = lr_phase1.ptr;
    const entry = capability.resolveHandleOnProcess(process_phase1, slot, .reply) orelse {
        caller_cd_ref.unlockIrqRestore(lr_phase1.irq_state);
        return clearReplyTransferPendingAndReturn(caller, errors.E_BADCAP);
    };
    const sender_ref = capability.typedRef(Thread, entry.*) orelse {
        caller_cd_ref.unlockIrqRestore(lr_phase1.irq_state);
        return clearReplyTransferPendingAndReturn(caller, errors.E_BADCAP);
    };
    // Spec §[terminate] test 07: a reply handle whose suspended sender
    // was destroyed via terminate carries the `abandoned` bit.
    const reply_caps: ReplyCaps = @bitCast(Word0.caps(process_phase1.user_table[slot].word0));
    caller_cd_ref.unlockIrqRestore(lr_phase1.irq_state);

    if (reply_caps.abandoned) {
        // Spec §[reply_transfer] test 10 names E_TERM for the
        // reply_transfer path when the suspended sender was terminated;
        // §[terminate] test 07 names E_ABANDONED for the symmetric
        // `reply` and `delete` paths. We honor reply_transfer's spec
        // verbatim here — the abandoned bit is the witness that the
        // sender was destroyed via `terminate`, and reply_transfer
        // surfaces that as E_TERM. The reply slot is consumed in
        // either case so subsequent ops don't loop on the same id.
        const process_clear_lr = caller_cd_ref.lockIrqSave(@src()) catch
            return clearReplyTransferPendingAndReturn(caller, errors.E_TERM);
        const process_clear = process_clear_lr.ptr;
        if (capability.resolveHandleOnProcess(process_clear, slot, .reply)) |e| {
            capability.clearAndFreeSlot(process_clear, slot, e);
        }
        caller_cd_ref.unlockIrqRestore(process_clear_lr.irq_state);
        releasePendingPairEntries(caller);
        return errors.E_TERM;
    }

    // Phase 2 — sender liveness probe. Take the sender's thread lock just
    // long enough to validate the slab gen and capture the sender's
    // process ref. The lock is dropped before the sender's process is
    // acquired — sender_cd_ref.lock validates that ref's own gen so
    // the sender process pointer doesn't dangle even with the thread lock
    // released. Holding the thread lock here while taking the process lock
    // would invert the kernel-wide process → thread order.
    const sender_lr = sender_ref.lockIrqSave(@src()) catch {
        const process_clear_lr = caller_cd_ref.lockIrqSave(@src()) catch
            return clearReplyTransferPendingAndReturn(caller, errors.E_TERM);
        const process_clear = process_clear_lr.ptr;
        if (capability.resolveHandleOnProcess(process_clear, slot, .reply)) |e| {
            capability.clearAndFreeSlot(process_clear, slot, e);
        }
        caller_cd_ref.unlockIrqRestore(process_clear_lr.irq_state);
        releasePendingPairEntries(caller);
        return errors.E_TERM;
    };
    const sender = sender_lr.ptr;
    const sender_cd_ref = sender.process;
    // Spec §[reply] typed routing — pick up the originating event_type
    // while we hold the sender lock so reply-side state writeback below
    // can branch on it without re-locking.
    const sender_event_type = sender.event_type;
    sender_ref.unlockIrqRestore(sender_lr.irq_state);

    // Phase 3 — sender's process: reserve N contiguous slots and install
    // each pair entry. process-at-a-time: caller's process is unlocked here, no
    // other lock is held.
    const sender_cd_lr = sender_cd_ref.lockIrqSave(@src()) catch {
        releasePendingPairEntries(caller);
        return errors.E_BADCAP;
    };
    const sender_process = sender_cd_lr.ptr;
    const tstart = process_mod.allocContiguousFreeSlots(sender_process, n) catch {
        // Test 11: [1] is NOT consumed and the caller's table is
        // unchanged on E_FULL.
        sender_cd_ref.unlockIrqRestore(sender_cd_lr.irq_state);
        releasePendingPairEntries(caller);
        return errors.E_FULL;
    };

    // Spec §[ipc_rx] test 01: IPC handles delivered to the sender's
    // process get caps ∩ sender_process.ipc_rx (self-handle field0 bits 32-39).
    const sender_ipc_rx: u16 = @truncate((sender_process.user_table[0].field0 >> 32) & 0xFF);
    var k: u8 = 0;
    while (k < n) : (k += 1) {
        const stash = caller.pending_pair_entries[k];
        const target_slot: u12 = @intCast(@as(u16, tstart) + k);
        const installed_caps: u16 = if (stash.obj_type == .process)
            stash.caps & sender_ipc_rx
        else
            stash.caps;
        acquireTransferredHandleRef(stash, installed_caps);
        process_mod.mintHandleAt(
            sender_process,
            target_slot,
            stash.obj_ref,
            stash.obj_type,
            installed_caps,
            0,
            0,
        );
    }
    // Snapshot the sender-process ref while its gen is provably live (lock
    // still held) for the post-unlock derive loop below.
    const sender_dom_ref_for_derive: capability.ErasedSlabRef = .{
        .ptr = sender_process,
        .gen = @intCast(sender_process._gen_lock.currentGen()),
    };
    sender_cd_ref.unlockIrqRestore(sender_cd_lr.irq_state);

    // Spec §[capabilities].revoke: hang each new alias in the sender's
    // process under the source handle in its original holder process.
    // Runs AFTER the sender-process gen-lock dropped: `derive`
    // takes `tree_mutex`, and the old in-loop call (with the process held
    // via `held_dom`) was one half of a live AB-BA against the
    // process-teardown tree walk — this core spinning on `tree_mutex`
    // holding sender_process, the teardown core holding `tree_mutex`
    // spinning on sender_process (see `caps.derivation.tree_mutex`).
    // Ordering is safe: the suspended sender cannot use (or delete)
    // the minted handles until `deliverReplyTransferResume` marks it
    // ready in phase 5, and `derive` re-validates gens / bails on
    // touched slots for every other racer.
    k = 0;
    while (k < n) : (k += 1) {
        const stash = caller.pending_pair_entries[k];
        _ = stygia.caps.derivation.deriveExpected(
            stash.source_process,
            stash.src_slot,
            stash.obj_ref,
            stash.obj_type,
            stash.source_caps,
            stash.source_instance,
            sender_dom_ref_for_derive,
            @intCast(@as(u16, tstart) + k),
        );
    }

    // §[reply_transfer] test 14 vreg-14 (RIP) reload: harvest the
    // SMAP-bracketed user-stack read NOW, before any sender lock, so a
    // page fault on the user page can abort cleanly without leaking the
    // sender's `_gen_lock` bit. The receiver (`caller`) is the running
    // thread on this core, so CR3 already references its address space.
    const receiver_frame = caller.iret_frame orelse caller.ctx;
    const new_rip = arch.syscall.readUserVreg14(receiver_frame);

    k = 0;
    while (k < n) : (k += 1) {
        const stash = caller.pending_pair_entries[k];
        if (!stash.move) continue;
        _ = stygia.caps.derivation.deleteAndDetachExpected(
            stash.source_process,
            stash.src_slot,
            stash.obj_ref,
            stash.obj_type,
            stash.source_caps,
            stash.source_instance,
        );
    }

    // Phase 4 — caller's process: consume the reply slot. Same
    // single-process-at-a-time pattern; moved source slots were consumed
    // above through derivation.deleteAndDetachExpected so their
    // children are reparented before the source is cleared.
    const process_phase4_lr = caller_cd_ref.lockIrqSave(@src()) catch {
        // Caller's process is gone mid-transfer. The sender-side install
        // already committed; resume the sender so the test thread's death
        // doesn't strand a parked sender forever.
        releasePendingPairEntries(caller);
        const sender2_lr = sender_ref.lockIrqSave(@src()) catch return errors.OK;
        const sender2 = sender2_lr.ptr;
        defer sender_ref.unlockIrqRestore(sender2_lr.irq_state);
        deliverReplyTransferResume(caller, sender2, n, tstart, new_rip, sender_event_type);
        return errors.OK;
    };
    const process_phase4 = process_phase4_lr.ptr;
    if (capability.resolveHandleOnProcess(process_phase4, slot, .reply)) |reply_entry| {
        capability.clearAndFreeSlot(process_phase4, slot, reply_entry);
    }
    caller_cd_ref.unlockIrqRestore(process_phase4_lr.irq_state);

    releasePendingPairEntries(caller);

    // Phase 5 — sender's thread: stage the §[event_state] return word and
    // resume. Re-lock the sender; if the slab gen has moved between
    // phases the sender was reaped concurrently, in which case the
    // installed handles in the sender's process become orphans (they share
    // the process's lifetime, so they'll be reclaimed when the process
    // dies). The reply handle is already consumed; surface OK so the
    // caller observes a clean transfer.
    const sender2_lr = sender_ref.lockIrqSave(@src()) catch return errors.OK;
    const sender2 = sender2_lr.ptr;
    defer sender_ref.unlockIrqRestore(sender2_lr.irq_state);
    deliverReplyTransferResume(caller, sender2, n, tstart, new_rip, sender_event_type);
    return errors.OK;
}

/// Stage the resumed sender's syscall return state and re-enqueue them.
/// Mirrors `consumeReply` for GPR write-back, plus stages the
/// §[event_state] syscall return word with `pair_count`/`tstart` so
/// the iretq flush surfaces the spec-mandated values to the sender.
///
/// `new_rip` was harvested by the caller via `arch.syscall.readUserVreg14`
/// BEFORE acquiring the sender's `_gen_lock` — the SMAP-bracketed user
/// read can fault, and faulting under the sender lock would strand the
/// lock bit. Pure memory writes here.
fn deliverReplyTransferResume(
    caller: *Thread,
    sender: *Thread,
    pair_count: u8,
    tstart: u12,
    new_rip: u64,
    event_type: EventType,
) void {
    // Stage the §[event_state] post-resume word for the sender. Field
    // positions mirror the recv-side composition: pair_count at bits
    // 12-19, tstart at bits 20-31. event_type/reply_handle_id are
    // zeroed — the resumed sender is exiting `suspend`, not entering
    // a recv, so those fields stay 0. For vm_exit reply_transfer the
    // sender is a vCPU thread that resumes via guest entry, not via a
    // user-mode iretq, but staging the word is harmless (the vCPU's
    // user_rsp is unused on guest re-entry).
    const ret_word: u64 =
        (@as(u64, pair_count) << PAIR_COUNT_SHIFT) |
        (@as(u64, tstart) << TSTART_SHIFT);
    sender.pending_event_word = ret_word;
    sender.pending_event_word_valid = true;

    // Apply receiver-side GPR mods only for non-vm_exit replies. For
    // vm_exit reply_transfer the sender's `iret_frame` is the vCPU's
    // saved kernel-mode run-loop frame (not a user-mode resume frame),
    // so writing user-style GPRs would corrupt the kernel's own state.
    // Spec test 16 covers the initial_state handshake on
    // reply_transfer; the vCPU stays not-started (synthetic-exit
    // re-delivery), so guest-state writeback is unnecessary here.
    if (event_type != .vm_exit and sender.originating_write_cap) {
        const sender_frame = sender.iret_frame orelse sender.ctx;
        const receiver_frame = caller.iret_frame orelse caller.ctx;
        arch.syscall.copyEventStateGprs(sender_frame, receiver_frame);
        arch.syscall.setEventRip(sender_frame, new_rip);
    }
    thread_mod.resumeFromReply(sender, sender.originating_write_cap);
}

/// Report an unhandled user fault before tearing down its process.
/// The fault path may hold locks, so use the raw printer.
fn reportUnhandledFault(
    thread: *Thread,
    kind: []const u8,
    terminal_reason: []const u8,
    subcode: u8,
    payload: u64,
) void {
    thread_mod.printPreReportTerminal(thread, null, terminal_reason, subcode);
    const n = @atomicRmw(u32, &unhandled_prints, .Add, 1, .monotonic);
    if (n >= UNHANDLED_PRINT_BUDGET) return;

    arch.boot.printRaw("[UNHANDLED] ");
    arch.boot.printRaw(kind);
    arch.boot.printRaw(" thread=0x");
    printHex64(@intFromPtr(thread));
    arch.boot.printRaw(" subcode=");
    printHex64(subcode);
    arch.boot.printRaw(" payload=0x");
    printHex64(payload);
    const maybe_tag = arch_syscall.getEventStateGprs(thread.ctx)[4];
    if ((maybe_tag & REPORT_TAG_MAGIC) != 0) {
        arch.boot.printRaw(" tag=0x");
        printHex64(maybe_tag);
    }
    arch.boot.printRaw(" -- thread parked, result (if any) will never be delivered\n");
}

fn printHex64(n: u64) void {
    var buf: [16]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            const d: u8 = @intCast(v & 0xF);
            buf[i] = if (d < 10) d + '0' else d - 10 + 'a';
            v >>= 4;
        }
    }
    arch.boot.printRaw(buf[i..]);
}

fn maybePrintReportDelivered(sender: *Thread, receiver: *Thread, reply_slot: u12) void {
    if (!build_options.kernel_spawn_diag) return;
    const tag = sender.event_state_gprs[4];
    if ((tag & REPORT_TAG_MAGIC) == 0) return;
    const n = @atomicRmw(u32, &report_deliver_prints, .Add, 1, .monotonic);
    if (n >= REPORT_PRINT_BUDGET) return;
    arch.boot.print(
        "[rpt-deliver] sender=0x{x} receiver=0x{x} tag=0x{x} reply={x}\n",
        .{ @intFromPtr(sender), @intFromPtr(receiver), tag, reply_slot },
    );
}

fn queueFaultProcessTeardown(thread: *Thread, kind: scheduler.TeardownKind) void {
    scheduler.queueCurrentTeardown(.{ .kind = kind, .process = thread.process });
    thread_mod.parkSelfFaulted(thread);
    if (scheduler.currentThread() == thread) scheduler.hopParkRun();
}

pub fn fireMemoryFault(thread: *Thread, subcode: u8, fault_addr: u64) void {
    reportUnhandledFault(thread, "memory_fault", "unhandled_memory_fault", subcode, fault_addr);

    queueFaultProcessTeardown(thread, .unhandled_fault);
}

/// An unhandled thread fault tears down the thread's process.
pub fn fireThreadFault(thread: *Thread, subcode: u8, payload: u64) void {
    reportUnhandledFault(thread, "thread_fault", "unhandled_thread_fault", subcode, payload);
    queueFaultProcessTeardown(thread, .unhandled_fault);
}

/// Fire a vm_exit event for a vCPU thread through its exit_port.
/// Spec §[vm_exit_state].
pub fn fireVmExit(thread: *Thread, subcode: u8, payload: [3]u64) void {
    const exit_port_ref = thread.exit_port orelse return;
    const exit_lr = exit_port_ref.lockIrqSave(@src()) catch return;
    const port_ptr = exit_lr.ptr;
    // `suspendOnPort` releases the port lock before returning — see its
    // contract. Do NOT add `defer exit_port_ref.unlockIrqRestore(...)` here.

    // Stash payload[3] on the vCPU's arch state so `port.deliverEvent`
    // (and the rendezvous resume path) can pick it up at delivery time
    // without re-threading the [3]u64 through suspendOnPort. payload[0]
    // also rides in `event_addr` for compatibility with the
    // event-state addr field, and is mirrored here for vm_exit.
    arch.vm.stashLastExitPayload(thread, payload);

    // The originating thread handle for vm_exit is the vCPU thread handle held
    // by the VMM. `read`/`write` default to true so §[event_state] /
    // §[vm_exit_state] vregs are exposed and reply mutations are
    // committed back; per-vCPU cap-snapshot wiring lands when the
    // VMM-side handle is captured at create_vcpu time.
    _ = thread_mod.suspendOnPort(thread, port_ptr, .vm_exit, subcode, payload[0], true, true, exit_lr.irq_state);
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate a Port. Initial counters are caps-driven by the caller.
fn allocPort() !*Port {
    const pending = try slab_instance.create();
    // Slab zero-on-free leaves every field at its zero pattern, which
    // matches Port's initial state (refcounts=0, waiters empty, kind
    // .none, vcpu_list_head null).
    _ = slab_instance.publish(pending);
    return pending.ptr;
}

/// Final teardown — caller observed `.observed_zero` on a refcount dec.
/// Frees the slab slot.
fn destroyPort(p: *Port) void {
    // Lock is held by the decrementer that drove a counter to 0; release
    // and gen-bump in one shot via `destroyLocked`.
    const gen = p._gen_lock.currentGen();
    slab_instance.destroyLocked(p, gen);
}

/// Detach every vCPU from `p.vcpu_list_head` UNDER `p._gen_lock`. Nulls
/// each thread's `exit_port` and rechains the snapshot through `vcpu_list_next`.
/// Returns the snapshot head; caller must invoke `finalizePendingVcpus`
/// on it AFTER `p._gen_lock` has been released.
///
/// Detach under the port lock and finalize after release so teardown
/// never recursively locks this port while unlinking a vCPU.
fn cascadeDetachVcpus(p: *Port) ?SlabRef(Thread) {
    var head: ?SlabRef(Thread) = null;
    var cur = p.vcpu_list_head;
    p.vcpu_list_head = null;
    while (cur) |thread_ref| {
        const thread = thread_ref.ptr;
        const next = thread.vcpu_list_next;
        thread.exit_port = null;
        if (lifecycle.tryPinLive(thread)) {
            thread.vcpu_list_next = head;
            head = thread_ref;
        } else {
            thread.vcpu_list_next = null;
        }
        cur = next;
    }
    return head;
}

/// Walk the snapshot returned by `cascadeDetachVcpus` and destroy each
/// thread. Callers MUST have released `p._gen_lock` (and `p` itself may
/// already be freed) before invoking this — the snapshot only carries
/// thread refs, not the port pointer.
pub fn finalizePendingVcpus(head: ?SlabRef(Thread)) void {
    var cur = head;
    while (cur) |thread_ref| {
        const thread = thread_ref.ptr;
        const next = thread.vcpu_list_next;
        thread.vcpu_list_next = null;
        // `cascadeDetachVcpus` took a lifecycle pin before publishing this
        // node into the detached chain. Release it before destruction so
        // `destroyThreadRefLocked` can drain pins, but destroy
        // through the captured SlabRef so a stale/recycled thread slot is
        // rejected by the gen-lock.
        lifecycle.releasePin(thread);
        // Port-cascade teardown is not process teardown: the vCPU's process is
        // still live, so pending replies must be abandoned through the normal
        // live-process path instead of the same-process teardown shortcut.
        thread_mod.destroyThreadRefLocked(thread_ref, null);
        cur = next;
    }
}

/// Result of a refcount dec. `destroyed` is true iff the dec drove the
/// port to teardown (`.observed_zero`); when set, `destroyPort` has
/// already released `p._gen_lock` via `destroyLocked` so the caller
/// must skip its standard unlock. `pending_vcpus` is the snapshot of
/// vCPUs that were detached from `p.vcpu_list_head` while the lock was
/// held; callers MUST drop the port lock and then invoke
/// `finalizePendingVcpus(pending_vcpus)` to complete the cascade.
pub const DecResult = struct {
    destroyed: bool,
    /// Snapshot head detached under `p._gen_lock` from `p.vcpu_list_head`.
    /// Each node is a generation-stamped thread ref, and `cascadeDetachVcpus`
    /// holds one lifecycle pin per pending node until
    /// `finalizePendingVcpus` consumes it.
    pending_vcpus: ?SlabRef(Thread),
    /// Sender waiters detached under the closing port lock. They are
    /// completed after the port lock drops so releasing stashed
    /// attachments cannot nest arbitrary cross-port port locks.
    pending_senders: ThreadQueue = .{},
};

/// Refcount adjusters. Each `inc*` returns `error.BadCap` when it
/// observes the Sticky bit (a concurrent dec already drove the count
/// to 0); the caller must NOT proceed as if it acquired a reference.
/// All run under `p._gen_lock`.
pub fn incBindRef(p: *Port) error{BadCap}!void {
    if (p.bind_refcount.inc() == .observed_zero) return error.BadCap;
}

/// Drop one bind-side reference. On `observed_zero` (last bind holder
/// gone, no vCPU `exit_port` pin), wake
/// any blocked receivers with E_CLOSED but DO NOT destroy the slab —
/// the recv-cap holder is still authorized to call `recv` and observe
/// E_CLOSED until they release. Slab teardown is gated solely on
/// `recv_refcount → 0` (see `decRecvRef`). The vcpu_list is empty by
/// invariant when this fires: each vCPU's destroy decrements
/// `bind_refcount` before the count can hit zero.
pub fn decBindRef(p: *Port) void {
    if (p.bind_refcount.dec() == .observed_zero) {
        propagateClosedToReceivers(p);
    }
}
pub fn incRecvRef(p: *Port) error{BadCap}!void {
    if (p.recv_refcount.inc() == .observed_zero) return error.BadCap;
}

/// Drop one recv-side reference. On `observed_zero` the port is
/// unreachable from any future recv path: parked senders wake with
/// E_CLOSED, any blocked receivers still queued (their handle was
/// deleted while they were parked) wake with E_CLOSED, vCPUs still
/// pinning `exit_port` are detached for cascade-terminate, and the
/// slab is freed. The destroyed flag tells the caller to skip its
/// standard unlock — `destroyLocked` consumed the gen-lock.
pub fn decRecvRef(p: *Port) DecResult {
    const result = p.recv_refcount.dec();
    if (result == .observed_zero) {
        var pending_senders: ThreadQueue = .{};
        detachClosedSenders(p, &pending_senders);
        // A blocked recv whose handle was deleted while parked sees
        // its port die from underneath it. Wake with E_CLOSED so the
        // thread doesn't sit on a stale waiter list past the slab's gen
        // bump.
        propagateClosedToReceivers(p);
        const pending = cascadeDetachVcpus(p);
        destroyPort(p);
        return .{ .destroyed = true, .pending_vcpus = pending, .pending_senders = pending_senders };
    }
    return .{ .destroyed = false, .pending_vcpus = null };
}

/// Aggregate handle-cap bookkeeping. Called from caps copy/delete/
/// restrict to translate cap-bit edge transitions into refcount calls.
/// Only the `bind` and `recv` caps contribute to port lifetime — the
/// `suspend` cap authorizes the `suspend` syscall but doesn't pin the
/// slab; suspend-only handles silently observe E_BADCAP if recv-side
/// teardown frees the port out from under them.
/// On `.observed_zero` from either inc, returns `error.BadCap` — and
/// rolls back the bind-side inc if the recv-side inc fails after it.
pub fn onHandleAcquire(p: *Port, caps: u16) error{BadCap}!void {
    const c: PortCaps = @bitCast(caps);
    var inc_bind = false;
    if (c.bind) {
        try incBindRef(p);
        inc_bind = true;
    }
    if (c.recv) {
        incRecvRef(p) catch |err| {
            if (inc_bind) {
                // Rollback dec must not drive teardown — we just inc'd.
                // bind_refcount dec never destroys; just walk the wake
                // path if it observes zero (which it can't here since
                // we just inc'd).
                decBindRef(p);
            }
            return err;
        };
    }
}

/// Run both decs BEFORE inspecting the recv result so a handle holding
/// both `bind` AND `recv` doesn't have its second dec operate on a
/// freed slab. Returns the cascade snapshot for the caller to
/// finalize after lock release. The bind-side dec never destroys —
/// only the recv-side dec can drive slab teardown.
fn onHandleRelease(p: *Port, caps: u16) DecResult {
    const c: PortCaps = @bitCast(caps);
    var bind_zero = false;
    var recv_zero = false;
    if (c.bind) {
        bind_zero = p.bind_refcount.dec() == .observed_zero;
    }
    if (c.recv) {
        recv_zero = p.recv_refcount.dec() == .observed_zero;
    }
    if (!bind_zero and !recv_zero) return .{ .destroyed = false, .pending_vcpus = null };

    if (bind_zero) propagateClosedToReceivers(p);
    if (recv_zero) {
        var pending_senders: ThreadQueue = .{};
        detachClosedSenders(p, &pending_senders);
        // A blocked recv whose handle was the same one being dropped
        // here observes E_CLOSED through the bind-side wake above; the
        // recv-side wake catches the rare race where a different
        // recv-cap holder's blocked recv was queued and the port now
        // has no recv path at all.
        if (!bind_zero) propagateClosedToReceivers(p);
        const pending = cascadeDetachVcpus(p);
        destroyPort(p);
        return .{ .destroyed = true, .pending_vcpus = pending, .pending_senders = pending_senders };
    }
    return .{ .destroyed = false, .pending_vcpus = null };
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Wraps `onHandleRelease` and finalizes
/// the cascade snapshot after `p._gen_lock` is released.
pub fn releaseHandle(p: *Port, caps: u16) void {
    const irq_state = p._gen_lock.lockIrqSave(@src());
    var result = onHandleRelease(p, caps);
    // `destroyPort` released the lock via `destroyLocked` on teardown;
    // teardown bumps gen via setGenRelease without touching IRQ state,
    // so restore it explicitly. Otherwise `unlockIrqRestore` does both.
    if (!result.destroyed) {
        p._gen_lock.unlockIrqRestore(irq_state);
    } else {
        arch.cpu.restoreInterrupts(irq_state);
    }
    finalizePendingVcpus(result.pending_vcpus);
    finalizeClosedSenders(&result.pending_senders);
}

/// `releaseHandle` for callers that already hold `p._gen_lock`. The
/// caller passes its IRQ-state token so the destroy path can restore
/// interrupts when `destroyLocked` consumed the lock without
/// restoring IRQs. The vCPU finalize walk runs only AFTER the lock
/// has been released.
pub fn releaseHandleLocked(p: *Port, caps: u16, held_irq: u64) void {
    var result = onHandleRelease(p, caps);
    if (!result.destroyed) {
        p._gen_lock.unlockIrqRestore(held_irq);
    } else {
        arch.cpu.restoreInterrupts(held_irq);
    }
    finalizePendingVcpus(result.pending_vcpus);
    finalizeClosedSenders(&result.pending_senders);
}

/// Wait queue ops — assert empty or matching kind, transition kind
/// on (en)queue, reset to .none when drained.
fn enqueueReceiver(p: *Port, receiver: *Thread) void {
    std.debug.assert(p.waiter_kind != .senders);
    p.waiters.enqueue(receiver);
    p.waiter_kind = .receivers;
}
fn popHighestPrioritySender(p: *Port) ?*Thread {
    if (p.waiter_kind != .senders) return null;
    while (p.waiters.dequeue()) |thread| {
        if (p.waiters.isEmpty()) p.waiter_kind = .none;
        // Cross-core terminate may have left a dead thread parked here;
        // skip it so callers never resume an exited slot.
        if (lifecycle.isDestroyMarked(thread) or lifecycle.load(thread) == .retired or thread._gen_lock.currentGen() % 2 == 0) continue;
        return thread;
    }
    return null;
}
fn popHighestPriorityReceiver(p: *Port) ?*Thread {
    if (p.waiter_kind != .receivers) return null;
    while (p.waiters.dequeue()) |thread| {
        if (p.waiters.isEmpty()) p.waiter_kind = .none;
        if (lifecycle.isDestroyMarked(thread) or lifecycle.load(thread) == .retired or thread._gen_lock.currentGen() % 2 == 0) continue;
        return thread;
    }
    return null;
}

/// Rendezvous + delivery — called once a (sender, receiver) pair is
/// identified. Mints a reply handle in receiver's process, processes
/// attachments, writes event-state vregs, transitions states.
///
/// Slow-path mirror of arch/x64/interrupts.zig Phase 4: the syscall
/// return word and event-state vregs written here MUST match what the
/// fast path produces so the two are interchangeable.
///
/// LOCK ORDER: Caller MUST already hold `dom` (receiver's process `_gen_lock`)
/// AND MUST NOT hold any Port `_gen_lock`. Canonical order across the
/// kernel is `Process` → `Port`; the matching `delete` path
/// takes process then dispatches to `port.releaseHandle` which takes Port,
/// so this side must finish all Port-held work and drop Port BEFORE
/// reaching here. Holding Port across the process acquisition done by the
/// previous version of this function created an AB-BA cycle observed
/// by lockdep at port.zig:613 vs port.zig:552.
/// Derivation-tree link work recorded by `deliverEvent` for execution
/// AFTER the receiver-process gen-lock drops. `derive` takes `tree_mutex`
/// and must never run with a process gen-lock held (see the tree_mutex
/// order contract in `caps.derivation`) — the old inline derive inside
/// `deliverEvent`'s mint loop deadlocked against the process-teardown
/// tree walk. `src_slots` is bounded by the pair-transfer stash size.
pub const DeferredDerives = struct {
    child_dom: capability.ErasedSlabRef = .{ .ptr = null, .gen = 0 },
    tstart: u12 = 0,
    count: u8 = 0,
    parent_doms: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]capability.ErasedSlabRef = undefined,
    parent_refs: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]capability.ErasedSlabRef = undefined,
    parent_types: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]capability.CapabilityType = undefined,
    parent_caps: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]u16 = undefined,
    parent_instances: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]u64 = undefined,
    src_slots: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]u12 = undefined,

    /// Run the recorded links. Caller must hold NO process gen-lock. Every
    /// `derive` re-validates both processes' gens and bails on slots a
    /// racer touched in the deferral window, so a stale record is a
    /// silent no-op.
    pub fn run(self: *const DeferredDerives) void {
        var k: u8 = 0;
        while (k < self.count) : (k += 1) {
            _ = stygia.caps.derivation.deriveExpected(
                self.parent_doms[k],
                self.src_slots[k],
                self.parent_refs[k],
                self.parent_types[k],
                self.parent_caps[k],
                self.parent_instances[k],
                self.child_dom,
                @intCast(@as(u16, self.tstart) + k),
            );
        }
    }
};

pub const DeferredMoveClears = struct {
    count: u8 = 0,
    entries: [thread_mod.MAX_PAIR_ENTRIES_PER_THREAD]thread_mod.PairEntryStashed = undefined,

    pub fn record(self: *DeferredMoveClears, entry: thread_mod.PairEntryStashed) void {
        self.entries[self.count] = entry;
        self.count += 1;
    }

    pub fn run(self: *const DeferredMoveClears) void {
        var k: u8 = 0;
        while (k < self.count) : (k += 1) {
            const entry = self.entries[k];
            _ = stygia.caps.derivation.deleteAndDetachExpected(
                entry.source_process,
                entry.src_slot,
                entry.obj_ref,
                entry.obj_type,
                entry.source_caps,
                entry.source_instance,
            );
        }
    }
};

pub const RendezvousResult = union(enum) {
    no_receiver,
    delivered,
    parked,
};

fn deliverEvent(
    sender: *Thread,
    receiver: *Thread,
    dom: *Process,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
    pair_count: u8,
    port_xfer: bool,
    deferred: *DeferredDerives,
    moves: *DeferredMoveClears,
) i64 {
    // Spec §[reply]: minted reply handle inherits `xfer = 1` iff the
    // recv'ing port carried the `xfer` cap. Caller threads that bit
    // through from the recv-time port-handle resolution (it is NOT
    // derived from `pair_count`).
    const xfer_allowed = port_xfer;
    if (!canFitReplyAndAttachments(dom, pair_count)) {
        // Receiver's table is full — surface E_FULL into the receiver's
        // iret frame so the rendezvous wake path delivers it correctly.
        // The synchronous recv path (where caller == receiver) overwrites
        // rax via the syscall epilogue from the i64 return below; the
        // rendezvous path (sender resumes a parked receiver) has no such
        // epilogue and would otherwise leave rax = 0 from recv's pre-
        // suspend return. Spec §[recv] test 06.
        const target_ctx = receiver.iret_frame orelse receiver.ctx;
        arch.syscall.setSyscallReturn(target_ctx, @bitCast(errors.E_FULL));
        return errors.E_FULL;
    }

    // Spec §[handle_attachments]: when the sender stashed pair entries
    // at suspend time, install them now in `[tstart, tstart+N)` of the
    // receiver's process. The sender stash captured the source object's
    // ErasedSlabRef under the sender's process lock, so the gen baked
    // into each entry matches a live object as long as the object
    // hasn't been destroyed in the interim. We install via
    // `mintHandleAt` to bypass the at-most-one-per-(process, object)
    // coalescing (spec test 08 requires N fresh slots even when the
    // receiver already holds a handle to the same object).
    var tstart: u12 = 0;
    var reply_slot: u12 = 0;
    if (pair_count > 0) {
        tstart = process_mod.allocContiguousFreeSlots(dom, pair_count) catch {
            // Couldn't reserve a contiguous run — should have been
            // caught by the free_count pre-check, but the contiguous
            // requirement can fail even when there are enough total
            // free slots (fragmented table). Surface E_FULL.
            const target_ctx = receiver.iret_frame orelse receiver.ctx;
            arch.syscall.setSyscallReturn(target_ctx, @bitCast(errors.E_FULL));
            return errors.E_FULL;
        };
        // Spec §[ipc_rx] test 01: when a process receives an IPC handle
        // over IPC, the installed caps = granted ∩ receiver's ipc_rx.
        // ipc_rx lives in receiver self-handle field0 bits 32-39.
        const dom_ipc_rx: u16 = @truncate((dom.user_table[0].field0 >> 32) & 0xFF);
        var k: u8 = 0;
        while (k < pair_count) {
            const entry = sender.pending_pair_entries[k];
            const target_slot: u12 = @intCast(@as(u16, tstart) + k);
            // Spec §[ipc_rx] test 01: when receiving an IPC handle over
            // IPC, installed caps = granted ∩ receiver's ipc_rx.
            const installed_caps: u16 = if (entry.obj_type == .process)
                entry.caps & dom_ipc_rx
            else
                entry.caps;
            // Spec §[handle_attachments]: refcount-lifetime types
            // (page_frame, timer, port, device_region) must take an
            // object-side refcount on the new alias so a `delete` of
            // the source slot cannot destroy the object out from under
            // the receiver's freshly minted handle.
            acquireTransferredHandleRef(entry, installed_caps);
            process_mod.mintHandleAt(
                dom,
                target_slot,
                entry.obj_ref,
                entry.obj_type,
                installed_caps,
                0,
                0,
            );

            // Spec §[capabilities].revoke: hang the new alias in the
            // receiver's process under the source handle in its original
            // holder process so a future revoke on any ancestor of that
            // source reaches the alias.
            // RECORDED, not executed: `derive` takes `tree_mutex`, and
            // the receiver's process gen-lock is held here — running it
            // inline is the `process → tree_mutex` inversion that
            // deadlocked against the teardown tree walk. The caller
            // runs `deferred.run()` after this process lock drops (and, on
            // the rendezvous path, before the receiver is marked
            // ready, so the fresh slots cannot be raced by their
            // owner).
            deferred.child_dom = .{
                .ptr = dom,
                .gen = @intCast(dom._gen_lock.currentGen()),
            };
            deferred.tstart = tstart;
            deferred.parent_doms[deferred.count] = entry.source_process;
            deferred.parent_refs[deferred.count] = entry.obj_ref;
            deferred.parent_types[deferred.count] = entry.obj_type;
            deferred.parent_caps[deferred.count] = entry.source_caps;
            deferred.parent_instances[deferred.count] = entry.source_instance;
            deferred.src_slots[deferred.count] = entry.src_slot;
            deferred.count += 1;

            k += 1;
        }

        // Mint the reply handle before recording moved-source deletes.
        // In a same-process recv, deleting first returns the moved source
        // slot to the receiver's free list, letting the reply handle
        // reuse it and making the source look occupied immediately
        // after recv.
        reply_slot = mintReply(dom, sender, xfer_allowed) catch {
            const target_ctx = receiver.iret_frame orelse receiver.ctx;
            arch.syscall.setSyscallReturn(target_ctx, @bitCast(errors.E_FULL));
            return errors.E_FULL;
        };

        k = 0;
        while (k < pair_count) : (k += 1) {
            const entry = sender.pending_pair_entries[k];
            releasePendingPairEntryRef(entry, null);
            if (entry.move) moves.record(entry);
        }

        // Consume the stash — the move/copy completes here. Spec
        // §[handle_attachments] test 10 specifies that if the suspend
        // resumes with E_CLOSED before any recv, no entry is moved or
        // copied; clearing only on the recv-success path preserves
        // that contract.
        sender.pending_pair_count = 0;
    } else {
        reply_slot = mintReply(dom, sender, xfer_allowed) catch {
            const target_ctx = receiver.iret_frame orelse receiver.ctx;
            arch.syscall.setSyscallReturn(target_ctx, @bitCast(errors.E_FULL));
            return errors.E_FULL;
        };
    }

    // Compose §[event_state] syscall return word: pair_count, tstart,
    // reply_handle_id, event_type. tstart only meaningful when pair_count
    // > 0; the fast path leaves it 0 in the no-attachment case so this
    // mirror does the same.
    const ret_word: u64 =
        (@as(u64, pair_count) << PAIR_COUNT_SHIFT) |
        (@as(u64, tstart) << TSTART_SHIFT) |
        (@as(u64, reply_slot) << REPLY_HANDLE_SHIFT) |
        (@as(u64, @intFromEnum(event_type)) << EVENT_TYPE_SHIFT);
    if (event_type == .suspension) maybePrintReportDelivered(sender, receiver, reply_slot);

    // §[event_state] vregs 1..13 = the suspending thread's GPRs snapshotted
    // at `suspendOnPort` time, projected onto the receiver's matching
    // vregs here when the originating handle carried `read` (Spec
    // §[suspend] test 10). When `read` is clear the entire 13-vreg
    // window is delivered as zero. vreg 2 then carries the
    // event-type-specific sub-code on top of the GPR projection
    // (overlapping the snapshot's vreg 2 slot — the firing site's
    // sub-code wins for fault/vm_exit events; for `suspend(target,port)`
    // the spec leaves `subcode` 0 anyway, so the projection's sender
    // rbx/x1 surfaces unchanged).
    // Spec §[syscall_abi]: vreg 0 (`[rsp+0]`) carries the recv-success
    // syscall return word; vreg 1 (rax) holds an error code on failure
    // and is 0 on success. Stage `ret_word` in `pending_event_word` so
    // the receiver's resume path can flush it to user `[rsp+0]` while
    // running in the receiver's address space (only safe at iretq
    // time — both the sender-already-waiting path and the rendezvous
    // path can run with a different CR3 active here).
    const target_ctx = receiver.iret_frame orelse receiver.ctx;
    receiver.pending_event_word = ret_word;
    receiver.pending_event_word_valid = true;
    // The instruction pointer is an event-state lane too. A receiver
    // without the originating handle's read cap must not see it.
    receiver.pending_event_rip = if (sender.originating_read_cap) sender.event_rip else 0;
    receiver.pending_event_rip_valid = true;
    _ = event_addr;
    if (sender.originating_read_cap) {
        arch.syscall.setEventStateGprs(target_ctx, sender.event_state_gprs);
    } else {
        // §[suspend] test 10 / §[recv] tests 11/12: the snapshot is
        // delivered iff the originating thread handle had the `read` cap;
        // otherwise the GPR-backed event-state vregs are zeroed.
        arch.syscall.setEventStateGprs(target_ctx, [_]u64{0} ** 13);
    }
    // Spec §[error_codes]: vreg 1 (rax) is the syscall return register —
    // OK on success, error code on failure. setEventStateGprs above
    // wrote sender's rax into vreg 1, which clobbers the OK return on
    // the rendezvous-from-suspendOnPort path (the receiver was already
    // parked, so the recv-syscall epilogue's `r.rax = OK` is bypassed).
    // The recv-from-queued-sender path doesn't see the bug because its
    // post-deliverEvent `syscallDispatch` epilogue overwrites rax with
    // OK; this assignment makes the two delivery paths symmetric.
    // sender's rbx..r15 stay in vregs 2..13 per the §[event_state] GPR
    // projection.
    arch.syscall.setSyscallReturn(target_ctx, @bitCast(errors.OK));
    // Surface `subcode` in vreg 2 for events that carry an event-
    // specific sub-code (vm_exit). The firing-site sub-code overlays the
    // GPR projection's vreg 2 slot — §[create_vcpu] test 12 requires
    // the synthetic initial vm_exit to surface the initial-state
    // sentinel even though the sender's GPR snapshot is all zero.
    // For `suspension` the spec leaves `subcode` 0, so we leave the
    // snapshot's rbx (the suspending thread's value) untouched.
    switch (event_type) {
        .vm_exit => {
            arch.syscall.setEventSubcode(target_ctx, subcode);
        },
        else => {},
    }

    // Spec §[vm_exit_state]: project the vCPU's full guest state
    // (CR0/2/3/4, EFER, segs, GDTR/IDTR, MSRs, DRs) plus the exit
    // sub-code + 3-vreg payload into the receiver's vreg slots. Only
    // active for vCPUs whose VMM has supplied initial state
    // (post-first-reply); the pre-started synthetic-init exit
    // delivers only sub-code + zeroed GPRs (the existing minimal
    // projection above) so receivers that haven't reserved the full
    // §[vm_exit_state] stack window aren't stomped.
    if (event_type == .vm_exit and sender.vm != null and sender.originating_read_cap) {
        arch.vm.populateVmExitVregsIfStarted(receiver, sender, subcode);
    }

    // i64 return == OK on success. The composed `ret_word` is delivered
    // out-of-band via `pending_event_word` rather than through
    // syscallDispatch's `r.rax = ret` epilogue; the syscall-result
    // register-1 contract in §[error_codes] reserves vreg 1 for error
    // codes only.
    return errors.OK;
}

/// Sender-side rendezvous with a waiting receiver. Caller is the
/// suspended sender thread (state already set to `.suspended_on_port` by
/// the suspendOnPort path); we dequeue the highest-priority waiting
/// receiver, mint a reply handle in the receiver's process, write the
/// event-state syscall return into the receiver's iret frame, and
/// enqueue the receiver as ready.
///
/// Caller MUST hold `p._gen_lock`. On a successful match (`.delivered`
/// returned) the function RELEASES that Port lock before acquiring the
/// receiver's process lock — canonical kernel order is process → Port and Port
/// must be dropped before deliverEvent reaches mintReply. Callers must
/// therefore not also unlock `p` themselves on the success path.
/// Returns `.no_receiver` (with `p._gen_lock` still held) if no receiver was
/// eligible — the caller resumes the slow-path enqueue.
pub fn rendezvousWithReceiver(
    sender: *Thread,
    p: *Port,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
    port_irq_state: u64,
) RendezvousResult {
    var current_port_irq_state = port_irq_state;
    var temp_recv_ref = false;
    while (true) {
        const receiver = popHighestPriorityReceiver(p) orelse {
            if (temp_recv_ref) {
                p.waiters.enqueue(sender);
                p.waiter_kind = .senders;
                dropTempRecvRefLocked(p, current_port_irq_state);
                return .parked;
            }
            return .no_receiver;
        };
        if (!pinReceiver(receiver)) continue;
        const receiver_claim = lifecycle.beginWaitingClaim(receiver);
        if (receiver_claim == .none) {
            lifecycle.unpin(receiver);
            continue;
        }
        if (lifecycle.isDestroyMarked(receiver)) {
            if (receiver_claim == .pended) lifecycle.publishPendedPayload(receiver);
            lifecycle.unpin(receiver);
            continue;
        }
        receiver.event_type = .none;
        receiver.suspend_port = null;

        // Cancel any pending recv-with-timeout deadline before delivery.
        // Setting deadline to 0 also makes a stale-snapshot phase-2 expiry
        // skip this thread.
        if (receiver.recv_deadline_ns != 0) {
            receiver.recv_deadline_ns = 0;
            removeTimedRecvWaiter(receiver);
        }

        // Snapshot receiver's process ref under the port lock, then drop the
        // port lock before acquiring the process lock. The receiver is no
        // longer queued on the port; the short lifecycle pin above keeps
        // its slab slot live until delivery/failure publication finishes.
        // Holding port across the process acquisition would re-introduce the
        // AB-BA cycle that lockdep catches against the
        // `delete → releaseHandle` path.
        const receiver_dom_ref = receiver.process;
        if (!temp_recv_ref) {
            incRecvRef(p) catch unreachable;
            temp_recv_ref = true;
        }
        p._gen_lock.unlockIrqRestore(current_port_irq_state);

        const domlr = receiver_dom_ref.lockIrqSave(@src()) catch {
            const plr = p._gen_lock.lockIrqSave(@src());
            current_port_irq_state = plr;
            if (p.waiter_kind == .receivers) {
                publishFailedReceiverAndUnpin(receiver, receiver_claim, errors.E_CLOSED);
                continue;
            }
            p.waiters.enqueue(sender);
            p.waiter_kind = .senders;
            dropTempRecvRefLocked(p, current_port_irq_state);
            publishFailedReceiverAndUnpin(receiver, receiver_claim, errors.E_CLOSED);
            return .parked;
        };
        const dom = domlr.ptr;

        var deferred: DeferredDerives = .{};
        var moves: DeferredMoveClears = .{};
        const deliver_ret = deliverEvent(
            sender,
            receiver,
            dom,
            event_type,
            subcode,
            event_addr,
            sender.pending_pair_count,
            receiver.recv_port_xfer,
            &deferred,
            &moves,
        );
        // Drop the receiver-process lock BEFORE running the recorded derivation
        // links: `derive` takes `tree_mutex`, and holding a process gen-lock
        // across that acquire is the AB-BA against the teardown tree walk
        // (see `caps.derivation.tree_mutex`). Running the links BEFORE
        // `markReady` keeps the fresh slots unracable: the receiver — the
        // only legitimate user of the minted handles — cannot run until it
        // is enqueued below.
        receiver_dom_ref.unlockIrqRestore(domlr.irq_state);
        if (deliver_ret == errors.OK) {
            deferred.run();
            moves.run();
            const plr = p._gen_lock.lockIrqSave(@src());
            dropTempRecvRefLocked(p, plr);
            temp_recv_ref = false;
            publishReceiverAndUnpin(receiver, receiver_claim);
            return .delivered;
        }

        const plr = p._gen_lock.lockIrqSave(@src());
        current_port_irq_state = plr;
        if (p.waiter_kind == .receivers) {
            publishFailedReceiverAndUnpin(receiver, receiver_claim, deliver_ret);
            continue;
        }
        p.waiters.enqueue(sender);
        p.waiter_kind = .senders;
        dropTempRecvRefLocked(p, current_port_irq_state);
        publishFailedReceiverAndUnpin(receiver, receiver_claim, deliver_ret);
        return .parked;
    }
}

/// Mint a reply handle in `receiver_process`'s table pointing at the
/// suspended `sender` thread. Sets `sender.pending_reply_holder` back-pointer.
fn mintReply(receiver_process: *Process, sender: *Thread, xfer: bool) !u12 {
    const reply_caps: ReplyCaps = .{
        .move = true,
        .copy = false,
        .xfer = xfer,
    };

    const obj_ref: ErasedSlabRef = .{
        .ptr = sender,
        .gen = @intCast(sender._gen_lock.currentGen()),
    };
    const slot = try process_mod.mintHandle(
        receiver_process,
        obj_ref,
        .reply,
        @bitCast(reply_caps),
        0,
        0,
    );

    sender.pending_reply_holder = &receiver_process.kernel_table[slot];
    sender.pending_reply_process = SlabRef(Process).init(
        receiver_process,
        receiver_process._gen_lock.currentGen(),
    );
    sender.pending_reply_slot = slot;
    sender.wait.kind = .reply;
    return slot;
}

/// Resume the sender via the reply path, applying receiver's GPR
/// modifications (gated by originating thread handle's `write` cap).
/// Spec §[reply] tests 05/06 plus typed routing (test 08).
///
/// `snap` was captured by the caller BEFORE acquiring the sender's
/// `_gen_lock` so a fault on the receiver's SMAP-bracketed user-stack
/// reads can't strand the lock bit. Apply is pure memory writes.
///
/// `event_type` is the originating event_type captured at recv time —
/// the kernel projects the wide §[vm_exit_state] window onto the vCPU's
/// GuestState only when this is `.vm_exit`. Snap is `.{}` (zero) for
/// non-vm_exit replies, so `applyReplyStateToVcpu` becomes a no-op.
fn consumeReply(
    holder: *KernelHandle,
    receiver: *Thread,
    sender: *Thread,
    snap: *const arch.vm.ReplyVregSnapshot,
    event_type: EventType,
) void {
    _ = holder;
    // The write-cap snapshot was stamped onto `sender` at suspend time
    // (see `suspendOnPort`); any receiver-side modifications to the
    // event-state vregs commit to the sender's saved iret frame iff
    // that bit was set. The receiver's in-flight syscall frame holds
    // the post-recv, pre-reply GPR values per §[event_state] (vregs
    // 1..13 are 1:1 with hardware registers during handler execution),
    // so we copy from the receiver's current ctx into the sender's
    // saved frame.
    if (sender.originating_write_cap) {
        const sender_frame = sender.iret_frame orelse sender.ctx;
        const receiver_frame = receiver.iret_frame orelse receiver.ctx;
        arch.syscall.copyEventStateGprs(sender_frame, receiver_frame);
    }
    // Spec §[vm_exit_state] reply writeback only for vm_exit-typed
    // replies. Non-vm_exit reply paths (`suspension`)
    // never carry a vCPU sender, so `applyReplyStateToVcpu` would also
    // no-op via `archStateOf == null`, but skipping the call entirely
    // is the explicit type-driven gate.
    if (event_type == .vm_exit and sender.originating_write_cap) {
        arch.vm.applyReplyStateToVcpu(sender, snap);
    }
    thread_mod.resumeFromReply(sender, sender.originating_write_cap);
}

/// Resume the suspended sender with `E_ABANDONED` — the path invoked
/// when `delete` consumes a reply handle without resuming. Spec
/// §[capabilities] line 176: deleting a reply handle whose suspended
/// sender is still waiting resolves them with E_ABANDONED.
///
/// Caller has already verified the sender slab is live (via SlabRef
/// gen-lock) and holds `sender._gen_lock`. State must be
/// `.suspended_on_port` — a sender on the queue side or already woken
/// is not eligible.
pub fn resumeWithAbandoned(sender: *Thread) void {
    if (!lifecycle.isPortSuspended(sender) or sender.wait.kind != .reply) return;

    if (sender.iret_frame) |frame| {
        arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_ABANDONED));
    } else {
        arch.syscall.setSyscallReturn(sender.ctx, @bitCast(errors.E_ABANDONED));
    }
    thread_mod.resumeFromReply(sender, false);
}

/// On bind_refcount → 0 (or recv_refcount → 0 with blocked recvs in
/// flight): wake all blocked receivers with E_CLOSED.
fn propagateClosedToReceivers(p: *Port) void {
    if (p.waiter_kind != .receivers) return;
    while (p.waiters.dequeue()) |waiter| {
        const claim = lifecycle.beginWaitingClaimPinned(waiter);
        if (claim == .none) continue;
        if (waiter.iret_frame) |frame| {
            arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_CLOSED));
        } else {
            arch.syscall.setSyscallReturn(waiter.ctx, @bitCast(errors.E_CLOSED));
        }
        waiter.suspend_port = null;
        switch (claim) {
            .claimed => scheduler.enqueue(waiter),
            .pended => lifecycle.publishPendedPayload(waiter),
            .none => unreachable,
        }
        lifecycle.unpin(waiter);
    }
    p.waiter_kind = .none;
}

/// On recv_refcount → 0: detach suspended senders under the closing
/// port lock. Wake and pending-attachment release run after the lock
/// drops via `finalizeClosedSenders`.
fn detachClosedSenders(p: *Port, pending: *ThreadQueue) void {
    if (p.waiter_kind != .senders) return;
    while (p.waiters.dequeue()) |sender| {
        pending.enqueue(sender);
    }
    p.waiter_kind = .none;
}

pub fn finalizeClosedSenders(pending: *ThreadQueue) void {
    while (pending.dequeue()) |sender| {
        const claim = lifecycle.beginWaitingClaimPinned(sender);
        if (claim == .none) continue;
        if (sender.iret_frame) |frame| {
            arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_CLOSED));
        } else {
            arch.syscall.setSyscallReturn(sender.ctx, @bitCast(errors.E_CLOSED));
        }
        sender.suspend_port = null;
        sender.event_type = .none;
        sender.event_subcode = 0;
        sender.event_addr = 0;
        sender.originating_write_cap = false;
        // Spec §[handle_attachments] test 10: an E_CLOSED-resumed
        // sender's pre-validated stash is dropped without effect — no
        // entry is moved or copied. Drop the pending object refs and
        // clear the count so a subsequent recv on this thread doesn't
        // observe stale stash from this closed suspend.
        releasePendingPairEntries(sender);
        switch (claim) {
            .claimed => scheduler.enqueue(sender),
            .pended => lifecycle.publishPendedPayload(sender),
            .none => unreachable,
        }
        lifecycle.unpin(sender);
    }
}
