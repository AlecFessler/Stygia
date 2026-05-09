//! Port — rendezvous point between a calling EC and a receiving EC,
//! used for IDC, capability transfer, and EC event delivery.
//! See docs/kernel/specv3.md §[port].
//!
//! Lifecycle invariant: a port is alive iff
//!     recv_refcount > 0.
//! Slab teardown is gated solely on the recv side so the recv-cap holder
//! always has a chance to observe E_CLOSED before the underlying slot is
//! reclaimed. `bind_refcount` aggregates the contributors that fire
//! events on the port (handles with the `bind` cap, kernel-held
//! event_routes targeting the port, and vCPU `exit_port` pins);
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
//! returns E_CLOSED iff the port has no bind-cap holders, no
//! event_routes targeting it (both contribute to `bind_refcount`), and
//! no queued events.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const arch_syscall = zag.arch.dispatch.syscall;
const capability = zag.caps.capability;
const capability_domain = zag.caps.capability_domain;
const errors = zag.syscall.errors;
const execution_context = zag.sched.execution_context;
const kprof = zag.kprof.trace_id;
const scheduler = zag.sched.scheduler;

const CapabilityDomain = capability_domain.CapabilityDomain;
const EcCaps = execution_context.EcCaps;
const EcQueue = scheduler.EcQueue;
const ErasedSlabRef = capability.ErasedSlabRef;
const EventType = execution_context.EventType;
const ExecutionContext = execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = capability.KernelHandle;
const Refcount = zag.utils.refcount.Refcount;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Word0 = capability.Word0;

// ── Timed recv waiters ───────────────────────────────────────────────
//
// Parallel structure to sched.futex.timed_waiters: a fixed array of EC
// pointers blocked in `recv` with a non-zero timeout. The scheduler
// tick (arch.x64.irq.schedTimerHandler) drives `expireTimedRecvWaiters`
// which dequeues expired ECs from their port's receiver queue, sets
// their syscall return to E_TIMEOUT, and re-schedules them.
//
// 256 slots is more than the spec needs (one EC can hold at most one
// recv-with-timeout in flight; concurrent recv-with-timeout count is
// bounded by core count plus user-space concurrency).
pub const MAX_TIMED_RECV_WAITERS: usize = 256;
pub var timed_recv_waiters: [MAX_TIMED_RECV_WAITERS]?*ExecutionContext = blk: {
    var arr: [MAX_TIMED_RECV_WAITERS]?*ExecutionContext = undefined;
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
const RecvSnapshot = struct { ec: SlabRef(ExecutionContext), deadline: u64 };
var expire_recv_scratch: [scheduler.MAX_CORES][MAX_TIMED_RECV_WAITERS]RecvSnapshot = undefined;

fn addTimedRecvWaiter(ec: *ExecutionContext) bool {
    const irq = timed_recv_lock.lockIrqSave(@src());
    defer timed_recv_lock.unlockIrqRestore(irq);
    for (&timed_recv_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = ec;
            return true;
        }
    }
    return false;
}

/// Public wrapper around `removeTimedRecvWaiter` for `terminate` /
/// `destroyExecutionContextLocked` to drop a recv-timed slot that
/// would otherwise be revisited by the per-core timer tick after the
/// EC's gen has been bumped.
pub fn cancelRecvDeadline(ec: *ExecutionContext) void {
    removeTimedRecvWaiter(ec);
    ec.recv_deadline_ns = 0;
}

fn removeTimedRecvWaiter(ec: *ExecutionContext) void {
    const irq = timed_recv_lock.lockIrqSave(@src());
    defer timed_recv_lock.unlockIrqRestore(irq);
    for (&timed_recv_waiters) |*slot| {
        if (slot.* == ec) {
            slot.* = null;
            return;
        }
    }
}

/// Called from the scheduler tick to expire any recv-blocked ECs whose
/// `recv_deadline_ns` has passed. Spec §[port].recv test 14.
///
/// Phase 1 snapshots expired ECs under `timed_recv_lock`; Phase 2
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
            const ec = slot.* orelse continue;
            // Cross-core terminate may have rotated this EC's slab gen
            // to even (freed) and left a stale entry here — `terminate`
            // / `destroyExecutionContextLocked` don't reach into this
            // list. Drop dead entries before SlabRef.init's
            // `gen % 2 == 1` assertion fires from the per-core timer
            // tick.
            const gen = ec._gen_lock.currentGen();
            if (gen % 2 == 0) {
                slot.* = null;
                continue;
            }
            if (now_ns < ec.recv_deadline_ns) continue;
            // caller-pinned: `ec` is pinned by the `timed_recv_waiters`
            // slot we just dequeued; capturing its current gen here
            // gives the phase-2 walk a stale-detector if the slot is
            // freed and reallocated between phases. The deadline
            // re-check below still catches the wake/re-wait race.
            expired[expired_count] = .{
                .ec = SlabRef(ExecutionContext).init(ec, gen),
                .deadline = ec.recv_deadline_ns,
            };
            expired_count += 1;
            slot.* = null;
        }
    }

    for (expired[0..expired_count]) |entry| {
        // caller-pinned: `entry.ec` was captured under timed_recv_lock
        // above and the EC's slot can only be freed after this phase
        // unwinds the recv-waiter from its port queue. The deadline
        // check below catches a sender-wake / fresh-recv race.
        const ec = entry.ec.ptr;
        // Re-check deadline. If a sender wake ran between phases the
        // deadline is now 0; if the EC was woken and made a fresh recv
        // it'd be a different value. Either way this snapshot is stale.
        if (ec.recv_deadline_ns != entry.deadline) continue;

        const port_ref = ec.suspend_port orelse continue;
        const p = port_ref.lock(@src()) catch continue;

        // Remove from the port's receiver queue if still present.
        // (`waiters.remove` is a no-op if the EC was already dequeued
        // by a sender on a different core.)
        const removed = p.waiters.remove(ec);
        if (removed and p.waiters.isEmpty()) p.waiter_kind = .none;
        port_ref.unlock();

        if (!removed) continue;

        // EC has been removed from the wait queue; safe to wake.
        while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        ec.recv_deadline_ns = 0;
        ec.suspend_port = null;
        ec.event_type = .none;
        // Stash E_TIMEOUT in the syscall return slot. The scheduler's
        // resume path restores the syscall-return register on iretq.
        arch_syscall.setSyscallReturn(ec.ctx, @bitCast(@as(i64, errors.E_TIMEOUT)));
        ec.state = .ready;
        scheduler.markReady(ec);
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

/// Names which side currently owns `Port.waiters`. A port can never
/// hold both senders and receivers at once: if a sender arrives with
/// receivers queued (or vice versa), the matching pair is consumed
/// before the queue settles. The dequeuer that empties the queue is
/// responsible for resetting this back to `.none`.
pub const WaiterKind = enum {
    /// Queue empty.
    none,
    /// Suspended ECs waiting to be picked up by a `recv`.
    senders,
    /// ECs blocked in `recv` waiting for an event.
    receivers,
};

pub const Port = struct {
    /// Slab generation lock. Validates `SlabRef(Port)` liveness AND
    /// guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Bind-side reference count. Aggregates everything that can fire
    /// an event on this port spontaneously:
    ///   - handles with the `bind` cap (one per handle),
    ///   - kernel-held event routes targeting this port (one per route),
    ///   - vCPU ECs whose `exit_port` references this port (one per vCPU).
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

    /// Head of the singly-linked list of vCPU ECs whose `exit_port`
    /// references this port. Each vCPU contributes one to
    /// `bind_refcount`; the cascade walk on `recv_refcount → 0`
    /// terminates each bound vCPU before the slab is freed. Mutated
    /// under `_gen_lock` only.
    /// caller-pinned: every EC on this chain holds a `bind_refcount`
    /// reference on `self`, and exactly mirrors the same pin running
    /// the EC's slab slot — list membership keeps both ends alive.
    vcpu_list_head: ?*ExecutionContext = null,

    /// Wait queue, holding either suspended senders OR blocked receivers
    /// — never both. `waiter_kind` names which.
    waiters: EcQueue = .{},

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
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
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

// ── External API ─────────────────────────────────────────────────────

/// `create_port` syscall handler. Spec §[port].create_port.
///
/// Caller-side cap-ceiling and `crpt` checks are done in syscall/port.zig
/// before reaching here; this layer mints the slab and the handle.
pub fn createPort(caller: *ExecutionContext, caps: u64) i64 {
    const port_caps: PortCaps = @bitCast(@as(u16, @truncate(caps)));

    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);

    if (cd.free_count == 0) return errors.E_FULL;

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
    const slot = capability_domain.mintHandle(
        cd,
        obj_ref,
        .port,
        port_caps_word,
        0,
        0,
    ) catch {
        // mintHandle failed after onHandleAcquire bumped the refcounts.
        // Roll back via onHandleRelease + finalize the cascade snapshot.
        // The caller (createPort) holds the CD lock but no port lock;
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
/// the caller's EC ends up either suspended on `port` (if no receiver
/// waiting) or still running with the receiver dequeued and event state
/// delivered. State produced here MUST match what the fast path produces
/// so the two are interchangeable.
pub fn suspendEc(caller: *ExecutionContext, target: u64, port: u64) i64 {
    kprof.enter(.suspend_ec);
    defer kprof.exit(.suspend_ec);
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const cd_irq_state = lr.irq_state;

    const target_slot: u12 = @truncate(target);
    const port_slot: u12 = @truncate(port);

    const target_entry = capability.resolveHandleOnDomain(cd, target_slot, .execution_context) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[target_slot].word0));
    if (!ec_caps.susp) {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_PERM;
    }

    const target_ref = capability.typedRef(ExecutionContext, target_entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    const port_ref = capability.typedRef(Port, port_entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    cd_ref.unlockIrqRestore(cd_irq_state);

    const tlr = target_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const target_ec = tlr.ptr;
    const target_irq_state = tlr.irq_state;
    if (target_ec.vm != null) {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_INVAL;
    }
    if (target_ec.state != .running and target_ec.state != .ready and target_ec.state != .idle_wait) {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_INVAL;
    }
    // Spec §[handle_attachments]: when the caller is suspending a
    // different EC, the pair entries were validated against the
    // caller's domain in `validatePairEntries` and stashed on the
    // caller's EC. The actual move/copy at recv time runs against
    // the suspended EC (which is what `deliverEvent` sees), so we
    // hand the stash off to the target before the suspension is
    // committed. A self-suspend leaves the stash where it already
    // lives.
    if (target_ec != caller and caller.pending_pair_count > 0) {
        target_ec.pending_pair_count = caller.pending_pair_count;
        var k: usize = 0;
        while (k < caller.pending_pair_count) {
            target_ec.pending_pair_entries[k] = caller.pending_pair_entries[k];
            k += 1;
        }
        caller.pending_pair_count = 0;
    }

    target_ref.unlockIrqRestore(target_irq_state);

    const plr = port_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const p = plr.ptr;
    // Re-validate target state under the port lock. Between the pre-port
    // EC validation above and here, a concurrent `terminate` or
    // `suspend(target=target_ec, ...)` from another core could have flipped
    // the state to `.exited` or `.suspended_on_port`; without this check
    // `suspendOnPort` trips the `assert(state ∈ {.running,.ready,.idle_wait})`
    // at execution_context.zig:1339 and panics the kernel.
    //
    // Re-locking the EC's gen-lock here would invert the (Port → EC) order
    // — the canonical kernel-wide order is EC → Port, established by
    // bindEventRoute. Read the state without the EC lock: a torn read of
    // the small enum is impossible (single-byte) and any post-check change
    // is harmless: the suspend completes against a target that has just
    // become `.exited` (the EC slab and kstack stay pinned by domain
    // ownership; the target was already going to be unrunnable).
    if (target_ec.state != .running and target_ec.state != .ready and target_ec.state != .idle_wait) {
        port_ref.unlockIrqRestore(plr.irq_state);
        return errors.E_INVAL;
    }
    // `suspendOnPort` releases the port lock before returning (directly
    // on the no-receiver path, transitively via `rendezvousWithReceiver`
    // on the success path) so we MUST NOT add `defer port_ref.unlockIrqRestore(...)`.

    // Snapshot the originating EC handle's `write` and `read` caps so
    // reply-time can decide whether receiver mutations apply (Spec
    // §[reply] tests 05/06) and so recv-time gates the suspended EC's
    // §[event_state] vregs 1..13 exposure (Spec §[suspend] test 10).
    // The caps were captured into `ec_caps` above under the domain lock.
    return execution_context.suspendOnPort(target_ec, p, .suspension, 0, 0, ec_caps.write, ec_caps.read, plr.irq_state);
}

/// `recv` syscall handler. Spec §[port].recv.
///
/// Slow path: if a sender is queued, pair off, mint a reply handle in
/// the caller's domain, deliver event state via vregs, and return. If no
/// sender is queued and the port has bind holders or routes, the caller
/// suspends as a receiver; otherwise returns E_CLOSED.
///
/// Lock order: caller's CD `_gen_lock` is acquired first, held for the
/// duration of the Port lock acquisition + port-side work, and only
/// dropped after `deliverEvent` finishes (which needs CD held to mint
/// the reply slot). The Port lock is released before `deliverEvent` runs
/// so the canonical CD → Port order is never inverted — see the lock-
/// order note on `deliverEvent`.
pub fn recv(caller: *ExecutionContext, port: u64, timeout_ns: u64) i64 {
    kprof.enter(.recv);
    defer kprof.exit(.recv);
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);

    const port_slot: u12 = @truncate(port);
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse
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
        const need: u32 = 1 + @as(u32, sender.pending_pair_count);
        if (cd.free_count < need) {
            // Re-enqueue: the sender was popped from the head; push
            // it back so a future recv can match it.
            p.waiters.enqueue(sender);
            p.waiter_kind = .senders;
            port_ref.unlockIrqRestore(port_irq_state);
            return errors.E_FULL;
        }
        // Drop the Port lock before deliverEvent — it needs receiver-CD
        // (the caller's CD, already held by us). Holding both would
        // re-introduce the Port → CD inversion.
        const evt_type = sender.event_type;
        const evt_sub = sender.event_subcode;
        const evt_addr = sender.event_addr;
        const pair_count = sender.pending_pair_count;
        // Spec §[reply]: the minted reply handle inherits `xfer = 1`
        // iff the recv'ing port carried the `xfer` cap. Snapshot the
        // recv'ing port's xfer cap from the caller's table while the
        // CD lock is still held; deliverEvent uses it to set the
        // minted reply handle's caps below.
        const port_caps_word: u16 = @truncate(Word0.caps(cd.user_table[port_slot].word0));
        const port_caps_typed: PortCaps = @bitCast(port_caps_word);
        const port_xfer = port_caps_typed.xfer;
        port_ref.unlockIrqRestore(port_irq_state);
        return deliverEvent(sender, caller, cd, evt_type, evt_sub, evt_addr, pair_count, port_xfer);
    }

    // No sender ready. Spec §[recv] test 04: if the port has no
    // bind-cap holders, no event_routes targeting it, and no queued
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
    if (cd.free_count == 0) {
        port_ref.unlockIrqRestore(port_irq_state);
        return errors.E_FULL;
    }

    // suspend_port MUST be set before adding the caller to the port's
    // waiter queue. A cross-core `terminate(caller)` reads suspend_port
    // without holding the port lock to decide whether to run the port-
    // queue cleanup arm; if it observed null while the caller was
    // already enqueued here, it would skip cleanup, bump-and-free the
    // EC, and leave a stale `*EC` in the port's waiter queue. The next
    // `popHighest*` walk would then return that pointer (gen now odd
    // again from reallocation, state=.ready from the new owner) as a
    // phantom receiver.
    caller.suspend_port = SlabRef(Port).init(p, p._gen_lock.currentGen());
    caller.event_type = .none;
    enqueueReceiver(p, caller);
    // Spec §[reply]: cache the recv'ing port's xfer cap so the
    // rendezvous-with-receiver wake path can mint the reply handle
    // with `xfer` derived from the recv'ing handle, not from
    // pair_count.
    {
        const port_caps_word: u16 = @truncate(Word0.caps(cd.user_table[port_slot].word0));
        const port_caps_typed: PortCaps = @bitCast(port_caps_word);
        caller.recv_port_xfer = port_caps_typed.xfer;
    }
    caller.state = .suspended_on_port;
    caller.pending_reply_holder = null;
    caller.pending_reply_domain = null;
    caller.pending_reply_slot = 0;
    caller.on_cpu.store(false, .release);

    // Timed recv — register before dropping the port lock so the wakeup
    // path can find us. Spec §[port].recv test 14.
    if (timeout_ns != 0) {
        const now_ns = arch.time.getMonotonicClock().now();
        caller.recv_deadline_ns = now_ns + timeout_ns;
        _ = addTimedRecvWaiter(caller);
    }

    port_ref.unlockIrqRestore(port_irq_state);

    const core_id: u8 = @truncate(arch.smp.coreID());
    if (scheduler.coreCurrentIs(core_id, caller)) {
        scheduler.clearCurrentEc(core_id);
    }
    return 0;
}

/// Reply-FP atomic-recv-park senders bail. Called from the reply fast
/// path's asm when, having committed the reply portion (R6/R9/R10),
/// the recv portion's port_lock acquire reveals
/// `waiter_kind == .senders` — meaning a peer EC arrived on the
/// recv_port BEFORE the caller's atomic-recv reached this point. The
/// asm cannot enqueue the caller as a receiver (would clobber
/// waiter_kind and strand the sender), so it releases port_lock +
/// caller_gen_lock and routes here to perform the slow-path equivalent
/// of `port.recv` against the now-unlocked port. Slow-path recv sees
/// `.senders`, pops the highest-priority sender, calls `deliverEvent`
/// (mints reply handle, stages event_state in
/// `caller.pending_event_word`), and returns; we then transition the
/// caller from `.running` to `.ready` and enqueue it on this core's
/// run queue so the asm's R14 swap to the original replyee can proceed
/// while the caller awaits dispatch with the event ready to deliver.
///
/// The asm has already cleared the reply slot (R6) and resumed the
/// replyee (R9/R10 sender state writes), so a true bail to the
/// reply-syscall slow path is impossible — that path would re-resolve
/// the now-cleared reply handle and return E_BADCAP. The
/// reply-half-already-committed shape is what makes this helper
/// necessary in the first place.
pub export fn replyAtomicRecvSendersFallback(
    caller: *ExecutionContext,
    recv_port_handle: u64,
) callconv(.c) void {
    // Slow-path recv. Re-acquires the receiver CD lock and the port
    // gen-lock, observes `.senders` under lock, runs the rendezvous
    // path. Return value is the §[event_state] word for the rendezvous
    // case or `0` for the (race-window: senders drained between asm
    // observation and here) park case. Either way the data is staged
    // through `pending_event_word` / port wait queue; we don't need
    // the return value here.
    _ = recv(caller, recv_port_handle, 0);

    // After recv:
    //   - Rendezvous case: `caller.state == .running` (deliverEvent
    //     doesn't transition state — it expects the syscall epilogue
    //     to handle the post-syscall flow). We need to enqueue the
    //     caller as `.ready` so the next dispatch picks it up; the
    //     asm's R14 swap to the original replyee dispatches a
    //     different EC on this core, leaving the caller in the run
    //     queue with `pending_event_word` ready to flush at iretq.
    //   - Park case: `caller.state == .suspended_on_port` (recv
    //     parked it on the port wait queue). Nothing more to do.
    if (caller.state == .running) {
        caller.state = .ready;
        const calling_core: u8 = @truncate(arch.smp.coreID());
        scheduler.enqueueOnCore(calling_core, caller);
    }
}

/// `reply` syscall handler. Spec §[reply].reply.
pub fn reply(caller: *ExecutionContext, reply_handle: u64) i64 {
    kprof.enter(.reply);
    defer kprof.exit(.reply);
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const cd_irq_state = lr.irq_state;

    const slot: u12 = @truncate(reply_handle);
    const entry = capability.resolveHandleOnDomain(cd, slot, .reply) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const sender_ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    // Snapshot the caps on the reply handle and clear the slot under
    // the domain lock so a concurrent delete cannot race the resume.
    const reply_caps: ReplyCaps = @bitCast(Word0.caps(cd.user_table[slot].word0));

    capability.clearAndFreeSlot(cd, slot, entry);

    cd_ref.unlockIrqRestore(cd_irq_state);

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
    // EC._gen_lock held; masking IRQs across the held window prevents
    // the timer ISR's scheduler dispatch from registering an EC→CD
    // edge that would invert the destroy-side CD→EC ordering. Spec
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
/// `move` flag, and the source slot id in the caller's domain.
///
/// Order:
///   1. Resolve the reply handle in caller's domain (no clear yet —
///      test 11 demands the caller's table is unchanged on E_FULL).
///      Pull the suspended sender out of the entry's typed ref and
///      surface E_TERM if the sender slab generation moved (test 10).
///   2. Lock the resumed sender's domain (== `sender.domain`) and
///      reserve N contiguous slots via `allocContiguousFreeSlots`. On
///      failure, drop locks and return E_FULL with the reply handle
///      still in the caller's table and the stash untouched (test 11).
///   3. With contiguous slots reserved, install each pair entry via
///      `mintHandleAt` at `[tstart, tstart+N)` in the sender's domain.
///   4. Drop the sender's CD lock; re-acquire the caller's CD lock to
///      clear `move == 1` source slots and free the reply slot. The
///      reply handle is consumed last so test 11's "[1] is NOT
///      consumed on E_FULL" stays observably true above.
///   5. Stage the §[event_state] return word (`pair_count`, `tstart`)
///      on the resumed sender's `pending_event_word` so the iretq
///      flush writes it to `[user_rsp + 0]` while CR3 is the sender's.
///   6. Apply receiver-side GPR mods (gated by sender's
///      `originating_write_cap`, mirroring `consumeReply`) and resume
///      the sender via `resumeFromReply`.
pub fn replyTransfer(caller: *ExecutionContext, reply_handle: u64, n: u8) i64 {
    const caller_cd_ref = caller.domain;
    const slot: u12 = @truncate(reply_handle);

    // Phase 1 — caller's CD: resolve the reply handle, capture the
    // sender's typed ref, snapshot reply caps. Drop the CD lock before
    // taking the sender's EC lock to honor the canonical CD-at-a-time
    // discipline observed by `terminate` (which holds CD across an EC
    // lock and so registers the order CD → EC with lockdep). Holding
    // CD across an EC acquire here would otherwise invert that.
    const lr_phase1 = caller_cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd_phase1 = lr_phase1.ptr;
    const entry = capability.resolveHandleOnDomain(cd_phase1, slot, .reply) orelse {
        caller_cd_ref.unlockIrqRestore(lr_phase1.irq_state);
        return errors.E_BADCAP;
    };
    const sender_ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        caller_cd_ref.unlockIrqRestore(lr_phase1.irq_state);
        return errors.E_BADCAP;
    };
    // Spec §[terminate] test 07: a reply handle whose suspended sender
    // was destroyed via terminate carries the `abandoned` bit.
    const reply_caps: ReplyCaps = @bitCast(Word0.caps(cd_phase1.user_table[slot].word0));
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
        const cd_clear_lr = caller_cd_ref.lockIrqSave(@src()) catch return errors.E_TERM;
        const cd_clear = cd_clear_lr.ptr;
        if (capability.resolveHandleOnDomain(cd_clear, slot, .reply)) |e| {
            capability.clearAndFreeSlot(cd_clear, slot, e);
        }
        caller_cd_ref.unlockIrqRestore(cd_clear_lr.irq_state);
        caller.pending_pair_count = 0;
        return errors.E_TERM;
    }

    // Phase 2 — sender liveness probe. Take the sender's EC lock just
    // long enough to validate the slab gen and capture the sender's
    // domain ref. The lock is dropped before the sender's CD is
    // acquired — sender_cd_ref.lock validates that ref's own gen so
    // the sender domain pointer doesn't dangle even with the EC lock
    // released. Holding the EC lock here while taking the CD lock
    // would invert the kernel-wide CD → EC order.
    const sender_lr = sender_ref.lockIrqSave(@src()) catch {
        const cd_clear_lr = caller_cd_ref.lockIrqSave(@src()) catch return errors.E_TERM;
        const cd_clear = cd_clear_lr.ptr;
        if (capability.resolveHandleOnDomain(cd_clear, slot, .reply)) |e| {
            capability.clearAndFreeSlot(cd_clear, slot, e);
        }
        caller_cd_ref.unlockIrqRestore(cd_clear_lr.irq_state);
        caller.pending_pair_count = 0;
        return errors.E_TERM;
    };
    const sender = sender_lr.ptr;
    const sender_cd_ref = sender.domain;
    // Spec §[reply] typed routing — pick up the originating event_type
    // while we hold the sender lock so reply-side state writeback below
    // can branch on it without re-locking.
    const sender_event_type = sender.event_type;
    sender_ref.unlockIrqRestore(sender_lr.irq_state);

    // Phase 3 — sender's CD: reserve N contiguous slots and install
    // each pair entry. CD-at-a-time: caller's CD is unlocked here, no
    // other lock is held.
    const sender_cd_lr = sender_cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const sender_cd = sender_cd_lr.ptr;
    const tstart = capability_domain.allocContiguousFreeSlots(sender_cd, n) catch {
        // Test 11: [1] is NOT consumed and the caller's table is
        // unchanged on E_FULL.
        sender_cd_ref.unlockIrqRestore(sender_cd_lr.irq_state);
        caller.pending_pair_count = 0;
        return errors.E_FULL;
    };

    // Spec §[idc_rx] test 01: IDC handles delivered to the sender's
    // domain get caps ∩ sender_cd.idc_rx (self-handle field0 bits 32-39).
    const sender_idc_rx: u16 = @truncate((sender_cd.user_table[0].field0 >> 32) & 0xFF);
    var k: u8 = 0;
    while (k < n) : (k += 1) {
        const stash = caller.pending_pair_entries[k];
        const target_slot: u12 = @intCast(@as(u16, tstart) + k);
        const installed_caps: u16 = if (stash.obj_type == .capability_domain)
            stash.caps & sender_idc_rx
        else
            stash.caps;
        capability_domain.mintHandleAt(
            sender_cd,
            target_slot,
            stash.obj_ref,
            stash.obj_type,
            installed_caps,
            0,
            0,
        );

        // Spec §[capabilities].revoke: hang the new alias in the
        // sender's domain under the source handle in the caller's
        // (replier's) domain. The sender's CD lock is held; pass it
        // as `held_dom` so `derive` doesn't re-acquire and deadlock.
        const caller_dom_ref: capability.ErasedSlabRef = @bitCast(caller.domain);
        const sender_dom_ref_for_derive: capability.ErasedSlabRef = .{
            .ptr = sender_cd,
            .gen = @intCast(sender_cd._gen_lock.currentGen()),
        };
        _ = zag.caps.derivation.derive(
            caller_dom_ref,
            stash.src_slot,
            sender_dom_ref_for_derive,
            target_slot,
            sender_cd,
        );
    }
    sender_cd_ref.unlockIrqRestore(sender_cd_lr.irq_state);

    // §[reply_transfer] test 14 vreg-14 (RIP) reload: harvest the
    // SMAP-bracketed user-stack read NOW, before any sender lock, so a
    // page fault on the user page can abort cleanly without leaking the
    // sender's `_gen_lock` bit. The receiver (`caller`) is the running
    // EC on this core, so CR3 already references its address space.
    const receiver_frame = caller.iret_frame orelse caller.ctx;
    const new_rip = arch.syscall.readUserVreg14(receiver_frame);

    // Phase 4 — caller's CD: clear `move = 1` source slots and consume
    // the reply slot. Same single-CD-at-a-time pattern.
    const cd_phase4_lr = caller_cd_ref.lockIrqSave(@src()) catch {
        // Caller's CD is gone mid-transfer. The sender-side install
        // already committed; resume the sender so the test EC's death
        // doesn't strand a parked sender forever.
        caller.pending_pair_count = 0;
        const sender2_lr = sender_ref.lockIrqSave(@src()) catch return errors.OK;
        const sender2 = sender2_lr.ptr;
        defer sender_ref.unlockIrqRestore(sender2_lr.irq_state);
        deliverReplyTransferResume(caller, sender2, n, tstart, new_rip, sender_event_type);
        return errors.OK;
    };
    const cd_phase4 = cd_phase4_lr.ptr;
    k = 0;
    while (k < n) : (k += 1) {
        const stash = caller.pending_pair_entries[k];
        if (!stash.move) continue;
        const src_slot = stash.src_slot;
        if (capability.resolveHandleOnDomain(cd_phase4, src_slot, null)) |src_entry| {
            capability.clearAndFreeSlot(cd_phase4, src_slot, src_entry);
        }
    }
    if (capability.resolveHandleOnDomain(cd_phase4, slot, .reply)) |reply_entry| {
        capability.clearAndFreeSlot(cd_phase4, slot, reply_entry);
    }
    caller_cd_ref.unlockIrqRestore(cd_phase4_lr.irq_state);

    caller.pending_pair_count = 0;

    // Phase 5 — sender's EC: stage the §[event_state] return word and
    // resume. Re-lock the sender; if the slab gen has moved between
    // phases the sender was reaped concurrently, in which case the
    // installed handles in the sender's CD become orphans (they share
    // the domain's lifetime, so they'll be reclaimed when the domain
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
    caller: *ExecutionContext,
    sender: *ExecutionContext,
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
    // sender is a vCPU EC that resumes via guest entry, not via a
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
    execution_context.resumeFromReply(sender, sender.originating_write_cap);
}

/// Install `port` as `ec.event_routes[slot_idx]`, replacing any prior
/// binding. Caller has already locked `ec` and `port` and validated caps.
/// Bumps `port.bind_refcount` (routes contribute to bind-side
/// liveness) and decrements the prior port's bind_refcount (if any)
/// under their respective `_gen_lock`s. The new port's increment runs
/// BEFORE the prior port's decrement so the rebind is observably
/// monotonic to event firing.
pub fn installEventRoute(ec: *ExecutionContext, port: *Port, slot_idx: u8) i64 {
    // Inc on the new port first so a route-only-refcount window where
    // the destination flips between (decremented prior, not-yet-inc'd
    // new) cannot drive the new port's bind_refcount through 0 and
    // close it before the bind even publishes. Caller already resolved
    // `port` via SlabRef.lock so observed_zero would mean concurrent
    // close-via-bind-drop is in flight; surface E_BADCAP.
    incBindRef(port) catch return errors.E_BADCAP;
    if (ec.event_routes[slot_idx]) |prior_ref| {
        // Caller already holds `port._gen_lock` and `ec._gen_lock`. The
        // prior port is a different slab slot; reach in to dec its route
        // count without re-acquiring `port`'s lock. Tag the acquisition
        // with `PORT_REROUTE_GROUP` so lockdep doesn't fire same-class
        // overlap on the second `Port._gen_lock` — the caller is the
        // sole writer of `ec.event_routes[slot_idx]` (it holds `ec`'s
        // gen-lock) and never inverts the (new_port → prior_port)
        // acquire order, so same-class detection here is a false
        // positive.
        if (prior_ref.lockOrderedIrqSave(PORT_REROUTE_GROUP, @src())) |prior_lr| {
            decBindRef(prior_lr.ptr);
            prior_ref.unlockIrqRestore(prior_lr.irq_state);
        } else |_| {}
    }
    ec.event_routes[slot_idx] = SlabRef(Port).init(port, port._gen_lock.currentGen());
    return 0;
}

/// `Port._gen_lock` ordered_group used by `installEventRoute` when it
/// acquires a *prior* route's port lock while already holding the
/// *new* route's port lock. The caller (bind_event_route) is the
/// sole writer of `ec.event_routes[slot_idx]` and never inverts the
/// (new_port → prior_port) acquire order, so the same-class lockdep
/// panic on the second `Port._gen_lock` is a false positive. Caller
/// discipline: the ordered acquire is always made *while holding*
/// `port._gen_lock` for the new route, never standalone.
const PORT_REROUTE_GROUP: u32 = 0x504F; // "PO"

/// Remove the binding at `ec.event_routes[slot_idx]`. Caller has already
/// locked `ec` and validated `unbind` cap and that the slot is non-null.
/// Decrements the bound port's `bind_refcount` under its `_gen_lock`,
/// triggering `propagateClosedToReceivers` if the port now has no
/// remaining bind-side holders.
pub fn removeEventRoute(ec: *ExecutionContext, slot_idx: u8) i64 {
    const prior_ref = ec.event_routes[slot_idx] orelse return errors.E_NOENT;
    const prior_lr = prior_ref.lockIrqSave(@src()) catch {
        ec.event_routes[slot_idx] = null;
        return 0;
    };
    decBindRef(prior_lr.ptr);
    prior_ref.unlockIrqRestore(prior_lr.irq_state);
    ec.event_routes[slot_idx] = null;
    return 0;
}

// ── Kernel-internal event firing (called from arch fault/PMU paths) ──

/// Common dispatch for `fire*`. Looks up `ec.event_routes[event_type]`;
/// if bound, suspends `ec` on the port. Returns true iff the suspend was
/// performed; false leaves the caller to apply the no-route fallback.
fn fireRouted(
    ec: *ExecutionContext,
    event: EventType,
    subcode: u8,
    addr: u64,
) bool {
    const slot_idx = execution_context.eventRouteSlot(event) orelse return false;
    // Snapshot `ec.event_routes[slot_idx]` under `ec._gen_lock` — the
    // optional `SlabRef(Port)` is two words (ptr + gen) and an in-flight
    // `installEventRoute`/`removeEventRoute` writer (see lines 967/989)
    // can be torn-read by this fault-context observer otherwise. Match
    // the wake/install pattern that uses `ec._gen_lock` as the route-
    // table mutator's exclusion. Note: this fault path runs on the
    // EC's own core, but cross-core rebind is allowed and is the race
    // we're plugging.
    const ec_irq = ec._gen_lock.lockIrqSave(@src());
    const route_ref_opt = ec.event_routes[slot_idx];
    ec._gen_lock.unlockIrqRestore(ec_irq);
    const route_ref = route_ref_opt orelse return false;
    const route_lr = route_ref.lockIrqSave(@src()) catch return false;
    const port_ptr = route_lr.ptr;
    // `suspendOnPort` is responsible for releasing `port_ptr._gen_lock`
    // (it must drop Port before any receiver-CD acquisition to honor the
    // canonical CD → Port order). We must NOT also `defer route_ref.unlockIrqRestore(...)`.

    // A route whose port has lost every bind-cap holder AND has no other
    // routes pointing at it survives only on the route's own increment.
    // Receivers are still allowed to dequeue from such a port, so honor
    // the route here — the EC will sit suspended until either a recv
    // arrives or the route itself is cleared.
    // The originating EC handle here is the one that called
    // `bind_event_route` (Spec §[reply] originating-handle table). Its
    // write-cap snapshot is not yet plumbed through to this path; until
    // event_route bookkeeping records that snapshot at bind time the
    // safe default is to discard receiver mutations on reply (§[reply]
    // test 06's no-write-cap branch). The fault-firing site has read
    // access to the EC's full saved frame so default `read=true` —
    // §[suspend] test 10 only zeroes the payload when the originating
    // handle explicitly lacks `read`, which the bind_event_route path
    // would record once plumbed through.
    _ = execution_context.suspendOnPort(ec, port_ptr, event, subcode, addr, false, true, route_lr.irq_state);
    return true;
}

/// Fire a memory_fault event for `ec`. Looks up `ec.event_routes[0]`;
/// if bound, suspends `ec` on the port; else applies the no-route
/// fallback per Spec §[event_route]:3247: "the EC's capability domain
/// is restarted if its self-handle has the `restart` cap (per
/// §[restart_semantics]); otherwise the capability domain is destroyed".
///
/// Restart engine is not yet wired in this kernel. We honor the
/// destroy arm here: drive the standard SLOT_SELF tear-down via
/// `releaseSelf` (parks the calling EC, then runs phase1 + phase2 of
/// `destroyCapabilityDomain`). Without this — when this path used to
/// just `parkSelfFaulted` — a faulting child stayed parked but its
/// domain leaked, and any peer EC in the same domain kept running
/// over a half-broken address space until the test runner timed out.
///
/// Lock discipline: `releaseSelf` acquires the CD `_gen_lock`. The
/// in-tree fault paths reach this fallback with the CD lock already
/// dropped (see fault.zig: the user-fault arm `defer`s the unlock
/// before `fireMemoryFault`; the catch arm runs without taking the
/// lock at all). `tree_mutex` is also untaken on these paths. If a
/// future caller arrives with the CD lock held, `lockIrqSave` would
/// dead-spin — hence the explicit lock-state contract documented on
/// each call site under fault.zig / arch/*/exceptions.zig.
pub fn fireMemoryFault(ec: *ExecutionContext, subcode: u8, fault_addr: u64) void {
    if (fireRouted(ec, .memory_fault, subcode, fault_addr)) return;

    // No-route destroy. Park the EC first so it leaves the dispatch
    // queue, then run the standard CD self-destruct via `releaseSelf`.
    // `releaseSelf` calls `parkSelfFaulted` internally as well, but
    // only on `currentEc()` — guard for the rare path that fires
    // memory_fault on an EC that isn't this core's current_ec (e.g.
    // a cross-core synthetic-fault handler). For the common case
    // this is a no-op since `releaseSelf` will park it.
    const cd_ref = ec.domain;
    const cd_lr = cd_ref.lockIrqSave(@src()) catch {
        // CD slab gen has moved — domain is already being torn down
        // by another path. Park the EC; the in-flight teardown will
        // reap it.
        execution_context.parkSelfFaulted(ec);
        return;
    };
    const cd = cd_lr.ptr;
    const cd_irq_state = cd_lr.irq_state;

    // Acquire tree_mutex to mirror the `delete(SLOT_SELF)` path
    // (caps.derivation.deleteAndDetach slot==0 arm); tree_mutex
    // serializes against concurrent revoke/derive.
    const tree_irq = zag.caps.derivation.tree_mutex.lockIrqSave(@src());

    // `releaseSelf` releases `cd._gen_lock` via `destroyLocked`
    // before returning; we restore the captured IRQ state manually
    // because the standard `unlockIrqRestore` would assert on the
    // already-cleared lock bit.
    const deferred = capability_domain.releaseSelf(cd);
    arch.cpu.restoreInterrupts(cd_irq_state);

    zag.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);

    capability_domain.destroyPhase2(deferred);
}

/// Fire a thread_fault event. Fallback on no route: park the EC so the
/// same fault doesn't loop forever.
pub fn fireThreadFault(ec: *ExecutionContext, subcode: u8, payload: u64) void {
    if (fireRouted(ec, .thread_fault, subcode, payload)) return;
    // No-route fallback. Earlier this called `execution_context.terminate(
    // ec, 0)`, but `terminate(caller, target)` resolves `target` as a
    // handle in the caller's table — slot 0 is the SELF capability_domain
    // handle, so resolution as `.execution_context` always returned
    // E_BADCAP. The faulting EC was then iretq'd back onto the same RIP,
    // faulted again, and (when higher-priority than its peers) starved
    // every other EC in the domain.
    //
    // Park instead of destroying: `parkSelfFaulted` clears the local
    // core's `current_ec` and marks state `.exited` so the scheduler
    // stops re-enqueueing it. We don't free the slab or kernel stack
    // here — we're still running on that very stack inside the
    // exception handler. The slab + stack are reclaimed when the
    // owning domain is torn down.
    execution_context.parkSelfFaulted(ec);
}

/// Fire a breakpoint event. Fallback: drop, advance past trap, resume.
pub fn fireBreakpoint(ec: *ExecutionContext, subcode: u8) void {
    if (fireRouted(ec, .breakpoint, subcode, 0)) return;
    // No-route fallback: drop the event and let `ec` resume. The
    // arch-specific helper that advances past the trap instruction
    // lives in arch.dispatch.cpu — until that one-byte INT3 advance is
    // wired through dispatch, leave the EC at the trapping RIP and
    // rely on the arch entry path to continue.
}

/// Fire a pmu_overflow event. Fallback: drop, EC continues running.
pub fn firePmuOverflow(ec: *ExecutionContext, counter_idx: u64) void {
    const subcode: u8 = @truncate(counter_idx);
    if (fireRouted(ec, .pmu_overflow, subcode, counter_idx)) return;
    // No-route fallback: silently drop. The EC keeps running and the
    // counter has already been re-armed by the arch ISR.
}

/// Fire a vm_exit event for a vCPU EC. Routes to `ec.exit_port`
/// directly (not through `event_routes`). Spec §[vm_exit_state].
pub fn fireVmExit(ec: *ExecutionContext, subcode: u8, payload: [3]u64) void {
    kprof.point(.vm_exit, subcode);

    const exit_port_ref = ec.exit_port orelse return;
    const exit_lr = exit_port_ref.lockIrqSave(@src()) catch return;
    const port_ptr = exit_lr.ptr;
    // `suspendOnPort` releases the port lock before returning — see its
    // contract. Do NOT add `defer exit_port_ref.unlockIrqRestore(...)` here.

    // Stash payload[3] on the vCPU's arch state so `port.deliverEvent`
    // (and the rendezvous resume path) can pick it up at delivery time
    // without re-threading the [3]u64 through suspendOnPort. payload[0]
    // also rides in `event_addr` for compatibility with the
    // event-state addr field, and is mirrored here for vm_exit.
    arch.vm.stashLastExitPayload(ec, payload);

    // The originating EC handle for vm_exit is the vCPU EC handle held
    // by the VMM. `read`/`write` default to true so §[event_state] /
    // §[vm_exit_state] vregs are exposed and reply mutations are
    // committed back; per-vCPU cap-snapshot wiring lands when the
    // VMM-side handle is captured at create_vcpu time.
    _ = execution_context.suspendOnPort(ec, port_ptr, .vm_exit, subcode, payload[0], true, true, exit_lr.irq_state);
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
/// each EC's `exit_port` and rechains the snapshot through `vcpu_list_next`.
/// Returns the snapshot head; caller must invoke `finalizePendingVcpus`
/// on it AFTER `p._gen_lock` has been released.
///
/// Lock-order rationale: `destroyExecutionContextLocked` walks
/// `ec.event_routes` and locks each non-null route's destination port.
/// If any vCPU has an `event_routes[i]` slot pointing back at `p`, doing
/// the destroy walk under `p._gen_lock` self-deadlocks. Even routes that
/// don't loop back create lock-order inversions vs. paths that go
/// EC-lock-first. Detach under the lock; finalize after release.
fn cascadeDetachVcpus(p: *Port) ?*ExecutionContext {
    var head: ?*ExecutionContext = null;
    var cur = p.vcpu_list_head;
    p.vcpu_list_head = null;
    while (cur) |ec| {
        const next = ec.vcpu_list_next;
        ec.exit_port = null;
        ec.vcpu_list_next = head;
        head = ec;
        cur = next;
    }
    return head;
}

/// Walk the snapshot returned by `cascadeDetachVcpus` and destroy each
/// EC. Callers MUST have released `p._gen_lock` (and `p` itself may
/// already be freed) before invoking this — the snapshot only carries
/// EC pointers, not the port pointer.
pub fn finalizePendingVcpus(head: ?*ExecutionContext) void {
    var cur = head;
    while (cur) |ec| {
        const next = ec.vcpu_list_next;
        ec.vcpu_list_next = null;
        // caller-pinned: each EC on this detached snapshot holds the
        // pre-cascade `bind_refcount` contribution and is not yet on
        // any other reachability path, so its slab slot can't be
        // reaped before this destroy completes.
        const ec_dom = ec.domain.ptr;
        execution_context.destroyExecutionContextLocked(
            ec,
            ec_dom.addr_space_root,
            ec_dom,
        );
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
    /// caller-pinned: snapshot head detached under `p._gen_lock` from
    /// `p.vcpu_list_head`; each EC on the chain still holds a kernel
    /// reference (the pre-cascade `bind_refcount` contribution) until
    /// `finalizePendingVcpus` destroys it, so the slab slots stay live
    /// for the duration of the post-lock-release walk.
    pending_vcpus: ?*ExecutionContext,
};

/// Refcount adjusters. Each `inc*` returns `error.BadCap` when it
/// observes the Sticky bit (a concurrent dec already drove the count
/// to 0); the caller must NOT proceed as if it acquired a reference.
/// All run under `p._gen_lock`.
pub fn incBindRef(p: *Port) error{BadCap}!void {
    if (p.bind_refcount.inc() == .observed_zero) return error.BadCap;
}

/// Drop one bind-side reference. On `observed_zero` (last bind holder
/// gone, no routes targeting the port, no vCPU `exit_port` pin), wake
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
        propagateClosedToSenders(p);
        // A blocked recv whose handle was deleted while parked sees
        // its port die from underneath it. Wake with E_CLOSED so the
        // EC doesn't sit on a stale waiter list past the slab's gen
        // bump.
        propagateClosedToReceivers(p);
        const pending = cascadeDetachVcpus(p);
        destroyPort(p);
        return .{ .destroyed = true, .pending_vcpus = pending };
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
        propagateClosedToSenders(p);
        // A blocked recv whose handle was the same one being dropped
        // here observes E_CLOSED through the bind-side wake above; the
        // recv-side wake catches the rare race where a different
        // recv-cap holder's blocked recv was queued and the port now
        // has no recv path at all.
        if (!bind_zero) propagateClosedToReceivers(p);
        const pending = cascadeDetachVcpus(p);
        destroyPort(p);
        return .{ .destroyed = true, .pending_vcpus = pending };
    }
    return .{ .destroyed = false, .pending_vcpus = null };
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Wraps `onHandleRelease` and finalizes
/// the cascade snapshot after `p._gen_lock` is released.
pub fn releaseHandle(p: *Port, caps: u16) void {
    const irq_state = p._gen_lock.lockIrqSave(@src());
    const result = onHandleRelease(p, caps);
    // `destroyPort` released the lock via `destroyLocked` on teardown;
    // teardown bumps gen via setGenRelease without touching IRQ state,
    // so restore it explicitly. Otherwise `unlockIrqRestore` does both.
    if (!result.destroyed) {
        p._gen_lock.unlockIrqRestore(irq_state);
    } else {
        arch.cpu.restoreInterrupts(irq_state);
    }
    finalizePendingVcpus(result.pending_vcpus);
}

/// `releaseHandle` for callers that already hold `p._gen_lock`. The
/// caller passes its IRQ-state token so the destroy path can restore
/// interrupts when `destroyLocked` consumed the lock without
/// restoring IRQs. The vCPU finalize walk runs only AFTER the lock
/// has been released.
pub fn releaseHandleLocked(p: *Port, caps: u16, held_irq: u64) void {
    const result = onHandleRelease(p, caps);
    if (!result.destroyed) {
        p._gen_lock.unlockIrqRestore(held_irq);
    } else {
        arch.cpu.restoreInterrupts(held_irq);
    }
    finalizePendingVcpus(result.pending_vcpus);
}

/// Wait queue ops — assert empty or matching kind, transition kind
/// on (en)queue, reset to .none when drained.
fn enqueueReceiver(p: *Port, receiver: *ExecutionContext) void {
    std.debug.assert(p.waiter_kind != .senders);
    p.waiters.enqueue(receiver);
    p.waiter_kind = .receivers;
}
fn popHighestPrioritySender(p: *Port) ?*ExecutionContext {
    if (p.waiter_kind != .senders) return null;
    while (p.waiters.dequeue()) |ec| {
        if (p.waiters.isEmpty()) p.waiter_kind = .none;
        // Cross-core terminate may have left a dead EC parked here;
        // skip it so callers never resume an exited slot.
        if (ec.state == .exited or ec._gen_lock.currentGen() % 2 == 0) continue;
        return ec;
    }
    return null;
}
fn popHighestPriorityReceiver(p: *Port) ?*ExecutionContext {
    if (p.waiter_kind != .receivers) return null;
    while (p.waiters.dequeue()) |ec| {
        if (p.waiters.isEmpty()) p.waiter_kind = .none;
        if (ec.state == .exited or ec._gen_lock.currentGen() % 2 == 0) continue;
        return ec;
    }
    return null;
}

/// Rendezvous + delivery — called once a (sender, receiver) pair is
/// identified. Mints a reply handle in receiver's domain, processes
/// attachments, writes event-state vregs, transitions states.
///
/// Slow-path mirror of arch/x64/interrupts.zig Phase 4: the syscall
/// return word and event-state vregs written here MUST match what the
/// fast path produces so the two are interchangeable.
///
/// LOCK ORDER: Caller MUST already hold `dom` (receiver's CD `_gen_lock`)
/// AND MUST NOT hold any Port `_gen_lock`. Canonical order across the
/// kernel is `CapabilityDomain` → `Port`; the matching `delete` path
/// takes CD then dispatches to `port.releaseHandle` which takes Port,
/// so this side must finish all Port-held work and drop Port BEFORE
/// reaching here. Holding Port across the CD acquisition done by the
/// previous version of this function created an AB-BA cycle observed
/// by lockdep at port.zig:613 vs port.zig:552.
fn deliverEvent(
    sender: *ExecutionContext,
    receiver: *ExecutionContext,
    dom: *CapabilityDomain,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
    pair_count: u8,
    port_xfer: bool,
) i64 {
    kprof.enter(.deliver_event);
    defer kprof.exit(.deliver_event);
    // Spec §[reply]: minted reply handle inherits `xfer = 1` iff the
    // recv'ing port carried the `xfer` cap. Caller threads that bit
    // through from the recv-time port-handle resolution (it is NOT
    // derived from `pair_count`).
    const xfer_allowed = port_xfer;
    const reply_slot = mintReply(dom, sender, xfer_allowed) catch {
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
    };

    // Spec §[handle_attachments]: when the sender stashed pair entries
    // at suspend time, install them now in `[tstart, tstart+N)` of the
    // receiver's domain. The sender stash captured the source object's
    // ErasedSlabRef under the sender's domain lock, so the gen baked
    // into each entry matches a live object as long as the object
    // hasn't been destroyed in the interim. We install via
    // `mintHandleAt` to bypass the at-most-one-per-(domain, object)
    // coalescing (spec test 08 requires N fresh slots even when the
    // receiver already holds a handle to the same object).
    var tstart: u12 = 0;
    if (pair_count > 0) {
        tstart = capability_domain.allocContiguousFreeSlots(dom, pair_count) catch {
            // Couldn't reserve a contiguous run — should have been
            // caught by the free_count pre-check, but the contiguous
            // requirement can fail even when there are enough total
            // free slots (fragmented table). Surface E_FULL.
            return errors.E_FULL;
        };
        // Spec §[idc_rx] test 01: when a domain receives an IDC handle
        // over IDC, the installed caps = granted ∩ receiver's idc_rx.
        // idc_rx lives in receiver self-handle field0 bits 32-39.
        const dom_idc_rx: u16 = @truncate((dom.user_table[0].field0 >> 32) & 0xFF);
        var k: u8 = 0;
        while (k < pair_count) {
            const entry = sender.pending_pair_entries[k];
            const target_slot: u12 = @intCast(@as(u16, tstart) + k);
            // Spec §[handle_attachments]: refcount-lifetime types
            // (page_frame, timer, port, device_region) must take an
            // object-side refcount on the new alias so a `delete` of
            // the source slot cannot destroy the object out from under
            // the receiver's freshly minted handle.
            switch (entry.obj_type) {
                .page_frame => {
                    const pf: *zag.memory.page_frame.PageFrame =
                        @ptrCast(@alignCast(entry.obj_ref.ptr.?));
                    zag.memory.page_frame.incHandleRef(pf) catch unreachable;
                },
                .timer => {
                    const t: *zag.sched.timer.Timer =
                        @ptrCast(@alignCast(entry.obj_ref.ptr.?));
                    zag.sched.timer.incHandleRef(t) catch unreachable;
                },
                .port => {
                    const alias_p: *Port = @ptrCast(@alignCast(entry.obj_ref.ptr.?));
                    const alias_irq = alias_p._gen_lock.lockIrqSave(@src());
                    defer alias_p._gen_lock.unlockIrqRestore(alias_irq);
                    onHandleAcquire(alias_p, entry.caps) catch unreachable;
                },
                .device_region => {
                    const dr: *zag.devices.device_region.DeviceRegion =
                        @ptrCast(@alignCast(entry.obj_ref.ptr.?));
                    zag.devices.device_region.incHandleRef(dr) catch unreachable;
                },
                else => {},
            }
            // Spec §[idc_rx] test 01: when receiving an IDC handle over
            // IDC, installed caps = granted ∩ receiver's idc_rx.
            const installed_caps: u16 = if (entry.obj_type == .capability_domain)
                entry.caps & dom_idc_rx
            else
                entry.caps;
            capability_domain.mintHandleAt(
                dom,
                target_slot,
                entry.obj_ref,
                entry.obj_type,
                installed_caps,
                0,
                0,
            );

            // Spec §[capabilities].revoke: hang the new alias in the
            // receiver's domain under the source handle in the sender's
            // domain so a future revoke on any ancestor of
            // `(sender.domain, entry.src_slot)` reaches the alias. The
            // receiver's CD `dom` is held; we pass it as `held_dom` to
            // skip the re-acquire inside `derive`.
            const sender_dom_ref: capability.ErasedSlabRef = @bitCast(sender.domain);
            const dom_ref: capability.ErasedSlabRef = .{
                .ptr = dom,
                .gen = @intCast(dom._gen_lock.currentGen()),
            };
            _ = zag.caps.derivation.derive(
                sender_dom_ref,
                entry.src_slot,
                dom_ref,
                target_slot,
                dom,
            );

            k += 1;
        }

        // Spec §[handle_attachments] test 09: on recv, source entries
        // with `move = 1` are removed from the sender's table; entries
        // with `move = 0` are not removed. Mirrors the source-slot
        // clear in `replyTransfer` (port.zig:861-867) and the
        // copy/move alias path in capability_domain.zig:444-468.
        //
        // Same-CD common case: the sender and receiver share a single
        // CapabilityDomain (the suspend-target-self single-process
        // tests live here). Receiver CD lock is already held, so we
        // can clear the source slot directly. The acquire+release on
        // refcount-lifetime types nets to zero — the new alias bumped
        // above is the heir to the source handle's lifetime
        // contribution, and the source's release here balances it.
        //
        // Cross-CD: skipping the source clear here is a known
        // limitation. Honoring it would require dropping the receiver
        // CD lock and re-locking the sender's CD via the same
        // single-CD-at-a-time pattern as `replyTransfer`. The
        // single-process spec tests (test 09) don't exercise the
        // cross-CD path; the multi-process IPC path will need that
        // refactor to be observably move-correct. TODO: extend the
        // recv-time delivery to phase out receiver-CD before
        // acquiring sender-CD for the source clear (matches the
        // reply-transfer phase split).
        if (sender.domain.ptr == dom) {
            k = 0;
            while (k < pair_count) : (k += 1) {
                const entry = sender.pending_pair_entries[k];
                if (!entry.move) continue;
                const src_slot = entry.src_slot;
                if (capability.resolveHandleOnDomain(dom, src_slot, null)) |src_entry| {
                    // Apply the per-type release for refcount-lifetime
                    // handles before clearing the slot. Mirrors the
                    // copy/move-alias `move=1` arm in
                    // capability_domain.zig:444-467.
                    switch (entry.obj_type) {
                        .page_frame => zag.memory.page_frame.releaseHandle(@ptrCast(@alignCast(src_entry.ref.ptr.?))),
                        .timer => zag.sched.timer.decHandleRef(@ptrCast(@alignCast(src_entry.ref.ptr.?))),
                        .port => {
                            const sp: *Port = @ptrCast(@alignCast(src_entry.ref.ptr.?));
                            const src_caps_word: u16 = @truncate(Word0.caps(dom.user_table[src_slot].word0));
                            releaseHandle(sp, src_caps_word);
                        },
                        .device_region => {
                            const sdr: *zag.devices.device_region.DeviceRegion =
                                @ptrCast(@alignCast(src_entry.ref.ptr.?));
                            const sdr_irq = sdr._gen_lock.lockIrqSave(@src());
                            zag.devices.device_region.removeHandleListNodeLocked(sdr, &dom.kernel_table[src_slot].dr_node);
                            zag.devices.device_region.releaseHandleLocked(sdr, sdr_irq);
                        },
                        else => {},
                    }
                    capability.clearAndFreeSlot(dom, src_slot, src_entry);
                }
            }
        }

        // Consume the stash — the move/copy completes here. Spec
        // §[handle_attachments] test 10 specifies that if the suspend
        // resumes with E_CLOSED before any recv, no entry is moved or
        // copied; clearing only on the recv-success path preserves
        // that contract.
        sender.pending_pair_count = 0;
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

    // §[event_state] vregs 1..13 = the suspending EC's GPRs snapshotted
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
    receiver.pending_event_rip = sender.event_rip;
    receiver.pending_event_rip_valid = true;
    _ = event_addr;
    if (sender.originating_read_cap) {
        arch.syscall.setEventStateGprs(target_ctx, sender.event_state_gprs);
    } else {
        // §[suspend] test 10 / §[recv] tests 11/12: the snapshot is
        // delivered iff the originating EC handle had the `read` cap;
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
    // specific sub-code (memory_fault, thread_fault, breakpoint,
    // vm_exit, pmu_overflow). The firing-site sub-code overlays the
    // GPR projection's vreg 2 slot — §[create_vcpu] test 12 requires
    // the synthetic initial vm_exit to surface the initial-state
    // sentinel even though the sender's GPR snapshot is all zero.
    // For `suspension` the spec leaves `subcode` 0, so we leave the
    // snapshot's rbx (the suspending EC's value) untouched.
    switch (event_type) {
        .memory_fault, .thread_fault, .breakpoint, .vm_exit, .pmu_overflow => {
            arch.syscall.setEventSubcode(target_ctx, subcode);
        },
        .none, .suspension => {},
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
/// suspended sender EC (state already set to `.suspended_on_port` by
/// the suspendOnPort path); we dequeue the highest-priority waiting
/// receiver, mint a reply handle in the receiver's domain, write the
/// event-state syscall return into the receiver's iret frame, and
/// enqueue the receiver as ready.
///
/// Caller MUST hold `p._gen_lock`. On a successful match (`true`
/// returned) the function RELEASES that Port lock before acquiring the
/// receiver's CD lock — canonical kernel order is CD → Port and Port
/// must be dropped before deliverEvent reaches mintReply. Callers must
/// therefore not also unlock `p` themselves on the success path.
/// Returns `false` (with `p._gen_lock` still held) if no receiver was
/// eligible — the caller resumes the slow-path enqueue.
pub fn rendezvousWithReceiver(
    sender: *ExecutionContext,
    p: *Port,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
    port_irq_state: u64,
) bool {
    const receiver = popHighestPriorityReceiver(p) orelse return false;
    // SMP race: a receiver popped here may still be on its previous core
    // mid-context-save (the dequeuing core is the sender's CPU, distinct
    // from where the receiver last ran). Mutating `receiver.ctx` /
    // `receiver.event_*` before its prior core has cleared `on_cpu`
    // would race the saving core's GPR writes. Mirror the standard
    // wake-side pattern from futex.zig:239,588 and port.zig:187 — spin
    // until the prior core releases the EC.
    while (receiver.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    receiver.event_type = .none;
    receiver.suspend_port = null;

    // Cancel any pending recv-with-timeout deadline before delivery.
    // Setting deadline to 0 also makes a stale-snapshot phase-2 expiry
    // skip this EC.
    if (receiver.recv_deadline_ns != 0) {
        receiver.recv_deadline_ns = 0;
        removeTimedRecvWaiter(receiver);
    }

    // Snapshot receiver's CD ref under the port lock, then drop the
    // port lock before acquiring the CD lock. The receiver is no
    // longer queued on the port; its slab slot stays alive while
    // state is `.suspended_on_port`. Holding port across the CD
    // acquisition would re-introduce the AB-BA cycle that lockdep
    // catches against the `delete → releaseHandle` path.
    const receiver_dom_ref = receiver.domain;
    p._gen_lock.unlockIrqRestore(port_irq_state);

    const domlr = receiver_dom_ref.lockIrqSave(@src()) catch {
        // Receiver's CD was torn down between the pop and our lock —
        // the receiver itself is doomed via the same teardown. Drop
        // the rendezvous; the sender remains parked (state already set
        // by suspendOnPort) and will be woken by E_CLOSED when the
        // port's last refcount drops, or be reaped at sender teardown.
        return true;
    };
    const dom = domlr.ptr;
    defer receiver_dom_ref.unlockIrqRestore(domlr.irq_state);

    _ = deliverEvent(
        sender,
        receiver,
        dom,
        event_type,
        subcode,
        event_addr,
        sender.pending_pair_count,
        receiver.recv_port_xfer,
    );
    receiver.state = .ready;
    scheduler.markReady(receiver);
    return true;
}

/// Mint a reply handle in `receiver_domain`'s table pointing at the
/// suspended `sender` EC. Sets `sender.pending_reply_holder` back-pointer.
fn mintReply(receiver_domain: *CapabilityDomain, sender: *ExecutionContext, xfer: bool) !u12 {
    const reply_caps: ReplyCaps = .{
        .move = true,
        .copy = false,
        .xfer = xfer,
    };

    const obj_ref: ErasedSlabRef = .{
        .ptr = sender,
        .gen = @intCast(sender._gen_lock.currentGen()),
    };
    const slot = try capability_domain.mintHandle(
        receiver_domain,
        obj_ref,
        .reply,
        @bitCast(reply_caps),
        0,
        0,
    );

    sender.pending_reply_holder = &receiver_domain.kernel_table[slot];
    sender.pending_reply_domain = SlabRef(CapabilityDomain).init(
        receiver_domain,
        receiver_domain._gen_lock.currentGen(),
    );
    sender.pending_reply_slot = slot;
    return slot;
}

/// Resume the sender via the reply path, applying receiver's GPR
/// modifications (gated by originating EC handle's `write` cap).
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
    receiver: *ExecutionContext,
    sender: *ExecutionContext,
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
    // replies. Non-vm_exit reply paths (`suspension`, fault events)
    // never carry a vCPU sender, so `applyReplyStateToVcpu` would also
    // no-op via `archStateOf == null`, but skipping the call entirely
    // is the explicit type-driven gate.
    if (event_type == .vm_exit and sender.originating_write_cap) {
        arch.vm.applyReplyStateToVcpu(sender, snap);
    }
    execution_context.resumeFromReply(sender, sender.originating_write_cap);
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
pub fn resumeWithAbandoned(sender: *ExecutionContext) void {
    // Sender may have been pulled off the port by an earlier wake path
    // (e.g. a concurrent E_CLOSED propagation). resumeFromReply asserts
    // .suspended_on_port — gate to avoid asserting in those races.
    if (sender.state != .suspended_on_port) return;

    if (sender.iret_frame) |frame| {
        arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_ABANDONED));
    } else {
        arch.syscall.setSyscallReturn(sender.ctx, @bitCast(errors.E_ABANDONED));
    }
    execution_context.resumeFromReply(sender, false);
}

/// On bind_refcount → 0 (or recv_refcount → 0 with blocked recvs in
/// flight): wake all blocked receivers with E_CLOSED.
fn propagateClosedToReceivers(p: *Port) void {
    if (p.waiter_kind != .receivers) return;
    while (p.waiters.dequeue()) |waiter| {
        if (waiter.iret_frame) |frame| {
            arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_CLOSED));
        } else {
            arch.syscall.setSyscallReturn(waiter.ctx, @bitCast(errors.E_CLOSED));
        }
        waiter.suspend_port = null;
        waiter.state = .ready;
        scheduler.markReady(waiter);
    }
    p.waiter_kind = .none;
}

/// On recv_refcount → 0: wake all suspended senders with E_CLOSED;
/// drop their pre-validated attachments without effect.
fn propagateClosedToSenders(p: *Port) void {
    if (p.waiter_kind != .senders) return;
    while (p.waiters.dequeue()) |sender| {
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
        // entry is moved or copied. Clear the count so a subsequent
        // recv on this EC doesn't observe stale stash from this
        // closed suspend (`deliverEvent`'s install loop reads
        // `sender.pending_pair_count` on the next pairing and would
        // otherwise install ghost handles from the dead session).
        sender.pending_pair_count = 0;
        sender.state = .ready;
        scheduler.markReady(sender);
    }
    p.waiter_kind = .none;
}
