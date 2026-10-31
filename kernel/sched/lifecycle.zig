//! Thread lifecycle authority.
//!
//! The scheduler, wait containers, and arch dispatch tails all consume the
//! same state word, but lifecycle transitions are centralized here so there
//! is one CAS discipline for queue publication, wake claims, parking
//! discharge, and retirement.

const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const spin_diag = stygia.utils.spin_diag;

/// Authoritative thread lifecycle state.
pub const State = enum(u8) {
    /// Linked in exactly one run queue.
    ready,
    /// Current on exactly one core.
    running,
    /// Current on an owner core, published in a wait container, and waiting
    /// for the owner to hop off its kernel stack.
    parking,
    /// Linked in exactly one wait container, or parked awaiting reply.
    waiting,
    /// Claimed by a single dequeuer/waker; not linked in any container.
    claimed,
    /// A waker won while the owner was still in `parking`; payload is valid
    /// once `wait.payload_done` becomes true.
    pended,
    /// Gen-dead or becoming gen-dead. Never runnable.
    retired,
};

/// Destination container for the current wait episode.
pub const WaitKind = enum(u8) {
    none,
    port_sender,
    port_receiver,
    reply,
    futex,
    idle,
    requeue,
};

pub const MarkState = enum(u8) {
    clear = 0,
    destroy = 1,
};

pub const DirectiveTag = enum(u8) {
    none = 0,
    suspending = 1,
    claiming = 2,
    armed = 3,
    dead = 4,
    failed = 5,
};

pub const Directive = packed struct(u32) {
    state: u8 = @intFromEnum(DirectiveTag.none),
    owner_slot: u24 = 0,
};

pub const ClaimResult = enum {
    none,
    claimed,
    pended,
};

pub fn packDirective(tag: DirectiveTag, owner_slot: u24) u32 {
    return @bitCast(Directive{
        .state = @intFromEnum(tag),
        .owner_slot = owner_slot,
    });
}

pub fn directiveTag(word: u32) DirectiveTag {
    const d: Directive = @bitCast(word);
    return @enumFromInt(d.state);
}

pub fn directiveOwnerSlot(word: u32) u24 {
    const d: Directive = @bitCast(word);
    return d.owner_slot;
}

pub fn load(thread: anytype) State {
    return @atomicLoad(State, &thread.state, .acquire);
}

pub fn storePrivate(thread: anytype, state: State) void {
    @atomicStore(State, &thread.state, state, .release);
}

pub fn cas(thread: anytype, expected: State, desired: State) bool {
    return @cmpxchgStrong(
        State,
        &thread.state,
        expected,
        desired,
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn isDestroyMarked(thread: anytype) bool {
    return thread.mark_state.load(.seq_cst) != @intFromEnum(MarkState.clear);
}

pub fn markRetiring(thread: anytype) bool {
    return thread.mark_state.cmpxchgStrong(
        @intFromEnum(MarkState.clear),
        @intFromEnum(MarkState.destroy),
        .seq_cst,
        .seq_cst,
    ) == null;
}

pub fn tryPinLive(thread: anytype) bool {
    while (true) {
        if (isDestroyMarked(thread)) return false;

        const old = thread.pin_depth.load(.seq_cst);
        std.debug.assert(old != std.math.maxInt(u8));
        if (thread.pin_depth.cmpxchgWeak(old, old + 1, .seq_cst, .seq_cst) != null) {
            spin_diag.note(.claim_cas, @intFromPtr(thread));
            std.atomic.spinLoopHint();
            continue;
        }

        if (!isDestroyMarked(thread) and load(thread) != .retired and thread._gen_lock.currentGen() % 2 == 1) {
            return true;
        }

        releasePin(thread);
        return false;
    }
}

pub fn releasePin(thread: anytype) void {
    const old = thread.pin_depth.fetchSub(1, .seq_cst);
    std.debug.assert(old > 0);
}

pub fn waitForPinsDrained(thread: anytype) void {
    while (thread.pin_depth.load(.seq_cst) != 0) {
        spin_diag.note(.pins_drained, @intFromPtr(thread));
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        // stygia-8xl: pin holders can be blocked in `migrateFlush`.
        stygia.sched.fpu.serviceLocalFlushWhileSpinning();
        std.atomic.spinLoopHint();
    }
}

pub fn isReadyCacheValid(thread: anytype, not_in_queue: u8) bool {
    return load(thread) == .ready and thread.current_queue_core.load(.acquire) != not_in_queue;
}

pub fn initNewThread(thread: anytype, not_in_queue: u8) void {
    storePrivate(thread, .ready);
    thread.owner_core = not_in_queue;
    thread.pin_depth.store(0, .release);
    thread.mark_state.store(@intFromEnum(MarkState.clear), .release);
    thread.directive_state.store(packDirective(.none, 0), .release);
    thread.directive_result.store(0, .release);
    thread.directive_port = null;
    thread.directive_owner = null;
    thread.wait.clear();
    thread.current_queue_core.store(not_in_queue, .release);
}

pub fn prepareDispatchLocked(thread: anytype, core: u8, not_in_queue: u8) bool {
    if (!cas(thread, .ready, .running)) return false;
    thread.owner_core = core;
    thread.current_queue_core.store(not_in_queue, .release);
    return true;
}

pub fn prepareRunningPark(thread: anytype, core: u8, kind: WaitKind) bool {
    thread.wait.begin(kind);
    thread.owner_core = core;
    if (!cas(thread, .running, .parking)) {
        thread.wait.clear();
        return false;
    }
    return true;
}

pub fn beginReadyClaim(thread: anytype) bool {
    return cas(thread, .ready, .claimed);
}

pub fn beginReadyClaimPinned(thread: anytype) bool {
    if (!tryPinLive(thread)) return false;
    if (beginReadyClaim(thread)) return true;
    releasePin(thread);
    return false;
}

pub fn beginWaitingClaim(thread: anytype) ClaimResult {
    while (true) {
        switch (load(thread)) {
            .waiting => {
                if (cas(thread, .waiting, .claimed)) return .claimed;
            },
            .parking => {
                if (cas(thread, .parking, .pended)) return .pended;
            },
            else => return .none,
        }
        spin_diag.note(.claim_cas, @intFromPtr(thread));
        std.atomic.spinLoopHint();
    }
}

/// On `.claimed` or `.pended`, returns with one live pin held by caller.
/// On `.none`, returns without a pin.
pub fn beginWaitingClaimPinned(thread: anytype) ClaimResult {
    while (true) {
        if (!tryPinLive(thread)) return .none;

        switch (load(thread)) {
            .waiting => {
                if (cas(thread, .waiting, .claimed)) return .claimed;
            },
            .parking => {
                if (cas(thread, .parking, .pended)) return .pended;
            },
            else => {
                releasePin(thread);
                return .none;
            },
        }

        releasePin(thread);
        spin_diag.note(.claim_cas, @intFromPtr(thread));
        std.atomic.spinLoopHint();
    }
}

pub fn pinLiveLocked(thread: anytype) bool {
    return tryPinLive(thread);
}

pub fn unpin(thread: anytype) void {
    releasePin(thread);
}

pub fn waitPinsDrained(thread: anytype) void {
    waitForPinsDrained(thread);
}

pub fn commitClaimedWaiting(thread: anytype) bool {
    return cas(thread, .claimed, .waiting);
}

pub fn commitParkingWaiting(thread: anytype, not_in_queue: u8) bool {
    if (!cas(thread, .parking, .waiting)) return false;
    thread.owner_core = not_in_queue;
    return true;
}

pub fn publishPendedPayload(thread: anytype) void {
    thread.wait.payload_done.store(true, .release);
}

pub fn waitForPendedPayload(thread: anytype) void {
    while (!thread.wait.payload_done.load(.acquire)) {
        spin_diag.note(.pended_payload, @intFromPtr(thread));
        std.atomic.spinLoopHint();
    }
}

pub fn finishPendedReady(thread: anytype, not_in_queue: u8) bool {
    waitForPendedPayload(thread);
    if (!cas(thread, .pended, .ready)) return false;
    thread.owner_core = not_in_queue;
    thread.wait.clear();
    return true;
}

pub fn finishClaimedReady(thread: anytype, not_in_queue: u8) bool {
    if (!cas(thread, .claimed, .ready)) return false;
    thread.owner_core = not_in_queue;
    thread.wait.clear();
    return true;
}

pub fn finishClaimedDispatch(thread: anytype, core: u8, not_in_queue: u8) bool {
    if (!cas(thread, .claimed, .running)) return false;
    thread.owner_core = core;
    thread.current_queue_core.store(not_in_queue, .release);
    thread.wait.clear();
    return true;
}

pub fn retire(thread: anytype) State {
    while (true) {
        const from = load(thread);
        if (from == .retired) return from;
        if (from == .pended) waitForPendedPayload(thread);
        if (cas(thread, from, .retired)) {
            thread.mark_state.store(@intFromEnum(MarkState.destroy), .release);
            return from;
        }
        spin_diag.note(.retire_cas, @intFromPtr(thread));
        std.atomic.spinLoopHint();
    }
}

pub fn canSuspendTarget(thread: anytype) bool {
    return switch (load(thread)) {
        .running, .ready => true,
        .waiting => thread.wait.kind == .idle,
        else => false,
    };
}

pub fn isPortSuspended(thread: anytype) bool {
    return switch (load(thread)) {
        .waiting, .claimed, .pended, .parking => switch (thread.wait.kind) {
            .port_sender, .port_receiver, .reply => true,
            else => false,
        },
        else => false,
    };
}

pub fn selfMarkSuspending(thread: anytype) bool {
    return thread.directive_state.cmpxchgStrong(
        packDirective(.none, 0),
        packDirective(.suspending, 0),
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn clearSelfDirective(thread: anytype) void {
    _ = thread.directive_state.cmpxchgStrong(
        packDirective(.suspending, 0),
        packDirective(.none, 0),
        .acq_rel,
        .acquire,
    );
}

pub fn claimRemoteSuspend(target: anytype, owner_slot: u24) bool {
    return target.directive_state.cmpxchgStrong(
        packDirective(.none, 0),
        packDirective(.claiming, owner_slot),
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn armRemoteSuspend(target: anytype, owner_slot: u24) bool {
    if (target.directive_state.cmpxchgStrong(
        packDirective(.claiming, owner_slot),
        packDirective(.armed, owner_slot),
        .acq_rel,
        .acquire,
    ) == null) return true;
    _ = target.directive_state.cmpxchgStrong(
        packDirective(.claiming, owner_slot),
        packDirective(.none, 0),
        .acq_rel,
        .acquire,
    );
    return false;
}

pub fn disarmDirectiveWord(target: anytype, word: u32) bool {
    return target.directive_state.cmpxchgStrong(
        word,
        packDirective(.none, 0),
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn failDirectiveWord(target: anytype, word: u32, result: i64) bool {
    target.directive_result.store(result, .release);
    return target.directive_state.cmpxchgStrong(
        word,
        packDirective(.failed, directiveOwnerSlot(word)),
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn clearFailedDirectiveWord(target: anytype, failed_word: u32) bool {
    return target.directive_state.cmpxchgStrong(
        failed_word,
        packDirective(.none, 0),
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn markDirectiveDead(thread: anytype) void {
    thread.directive_state.store(packDirective(.dead, 0), .release);
}
