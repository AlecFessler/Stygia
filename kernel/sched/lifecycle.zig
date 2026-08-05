//! Execution-context lifecycle authority.
//!
//! The scheduler, wait containers, and arch dispatch tails all consume the
//! same state word, but lifecycle transitions are centralized here so there
//! is one CAS discipline for queue publication, wake claims, parking
//! discharge, and retirement.

const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;

/// Authoritative EC lifecycle state.
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

pub fn load(ec: anytype) State {
    return @atomicLoad(State, &ec.state, .acquire);
}

pub fn storePrivate(ec: anytype, state: State) void {
    @atomicStore(State, &ec.state, state, .release);
}

pub fn cas(ec: anytype, expected: State, desired: State) bool {
    return @cmpxchgStrong(
        State,
        &ec.state,
        expected,
        desired,
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn isDestroyMarked(ec: anytype) bool {
    return ec.mark_state.load(.seq_cst) != @intFromEnum(MarkState.clear);
}

pub fn markRetiring(ec: anytype) bool {
    return ec.mark_state.cmpxchgStrong(
        @intFromEnum(MarkState.clear),
        @intFromEnum(MarkState.destroy),
        .seq_cst,
        .seq_cst,
    ) == null;
}

pub fn tryPinLive(ec: anytype) bool {
    while (true) {
        if (isDestroyMarked(ec)) return false;

        const old = ec.pin_depth.load(.seq_cst);
        std.debug.assert(old != std.math.maxInt(u8));
        if (ec.pin_depth.cmpxchgWeak(old, old + 1, .seq_cst, .seq_cst) != null) {
            std.atomic.spinLoopHint();
            continue;
        }

        if (!isDestroyMarked(ec) and load(ec) != .retired and ec._gen_lock.currentGen() % 2 == 1) {
            return true;
        }

        releasePin(ec);
        return false;
    }
}

pub fn releasePin(ec: anytype) void {
    const old = ec.pin_depth.fetchSub(1, .seq_cst);
    std.debug.assert(old > 0);
}

pub fn waitForPinsDrained(ec: anytype) void {
    while (ec.pin_depth.load(.seq_cst) != 0) {
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        std.atomic.spinLoopHint();
    }
}

pub fn isReadyCacheValid(ec: anytype, not_in_queue: u8) bool {
    return load(ec) == .ready and ec.current_queue_core.load(.acquire) != not_in_queue;
}

pub fn initNewEc(ec: anytype, not_in_queue: u8) void {
    storePrivate(ec, .ready);
    ec.owner_core = not_in_queue;
    ec.pin_depth.store(0, .release);
    ec.mark_state.store(@intFromEnum(MarkState.clear), .release);
    ec.directive_state.store(packDirective(.none, 0), .release);
    ec.directive_result.store(0, .release);
    ec.directive_port = null;
    ec.directive_owner = null;
    ec.wait.clear();
    ec.current_queue_core.store(not_in_queue, .release);
}

pub fn prepareDispatchLocked(ec: anytype, core: u8, not_in_queue: u8) bool {
    if (!cas(ec, .ready, .running)) return false;
    ec.owner_core = core;
    ec.current_queue_core.store(not_in_queue, .release);
    return true;
}

pub fn prepareRunningPark(ec: anytype, core: u8, kind: WaitKind) bool {
    ec.wait.begin(kind);
    ec.owner_core = core;
    if (!cas(ec, .running, .parking)) {
        ec.wait.clear();
        return false;
    }
    return true;
}

pub fn beginReadyClaim(ec: anytype) bool {
    return cas(ec, .ready, .claimed);
}

pub fn beginReadyClaimPinned(ec: anytype) bool {
    if (!tryPinLive(ec)) return false;
    if (beginReadyClaim(ec)) return true;
    releasePin(ec);
    return false;
}

pub fn beginWaitingClaim(ec: anytype) ClaimResult {
    while (true) {
        switch (load(ec)) {
            .waiting => {
                if (cas(ec, .waiting, .claimed)) return .claimed;
            },
            .parking => {
                if (cas(ec, .parking, .pended)) return .pended;
            },
            else => return .none,
        }
        std.atomic.spinLoopHint();
    }
}

/// On `.claimed` or `.pended`, returns with one live pin held by caller.
/// On `.none`, returns without a pin.
pub fn beginWaitingClaimPinned(ec: anytype) ClaimResult {
    while (true) {
        if (!tryPinLive(ec)) return .none;

        switch (load(ec)) {
            .waiting => {
                if (cas(ec, .waiting, .claimed)) return .claimed;
            },
            .parking => {
                if (cas(ec, .parking, .pended)) return .pended;
            },
            else => {
                releasePin(ec);
                return .none;
            },
        }

        releasePin(ec);
        std.atomic.spinLoopHint();
    }
}

pub fn pinLiveLocked(ec: anytype) bool {
    return tryPinLive(ec);
}

pub fn unpin(ec: anytype) void {
    releasePin(ec);
}

pub fn waitPinsDrained(ec: anytype) void {
    waitForPinsDrained(ec);
}

pub fn commitClaimedWaiting(ec: anytype) bool {
    return cas(ec, .claimed, .waiting);
}

pub fn commitParkingWaiting(ec: anytype, not_in_queue: u8) bool {
    if (!cas(ec, .parking, .waiting)) return false;
    ec.owner_core = not_in_queue;
    return true;
}

pub fn publishPendedPayload(ec: anytype) void {
    ec.wait.payload_done.store(true, .release);
}

pub fn waitForPendedPayload(ec: anytype) void {
    while (!ec.wait.payload_done.load(.acquire)) {
        std.atomic.spinLoopHint();
    }
}

pub fn finishPendedReady(ec: anytype, not_in_queue: u8) bool {
    waitForPendedPayload(ec);
    if (!cas(ec, .pended, .ready)) return false;
    ec.owner_core = not_in_queue;
    ec.wait.clear();
    return true;
}

pub fn finishClaimedReady(ec: anytype, not_in_queue: u8) bool {
    if (!cas(ec, .claimed, .ready)) return false;
    ec.owner_core = not_in_queue;
    ec.wait.clear();
    return true;
}

pub fn finishClaimedDispatch(ec: anytype, core: u8, not_in_queue: u8) bool {
    if (!cas(ec, .claimed, .running)) return false;
    ec.owner_core = core;
    ec.current_queue_core.store(not_in_queue, .release);
    ec.wait.clear();
    return true;
}

pub fn retire(ec: anytype) State {
    while (true) {
        const from = load(ec);
        if (from == .retired) return from;
        if (from == .pended) waitForPendedPayload(ec);
        if (cas(ec, from, .retired)) {
            ec.mark_state.store(@intFromEnum(MarkState.destroy), .release);
            return from;
        }
        std.atomic.spinLoopHint();
    }
}

pub fn canSuspendTarget(ec: anytype) bool {
    return switch (load(ec)) {
        .running, .ready => true,
        .waiting => ec.wait.kind == .idle,
        else => false,
    };
}

pub fn isPortSuspended(ec: anytype) bool {
    return switch (load(ec)) {
        .waiting, .claimed, .pended, .parking => switch (ec.wait.kind) {
            .port_sender, .port_receiver, .reply => true,
            else => false,
        },
        else => false,
    };
}

pub fn selfMarkSuspending(ec: anytype) bool {
    return ec.directive_state.cmpxchgStrong(
        packDirective(.none, 0),
        packDirective(.suspending, 0),
        .acq_rel,
        .acquire,
    ) == null;
}

pub fn clearSelfDirective(ec: anytype) void {
    _ = ec.directive_state.cmpxchgStrong(
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

pub fn markDirectiveDead(ec: anytype) void {
    ec.directive_state.store(packDirective(.dead, 0), .release);
}
