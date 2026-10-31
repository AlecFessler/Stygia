//! Per-core "what is this core waiting on" breadcrumbs (stygia-8xl).
//!
//! The terminal photograph for the surviving repeat-mode hang is a core
//! that still names a RETIRED, gen-dead EC in `current_ec` while every
//! other core has gone quiet. The per-core dump in `hang_detector` can
//! say WHAT that core holds but not WHERE that core is, and the whole
//! family of failed candidate fixes so far was built on guesses about
//! that second half.
//!
//! This module closes it. Every unbounded spin/wait loop in the kernel
//! calls `note()` once per iteration with a site id and one argument
//! (usually the object being waited on). Three stores, no lock, no
//! serial output. `note` is unconditional: it only ever executes inside
//! a loop that is already spinning on `pause`, so the added cost is not
//! observable against what that loop was doing anyway.
//!
//! `noteEntry` is different and is build-gated (`-Dspin_entry_diag`,
//! default on under `-Dprofile=test`). It is the one call site with no
//! surrounding spin — it fires on every preemption tick and every
//! cross-core wake/scheduler IPI — so the "free next to the pause"
//! argument does not cover it and production builds do not carry it.
//! No perf regression was measured either way; this is a static-cost
//! judgement, not a measurement (the only box available has a ±19%
//! noise floor from an unrelated 14 GB training job, and a
//! base-vs-base control on it drifted +18%).
//!
//! Nothing outside `hang_detector` ever reads any of it.
//!
//! `iters` is the liveness half: the hang dump samples it twice, a
//! bounded delay apart. A site whose `iters` ADVANCES between the two
//! samples is where the core is spinning right now; a site whose
//! `iters` is frozen is a stale breadcrumb from some earlier wait and
//! the core is somewhere uninstrumented (userspace, a bounded loop, or
//! wedged with interrupts masked). `entries` is the same test for the
//! interrupt path: a core that is taking timer ticks keeps counting.

const std = @import("std");
const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;

/// Matches `scheduler.MAX_CORES`; kept local so this module imports
/// nothing from the scheduler (the spin sites include primitives the
/// scheduler itself is built on).
pub const MAX_CORES: usize = 64;

/// Waiting sites. Ids are stable — they are printed by number as well
/// as by name so an old log stays readable.
pub const Site = enum(u16) {
    none = 0,
    /// `execution_context.routeRetiredFinalize` — terminator waiting for
    /// the retired EC's owner core to drop it from `current_ec`.
    route_retired_wait = 1,
    /// `scheduler.awaitDomainQuiesced` — phase-2 translation barrier.
    await_quiesced = 2,
    /// `lifecycle.waitForPinsDrained`.
    pins_drained = 3,
    /// `lifecycle.waitForPendedPayload`.
    pended_payload = 4,
    /// `lifecycle.retire`'s CAS loop.
    retire_cas = 5,
    /// `lifecycle.beginWaitingClaim{,Pinned}` / `tryPinLive` CAS loops.
    claim_cas = 6,
    /// `scheduler.queueCurrentTeardown`.
    queue_teardown = 7,
    /// Lazy-FPU cross-core flush mailbox.
    fpu_mailbox = 9,
    /// `port.zig` suspend-directive / running-target retry loops.
    suspend_retry = 10,
    /// `secure_slab` gen-lock spins.
    slab_lock = 11,
    /// Generic `SpinLock` acquire.
    spin_lock = 12,
    /// TLB shootdown ack wait.
    shootdown_ack = 13,
    /// `port.zig` remote-directive arm/observe spins.
    directive_spin = 14,
};

pub var site: [MAX_CORES]u16 = [_]u16{0} ** MAX_CORES;
pub var arg: [MAX_CORES]u64 = [_]u64{0} ** MAX_CORES;
pub var iters: [MAX_CORES]u64 = [_]u64{0} ** MAX_CORES;
/// Kernel entries on the scheduler vector (preemption tick + cross-core
/// wake IPI). A frozen counter on a core that is not spinning at an
/// instrumented site means the core is not taking interrupts at all.
/// Zero-sized when `-Dspin_entry_diag` is off.
pub var entries: [if (entry_diag_enabled) MAX_CORES else 0]u64 =
    [_]u64{0} ** (if (entry_diag_enabled) MAX_CORES else 0);

pub const entry_diag_enabled: bool = build_options.kernel_spin_entry_diag;

/// One spin iteration at `s`, waiting on `a`. Relaxed stores: the only
/// reader is the hang dump, which tolerates tearing by design.
pub inline fn note(s: Site, a: u64) void {
    const core: usize = @truncate(arch.smp.coreID());
    if (core >= MAX_CORES) return;
    @atomicStore(u16, &site[core], @intFromEnum(s), .monotonic);
    @atomicStore(u64, &arg[core], a, .monotonic);
    _ = @atomicRmw(u64, &iters[core], .Add, 1, .monotonic);
}

/// One kernel entry on this core. Compiled out entirely (including the
/// `coreID()` read) unless `-Dspin_entry_diag` is set — see the module
/// doc for why this one is gated and `note` is not.
pub inline fn noteEntry() void {
    if (comptime !entry_diag_enabled) return;
    const core: usize = @truncate(arch.smp.coreID());
    if (core >= MAX_CORES) return;
    _ = @atomicRmw(u64, &entries[core], .Add, 1, .monotonic);
}

/// Entry count for `core`, or 0 when the counter is compiled out.
pub inline fn entryCount(core: usize) u64 {
    if (comptime !entry_diag_enabled) return 0;
    if (core >= MAX_CORES) return 0;
    return @atomicLoad(u64, &entries[core], .monotonic);
}

pub fn siteName(s: u16) []const u8 {
    return switch (s) {
        0 => "none",
        1 => "route_retired_wait",
        2 => "await_quiesced",
        3 => "pins_drained",
        4 => "pended_payload",
        5 => "retire_cas",
        6 => "claim_cas",
        7 => "queue_teardown",
        9 => "fpu_mailbox",
        10 => "suspend_retry",
        11 => "slab_lock",
        12 => "spin_lock",
        13 => "shootdown_ack",
        14 => "directive_spin",
        else => "?",
    };
}
