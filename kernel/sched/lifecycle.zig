//! Phase-2 EC lifecycle SHADOW OBSERVER — `docs/kernel/systems.md` rev 7.
//!
//! This module implements the systems.md §2.1 seven-state lifecycle word and
//! the §5 edge table as an **additive observer** running alongside today's
//! eight overlapping lifecycle signals (`State`, `on_cpu`, gen parity,
//! `current_queue_core`, `last_dispatched_core`, the referenced-by set,
//! `suspend_port`, `pending_reply_holder`). It DELETES NOTHING and it
//! ARBITRATES NOTHING: today's signals remain the sole authority over what
//! the kernel actually does. The shadow word is written alongside them and
//! read only by the assertions below.
//!
//! The point is measurement. A TLA+ model of the target machine is green;
//! what the model cannot see is 4-core hardware timing — torn reads, cache
//! coherence, real preemption. So: re-encode today's transition SITES into
//! the target machine's vocabulary, run the full suite, and find out whether
//! the sequence of transitions the real kernel performs is a walk on the
//! model's edge graph. Silence means Phase 3 is a refactor toward a proven
//! target. Noise means we get the divergence list, with sites, BEFORE
//! anything is deleted.
//!
//! ## Why this is not simply a copy of `ec.state`
//!
//! Three of the seven target states have no representation in today's tree:
//!
//!   * `parking` — today's park publishes the wait state in ONE store; the
//!     "published but the owner core is still on the kstack" window is
//!     signalled only by `on_cpu` staying true.
//!   * `claimed` — `tryClaimWake` stamps `.ready` at the claim, so the
//!     claim→enqueue window is a `.ready` EC that is in no queue.
//!   * `pended` — does not exist; a claimant that finds its target mid-park
//!     SPINS on `on_cpu` instead of handing placement to the owner's hop.
//!
//! and today's three wait states collapse into `waiting` (§2.6). So the
//! shadow is driven by SITE, not by value: each instrumented site declares
//! which §5 edge it is performing. See the map in the Phase 2 notes.
//!
//! ## Not-a-panic, by design
//!
//! A panic costs a whole boot to learn one fact. Instead every check
//! accumulates into a per-kind counter plus a bounded ring of the first
//! `RING_CAPACITY` occurrences, and the full 8x8 transition census is kept
//! so legal traffic is quantified alongside the illegal. `dump()` prints the
//! profile at the end of a run (wired into the `power_shutdown`/`power_reboot`
//! syscall, which is how the in-kernel test runner terminates a boot). One
//! boot yields a complete divergence profile.
//!
//! ## Memory ordering
//!
//! `observe()` is a single `.acq_rel` read-modify-write (`@atomicRmw .Xchg`)
//! on the shadow byte. RMW rather than load+store is deliberate and is the
//! one ordering decision worth arguing:
//!
//!   * It cannot lose. A CAS-based observer would have a failure arm, and
//!     an observer whose failure arm is itself a race is useless — the
//!     recorded (from, to) pair must be the pair that actually happened in
//!     the coherence order of the shadow byte, not the pair some core hoped
//!     for. `Xchg` linearizes: N concurrent observers of one EC produce N
//!     records whose `from` values chain exactly, so a divergence report
//!     names a real ordering the hardware produced.
//!   * `acquire` on the RMW so this core sees the writes the previous
//!     transition's owner made before its own `observe` (payload staging,
//!     container links) — without it a cross-check could read a torn
//!     descriptor and report a phantom.
//!   * `release` on the RMW so the same holds for the next observer.
//!
//! The shadow therefore introduces no race of its own: it is one more
//! release/acquire chain over a byte that nothing else reads. It does add
//! one RMW per transition in Debug builds, which is the whole cost.
//!
//! ## Debug gating
//!
//! `enabled` follows the tree's existing idiom (`utils/sync/debug.zig`'s
//! `active`): Debug builds only, host tests excluded. The kernel's default
//! optimize mode is `.Debug` (root `build.zig`) except under
//! `-Dkernel_profile=trace`, which selects `.ReleaseFast` — so the perf
//! stage of the gauntlet runs with the observer fully compiled out and is
//! unaffected. Every entry point below is `if (!enabled) return;` first, so
//! a release build contains no shadow stores at all.

const builtin = @import("builtin");
const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;

/// Master gate. Debug builds only; host `zig test` excluded (the pure logic
/// is exercised by the kernel suite, and `is_test` builds have no arch
/// dispatch to print through).
pub const enabled = builtin.mode == .Debug and !builtin.is_test;

// ── The lifecycle word (§2.1) ────────────────────────────────────────

/// The target machine's seven states, plus `absent`.
///
/// `absent` is NOT one of §2.1's states. It is the sentinel for "outside
/// the machine": a slab-private slot before edge 1's publish, and a freed
/// slot after edge 10. It is deliberately value 0 so that the slab's
/// zero-on-free leaves every recycled slot correctly outside the machine
/// without an explicit reset — see `allocExecutionContext`'s "slab zeroes
/// every byte except `_gen_lock`" contract.
pub const State = enum(u8) {
    absent = 0,
    ready = 1,
    running = 2,
    parking = 3,
    waiting = 4,
    claimed = 5,
    pended = 6,
    retired = 7,
};

const STATE_COUNT = 8;

fn bit(s: State) u8 {
    return @as(u8, 1) << @as(u3, @intCast(@intFromEnum(s)));
}

/// The §5 transition table, as a per-from-state bitmask of legal to-states.
/// Absent rows are illegal — §5: "Absent rows are illegal (debug assert on
/// every CAS)". This is the comptime mirror §9.1 asks for.
const legal_to: [STATE_COUNT]u8 = blk: {
    var t = [_]u8{0} ** STATE_COUNT;
    // edge 1 — creation publish (into `ready`, or `waiting` for a
    // born-suspended vCPU).
    t[@intFromEnum(State.absent)] = bit(.ready) | bit(.waiting);
    // edge 2 — dispatch; 5c — claim of a ready target; 9 — retire.
    t[@intFromEnum(State.ready)] = bit(.running) | bit(.claimed) | bit(.retired);
    // edge 3 — park; 9 — retire. NOTE: no `running -> ready` edge exists
    // (§5 notes), and `running` is unclaimable except by retire (§2.1).
    t[@intFromEnum(State.running)] = bit(.parking) | bit(.retired);
    // edge 4 — hop commit; 5b — claim of a mid-park target; 8 — requeue
    // placement at the hop; 9 — retire.
    t[@intFromEnum(State.parking)] = bit(.waiting) | bit(.pended) | bit(.ready) | bit(.retired);
    // edge 5a — claim; 9 — retire.
    t[@intFromEnum(State.waiting)] = bit(.claimed) | bit(.retired);
    // edge 6 — placement; 7 — re-containment; 9 — retire.
    t[@intFromEnum(State.claimed)] = bit(.ready) | bit(.waiting) | bit(.retired);
    // edge 6p — placement by the owner core's hop; 9 — retire.
    t[@intFromEnum(State.pended)] = bit(.ready) | bit(.retired);
    // edge 10 — finalize.
    t[@intFromEnum(State.retired)] = bit(.absent);
    break :blk t;
};

/// Which §5 edge a (from, to) pair names, for the census printout. Returns
/// `null` for pairs the table forbids.
fn edgeName(from: State, to: State) ?[]const u8 {
    return switch (from) {
        .absent => switch (to) {
            .ready => "1",
            .waiting => "1'",
            else => null,
        },
        .ready => switch (to) {
            .running => "2",
            .claimed => "5c",
            .retired => "9",
            else => null,
        },
        .running => switch (to) {
            .parking => "3",
            .retired => "9",
            else => null,
        },
        .parking => switch (to) {
            .waiting => "4",
            .pended => "5b",
            .ready => "8",
            .retired => "9",
            else => null,
        },
        .waiting => switch (to) {
            .claimed => "5a",
            .retired => "9",
            else => null,
        },
        .claimed => switch (to) {
            .ready => "6",
            .waiting => "7",
            .retired => "9",
            else => null,
        },
        .pended => switch (to) {
            .ready => "6p",
            .retired => "9",
            else => null,
        },
        .retired => switch (to) {
            .absent => "10",
            else => null,
        },
    };
}

// ── Instrumented sites ───────────────────────────────────────────────

/// Every instrumented transition site, one tag each. Keep the names short —
/// they are printed verbatim in the divergence records.
pub const Site = enum(u8) {
    /// Only ever the `Record` default; never passed to `observe`.
    unknown,
    // edge 2
    dispatch_commit,
    // edge 3
    park_port,
    park_recv,
    park_futex_val,
    park_futex_chg,
    park_port_remote,
    park_idle,
    requeue_park,
    // edge 3 undo arms (no doc edge — see the map)
    futex_nomem_undo,
    // edge 4 / 8 — the hop
    hop_dispatch,
    hop_park_run,
    hop_post_park,
    hop_faulted,
    // edges 5a/5b/5c — claims
    claim_mark_ready,
    claim_futex_wake,
    claim_futex_expire,
    claim_recv_expire,
    claim_port_closed,
    claim_suspend_ready,
    // edges 6 / 6p / 8
    enqueue_place,
    requeue_place,
    // edge 7
    repin_suspend,
    // edge 9
    retire_faulted,
    retire_terminate,
    retire_destroy,
    // edge 10
    finalize,
};

// ── Violation kinds ──────────────────────────────────────────────────

pub const Kind = enum(u8) {
    /// The headline check (§9.2 "transition legality on every CAS"): an
    /// observed (from, to) pair that no §5 edge permits.
    illegal_edge,
    /// S3 half: the shadow says the EC is kstack-quiescent
    /// (`ready`/`waiting`/`claimed`) but `on_cpu` is still set. "Claimable
    /// ⇒ kstack-quiescent" (§4).
    quiescent_on_cpu,
    /// The shadow and today's `State` enum disagree under the §0
    /// correspondence (systems.md §2.6's mapping).
    legacy_mismatch,
    /// A wake claim whose from-state is `running`. §2.1: `running` is
    /// unclaimable except by retire; §5: no `running -> ready` edge.
    claim_of_running,
    /// Dispatch commit (edge 2) against a shadow-`retired` EC.
    dispatch_of_retired,
    /// Placement into `ready` (edge 6/6p/8) that did not leave the EC
    /// linked in a run queue — §9.2 "Into `ready` ⇒ linked in the same
    /// section".
    place_unlinked,
    /// Placement into `ready` from `ready`: a second placement of an
    /// already-placed EC (the double-enqueue shape S8 forbids).
    place_from_ready,
    /// The hop's outgoing state is not one of {parking, pended, retired}
    /// (§9.2). `claimed` here is specifically asserted unreachable in §4.
    hop_bad_outgoing,
    /// Finalize (edge 10) while some core's `current_ec` still names the
    /// EC — §9.2's 64-way `current` scan.
    finalize_referenced,
    /// Retire (edge 9) of an EC that never entered the machine, or a
    /// second retire of the same EC.
    retire_of_absent,
    /// The shadow byte read outside the enum range — either memory
    /// corruption or a slot recycled under an in-flight observer.
    shadow_out_of_range,
};

const KIND_COUNT = @typeInfo(Kind).@"enum".fields.len;

// ── The violation profile ────────────────────────────────────────────

/// Ring slots reserved per violation kind.
///
/// A flat first-N ring is the wrong shape here: several of the checks below
/// are expected to fire *structurally* (today's requeue makes an EC
/// claimable while its owner core is still on its kstack — that is what
/// `on_cpu` exists to paper over), so a flat ring would fill entirely with
/// one kind's first 96 hits and the rare, interesting kinds would never be
/// sampled at all. Per-kind reservation guarantees a head sample of every
/// kind that fires. The counters are unbounded regardless, so the profile's
/// magnitudes are never truncated — only the traces are.
pub const RING_PER_KIND: usize = 8;

/// Total ring capacity. `RING_PER_KIND` x kinds, ~24 B per record.
pub const RING_CAPACITY: usize = RING_PER_KIND * KIND_COUNT;

pub const Record = struct {
    /// Monotonic sequence number of this record across all cores.
    seq: u32 = 0,
    /// Low 32 bits of the EC pointer. The slab slot stride is fixed, so
    /// this is a stable per-slot identity for the life of a boot; equal
    /// ids across records mean the same slot (possibly recycled).
    ec_id: u32 = 0,
    kind: Kind = .illegal_edge,
    site: Site = .unknown,
    /// For `illegal_edge`: the observed from-state. For the cross-checks:
    /// the shadow state at the time of the check.
    from: State = .absent,
    /// For `illegal_edge`: the attempted to-state. For the cross-checks:
    /// the state the other signal implied.
    to: State = .absent,
    core: u8 = 0xFF,
    /// Kind-specific extra: today's `State` tag for `legacy_mismatch`,
    /// `on_cpu` for the S3 checks, `current_queue_core` for
    /// `place_unlinked`.
    extra: u8 = 0,
};

/// Per-kind counters. Monotonic RMW — a plain `+=` raced by four cores
/// loses increments, and the whole deliverable is the counts.
var counts: [KIND_COUNT]u64 align(64) = [_]u64{0} ** KIND_COUNT;

/// The full observed transition census, legal and illegal. `census[f][t]`
/// counts observed transitions from `f` to `t`. This is what quantifies the
/// legal traffic a divergence has to be read against — an illegal edge seen
/// 3 times out of 400 000 transitions is a different finding from one seen
/// 200 000 times.
var census: [STATE_COUNT][STATE_COUNT]u64 align(64) =
    [_][STATE_COUNT]u64{[_]u64{0} ** STATE_COUNT} ** STATE_COUNT;

/// Informational counters — NOT violations. These are the direct
/// measurements the model cannot make.
pub const Counter = enum(u8) {
    /// Edge 5b actually fired: a claimant found its target mid-park.
    /// This is the population `pended` exists to serve.
    claim_found_parking,
    /// A claimant entered today's `on_cpu` spin (i.e. it waited on
    /// scheduler progress — the X2 shape the target machine deletes).
    oncpu_spin_entered,
    /// Hop commits observed.
    hop_commits,
    /// Total observed transitions.
    transitions,
};
const COUNTER_COUNT = @typeInfo(Counter).@"enum".fields.len;
var info: [COUNTER_COUNT]u64 align(64) = [_]u64{0} ** COUNTER_COUNT;

var ring: [RING_CAPACITY]Record = [_]Record{.{}} ** RING_CAPACITY;
/// Per-slot publication flag, `.release`-stored after the record's bytes
/// land so `dump()`'s `.acquire` read never prints a half-built row.
var ring_filled: [RING_CAPACITY]bool = [_]bool{false} ** RING_CAPACITY;

pub fn bumpCounter(c: Counter) void {
    if (!enabled) return;
    _ = @atomicRmw(u64, &info[@intFromEnum(c)], .Add, 1, .monotonic);
}

fn record(
    kind: Kind,
    site: Site,
    ec_id: u32,
    from: State,
    to: State,
    extra: u8,
) void {
    // Pre-increment value is this occurrence's 0-based index within its
    // kind, which is exactly the "first N per kind" predicate.
    const seq = @atomicRmw(u64, &counts[@intFromEnum(kind)], .Add, 1, .monotonic);
    if (seq >= RING_PER_KIND) return;
    const idx = @intFromEnum(kind) * RING_PER_KIND + @as(usize, @intCast(seq));
    ring[idx] = .{
        .seq = @truncate(seq),
        .ec_id = ec_id,
        .kind = kind,
        .site = site,
        .from = from,
        .to = to,
        .core = @truncate(arch.smp.coreID()),
        .extra = extra,
    };
    // Publish the row. `filled` is only ever read by `dump()` after the
    // system has quiesced, but the release pairs with its acquire so a
    // half-written row can never be printed.
    @atomicStore(bool, &ring_filled[idx], true, .release);
}

// ── EC identity ──────────────────────────────────────────────────────

/// Stable per-boot identity for an EC. The slab lays slots out at a fixed
/// stride from one base, so the low 32 bits of the pointer identify the
/// slot uniquely within a boot without taking any slab lock (which an
/// observer running inside a claim CAS must not do).
pub fn ecId(ptr: *const anyopaque) u32 {
    return @truncate(@intFromPtr(ptr));
}

// ── The observer ─────────────────────────────────────────────────────

/// Read the shadow word without transitioning.
pub fn peek(word: *const std.atomic.Value(u8)) State {
    if (!enabled) return .absent;
    const raw = word.load(.acquire);
    if (raw >= STATE_COUNT) return .absent;
    return @enumFromInt(raw);
}

/// Perform a shadow transition to `to` and check it against §5.
///
/// Returns the from-state, so a caller that must branch on the claim's
/// origin (5a vs 5b) can do so without a second read. Never fails, never
/// spins, never allocates, takes no lock: legal from any context including
/// interrupt handlers holding container locks.
pub fn observe(
    word: *std.atomic.Value(u8),
    ec_id: u32,
    to: State,
    site: Site,
) State {
    if (!enabled) return .absent;
    const raw = @atomicRmw(u8, &word.raw, .Xchg, @intFromEnum(to), .acq_rel);
    if (raw >= STATE_COUNT) {
        record(.shadow_out_of_range, site, ec_id, .absent, to, raw);
        return .absent;
    }
    const from: State = @enumFromInt(raw);
    _ = @atomicRmw(
        u64,
        &census[@intFromEnum(from)][@intFromEnum(to)],
        .Add,
        1,
        .monotonic,
    );
    _ = @atomicRmw(u64, &info[@intFromEnum(Counter.transitions)], .Add, 1, .monotonic);
    if ((legal_to[@intFromEnum(from)] & bit(to)) == 0) {
        record(.illegal_edge, site, ec_id, from, to, 0);
    }
    return from;
}

/// Report a cross-check failure between the shadow and one of today's
/// signals. `shadow` is what the shadow said; `implied` is what the other
/// signal implied.
pub fn flag(
    kind: Kind,
    site: Site,
    ec_id: u32,
    shadow: State,
    implied: State,
    extra: u8,
) void {
    if (!enabled) return;
    record(kind, site, ec_id, shadow, implied, extra);
}

// ── Report ───────────────────────────────────────────────────────────

/// Print the divergence profile. Called from the `power_shutdown` /
/// `power_reboot` syscall path, which is how the in-kernel test runner ends
/// a boot; safe to call more than once (idempotent, read-only).
///
/// Prefix is `[lifecycle]` — deliberately distinct from `[runner]`,
/// `[KPROF]`, and every pattern `tests/precommit.sh`'s
/// `verify_no_kernel_faults` greps for, so a fat divergence list never
/// masquerades as a stage failure.
pub fn dump() void {
    if (!enabled) return;

    arch.boot.print("[lifecycle] begin rev7-shadow\n", .{});

    const total = @atomicLoad(u64, &info[@intFromEnum(Counter.transitions)], .monotonic);
    arch.boot.print("[lifecycle] transitions={d} hop_commits={d} claim_found_parking={d} oncpu_spin_entered={d}\n", .{
        total,
        @atomicLoad(u64, &info[@intFromEnum(Counter.hop_commits)], .monotonic),
        @atomicLoad(u64, &info[@intFromEnum(Counter.claim_found_parking)], .monotonic),
        @atomicLoad(u64, &info[@intFromEnum(Counter.oncpu_spin_entered)], .monotonic),
    });

    // Census: every non-zero cell, tagged with its §5 edge or ILLEGAL.
    inline for (@typeInfo(State).@"enum".fields) |ff| {
        inline for (@typeInfo(State).@"enum".fields) |tf| {
            const n = @atomicLoad(u64, &census[ff.value][tf.value], .monotonic);
            if (n != 0) {
                const from: State = @enumFromInt(ff.value);
                const to: State = @enumFromInt(tf.value);
                if (edgeName(from, to)) |e| {
                    arch.boot.print("[lifecycle] census {s}->{s} n={d} edge={s}\n", .{
                        ff.name, tf.name, n, e,
                    });
                } else {
                    arch.boot.print("[lifecycle] census {s}->{s} n={d} edge=ILLEGAL\n", .{
                        ff.name, tf.name, n,
                    });
                }
            }
        }
    }

    var any: bool = false;
    inline for (@typeInfo(Kind).@"enum".fields) |kf| {
        const n = @atomicLoad(u64, &counts[kf.value], .monotonic);
        if (n != 0) {
            any = true;
            arch.boot.print("[lifecycle] violation {s} n={d}\n", .{ kf.name, n });
        }
    }
    if (!any) arch.boot.print("[lifecycle] violation NONE\n", .{});

    arch.boot.print("[lifecycle] first {d} occurrences per kind:\n", .{RING_PER_KIND});
    var i: usize = 0;
    while (i < RING_CAPACITY) : (i += 1) {
        if (!@atomicLoad(bool, &ring_filled[i], .acquire)) continue;
        const r = ring[i];
        arch.boot.print(
            "[lifecycle]   #{d} core={d} kind={s} site={s} ec={x} from={s} to={s} extra={d}\n",
            .{
                r.seq,
                r.core,
                @tagName(r.kind),
                @tagName(r.site),
                r.ec_id,
                @tagName(r.from),
                @tagName(r.to),
                r.extra,
            },
        );
    }
    arch.boot.print("[lifecycle] end\n", .{});
}
