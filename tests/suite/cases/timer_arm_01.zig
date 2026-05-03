// Spec §[timer_arm] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `timer`."
//
// Spec semantics
//   §[timer_arm]: "Self-handle cap required: `timer`."
//   §[restrict]: "Reduces the caps on a handle in place. The new caps
//   must be a subset of the current caps. No self-handle cap is
//   required — reducing authority never requires authority." Restrict
//   on the self-handle is a legal way for a domain to drop bits from
//   its own SelfCap.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `timer` (see runner/primary.zig — the child
//   needs `timer` to construct timer handles tested elsewhere in the
//   suite). To exercise the missing-`timer` failure path, the test
//   itself must drop `timer` from its self-handle before calling
//   timer_arm.
//
//   `restrict` lets a domain reduce its own SelfCap caps in place.
//   The new caps must be a bitwise subset of the current caps, so we
//   compute the reduced SelfCap by copying the runner's grant and
//   clearing only the `timer` bit. All other bits remain set, so the
//   subset check passes and the only behavioural change is `timer`
//   becoming 0. After the restrict succeeds, timer_arm must return
//   E_PERM per the cap-required rule.
//
// Action
//   1. restrict(SLOT_SELF, runner_caps_minus_timer) — must succeed.
//   2. timer_arm(caps=TimerCap{}, deadline_ns=1, flags=0)
//      — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-zero error word (failed to drop timer).
//   2: timer_arm returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mirror runner/primary.zig's child_self grant exactly, with
    // `timer` cleared. Every other bit must stay set so the bitwise
    // subset check in `restrict` (§[restrict] test 02) accepts the
    // reduction. `pri` is a 2-bit numeric field on SelfCap; restrict's
    // bitwise subset rule applies to it as well, so we keep pri = 3
    // (matching the runner).
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = false, // <-- the bit under test
        .pri = 3,
    };

    const restrict_result = syscall.restrict(
        caps.SLOT_SELF,
        @as(u64, reduced.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // §[timer] TimerCap layout: move/copy/arm/cancel/restart_policy
    // are all clean bits with the rest reserved. The cap check in
    // timer_arm is gated on the self-handle's `timer` bit and runs
    // before any other validation (deadline_ns, reserved-bit checks),
    // so neither E_INVAL on deadline nor on reserved bits can preempt
    // it. We pass deadline_ns = 1 (non-zero) and flags = 0 to keep all
    // other inputs valid; with `timer` cleared the kernel must
    // short-circuit to E_PERM.
    const timer_caps = caps.TimerCap{};
    const result = syscall.timerArm(
        @as(u64, timer_caps.toU16()),
        1,
        0,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
