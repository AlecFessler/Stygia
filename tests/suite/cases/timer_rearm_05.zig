// Spec §[timer] timer_rearm — test 05 (degraded smoke for cross-domain
// half).
//
// "[test 05] on success, the calling domain's copy of [1] has
//  `field0 = 0` immediately on return; every other domain-local copy
//  returns 0 from a fresh `sync` within a bounded delay."
//
// Strategy
//   The assertion is in two halves:
//
//     (a) The calling domain's own cap-table slot for the timer
//         handle has `field0 = 0` immediately on return from
//         `timer_rearm`. This half is fully testable in-process: the
//         kernel writes through to the read-only-mapped cap table at
//         `cap_table_base`, and we read it back the instant the
//         syscall returns.
//
//     (b) Every *other* domain-local copy of the same timer handle
//         returns 0 from a fresh `sync` within a bounded delay. This
//         half requires at least two capability domains each holding
//         a copy of the same timer handle. The runner spawns one
//         child capability domain per test ELF (see
//         runner/primary.zig), so there is no second domain to hold
//         a sibling copy from inside this test. The cross-domain
//         half is therefore structurally unreachable from a single
//         test ELF on this branch and is not asserted here.
//
//   To make the (a) half meaningful we drive the timer into a state
//   where field0 is *not* zero before calling `timer_rearm`, then
//   verify the rearm resets it. Sequence:
//
//     1. `timer_arm` with periodic = 1 and a small `deadline_ns` so
//        the kernel will increment field0 in the background.
//     2. Bounded poll on the cap-table slot waiting for
//        `field0 >= 1`. The eager-propagation rule
//        (§[timer] field0: "eagerly propagated to every domain-local
//        copy of the handle") guarantees the kernel writes the
//        increment back to our cap-table slot without us having to
//        call `sync`. Cap on the spin so a slow host doesn't hang
//        the test forever; if the spin exhausts we still proceed —
//        even with field0 = 0 going in, the rearm post-condition
//        (field0 = 0 on return) is still verifiable, just less
//        load-bearing.
//     3. `timer_rearm` on the live timer handle with the same
//        periodic flag. Per the spec sentence above, the calling
//        domain's copy of field0 must read 0 on the very next
//        access.
//     4. Read the cap table and assert field0 == 0.
//
//   For `timer_rearm` itself we want every error path to be
//   unreachable so the success contract is the only path:
//
//     - [1] is the handle returned by step 1's `timer_arm`, valid
//       with `arm` cap set, so tests 01 (BADCAP) and 02 (PERM) cannot
//       fire.
//     - [2] deadline_ns is non-zero, so test 03 cannot fire.
//     - [3] flags has only bit 0 (`periodic`) potentially set; all
//       other bits clear. The handle id syscall slot has its 12-bit
//       id in the low bits and zeros above, so test 04 (reserved
//       bits in [1] or [3]) cannot fire.
//
//   That leaves the success path as the only spec-mandated outcome
//   and the field0 = 0 post-condition as the only thing to check.
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns = ARM_DEADLINE_NS,
//                flags = periodic) — must succeed
//   2. Bounded spin reading cap_table[timer].field0 until it is
//      >= 1 or the spin budget exhausts.
//   3. timer_rearm(timer, deadline_ns = REARM_DEADLINE_NS,
//                  flags = periodic) — must succeed
//   4. readCap(cap_table_base, timer).field0 — must equal 0
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word in vreg 1)
//   2: timer_rearm returned non-OK in vreg 1
//   3: post-rearm field0 is non-zero in the calling domain's
//      cap-table copy (violates the "field0 = 0 immediately on
//      return" half of test 05)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// 1 ms — well above any plausible kernel scheduling granularity yet
// short enough that a periodic timer can plausibly fire while the
// post-arm spin is running.
const ARM_DEADLINE_NS: u64 = 1_000_000;

// 500 ms rearm period. The rearm post-condition checked below is
// "field0 = 0 immediately on return" — a periodic fire that lands
// between the rearm syscall returning and the next user-mode
// `readCap` would race the post-condition observation. On the
// aarch64 Pi 5 KVM runner the per-syscall return path includes a
// kernel-side propagation walk plus user-mode mode switch that can
// span well over 1 ms; smaller rearm periods race and trip
// assertion 3. 500 ms gives ~10× safety margin while still
// exercising the periodic flag's distinct-from-arm-period side.
// Spec §[timer_rearm] pins the reset-to-zero semantics, not the
// absolute period.
const REARM_DEADLINE_NS: u64 = 500_000_000;

// Bound on the post-arm spin. If field0 has not advanced in this
// many iterations, fall back to exercising the "field0 = 0 on rearm
// return" post-condition without a guaranteed pre-rearm increment.
// Keeping the post-condition check unconditional means the test
// still validates rearm's reset-to-0 contract even on a host where
// the timer never fires within the budget.
const POLL_BUDGET: u64 = 1_000_000;

const TIMER_FLAG_PERIODIC: u64 = 1;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bits 0-15 carry the cap bits on
    // the returned timer handle. `arm` is required by timer_rearm
    // (§[timer] timer_rearm cap row), so set it; clear everything
    // else to keep the caps word minimal.
    const timer_caps = caps.TimerCap{ .arm = true };
    const arm_caps_word: u64 = @as(u64, timer_caps.toU16());

    const arm_result = syscall.timerArm(
        arm_caps_word,
        ARM_DEADLINE_NS,
        TIMER_FLAG_PERIODIC,
    );
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // Bounded spin waiting for a fire to bump field0. The kernel
    // eagerly propagates increments to this domain's cap-table slot
    // (§[timer] field0 row), so a successful fire is observable
    // here without an explicit `sync`. If the budget exhausts the
    // post-condition check below still validates rearm's reset
    // contract; we simply lose the "transitions non-zero -> zero"
    // observation.
    var spin: u64 = 0;
    while (spin < POLL_BUDGET) {
        const observed = caps.readCap(cap_table_base, timer_handle);
        if (observed.field0 >= 1) break;
        spin += 1;
    }

    const rearm_result = syscall.timerRearm(
        timer_handle,
        REARM_DEADLINE_NS,
        TIMER_FLAG_PERIODIC,
    );
    if (rearm_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // §[timer] timer_rearm test 05 (calling-domain half): the
    // caller's cap-table copy must read field0 = 0 on the very next
    // access after the syscall returns. The kernel writes through
    // the read-only-mapped cap table as part of the syscall return
    // path; reading it here samples that authoritative post-rearm
    // state.
    const cap = caps.readCap(cap_table_base, timer_handle);
    if (cap.field0 != 0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
