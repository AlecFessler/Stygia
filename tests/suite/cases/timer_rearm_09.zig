// Spec §[timer] timer_rearm — test 09.
//
// "[test 09] `timer_rearm` called on a currently-armed timer replaces
//  the prior configuration; the prior pending fire does not occur and
//  field0 reflects the reset to 0 rather than any partial fire."
//
// DEGRADED SMOKE VARIANT
//
//   The faithful test has two halves: (a) the immediate post-rearm
//   state — field0 must be 0 with the new config installed — and (b)
//   the no-fire-from-prior-config invariant — across the original
//   deadline window, field0 must remain 0 (specifically: the prior
//   one-shot's pending fire must not increment the counter, even
//   transiently, before the new deadline elapses).
//
//   Half (b) needs a bounded-delay timing primitive the test can spin
//   against to confirm the prior deadline window has elapsed without
//   firing. The v0 test child has no wall-clock IDC service, no
//   wired-up `time_monotonic`, and the runner exposes no harness-side
//   timing bound. The closest available shape would be to spin on
//   `time_monotonic` until two prior `deadline_ns` worth of nanoseconds
//   have elapsed, then read field0; without a kernel-side
//   time_monotonic implementation surfaced through the test child, that
//   path is not reachable yet.
//
//   Half (a) is fully observable from the v0 child: §[timer_rearm]
//   line 2298 specifies that timer_rearm "Resets `field0` to 0, sets
//   `field1.arm = 1`, sets `field1.pd = [3].periodic`", and test 05
//   confirms "the calling domain's copy of [1] has `field0 = 0`
//   immediately on return". That immediate-state half is exactly what
//   distinguishes test 09 from test 07 (which checks the post-rearm
//   fire) — test 09 says the *prior pending fire* must be cancelled
//   and field0 must read 0 (i.e., not 1 from a partial fire). We can
//   exercise that half by:
//
//     1. Arming a one-shot timer with a deadline_ns large enough that
//        the kernel will not have fired it during the test prelude
//        (1 second — well above the latency of two consecutive
//        syscalls in this child).
//     2. Calling timer_rearm before that deadline elapses, with a new
//        one-shot configuration.
//     3. Reading field0 from the calling domain's handle table copy
//        immediately after the rearm returns, confirming it is 0 — not
//        1 from a partial fire that the kernel might have leaked
//        through the rearm transition.
//     4. Reading field1.arm == 1 to confirm the new config is armed
//        (rather than the prior one-shot having fired-then-cleared
//        before the rearm took effect).
//
//   Half (b) — that no fire from the prior pending deadline can be
//   observed across the original-deadline window — is left as a
//   reservation. When time_monotonic (or a similar bounded-delay
//   harness primitive) lands in the v0 child, replace the smoke body
//   with: arm short, rearm long, spin on time_monotonic past the
//   short deadline (but not past the long), assert field0 still 0.
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns=1_000_000_000, flags=0)
//        — mint a one-shot timer with a 1-second deadline. The arm
//          cap is required so we can rearm; cancel is omitted because
//          we don't need it for this test path.
//   2. readCap(timer) — sanity-check the post-arm field0 is 0 and
//        field1.arm is 1, so any later non-zero field0 is unambiguously
//        attributable to the rearm transition (not to a stale slot).
//   3. timer_rearm(timer, deadline_ns=2_000_000_000, flags=0) — replace
//        the prior config with a one-shot at 2 seconds. The original
//        1-second deadline is still pending at this point; the rearm
//        must cancel it.
//   4. readCap(timer) — assert field0 == 0 and field1.arm == 1 and
//        field1.pd == 0 (one-shot per [3].periodic = 0).
//
// Assertions
//   1: setup — timer_arm returned an error word in vreg 1
//   2: setup — post-arm field0 was non-zero (an arm-time partial fire
//      or stale slot would invalidate the rearm-time observation)
//   3: setup — post-arm field1.arm was 0 (the kernel did not leave the
//      handle armed; nothing for rearm to cancel)
//   4: timer_rearm returned a non-OK code in vreg 1
//   5: post-rearm field0 != 0 — a partial fire from the prior
//      configuration leaked through the rearm transition (the spec
//      assertion under test)
//   6: post-rearm field1.arm != 1 — the new config did not take effect
//   7: post-rearm field1.pd != 0 — the new config's periodic bit did
//      not match flags = 0 (one-shot)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: arm cap is required for the
    // subsequent timer_rearm to succeed. restart_policy is left clear
    // so the runner's restart_policy_ceiling never gates us.
    const timer_caps = caps.TimerCap{ .arm = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // Prior deadline: 1 second. Large enough that the prior one-shot
    // is still pending when we issue timer_rearm a few syscalls later.
    const prior_deadline_ns: u64 = 1_000_000_000;
    // Flags = 0 → periodic bit clear → one-shot. The prior pending
    // fire is what test 09's invariant is about.
    const prior_flags: u64 = 0;

    const arm_result = syscall.timerArm(caps_word, prior_deadline_ns, prior_flags);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // §[timer] field0 = counter, field1 bit 0 = arm. Test 06 of
    // timer_arm pins field0 = 0 and field1.arm = 1 immediately after
    // a successful arm; we read those here so that the post-rearm
    // comparison is anchored to a known initial state.
    const post_arm = caps.readCap(cap_table_base, timer_handle);
    if (post_arm.field0 != 0) {
        testing.fail(2);
        return;
    }
    if ((post_arm.field1 & 0x1) != 1) {
        testing.fail(3);
        return;
    }

    // New deadline: 2 seconds. The prior 1-second one-shot is still
    // pending when this call lands; per [test 09] it must be cancelled
    // and field0 must read 0 — not 1 from any partial fire.
    const new_deadline_ns: u64 = 2_000_000_000;
    const new_flags: u64 = 0;

    const rearm_result = syscall.timerRearm(timer_handle, new_deadline_ns, new_flags);
    if (rearm_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // The core spec assertion of test 09: field0 must read 0 from the
    // calling domain's copy immediately on return. Any non-zero value
    // here would indicate a partial fire from the prior configuration
    // leaking through the rearm transition.
    const post_rearm = caps.readCap(cap_table_base, timer_handle);
    if (post_rearm.field0 != 0) {
        testing.fail(5);
        return;
    }
    if ((post_rearm.field1 & 0x1) != 1) {
        testing.fail(6);
        return;
    }
    if ((post_rearm.field1 & 0x2) != 0) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
