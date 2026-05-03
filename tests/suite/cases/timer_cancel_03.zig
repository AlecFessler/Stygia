// Spec §[timer] timer_cancel — test 03.
//
// "[test 03] returns E_INVAL if [1].field1.arm = 0."
//
// Strategy
//   §[timer_cancel]: "Disarms a timer. Returns an error if the timer
//   is not currently armed (e.g., a one-shot that already fired, or
//   one already cancelled). Sets `field0` to `u64::MAX`, sets
//   `field1.arm = 0`, and wakes futex waiters."
//
//   The cleanest way to drive `field1.arm = 0` from userspace without
//   waiting on a one-shot's deadline is to cancel the timer once
//   (which the spec defines as the operation that flips arm to 0)
//   and then call cancel again on the same handle. The second call
//   sees `field1.arm = 0` and must return E_INVAL.
//
//   Setup mints a periodic timer with caps {arm, cancel}: periodic so
//   the only path to `arm = 0` in this test is the explicit cancel
//   we issue below, and {arm, cancel} so subsequent cancel calls pass
//   the §[timer_cancel] cap gate. `restart_policy` stays cleared so
//   the runner's `tm_restart_max = 1` ceiling is irrelevant.
//
//   `deadline_ns` is set well past the test's lifetime so the periodic
//   fire path can't race ahead of our second cancel and re-arm /
//   alter `field1` semantics; the spec defines arm transitions only
//   via timer_arm/timer_rearm/timer_cancel and the one-shot fire
//   path, none of which run between our two cancel calls.
//
// Action
//   1. timer_arm(caps={arm, cancel}, deadline_ns=large, flags=periodic)
//      — mint a periodic timer; must succeed (handle returned in v1).
//   2. timer_cancel(handle) — first cancel; must return OK and set
//      field1.arm to 0.
//   3. timer_cancel(handle) — second cancel; the precondition
//      `field1.arm = 0` now holds, so the kernel must return E_INVAL.
//
// Assertions
//   1: timer_arm setup failed (vreg 1 carried an error code instead
//      of a handle).
//   2: first cancel did not return OK.
//   3: second cancel did not return E_INVAL (the spec assertion
//      under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // Periodic so arm only flips to 0 via our explicit cancel, with a
    // deadline far past the test's lifetime so a fire cannot interleave
    // between the two cancels.
    const deadline_ns: u64 = 1_000_000_000_000;
    const flags: u64 = 1; // periodic

    const arm_result = syscall.timerArm(caps_word, deadline_ns, flags);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    const first_cancel = syscall.timerCancel(timer_handle);
    if (first_cancel.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const second_cancel = syscall.timerCancel(timer_handle);
    if (second_cancel.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
