// Spec §[timer] timer_rearm — test 03.
//
// "[test 03] returns E_INVAL if [2] deadline_ns is 0."
//
// Strategy
//   `timer_rearm` rejects a zero deadline regardless of any other
//   property of the call. To isolate that single check we must make
//   every other check pass:
//     - [1] must be a valid timer handle (so no E_BADCAP, test 01)
//     - [1] must carry the `arm` cap            (so no E_PERM,   test 02)
//     - reserved bits in [1] and [3] must be 0  (so no E_INVAL,  test 04)
//   That leaves the deadline check as the only spec-mandated failure
//   path.
//
//   Setup mints a fresh timer via `timer_arm` with caps {arm}. A
//   one-shot timer with a long deadline is convenient — it stays armed
//   until cancellation, but its arm state is irrelevant to test 03
//   because §[timer_rearm] explicitly notes the call "[w]orks regardless
//   of whether the timer was armed or disarmed at call time."
//
//   The rearm call then passes `deadline_ns = 0` with a clean flags word
//   (all bits clear, including bit 0 periodic). The kernel must surface
//   E_INVAL.
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns=1_000_000_000, flags=0)
//      — must succeed, returning a timer handle word
//   2. timer_rearm(handle, deadline_ns=0, flags=0)
//      — must return E_INVAL
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word)
//   2: timer_rearm with deadline_ns=0 returned something other than
//      E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const tcaps = caps.TimerCap{ .arm = true };
    const arm_caps_word: u64 = @as(u64, tcaps.toU16());
    const armed = syscall.timerArm(arm_caps_word, 1_000_000_000, 0);
    if (testing.isHandleError(armed.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(armed.v1 & 0xFFF);

    const r = syscall.timerRearm(timer_handle, 0, 0);
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
