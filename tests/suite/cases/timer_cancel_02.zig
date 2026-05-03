// Spec §[timer_cancel] — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `cancel` cap."
//
// Strategy
//   Mint a fresh timer via `timer_arm` with cap word containing `arm`
//   but NOT `cancel`. The resulting handle is valid and currently
//   armed (so [test 01] E_BADCAP and [test 03] E_INVAL on arm=0 do
//   not pre-empt the cancel-cap gate), reserved bits are clean, and
//   the only thing that can fail the call is the missing `cancel`
//   cap. `timer_cancel` must therefore return E_PERM rather than
//   succeeding or returning a different error.
//
//   The runner spawns each test inside a capability domain whose
//   self-handle has the `timer` cap, so `timer_arm` itself succeeds
//   (gated by §[timer_arm] [test 01]). `restart_policy` is left clear
//   so the runner's `tm_restart_max` ceiling does not interact with
//   the call (see §[timer_arm] [test 02] / restart_semantics_08).
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns=1_000_000_000, flags=0)
//      — must succeed; deadline is long enough that the one-shot
//        does not fire during the test body.
//   2. timer_cancel(timer_handle)              — must return E_PERM
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word in vreg 1)
//   2: timer_cancel returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[timer] timer cap bits: bit 2 = arm, bit 3 = cancel. Set arm
    // only — the resulting handle can be `timer_rearm`'d but not
    // `timer_cancel`'d, isolating the cancel-cap gate.
    const timer_caps = caps.TimerCap{ .arm = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // deadline_ns must be nonzero (§[timer_arm] [test 03]); pick a
    // value comfortably larger than the test runtime so the one-shot
    // does not fire and auto-clear `field1.arm` before the cancel
    // call observes the cap-gate. flags = 0 = one-shot.
    const deadline_ns: u64 = 1_000_000_000;
    const flags: u64 = 0;

    const arm_result = syscall.timerArm(caps_word, deadline_ns, flags);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    const cancel_result = syscall.timerCancel(timer_handle);
    if (cancel_result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
