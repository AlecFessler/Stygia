// Spec §[timer] timer_cancel — test 06.
//
// "[test 06] on success, [1].field1.arm becomes 0."
//
// Strategy
//   Mint a periodic timer with caps {arm, cancel} and a far-future
//   deadline so it does not fire during the test. timer_arm establishes
//   field1.arm = 1 (timer_arm test 06). Cancelling the timer must flip
//   field1.arm to 0 in the calling domain's cap table snapshot.
//
//   §[timer]: field1.arm is "kernel-mutable, sync-refreshed". The
//   handle table is mapped read-only into the holding domain at
//   `cap_table_base`, and timer_cancel writes the calling domain's
//   copy as part of completing the call (cf. timer_cancel test 05's
//   "calling domain's copy of [1] has `field0 = u64::MAX` immediately
//   on return"). A direct readCap after the syscall is therefore
//   authoritative for the calling domain — no explicit `sync` needed.
//
//   The arm bit is field1 bit 0.
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=u64::MAX,
//      flags={periodic=1})           — must succeed, returns timer handle
//   2. timer_cancel(timer)            — must return OK
//   3. readCap(cap_table_base, timer) — verify field1 bit 0 == 0
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word)
//   2: timer_cancel returned non-success in vreg 1
//   3: field1.arm was not 0 after timer_cancel returned

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const flags_periodic: u64 = 1;
    const ta = syscall.timerArm(
        @as(u64, timer_caps.toU16()),
        ~@as(u64, 0),
        flags_periodic,
    );
    if (testing.isHandleError(ta.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(ta.v1 & 0xFFF);

    const tc = syscall.timerCancel(timer_handle);
    if (tc.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, timer_handle);
    if ((cap.field1 & 1) != 0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
