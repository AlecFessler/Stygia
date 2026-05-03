// Spec §[timer] timer_cancel — test 05.
//
// "[test 05] on success, the calling domain's copy of [1] has
//  `field0 = u64::MAX` immediately on return; every other domain-local
//  copy returns u64::MAX from a fresh `sync` within a bounded delay."
//
// Strategy
//   timer_cancel sets `field0` to the cancellation sentinel (u64::MAX,
//   per §[timer]: "The kernel reserves `u64::MAX` as the cancellation
//   sentinel; fire-driven increments saturate at `u64::MAX − 1`, so a
//   real counter value is never confused with cancellation.") and
//   eagerly propagates that to the calling domain's copy of the timer
//   handle in the read-only-mapped cap table.
//
//   The "every other domain-local copy" clause requires a second
//   capability domain holding a copy of the same timer handle, plus the
//   nested-domain spawn infrastructure to set that up. No existing test
//   wires that yet; this test exercises the calling-domain post-
//   condition only — read field0 directly from the cap table after
//   timer_cancel returns OK and assert it equals u64::MAX.
//
//   Setup mints a one-shot timer with `arm` and `cancel` caps via
//   `timer_arm`. `arm = 1` after timer_arm (§[timer_arm] test 06), so
//   the §[timer_cancel] test 03 gate (E_INVAL when arm = 0) does not
//   fire. The deadline_ns is large (well beyond test runtime) so no
//   fire propagation interleaves with the cancel. flags = 0 selects
//   one-shot, but periodic vs. one-shot has no bearing on cancel's
//   field0 sentinel write.
//
// Action
//   1. timer_arm(caps={arm, cancel}, deadline_ns=1s, flags=0)
//                                              — must succeed
//   2. timer_cancel(timer)                     — must return OK
//   3. readCap(cap_table_base, timer)          — verify field0 ==
//                                                u64::MAX (cancellation
//                                                sentinel)
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word)
//   2: timer_cancel returned non-OK in vreg 1
//   3: post-cancel field0 in the calling domain's cap table copy is
//      not u64::MAX (the cancellation sentinel)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // deadline_ns must be nonzero (§[timer_arm] test 03). 1s is well
    // beyond any realistic test runtime, so no fire-driven update to
    // field0 will interleave with the cancel.
    const deadline_ns: u64 = 1_000_000_000;
    const flags: u64 = 0;

    const ta = syscall.timerArm(caps_word, deadline_ns, flags);
    if (testing.isHandleError(ta.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(ta.v1 & 0xFFF);

    const result = syscall.timerCancel(timer_handle);
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, timer_handle);
    if (cap.field0 != ~@as(u64, 0)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
