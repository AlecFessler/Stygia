// Spec §[timer_rearm] — test 06.
//
// "[test 06] on success, [1].field1.arm = 1 and [1].field1.pd = [3].periodic."
//
// Strategy
//   The spec assertion pins the post-rearm field1 state regardless of
//   what the prior arm/pd bits were. To make that statement load-
//   bearing the test must drive field1 into a state that is
//   distinguishable from the post-rearm result before issuing the
//   rearm — otherwise we cannot tell whether the kernel recomputed
//   field1 during the rearm or whether it merely left a pre-existing
//   matching value untouched.
//
//   Concretely, the test exercises rearm with both periodic = 0 and
//   periodic = 1 and sandwiches each rearm between a state-changing
//   precondition and a sync+readback observation:
//
//     Step 1: timer_arm a one-shot with a short deadline so the
//             initial timer actually fires. Per §[timer_arm] [test
//             07] this transitions field1.arm to 0 after the fire.
//     Step 2: futex_wait_val on &field0 with expected = 0 — blocks
//             until the kernel's per-fire wake (§[timer] field0
//             row) returns the call with [1] = field0 vaddr. This
//             witnesses that the fire actually landed.
//     Step 3: sync + readback — confirm the precondition: the
//             post-fire authoritative state is field1.arm = 0 (and
//             pd = 0 since periodic was 0). Any non-zero field1
//             here means the precondition state for periodic=0
//             rearm is wrong and assertion 4 would no longer prove
//             that the kernel reset arm = 1 during the rearm.
//     Step 4: timer_rearm with periodic = 0 and a deadline far
//             larger than the test wall-clock so the new
//             configuration cannot fire before we observe field1.
//             Per the spec sentence under test, post-rearm
//             field1 = 0b01 (arm = 1, pd = 0). Because we just
//             proved field1 was 0b00 immediately before the call,
//             observing 0b01 here is unambiguously attributable to
//             the rearm setting arm = 1 — not a stale snapshot.
//     Step 5: sync + readback — assert field1 == 0b01.
//     Step 6: timer_rearm with periodic = 1, same long deadline.
//             Spec post-condition: field1 = 0b11 (arm = 1, pd = 1).
//             Because step 5 already pinned field1 = 0b01, observing
//             0b11 here requires the kernel to have flipped pd from
//             0 to 1 during the rearm — which is the second half of
//             the test 06 assertion (pd = [3].periodic).
//     Step 7: sync + readback — assert field1 == 0b11.
//
//   Every error path on `timer_rearm` is held inert across both
//   rearm calls so the success contract is the only path:
//     - test 01 BADCAP — handle is the freshly armed timer.
//     - test 02 PERM   — caps include `arm`.
//     - test 03 INVAL  — deadline_ns ≠ 0.
//     - test 04 INVAL  — handle is u12 with reserved bits implicitly
//                        zero; flags carries only bit 0.
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=ARM_DEADLINE_NS,
//                flags=0) — mint a one-shot timer that will fire.
//   2. futex_wait_val(timeout=FUTEX_TIMEOUT_NS, addr=&field0,
//                     expected=0) — block on the fire wake.
//   3. sync(handle) + readCap; assert field1 == 0 (post-fire,
//      one-shot disarmed).
//   4. timer_rearm(handle, deadline_ns=LONG_DEADLINE_NS, flags=0)
//      — periodic=0; must succeed.
//   5. sync(handle) + readCap; assert field1 == 0b01 (arm=1, pd=0).
//   6. timer_rearm(handle, deadline_ns=LONG_DEADLINE_NS, flags=1)
//      — periodic=1; must succeed.
//   7. sync(handle) + readCap; assert field1 == 0b11 (arm=1, pd=1).
//   8. timer_cancel(handle) — tidy shutdown.
//
// Assertions
//   1: timer_arm returned an error word in vreg 1 (setup failed).
//   2: futex_wait_val did not return [1] = &field0 — the initial
//      one-shot fire never delivered a wake, so the precondition
//      for the rest of the test is not established.
//   3: sync after the fire returned a non-OK status.
//   4: post-fire field1 != 0 — the one-shot did not actually
//      transition arm to 0, so the periodic=0 rearm assertion
//      below would not be load-bearing.
//   5: timer_rearm with periodic=0 returned a non-OK status.
//   6: sync after the periodic=0 rearm returned a non-OK status.
//   7: field1 after the periodic=0 rearm is not 0b01 (arm bit
//      clear, or pd bit set, or any reserved bit set).
//   8: timer_rearm with periodic=1 returned a non-OK status.
//   9: sync after the periodic=1 rearm returned a non-OK status.
//  10: field1 after the periodic=1 rearm is not 0b11 (arm bit
//      clear, or pd bit clear, or any reserved bit set).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const FIELD1_ARM_BIT: u64 = 1 << 0;
const FIELD1_PD_BIT: u64 = 1 << 1;

// 5 ms initial-arm deadline — well above per-syscall latency yet
// short enough that the one-shot fires comfortably inside the 1 s
// futex timeout, even on slow QEMU+TCG. Mirrors the sizing used by
// timer_rearm_05.
const ARM_DEADLINE_NS: u64 = 5_000_000;

// 1 s futex timeout — a 5 ms one-shot must fire inside this window;
// E_TIMEOUT here is a structural failure surfaced via assertion 2.
const FUTEX_TIMEOUT_NS: u64 = 1_000_000_000;

// 1000 s — far above any plausible test wall-clock so neither rearm
// re-fires before its post-condition readback. We need field1 to be
// observably attributable to the rearm itself rather than a follow-up
// fire, so the new deadline must not elapse during the test window.
const LONG_DEADLINE_NS: u64 = 1_000_000_000_000;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bit 2 = arm, bit 3 = cancel.
    // `arm` is required for the rearm cap gate (test 02); `cancel`
    // is needed for tidy shutdown of the rearmed (long-deadline)
    // timer at the end of the test.
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    const arm_result = syscall.timerArm(caps_word, ARM_DEADLINE_NS, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // §[capabilities] handle layout: Cap = { word0, field0, field1 }
    // (24 bytes). field0 sits at offset 8.
    const slot_offset: u64 = @as(u64, timer_handle) * @as(u64, caps.HANDLE_BYTES);
    const field0_addr: u64 = cap_table_base + slot_offset + @offsetOf(caps.Cap, "field0");

    // Block until the one-shot fires (§[timer] field0 wake path /
    // §[futex_wait_val] [test 08]). Either entry-mismatch or wake
    // returns [1] = field0_addr; that equality witnesses the fire.
    const pairs = [_]u64{ field0_addr, 0 };
    const wake = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs[0..]);
    if (wake.v1 != field0_addr) {
        testing.fail(2);
        return;
    }

    // §[timer_arm] [test 07]: a fired one-shot transitions
    // field1.arm to 0. Sync to force a kernel-authoritative
    // snapshot, then read back: field1 must be 0 (arm=0, pd=0).
    // This pins the precondition for the periodic=0 rearm below.
    const sync_post_fire = syscall.sync(timer_handle);
    if (sync_post_fire.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }
    const field1_post_fire = caps.readCap(cap_table_base, timer_handle).field1;
    if (field1_post_fire != 0) {
        testing.fail(4);
        return;
    }

    // Step 4: rearm with periodic = 0 (one-shot). Long deadline so
    // the new configuration cannot fire before step 5 observes
    // field1.
    const rearm_oneshot = syscall.timerRearm(timer_handle, LONG_DEADLINE_NS, 0);
    if (rearm_oneshot.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 5: sync + readback. With field1 just-pinned to 0,
    // observing 0b01 here proves the rearm explicitly set arm = 1
    // (and left pd = 0, matching periodic = 0).
    const s1 = syscall.sync(timer_handle);
    if (s1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }
    const field1_oneshot = caps.readCap(cap_table_base, timer_handle).field1;
    if (field1_oneshot != FIELD1_ARM_BIT) {
        testing.fail(7);
        return;
    }

    // Step 6: rearm with periodic = 1.
    const rearm_periodic = syscall.timerRearm(timer_handle, LONG_DEADLINE_NS, 1);
    if (rearm_periodic.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(8);
        return;
    }

    // Step 7: sync + readback. With field1 just-pinned to 0b01,
    // observing 0b11 here proves the rearm flipped pd from 0 to 1
    // — directly witnessing the spec sentence
    // "field1.pd = [3].periodic".
    const s2 = syscall.sync(timer_handle);
    if (s2.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }
    const field1_periodic = caps.readCap(cap_table_base, timer_handle).field1;
    if (field1_periodic != (FIELD1_ARM_BIT | FIELD1_PD_BIT)) {
        testing.fail(10);
        return;
    }

    // Tidy: stop the long-deadline timer so it does not linger into
    // suite teardown. Errors here are not part of the test 06
    // contract; ignore the return.
    _ = syscall.timerCancel(timer_handle);

    testing.pass();
}
