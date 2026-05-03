// Spec §[timer_rearm] — test 06.
//
// "[test 06] on success, [1].field1.arm = 1 and [1].field1.pd = [3].periodic."
//
// Strategy
//   The runner spawns each test inside a child capability domain whose
//   self-handle carries the `timer` mint right (runner/primary.zig sets
//   `.timer = true` on `child_self`), so the test can call `timer_arm`
//   to mint its own timer handle and then drive `timer_rearm` against
//   it. With deadline_ns nonzero, no reserved bits set, and the `arm`
//   cap on the minted handle, every prior gate (timer_rearm tests
//   01-04) is satisfied — the call must take the success path and the
//   only observable post-condition this test asserts is the field1
//   readback: `arm = 1` regardless of the prior arm state, and
//   `pd = [3].periodic` regardless of the prior pd state.
//
//   To exercise both pd values, drive timer_rearm twice: once with
//   `periodic = 0` (expect field1 = 0b01) and once with
//   `periodic = 1` (expect field1 = 0b11). Each readback is preceded
//   by a `sync` so the cap-table snapshot reflects the kernel's
//   authoritative state — `field1.arm` and `field1.pd` are
//   kernel-mutable, sync-refreshed per §[timer] field layout.
//
//   The deadline_ns is chosen large (well over a second of nanoseconds)
//   so the one-shot variant cannot fire and clear `field1.arm` before
//   we read it back. Test 09 covers the one-shot-fire transition; this
//   test pins only the immediate post-rearm observable state.
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns=large, flags=0) — mint a
//      one-shot timer. Must succeed.
//   2. timer_rearm(handle, deadline_ns=large, flags=0)   — periodic=0.
//      Must succeed.
//   3. sync(handle) + readCap; assert field1.arm = 1, field1.pd = 0.
//   4. timer_rearm(handle, deadline_ns=large, flags=1)   — periodic=1.
//      Must succeed.
//   5. sync(handle) + readCap; assert field1.arm = 1, field1.pd = 1.
//
// Assertions
//   1: timer_arm returned an error word in vreg 1 (setup failed).
//   2: timer_rearm with periodic=0 returned a non-OK status.
//   3: sync after the periodic=0 rearm returned a non-OK status.
//   4: field1 after the periodic=0 rearm is not 0b01
//      (arm bit 0 clear, or pd bit 1 set, or any reserved bit set).
//   5: timer_rearm with periodic=1 returned a non-OK status.
//   6: sync after the periodic=1 rearm returned a non-OK status.
//   7: field1 after the periodic=1 rearm is not 0b11
//      (arm bit 0 clear, or pd bit 1 clear, or any reserved bit set).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const FIELD1_ARM_BIT: u64 = 1 << 0;
const FIELD1_PD_BIT: u64 = 1 << 1;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bit 2 = arm. We need `arm` so the
    // subsequent timer_rearm calls satisfy the cap gate (test 02);
    // every other cap stays clear so the readback is uncluttered.
    const timer_caps = caps.TimerCap{ .arm = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // Large deadline so the one-shot armed by step 1, and the one-shot
    // re-armed by step 2, cannot fire before we read field1 back.
    // Test 09 covers the fire-driven transitions; this test pins
    // only the immediate post-rearm field1 state.
    const deadline_ns: u64 = 1_000_000_000_000;

    const arm_result = syscall.timerArm(caps_word, deadline_ns, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // Step 2: rearm with periodic = 0. flags bit 0 clear.
    const rearm_oneshot = syscall.timerRearm(timer_handle, deadline_ns, 0);
    if (rearm_oneshot.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 3: sync to force a kernel-authoritative snapshot of the
    // handle's field1 into the read-only-mapped cap table, then read
    // it back and assert the exact bit pattern.
    const s1 = syscall.sync(timer_handle);
    if (s1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }
    const field1_oneshot = caps.readCap(cap_table_base, timer_handle).field1;
    if (field1_oneshot != FIELD1_ARM_BIT) {
        testing.fail(4);
        return;
    }

    // Step 4: rearm with periodic = 1. flags bit 0 set.
    const rearm_periodic = syscall.timerRearm(timer_handle, deadline_ns, 1);
    if (rearm_periodic.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 5: sync + readback; expect both arm and pd bits set, and
    // every reserved bit (2..63) clear.
    const s2 = syscall.sync(timer_handle);
    if (s2.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }
    const field1_periodic = caps.readCap(cap_table_base, timer_handle).field1;
    if (field1_periodic != (FIELD1_ARM_BIT | FIELD1_PD_BIT)) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
