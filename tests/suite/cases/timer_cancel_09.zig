// Spec §[timer_cancel] — test 09.
//
// "[test 09] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   The spec gates the implicit-sync side effect on "[1] is a valid
//   handle." That excludes the test 01 path (E_BADCAP, where [1] does
//   not name a real handle), but it admits every other failure mode
//   (test 02 E_PERM, test 03 E_INVAL, test 04 E_INVAL) as well as the
//   success path (test 05+).
//
//   The cleanest error path that keeps [1] resolving to a valid timer
//   is test 04 — setting a reserved bit in word [1]. The 12-bit handle
//   id sits in bits 0-11 and the rest of the word is _reserved; ORing
//   bit 12 over a real handle id forces E_INVAL while leaving the
//   underlying timer untouched.
//
//   We arm a periodic timer with a very long deadline so the kernel
//   never fires it during the test. Periodic + long deadline pins the
//   authoritative kernel state at field0 = 0, field1.arm = 1,
//   field1.pd = 1 across the entire test window. That gives us a
//   stable post-condition for the implicit-sync side effect.
//
//   We bypass the typed `timerCancel` wrapper (which takes u12 and
//   would scrub the reserved bit) and dispatch through `issueReg`
//   directly so bit 12 reaches the kernel.
//
// Action
//   1. timer_arm(caps={arm, cancel}, deadline_ns=1 hour, periodic=1)
//                                                — must succeed
//   2. readCap(handle) before the cancel call    — sanity check that
//      the kernel propagated field0 = 0 and field1 = {arm=1, pd=1}
//      into the domain-local snapshot at arm time
//   3. timer_cancel(handle | (1 << 12))          — must return
//      E_INVAL (test 04 reserved-bits path)
//   4. readCap(handle) after the cancel call     — must still observe
//      the authoritative kernel state (field0 = 0, field1 = {arm=1,
//      pd=1}) as the side-effect refresh mandated by test 09
//
// Assertions
//   1: timer_arm setup failed (arm returned an error word)
//   2: pre-call snapshot did not match the just-armed kernel state
//      (field0 ≠ 0 or field1 ≠ {arm=1, pd=1})
//   3: timer_cancel with reserved bit 12 of [1] set did not return
//      E_INVAL
//   4: post-call snapshot diverged from the authoritative kernel
//      state — the kernel returned an error but did not refresh the
//      domain-local field0/field1 as the spec requires

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[timer] field1 bit layout: bit 0 = arm, bit 1 = pd, bits 2-63
// _reserved. The expected post-condition for an armed periodic timer
// is therefore exactly 0b11.
const FIELD1_ARMED_PERIODIC: u64 = 0b11;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer cap word: bit 2 = arm, bit 3 = cancel. Both are
    // set so the resulting handle is a fully-configured timer; only
    // `cancel` is strictly required for this test, but `arm` keeps the
    // handle symmetric with the rest of the §[timer_cancel] suite.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // 1 hour in nanoseconds. Picked far above any plausible test
    // wall-clock so the periodic timer cannot fire during the test
    // window — that pins the authoritative kernel state at
    // field0 = 0, field1 = {arm=1, pd=1} across the cancel call.
    const deadline_ns: u64 = 60 * 60 * 1_000_000_000;

    // §[timer_arm] flags: bit 0 = periodic. Periodic so field1.pd = 1
    // shows up in the post-condition (one-shot would leave pd = 0,
    // which is the same as the unset reserved-bit pattern and is
    // therefore weaker as an authoritative-state probe).
    const flags_periodic: u64 = 1;

    const arm_result = syscall.timerArm(caps_word, deadline_ns, flags_periodic);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // Pre-call sanity: the kernel must already have populated the
    // domain-local snapshot at arm time. If this fails, test 09 is
    // not meaningfully exercised because we cannot distinguish a
    // post-call refresh from a snapshot that was always correct.
    const pre = caps.readCap(cap_table_base, timer_handle);
    if (pre.field0 != 0 or pre.field1 != FIELD1_ARMED_PERIODIC) {
        testing.fail(2);
        return;
    }

    // Drive timer_cancel with reserved bit 12 of [1] set. Bypass the
    // typed wrapper (which takes u12 and would truncate the reserved
    // bit) and dispatch through issueReg directly so the bit reaches
    // the kernel. The low 12 bits hold the valid timer id, so the
    // handle is "valid" per the spec's gating phrase even though the
    // word encoding is rejected.
    const handle_with_reserved: u64 = @as(u64, timer_handle) | (@as(u64, 1) << 12);
    const cancel_result = syscall.issueReg(.timer_cancel, 0, .{ .v1 = handle_with_reserved });
    if (cancel_result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    // Post-call refresh check. The kernel rejected the call with
    // E_INVAL but, per test 09, must still have refreshed the
    // domain-local field0/field1 from authoritative kernel state.
    // The timer is still armed and periodic and has not fired, so
    // authoritative state remains field0 = 0, field1 = {arm=1, pd=1}.
    const post = caps.readCap(cap_table_base, timer_handle);
    if (post.field0 != 0 or post.field1 != FIELD1_ARMED_PERIODIC) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
