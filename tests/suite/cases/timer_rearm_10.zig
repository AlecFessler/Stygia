// Spec §[timer_rearm] timer_rearm — test 10.
//
// "[test 10] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   The spec gates the implicit-sync side effect on "[1] is a valid
//   handle." That excludes the test 01 path (E_BADCAP, where [1] does
//   not name a real handle), but it admits every other failure mode
//   (test 02 E_PERM, test 03 E_INVAL on [2], test 04 E_INVAL on
//   reserved bits) as well as the success path (test 05+).
//
//   The cleanest error path that keeps [1] resolving to a valid timer
//   is test 04 — setting a reserved bit in word [1]. The 12-bit handle
//   id sits in bits 0-11 and the rest of the word is _reserved; ORing
//   bit 12 over a real handle id forces E_INVAL while leaving the
//   underlying timer untouched (the kernel still resolves [1] to the
//   live timer, runs the side-effect refresh, then rejects the call
//   on the reserved-bits check).
//
//   For the test 10 refresh post-condition to be load-bearing the
//   authoritative kernel state must demonstrably *differ* from the
//   pre-call domain-local snapshot — otherwise an "OK" readback after
//   the failed rearm could be explained by the snapshot being
//   correct already, with no refresh having occurred. We therefore:
//
//     1. timer_arm a one-shot with a short deadline (caps={arm,
//        cancel}).
//     2. futex_wait_val on &field0 with expected=0 — block until the
//        fire wake returns with [1] = field0_addr (witnesses the
//        fire end-to-end via §[timer] field0 wake / §[futex_wait_val]
//        [test 08]).
//     3. After the fire, kernel-authoritative state is field0 = 1,
//        field1.arm = 0, field1.pd = 0 (§[timer_arm] [test 07] for
//        the one-shot disarm).
//     4. Issue timer_rearm with reserved bit 12 of [1] set — must
//        return E_INVAL (§[timer_rearm] test 04). [1] resolves to a
//        valid handle, so the side-effect refresh per spec test 10
//        is mandated.
//     5. Read the cap-table snapshot and assert it matches the
//        post-fire authoritative state: field0 = 1, field1 = 0.
//        Because we deliberately exited the rearm error path
//        without success, the only way this readback can match is
//        if the kernel performed the implicit refresh during the
//        failing call — exactly the spec sentence under test.
//
//   We bypass the typed `timerRearm` wrapper (which takes u12 and
//   would scrub the reserved bit) and dispatch through `issueReg`
//   directly so bit 12 reaches the kernel, mirroring the dispatch
//   shape used in timer_rearm_04 and timer_cancel_09.
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=ARM_DEADLINE_NS,
//                flags=0)                            — must succeed
//   2. futex_wait_val(timeout=FUTEX_TIMEOUT_NS, addr=&field0,
//                     expected=0)                    — wake with
//      [1] = field0_addr (one-shot fire witnessed)
//   3. timer_rearm(handle | (1 << 12), ARM_DEADLINE_NS, 0)
//                                                    — must return
//      E_INVAL (test 04 reserved-bits path) on a valid handle
//   4. readCap(handle) — must observe the authoritative kernel
//      state (field0 = 1, field1 = 0) as the side-effect refresh
//      mandated by test 10
//
// Assertions
//   1: timer_arm setup failed (arm returned an error word)
//   2: futex_wait_val did not return [1] = &field0 — the one-shot
//      fire never delivered a wake, so test 10's pre-call
//      authoritative state is unestablished
//   3: timer_rearm with reserved bit 12 of [1] set did not return
//      E_INVAL (the call resolved a valid handle but did not take
//      the reserved-bits failure path)
//   4: post-call snapshot diverged from the post-fire authoritative
//      kernel state — the kernel returned an error but did not
//      refresh the domain-local field0/field1 as the spec requires.
//      Concretely: field0 != 1 OR field1 != 0.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// 5 ms — short enough that a one-shot fires inside the 1 s futex
// timeout below; far above per-syscall latency so the call sequence
// arrives at futex_wait_val while the timer is still genuinely
// armed. Mirrors sizing in timer_rearm_05/06/07.
const ARM_DEADLINE_NS: u64 = 5_000_000;

// 1 s futex timeout — a 5 ms one-shot must fire inside this; an
// E_TIMEOUT here is a structural failure surfaced via assertion 2.
const FUTEX_TIMEOUT_NS: u64 = 1_000_000_000;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer cap word: bit 2 = arm, bit 3 = cancel. `arm` is
    // required so the rearm call's test 02 PERM check cannot fire on
    // the reserved-bit path — we want test 04 to be the sole spec-
    // mandated failure mode. `cancel` is unused here (the one-shot
    // self-disarms on fire) but is harmless.
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // §[timer_arm] flags: bit 0 = periodic. One-shot (periodic=0) so
    // the post-fire authoritative state is uniquely determined:
    // field0 = 1, field1.arm = 0, field1.pd = 0. That tuple is
    // distinguishable from arm-time (field0 = 0, field1.arm = 1),
    // which is what makes the post-call refresh observable.
    const arm_result = syscall.timerArm(caps_word, ARM_DEADLINE_NS, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // §[capabilities] handle layout: Cap = { word0, field0, field1 }
    // (24 bytes). field0 sits at offset 8 within the slot — the
    // kernel-keyed paddr for the per-fire futex wake.
    const slot_offset: u64 = @as(u64, timer_handle) * @as(u64, caps.HANDLE_BYTES);
    const field0_addr: u64 = cap_table_base + slot_offset + @offsetOf(caps.Cap, "field0");

    // Block on the one-shot fire. *field0 starts at 0 (arm time),
    // so this can only return via a wake — the entry-mismatch path
    // is unreachable. The wake's [1] = field0_addr witnesses the
    // fire end-to-end.
    const pairs = [_]u64{ field0_addr, 0 };
    const wake = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs[0..]);
    if (wake.v1 != field0_addr) {
        testing.fail(2);
        return;
    }

    // Drive timer_rearm with reserved bit 12 of [1] set. Bypass the
    // typed wrapper (which takes u12 and would truncate the reserved
    // bit) and dispatch through issueReg directly so the bit reaches
    // the kernel. The low 12 bits hold the valid timer id, so [1] is
    // a "valid handle" per the spec's gating phrase even though the
    // word encoding is rejected. deadline_ns is non-zero (test 03
    // cannot fire) and flags has only bit 0 cleared (test 04 on [3]
    // cannot fire) — the reserved bit on [1] is the sole spec-
    // mandated failure trigger.
    const handle_with_reserved: u64 = @as(u64, timer_handle) | (@as(u64, 1) << 12);
    const rearm_result = syscall.issueReg(.timer_rearm, 0, .{
        .v1 = handle_with_reserved,
        .v2 = ARM_DEADLINE_NS,
        .v3 = 0,
    });
    if (rearm_result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    // Post-call refresh check. The kernel rejected the call with
    // E_INVAL but, per test 10, must still have refreshed the
    // domain-local field0/field1 from authoritative kernel state.
    // After the witnessed one-shot fire that authoritative state is
    //   field0 = 1, field1.arm = 0, field1.pd = 0 (i.e. field1 = 0).
    // A snapshot showing anything else means the kernel skipped the
    // implicit refresh on the error path — the exact behaviour
    // test 10 forbids.
    const post = caps.readCap(cap_table_base, timer_handle);
    if (post.field0 != 1 or post.field1 != 0) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
