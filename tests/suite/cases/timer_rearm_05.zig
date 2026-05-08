// Spec §[timer] timer_rearm — test 05 (degraded smoke for cross-domain
// half).
//
// "[test 05] on success, the calling domain's copy of [1] has
//  `field0 = 0` immediately on return; every other domain-local copy
//  returns 0 from a fresh `sync` within a bounded delay."
//
// Strategy
//   The assertion is in two halves:
//
//     (a) The calling domain's own cap-table slot for the timer
//         handle has `field0 = 0` immediately on return from
//         `timer_rearm`. This half is fully testable in-process: the
//         kernel writes through to the read-only-mapped cap table at
//         `cap_table_base`, and we read it back the instant the
//         syscall returns.
//
//     (b) Every *other* domain-local copy of the same timer handle
//         returns 0 from a fresh `sync` within a bounded delay. This
//         half requires at least two capability domains each holding
//         a copy of the same timer handle. The runner spawns one
//         child capability domain per test ELF (see
//         runner/primary.zig), so there is no second domain to hold
//         a sibling copy from inside this test. The cross-domain
//         half is therefore structurally unreachable from a single
//         test ELF on this branch and is not asserted here.
//
//   For half (a) to be load-bearing, field0 must demonstrably be
//   non-zero before the rearm so the post-call observation is a
//   genuine reset rather than a no-op against an already-zero slot.
//   We therefore witness an actual fire from the initial timer_arm
//   before issuing rearm, using the same futex_wait_val pattern that
//   timer_rearm_08 / timer_arm_09 use to surface the fire-driven wake
//   path:
//
//     1. timer_arm with `periodic = 1` and a short `deadline_ns` so
//        the kernel will fire the timer before our wait window
//        expires.
//     2. futex_wait_val on `&cap_table[timer].field0` with
//        expected = 0. Per §[timer] field0 row, the kernel's
//        per-fire wake walks every domain-local copy of field0, and
//        per §[futex_wait_val] [test 08] that wake causes the
//        syscall to return with [1] set to the woken vaddr. The
//        return-vaddr equality check witnesses the fire end-to-end.
//     3. Confirm the cap-table slot now reads field0 >= 1 — the
//        eager-propagation contract under §[timer] field0 means the
//        kernel has written through the increment by the time the
//        wake reaches us.
//     4. timer_rearm with periodic = 1 and a longer `deadline_ns` so
//        no follow-up fire lands between the rearm return and the
//        post-rearm cap-table read.
//     5. Read the cap table and assert field0 == 0 — the spec
//        sentence under test, now load-bearing because we know the
//        kernel had to clear a previously non-zero slot.
//
//   For `timer_rearm` itself we want every error path to be
//   unreachable so the success contract is the only path:
//
//     - [1] is the handle returned by step 1's `timer_arm`, valid
//       with `arm` cap set, so tests 01 (BADCAP) and 02 (PERM) cannot
//       fire.
//     - [2] deadline_ns is non-zero, so test 03 cannot fire.
//     - [3] flags has only bit 0 (`periodic`) potentially set; all
//       other bits clear. The handle id syscall slot has its 12-bit
//       id in the low bits and zeros above, so test 04 (reserved
//       bits in [1] or [3]) cannot fire.
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=ARM_DEADLINE_NS,
//                flags=periodic) — must succeed
//   2. futex_wait_val(timeout=FUTEX_TIMEOUT_NS, addr=&field0,
//                     expected=0) — must return with [1] = field0
//      vaddr (witnesses the fire-driven wake)
//   3. readCap(cap_table_base, timer).field0 — must be >= 1
//      (load-bearing pre-condition for the rearm reset)
//   4. timer_rearm(timer, deadline_ns=REARM_DEADLINE_NS,
//                  flags=periodic) — must succeed
//   5. readCap(cap_table_base, timer).field0 — must equal 0
//   6. timer_cancel(timer) — tidy shutdown so the periodic fire does
//      not leak into suite teardown.
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word in vreg 1)
//   2: futex_wait_val did not return [1] = &field0 — either
//      E_TIMEOUT (no fire within FUTEX_TIMEOUT_NS) or some other
//      address. The fire-driven wake the spec relies on did not
//      surface, so the rest of the test is unobservable.
//   3: pre-rearm field0 was still 0 after the wake. The wake fired
//      but the kernel did not propagate the increment into this
//      domain's cap-table copy — the post-rearm reset would not be
//      load-bearing.
//   4: timer_rearm returned non-OK in vreg 1
//   5: post-rearm field0 is non-zero in the calling domain's
//      cap-table copy (violates the "field0 = 0 immediately on
//      return" half of test 05)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// 5 ms — well above any plausible kernel scheduling granularity yet
// short enough that the periodic timer fires repeatedly within the
// 1 s futex timeout below. timer_rearm_08 uses 10 ms for the same
// "wait for the kernel to fire and propagate" purpose; 5 ms gives an
// extra margin for the eager-propagation walk to complete before our
// post-wake readCap.
const ARM_DEADLINE_NS: u64 = 5_000_000;

// 1 s rearm period. The rearm post-condition checked below is
// "field0 = 0 immediately on return" — a periodic fire that lands
// between the rearm syscall returning and the next user-mode
// readCap would race the post-condition observation. 1 s gives a
// wide margin against scheduling jitter on QEMU+TCG even when the
// initial 5 ms deadline is still ticking when rearm replaces it.
// Spec §[timer_rearm] pins the reset-to-zero semantics, not the
// absolute period.
const REARM_DEADLINE_NS: u64 = 1_000_000_000;

// 1 s futex timeout — a periodic 5 ms timer must fire ≥ 100 times in
// this window even on slow QEMU+TCG. If the wait still returns
// E_TIMEOUT something is structurally wrong with either the timer
// fire path or the futex wake path; assertion 2 surfaces that
// loudly rather than hanging.
const FUTEX_TIMEOUT_NS: u64 = 1_000_000_000;

const TIMER_FLAG_PERIODIC: u64 = 1;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bits 0-15 carry the cap bits on
    // the returned timer handle. `arm` is required by timer_rearm
    // (§[timer] timer_rearm cap row); `cancel` lets us shut the
    // periodic timer down cleanly so it does not keep firing into
    // the suite's teardown path.
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const arm_caps_word: u64 = @as(u64, timer_caps.toU16());

    const arm_result = syscall.timerArm(
        arm_caps_word,
        ARM_DEADLINE_NS,
        TIMER_FLAG_PERIODIC,
    );
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // §[capabilities] handle layout: Cap = { word0, field0, field1 },
    // each u64. field0 sits at offset 8 within the handle's 24-byte
    // slot. The cap table is mapped read-only at `cap_table_base`,
    // so the vaddr the kernel keys this domain's futex waiter on is
    // the byte offset arithmetic below — the very address §[timer]
    // says wakes propagate to.
    const slot_offset: u64 = @as(u64, timer_handle) * @as(u64, caps.HANDLE_BYTES);
    const field0_addr: u64 = cap_table_base + slot_offset + @offsetOf(caps.Cap, "field0");

    // Block on the fire-driven wake. Two return paths satisfy the
    // spec assertion equivalently:
    //   - On-entry mismatch (futex_wait_val test 07): if the timer
    //     has already fired by call entry, *field0 != 0 and the
    //     call returns immediately with [1] = &field0.
    //   - Wake (futex_wait_val test 08): if we register before the
    //     fire, the kernel's wake on field0's paddr returns the
    //     call with [1] = &field0.
    // Either way [1] == field0_addr witnesses the fire.
    const pairs = [_]u64{ field0_addr, 0 };
    const wake = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs[0..]);
    if (wake.v1 != field0_addr) {
        testing.fail(2);
        return;
    }

    // Confirm the increment is actually visible in this domain's
    // cap-table snapshot. Per §[timer] field0 the kernel eagerly
    // propagates the increment to every domain-local copy as part
    // of the same fire, so by the time the wake arrives the slot
    // we read here must be ≥ 1. If it is still 0 the test 05 reset
    // post-condition would not be load-bearing.
    const pre_rearm = caps.readCap(cap_table_base, timer_handle);
    if (pre_rearm.field0 < 1) {
        testing.fail(3);
        return;
    }

    const rearm_result = syscall.timerRearm(
        timer_handle,
        REARM_DEADLINE_NS,
        TIMER_FLAG_PERIODIC,
    );
    if (rearm_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // §[timer] timer_rearm test 05 (calling-domain half): the
    // caller's cap-table copy must read field0 = 0 on the very next
    // access after the syscall returns. With pre-rearm field0 ≥ 1
    // confirmed above, this read is now load-bearing — it can only
    // pass if the kernel cleared the slot during the rearm path.
    const post_rearm = caps.readCap(cap_table_base, timer_handle);
    if (post_rearm.field0 != 0) {
        testing.fail(5);
        return;
    }

    // Tidy: cancel so the periodic fire stops bumping field0 into
    // the suite's shutdown path. Errors here are not part of the
    // test 05 contract; ignore the return.
    _ = syscall.timerCancel(timer_handle);

    testing.pass();
}
