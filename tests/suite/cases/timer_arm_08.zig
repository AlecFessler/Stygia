// Spec §[timer_arm] — test 08.
//
// "[test 08] on success with [3].periodic = 1, [1].field0 is
//  incremented by 1 every [2] deadline_ns until `timer_cancel` or
//  `timer_rearm`; [1].field1.arm remains 1."
//
// Spec semantics
//   §[timer]: a timer's field0 is a u64 counter the kernel atomically
//   increments on each fire and propagates to every domain-local copy
//   of the handle; field1.arm indicates whether the timer is currently
//   armed. §[timer_arm]: "On each fire, the kernel atomically
//   increments `field0` of every domain-local copy of the handle ...
//   One-shot timers transition `field1.arm` to 0 after the single
//   fire; periodic timers stay armed until `timer_cancel`."
//
// Strategy
//   With [3].periodic = 1, the timer must fire every deadline_ns. We
//   need to observe at least two distinct increments of field0 to
//   distinguish a periodic timer from a one-shot (test 07's behavior),
//   and we need field1.arm to stay 1 across both observations.
//
//   Use `futex_wait_val` against the local field0 vaddr (computed from
//   the cap table base + handle slot * sizeof(Cap) + offsetof(field0))
//   as the waiting primitive: the kernel issues a futex wake on each
//   copy's field0 paddr on fire (§[timer_arm]), so the wait returns
//   shortly after each fire. A timeout caps the test in case of a
//   missed fire.
//
//   Expected sequence:
//     1. After arming, field0 starts at 0.
//     2. Wait for field0 != 0 → first fire occurred.
//     3. sync, then read: field0 should be 1; field1.arm should be 1.
//     4. Wait for field0 != 1 → second fire occurred.
//     5. sync, then read: field0 should be 2; field1.arm should be 1.
//     6. timer_cancel to halt the periodic stream cleanly so the test
//        domain can wind down without lingering kernel-side fires.
//
//   `cancel` cap is required to terminate the periodic stream at the
//   end. restart_policy is left 0 so test 02's ceiling gate cannot
//   fire. arm cap is not strictly required (we never call timer_rearm
//   here) but adding it doesn't change the test surface.
//
//   Use a deadline_ns of 1 ms — long enough that the kernel timer
//   path doesn't churn but short enough that two fires complete well
//   inside the 1 s futex wait timeout the test uses as a fence.
//
// Action
//   1. timerArm(caps={cancel}, deadline_ns=1_000_000, periodic=1) →
//      must return a handle.
//   2. futex_wait_val(timeout=1s, addr=&field0, expected=0) →
//      blocks until first fire, returns &field0.
//   3. sync(handle); readCap → field0 == 1, field1.arm == 1.
//   4. futex_wait_val(timeout=1s, addr=&field0, expected=1) →
//      blocks until second fire, returns &field0.
//   5. sync(handle); readCap → field0 == 2, field1.arm == 1.
//   6. timer_cancel(handle) — best-effort cleanup.
//
// Assertions
//   1: timer_arm returned an error word instead of a handle.
//   2: first futex_wait_val returned an unexpected divergent address
//      (kernel keyed on the wrong paddr or returned a stale wake).
//   3: sync after first fire returned non-OK.
//   4: post-first-fire field0 != 1 (kernel didn't increment exactly
//      once before our wait re-armed for the second fire window).
//   5: post-first-fire field1.arm != 1 (periodic timer disarmed
//      itself like a one-shot).
//   6: second futex_wait_val returned an unexpected divergent address.
//   7: sync after second fire returned non-OK.
//   8: post-second-fire field0 != 2 (counter did not advance to the
//      second tick — periodic stream stalled or skipped).
//   9: post-second-fire field1.arm != 1 (periodic timer disarmed
//      after a fire — violates "remains 1").

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const ARM_BIT: u64 = 1 << 0;
const PERIODIC_FLAG: u64 = 1 << 0;

// §[timer] handle cap-table layout: word0, field0, field1, each u64.
// field0 sits at offset 8 within the 24-byte Cap.
const FIELD0_OFFSET: u64 = 8;
const HANDLE_BYTES: u64 = 24;

pub fn main(cap_table_base: u64) void {
    const timer_caps = caps.TimerCap{
        .cancel = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // 50 ms period. Two fires complete well within the 1 s futex wait
    // timeout, but the gap between fires is long enough that the
    // intervening `sync` + `readCap` window on slow hosts (aarch64 Pi 5
    // KVM with the in-kernel-parallel runner) cannot overlap a second
    // fire. The earlier 1 ms period left no margin for futex
    // wake → user-mode resume → sync → readCap on KVM aarch64; field0
    // would tick to 2 before the post-wake read landed and the test
    // tripped on assertion 4. Spec §[timer_arm] only pins the order of
    // counter values, not their absolute timing, so any period that
    // keeps the assertion observable is conformant.
    const deadline_ns: u64 = 50_000_000;

    const arm_result = syscall.timerArm(caps_word, deadline_ns, PERIODIC_FLAG);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // Vaddr of this domain's local copy of field0 in the read-only
    // mapped cap table. The kernel issues a futex wake against this
    // paddr on every fire (§[timer_arm]).
    const field0_vaddr: u64 = cap_table_base +
        @as(u64, timer_handle) * HANDLE_BYTES +
        FIELD0_OFFSET;

    const wait_timeout_ns: u64 = 1_000_000_000;

    // First fire: block while *field0 == 0; return when the kernel
    // increments it on fire.
    const wait1 = syscall.futexWaitVal(wait_timeout_ns, &.{ field0_vaddr, 0 });
    if (wait1.v1 != field0_vaddr) {
        testing.fail(2);
        return;
    }

    const sync1 = syscall.sync(timer_handle);
    if (sync1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    const cap1 = caps.readCap(cap_table_base, timer_handle);
    if (cap1.field0 != 1) {
        testing.fail(4);
        return;
    }
    if ((cap1.field1 & ARM_BIT) != ARM_BIT) {
        testing.fail(5);
        return;
    }

    // Second fire: block while *field0 == 1; return when the kernel
    // bumps it to 2.
    const wait2 = syscall.futexWaitVal(wait_timeout_ns, &.{ field0_vaddr, 1 });
    if (wait2.v1 != field0_vaddr) {
        testing.fail(6);
        return;
    }

    const sync2 = syscall.sync(timer_handle);
    if (sync2.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    const cap2 = caps.readCap(cap_table_base, timer_handle);
    if (cap2.field0 != 2) {
        testing.fail(8);
        return;
    }
    if ((cap2.field1 & ARM_BIT) != ARM_BIT) {
        testing.fail(9);
        return;
    }

    // Best-effort halt of the periodic stream so further fires don't
    // race the test's wind-down. Outcome is not asserted (covered by
    // timer_cancel tests).
    _ = syscall.timerCancel(timer_handle);

    testing.pass();
}
