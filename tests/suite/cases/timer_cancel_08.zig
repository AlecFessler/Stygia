// Spec §[timer_cancel] timer_cancel — test 08.
//
// "[test 08] on success, after one full prior `deadline_ns` has
//  elapsed, every domain-local copy of [1] still returns
//  `field0 = u64::MAX` from a fresh `sync`."
//
// Strategy
//   The semantic this test pins is that timer_cancel is permanent: a
//   cancelled timer does not fire again, so its u64::MAX sentinel must
//   not be overwritten by a later periodic-fire increment even after
//   the prior deadline_ns has elapsed.
//
//   Choose a periodic timer (flags.periodic = 1). Periodic is the
//   stronger of the two choices because a one-shot would also have
//   gone idle on its own; if periodic stays at u64::MAX past one full
//   period, the cancel undeniably stuck.
//
//   The runner spawns this test inside a single capability domain, so
//   "every domain-local copy of [1]" reduces to the one slot the test
//   itself holds. The spec invariant still applies: that lone copy
//   must read u64::MAX from a fresh sync after the elapsed deadline.
//
//   Time elapses via a busy-poll on `time_monotonic` until at least
//   one full prior deadline_ns has passed. We pick deadline_ns =
//   1_000_000 ns (1 ms) — large enough that the kernel's tick / timer-
//   queue resolution can plausibly fire a periodic timer multiple
//   times before the test moves on, small enough that polling for it
//   is cheap. We then wait for 4*deadline_ns to give the kernel
//   ample opportunity to attempt a fire (and cement that no fire
//   happened post-cancel).
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=1_000_000,
//                flags=periodic)                — must succeed
//   2. timer_cancel(timer)                       — must succeed
//   3. busy-poll time_monotonic until elapsed >= 4 * deadline_ns
//   4. sync(timer)                               — must return OK
//   5. readCap(cap_table_base, timer)            — verify field0 ==
//                                                  u64::MAX
//
// Assertions
//   1: timer_arm returned an error word in vreg 1
//   2: timer_cancel returned non-OK in vreg 1
//   3: time_monotonic returned an error code (degraded; can't measure)
//   4: sync returned non-OK in vreg 1
//   5: post-elapsed-deadline readCap shows field0 != u64::MAX
//      (the cancel sentinel was clobbered by a fire — spec violation)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CANCEL_SENTINEL: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub fn main(cap_table_base: u64) void {
    // §[timer] caps word: bits 2,3 = arm, cancel. arm is needed at
    // mint time per §[timer_arm]; cancel is needed for the cancel
    // call per §[timer_cancel]. periodic is selected by flags bit 0.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    const deadline_ns: u64 = 1_000_000;
    const periodic_flags: u64 = 1;

    const arm_result = syscall.timerArm(caps_word, deadline_ns, periodic_flags);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    const cancel_result = syscall.timerCancel(timer_handle);
    if (cancel_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Wait for at least one full prior deadline_ns. Use 4x to give the
    // kernel multiple periodic-fire opportunities; if any of them
    // overrode the cancel sentinel, we'd see field0 != u64::MAX below.
    const wait_ns: u64 = 4 * deadline_ns;

    const t0 = syscall.timeMonotonic();
    if (t0.v1 != 0 and t0.v1 < 16) {
        // time_monotonic returned an error-shaped value — can't measure
        // elapsed time. Spec invariant unobservable; fail loudly so the
        // missing dependency surfaces rather than silently passing.
        testing.fail(3);
        return;
    }
    const start_ns: u64 = t0.v1;

    while (true) {
        const tn = syscall.timeMonotonic();
        if (tn.v1 != 0 and tn.v1 < 16) {
            testing.fail(3);
            return;
        }
        const now_ns: u64 = tn.v1;
        // Saturating subtraction: time_monotonic is strictly monotonic
        // per §[time] [test 01], so now_ns >= start_ns always — but
        // guard against an unwrapping underflow defensively.
        const elapsed: u64 = if (now_ns >= start_ns) now_ns - start_ns else 0;
        if (elapsed >= wait_ns) break;
    }

    const sync_result = syscall.sync(timer_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    const cap = caps.readCap(cap_table_base, timer_handle);
    if (cap.field0 != CANCEL_SENTINEL) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
