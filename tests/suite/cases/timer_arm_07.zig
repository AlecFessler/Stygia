// Spec §[timer_arm] — test 07.
//
// "[test 07] on success with [3].periodic = 0, [1].field0 is incremented
//  by 1 once after [2] deadline_ns; [1].field1.arm becomes 0 after the
//  fire."
//
// Strategy
//   Mint a one-shot timer (flags = 0) with `arm` cap so the resulting
//   handle is the spec's "timer handle". Per §[timer], `field0` is the
//   counter, `field1.arm` reflects armed/disarmed state, `field1.pd`
//   reflects periodic/one-shot. Per §[timer_arm], a fresh timer starts
//   with field0 = 0 and field1.arm = 1 (test 06's invariant), then on
//   one-shot fire field0 increments by 1 and arm flips to 0.
//
//   The handle table is mapped read-only into the holding domain, so
//   the address of `field0` for a freshly-minted timer at slot `t` is
//   `cap_table_base + t*sizeof(Cap) + offsetof(field0)`. §[timer_arm]
//   specifies the kernel issues a futex wake on each domain-local
//   copy's `field0` paddr after each fire; userspace observes the fire
//   either by polling the cap table or by waiting on that paddr via
//   `futex_wait_val(addr=&field0, expected=0)`. Use the futex path so
//   the test does not race the deadline.
//
//   To avoid an indefinite hang on a missed wake (e.g. a spurious early
//   return), bound the wait at 100 ms (deadline = 10 ms, so any fire
//   has long since happened). On wake, read the cap entry and assert
//   the post-fire shape: field0 == 1, field1.arm == 0, field1.pd == 0.
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns=10ms, flags=0) — must succeed.
//   2. futex_wait_val(timeout=100ms, addr=&field0, expected=0)
//        — returns when field0 transitions from 0 to non-zero.
//   3. readCap(timer slot) — observe post-fire fields.
//   4. sync(timer slot) so field1.arm reflects the kernel-mutable flip.
//   5. readCap again — verify field1.arm == 0.
//
// Assertions
//   1: timer_arm did not return a valid handle in vreg 1.
//   2: futex_wait_val returned an error (E_TIMEOUT or other) instead of
//      a wake address.
//   3: post-fire field0 is not 1.
//   4: sync after the fire returned non-OK.
//   5: post-fire field1.arm is still 1, or field1.pd is non-zero (the
//      one-shot flag should not have been set to periodic).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const Cap = caps.Cap;

pub fn main(cap_table_base: u64) void {
    const timer_caps = caps.TimerCap{ .arm = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());
    const deadline_ns: u64 = 10_000_000; // 10 ms
    const flags: u64 = 0; // periodic = 0 → one-shot

    const armed = syscall.timerArm(caps_word, deadline_ns, flags);
    if (testing.isHandleError(armed.v1)) {
        testing.fail(1);
        return;
    }
    const timer_slot: u12 = @truncate(armed.v1 & 0xFFF);

    // Compute &field0 for this slot. caps.Cap is extern { word0, field0,
    // field1 }, so field0 sits at offset 8 inside the slot.
    const field0_addr: u64 = cap_table_base +
        @as(u64, timer_slot) * @sizeOf(Cap) +
        @offsetOf(Cap, "field0");

    // Bound the wait at 100 ms: deadline is 10 ms, so a one-shot fire
    // must have arrived by then. A return from futex_wait_val with
    // [1] = field0_addr means the kernel-driven fire hit; a timeout
    // (E_TIMEOUT in vreg 1) means the timer never fired.
    const timeout_ns: u64 = 100_000_000;
    const wait_pairs = [_]u64{ field0_addr, 0 };
    const waited = syscall.futexWaitVal(timeout_ns, wait_pairs[0..]);
    if (waited.v1 != field0_addr) {
        testing.fail(2);
        return;
    }

    const after_fire = caps.readCap(cap_table_base, timer_slot);
    if (after_fire.field0 != 1) {
        testing.fail(3);
        return;
    }

    // §[capabilities]: field1's `arm`/`pd` are kernel-mutable and
    // sync-refreshed; force a fresh kernel-authoritative snapshot
    // before checking arm.
    const synced = syscall.sync(timer_slot);
    if (synced.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    const post_sync = caps.readCap(cap_table_base, timer_slot);
    const arm_bit: u64 = post_sync.field1 & 0x1;
    const pd_bit: u64 = (post_sync.field1 >> 1) & 0x1;
    if (arm_bit != 0 or pd_bit != 0) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
