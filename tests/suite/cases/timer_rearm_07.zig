// Spec §[timer_rearm] — test 07.
//
// "[test 07] on success with [3].periodic = 0, [1].field0 is
//  incremented by 1 once after [2] deadline_ns and `[1].field1.arm`
//  becomes 0; with [3].periodic = 1, [1].field0 is incremented by 1
//  every [2] deadline_ns until `timer_cancel` or another
//  `timer_rearm`."
//
// Strategy
//   The assertion has two halves, both of which must witness actual
//   fires rather than merely sampling state under timing assumptions.
//
//     Half A: rearm with periodic = 0. Kernel must increment field0
//     to 1 once after deadline_ns elapses, then transition field1.arm
//     from 1 to 0 (one-shot complete). field0 must stay at 1
//     thereafter — no second fire on a one-shot.
//
//     Half B: rearm the same handle with periodic = 1. Kernel must
//     reset field0 to 0 (per the rearm contract), set field1.arm = 1
//     and field1.pd = 1, then increment field0 every deadline_ns
//     while the timer remains armed. field1.arm must remain 1
//     across fires.
//
//   Both halves rely on §[timer] field0 row: "the kernel's per-fire
//   wake walks every domain-local copy and issues a futex wake on
//   its field0 paddr." That is the same wake observed by
//   timer_arm_09 / timer_rearm_08, so the fire is observable via
//   `futex_wait_val(addr=&field0, expected=<current>)`. The wake
//   return value `[1]` carries the woken vaddr, which we compare
//   against `field0_addr` to witness the fire end-to-end.
//
//   Two fires distinguish periodic from one-shot:
//     - one-shot: after the first fire `field0 == 1`. A second
//       `futex_wait_val(expected=1)` would have to come from a wake
//       (no entry-mismatch since *field0 == 1), which a correctly
//       implemented one-shot must never deliver. We therefore use a
//       short non-blocking timeout on the second wait and assert it
//       returns E_TIMEOUT — the spec-mandated "no second fire on a
//       one-shot" surfaces directly.
//     - periodic: after the first fire `field0 >= 1`; a second
//       `futex_wait_val(expected=that_value)` will wake when the
//       next fire bumps field0 again. The wake's `[1]` equality
//       check witnesses the second fire end-to-end.
//
//   field1.arm transitions are read-back via the cap-table snapshot
//   the kernel eagerly propagates on each fire (§[timer] field0 row
//   covers the value; §[timer_arm] [test 07] / [test 08] cover the
//   arm-bit transitions). A `sync` before the post-fire field1 read
//   forces a kernel-authoritative snapshot in case the eager
//   propagation has not yet caught up.
//
//   Setup mints a fresh timer via `timer_arm` so the rearm path has
//   a live handle to operate on; the initial arm call's deadline is
//   irrelevant (rearm fully replaces the configuration per
//   §[timer_rearm]).
//
//   Cap layout (§[timer], §[capabilities]):
//     field0 = u64 counter at slot offset 8
//     field1 bit 0 = arm, bit 1 = pd
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=DEADLINE_NS, flags=0)
//      — mint a timer handle.
//   2. timer_rearm(handle, deadline_ns=DEADLINE_NS, flags=0)
//      — one-shot reconfigure; resets field0=0, arm=1, pd=0.
//   3. futex_wait_val(timeout=FUTEX_TIMEOUT_NS, addr=&field0,
//                     expected=0) — block on Half-A fire.
//   4. sync + readCap; assert field0 == 1 and field1.arm == 0.
//   5. futex_wait_val(timeout=NO_SECOND_FIRE_NS, addr=&field0,
//                     expected=1) — must return E_TIMEOUT (no
//      second fire on a one-shot).
//   6. timer_rearm(handle, deadline_ns=DEADLINE_NS, flags=1)
//      — periodic reconfigure; resets field0=0, arm=1, pd=1.
//   7. futex_wait_val(timeout=FUTEX_TIMEOUT_NS, addr=&field0,
//                     expected=0) — block on Half-B first fire.
//   8. Read current field0 as `seen`.
//   9. futex_wait_val(timeout=FUTEX_TIMEOUT_NS, addr=&field0,
//                     expected=seen) — block on Half-B second fire.
//  10. sync + readCap; assert field1.arm == 1 (still armed
//      periodic).
//  11. timer_cancel(handle) — tidy shutdown.
//
// Assertions
//   1: timer_arm setup returned an error (no handle to test against)
//   2: first timer_rearm (periodic=0) returned non-OK
//   3: futex_wait_val on Half-A first fire did not return [1] =
//      &field0 (E_TIMEOUT or wrong addr — the one-shot fire wake
//      did not surface)
//   4: post-Half-A sync returned non-OK
//   5: post-Half-A field0 != 1 (kernel double-incremented a
//      one-shot OR did not increment at all despite the wake)
//   6: post-Half-A field1.arm != 0 (one-shot did not clear arm)
//   7: post-Half-A second-fire probe did not return E_TIMEOUT
//      (kernel delivered a spurious second wake on a one-shot)
//   8: second timer_rearm (periodic=1) returned non-OK
//   9: futex_wait_val on Half-B first fire did not return [1] =
//      &field0
//  10: futex_wait_val on Half-B second fire did not return [1] =
//      &field0 (periodic timer fired only once)
//  11: post-Half-B sync returned non-OK
//  12: post-Half-B field1.arm != 1 (periodic spuriously cleared
//      arm)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// 5 ms timer deadline — short enough that a periodic timer fires
// twice inside the futex timeout below, long enough that scheduling
// jitter from the runner spawning siblings will not flap the fires.
const DEADLINE_NS: u64 = 5_000_000;

// 1 s futex timeout for fire waits — a 5 ms timer must fire
// comfortably within this even on slow QEMU+TCG. E_TIMEOUT here is a
// structural failure surfaced via the per-step assertion.
const FUTEX_TIMEOUT_NS: u64 = 1_000_000_000;

// 50 ms — 10× the deadline. After a one-shot fire, this is long
// enough that any spurious second fire from a buggy kernel would
// have to wake the futex; if the kernel is correct, the wait
// completes via E_TIMEOUT, which we assert.
const NO_SECOND_FIRE_NS: u64 = 50_000_000;

pub fn main(cap_table_base: u64) void {
    // Step 1: mint a timer handle. arm + cancel caps so we can both
    // rearm and clean up on exit. restart_policy stays 0 to dodge
    // §[timer_arm] [test 02]'s tm_restart_max gate.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const arm_caps_word: u64 = @as(u64, timer_caps.toU16());
    const arm_result = syscall.timerArm(arm_caps_word, DEADLINE_NS, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // §[capabilities] handle layout: Cap = { word0, field0, field1 }
    // (24 bytes). field0 sits at offset 8 — the kernel-keyed paddr
    // for the per-fire futex wake.
    const slot_offset: u64 = @as(u64, timer_handle) * @as(u64, caps.HANDLE_BYTES);
    const field0_addr: u64 = cap_table_base + slot_offset + @offsetOf(caps.Cap, "field0");

    // ---- Half A: periodic = 0 (one-shot) ----
    const rearm_oneshot = syscall.timerRearm(timer_handle, DEADLINE_NS, 0);
    if (rearm_oneshot.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Block on the one-shot fire wake. *field0 starts at 0 (rearm
    // reset), so this can only return via the wake path — the
    // entry-mismatch path is not yet reachable.
    const pairs_a1 = [_]u64{ field0_addr, 0 };
    const wake_a1 = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs_a1[0..]);
    if (wake_a1.v1 != field0_addr) {
        testing.fail(3);
        return;
    }

    // sync + readback. The wake says the fire happened; sync forces
    // an authoritative field0/field1 snapshot before we read.
    const sync_a = syscall.sync(timer_handle);
    if (sync_a.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const post_fire_a = caps.readCap(cap_table_base, timer_handle);
    if (post_fire_a.field0 != 1) {
        testing.fail(5);
        return;
    }
    // §[timer_arm]: "One-shot timers transition `field1.arm` to 0
    // after the single fire". Bit 0 of field1 carries arm.
    if ((post_fire_a.field1 & 0x1) != 0) {
        testing.fail(6);
        return;
    }

    // Probe for a (forbidden) second fire. *field0 == 1 right now,
    // so futex_wait_val(expected=1) sleeps until either a wake on
    // field0_addr or the timeout. A correct one-shot delivers no
    // wake — E_TIMEOUT is the spec-mandated outcome.
    const pairs_a2 = [_]u64{ field0_addr, 1 };
    const wake_a2 = syscall.futexWaitVal(NO_SECOND_FIRE_NS, pairs_a2[0..]);
    if (wake_a2.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
        testing.fail(7);
        return;
    }

    // ---- Half B: periodic = 1 ----
    const rearm_periodic = syscall.timerRearm(timer_handle, DEADLINE_NS, 1);
    if (rearm_periodic.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(8);
        return;
    }

    // First periodic fire. Rearm reset field0 to 0, so this is
    // again a wake-path return.
    const pairs_b1 = [_]u64{ field0_addr, 0 };
    const wake_b1 = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs_b1[0..]);
    if (wake_b1.v1 != field0_addr) {
        testing.fail(9);
        return;
    }

    // Snapshot the current count and wait for the next change.
    // Either the kernel has already advanced past `seen` by the
    // time we make the syscall (entry-mismatch return) or we sleep
    // and the next fire wakes us (wake-path return). Both signal a
    // genuine second fire and both return [1] = field0_addr per
    // §[futex_wait_val] tests 07/08.
    const seen: u64 = caps.readCap(cap_table_base, timer_handle).field0;
    const pairs_b2 = [_]u64{ field0_addr, seen };
    const wake_b2 = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs_b2[0..]);
    if (wake_b2.v1 != field0_addr) {
        testing.fail(10);
        return;
    }

    // While the periodic timer is still firing, field1.arm must
    // remain 1 (§[timer_arm] [test 08]: arm stays set across fires
    // for periodic timers; rearm with periodic=1 inherits the same
    // invariant per §[timer_rearm]).
    const sync_b = syscall.sync(timer_handle);
    if (sync_b.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(11);
        return;
    }
    const post_fires_b = caps.readCap(cap_table_base, timer_handle);
    if ((post_fires_b.field1 & 0x1) != 1) {
        testing.fail(12);
        return;
    }

    // Tidy: cancel so the periodic timer doesn't keep firing into
    // suite shutdown. Errors here are not part of the test 07
    // contract; ignore the return.
    _ = syscall.timerCancel(timer_handle);

    testing.pass();
}
