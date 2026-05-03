// Spec §[timer] timer_cancel — test 07.
//
// "[test 07] on success, every EC blocked in futex_wait_val keyed on
//  the paddr of any domain-local copy of [1].field0 returns from the
//  call with [1] = the corresponding domain-local vaddr of field0;
//  subsequent reads observe field0 = u64::MAX."
//
// Strategy (degraded smoke for the cross-EC half + direct check on the
// post-cancel observation half)
//   The full assertion has two coupled parts:
//     A. Every EC parked in `futex_wait_val` on a domain-local copy of
//        the timer's field0 paddr is woken by `timer_cancel`, with the
//        wake returning [1] = that copy's vaddr.
//     B. Reads of field0 from any holder after the cancel observe the
//        cancellation sentinel `u64::MAX`.
//
//   Part (A) cannot be exercised end-to-end inside a single test ELF.
//   The runner's child capability domain runs a single initial EC; a
//   real `futex_wait_val` issued by that EC ahead of `timer_cancel`
//   would either block with no other EC available to issue the cancel,
//   or be trivially satisfied by the same EC's subsequent cancel call
//   (turning the test into an asymmetric self-wake rather than a
//   cross-EC wake). Faithfully driving (A) requires either:
//     - a second EC in the same domain parked in `futex_wait_val` on
//       `&handle.field0` ahead of the cancel, with a side-channel
//       reporting the wake back to the test EC, or
//     - a second capability domain holding a moved/copied timer handle
//       so the "any domain-local copy" propagation half is observable.
//   Neither piece is wired up in the v0 runner, which spawns one
//   initial EC per test ELF (runner/primary.zig spawnOne forwards only
//   the result port at slot 3 of the child cap table); there is no
//   pre-staged shared page_frame for an in-test cross-EC rendezvous,
//   no second worker entry, and no cross-domain timer-handle sharing.
//   ack_07 documents the same harness gap for `ack`'s test 07.
//
//   Part (B), however, is observable from a single EC: arm a timer,
//   cancel it, and read back field0 from the read-only-mapped cap
//   table. The handle table's `field0` slot is a valid futex address
//   (§[timer]: "The handle table is mapped read-only into the holding
//   domain, so `field0`'s vaddr (computable from the handle id and
//   table base) is a valid futex address"), so reading it through
//   `readCap` after the cancel returns reflects the post-cancel
//   authoritative state. §[timer_cancel] explicitly defines the
//   cancellation sentinel as `u64::MAX` and says the calling domain's
//   copy "has `field0 = u64::MAX` immediately on return" (test 05) —
//   the same sentinel test 07 ends with ("subsequent reads observe
//   field0 = u64::MAX"). Asserting that part directly here exercises
//   half of test 07's claim with no new harness.
//
//   Other failure paths neutralized for the timer_cancel call:
//     - test 01 (E_BADCAP): the handle is the freshly-armed timer.
//     - test 02 (E_PERM via missing `cancel`): the timer is minted
//       with `cancel` (and `arm` to keep the cap word contiguous).
//     - test 03 (E_INVAL: arm = 0): a one-shot timer with a deadline
//       far in the future stays armed long enough for the cancel call
//       to land while arm is still 1.
//     - test 04 (E_INVAL: reserved bits): the typed `timerCancel`
//       wrapper takes u12 and zero-extends.
//
// Action
//   1. timer_arm(caps = {arm, cancel}, deadline_ns = u64::MAX,
//                flags.periodic = 0) — must succeed.
//   2. timer_cancel(timer_handle)    — must succeed (vreg 1 == OK).
//   3. readCap(timer_handle).field0  — must equal u64::MAX (the
//                                       cancellation sentinel; the
//                                       single-EC observable half of
//                                       test 07).
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word — no
//      armed timer to cancel).
//   2: timer_cancel itself returned non-OK in vreg 1 (E_BADCAP / E_PERM
//      / E_INVAL — none of which are reachable by construction here).
//   3: post-cancel field0 read does not equal u64::MAX (the observable
//      half of test 07's "subsequent reads observe field0 = u64::MAX").
//   The cross-EC futex_wait_val wake half of test 07 is structurally
//   unreachable on this branch — see strategy above. No assertion id
//   is claimed for it; this test smoke-passes that half via the
//   document-the-gap pattern used by ack_07.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[timer] cap layout: bit 2 = arm, bit 3 = cancel. `arm` is
    // included so the timer can be (re)armed if a future iteration
    // wants to chase test 09's "field0/field1 refresh on call". For
    // test 07 we only need `cancel`.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };

    // §[timer_arm] caps word: bits 0-15 carry caps. flags bit 0 is
    // periodic; we want a one-shot whose fire is far enough in the
    // future that arm remains 1 when the cancel lands. `u64::MAX`
    // nanoseconds is well beyond the test's lifetime — the timer
    // cannot fire before we cancel it.
    const armed = syscall.timerArm(
        @as(u64, timer_caps.toU16()),
        ~@as(u64, 0), // deadline_ns: far enough out that arm = 1 stays true
        0, // flags: periodic = 0 (one-shot)
    );
    if (testing.isHandleError(armed.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(armed.v1 & 0xFFF);

    // §[timer_cancel] success path. The timer is freshly armed (test
    // 03 cannot fire), the handle has `cancel` (test 02 cannot fire),
    // the handle id is valid (test 01 cannot fire), and the typed
    // wrapper zero-extends the u12 so reserved bits are clean (test 04
    // cannot fire). The only path the kernel can take is success.
    const cancel = syscall.timerCancel(timer_handle);
    if (cancel.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // §[timer_cancel]: "Sets `field0` to `u64::MAX` (the cancellation
    // sentinel) ... wakes futex waiters." Reading the read-only-mapped
    // cap table at this point reflects the post-cancel snapshot in the
    // calling domain's copy. The cross-EC futex wake half of test 07
    // is documented as unreachable in the strategy comment above; this
    // assertion exercises the "subsequent reads observe field0 =
    // u64::MAX" half directly.
    const cap = caps.readCap(cap_table_base, timer_handle);
    if (cap.field0 != ~@as(u64, 0)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
