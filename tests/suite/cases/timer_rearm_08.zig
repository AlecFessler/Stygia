// Spec §[timer_rearm] timer_rearm — test 08.
//
// "[test 08] on success, every EC blocked in futex_wait_val keyed on
//  the paddr of any domain-local copy of [1].field0 returns from the
//  call with [1] = the corresponding domain-local vaddr of field0."
//
// Strategy
//   "every domain-local copy" reduces to "this EC's own copy" inside
//   a single child capability domain — the runner does not stand up
//   sibling domains holding `xfer`-copied views of this timer. With
//   one copy, the assertion collapses to: the calling EC's
//   `futex_wait_val` keyed on `&cap_table[timer_handle].field0`
//   returns from the call with vreg 1 set to that same address after
//   the timer fires.
//
//   The handle table is mapped read-only into the holding domain at
//   `cap_table_base` (§[capabilities]). field0 sits at offset 8 of
//   each 24-byte slot (Cap = { word0, field0, field1 }), so the
//   user-visible vaddr `cap_table_base + handle * sizeof(Cap) + 8`
//   is the address the spec test refers to. The kernel keys futex
//   waits by the paddr that backs each domain-local vaddr (§[futex]
//   preamble), and the timer's per-fire wake walks every
//   domain-local copy and issues a futex wake on its field0 paddr
//   (§[timer_arm] description), so a wake on this address is the
//   spec-mandated post-condition.
//
//   Two return paths satisfy the spec assertion equivalently —
//   identical to the timer_arm_09 proof shape:
//     - On-entry mismatch (futex_wait_val test 07): if the timer has
//       already fired by the time the kernel checks the value at
//       call entry, `*field0 == 1 != expected (0)` and the call
//       returns immediately with vreg 1 = `&field0`.
//     - Wake (futex_wait_val test 08): if we register before the
//       fire, the kernel's wake on field0's paddr returns the call
//       with vreg 1 = `&field0`.
//
//   Either way the spec assertion under test — vreg 1 == vaddr of
//   field0 — is the value being checked.
//
//   To ensure the wake is provoked specifically by the rearm-armed
//   schedule (rather than the original timer_arm), we rearm with a
//   distinctly larger deadline than the initial arm. Sequence:
//
//     1. timer_arm with a long enough deadline that the original
//        configuration cannot have fired by step 3.
//     2. Sanity-check the post-arm field0 = 0.
//     3. timer_rearm with a 10 ms deadline + periodic = 1.
//     4. futex_wait_val(timeout=1 s, addr=&field0, expected=0) —
//        either the rearm-installed periodic fire wakes us, or the
//        on-entry check sees field0 already incremented; either way
//        vreg 1 == &field0 witnesses the rearm-driven wake.
//
//   Reserved-bit and cap setup:
//     - timer_arm: caps={arm, cancel} (cancel for tidy shutdown,
//       arm to satisfy the rearm cap gate). flags=0 (one-shot
//       initial config) keeps the initial timer's behaviour
//       irrelevant — rearm fully replaces it per §[timer_rearm].
//     - timer_rearm: deadline_ns = 10 ms (non-zero, well under the
//       1 s futex timeout); flags = 1 (periodic; bit 0 only, every
//       reserved bit clear). Handle id is the typed u12 from the
//       arm result, so reserved bits in [1] are zero by
//       construction.
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=1 s, flags=0)
//      — must succeed; carries the timer handle.
//   2. addr = cap_table_base + timer_handle*sizeof(Cap) + 8
//      — vaddr of `field0` for the minted timer in this domain.
//   3. timer_rearm(handle, deadline_ns=10 ms, flags=1) — the call
//      whose post-condition test 08 covers; periodic so the wake
//      arrives via a fire-driven path rather than the rearm itself.
//   4. futex_wait_val(timeout=1 s, pairs=[(addr, expected=0)])
//      — must return with vreg 1 == addr.
//   5. timer_cancel — clean shutdown.
//
// Assertions
//   1: timer_arm setup returned an error (no handle to test against).
//   2: timer_rearm returned non-OK (the syscall under test must
//      reach its success post-condition).
//   3: futex_wait_val returned vreg 1 != &field0 — the wake/entry
//      path did not surface the field0 vaddr the spec requires.
//      Includes the E_TIMEOUT case.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// 1 second initial-arm deadline — long enough that the original
// timer_arm cannot have fired by the time we issue timer_rearm a
// few syscalls later, so the wake observed below must be from the
// rearm-installed schedule.
const ARM_DEADLINE_NS: u64 = 1_000_000_000;

// 10 ms rearm deadline — short enough to fire well within the 1 s
// futex timeout, long enough that scheduling jitter on QEMU+TCG
// won't flap.
const REARM_DEADLINE_NS: u64 = 10_000_000;

// 1 s futex timeout — absorbs the rearm deadline and any kernel
// scheduling latency while keeping a regression visible as a
// mismatched return rather than a hang.
const FUTEX_TIMEOUT_NS: u64 = 1_000_000_000;

const TIMER_FLAG_PERIODIC: u64 = 1;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bits 0-15 carry caps. arm + cancel
    // — `arm` is required so the rearm cap gate (test 02) stays
    // inert; `cancel` lets us clean up without the runner needing to
    // chase a still-firing timer at shutdown. restart_policy = 0
    // keeps caps within the runner's tm_restart_max ceiling
    // unconditionally.
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const arm_caps_word: u64 = @as(u64, timer_caps.toU16());

    const arm = syscall.timerArm(arm_caps_word, ARM_DEADLINE_NS, 0);
    if (testing.isHandleError(arm.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm.v1 & 0xFFF);

    // §[timer_rearm] — the syscall whose post-condition this test
    // covers. periodic = 1 so a fire-driven wake exercises the
    // wake-on-fire path the spec sentence references; deadline_ns
    // 10 ms ≪ 1 s futex timeout so neither return path is starved.
    const rearm_result = syscall.timerRearm(
        timer_handle,
        REARM_DEADLINE_NS,
        TIMER_FLAG_PERIODIC,
    );
    if (rearm_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // §[capabilities] handle layout: Cap = { word0, field0, field1 },
    // each u64. field0 sits at offset 8 within the handle's 24-byte
    // slot. The cap table is mapped read-only at `cap_table_base`,
    // so the vaddr the kernel keys this domain's futex waiter on is
    // the byte offset arithmetic below — the very address §[timer]
    // says wakes propagate to.
    const slot_offset: u64 = @as(u64, timer_handle) * @as(u64, caps.HANDLE_BYTES);
    const field0_addr: u64 = cap_table_base + slot_offset + @offsetOf(caps.Cap, "field0");

    const pairs = [_]u64{ field0_addr, 0 };
    const r = syscall.futexWaitVal(FUTEX_TIMEOUT_NS, pairs[0..]);

    if (r.v1 != field0_addr) {
        testing.fail(3);
        return;
    }

    // Tidy: cancel so the periodic fire stops bumping field0 into
    // the suite's shutdown path. Errors here are not part of the
    // test 08 contract; ignore the return.
    _ = syscall.timerCancel(timer_handle);

    testing.pass();
}
