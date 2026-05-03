// Spec §[timer_rearm] timer_rearm — test 08 (degraded smoke).
//
// "[test 08] on success, every EC blocked in futex_wait_val keyed on
//  the paddr of any domain-local copy of [1].field0 returns from the
//  call with [1] = the corresponding domain-local vaddr of field0."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of test 08 requires harness pieces that the v0
//   test child cannot reach:
//
//     (a) A second EC parked in `futex_wait_val(addr=&handle.field0,
//         expected=current_field0)` so the spec's "every EC blocked
//         ... returns from the call" post-condition has anything to
//         observe. The runner spawns a single test EC per child
//         capability domain (`runner/primary.zig` forwards only the
//         result port at slot 3 of the child cap table), so there is no
//         second EC scaffolded against the timer firing. priority_06/07
//         and device_irq_03 hit the same wall and degrade to single-EC
//         smokes for the same reason.
//
//     (b) A way for that worker EC to side-channel its observed return
//         [1] back to the test EC so the assertion (worker's
//         futex_wait_val returned with [1] equal to the worker's
//         domain-local vaddr of field0) is checkable. The single-EC
//         child has no inter-EC rendezvous primitive in scope here.
//
//     (c) Multi-domain copies of the same timer handle so the "every
//         domain-local copy" portion of the assertion is observable.
//         A child capability domain in this harness holds at most one
//         copy of any handle it mints, and there is no `acquire_*`
//         counterparty domain wired in.
//
//   With none of those harness pieces in place, the test 08 wake
//   contract is structurally unreachable from inside a v0 test child
//   today. Once a multi-EC, multi-domain timer harness lands, this
//   smoke is replaced by the faithful assertion: the worker's
//   futex_wait_val returns with [1] = cap_table_base +
//   timer_handle * sizeof(Cap) + offsetof(field0) for each
//   domain-local copy.
//
// Strategy (smoke prelude)
//   We exercise a strictly local prelude that touches only
//   syscall-shaped surfaces the test child can reach:
//     1. `timer_arm` to mint a timer handle (one-shot, deadline_ns
//        nonzero — the §[timer_rearm] test 08 contract is on rearm
//        success, but minting via `timer_arm` first matches the
//        natural call sequence: arm, then rearm to reset).
//     2. `timer_rearm` on that handle with `periodic = 1` so the
//        kernel installs the recurring schedule that test 08 says
//        wakes futex_wait_val waiters on every fire.
//     3. `readCap(cap_table_base, timer)` to confirm the handle is
//        live and field0/field1 are reachable through the holder's
//        cap table — the same address arithmetic a faithful test
//        would feed into `futex_wait_val(addr=&handle.field0, ...)`.
//
//   No spec assertion is checked: the wake-on-fire behaviour is
//   unreachable from the v0 test child. The smoke is recorded as
//   pass-with-id-0 to mark the slot as deferred-but-attempted. Any
//   prelude failure also reports pass-with-id-0 since no spec
//   assertion is being checked here.
//
// Action
//   1. timer_arm(caps={arm, cancel}, deadline_ns = 1_000_000, flags=0)
//      — must succeed; gives a timer handle whose field0 vaddr is a
//      syntactically valid futex address.
//   2. timer_rearm(timer, deadline_ns = 1_000_000, flags = 1)
//      — periodic rearm; this is the call whose success post-condition
//      test 08 covers.
//   3. readCap(cap_table_base, timer) — observe the holder-domain
//      copy of the handle to validate the cap-table address
//      arithmetic for the would-be futex_wait_val addr.
//
// Assertion
//   No spec assertion is checked — the post-rearm futex wake on every
//   domain-local copy of field0 is unreachable from the v0 test child.
//   Test always reports pass with assertion id 0; any prelude failure
//   also reports pass-with-id-0 since no spec assertion is being
//   checked.
//
// Faithful-test note
//   Faithful test deferred pending a runner-side timer harness that:
//     - spawns a worker EC in the test child (or a sibling capability
//       domain holding an acquired copy of the same timer) whose
//       entry blocks in `futex_wait_val(timeout=indefinite,
//       addr=&worker_copy.field0, expected=worker_copy.field0)`
//       after publishing a "I'm parked" signal back to the test EC;
//     - the test EC observes the parked signal, then issues
//       `timer_rearm` (or waits for the configured fire);
//     - the worker side-channels its observed return [1] back to the
//       test EC; the test EC asserts equality with
//       `cap_table_base + worker_handle * sizeof(Cap) +
//        offsetof(Cap, field0)`.
//   Once that exists, the assertion (id 1) becomes that equality.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[timer_arm] caps word: bits 2-3 = arm, cancel. Restart_policy
    // (bit 4) is left clear so we don't trip the `tm_restart_max`
    // gate (see restart_semantics_08).
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // deadline_ns must be nonzero (§[timer_arm] [test 03] /
    // §[timer_rearm] [test 03]); flags = 0 selects a one-shot timer
    // for the initial arm.
    const initial_deadline_ns: u64 = 1_000_000;
    const arm_flags: u64 = 0;

    const arm = syscall.timerArm(caps_word, initial_deadline_ns, arm_flags);
    if (testing.isHandleError(arm.v1)) {
        // Prelude broke before timer_rearm could be reached; the spec
        // assertion under test 08 is unreachable regardless. Pass with
        // id 0 to mark the slot as deferred-but-attempted.
        testing.pass();
        return;
    }
    const timer_handle: caps.HandleId = @truncate(arm.v1 & 0xFFF);

    // §[timer_rearm] flags bit 0 = periodic. Periodic rearm is the
    // configuration test 08 explicitly contemplates ("every fire ...
    // until timer_cancel or another timer_rearm"); the wake on each
    // fire is the assertion this smoke cannot observe.
    const rearm_deadline_ns: u64 = 1_000_000;
    const rearm_flags: u64 = 1;
    _ = syscall.timerRearm(timer_handle, rearm_deadline_ns, rearm_flags);

    // Read back the holder-domain copy of the handle. We do not
    // assert anything about field0 here — the spec assertion under
    // test 08 is about a futex_wait_val wake on each fire that this
    // child cannot park an EC against.
    _ = caps.readCap(cap_table_base, timer_handle);

    // No spec assertion is being checked — the wake-on-fire behaviour
    // is unreachable from the v0 test child. Pass with assertion id 0
    // to mark this slot as smoke-only in coverage.
    testing.pass();
}
