// Spec §[recv] — test 13 (degraded smoke).
//
// "[test 13] when multiple senders are queued, the kernel selects the
//  highest-priority sender; ties resolve FIFO."
//
// Spec semantics
//   §[recv]: "When multiple senders are queued on the port, the kernel
//   selects the highest-priority sender; ties resolve FIFO. The chosen
//   sender remains suspended until the reply handle is consumed."
//   This is the same wake-ordering claim that priority_06 calls out
//   for the futex/recv pair: the per-EC priority field set via
//   `priority` determines the dequeue order, with FIFO breaking ties
//   among equal-priority senders.
//
// Faithful test blocker
//   The full assertion needs at least three coordinated ECs:
//     - two (or more) sender ECs that each issue `suspend` against the
//       same port, with priorities arranged so the receiver's recv
//       dequeues a known order,
//     - a third EC (the test EC) that holds the port's `recv` cap,
//       waits until both senders are reliably enqueued, and then
//       issues `recv` to observe which sender comes off first,
//     - a side channel from the dequeued sender back to the test EC
//       carrying that sender's identity (so "highest priority first;
//       ties FIFO" can be verified across multiple recv rounds).
//
//   None of those harness pieces exist in the v0 spec-test runner:
//     - The runner spawns one initial EC per test ELF; bringing up
//       additional cooperating ECs from inside this test means
//       composing `create_execution_context` for two senders, each
//       with its own stack, plus a synchronization primitive (futex
//       or a separate signaling port) so the test EC can know both
//       senders have entered their `suspend` calls. Stack-relative
//       per-EC state distribution is not yet validated end-to-end
//       across the spec-test suite, and `priority` test 06 / test 07
//       both document the same blocker rather than wire that
//       choreography up themselves.
//     - `suspend` with attachments (`N > 0`) is not wired through libz
//       (suspendEc panics on N > 0; see syscall.zig), so even staging
//       the senders to attach an identity vreg payload requires
//       inline-asm composition inside the test. The test 13 assertion
//       does not require attachments — it only constrains dequeue
//       order — but observing the dequeued identity from inside the
//       receiver typically wants a sender-supplied marker.
//     - The recv-side observation has to compare sender identities
//       across rounds. Until the senders can be uniquely identified
//       through some kernel-mediated channel (their EC handle ids in
//       the receiver's table, an attached marker vreg, etc.) the
//       result of recv is opaque — the receiver gets a reply handle
//       and event-state vregs but cannot in general read back "which
//       sender was that".
//
//   The same blocker applies to `priority` test 06 (futex/recv wake
//   ordering) and priority test 07 (next-wake takes new priority);
//   both of those tests landed degraded smoke variants pending
//   multi-EC harness work. recv test 13 reduces to the same shape.
//
// Degraded smoke
//   This test exercises the building blocks the faithful test would
//   compose, on the success-path side of each:
//     1. create_port with `xfer | recv | bind` — the port the
//        receiver would `recv` on. Confirms the kernel mints a port
//        that carries the `recv` cap (test 02 gate) under the
//        runner-provided port_ceiling = 0x1C (xfer/recv/bind).
//     2. create_execution_context for an EC with `spri` so the test
//        could later raise its priority — confirms the `spri` cap
//        is grantable on a freshly-created EC, which is the
//        precondition for arranging "highest-priority sender wins".
//     3. priority(child_ec, 1) — confirms the priority syscall
//        actually accepts a priority change on a non-running target,
//        the central mechanism the spec assertion turns on.
//   None of those calls exercises the dequeue-order claim itself.
//   They confirm the call shapes the faithful test would chain.
//
//   The runner's port_ceiling and self-handle priority ceiling (3)
//   are wide enough for these three steps to all be on the success
//   path, so any non-OK return here surfaces a regression in the
//   underlying syscalls rather than something specific to test 13.
//
//   The day a multi-EC + cross-EC-identity harness lands, this test
//   should be rewritten to:
//     - spawn two sender ECs, one at priority 0 and one at priority
//       1, both targeting `port`,
//     - wait for both to enqueue,
//     - issue recv twice and assert the priority-1 sender dequeues
//       first (highest-priority-first), then
//     - re-run with both senders at the same priority and assert
//       FIFO order on the dequeues.
//
// Action
//   1. create_port(caps = {xfer, recv, bind})         — must succeed.
//   2. create_execution_context(target = self,
//                               caps = {spri, susp, term, restart=0},
//                               entry = &dummyEntry,
//                               stack_pages = 1,
//                               affinity = 0)         — must succeed.
//   3. priority(child_ec, new_priority = 1)           — must succeed.
//
// Assertions
//   1: create_port returned an error (port plumbing for recv broken)
//   2: create_execution_context returned an error (cannot stage the
//      sender ECs the faithful test would queue)
//   3: priority returned non-OK (cannot arrange highest-priority
//      sender; the dequeue-order assertion has no mechanism to bias)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[port] PortCap: `recv` (bit 3) gates the recv syscall on this
    // handle (§[recv] cap requirement, test 02). `bind` keeps the port
    // open against the test 04/05 closed-port paths so a future
    // strengthening of this test does not flap on terminal-close
    // races. `xfer` is included because the faithful test will want
    // attached-handle markers to identify dequeued senders. The
    // runner's port_ceiling is 0x1C (xfer | recv | bind), so this
    // exact set is the maximal subset and creation must succeed.
    const port_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    // The minted port handle is intentionally not used past this point
    // — the faithful test would queue senders against it and then call
    // `recv`. Issuing `recv` here with no senders enqueued and the
    // bind-cap-holding handle live would block the test EC forever
    // (§[recv] only returns E_CLOSED when there are no bind holders,
    // no event_routes, and no queued events; we hold a bind handle
    // ourselves). Documented gap; do not call recv from this branch.

    // §[execution_context] EcCap: `spri` is the cap that gates the
    // priority syscall on the resulting handle (priority test 02).
    // `susp` and `term` are added so the handle's caps stay well
    // within the runner's ec_inner_ceiling = 0xFF and so the EC can
    // be cleaned up without interaction with restart_policy ceilings
    // (the faithful test will need `susp` on the senders so the test
    // EC can suspend them on the port). restart_policy = 0 keeps the
    // handle inside the inner ceiling for restart_semantics test 01.
    const ec_caps = caps.EcCap{
        .spri = true,
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word layout:
    //   bits  0-15: caps         ({spri, susp, term})
    //   bits 16-31: target_caps  (ignored when target = 0)
    //   bits 32-33: priority     (0 — within caller's pri = 3 ceiling)
    //   bits 34-63: _reserved
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — non-zero (create_execution_context test 08)
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const child_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // §[priority]: priority([1] target, [2] new_priority). Caller's
    // pri ceiling is 3 (runner-minted self caps); new_priority = 1
    // sits at "elevated relative to default 0" — exactly the bias the
    // faithful test 13 would arrange between the two senders. Handle
    // is fresh+valid with reserved bits clean, and `spri` is set on
    // the EC handle, so the only kernel path is success.
    const pri_result = syscall.priority(child_ec, 1);
    if (pri_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
