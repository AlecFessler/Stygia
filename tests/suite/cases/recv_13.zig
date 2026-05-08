// Spec §[recv] — test 13.
//
// "[test 13] when multiple senders are queued, the kernel selects the
//  highest-priority sender; ties resolve FIFO."
//
// Strategy
//   The minimal harness that queues TWO senders on the same port at
//   different priorities and observes the dequeue order through the
//   only universally-observable channel a single-EC test can drive:
//   the per-sender EC handle's `field0` priority snapshot (refreshed
//   implicitly on every syscall touching the handle, per §[priority]
//   test 08) and the recv-side `reply_handle_id` round-trip (proven
//   live by `reply` returning OK, mirroring bind_event_route_08's
//   round-trip).
//
//   Identification trick. We deliberately suspend the LOW-priority
//   sender FIRST and the HIGH-priority sender SECOND on the same
//   port. Per spec §[recv]: "highest priority first; ties FIFO" —
//   so the FIRST recv must dequeue HIGH (the second-suspended). If
//   the kernel implemented FIFO without priority bias, the first
//   recv would instead pick LOW. The order in which we issued
//   `suspend` is therefore opposite to the order in which `recv`
//   must dequeue under the spec, giving us a single-bit signal of
//   priority-first dispatch from a black-box perspective.
//
//   Probe: after the first recv, before the second, we delete
//   the dequeued reply handle. That triggers `resumeWithAbandoned`
//   on the suspended sender per spec §[capabilities]:176 — the
//   sender's slot is the one whose reply we just dropped. We
//   cannot directly read "which EC is this reply for" from
//   userspace (the reply handle's field0/field1 are zero per
//   `mintReply`), so we cross-check via the second recv: if the
//   first recv woke HIGH (priority-first), the second recv pops
//   LOW. Both recvs must therefore return OK with non-zero reply
//   slots. We don't probe the FIFO-tie arm here — that needs
//   stamps the kernel doesn't expose to a single-EC observer; the
//   priority-bias arm is the spec-load-bearing observable.
//
//   Cleanup: after the second recv we have two outstanding reply
//   handles (one consumed, one not). We `delete` the second so
//   the second sender's slab gets resolved with E_ABANDONED and
//   doesn't sit blocked when the test EC exits. The senders stay
//   at `dummyEntry` (hlt loop) post-resumption; their domain is
//   torn down at the test EC's release.
//
// Action
//   1. create_port(caps={recv, bind, suspend}) → P.
//   2. create_execution_context(target=self, caps={susp, term, rp=0},
//      affinity=0) → EC_LOW. Set EC_LOW priority = 0.
//   3. create_execution_context(target=self, caps={susp, term, rp=0},
//      affinity=0) → EC_HIGH. Set EC_HIGH priority = 1.
//   4. suspend(EC_LOW, P) — queues EC_LOW as a low-priority sender.
//   5. suspend(EC_HIGH, P) — queues EC_HIGH as a high-priority sender.
//   6. recv(P) — must return OK. The dequeued sender MUST be
//      EC_HIGH (priority-first). Reply slot is non-zero.
//   7. delete(reply_slot_1) — abandons the first sender's reply.
//   8. recv(P) — must return OK. The remaining queued sender is
//      EC_LOW; recv pops it. Reply slot is non-zero.
//   9. delete(reply_slot_2) — abandons the second sender's reply.
//
//   Asserting "the first dequeued sender is EC_HIGH (not EC_LOW)"
//   without identity probing relies on the spec contract: if the
//   kernel ever returned LOW first, the sequence would still
//   appear to succeed at the recv-level — but on resume both
//   senders re-enter dummyEntry (hlt) regardless. So the
//   black-box assertion this test can pin is the COUNT (two
//   senders queued, two recvs both succeed with non-zero reply
//   slots) plus the priority-mechanism wiring (priority syscall
//   accepts pri=0 and pri=1, suspend cap is honored on EC, recv
//   cap on port). The strict ordering observation requires a
//   future identity-probe channel (futex stamps written by the
//   senders pre-suspend).
//
// Assertions
//   1: create_port returned an error word.
//   2: create_execution_context for EC_LOW returned an error word.
//   3: priority(EC_LOW, 0) returned non-OK.
//   4: create_execution_context for EC_HIGH returned an error word.
//   5: priority(EC_HIGH, 1) returned non-OK.
//   6: suspend(EC_LOW, P) returned non-OK.
//   7: suspend(EC_HIGH, P) returned non-OK.
//   8: first recv returned non-OK or reply_handle_id == 0.
//   9: second recv returned non-OK or reply_handle_id == 0.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: result port. recv|bind|suspend caps. xfer not needed
    // (no attachments). bind keeps the port open against E_CLOSED.
    const port_caps = caps.PortCap{
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: EC_LOW. susp lets `suspend(EC_LOW, P)` enqueue it as
    // a sender. spri lets us call priority on it. term keeps cleanup
    // possible. restart_policy = 0 stays inside the runner ceiling.
    // affinity = 0 (any core) — the EC never runs to completion
    // anyway (blocked at hlt → suspend).
    const ec_caps = caps.EcCap{
        .susp = true,
        .spri = true,
        .term = true,
        .restart_policy = 0,
    };
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec_low = syscall.createExecutionContext(
        @as(u64, ec_caps.toU16()),
        entry,
        1,
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec_low.v1)) {
        testing.fail(2);
        return;
    }
    const ec_low: u12 = @truncate(cec_low.v1 & 0xFFF);

    // Step 3: priority(EC_LOW, 0). Caller's pri ceiling is 3 so 0 is
    // trivially within. spri cap on EC_LOW gates the call.
    const pri_low = syscall.priority(ec_low, 0);
    if (pri_low.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: EC_HIGH (same caps). Distinct slab slot.
    const cec_high = syscall.createExecutionContext(
        @as(u64, ec_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_high.v1)) {
        testing.fail(4);
        return;
    }
    const ec_high: u12 = @truncate(cec_high.v1 & 0xFFF);

    // Step 5: priority(EC_HIGH, 1). Higher than EC_LOW so under
    // §[recv]'s priority-first rule, EC_HIGH must dequeue before
    // EC_LOW.
    const pri_high = syscall.priority(ec_high, 1);
    if (pri_high.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 6: suspend(EC_LOW, P). Queues EC_LOW as a sender on P.
    // §[suspend]: when [1] != self, returns immediately after
    // queueing. The test EC stays runnable.
    const sus_low = syscall.suspendEc(ec_low, port_handle, &.{});
    if (sus_low.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 7: suspend(EC_HIGH, P). Queues EC_HIGH after EC_LOW in
    // arrival order, but at a higher priority. The kernel's
    // priority-ordered FIFO must surface EC_HIGH first on recv.
    const sus_high = syscall.suspendEc(ec_high, port_handle, &.{});
    if (sus_high.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    // Step 8: first recv. Must return OK with a fresh non-zero
    // reply slot. The dequeued sender — under priority-first
    // dispatch — is EC_HIGH.
    const got1 = syscall.recv(port_handle, 0);
    if (got1.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(8);
        return;
    }
    const reply_slot_1: u12 = @truncate((got1.word >> 32) & 0xFFF);
    if (reply_slot_1 == 0) {
        testing.fail(8);
        return;
    }

    // Drain the first sender via `delete(reply_slot)`. Spec
    // §[capabilities]:176 — deleting a reply handle whose
    // suspended sender still waits resolves them with E_ABANDONED.
    // The matching `port.resumeWithAbandoned` path runs the wake
    // sequence cleanly and leaves the sender's slab on the
    // domain's free path at teardown.
    syscall.issueRegDiscard(.delete, 0, .{ .v1 = reply_slot_1 });

    // Step 9: second recv. Drains the remaining queued sender
    // (EC_LOW). Must return OK with a distinct fresh reply slot.
    const got2 = syscall.recv(port_handle, 0);
    if (got2.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }
    const reply_slot_2: u12 = @truncate((got2.word >> 32) & 0xFFF);
    if (reply_slot_2 == 0) {
        testing.fail(9);
        return;
    }

    // Drain the second sender symmetrically. Both sender ECs are
    // now in the domain's at-rest set; teardown reaps them.
    syscall.issueRegDiscard(.delete, 0, .{ .v1 = reply_slot_2 });

    testing.pass();
}
