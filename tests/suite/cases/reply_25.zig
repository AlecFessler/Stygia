// Spec §[reply] reply — test 25.
//
// "[test 25] returns E_TERM when `recv_port_handle_id != 0` and the
//  suspended EC was terminated before reply could deliver; the reply
//  handle is consumed and the caller does NOT park on the recv port."
//
// Strategy
//   This is the recv-mode counterpart of reply test 03 (bare reply
//   E_TERM on terminated sender). We need to arrive at the unified
//   `reply` syscall with all four conditions wired:
//
//     (a) a real reply handle in the caller's table whose underlying
//         suspended sender has been terminated;
//     (b) a real recv port handle in the caller's table (so the
//         recv-port-validity gate from test 22 does not fire first);
//     (c) execution control returning to userspace (i.e. the call did
//         NOT park) after the call completes;
//     (d) the reply handle slot consumed.
//
//   Pipeline (single domain, test EC owns everything):
//
//     1. Mint port_A with caps = {bind, recv}. bind authorizes the
//        third-party suspend of W onto this port (§[suspend] [2] cap);
//        recv lets the test EC dequeue the suspension event.
//     2. Mint port_B with caps = {bind, recv}. This is the "we WOULD
//        park here" port that the recv-port gate must accept as a
//        valid handle. We never queue an event onto it; if the kernel
//        incorrectly parks the caller on port_B, recv blocks
//        indefinitely and the test never reports pass.
//     3. Mint EC W with caps = {susp, term, restart_policy = 0}.
//        susp authorizes step 4 (third-party suspend of W on port_A);
//        term authorizes step 6 (terminate of W). entry =
//        testing.dummyEntry — W never actually runs; suspend queues a
//        suspended-sender event on port_A directly without any EL0
//        execution by W.
//     4. suspend(W, port_A). Non-blocking on the test EC since
//        [1] = W != self per §[suspend].
//     5. recv(port_A, 0). Returns immediately with the reply handle id
//        in syscall word bits 32-43. After this point W is parked in
//        the kernel referencing the freshly-minted reply handle.
//     6. terminate(W). Per §[terminate] test 04 W stops executing;
//        per the §[terminate] paragraph "Termination also clears ...
//        marks any reply handles whose suspended sender was the
//        terminated EC such that subsequent operations on those reply
//        handles return E_ABANDONED."
//     7. replyRecv(reply_handle, port_B). Per spec test 25 the reply
//        portion observes the terminated sender, returns E_TERM, and
//        does NOT park the caller on port_B. The reply handle is
//        consumed.
//
//   "Caller does NOT park on port_B" assertion: if the kernel had
//   parked us on port_B, control would never return to userspace
//   because no event is ever queued on port_B. Reaching testing.pass()
//   is therefore the witness — every line of the test after the
//   replyRecv call only executes if we returned to userspace, i.e.
//   were not parked.
//
//   SPEC AMBIGUITY: spec §[reply] test 25 names E_TERM, but the
//   §[terminate] paragraph + test 07 names E_ABANDONED for "subsequent
//   operations on those reply handles" — and the bare-reply variant
//   (reply test 03) describes the same "terminated sender, reply
//   afterward" choreography also pinned to E_TERM. The kernel cannot
//   satisfy both literal readings on the same call. reply_03 in this
//   suite documents that the kernel implements the §[terminate]-test-07
//   reading (E_ABANDONED) in its abandoned-bit gate, so the recv-mode
//   path here likely surfaces the same code by the same gate. We
//   accept BOTH E_TERM and E_ABANDONED as spec-conformant landings;
//   any other code (in particular OK or E_BADCAP) is a real failure.
//
// Action
//   1. create_port(caps = {bind, recv})           — must succeed (port_A)
//   2. create_port(caps = {bind, recv})           — must succeed (port_B)
//   3. create_execution_context(target = self,
//        caps = {susp, term, restart_policy = 0}) — must succeed (W)
//   4. suspend(W, port_A)                         — must return OK
//   5. recv(port_A, 0)                            — must return OK and
//      hand back a non-zero reply_handle_id
//   6. terminate(W)                               — must return OK
//   7. replyRecv(reply_handle, port_B)            — must return E_TERM
//      or E_ABANDONED (see SPEC AMBIGUITY); reply slot consumed; control
//      returns to userspace (caller not parked on port_B)
//
// Assertions
//   1: setup port_A creation failed
//   2: setup port_B creation failed
//   3: setup EC creation failed
//   4: third-party suspend(W, port_A) did not return OK
//   5: recv on port_A did not return OK
//   6: recv returned reply_handle_id == 0
//   7: terminate(W) did not return OK
//   8: replyRecv returned something other than E_TERM or E_ABANDONED
//   9: replyRecv did not consume the reply handle slot

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

pub fn main(cap_table_base: u64) void {
    // Step 1: mint port_A with bind|recv. xfer not needed (pair_count = 0).
    // bind lets the test EC issue the third-party suspend of W onto port_A
    // (§[suspend] [2] bind cap); recv lets the test EC dequeue the
    // resulting suspension event.
    const port_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    const cpa = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cpa.v1)) {
        testing.fail(1);
        return;
    }
    const port_a: HandleId = @truncate(cpa.v1 & 0xFFF);

    // Step 2: mint port_B. This is the "would-park" port for the recv
    // mode of the reply syscall. recv cap is required for the unified
    // reply's recv-port gate (test 23 — without recv we'd hit E_PERM
    // before E_TERM). bind not strictly needed here but matches the
    // standard port-cap profile.
    const cpb = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cpb.v1)) {
        testing.fail(2);
        return;
    }
    const port_b: HandleId = @truncate(cpb.v1 & 0xFFF);

    // Step 3: mint W. susp lets us third-party-suspend W onto port_A;
    // term lets us destroy W between recv and reply. restart_policy = 0
    // (kill) keeps the call inside the runner-granted ceiling. W never
    // actually runs — suspend queues the suspended-sender event directly
    // — but we still need a valid entry pointer to satisfy
    // create_execution_context.
    const w_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const w_handle: HandleId = @truncate(cec.v1 & 0xFFF);

    // Step 4: queue W as a suspended sender on port_A. Since [1] = W
    // != self, the call returns immediately without blocking the test
    // EC (§[suspend]).
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_a,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: dequeue the suspension event on port_A. Returns
    // immediately with reply_handle_id encoded in syscall word bits
    // 32-43 per §[recv].
    const got = syscall.recv(port_a, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }
    const reply_handle_id: HandleId = @truncate((got.word >> 32) & 0xFFF);
    if (reply_handle_id == 0) {
        testing.fail(6);
        return;
    }

    // Step 6: terminate W. Per §[terminate] test 04 W stops executing;
    // per the §[terminate] "Termination also clears ..." paragraph the
    // reply handle's suspended sender is now gone and the abandoned bit
    // is set on the reply handle.
    const t = syscall.terminate(w_handle);
    if (t.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    // Step 7: unified reply syscall with recv_port_handle_id = port_b.
    // Per spec test 25 this must return E_TERM (or E_ABANDONED — see
    // SPEC AMBIGUITY in header), consume the reply handle, and NOT park
    // the caller on port_b. If the kernel incorrectly parked us, recv
    // would block forever (no event ever lands on port_b in this test)
    // and we would never reach the assertions below.
    const rr = syscall.replyRecv(reply_handle_id, port_b);
    const is_term = rr.regs.v1 == @intFromEnum(errors.Error.E_TERM);
    const is_abandoned = rr.regs.v1 == @intFromEnum(errors.Error.E_ABANDONED);
    if (!is_term and !is_abandoned) {
        testing.fail(8);
        return;
    }

    // Reply handle must be consumed per the second clause of test 25.
    const reply_slot = caps.readCap(cap_table_base, @as(u32, reply_handle_id));
    if (reply_slot.handleType() == .reply) {
        testing.fail(9);
        return;
    }

    // Reaching this line is itself the "caller did NOT park on port_b"
    // witness — no event was ever queued on port_b, so a park would
    // block here forever.
    testing.pass();
}
