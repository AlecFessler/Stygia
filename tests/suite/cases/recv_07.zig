// Spec §[recv] recv — test 07.
//
// "[test 07] on success, the syscall word's reply_handle_id is the
//  slot id of a reply handle inserted into the caller's table
//  referencing the dequeued sender."
//
// Strategy
//   The assertion has two halves:
//     (a) The slot the kernel reports in the recv syscall word at
//         `reply_handle_id` (bits 32-43) must hold a handle of type
//         `reply` (handle-type tag 7 per §[capabilities]).
//     (b) That reply handle must reference the dequeued sender, i.e.
//         consuming it via `reply` resumes the EC that the kernel
//         actually dequeued from the port at recv time.
//
//   The cleanest way for one EC to set up both sides of the pipeline
//   is the same recipe terminate_07 uses: the test EC mints a port
//   with bind + recv caps, mints a worker EC W with susp + term, and
//   issues `suspend(W, port)` to queue W as a suspended sender on
//   the port. Per §[suspend] this is non-blocking when [1] != self,
//   so the test EC stays runnable. The test EC then calls `recv` on
//   the port — recv returns immediately because the test EC holds
//   the port's bind cap (no E_CLOSED) and W is the queued sender.
//
//   For (a) we read the reply_handle_id slot out of the cap table
//   (mapped read-only into the holding domain per §[capabilities])
//   and check `handleType() == reply`.
//
//   For (b) we invoke `reply(reply_handle_id)`. A healthy reply
//   handle that references the dequeued sender must succeed — the
//   sender is still suspended (the only way to free it is to
//   consume the reply handle, per §[reply]). If the slot held a
//   stale or unrelated reply handle the call would surface E_BADCAP
//   or E_TERM/E_ABANDONED instead of OK.
//
// Action
//   1. create_port(caps={bind, recv})        — must succeed
//   2. create_execution_context(target=self,
//        caps={term, susp, rp=0})            — must succeed
//      (entry = dummyEntry; W never executes meaningfully — it is
//      suspended before scheduling matters)
//   3. suspend(W, port)                      — must return OK
//      (non-blocking on the test EC since [1] != self; queues W as
//      a suspended sender on the port)
//   4. recv(port)                            — must return OK
//      (test EC holds the port's bind cap, so no E_CLOSED; W is the
//      queued sender)
//   5. readCap(cap_table_base, reply_handle_id)
//                                            — handleType == reply
//   6. reply(reply_handle_id)                — must return OK
//      (resumes the dequeued sender W, witnessing the reference)
//
// Assertions
//   1: setup port creation failed (createPort returned an error
//      word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: the slot named by reply_handle_id does not hold a handle of
//      type `reply`
//   6: reply on the reported slot returned non-OK; the slot did not
//      reference the dequeued sender

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Step 1: mint the port with bind + recv. bind keeps the port
    // alive for the duration of the test (no E_CLOSED on recv); recv
    // is required for the recv call itself.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W with susp (so the test can suspend it onto the
    // port) and term (kept symmetric with terminate_07; harmless
    // here). restart_policy = 0 keeps the request inside the
    // runner-granted ceiling.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Per
    // §[suspend], suspend([1], [2]) with [1] != self does not block
    // the caller — the target is suspended and enqueued on the port.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The test EC holds the port's bind cap (so the
    // port is not terminally closed) and W is queued, so recv
    // returns immediately with the kernel-allocated reply handle id
    // packed into the syscall word per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: read the slot the kernel named. The cap table is
    // mapped read-only into the holding domain per §[capabilities];
    // word 0 carries the handle-type tag in bits 12-15. The
    // assertion under test demands the inserted handle be a reply
    // handle.
    const cap = caps.readCap(cap_table_base, reply_handle_id);
    if (cap.handleType() != caps.HandleType.reply) {
        testing.fail(5);
        return;
    }

    // Step 6: probe the reference half of the assertion. A reply
    // handle that references the dequeued sender resumes that EC
    // when consumed via `reply`; the call must return OK. A slot
    // pointing at no sender or at a different sender would surface
    // an error here.
    const r = syscall.reply(reply_handle_id);
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
