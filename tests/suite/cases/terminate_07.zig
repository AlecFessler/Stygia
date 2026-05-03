// Spec §[execution_context] terminate — test 07.
//
// "[test 07] on success, reply handles whose suspended sender was the
//  terminated EC return E_ABANDONED on subsequent operations."
//
// Strategy
//   The assertion needs a witness pair:
//     (a) A reply handle in the caller's table whose recorded suspended
//         sender is some EC W.
//     (b) After terminate(W) succeeds, a "subsequent operation" on the
//         reply handle must return E_ABANDONED rather than its normal
//         success path.
//
//   Producing (a) requires both the suspend side (W queues a suspension
//   event on a port) and the recv side (the test EC dequeues that event
//   and is given the reply handle id in the syscall word). The test EC
//   itself owns both sides of the pipeline: it mints a port with bind +
//   recv caps, mints W, then calls `suspend(W, port)`. Per §[suspend],
//   "[1] may reference the calling EC; the syscall returns after the
//   calling EC is resumed" — when [1] is *not* the calling EC the call
//   simply suspends the target without blocking the caller. So the test
//   EC stays runnable, and W is queued as a suspended sender on the
//   port.
//
//   A `recv(port)` then returns immediately (no E_CLOSED, since the
//   test EC still holds the port handle with its `bind` cap; no E_FULL,
//   since the test's domain has plenty of free slots). The kernel hands
//   back the reply handle id in the recv syscall word; that id is the
//   handle the spec line under test refers to.
//
//   `terminate(W)` then destroys W. Per §[terminate]: "Termination also
//   marks any reply handles whose suspended sender was the terminated
//   EC such that subsequent operations on those reply handles return
//   `E_ABANDONED`." With W destroyed, the reply handle is now in the
//   marked state.
//
//   For the "subsequent operation" probe we use `reply(reply_handle)`.
//   On a healthy reply handle that resumes a still-suspended sender,
//   `reply` succeeds. With W terminated the spec line under test
//   demands E_ABANDONED.
//
//   SPEC AMBIGUITY: §[reply] [test 03] separately asserts that
//   `reply` returns E_TERM (not E_ABANDONED) when "the suspended EC
//   was terminated before reply could deliver". The two spec lines
//   read in tension: terminate test 07 names E_ABANDONED for any
//   subsequent operation on the marked reply handle, while reply test
//   03 specifically names E_TERM for the reply path. This test
//   enforces the wording of terminate test 07 verbatim — accept only
//   E_ABANDONED — since the assertion under test is the authority for
//   *this* test file. If the spec is later reconciled to E_TERM for
//   the reply path, this test's expected error code is the line that
//   needs to change, and a clarifying note belongs in §[terminate].
//
// Action
//   1. create_port(caps={bind, recv})        — must succeed
//   2. create_execution_context(target=self,
//        caps={term, susp, rp=0})            — must succeed
//      (entry = dummyEntry; W never executes meaningfully — it is
//      suspended and then terminated before scheduling matters)
//   3. suspend(W, port)                      — must return OK
//      (non-blocking on the test EC since [1] != self; queues W as a
//      suspended sender on the port)
//   4. recv(port)                            — must return OK and
//      yield a reply_handle_id in the syscall word
//      (the test EC holds the port's bind cap, so no E_CLOSED)
//   5. terminate(W)                          — must return OK
//      (W's EC handle has the term cap minted in step 2)
//   6. reply(reply_handle_id)                — must return E_ABANDONED
//      (the spec line under test)
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: terminate did not return OK
//   6: reply on the now-marked handle returned something other than
//      E_ABANDONED

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind + recv are the only caps the test
    // exercises; restricting the port to those keeps the runner's
    // port_ceiling check trivially satisfied (xfer/recv/bind = 0x1C).
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. term lets the test eventually destroy W; susp
    // lets the test queue W onto the port via suspend. restart_policy
    // = 0 (kill) keeps the call inside the runner-granted ceiling and
    // prevents any restart fallback from re-resurrecting W after the
    // terminate.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 stays inside the runner pri ceiling.
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

    // Step 3: queue W as a suspended sender on the port.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The port has the test EC as a live bind-cap holder
    // and W queued as a suspension event, so recv returns immediately
    // with the reply handle id encoded in the syscall word per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: terminate W. The spec mandates the kernel mark the reply
    // handle that referred to W as the suspended sender so that
    // subsequent operations on it surface E_ABANDONED.
    const term_result = syscall.terminate(w_handle);
    if (term_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 6: probe the marked reply handle. Per terminate test 07,
    // any subsequent operation on this handle must return E_ABANDONED.
    const r = syscall.reply(reply_handle_id);
    if (r.v1 != @intFromEnum(errors.Error.E_ABANDONED)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
