// Spec §[reply] reply — test 04.
//
// "[test 04] on success, the reply handle is consumed (removed from
//  the caller's table)."
//
// Strategy
//   The assertion needs a witness: a reply handle in the caller's
//   table that on a successful `reply` is removed from that table.
//
//   Producing a valid reply handle requires the same suspend/recv
//   pipeline used in terminate_07: mint a port with bind + recv,
//   mint a worker EC W with the `susp` cap, then `suspend(W, port)`.
//   Per §[suspend], when [1] != self the call simply queues the
//   target on the port without blocking the caller. A `recv(port)`
//   then returns immediately with the freshly-minted reply handle id
//   in the syscall word per §[recv] (bits 32-43).
//
//   The reply handle is now resident in the caller's table and refers
//   to W as the suspended sender. Calling `reply(reply_handle_id)`
//   resumes W and — per the spec line under test — must remove the
//   reply slot from the caller's table.
//
//   To probe the post-condition we re-use the slot-empty witness from
//   delete_03: `restrict(slot, 0)` on a released slot returns
//   E_BADCAP. New caps = 0 is trivially a subset of any prior caps
//   and reserved bits are clean, so the only error path that can fire
//   on the post-reply call is E_BADCAP — exactly the post-condition
//   the spec line names.
//
//   W's `restart_policy = 0` (kill) keeps the EC creation cap word
//   inside the runner-granted ceiling and prevents any post-resume
//   scheduling of W from interfering with this test's pass path; the
//   test asserts that `reply` returned OK and the slot is gone before
//   any further activity matters.
//
// Action
//   1. create_port(caps={bind, recv})        — must succeed
//   2. create_execution_context(target=self,
//        caps={susp, rp=0})                  — must succeed
//      (entry = dummyEntry; W is suspended via suspend before it
//      executes meaningfully)
//   3. suspend(W, port)                      — must return OK
//      (non-blocking on the test EC since [1] != self)
//   4. recv(port)                            — must return OK and
//      yield a reply_handle_id in the syscall word
//   5. reply(reply_handle_id)                — must return OK
//   6. restrict(reply_handle_id, 0)          — must return E_BADCAP
//      (witnesses the slot is no longer occupied)
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: reply did not return OK
//   6: post-reply restrict did not return E_BADCAP (the reply slot
//      was not consumed)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const w_caps = caps.EcCap{
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

    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    const r = syscall.reply(reply_handle_id);
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Post-condition probe: reply must have removed the slot from the
    // caller's table. `restrict(slot, 0)` on a released slot returns
    // E_BADCAP (delete_03 uses the same witness).
    const after = syscall.restrict(reply_handle_id, 0);
    if (after.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
