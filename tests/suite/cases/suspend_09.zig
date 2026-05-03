// Spec §[suspend] — test 09.
//
// "[test 09] on success, a suspension event is delivered on [2]."
//
// Strategy
//   The witness for "a suspension event is delivered on [2]" is that
//   a `recv` on port [2] dequeues exactly the event the kernel queued
//   in response to the suspend call. Two observable bits prove it:
//
//     (a) recv returns OK rather than blocking forever or returning
//         E_CLOSED — i.e., the port had a queued event waiting.
//     (b) The recv syscall word's event_type field equals the
//         §[event_type] code for `suspension` (4). Per §[suspend]
//         the only event-injection path is the suspension event the
//         kernel queues on [2], so an event_type of suspension on
//         this port is uniquely attributable to the suspend call.
//
//   Producing the precondition mirrors terminate_07: the test EC
//   mints a port (with bind + recv caps so it can both target the
//   port from suspend and dequeue from it), then mints a worker EC
//   W with the `susp` cap. Per §[suspend] "[1] may reference the
//   calling EC; the syscall returns after the calling EC is resumed"
//   — when [1] is *not* the calling EC the call simply queues the
//   target's suspension event on the port without blocking the
//   caller. So the test EC stays runnable, W lands as a queued
//   suspension event, and the subsequent recv consumes it.
//
//   The recv, given the port still has a live bind-cap holder (the
//   test EC) and a queued event, returns immediately per §[recv]
//   without E_CLOSED or E_FULL.
//
// Action
//   1. create_port(caps={bind, recv})        — must succeed
//   2. create_execution_context(target=self,
//        caps={susp, rp=0})                  — must succeed
//      (entry = dummyEntry; W never executes meaningfully — it sits
//      suspended for the duration of the test)
//   3. suspend(W, port)                      — must return OK
//      (non-blocking since [1] != self; queues a suspension event on
//      the port)
//   4. recv(port)                            — must return OK and
//      its syscall word's event_type field must equal `suspension`
//      (4)
//
// Assertions
//   1: setup port creation failed
//   2: setup EC creation failed
//   3: suspend itself did not return OK
//   4: recv did not return OK (no event was delivered)
//   5: recv returned OK but the event_type was not `suspension`

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[event_type] code for `suspension`.
const EVENT_TYPE_SUSPENSION: u64 = 4;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind lets the test EC be the destination
    // of `suspend`; recv lets it dequeue the resulting event. Caps are
    // restricted to those bits (xfer/recv/bind nibble = 0x18) to stay
    // inside the runner's port_ceiling.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. Only `susp` is required for the suspend call to
    // succeed; restart_policy = 0 (kill) keeps the call inside the
    // runner-granted ceiling. read/write are intentionally absent —
    // event payload contents are not what test 09 is asserting; only
    // delivery itself.
    const w_caps = caps.EcCap{
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

    // Step 3: queue W as a suspension event on the port. Non-blocking
    // for the test EC because [1] (W) is not the calling EC.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The port has the test EC as a live bind-cap holder
    // and a queued suspension event, so per §[recv] this returns
    // immediately with the event_type encoded in the syscall word.
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: event_type in bits 44-48
    // (5 bits).
    const event_type: u64 = (got.word >> 44) & 0x1F;
    if (event_type != EVENT_TYPE_SUSPENSION) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
