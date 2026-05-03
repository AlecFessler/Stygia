// Spec §[recv] — test 08.
//
// "[test 08] on success, the syscall word's event_type equals the
//  event_type that triggered delivery."
//
// Strategy
//   The assertion needs (a) a successful recv with (b) a known
//   event_type so the test can compare what the kernel reports
//   against ground truth. The simplest deterministic path is to
//   queue a `suspension` event (§[event_type] = 4) by calling
//   `suspend(W, port)` from the test EC, where W is a freshly
//   minted EC. Per §[suspend], when [1] is not the calling EC the
//   call returns immediately after queueing W as a suspended sender
//   on the port — so the test EC stays runnable and a follow-up
//   `recv(port)` returns immediately rather than blocking.
//
//   Mint the port with caps {bind, recv}: bind keeps the port from
//   ever entering the no-bind-cap-holders E_CLOSED case (§[recv]
//   test 04/05) for the duration of this test, and recv is the cap
//   `recv` itself gates on (§[recv] test 02). Mint W with caps
//   {susp, term} and restart_policy = 0; susp lets the test queue
//   W via `suspend`, term keeps the cleanup path open, and a
//   restart_policy of 0 (kill) keeps the call inside the runner-
//   granted EC ceiling.
//
//   §[recv] syscall word return layout puts event_type in bits
//   44-48 (5 bits). After a successful recv we mask those bits and
//   compare against the spec-named value 4 for `suspension`. A
//   match witnesses the spec line; any other value (including 0,
//   the reserved encoding) fails the assertion.
//
//   We do not exercise the read-cap-gated event-state vregs here —
//   that's §[recv] tests 11/12. We only need v1 = OK (recv
//   succeeded) and the syscall word's event_type field (bits
//   44-48).
//
// Action
//   1. create_port(caps={bind, recv})        — must succeed
//   2. create_execution_context(target=self,
//        caps={susp, term, restart_policy=0}) — must succeed
//      (entry = dummyEntry; W never executes meaningfully — it is
//      suspended before scheduling matters)
//   3. suspend(W, port)                      — must return OK
//      (non-blocking on the test EC since [1] != self; queues W as a
//      suspended sender on the port with event_type = suspension)
//   4. recv(port)                            — must return OK
//      (the test EC holds the port's bind cap, so no E_CLOSED)
//   5. extract event_type from the recv syscall word bits 44-48 and
//      compare against 4 (suspension)
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: recv syscall word's event_type field (bits 44-48) is not the
//      suspension code (4) — the kernel reported a different event
//      type than the one that triggered delivery.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[event_type]: suspension = 4.
const EVENT_TYPE_SUSPENSION: u64 = 4;

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

    // §[recv] syscall word return layout: event_type in bits 44-48
    // (5 bits).
    const event_type: u64 = (got.word >> 44) & 0x1F;
    if (event_type != EVENT_TYPE_SUSPENSION) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
