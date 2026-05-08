// Spec §[clear_event_route] — test 05.
//
// "[test 05] returns E_NOENT if no binding exists for ([1], [2])."
//
// Strategy
//   §[clear_event_route] error precedence: BADCAP (01), PERM (02),
//   INVAL (03/04), NOENT (05). To reach NOENT the call must clear all
//   four earlier gates:
//     - [1] is a valid EC handle (test 01),
//     - [1] has the `unbind` cap (test 02),
//     - [2] is a registerable event type ∈ {1, 2, 3, 6} (test 03),
//     - no reserved bits set in [1] or [2] (test 04),
//   AND no binding exists for ([1], [2]).
//
//   Bind/unbind cap availability — bit-passthrough discovery
//     The runner's `ec_inner_ceiling = 0xFF` covers EcCap bits 0-7
//     only — `unbind` lives at bit 12. However,
//     `kernel/syscall/execution_context.zig` only validates the LOW
//     BYTE of caps against `ec_inner_ceiling`:
//       const new_caps_low: u8 = @truncate(new_caps & 0xFF);
//       if (new_caps_low & ~ec_inner_ceiling != 0) → E_PERM
//     EcCap bits 8-15 (restart_policy[8..9], bind[10], rebind[11],
//     unbind[12]) flow through unchecked at mint time, and the file's
//     own header comment explicitly notes that bind/rebind/unbind
//     "carry their own runtime gates in bind_event_route /
//     clear_event_route and are not constrained at mint time." So a
//     `create_execution_context(target = self)` request with caps.bind
//     = 1 / caps.unbind = 1 in the high byte passes the ceiling check
//     and the resulting EC handle carries those caps.
//
//   Binding a route to drive the post-clear NOENT state
//     We bind (EC, breakpoint=3) → port, then clear (success path,
//     test 06 territory), then clear AGAIN. The second clear has the
//     unbind cap available (gate 02 closed), the event type is
//     registerable (gate 03 closed), the handle id is valid (gate 01
//     closed), and no binding exists (the prior clear removed it) —
//     exactly the state test 05 mandates E_NOENT for.
//
//     Why breakpoint and not memory_fault: §[event_route] no-route
//     fallback table — breakpoint drops the event and resumes the EC,
//     while memory_fault would restart the capability domain (or
//     destroy it absent `restart`) if a stray firing leaked through.
//     The dummy-EC entry never traps, so neither fallback fires in
//     practice, but breakpoint keeps the test benign in failure modes.
//
// Action
//   1. createPort(caps={bind, recv}) — must succeed (a legitimate
//      target for the bind_event_route call).
//   2. createExecutionContext(target=self,
//        caps={term, susp, bind, unbind}, entry=&dummyEntry)
//      — must succeed. caps.term/susp lie in the runner's 0xFF
//      ceiling; caps.bind (bit 10) and caps.unbind (bit 12) sit above
//      the 8-bit ceiling and pass through unchecked per the
//      bit-passthrough discovery above.
//   3. bindEventRoute(ec, breakpoint=3, port) — must return OK.
//      Closes the precondition for step 5: a binding now exists for
//      (ec, breakpoint).
//   4. clearEventRoute(ec, breakpoint=3) — must return OK. Removes
//      the binding installed in step 3. (This is essentially the
//      success path of clear_event_route, the same precondition that
//      test 06 asserts on — but here we use it only to set up the
//      "no binding exists" state for step 5.)
//   5. clearEventRoute(ec, breakpoint=3) — must return E_NOENT. The
//      cap, handle, and event-type checks are all closed by the prior
//      success in step 4 and the EC's stable cap set; the only
//      remaining gate is the binding-existence check, which this call
//      must fail on E_NOENT — the spec assertion under test.
//
// Assertions
//   1: setup syscall failed — createPort returned an error word.
//   2: setup syscall failed — createExecutionContext returned an
//      error word.
//   3: bindEventRoute did not return OK (precondition for clearing
//      a real binding).
//   4: first clearEventRoute did not return OK (precondition for
//      observing E_NOENT on the second clear).
//   5: second clearEventRoute did not return E_NOENT (the spec
//      assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[event_type]: registerable event types are 1 (memory_fault), 2
// (thread_fault), 3 (breakpoint), 6 (pmu_overflow). Pick 3 — its
// no-route fallback ("drop and resume") is the only benign choice if
// a stray firing raced this call.
const EVENT_BREAKPOINT: u64 = 3;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port. caps={bind, recv} so it can be used as the
    // event-route target (bind_event_route test 05 requires bind on
    // [3]) and so a recv-bearing handle exists for the runner-style
    // result-port shape.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint an EC with the high-byte cap bits {bind, unbind}
    // set in addition to the low-byte {term, susp}. The kernel's
    // ec_inner_ceiling check (execution_context.zig:148) only validates
    // the low byte, so bind/unbind pass through. term/susp are needed
    // for terminate (see cleanup) and to keep the EC's lifecycle
    // observable.
    const ec_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .bind = true,
        .unbind = true,
    };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = kernel default
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: install a binding for (ec, breakpoint). The EC handle
    // carries `bind` (no prior route exists, so test 06 of
    // bind_event_route demands it), the port handle carries `bind`
    // (test 05), and event_type 3 is registerable (test 03). All
    // earlier gates are closed; the call must succeed.
    const bind_result = syscall.bindEventRoute(
        ec_handle,
        EVENT_BREAKPOINT,
        port_handle,
    );
    if (bind_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: clear the binding we just installed. The EC carries
    // `unbind` (bit 12, passthrough), event_type matches the bound
    // tuple, and a binding exists — every gate closed, the call must
    // return OK and remove the binding.
    const clear1 = syscall.clearEventRoute(ec_handle, EVENT_BREAKPOINT);
    if (clear1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: clear AGAIN. Now the (ec, breakpoint) tuple has no
    // binding — exactly the state test 05 mandates E_NOENT for. All
    // earlier gates remain closed (handle still valid, unbind cap
    // still set, event type still registerable), so E_NOENT is the
    // only spec-mandated outcome.
    const clear2 = syscall.clearEventRoute(ec_handle, EVENT_BREAKPOINT);
    if (clear2.v1 != @intFromEnum(errors.Error.E_NOENT)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
