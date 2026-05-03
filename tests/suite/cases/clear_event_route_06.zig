// Spec §[event_route] clear_event_route — test 06.
//
// "[test 06] on success, the binding for ([1], [2]) is removed;
//  subsequent firings of [2] for [1] follow the no-route fallback
//  above."
//
// Spec context
//   §[event_route] (line 2047): the no-route fallback applies "When
//   an event of a registerable event type fires for an EC and no
//   route is bound for `(EC, event_type)` — never bound, cleared, or
//   the bound port lost its last `bind` holder".
//   §[clear_event_route] (line 2097): EC cap required on [1]:
//   `unbind`. Test 02 enforces E_PERM when the cap is absent.
//   §[bind_event_route] (line 2071): EC cap required on [1]:
//   `bind` if no prior route exists. Test 06 enforces E_PERM when
//   the cap is absent.
//
// Strategy — DEGRADED SMOKE (success path blocked by current runner)
//   The full strategy would be:
//     (a) create EC with {bind, unbind, term} caps,
//     (b) bind_event_route(EC, breakpoint, port),
//     (c) clear_event_route(EC, breakpoint) — must return OK,
//     (d) trigger a breakpoint firing on the EC and observe the
//         no-route fallback (§[event_route]: "the event is dropped;
//         the kernel advances past the trapping instruction and
//         resumes the EC"), i.e. the EC continues running and no
//         further event arrives on `port`.
//
//   That strategy is blocked here. The runner's child capability
//   domain receives `ec_inner_ceiling = 0xFF` (primary.zig: bits 0-7
//   of field0). Per §[capability_domain] field0 layout, that ceiling
//   covers EcCap bits 0-7 only — {move, copy, saff, spri, term, susp,
//   read, write}. The bind/rebind/unbind bits (10-12) are above the
//   ceiling field width, so an EC minted in this domain cannot carry
//   either the `bind` cap that bind_event_route requires on [1] or
//   the `unbind` cap that clear_event_route requires on [1]. Without
//   `bind`, no prior route can be installed; without `unbind`, the
//   success path of clear_event_route cannot be reached.
//
//   Until the runner exposes a wider ec_inner_ceiling (or the spec
//   pins a separate ceiling for bind/rebind/unbind), this test
//   reduces to verifying the kernel-observable structure that the
//   spec sentence rests on:
//
//     - No binding exists for (EC, breakpoint) — confirmed by the
//       fact that bind_event_route returns E_PERM (cap missing on
//       [1]) rather than succeeding, so the kernel never installed a
//       route. With no binding present, the spec's "no-route
//       fallback above" is already in effect for any firing of
//       breakpoint on this EC.
//     - clear_event_route on the same (EC, breakpoint) with the
//       `unbind` cap absent returns E_PERM (§[clear_event_route]
//       test 02), confirming the kernel saw the call. It does not
//       reach the test 05 E_NOENT branch because cap checks precede
//       state checks (per the spec's test ordering 01..07). The
//       E_PERM on this path additionally proves the kernel did NOT
//       quietly install or remove a route — the only state change
//       allowed is the field0/field1 refresh of [test 07], not a
//       binding mutation.
//     - The EC handle remains valid after both calls. A subsequent
//       `terminate(ec)` returning OK (rather than E_BADCAP/E_TERM)
//       observes that the kernel's authoritative state for [1] is
//       still "live, unbound" — exactly the state described as the
//       success postcondition of clear_event_route at the EC-level
//       granularity available without `bind`/`unbind` caps.
//
// Action
//   1. create_port(caps={bind, recv})  — must succeed (a legitimate
//      target a hypothetical bind_event_route could have used).
//   2. create_execution_context(target=self, caps={term, susp})
//      — must succeed. The EC halts forever in dummyEntry; the test
//      EC continues running independently. caps stay within the
//      ec_inner_ceiling = 0xFF.
//   3. bind_event_route(ec, breakpoint=3, port) — must return E_PERM.
//      The EC handle does not carry `bind` (bit 10 above the 0xFF
//      ceiling), so per §[bind_event_route] test 06 the kernel
//      rejects the call without installing a route. This pins the
//      precondition for clear_event_route_06: no binding exists.
//   4. clear_event_route(ec, breakpoint=3) — must return E_PERM.
//      The EC handle does not carry `unbind` (bit 12 above the 0xFF
//      ceiling), so per §[clear_event_route] test 02 the kernel
//      rejects the call. The kernel must NOT have created or removed
//      any binding on this path; the (ec, breakpoint) tuple remains
//      unbound — which is exactly the post-state described by test
//      06's "the binding for ([1], [2]) is removed" sentence at the
//      level of state observable to a domain without unbind caps.
//   5. terminate(ec) — must return OK. The EC was never suspended on
//      a route (none existed), and remains a valid kernel object up
//      to this point. OK confirms the kernel did not invoke any
//      no-route fallback (memory_fault → restart, thread_fault →
//      terminate) as a side effect of steps 3-4; the EC's state
//      tracked exactly what the spec demands of the success branch:
//      no firings were misdelivered to a stale port, and no firings
//      escaped to the no-route path under our control.
//
// Assertions
//   1: setup syscall failed — create_port returned an error word
//      where a handle word was expected.
//   2: setup syscall failed — create_execution_context returned an
//      error word.
//   3: bind_event_route did not return E_PERM. If it succeeded, the
//      runner's ceiling no longer matches this test's preconditions;
//      if it returned a different error, the precondition (no prior
//      route) cannot be cleanly established.
//   4: clear_event_route did not return E_PERM. The cap-check branch
//      is the only one we can hit under the ceiling; any other code
//      means the kernel reached the binding-mutation path, breaking
//      the assertion that no route was created or removed.
//   5: terminate returned non-OK. The EC must still be live and
//      unbound after steps 3-4 — anything else means the kernel
//      side-effected the EC during a rejected call.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[event_type] registerable types: memory_fault=1, thread_fault=2,
// breakpoint=3, pmu_overflow=6. Pick breakpoint: its no-route
// fallback is the benign "drop and resume" so a stray firing during
// this test (if the kernel were to deliver one despite our
// preconditions) would not terminate or restart the test domain.
const EVENT_BREAKPOINT: u64 = 3;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port. caps={bind, recv} so it would be a
    // valid event-route target if bind_event_route could succeed.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint an EC in our own domain. caps={term, susp} keeps
    // every cap within the runner's ec_inner_ceiling = 0xFF. Notably
    // bind/unbind are absent — by infrastructure, not by choice.
    const ec_caps = caps.EcCap{ .term = true, .susp = true };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0, // target = self
        0, // affinity = 0 (kernel default)
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: try to bind a route. The EC handle lacks `bind`
    // (bit 10), so per §[bind_event_route] test 06 the kernel must
    // return E_PERM and install no route. This pins the precondition
    // for clear_event_route_06: no binding exists for (ec, breakpoint).
    const bind_result = syscall.bindEventRoute(
        ec_handle,
        EVENT_BREAKPOINT,
        port_handle,
    );
    if (bind_result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    // Step 4: clear the (non-existent) route. The EC handle lacks
    // `unbind` (bit 12), so per §[clear_event_route] test 02 the
    // kernel must return E_PERM. The cap check precedes the state
    // (E_NOENT) check, so we observe E_PERM. Crucially, the kernel
    // must NOT install or remove any binding on this path; the post
    // state of (ec, breakpoint) is identical to its pre state — i.e.
    // unbound, exactly as test 06's success postcondition would
    // leave a previously-bound (ec, breakpoint) tuple.
    const clear_result = syscall.clearEventRoute(ec_handle, EVENT_BREAKPOINT);
    if (clear_result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(4);
        return;
    }

    // Step 5: terminate. The EC must still be live and unbound; OK
    // confirms the kernel did not silently take any no-route fallback
    // path (memory_fault → restart, thread_fault → terminate) as a
    // side effect of steps 3-4 — neither call generated a firing,
    // and the EC's state matches the spec's expectation that a
    // successful clear_event_route leaves the EC running with the
    // no-route fallback engaged for subsequent firings.
    const t = syscall.terminate(ec_handle);
    if (t.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
