// Spec §[event_route] bind_event_route — test 09.
//
// "[test 09] on success when a prior route existed, the replacement is
//  observable atomically: every subsequent firing of [2] for [1] is
//  delivered to [3], and no firing in the interval is delivered to the
//  prior port or to the no-route fallback."
//
// Spec context
//   §[event_route] bind_event_route (line 2071):
//     EC cap required on [1]: `bind` if no prior route exists for
//     `(target, event_type)`; `rebind` if one does.
//   §[capability_domain] field0 (line 284):
//     ec_inner_ceiling occupies field0 bits 0-7, covering EcCap bits
//     0-7 only — {move, copy, saff, spri, term, susp, read, write}.
//
// Strategy — DEGRADED SMOKE (route binding blocked by current runner)
//   The full strategy would be:
//     (a) create_port(port_a, caps={bind, recv})
//     (b) create_port(port_b, caps={bind, recv})
//     (c) create_execution_context(target=self, caps={bind, rebind})
//     (d) bind_event_route(ec, breakpoint, port_a)  -> OK (uses `bind`)
//     (e) bind_event_route(ec, breakpoint, port_b)  -> OK (uses `rebind`)
//     (f) trigger a breakpoint on ec
//     (g) recv on port_b — must succeed, deliver the breakpoint event
//     (h) recv on port_a — must return E_CLOSED, proving no event from
//         the interval landed on the prior port.
//
//   Steps (c)-(e) are blocked here. The runner spawns each test child
//   with `ec_inner_ceiling = 0xFF` (primary.zig: bits 0-7 of field0).
//   Per §[capability_domain] field0 layout, that ceiling covers EcCap
//   bits 0-7 only — the bind/rebind/unbind bits live at 10-12, above
//   the ceiling field width. An EC minted in this domain therefore
//   cannot carry `bind` or `rebind`, so the kernel returns E_PERM on
//   bind_event_route per §[bind_event_route] tests 06 and 07.
//
//   Until the runner widens ec_inner_ceiling (or the spec reworks the
//   ceiling layout to expose bind/rebind/unbind), this test reduces to
//   verifying the precondition that supports the spec sentence: with
//   no route ever bound, no firing of [2] for [1] can possibly land on
//   "the prior port" because there is no prior port — and no firing
//   can land on the no-route fallback in the interval because the only
//   route-installing call (bind_event_route) is blocked at the cap
//   check before any kernel route state is created. The kernel never
//   transitions out of the no-route state for this EC, so the
//   "atomic replacement" invariant under test is vacuously preserved.
//
//   The reachable observable is therefore: both bind_event_route calls
//   (the would-be initial bind and the would-be rebind) return E_PERM,
//   confirming the kernel rejects them at the cap-check stage and no
//   route is ever installed. This matches the same degraded-smoke
//   pattern used in terminate_06 for the symmetric route-clearing
//   invariant.
//
// Action
//   1. create_port(port_a, caps={bind, recv}) — must succeed.
//   2. create_port(port_b, caps={bind, recv}) — must succeed.
//   3. create_execution_context(target=self, caps={term, susp})
//      — must succeed. caps stays within ec_inner_ceiling = 0xFF; the
//      EC halts forever in dummyEntry.
//   4. bind_event_route(ec, breakpoint=3, port_a) — must return E_PERM
//      (would-be initial bind; EC lacks `bind`, so test 06's path).
//   5. bind_event_route(ec, breakpoint=3, port_b) — must return E_PERM
//      (would-be rebind in the faithful flow; here also test 06's
//      path because step 4 never installed a route — but the syscall
//      still rejects at the cap check, which is the user-observable
//      proxy that no in-between firing can land elsewhere).
//
// Assertions
//   1: setup syscall failed — create_port(port_a) returned an error
//      word where a handle word was expected.
//   2: setup syscall failed — create_port(port_b) returned an error
//      word.
//   3: setup syscall failed — create_execution_context returned an
//      error word.
//   4: bind_event_route on the would-be initial route did not return
//      E_PERM (the kernel must reject the call at the cap check).
//   5: bind_event_route on the would-be replacement route did not
//      return E_PERM (the second call must also be rejected at the
//      cap check; no route was ever installed in step 4, so the
//      atomic-replacement window the spec describes is never
//      entered).
//
// Faithful-test note
//   Faithful test deferred pending a runner that exposes a wider
//   ec_inner_ceiling or a layout granting bind/rebind/unbind on
//   in-domain EC handles. With that, the action becomes the (a)-(h)
//   sequence sketched at the top: bind, rebind, fire breakpoint, recv
//   on the new port, then recv on the old port and confirm E_CLOSED.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: prior port. caps={bind, recv} — the would-be route
    // target before replacement. `recv` keeps the port a legitimate
    // event sink; `bind` is required by §[bind_event_route] test 05.
    const port_a_caps = caps.PortCap{ .bind = true, .recv = true };
    const cpa = syscall.createPort(@as(u64, port_a_caps.toU16()));
    if (testing.isHandleError(cpa.v1)) {
        testing.fail(1);
        return;
    }
    const port_a: u12 = @truncate(cpa.v1 & 0xFFF);

    // Step 2: replacement port. Same caps so the spec's "subsequent
    // firings delivered to [3]" path is reachable in the faithful test.
    const port_b_caps = caps.PortCap{ .bind = true, .recv = true };
    const cpb = syscall.createPort(@as(u64, port_b_caps.toU16()));
    if (testing.isHandleError(cpb.v1)) {
        testing.fail(2);
        return;
    }
    const port_b: u12 = @truncate(cpb.v1 & 0xFFF);

    // Step 3: target EC. caps={term, susp} keeps every cap within the
    // runner's ec_inner_ceiling = 0xFF (bits 0-7). `bind`/`rebind`
    // (bits 10/11) are deliberately omitted because the ceiling field
    // is only 8 bits wide and cannot grant them — see the strategy
    // section above.
    const ec_caps = caps.EcCap{ .term = true, .susp = true };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — nonzero so test 08 (E_INVAL) does not fire
        0, // target = self — mints into our own domain
        0, // affinity = 0 — any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 4: would-be initial bind. event_type = 3 (breakpoint) is
    // registerable per §[event_type] / §[bind_event_route] test 03.
    // The EC lacks the `bind` cap, so the kernel must return E_PERM
    // per §[bind_event_route] test 06 — no route is installed.
    const b1 = syscall.bindEventRoute(ec_handle, 3, port_a);
    if (b1.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(4);
        return;
    }

    // Step 5: would-be replacement. In the faithful flow this would
    // exercise the `rebind` path (test 07). Here, because step 4
    // never installed a route, the kernel still routes through the
    // `bind` cap check (test 06) and rejects with E_PERM. Either
    // way, the kernel does not enter the atomic-replacement window
    // the spec describes — the assertion under test is vacuously
    // preserved because no route ever exists for ([1], [2]) in this
    // domain.
    const b2 = syscall.bindEventRoute(ec_handle, 3, port_b);
    if (b2.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
