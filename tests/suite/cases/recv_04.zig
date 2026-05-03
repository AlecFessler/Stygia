// Spec §[recv] recv — test 04.
//
// "[test 04] returns E_CLOSED if the port has no bind-cap holders, no
// event_routes targeting it, and no queued events."
//
// Strategy
//   §[recv] short-circuits with E_CLOSED when all three terminal-close
//   conditions hold simultaneously: no bind-cap holder, no event_route
//   targeting the port, and no queued event. Mint a port with only the
//   `recv` cap on the creator's own handle — no `bind` — so by
//   construction the port has zero bind-cap holders. The caller's
//   self-IDC and the runner's result-port handle (passed at slot 3) are
//   unrelated handles; they don't satisfy any of the three keep-alive
//   conditions for the freshly created port. No `bind_event_route` has
//   been issued targeting it and no sender has suspended on it, so the
//   queue is empty and no routes target it.
//
//   Per create_port test 04, the caller's returned handle has caps =
//   the requested caps verbatim — so requesting only `recv` yields a
//   handle without `bind`, satisfying the no-bind-cap-holder gate.
//
// Action
//   1. createPort(caps = {recv}) — must succeed, returning a port
//      handle whose caps are exactly `recv` (no bind, no event_routes
//      can be registered against it from this domain anyway).
//   2. recv(port_handle) — the port has no bind-cap holders, no
//      event_routes, and no queued events; the call must return
//      E_CLOSED immediately rather than block.
//
// Assertions
//   1: createPort returned an error word in vreg 1 (setup failed).
//   2: recv returned something other than E_CLOSED.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Port with only `recv`. Crucially no `bind`, so the returned
    // handle does not contribute a bind-cap holder to the port. The
    // runner's port_ceiling = xfer | recv | bind, so this is well
    // within the create_port ceiling gate.
    const port_caps = caps.PortCap{
        .recv = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // No bind-cap holders, no event_routes targeting this port, and
    // no queued events. recv must return E_CLOSED rather than block.
    const got = syscall.recv(port_handle, 0);

    if (got.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
