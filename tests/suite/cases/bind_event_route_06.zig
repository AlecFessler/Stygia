// Spec §[bind_event_route] — test 06.
//
// "[test 06] returns E_PERM if no prior route exists for ([1], [2]) and
//  [1] does not have the `bind` cap."
//
// Spec semantics
//   §[bind_event_route]: "EC cap required on [1]: `bind` if no prior
//   route exists for `(target, event_type)`; `rebind` if one does.
//   Port cap required on [3]: `bind`."
//
// Strategy
//   The runner spawns the test with a freshly minted self-handle that
//   carries `crec` and `crpt`, so we can mint both an EC and a port.
//
//   To hit the test-06 path cleanly we need every other validation
//   step to succeed:
//     - [1] is a valid EC handle.
//     - [3] is a valid port handle that carries the `bind` port cap.
//     - [2] is a registerable event type (we use 1).
//     - reserved bits in [1], [2], [3] are clean.
//     - no prior route exists for ([1], [2]).
//   The only failing precondition is then the missing `bind` EC cap on
//   [1]. Per the cap rule, the kernel must return E_PERM.
//
//   We mint the EC with the full cap set EXCEPT the `bind` and
//   `rebind` bits. Withholding `rebind` too avoids any ambiguity if a
//   future kernel-side reordering checked rebind first; the spec only
//   requires `bind` for the no-prior-route case, so withholding both
//   keeps the test honest. The EC entry is `dummyEntry` (halts forever)
//   — the test doesn't depend on the EC running anything.
//
//   We mint the port with both the port-cap `bind` (so the [3] check
//   passes) and `recv` (so the runner could conceivably deliver events
//   on it; not strictly needed but mirrors how a real binder would
//   shape the port).
//
// Action
//   1. create_port(caps={bind,recv})                    — must succeed.
//   2. create_execution_context(caps={susp,term},       — must succeed.
//      target=self, no `bind`/`rebind`)
//   3. bind_event_route(ec, event_type=1, port)         — must return E_PERM.
//
// Assertions
//   1: create_port returned an error word (failed setup).
//   2: create_execution_context returned an error word (failed setup).
//   3: bind_event_route returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[port] PortCap layout: bind = bit 4. Including `recv` keeps the
    // port cap shape conventional; the kernel only checks `bind` for
    // the [3] validation in bind_event_route.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // §[execution_context] EcCap: deliberately clear `bind` and
    // `rebind`. `susp`/`term` are kept so the cap word is a typical
    // shape; restart_policy stays 0. The kernel must reject the
    // bind_event_route call on grounds of the missing `bind` EC cap.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
        .bind = false,
        .rebind = false,
        .unbind = false,
    };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity_mask
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // event_type = 1 is a registerable type per spec §[event_types]
    // (the set is {1, 2, 3, 6}). No prior route has been installed for
    // (ec_handle, 1) — this is a freshly-minted EC — so the kernel
    // must take the "no prior route" branch and require `bind` on [1].
    const result = syscall.bindEventRoute(ec_handle, 1, port_handle);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
