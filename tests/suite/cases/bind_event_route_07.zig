// Spec §[bind_event_route] — test 07.
//
// "[test 07] returns E_PERM if a prior route exists for ([1], [2]) and
//  [1] does not have the `rebind` cap."
//
// Spec semantics
//   §[bind_event_route]: "EC cap required on [1]: `bind` if no prior
//   route exists for `(target, event_type)`; `rebind` if one does.
//   Port cap required on [3]: `bind`."
//
//   Test 06 covers the "no prior route, missing `bind`" branch. This
//   test covers the complementary "prior route exists, missing
//   `rebind`" branch.
//
// Strategy
//   We need a state where:
//     - [1] is a valid EC handle that holds `bind` (so the first
//       bind_event_route succeeds and installs the prior route).
//     - [1] does NOT hold `rebind` (so the second bind_event_route,
//       which is now an overwrite, fails the cap check).
//     - [2] is a registerable event type so test 03 doesn't fire.
//     - [3] is a valid port handle holding `bind` so test 02/05 don't
//       fire.
//     - reserved bits are clean so test 04 doesn't fire.
//
//   Per the §[capabilities] cap-bit layout in libz (`EcCap`), `bind`
//   and `rebind` are independent bits, so we mint the EC with `bind`
//   set and `rebind` cleared from the start. The first invocation
//   takes the "no prior route" branch, succeeds, and installs the
//   binding. The second invocation, on the same `(EC, event_type)`
//   tuple, takes the "prior route exists" branch and the kernel must
//   require `rebind` — which the EC handle does not hold — so the
//   call must return E_PERM.
//
//   The EC entry is `dummyEntry` (halts forever); the test does not
//   depend on the EC running anything. We give the EC `susp`/`term`
//   to keep the cap-word shape conventional but those are not load-
//   bearing here. `restart_policy` stays 0.
//
//   The port is minted with `bind` and `recv`; only `bind` matters
//   for the [3] check on bind_event_route, but `recv` keeps the port
//   shape conventional.
//
// Action
//   1. create_port(caps={bind,recv})                        — must succeed.
//   2. create_execution_context(caps={susp,term,bind},      — must succeed.
//      target=self, no `rebind`)
//   3. bind_event_route(ec, event_type=1, port)             — must return OK
//      (no prior route, EC has `bind`).
//   4. bind_event_route(ec, event_type=1, port)             — must return E_PERM
//      (prior route exists, EC lacks `rebind`).
//
// Assertions
//   1: create_port returned an error word (failed setup).
//   2: create_execution_context returned an error word (failed setup).
//   3: first bind_event_route did not return OK.
//   4: second bind_event_route returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[port] PortCap layout: `bind` (bit 4) is the cap the kernel
    // checks on [3]. `recv` is included to keep the port cap shape
    // conventional and is not load-bearing here.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // §[execution_context] EcCap: `bind` set so the first
    // bind_event_route succeeds; `rebind` cleared so the second one —
    // on the same (EC, event_type) tuple, hitting the "prior route
    // exists" branch — must surface E_PERM. `unbind` is irrelevant
    // here (only clear_event_route consults it). `susp`/`term` are
    // included to mirror a conventional EC cap word.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
        .bind = true,
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

    // First call: no prior route exists for (ec_handle, 1), so the
    // kernel takes the `bind`-required branch. The EC handle has
    // `bind`, the port handle has `bind`, all args are well-formed —
    // the call must succeed (vreg 1 = OK = 0).
    const first = syscall.bindEventRoute(ec_handle, 1, port_handle);
    if (first.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Second call: a prior route now exists for (ec_handle, 1), so the
    // kernel takes the `rebind`-required branch. The EC handle does
    // NOT have `rebind` — every other precondition is identical to
    // the first call — so the kernel must return E_PERM.
    const second = syscall.bindEventRoute(ec_handle, 1, port_handle);
    if (second.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
