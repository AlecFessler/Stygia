// Spec §[clear_event_route] clear_event_route — test 03.
//
// "[test 03] returns E_INVAL if [2] is not a registerable event type."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//
//   To isolate the E_INVAL gate on [2] we make every other argument
//   well-formed so the kernel cannot reject earlier:
//     - [1] = SLOT_INITIAL_EC (a valid EC handle, sidesteps test 01).
//   With that locked in, supplying any [2] outside the registerable
//   set forces the registerable-event-type check to fire.
//
//   Per §[bind_event_route] the registerable set is {1, 2, 3, 6}.
//   §[clear_event_route] reuses that same registerable set: any
//   non-registerable type for clear must also fail E_INVAL.
//
//   The bind_event_route_03 sibling establishes that the kernel checks
//   the registerable-event-type gate before the EC-cap (bind / unbind)
//   gate, so SLOT_INITIAL_EC's caps (= ec_inner_ceiling = 0xFF, which
//   omits `unbind` at bit 12) do not preempt the E_INVAL we expect
//   here.
//
//   The set of non-registerable values is open-ended; we sample several
//   representative ones to exercise the boundary on both sides of the
//   registerable set:
//     - 0     (below the registerable range)
//     - 4     (a hole inside the range — between 3 and 6)
//     - 5     (a hole inside the range — between 3 and 6)
//     - 7     (above the registerable range)
//   Each call must return E_INVAL.
//
// Action
//   For each non-registerable event_type N in {0, 4, 5, 7}:
//     clearEventRoute(SLOT_INITIAL_EC, N)
//       — must return E_INVAL.
//
// Assertions
//   1: clearEventRoute with event_type = 0 returned something other than E_INVAL.
//   2: clearEventRoute with event_type = 4 returned something other than E_INVAL.
//   3: clearEventRoute with event_type = 5 returned something other than E_INVAL.
//   4: clearEventRoute with event_type = 7 returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial_ec_slot: u12 = caps.SLOT_INITIAL_EC;
    const e_inval: u64 = @intFromEnum(errors.Error.E_INVAL);

    const r0 = syscall.clearEventRoute(initial_ec_slot, 0);
    if (r0.v1 != e_inval) {
        testing.fail(1);
        return;
    }

    const r4 = syscall.clearEventRoute(initial_ec_slot, 4);
    if (r4.v1 != e_inval) {
        testing.fail(2);
        return;
    }

    const r5 = syscall.clearEventRoute(initial_ec_slot, 5);
    if (r5.v1 != e_inval) {
        testing.fail(3);
        return;
    }

    const r7 = syscall.clearEventRoute(initial_ec_slot, 7);
    if (r7.v1 != e_inval) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
