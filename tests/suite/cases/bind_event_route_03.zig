// Spec §[bind_event_route] bind_event_route — test 03.
//
// "[test 03] returns E_INVAL if [2] is not a registerable event type
//  (i.e., not in {1, 2, 3, 6})."
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
//     - [1] = SLOT_INITIAL_EC (a valid EC handle, sidesteps test 01)
//     - [3] = SLOT_SELF_IDC   (a valid port handle, sidesteps test 02)
//   With those locked in, supplying any [2] outside {1, 2, 3, 6} forces
//   the registerable-event-type check to fire.
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
//     bindEventRoute(SLOT_INITIAL_EC, N, SLOT_SELF_IDC)
//       — must return E_INVAL.
//
// Assertions
//   1: bindEventRoute with event_type = 0 returned something other than E_INVAL.
//   2: bindEventRoute with event_type = 4 returned something other than E_INVAL.
//   3: bindEventRoute with event_type = 5 returned something other than E_INVAL.
//   4: bindEventRoute with event_type = 7 returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial_ec_slot: u12 = caps.SLOT_INITIAL_EC;
    const self_idc_slot: u12 = caps.SLOT_SELF_IDC;
    const e_inval: u64 = @intFromEnum(errors.Error.E_INVAL);

    const r0 = syscall.bindEventRoute(initial_ec_slot, 0, self_idc_slot);
    if (r0.v1 != e_inval) {
        testing.fail(1);
        return;
    }

    const r4 = syscall.bindEventRoute(initial_ec_slot, 4, self_idc_slot);
    if (r4.v1 != e_inval) {
        testing.fail(2);
        return;
    }

    const r5 = syscall.bindEventRoute(initial_ec_slot, 5, self_idc_slot);
    if (r5.v1 != e_inval) {
        testing.fail(3);
        return;
    }

    const r7 = syscall.bindEventRoute(initial_ec_slot, 7, self_idc_slot);
    if (r7.v1 != e_inval) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
