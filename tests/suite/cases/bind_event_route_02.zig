// Spec §[bind_event_route] bind_event_route — test 02.
//
// "[test 02] returns E_BADCAP if [3] is not a valid port handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid.
//
//   To exercise the BADCAP gate on [3] in isolation we must supply
//   well-formed [1] and [2] arguments so the kernel doesn't reject
//   the call earlier with E_BADCAP on [1] (test 01) or E_INVAL
//   (tests 03/04). Pass target = the initial EC at slot 1 (a valid
//   EC handle in the domain) and event_type = 1 (a registerable event
//   type). With those arguments well-formed, supplying slot 4095 as
//   [3] forces the BADCAP gate on [3] to fire.
//
// Action
//   1. bindEventRoute(initial_ec_slot, 1, invalid_port_slot)
//      — must return E_BADCAP because the port slot is empty.
//
// Assertions
//   1: bindEventRoute returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [3] must fire after [1] and [2]
    // have been validated.
    const initial_ec_slot: u12 = caps.SLOT_INITIAL_EC;
    const invalid_port_slot: u12 = caps.HANDLE_TABLE_MAX - 1;
    const event_type: u64 = 1;

    const result = syscall.bindEventRoute(initial_ec_slot, event_type, invalid_port_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
