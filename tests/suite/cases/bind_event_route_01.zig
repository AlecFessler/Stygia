// Spec §[bind_event_route] bind_event_route — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid EC handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid
//   as an EC handle.
//
//   To exercise the BADCAP gate on [1] in isolation we must supply
//   well-formed [2] and [3] arguments so the kernel doesn't reject
//   the call earlier with E_INVAL (test 03/04) or E_BADCAP on [3]
//   (test 02). Pass event_type = 1 (a registerable event type) and
//   port = the test's own self-IDC slot (slot 2), which is a valid
//   port handle in the domain.
//
// Action
//   1. bindEventRoute(invalid_ec_slot, 1, self_idc_slot)
//      — must return E_BADCAP because the EC slot is empty.
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
    // table layout. The BADCAP gate on [1] must fire before any
    // validation of [2] or [3].
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;
    const self_idc_slot: u12 = 2;
    const event_type: u64 = 1;

    const result = syscall.bindEventRoute(empty_slot, event_type, self_idc_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
