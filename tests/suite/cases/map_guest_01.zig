// Spec §[map_guest] map_guest — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid VM handle."
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
//   as a VM handle.
//
//   §[map_guest] test 03 says E_INVAL fires if N == 0, so passing an
//   empty pairs slice could mask the BADCAP signal. To exercise the
//   BADCAP gate with no risk of E_INVAL preempting it, supply a
//   single (guest_addr, page_frame) pair so N == 1. The BADCAP gate
//   on [1] must fire before the pairs list is dereferenced; the
//   validity of the page_frame in the pair is irrelevant once [1] is
//   rejected.
//
// Action
//   1. map_guest(invalid_vm_slot, &.{ 0, 0 }) — must return E_BADCAP
//      because the VM slot is empty.
//
// Assertions
//   1: map_guest returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [1] must fire before any
    // validation of the (guest_addr, page_frame) pairs, so the
    // page_frame value in the pair is irrelevant.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.mapGuest(empty_slot, &.{ 0, 0 });

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
