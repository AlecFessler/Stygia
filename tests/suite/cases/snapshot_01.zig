// Spec §[snapshot] snapshot — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid VAR handle."
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
//   as a VAR handle.
//
//   The §[snapshot] gate order rejects an invalid [1] before consulting
//   [2], so passing slot 4095 for both args still observes E_BADCAP
//   from the [1] check.
//
// Action
//   1. snapshot(invalid_var_slot, invalid_var_slot) — must return
//      E_BADCAP because [1] (the target VAR slot) is empty.
//
// Assertions
//   1: snapshot returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [1] must fire before any
    // dispatch on [2] or further validation.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.snapshot(empty_slot, empty_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
