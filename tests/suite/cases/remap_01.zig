// Spec §[remap] remap — test 01.
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
//   The §[remap] gate order rejects an invalid [1] before consulting
//   [2] new_cur_rwx, so we pass an arbitrary (but spec-shaped) rwx
//   value and still observe E_BADCAP from the [1] check.
//
// Action
//   1. remap(invalid_var_slot, new_cur_rwx) — must return E_BADCAP
//      because [1] (the VAR slot) is empty.
//
// Assertions
//   1: remap returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [1] must fire before any
    // consultation of [2]'s value or the VAR's `map` / caps fields.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    // new_cur_rwx = 0 (no permissions) — value is irrelevant since
    // the [1] BADCAP gate fires first.
    const new_cur_rwx: u64 = 0;

    const result = syscall.remap(empty_slot, new_cur_rwx);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
