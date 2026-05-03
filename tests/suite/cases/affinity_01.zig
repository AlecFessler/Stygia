// Spec §[affinity] affinity — test 01.
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
//   maximum 12-bit handle id — is therefore guaranteed to be invalid.
//
// Action
//   affinity(invalid_handle, 0). [2] = 0 means "kernel picks any core",
//   which is always in-bounds (no bits set outside the system's core
//   count, no reserved-bit conflict), so the E_INVAL checks (tests 03
//   and 04) cannot fire. With no valid handle present, the E_PERM
//   `saff`-cap check (test 02) cannot fire either. The only error path
//   that applies is BADCAP.
//
// Assertion
//   result.v1 == E_BADCAP  (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.affinity(empty_slot, 0);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
