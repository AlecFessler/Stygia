// Spec §[acquire_vars] acquire_vars — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid IDC handle."
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
//   acquire_vars(invalid_handle). With no handle in that slot at all
//   the E_PERM (test 02) and E_INVAL (test 03) checks cannot fire —
//   there is no handle whose `aqvr` cap could be missing, and the
//   reserved-bits pattern is clean (low 12 bits hold a nominal id, all
//   other bits zero). The only error path that applies is BADCAP.
//
// Assertion
//   result.regs.v1 == E_BADCAP  (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.acquireVars(empty_slot);

    if (result.regs.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
