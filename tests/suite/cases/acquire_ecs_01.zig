// Spec §[acquire_ecs] acquire_ecs — test 01.
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
//   maximum 12-bit handle id — is therefore guaranteed to be invalid,
//   matching the shape used by restrict_01.
//
// Action
//   acquire_ecs(invalid_handle). With no reserved bits set in [1] and
//   the slot empty, the only error path that applies is BADCAP — the
//   E_PERM (test 02) and E_INVAL (test 03) checks cannot fire.
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

    const result = syscall.acquireEcs(empty_slot);

    if (result.regs.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
