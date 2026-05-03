// Spec §[yield] — test 01.
//
// "[test 01] returns E_BADCAP if [1] is nonzero and not a valid EC handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  -> self
//     slot 1  -> initial EC
//     slot 2  -> self-IDC
//     slot 3+ -> passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid.
//
//   yield's [1] handle word is special: 0 means "yield to scheduler",
//   so the BADCAP path requires a *nonzero* slot id whose handle is
//   not present. Slot 4095 satisfies both conditions.
//
// Action
//   yield(empty_slot). The slot id fits in u12 with no reserved bits
//   set, so the E_INVAL check (test 02) cannot fire. The only error
//   path that applies is BADCAP.
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

    const empty_slot: u64 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.yieldEc(empty_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
