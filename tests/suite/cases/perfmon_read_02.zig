// Spec §[perfmon_read] perfmon_read — test 02.
//
// "[test 02] returns E_BADCAP if [1] is not a valid EC handle."
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
//   The runner grants the child self-handle the `pmu` cap (see
//   runner/primary.zig: `child_self.pmu = true`), so the §[perfmon_read]
//   test 01 E_PERM gate cannot fire. With handle validity preceding
//   started-state and busy-state checks per the spec section ordering,
//   the only error path that survives for an empty slot is E_BADCAP.
//
// Action
//   perfmon_read(invalid_handle). With no valid handle to resolve, the
//   E_INVAL (test 03, not-started) and E_BUSY (test 04, target not
//   suspended) paths are unreachable. BADCAP is the sole spec-mandated
//   failure path that applies.
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

    const result = syscall.perfmonRead(empty_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
