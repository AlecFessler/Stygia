// Spec §[perfmon_start] perfmon_start — test 02.
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
//   runner/primary.zig: `child_self.pmu = true`), so the §[perfmon_start]
//   test 01 E_PERM gate cannot fire. With handle validity preceding
//   config-content validation per the spec section ordering, the only
//   error path that survives is E_BADCAP regardless of the config
//   bits supplied.
//
// Action
//   perfmon_start(invalid_handle, num_configs = 1, configs = {0}). The
//   single config has event = 0, has_threshold = 0, and no reserved
//   bits set, so even if the kernel resolved the handle it would not
//   trip the E_INVAL paths from tests 03-06; and a missing handle
//   precludes the E_BUSY path from test 07. BADCAP is the sole
//   spec-mandated failure path that applies.
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

    const configs = [_]u64{0};
    const result = syscall.perfmonStart(empty_slot, 1, configs[0..]);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
