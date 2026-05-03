// Spec §[power] power_set_idle — test 15.
//
// "[test 15] returns E_INVAL if [2] is greater than 2."
//
// Strategy
//   The spec defines `[2] policy` for `power_set_idle` as a 0..2 value
//   (0 = busy-poll, 1 = halt only, 2 = deepest available c-state). Any
//   [2] > 2 is structurally out of range and must surface E_INVAL.
//
//   The other power_set_idle error paths are:
//     - test 12 (E_PERM):   caller's self-handle lacks `power`.
//     - test 13 (E_INVAL):  [1] core_id >= info_system's `cores`.
//     - test 14 (E_NODEV):  queried core does not support idle states.
//
//   The runner-spawned domain receives a self-handle with `power`
//   intentionally withheld (see runner/primary.zig: "`power` and
//   `restart` are intentionally withheld so a test can't shut the
//   runner down ..."). On a kernel that ordered rights validation
//   before structural validation, every `power_set_idle` call from a
//   test domain would resolve as E_PERM, rendering test 15 (and tests
//   13 and 14) untestable from any caller reachable in this runner.
//
//   The conventional ordering — structural argument validation before
//   permission validation — is the only reading consistent with tests
//   13, 14, and 15 each being independently asserted. Under that
//   ordering, `[2] > 2` trips E_INVAL before the `power` cap is
//   inspected. This is the same pattern priority_04 documents for
//   `priority` test 04 vs test 03.
//
//   `[1] core_id` is set to 0 so it is in range on any platform with at
//   least one core. The kernel may reach the core_id range check
//   before or after the policy range check; either way 0 is safe.
//
// Action
//   power_set_idle(core_id = 0, policy = 3) — must return E_INVAL.
//
//   3 is the smallest value strictly greater than the spec maximum of
//   2 and fits in any reasonable encoding the kernel might use for the
//   policy field, so the failure mode isn't masked by an unrelated
//   overflow.
//
// Assertion
//   1: power_set_idle(core_id = 0, policy = 3) returned something
//      other than E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const out_of_range_policy: u64 = 3;
    const result = syscall.powerSetIdle(0, out_of_range_policy);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
