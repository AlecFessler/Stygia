// Spec §[perfmon_read] perfmon_read — test 03.
//
// "[test 03] returns E_INVAL if perfmon was not started on the target EC."
//
// Strategy
//   `perfmon_read` returns E_INVAL when no perfmon session has ever
//   been started on the target EC. To isolate this check we must make
//   every other gate pass:
//     - self-handle carries `pmu` (so no E_PERM, test 01). The runner
//       provisions every test domain's self-handle with `pmu = true`
//       (see runner/primary.zig, `child_self.pmu = true`), so this is
//       given.
//     - the target handle id must be a valid EC (so no E_BADCAP, test
//       02). The runner installs the test EC at `SLOT_INITIAL_EC = 1`.
//     - the target must not trip the E_BUSY gate (test 04). Test 04
//       only fires when the target is a different EC that is not
//       currently suspended; targeting the calling EC itself bypasses
//       that path entirely.
//
//   The simplest construction is therefore: invoke `perfmon_read` on
//   `SLOT_INITIAL_EC` from within the test EC itself, having never
//   called `perfmon_start`. The only spec-mandated outcome is E_INVAL.
//
// Action
//   1. perfmon_read(SLOT_INITIAL_EC) — must return E_INVAL
//
// Assertions
//   1: perfmon_read returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const result = syscall.perfmonRead(caps.SLOT_INITIAL_EC);
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
