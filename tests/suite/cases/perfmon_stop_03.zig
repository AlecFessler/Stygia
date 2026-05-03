// Spec §[perfmon_stop] — test 03.
//
// "[test 03] returns E_INVAL if perfmon was not started on the
//  target EC."
//
// Strategy
//   `perfmon_stop` requires the caller's self-handle `pmu` cap.
//   The runner spawns each spec test in a child capability domain
//   whose self-handle carries `pmu = true` (see `runner/primary.zig`,
//   `child_self.pmu = true`), so the test 01 E_PERM gate cannot
//   fire.
//
//   To isolate the "perfmon not started" check we must make every
//   other gate pass:
//     - [1] must be a valid EC handle (so test 02 E_BADCAP cannot
//       fire). The runner installs the calling EC at slot
//       SLOT_INITIAL_EC, so that handle is unconditionally valid.
//     - [1] must not be E_BUSY (test 04). E_BUSY only applies when
//       the target is not the calling EC and not currently
//       suspended. Targeting SLOT_INITIAL_EC (== self) takes the
//       calling-EC branch, so the suspended-vs-running gate cannot
//       fire.
//
//   With those gates neutralised, the only remaining spec-mandated
//   failure is the "perfmon not started" check: this test never
//   calls `perfmon_start`, so the kernel must observe no active
//   perfmon state on the target EC and return E_INVAL.
//
// Action
//   1. perfmon_stop(SLOT_INITIAL_EC) — must return E_INVAL
//
// Assertions
//   1: perfmon_stop returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const result = syscall.perfmonStop(caps.SLOT_INITIAL_EC);
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
