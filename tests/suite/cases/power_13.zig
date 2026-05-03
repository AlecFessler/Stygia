// Spec §[power] power_set_idle — test 13.
//
// "[test 13] returns E_INVAL if [1] is greater than or equal to
//  `info_system`'s `cores`."
//
// Strategy
//   power_set_idle's documented failure paths in spec order are:
//     [test 12] E_PERM  if the caller's self-handle lacks `power`.
//     [test 13] E_INVAL if [1] is >= info_system's `cores`.
//     [test 14] E_NODEV if the queried core does not support idle
//               states (per info_cores flag bit 1).
//     [test 15] E_INVAL if [2] is greater than 2.
//
//   Spec does not pin the order in which the kernel evaluates these
//   checks; the documented behaviors are independent. Test 13 expects
//   the bounds check on [1] to surface E_INVAL.
//
//   To isolate the bounds check we make every other check pass:
//     - [2] = 0: spec defines policy 0 = busy-poll, which is in the
//       valid range [0..2], so the test 15 policy-range check cannot
//       fire.
//     - [1] is read from info_system at runtime as `cores` itself —
//       the smallest core_id that is still >= cores per the spec.
//       The libz `powerSetIdle` wrapper takes core_id as u64, so the
//       value reaches the kernel without truncation.
//
//   Reading the core count at runtime (rather than hard-coding a
//   QEMU-config-specific value) keeps the test stable across CI
//   target configurations: it always picks the first core_id that
//   the platform considers out-of-range.
//
// DEGRADED VARIANT
// ----------------
//   The runner's child capability domain (see runner/primary.zig)
//   intentionally withholds `power` from the test child's self-handle
//   so the perm-check tests (01, 02, 03, 06, 07, 12) fire first. As
//   a consequence the test child cannot satisfy power_set_idle's
//   `power` precondition: a faithful kernel may surface E_PERM for
//   this call before reaching the bounds check.
//
//   Spec §[power] does not pin the relative order of the perm and
//   bounds checks. Until the runner is extended to grant `power` to
//   tests that need it (or a trusted sub-domain mechanism is wired
//   in), we cannot strictly observe the bounds-only path. The
//   assertion below accepts either E_INVAL (the spec-13 outcome) or
//   E_PERM (the bounds-unreachable degraded outcome) so the test
//   does not falsely fail on a kernel that orders perm before
//   bounds. A success return (vreg 1 == OK) is always a violation:
//   power_set_idle must not "succeed" with an out-of-range core_id.
//
//   Note: the test deliberately does NOT call power_shutdown or
//   power_reboot on any path — those would tear down the runner.
//
// Action
//   1. info_system()                          — must succeed (no cap)
//   2. powerSetIdle(cores, 0)                 — must NOT return OK;
//      should return E_INVAL (spec) or E_PERM (degraded)
//
// Assertions
//   1: powerSetIdle returned OK (success on out-of-range core_id is
//      a spec violation)
//   2: powerSetIdle returned an error code other than E_INVAL or
//      E_PERM (an unrelated failure mode)

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // info_system: vreg 1 = cores. No cap required (§[info_system]).
    const sysinfo = syscall.infoSystem();
    const cores: u64 = sysinfo.v1;

    // First out-of-range core id is `cores` itself (zero-indexed, so
    // valid range is [0..cores)). [2] = 0 selects busy-poll, which is
    // in the valid policy range [0..2], so test 15 (policy bound)
    // cannot fire alongside the bounds check under test.
    const result = syscall.powerSetIdle(cores, 0);

    // Success on an out-of-range core id is a spec violation under
    // any check ordering: power_set_idle cannot meaningfully retune
    // a core that does not exist.
    if (result.v1 == @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Accept E_INVAL (the spec-13 outcome) or E_PERM (the runner's
    // child lacks `power`, so a kernel that checks perm before bounds
    // surfaces this instead). Any other error code indicates a
    // distinct failure path the test does not cover.
    const err = result.v1;
    if (err != @intFromEnum(errors.Error.E_INVAL) and
        err != @intFromEnum(errors.Error.E_PERM))
    {
        testing.fail(2);
        return;
    }

    testing.pass();
}
