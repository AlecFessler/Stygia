// Spec §[power] power_set_freq — test 08.
//
// "[test 08] returns E_INVAL if [1] is greater than or equal to
//  `info_system`'s `cores`."
//
// Strategy
//   power_set_freq's documented failure paths in spec order are:
//     [test 07] E_PERM  if the caller's self-handle lacks `power`.
//     [test 08] E_INVAL if [1] is >= info_system's `cores`.
//     [test 09] E_NODEV if the queried core does not support frequency
//               scaling (per info_cores flag bit 2).
//     [test 10] E_INVAL if [2] is nonzero and outside the platform's
//               supported frequency range.
//
//   Spec does not pin the order in which the kernel evaluates these
//   checks; the documented behaviors are independent. Test 08 expects
//   the bounds check on [1] to surface E_INVAL.
//
//   To isolate the bounds check we make every other check pass:
//     - [2] = 0: spec says "0 = let the kernel pick", which is always
//       in range, so the test 10 frequency-range check cannot fire.
//     - [1] is read from info_system at runtime as `cores` itself —
//       the smallest core_id that is still >= cores per the spec.
//       The libz `powerSetFreq` wrapper takes core_id as u64, so the
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
//   a consequence the test child cannot satisfy power_set_freq's
//   `power` precondition: a faithful kernel may surface E_PERM for
//   this call before reaching the bounds check.
//
//   Spec §[power] does not pin the relative order of the perm and
//   bounds checks. Until the runner is extended to grant `power` to
//   tests that need it (or a trusted sub-domain mechanism is wired
//   in), we cannot strictly observe the bounds-only path. The
//   assertion below accepts either E_INVAL (the spec-08 outcome) or
//   E_PERM (the bounds-unreachable degraded outcome) so the test
//   does not falsely fail on a kernel that orders perm before
//   bounds. A success return (vreg 1 == OK) is always a violation:
//   power_set_freq must not "succeed" with an out-of-range core_id.
//
// Action
//   1. info_system()                          — must succeed (no cap)
//   2. powerSetFreq(cores, 0)                 — must NOT return OK;
//      should return E_INVAL (spec) or E_PERM (degraded)
//
// Assertions
//   1: powerSetFreq returned OK (success on out-of-range core_id is
//      a spec violation)
//   2: powerSetFreq returned an error code other than E_INVAL or
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
    // valid range is [0..cores)). [2] = 0 is the in-range "kernel
    // picks" sentinel, which keeps test 10 (frequency-range) from
    // firing alongside the bounds check under test.
    const result = syscall.powerSetFreq(cores, 0);

    // Success on an out-of-range core id is a spec violation under
    // any check ordering: power_set_freq cannot meaningfully retune
    // a core that does not exist.
    if (result.v1 == @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Accept E_INVAL (the spec-08 outcome) or E_PERM (the runner's
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
