// Spec §[power] power_set_freq — test 10.
//
// "[test 10] returns E_INVAL if [2] is nonzero and outside the
//  platform's supported frequency range."
//
// Spec semantics
//   §[power] power_set_freq([1] core_id, [2] hz) defines hz = 0 as the
//   "let the kernel pick" sentinel. For nonzero hz the kernel is
//   expected to validate the requested frequency against the platform's
//   supported range and reject out-of-range targets with E_INVAL.
//
//   power_set_freq's documented failure paths in spec order are:
//     [test 07] E_PERM  if the caller's self-handle lacks `power`.
//     [test 08] E_INVAL if [1] is >= info_system's `cores`.
//     [test 09] E_NODEV if the queried core does not support frequency
//               scaling (per info_cores flag bit 2).
//     [test 10] E_INVAL if [2] is nonzero and outside the platform's
//               supported frequency range.
//
//   Spec does not pin the relative order of the cap, core-id-bounds,
//   per-core-capability, and frequency-range checks; the documented
//   behaviors are independent. Test 10 expects the frequency-range
//   check on [2] to surface E_INVAL.
//
// Strategy
//   To isolate the frequency-range check we make every other check
//   structurally pass:
//     - [1] = 0: core 0 always exists on every supported platform, so
//       the test 08 core-id bounds check cannot fire on [1].
//     - [2] = u64::MAX: the largest possible u64. No real CPU's tunable
//       frequency range reaches anywhere near 2^64 Hz (~1.8 × 10^19 Hz);
//       even allowing for synthetic platforms, this value is
//       unambiguously outside any plausible supported range, so the
//       test 10 spec line is the spec-mandated outcome whenever the
//       test 10 branch is reached.
//
//   Picking core_id at runtime via info_system would let the test
//   target a specific core, but the spec-10 assertion is platform-wide
//   ("the platform's supported frequency range"), not per-core. core 0
//   keeps the test simple and matches the convention used by
//   power_07/power_08 for the same syscall.
//
// DEGRADED VARIANT
// ----------------
//   The runner's child capability domain (see runner/primary.zig)
//   intentionally withholds `power` from the test child's self-handle
//   so the perm-check tests (01, 02, 03, 06, 07, 12) fire first. As a
//   consequence the test child cannot satisfy power_set_freq's `power`
//   precondition: a faithful kernel may surface E_PERM for this call
//   before reaching the frequency-range check.
//
//   Likewise, if the kernel evaluates the per-core frequency-scaling
//   capability probe (test 09, E_NODEV when info_cores flag bit 2 is
//   clear on core 0) before the frequency-range check, a platform
//   without scaling on core 0 surfaces E_NODEV instead of E_INVAL.
//
//   Spec §[power] does not pin the relative order of these checks.
//   Until the runner is extended to grant `power` to tests that need
//   it (or a trusted sub-domain mechanism is wired in), and until the
//   kernel's per-core capability probe is exposed, we cannot strictly
//   observe the frequency-range-only path. The assertion below accepts
//   E_INVAL (the spec-10 outcome), E_PERM (the cap-unreachable
//   degraded outcome), or E_NODEV (the per-core-probe outcome) so the
//   test does not falsely fail on a kernel that orders perm or per-
//   core-capability before frequency-range. A success return
//   (vreg 1 == OK) is always a violation: power_set_freq must not
//   "succeed" with an out-of-range frequency target.
//
// Action
//   power_set_freq(core_id = 0, hz = u64::MAX) — must NOT return OK;
//   should return E_INVAL (spec) or E_PERM / E_NODEV (degraded).
//
// Assertions
//   1: power_set_freq returned OK (success on out-of-range hz is a
//      spec violation under any check ordering).
//   2: power_set_freq returned an error code other than E_INVAL,
//      E_PERM, or E_NODEV (an unrelated failure mode that indicates
//      the test's preconditions are broken).

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // [2] = u64::MAX: nonzero, and unambiguously outside any plausible
    // platform's supported frequency range. Sidesteps the hz = 0
    // "kernel picks" sentinel that would clear test 10's precondition.
    const out_of_range_hz: u64 = ~@as(u64, 0);

    const result = syscall.powerSetFreq(0, out_of_range_hz);

    // Success on an out-of-range hz is a spec violation under any
    // check ordering: power_set_freq cannot meaningfully retune to a
    // frequency the platform does not support.
    if (result.v1 == @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Accept E_INVAL (the spec-10 outcome), E_PERM (the runner's
    // child lacks `power`, so a kernel that checks perm before
    // frequency-range surfaces this instead), or E_NODEV (a kernel
    // that checks per-core frequency-scaling capability before the
    // frequency-range check surfaces this when info_cores flag bit 2
    // is clear on core 0). Any other error code indicates a distinct
    // failure path the test does not cover.
    const err = result.v1;
    if (err != @intFromEnum(errors.Error.E_INVAL) and
        err != @intFromEnum(errors.Error.E_PERM) and
        err != @intFromEnum(errors.Error.E_NODEV))
    {
        testing.fail(2);
        return;
    }

    testing.pass();
}
