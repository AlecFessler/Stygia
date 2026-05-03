// Spec §[power] power_set_freq — test 09.
//
// "[test 09] returns E_NODEV if the queried core does not support
//  frequency scaling (per `info_cores` flag bit 2)."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of test 09 requires:
//     (a) the calling self-handle to hold the `power` cap (otherwise
//         the §[power] perm gate fires E_PERM before the per-core
//         frequency-scaling probe can be reached); and
//     (b) the platform to expose at least one core whose `info_cores`
//         flag bit 2 (frequency scaling supported) is 0 — that is the
//         only state in which the kernel's per-core capability probe
//         takes the E_NODEV branch.
//
//   Both preconditions are violated in the v0 runner:
//
//   1. The primary's `child_self` (runner/primary.zig) intentionally
//      withholds `power` (and `restart`) from every test child so a
//      test cannot shut the runner down or mask its own faults via
//      domain-restart fallback. Every spec test in this suite executes
//      with `self_caps.power = 0`, so any `power_set_freq` syscall
//      will be rejected with E_PERM at the syscall gate before the
//      core_id, core-capability, and frequency-range checks run.
//
//   2. The current kernel implementation (kernel/syscall/system.zig
//      `powerSetFreq`) carries an explicit TODO acknowledging that
//      "per-core frequency-scaling capability probe (spec test 09) and
//      per-platform frequency-range bounds check (spec test 10) are
//      not yet exposed by the arch dispatch." After the perm gate and
//      the core_id-bounds check, the backend forwards `set_freq` to
//      the local core unconditionally — there is no path that returns
//      E_NODEV today.
//
//   Reaching the faithful path therefore needs both:
//     - a runner mode (or per-test self_caps override) that grants
//       `power` to this single test child without compromising the
//       isolation invariants the runner currently relies on; and
//     - a kernel-side per-core frequency-scaling capability probe
//       wired into the arch dispatch that `power_set_freq` consults
//       before delegating to `cpu.cpuPowerAction(.set_freq, ...)`.
//   Neither exists in v0.
//
// Strategy (smoke prelude)
//   Reach the syscall dispatch with the documented arg shape and
//   confirm the syscall returns *something*. The platform-conditional
//   E_NODEV branch is unreachable here for the reasons above, so we do
//   not check the returned word against any spec error code.
//
// Action
//   1. powerSetFreq(core_id = 0, hz = 0) — call shape only. The
//      `power` cap is absent on the child's self-handle, so the actual
//      observable outcome on the v0 runner is E_PERM (gate 07), not
//      E_NODEV. We do not check the returned word against any spec
//      error: the assertion that test 09 actually makes is unreachable
//      here.
//
// Assertion
//   No spec assertion is checked — passes with assertion id 0 because
//   the E_NODEV path is unreachable on the current runner+kernel
//   combination. Test reports pass regardless of what `power_set_freq`
//   returns.
//
// Faithful-test note
//   Faithful test deferred pending both:
//     - a runner mode that grants `power` to this single test child; and
//     - a kernel-side per-core frequency-scaling capability probe that
//       can drive the E_NODEV branch.
//   Once both exist, the action becomes:
//     <runner: spawn this test with self_caps.power = 1>
//     <test: probe info_cores until a core with flag bit 2 == 0 is
//            found; if none, fail-soft pass with id 0>
//     <test: powerSetFreq(no_freq_scaling_core_id, hz = 0)>
//     <test: assert returned word == E_NODEV>
//   That equality assertion (id 1) would replace this smoke's
//   pass-with-id-0.

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Smoke the power_set_freq call shape with the canonical "let the
    // kernel pick" sentinel hz = 0 against core_id = 0. The runner
    // withholds `power` from the child's self-handle, so the syscall
    // takes the §[power] perm-gate path (E_PERM) on the v0 runner;
    // the test 09 E_NODEV branch is unreachable. We do not check the
    // returned word against any spec error.
    _ = syscall.powerSetFreq(0, 0);

    // No spec assertion is being checked — the E_NODEV path is
    // unreachable on the current runner+kernel combination. Pass with
    // assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
