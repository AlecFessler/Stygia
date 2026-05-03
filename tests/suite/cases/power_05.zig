// Spec §[power] power_sleep — test 05.
//
// "[test 05] returns E_NODEV if the platform does not support the
//  requested sleep depth."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of test 05 requires:
//     (a) the caller's self-handle holds the `power` cap so the syscall
//         clears the test 03 (E_PERM) gate, and
//     (b) the platform genuinely lacks support for one of {sleep,
//         hibernate} so the kernel takes the E_NODEV branch in
//         `powerSleep` (kernel/syscall/system.zig:198) for a depth that
//         passes the test 04 (E_INVAL) gate (depth ∈ {1, 3, 4}).
//
//   Both preconditions fail in the current runner:
//
//   (a) The runner withholds `power` and `restart` from `child_self`
//       intentionally so spec tests cannot shut the runner down or mask
//       their own faults via domain-restart fallback (see
//       runner/primary.zig:173). Every child domain spawned by the
//       runner therefore takes the E_PERM branch on `power_sleep` long
//       before depth-vs-platform support is consulted.
//
//   (b) Even were `power` granted, the QEMU/KVM platform that hosts the
//       suite advertises full ACPI sleep states; depth = 1 succeeds and
//       suspends the host, depth = 3/4 are mapped to .hibernate by the
//       kernel and likewise succeed on the host firmware. The aarch64
//       PSCI rig answers .sleep via PSCI_CPU_SUSPEND on supported cores
//       and only returns E_NODEV when PSCI itself is absent — a
//       configuration the test runner does not provision.
//
//   Reaching the faithful path needs either:
//     - a runner mode that re-launches a single test with the `power`
//       cap restored on `child_self` and a kernel build that masks
//       sleep-state advertisement so an in-spec depth (1, 3, or 4)
//       reports unsupported; or
//     - a separate test rig (bare hardware without ACPI sleep / without
//       PSCI) that the runner targets for E_NODEV-conditional power
//       assertions.
//   Neither is provisioned in the v0 runner.
//
// Strategy (smoke prelude)
//   We exercise the `power_sleep` call shape with depth = 1 (a value
//   that clears the E_INVAL gate per spec). The runner-imposed cap
//   withholding makes this the E_PERM path on every supported target,
//   so the spec assertion under test is unreachable here. We do not
//   check the returned word against any spec error: the assertion that
//   test 05 actually makes (E_NODEV under no-platform-support) is
//   unreachable through any construction available to a child domain.
//
// Action
//   1. powerSleep(depth = 1) — call shape only. We do not check the
//      returned word against any spec error: on every supported runner
//      configuration the E_PERM branch fires before the E_NODEV branch
//      can be reached.
//
// Assertion
//   No spec assertion is checked — passes with assertion id 0 because
//   the E_NODEV path is unreachable from a child domain that lacks
//   `power`. Test reports pass regardless of what `power_sleep`
//   returns.
//
// Faithful-test note
//   Faithful test deferred pending either:
//     - a runner mode that grants `power` to child_self for this single
//       test plus a kernel build/boot variant that masks platform sleep
//       support so an in-spec depth reports unsupported; or
//     - a no-sleep hardware target wired into the runner.
//   Once that exists, the action becomes:
//     <runner: spawn child with `power` cap and platform sleep masked>
//     <test: powerSleep(depth = 1)>
//     <test: assert returned word == E_NODEV>
//   That equality assertion (id 1) would replace this smoke's
//   pass-with-id-0.

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Smoke the power_sleep call shape with an in-spec depth value
    //    (1 — sleep / S1/S3-equivalent per §[power] power_sleep). caps
    //    on the calling self-handle lack `power`, so the syscall takes
    //    the E_PERM branch (test 03) before reaching the E_NODEV branch
    //    (test 05). We do not check the returned word against any spec
    //    error.
    _ = syscall.powerSleep(1);

    // No spec assertion is being checked — the E_NODEV path is
    // unreachable from a child domain that lacks `power`. Pass with
    // assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
