// Spec §[restart_semantics] — test 08.
//
// "[test 08] returns E_PERM if `timer_arm` is called with
//  `caps.restart_policy = 1` and the calling domain's
//  `restart_policy_ceiling.tm_restart_max = 0`."
//
// DEGRADED SMOKE VARIANT
//   Faithful coverage requires the test to run inside a capability
//   domain whose `restart_policy_ceiling.tm_restart_max` is 0, so that
//   `timer_arm` with `caps.restart_policy = 1` triggers the gate. The
//   test runner (`runner/primary.zig`) currently spawns every test
//   with a fixed `ceilings_outer` of `0x0000_003F_03FE_FFFF`, which
//   sets `tm_restart_max = 1` (bit 25 of the word, bit 9 of the
//   `restart_policy_ceiling` field). The only way to lower that
//   ceiling for a single test is to nest a fresh
//   `create_capability_domain` call from within the test body — which
//   in turn requires staging an embedded child ELF and reproducing the
//   primary's spawn-and-recv plumbing inside the test. No existing
//   spec test does that yet; landing the infrastructure is out of
//   scope for the v3 test gate.
//
//   What this smoke test exercises instead: the inverse path. With
//   `tm_restart_max = 1` the same `timer_arm` call must NOT return
//   E_PERM on the restart_policy gate. That at least pins the
//   compile-time shape of the syscall wrapper, the cap encoding, and
//   the deadline_ns / flags packing this test would need once the
//   real negative path is wired.
//
// Action
//   1. timer_arm(caps={arm, restart_policy=1}, deadline_ns=1_000_000,
//                flags=0)                               — should not
//      return E_PERM under the runner's `tm_restart_max = 1` ceiling.
//
// Assertions
//   1: timer_arm returned E_PERM in vreg 1 — the restart_policy gate
//      fired even though the runner's `tm_restart_max = 1` should
//      permit `caps.restart_policy = 1`. This is the smoke check; the
//      real spec assertion (E_PERM under `tm_restart_max = 0`) lands
//      once nested-domain infrastructure exists.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[timer] timer_arm caps word: bit 4 = restart_policy. Setting
    // restart_policy = 1 is the trigger condition for the spec test;
    // arm/cancel are added so the resulting handle is configurable
    // through the rest of the §[timer] surface.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
        .restart_policy = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // deadline_ns must be nonzero (§[timer_arm] [test 03]); flags = 0
    // selects a one-shot timer (`periodic` bit 0 clear).
    const deadline_ns: u64 = 1_000_000;
    const flags: u64 = 0;

    const result = syscall.timerArm(caps_word, deadline_ns, flags);

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
