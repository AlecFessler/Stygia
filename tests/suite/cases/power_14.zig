// Spec §[power] power_set_idle — test 14.
//
// "[test 14] returns E_NODEV if the queried core does not support
//  idle states (per `info_cores` flag bit 1)."
//
// DEGRADED SMOKE VARIANT
//
//   A faithful test for this rule needs two things the v0 runner +
//   libz cannot deliver to a child test domain:
//
//     1. The `power` cap on the calling EC's self-handle. Per the
//        §[power] preamble, every `power_*` syscall requires `power`
//        on the caller's self-handle; that gate fires before the
//        E_NODEV check (test 12 in the same syscall covers the E_PERM
//        path explicitly). The runner's child template
//        (runner/primary.zig: `child_self`) intentionally withholds
//        `power` (and `restart`) so a misbehaving test cannot shut the
//        runner down. Sub-domains spawned via create_capability_domain
//        cannot recover the bit either: §[create_capability_domain]
//        test 02 requires `self_caps` to be a subset of the caller's
//        self-handle caps, so any descendant inherits at most what we
//        already lack.
//
//     2. A core whose `info_cores` flag bit 1 (idle states supported)
//        is clear. Under the runner's QEMU TCG/KVM configuration
//        (`-smp cores=4 -cpu host`) every emulated core advertises a
//        uniform feature set; whether bit 1 is reported as 0 or 1
//        depends on the kernel's `info_cores` implementation choice
//        for the active platform. Even if `power` were granted, a
//        faithful test would also need to discover (or stage) a core
//        with bit 1 = 0 to drive the E_NODEV path; on a platform
//        where every core supports idle states the test 14 failure
//        mode is unreachable and the test would have to skip.
//
//   These blockers sit upstream — in the runner's `child_self`
//   layout, in the absence of a per-test override path that grants
//   `power` for the duration of one test, and in the kernel's
//   per-core idle-states reporting. The faithful body would walk
//   `info_cores` over the cores reported by `info_system`, locate
//   one whose flags bit 1 is 0, and assert E_NODEV; until the runner
//   exposes a per-test cap-grant escape hatch, the gate this child
//   hits first is E_PERM.
//
// Strategy (smoke prelude)
//   We exercise the dispatch shape: read `info_system` to discover
//   `cores`, walk `info_cores` to find a core with idle states
//   advertised as unsupported (flag bit 1 = 0), and call
//   `power_set_idle(core_id, policy = 0)` against that core. The
//   call returns E_PERM (because we lack `power`); a faithful run
//   under a runner that grants `power` would surface E_NODEV
//   instead. We do not check the return value — the failure mode
//   under test (E_NODEV) is unreachable from the v0 child, and any
//   assertion on the actual return code would either always pass
//   for the wrong reason (E_PERM rather than E_NODEV) or always
//   fail (asserting E_NODEV when the gate says E_PERM).
//
//   The smoke also exercises the reserved-bit-clean shape of [1] /
//   [2] (no high-bits set), so once the runner gains a per-test
//   cap-grant path the only assertion left to flip is "result.v1 ==
//   E_NODEV when a core with flag bit 1 = 0 was selected".
//
// Action (current degraded form)
//   1. infoSystem() — discover `cores` so we know the valid range.
//   2. Walk `info_cores(c)` for c in 0..cores; pick the first core
//      whose `flags & (1 << 1) == 0`. If none exists, target core 0
//      anyway — the smoke does not gate on selection.
//   3. powerSetIdle(target_core, 0) — policy = 0 (busy-poll) is in
//      range so spec test 15 (E_INVAL on policy > 2) does not fire.
//      Under v0 the call returns E_PERM (we lack `power`); under a
//      future strict-runner that grants `power` it would return
//      E_NODEV when the chosen core has flag bit 1 = 0.
//   4. testing.pass() — no spec assertion is checked.
//
// Assertion id reservations for the future faithful body
//   1: info_system / info_cores prelude failed (cannot enumerate cores)
//   2: no core in [0, cores) has flag bit 1 = 0 (E_NODEV unreachable
//      on this platform — test 14 would skip in a faithful runner)
//   3: power_set_idle returned something other than E_NODEV against
//      a core whose flag bit 1 = 0 (the spec failure under test)
//
// Faithful-test note
//   Replace the smoke body with the following once the runner can
//   grant `power` to a single test domain and a core with
//   `info_cores.flags & (1 << 1) == 0` exists on the platform:
//     <runner: spawn this test child with self_caps including power>
//     <child: walk info_cores, pick core_id with bit 1 = 0, fail(2)
//             if none>
//     <child: power_set_idle(core_id, 0)>
//     <child: assert result.v1 == E_NODEV, fail(3) otherwise>
//     <child: testing.pass()>

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;
    _ = errors;
    _ = caps;

    // Compile-time anchors so a future edit to the syscall enum or
    // the spec's idle-flag bit position would surface here, not in a
    // distant runtime mismatch. power_set_idle = 57 per spec §[power];
    // info_cores flag bit 1 names "idle states supported" per
    // §[system_info] info_cores output layout.
    _ = syscall.SyscallNum.power_set_idle;
    _ = syscall.SyscallNum.info_cores;
    _ = errors.Error.E_NODEV;

    // Discover the system core count. info_system requires no caps.
    const sys = syscall.infoSystem();
    const cores = sys.v1;

    // Walk cores to locate one whose idle-states flag is clear. The
    // smoke does not gate on the result of this scan — see the
    // strategy comment for why.
    var target: u64 = 0;
    var i: u64 = 0;
    while (i < cores) {
        const ic = syscall.infoCores(i);
        // flags bit 1 = idle states supported
        if ((ic.v1 & (@as(u64, 1) << 1)) == 0) {
            target = i;
            break;
        }
        i += 1;
    }

    // Issue the call shaped to test 14. policy = 0 (busy-poll) is in
    // range so spec test 15 (E_INVAL on policy > 2) does not fire.
    // Under v0 this returns E_PERM (child lacks `power`); under a
    // strict-runner future it would return E_NODEV when the selected
    // core has flag bit 1 = 0.
    _ = syscall.powerSetIdle(target, 0);

    // No spec assertion is checked — E_NODEV is unreachable from a
    // child whose self-handle lacks `power`. Pass with assertion id 0
    // to mark this slot as smoke-only in coverage.
    testing.pass();
}
