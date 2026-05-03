// Spec §[timer_arm] — test 02.
//
// "[test 02] returns E_PERM if [1].caps.restart_policy = 1 and the
//  caller's `restart_policy_ceiling.tm_restart_max = 0`."
//
// Spec semantics
//   `restart_policy_ceiling.tm_restart_max` lives at bit 25 of the
//   self-handle's field1 (per §[capability_domain] field1 layout: the
//   16-bit `restart_policy_ceiling` block occupies bits 16-31, and
//   `tm_restart_max` is bit 9 within that block — i.e., bit 25 of
//   field1). At `timer_arm` time the kernel rejects any
//   `caps.restart_policy = 1` (TimerCap bit 4) when the calling
//   domain's `tm_restart_max` ceiling is 0, surfacing E_PERM.
//
// Strategy (degraded smoke variant)
//   The faithful test would look like:
//     1. spawn a child capability domain whose `restart_policy_ceiling`
//        has `tm_restart_max = 0` (i.e., ceilings_outer with bit 25
//        cleared).
//     2. inside that child, call `timer_arm(caps.restart_policy = 1)`
//        and assert the return is E_PERM.
//     3. report the result back across the IDC link.
//
//   The current test infrastructure embeds each test ELF directly in
//   the primary's manifest and spawns each as a single capability
//   domain whose ceilings are fixed in `runner/primary.zig` to
//   `restart_policy_ceiling = 0x03FE` (bit 9 of the ceiling field set
//   = `tm_restart_max = 1`). A test ELF cannot reduce its own ceiling:
//   `restrict` only operates on the caps field (word0 bits 48-63) of
//   the self-handle, not on field0/field1 where the ceiling lives.
//   There is also no path for a single test ELF to embed and spawn a
//   grandchild domain with a different ceiling.
//
//   This mirrors the ceiling-coverage gap noted in restart_semantics_03
//   (the analogous `pf_restart_max = 0` case) — until either a per-test
//   ceilings override in the runner or a two-level test infra extension
//   lands, the faithful E_PERM path for this test is unreachable.
//
//   To still exercise the syscall surface, this test mints a timer
//   with `caps.restart_policy = 1` from the test domain itself and
//   asserts that — under the runner's default `tm_restart_max = 1` —
//   the call succeeds. The "ceiling = 0 ⇒ E_PERM" rule narrows to a
//   "ceiling = 1 ⇒ accept" smoke check, which is a strict subset of
//   the spec rule (the kernel must not erroneously reject when the
//   ceiling permits the value). When a ceiling-restriction syscall is
//   added, this test should be rewritten to: (a) narrow the calling
//   domain's `tm_restart_max` to 0, then (b) invoke `timer_arm` with
//   `caps.restart_policy = 1` and assert E_PERM.
//
// Action
//   1. timer_arm(caps={arm, cancel, restart_policy=1}, deadline_ns=1,
//                flags=0) — must succeed (return a handle, not an
//                error word).
//
// Assertions
//   1: timer_arm did not return a valid handle. Under the runner's
//      `tm_restart_max = 1`, the kernel must accept the request; an
//      error response (especially E_PERM) would mean the kernel is
//      over-rejecting.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[timer] TimerCap layout: arm = bit 2, cancel = bit 3,
    // restart_policy = bit 4. Setting `arm`/`cancel` so the resulting
    // handle is structurally usable (same shape as a timer minted by a
    // production caller); `restart_policy = 1` ("keep") is the value
    // the spec line under test gates on.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
        .restart_policy = true,
    };

    const result = syscall.timerArm(
        @as(u64, timer_caps.toU16()),
        1, // deadline_ns: 1 ns (smallest non-zero; satisfies test 03)
        0, // flags: periodic = 0, all reserved bits clean
    );

    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
