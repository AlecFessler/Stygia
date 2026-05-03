// Spec §[power] — test 07.
//
// "[test 07] returns E_PERM if the caller's self-handle lacks `power`."
//
// (This test 07 is the E_PERM gate for the `power_set_freq` syscall.
//  §[power] reuses the same E_PERM-on-missing-`power` rule across each
//  power_* syscall; the spec line under test here is the one anchored
//  to power_set_freq specifically.)
//
// Spec semantics
//   §[power]: "All `power_*` syscalls require `power` on the caller's
//   self-handle." The precondition for a positive observation of this
//   rule is that the caller's self-handle does NOT have the `power`
//   cap. If the cap is present, the syscall would proceed past the
//   permission check and either succeed (tearing down the runner) or
//   return a different error code, neither of which lets us assert the
//   spec line under test.
//
// Strategy
//   The runner mints each test child with a SelfCap that intentionally
//   omits `power` (and `restart`) — see runner/primary.zig, child_self,
//   which lists crcd/crec/crvr/crpf/crvm/crpt/pmu/fut_wake/timer/pri
//   but not `power`. So the test does not need to call `restrict` to
//   set up the precondition; the runner has already arranged it.
//
//   To make the precondition explicit (and to fail loudly if a future
//   runner change accidentally grants `power` to the child), the test
//   reads its self-handle caps out of slot 0 of the read-only-mapped
//   cap table and verifies bit 8 (`power`) is clear before invoking
//   the syscall.
//
//   `power_set_freq` is invoked with core_id = 0 and hz = 0. Both are
//   spec-legal values for a self-handle that DOES carry `power`
//   (core 0 always exists; hz = 0 is the "let the kernel pick"
//   sentinel). The cap check happens before any argument validation,
//   so the kernel must short-circuit to E_PERM regardless of whether
//   the platform supports frequency scaling on core 0.
//
//   Note: power_set_freq does not destroy state on success (unlike
//   power_shutdown / power_reboot), so even if the cap check were
//   somehow bypassed the runner would survive and the test would
//   simply fail assertion 3 — there is no risk of tearing down the
//   harness on the failure path.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table
//   2. verify the `power` bit (bit 8) is clear     — runner contract
//   3. power_set_freq(0, 0)                        — must return E_PERM
//
// Assertions
//   1: self-handle's `power` bit is set (runner contract broken; the
//      precondition this test relies on is gone)
//   2: power_set_freq returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const POWER_BIT: u16 = 1 << 8;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cur_caps: u16 = self_cap.caps();

    if ((cur_caps & POWER_BIT) != 0) {
        testing.fail(1);
        return;
    }

    const result = syscall.powerSetFreq(0, 0);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
