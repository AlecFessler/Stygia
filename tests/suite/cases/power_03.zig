// Spec §[power] / power_sleep — test 03.
//
// "[test 03] returns E_PERM if the caller's self-handle lacks `power`."
//
// Strategy
//   The runner's primary withholds the `power` cap from every test
//   domain's self-handle (see runner/primary.zig, child_self) precisely
//   so a spec test can never shut the runner down on a success path.
//   That precondition is exactly what test 03 asks us to observe: the
//   caller's self-handle lacks `power`, so power_sleep must return
//   E_PERM without performing any system action.
//
//   Unlike perfmon_info_01, no restrict step is needed here — the bit
//   is already cleared by the runner. We pass depth=1 (sleep) so that
//   the [1] argument is in the spec-defined valid set {1, 3, 4} and the
//   only possible spec-mandated outcome is E_PERM.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table to confirm
//      the runner still withholds `power` (defensive — if a future
//      runner change leaks the bit, this assertion catches it).
//   2. power_sleep(1) — must return E_PERM.
//
// Assertions
//   1: self-handle unexpectedly carries `power` (runner contract
//      changed; the precondition this test relies on is gone)
//   2: power_sleep returned something other than E_PERM

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

    const result = syscall.powerSleep(1);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
