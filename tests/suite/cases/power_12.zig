// Spec §[power] (#power_set_idle) — test 12.
//
// "[test 12] returns E_PERM if the caller's self-handle lacks `power`."
//
// Strategy
//   The runner's primary withholds `power` from every test domain's
//   self-handle (see runner/primary.zig, child_self — `power` is not
//   listed, so its bit is 0). The precondition this test relies on is
//   therefore satisfied by construction: we just need to invoke
//   power_set_idle and observe E_PERM.
//
//   We still read the self-handle caps from slot 0 of the read-only
//   cap table and assert the `power` bit is clear before the call so
//   that a runner-contract regression (e.g., someone flipping `power`
//   on for child_self) trips a distinct assertion id rather than
//   silently masking a real spec violation.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table
//   2. assert (caps & power) == 0  — runner contract
//   3. power_set_idle(core_id=0, policy=0) — must return E_PERM
//
// Assertions
//   1: self-handle unexpectedly carries `power` (runner contract
//      broken; the precondition this test relies on is gone)
//   2: power_set_idle returned something other than E_PERM

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

    const result = syscall.powerSetIdle(0, 0);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
