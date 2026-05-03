// Spec §[power] power_shutdown — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `power`."
//
// Strategy
//   The runner's primary intentionally withholds `power` from every
//   spawned test domain (see runner/primary.zig: `power` and `restart`
//   are explicitly NOT set on `child_self`) so a test can't shut the
//   suite down mid-run. That means the precondition for this E_PERM
//   path is already in place at test entry — no `restrict` setup is
//   needed. We only need to guard against a runner regression that
//   would silently grant `power`, which would let `power_shutdown`
//   actually fire and tear the suite down.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table; assert
//      `power` (bit 8) is clear so the runner contract still holds.
//   2. power_shutdown() — must return E_PERM.
//
// Assertions
//   1: self-handle unexpectedly carries `power` (runner contract
//      broken; refusing to invoke the syscall is the only safe thing
//      to do, since success would actually shut the system off).
//   2: power_shutdown returned something other than E_PERM.

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

    const result = syscall.powerShutdown();
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
