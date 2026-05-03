// Spec §[perfmon_stop] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `pmu`."
//
// Strategy
//   The runner's primary gives every test domain a self-handle with
//   `pmu = true` (see runner/primary.zig, child_self). To force the
//   perfmon_stop E_PERM path we must drop the `pmu` bit on the
//   self-handle before invoking the syscall.
//
//   §[restrict] is the right primitive: it reduces caps in place on
//   any handle and requires no self-handle cap of its own. Most
//   SelfCap fields use plain bitwise subset semantics; the spec only
//   pins numeric restart_policy ordering for EC and VAR handles
//   (§[capabilities] restrict tests 03/04). For the self-handle we
//   read the current caps verbatim out of the read-only-mapped cap
//   table, clear bit 6 (`pmu`), and write that reduced word back.
//   Every other bit stays identical, so neither the bitwise subset
//   check nor any reserved-bit rejection can fire — restrict must
//   succeed, and the only spec-mandated outcome of the subsequent
//   perfmon_stop call is E_PERM. The E_PERM check is sequenced ahead
//   of the EC-handle validation, so it dominates regardless of the
//   target slot's contents; we still pass SLOT_INITIAL_EC (the live
//   EC handle the runner installs at slot 1) so [1] is well-formed.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table
//   2. restrict(self, caps & ~pmu)             — must succeed
//   3. perfmon_stop(SLOT_INITIAL_EC)            — must return E_PERM
//
// Assertions
//   1: self-handle did not actually carry `pmu` (runner contract
//      broken; the precondition this test relies on is gone)
//   2: restrict failed when dropping the pmu bit
//   3: perfmon_stop returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const PMU_BIT: u16 = 1 << 6;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cur_caps: u16 = self_cap.caps();

    if ((cur_caps & PMU_BIT) == 0) {
        testing.fail(1);
        return;
    }

    const reduced_caps: u16 = cur_caps & ~PMU_BIT;
    const restrict_result = syscall.restrict(caps.SLOT_SELF, @as(u64, reduced_caps));
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const stop = syscall.perfmonStop(caps.SLOT_INITIAL_EC);
    if (stop.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
