// Spec §[perfmon_start] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `pmu`."
//
// Strategy
//   The runner's primary gives every test domain a self-handle with
//   `pmu = true` (see runner/primary.zig, child_self). To force the
//   perfmon_start E_PERM path we must drop the `pmu` bit on the
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
//   perfmon_start call is E_PERM.
//
//   For the perfmon_start call itself we want every other error
//   path to be unreachable so E_PERM is the only spec-mandated
//   outcome:
//     - target = SLOT_INITIAL_EC, the kernel-installed EC handle the
//       runner places at slot 1 of every child cap table — a valid
//       EC handle, so test 02 (E_BADCAP) cannot fire.
//     - num_configs = 1, in range [1, num_counters] for any plausible
//       hardware (every PMU has at least one counter), so test 03
//       (E_INVAL on count) cannot fire.
//     - one config_event with event index 0, has_threshold = 0, all
//       reserved bits clear; matching config_threshold = 0. Event
//       index 0 is the lowest bit of supported_events and is set on
//       any conforming PMU, so test 04 cannot fire. has_threshold = 0
//       means test 05 (overflow not supported) cannot fire. No
//       reserved bits set means test 06 cannot fire.
//     - the calling EC is targeting itself (same domain's initial EC
//       slot), so test 07 (E_BUSY when target is not caller and not
//       suspended) cannot fire either.
//   That leaves the missing `pmu` cap as the only fault, and E_PERM
//   as the only acceptable result.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table
//   2. restrict(self, caps & ~pmu) — must succeed
//   3. perfmon_start(target = initial EC, num_configs = 1,
//      config_event = 0, config_threshold = 0) — must return E_PERM
//
// Assertions
//   1: self-handle did not actually carry `pmu` (runner contract
//      broken; the precondition this test relies on is gone)
//   2: restrict failed when dropping the pmu bit
//   3: perfmon_start returned something other than E_PERM

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

    const configs = [_]u64{ 0, 0 };
    const result = syscall.perfmonStart(caps.SLOT_INITIAL_EC, 1, configs[0..]);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
