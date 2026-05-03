// Spec §[timer_arm] — test 03.
//
// "[test 03] returns E_INVAL if [2] deadline_ns is 0."
//
// Spec semantics
//   §[timer_arm] [2] deadline_ns: "nanoseconds until first fire (and
//   period if periodic)". A 0-ns deadline is meaningless: the timer
//   would either fire immediately and forever (periodic) or fire
//   instantly with no observable arming (one-shot). The kernel rejects
//   it with E_INVAL.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `timer` and a `restart_policy_ceiling` that
//   allows `tm_restart_max = 1` (see runner/primary.zig and the
//   commentary in timer_arm_02). We can therefore call timer_arm
//   directly without any setup — the only gate the call must trip is
//   the deadline_ns = 0 check.
//
//   To keep every other input clean (so neither E_PERM nor an earlier
//   E_INVAL on reserved bits / restart-policy can preempt the
//   deadline check), we pass:
//     - caps with `arm`/`cancel` set (matches timer_arm_02's shape;
//       no reserved bits), restart_policy left at 0 (no ceiling
//       interaction)
//     - deadline_ns = 0  (the bit under test)
//     - flags = 0        (periodic = 0, all reserved bits clean)
//
// Action
//   1. timer_arm(caps={arm, cancel}, deadline_ns=0, flags=0)
//      — must return E_INVAL.
//
// Assertions
//   1: timer_arm returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[timer] TimerCap layout: arm = bit 2, cancel = bit 3. Setting
    // these so the resulting handle would be structurally usable; the
    // call should never reach handle minting because deadline_ns = 0
    // is rejected up front. restart_policy left at 0 to keep clear of
    // any ceiling interaction (see timer_arm_02).
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };

    const result = syscall.timerArm(
        @as(u64, timer_caps.toU16()),
        0, // deadline_ns: the bit under test
        0, // flags: periodic = 0, all reserved bits clean
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
