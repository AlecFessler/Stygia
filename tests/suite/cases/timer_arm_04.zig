// Spec §[timer_arm] — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1] or [3]."
//
// Spec semantics
//   §[timer_arm] [1] is packed as
//     bits  0-15: caps     — caps on the returned timer handle
//     bits 16-63: _reserved
//   §[timer_arm] [3] is packed as
//     bit 0:      periodic
//     bits 1-63:  _reserved
//   The kernel must surface E_INVAL whenever any bit outside the
//   defined fields is set on either argument, regardless of whether
//   the well-defined bits would otherwise have produced a valid call.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `timer` (no E_PERM gate) and a
//   restart_policy_ceiling that allows `tm_restart_max = 1` (no
//   E_PERM on caps.restart_policy). We can therefore call timer_arm
//   directly and cleanly attribute any E_INVAL response to the
//   reserved-bit check.
//
//   Three independent reserved-bit shapes are exercised, each on a
//   fresh timer_arm call. All other inputs are kept syntactically
//   valid so neither E_PERM nor the deadline_ns = 0 path can preempt
//   the reserved-bit gate:
//     - caps' well-defined bits hold {arm, cancel}
//     - deadline_ns = 1 (smallest non-zero, satisfies test 03)
//     - flags' bit 0 (periodic) is 0 unless the test sets it
//
//   Setup A: [1] has a reserved bit set (bit 16, the lowest
//            _reserved bit on caps). [3] = 0.
//   Setup B: [1] has only well-defined bits. [3] has a reserved bit
//            set (bit 1, the lowest _reserved bit on flags).
//   Setup C: both arguments carry reserved bits (bit 63 of each, to
//            cover the high end of the reserved range and prove the
//            check is not limited to the low reserved bit).
//
// Assertions (distinct ids per setup + final)
//   1: setup A (reserved bit in [1]) did not return E_INVAL.
//   2: setup B (reserved bit in [3]) did not return E_INVAL.
//   3: setup C (reserved bits in both [1] and [3]) did not return
//      E_INVAL.
//
// On all three rejections, the test passes.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[timer] TimerCap layout: arm = bit 2, cancel = bit 3. Setting
    // these so the well-defined low 16 bits of [1] would otherwise
    // describe a usable handle; only the reserved bits should
    // trigger rejection.
    const valid_timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const valid_caps_word: u64 = @as(u64, valid_timer_caps.toU16());

    // Setup A: reserved bit 16 set on [1] (lowest bit outside the
    // 16-bit caps field). Flags clean.
    const caps_with_reserved_low: u64 = valid_caps_word | (@as(u64, 1) << 16);
    const result_a = syscall.timerArm(
        caps_with_reserved_low,
        1,
        0,
    );
    if (result_a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Setup B: caps clean. Reserved bit 1 set on [3] (lowest bit
    // outside the periodic flag at bit 0).
    const flags_with_reserved_low: u64 = @as(u64, 1) << 1;
    const result_b = syscall.timerArm(
        valid_caps_word,
        1,
        flags_with_reserved_low,
    );
    if (result_b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    // Setup C: high reserved bits on both arguments to confirm the
    // check covers the full reserved range, not just the boundary
    // bits exercised in A and B.
    const caps_with_reserved_high: u64 = valid_caps_word | (@as(u64, 1) << 63);
    const flags_with_reserved_high: u64 = @as(u64, 1) << 63;
    const result_c = syscall.timerArm(
        caps_with_reserved_high,
        1,
        flags_with_reserved_high,
    );
    if (result_c.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
