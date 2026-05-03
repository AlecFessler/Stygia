// Spec §[time] / §[time_setwall] time — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   `time_setwall`'s sole vreg argument is `[1] ns_since_epoch`, a
//   nanoseconds-since-Unix-epoch wall-clock value. Practical ns
//   timestamps fit comfortably below 2^63 (which encodes a wall-clock
//   moment ~292 years past the epoch — far beyond any plausible
//   real-time use). The high bit of [1] is therefore a reserved bit
//   that no well-formed call sets, and §[time_setwall] mandates
//   E_INVAL when it is set.
//
//   To isolate the reserved-bit check we make every other gate pass:
//     - the runner mints the test domain's self-handle with
//       `setwall = true` (see runner/primary.zig spawnOne), so test
//       03's E_PERM path cannot fire,
//     - bits 0-62 of [1] hold a clean ns_since_epoch value (0) so
//       there is no other malformed-input failure to compete with
//       the reserved-bit check.
//   That leaves bit 63 of [1] as the only spec-mandated failure path.
//
//   The libz `syscall.timeSetwall` wrapper takes the raw u64 verbatim
//   in vreg 1, so it can carry the dirty bit straight through to the
//   kernel without bypassing the wrapper.
//
// Action
//   1. time_setwall(1 << 63) — must return E_INVAL (reserved bit 63
//      of [1] set; bits 0-62 clean).
//
// Assertions
//   1: time_setwall with reserved bit 63 of [1] set returned
//      something other than E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const ns_with_reserved: u64 = @as(u64, 1) << 63;
    const result = syscall.timeSetwall(ns_with_reserved);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
