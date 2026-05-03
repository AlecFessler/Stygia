// Spec §[perfmon_info] — test 04.
//
// "[test 04] [2] is a bitmask of supported events indexed by the table
//  above."
//
// Strategy
//   The supported_events table fixes nine event bits:
//     bit 0  cycles
//     bit 1  instructions
//     bit 2  cache_references
//     bit 3  cache_misses
//     bit 4  branch_instructions
//     bit 5  branch_misses
//     bit 6  bus_cycles
//     bit 7  stalled_cycles_frontend
//     bit 8  stalled_cycles_backend
//   Bits 9..63 of [2] are not defined by the spec; they cannot encode
//   any event in the table, so a conformant `perfmon_info` must leave
//   them clear.
//
//   The runner grants the test domain's self-handle the `pmu` cap (see
//   `runner/primary.zig`: `child_self.pmu = true`), so test 01's
//   E_PERM gate cannot fire here. perfmon_info takes no input
//   parameters, so there are no other in-bounds error paths; on a
//   conformant kernel the call returns OK in vreg 1 with caps_word in
//   vreg 2 and supported_events in vreg 3 — wait, re-reading the spec:
//   the prose says "[1] caps_word, [2] supported_events" using the
//   spec's vreg numbering (vreg 1 / vreg 2). The libz `Regs` struct
//   names match: `regs.v1` = vreg 1 = caps_word, `regs.v2` = vreg 2 =
//   supported_events. So the supported_events bitmask we want to
//   inspect is `result.v2`.
//
//   The assertion: every bit of `result.v2` outside the defined
//   range [0..8] must be zero. Equivalently, `result.v2 & ~0x1FF` is
//   zero. Any bit set in 9..63 is a direct spec violation of test 04.
//
// Degraded-smoke note
//   Spec syscall 13 (perfmon_info) is not yet wired into the kernel
//   dispatch table. Until it is, the syscall path will return either
//   E_INVAL (bad syscall_num) or zero-fill the registers, depending on
//   how the unknown-num path is handled. Either way, the bits-9..63
//   invariant trivially holds (zero & ~0x1FF == 0, and so does
//   E_INVAL's encoding in vreg 1 only — vreg 2 would still be the
//   undefined / zero default). Once perfmon_info is implemented, this
//   test continues to assert the spec invariant on real hardware
//   results.
//
// Action
//   perfmon_info() — take whatever the kernel returns.
//
// Assertion
//   1: bits 9..63 of returned supported_events bitmask are nonzero
//      (a bit outside the defined event table is set)

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const result = syscall.perfmonInfo();

    // Defined event bits: 0..8 (nine entries). Anything in 9..63 is
    // reserved-by-omission and must not appear in the bitmask.
    const defined_mask: u64 = (@as(u64, 1) << 9) - 1; // bits 0..8 set
    if ((result.v2 & ~defined_mask) != 0) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
