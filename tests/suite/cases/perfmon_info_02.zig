// Spec §[perfmon_info] perfmon_info — test 02.
//
// "[test 02] [1] bits 0-7 contain the number of available PMU counters."
//
// Strategy
//   `perfmon_info` takes no inputs and returns the PMU caps_word in
//   vreg 1 and a bitmask of supported events in vreg 2. The caps_word
//   is packed as:
//     bits 0-7   num_counters    (u8)
//     bit  8     overflow_support
//     bits 9-63  _reserved
//
//   The runner spawns each test as a child capability domain whose
//   self-handle carries `pmu = true` (see `runner/primary.zig`,
//   `child_self.pmu = true`). With the cap held the E_PERM gate of
//   test 01 cannot fire, so `perfmon_info` reaches the path that
//   populates the caps_word from authoritative kernel state.
//
//   On any system the kernel is willing to expose the PMU on at all
//   (i.e. the syscall returns success rather than a no-PMU error
//   path), at least one architectural counter must be advertised —
//   a zero-counter PMU would be observationally indistinguishable
//   from a missing one, and the spec would have no use for it.
//   The faithful black-box check is therefore: on success, bits 0-7
//   of vreg 1 are nonzero.
//
// Action
//   1. perfmon_info()
//
// Assertions
//   1: perfmon_info returned an error code in vreg 1 (E_PERM and any
//      future no-PMU error live in 1..15 per §[error_codes]; a real
//      caps_word has num_counters in bits 0-7 which are within that
//      range only when num_counters is itself an error-code-shaped
//      small integer — see assertion 2 for the disambiguation).
//   2: bits 0-7 of vreg 1 are zero (no counters advertised on a
//      success path; see strategy).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const result = syscall.perfmonInfo();

    // Assertion 1: low byte (num_counters) by itself never collides with
    // an error code AND simultaneously sets any of bits 8-63. So the
    // unambiguous error-shape check is: vreg 1 is in 1..15 AND all
    // upper bits are zero. A genuine caps_word with overflow_support
    // set would have bit 8 = 1, taking it out of the error range.
    if (result.v1 != 0 and result.v1 < 16 and (result.v1 >> 8) == 0) {
        testing.fail(1);
        return;
    }

    const num_counters: u64 = result.v1 & 0xFF;
    if (num_counters == 0) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
