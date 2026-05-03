// Spec §[create_execution_context] create_execution_context — test 10.
//
// "[test 10] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] caps word layout (§[create_execution_context]):
//     bits  0-15: caps
//     bits 16-31: target_caps
//     bits 32-33: priority
//     bits 34-63: _reserved
//   Setting any bit in 34-63 is a spec violation that must surface
//   E_INVAL.
//
//   To isolate the reserved-bit check we must make every other check
//   pass:
//     - the caller's self-handle must have `crec` (test 01). The
//       primary's child setup grants `crec` so this holds.
//     - target = 0 (self) eliminates tests 02, 04, 05, 07 (they all
//       gate on [4] != 0).
//     - caps must be a subset of self's `ec_inner_ceiling` (test 03).
//       Pass caps = 0 — the empty set is a subset of any ceiling.
//     - priority (bits 32-33) must not exceed caller's priority
//       ceiling (test 06). Use priority = 0; the primary grants the
//       child `pri = 3`, so 0 is in range.
//     - stack_pages must be > 0 (test 08). Use 1.
//     - affinity must only have bits set for cores the system has
//       (test 09). Use 1 (bit 0 / core 0); the system always boots
//       at least one core.
//   That leaves the reserved-bit check (test 10) as the only
//   spec-mandated failure path.
//
//   The libz `createExecutionContext` wrapper takes the caps word as
//   a u64, so setting a high reserved bit flows through without
//   being truncated.
//
// Action
//   create_execution_context(
//       caps          = 1 << 34,   // reserved bit 34 of [1] set;
//                                  // bits 0-33 (caps/target_caps/priority) all clear
//       entry         = &dummyEntry,
//       stack_pages   = 1,
//       target        = 0,         // self
//       affinity_mask = 1,         // core 0 only
//   )
//   must return E_INVAL.
//
// Assertions
//   1: create_execution_context with reserved bit 34 of [1] returned
//      something other than E_INVAL

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const reserved_bit: u64 = @as(u64, 1) << 34;
    const result = syscall.createExecutionContext(
        reserved_bit,
        @intFromPtr(&testing.dummyEntry),
        1,
        0,
        1,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
