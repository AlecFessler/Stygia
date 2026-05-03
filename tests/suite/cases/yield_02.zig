// Spec §[yield] yield — test 02.
//
// "[test 02] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] target word carries either zero (yield to scheduler) or a
//   12-bit EC handle id in bits 0-11; bits 12-63 are _reserved. Setting
//   any bit outside the defined field is a spec violation that must
//   surface E_INVAL.
//
//   To isolate the reserved-bit check we make every other check pass:
//     - bits 0-11 carry a valid EC handle id so the E_BADCAP path
//       (test 01) cannot fire even if the kernel checks handle validity
//       before the reserved-bit guard.
//   That leaves the reserved-bit check as the only spec-mandated
//   failure path.
//
//   The runner populates the child's cap table with slot 1 = the
//   initial EC (the test EC itself). It is always a valid EC handle.
//
//   The libz `syscall.yieldEc` wrapper takes `target: u64`, so we can
//   stuff bit 12 directly through the typed wrapper without bypassing
//   it.
//
// Action
//   yield(target = SLOT_INITIAL_EC | (1 << 12)) — must return E_INVAL.
//
// Assertion
//   1: yield with reserved bit 12 of [1] returned something other than
//      E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const target_with_reserved: u64 =
        @as(u64, caps.SLOT_INITIAL_EC) | (@as(u64, 1) << 12);

    const result = syscall.yieldEc(target_with_reserved);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
