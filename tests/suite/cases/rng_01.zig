// Spec §[rng] random — test 01.
//
// "[test 01] returns E_INVAL if count is 0 or count > 127."
//
// Strategy
//   §[rng] random has no cap requirement and no operand handles — its
//   only inputs are the `count` field (syscall word bits 12-19) and
//   the per-vreg outputs. The spec pins the legal range as 1..127,
//   so the two boundary values that violate it are count == 0 and
//   count == 128. Both must surface E_INVAL.
//
//   The libz wrapper `syscall.random(count)` packs count via
//   `extraCount` into bits 12-19 verbatim, so passing 0 / 128 from
//   the test exercises the kernel's range check directly.
//
// Action
//   1. random(0)   — count == 0,   must return E_INVAL  (id 1)
//   2. random(128) — count > 127, must return E_INVAL   (id 2)
//
// Assertions
//   1: count == 0 path did not return E_INVAL.
//   2: count == 128 path did not return E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // count == 0 must return E_INVAL.
    const r_zero = syscall.random(0);
    if (r_zero.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // count == 128 (> 127) must return E_INVAL.
    const r_over = syscall.random(128);
    if (r_over.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
