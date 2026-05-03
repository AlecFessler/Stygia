// Spec §[futex_wait_val] — test 02.
//
// "[test 02] returns E_INVAL if N is 0 or N > 63."
//
// Strategy
//   N is encoded in syscall-word bits 12-19 (per §[futex_wait_val]:
//   "syscall word bits 12-19: N (1..63)"). The kernel must reject both
//   boundary violations: N == 0 and N > 63.
//
//   The §[futex_wait_val] gate order is:
//     test 01 — caller self-handle `fut_wait_max == 0` -> E_PERM
//     test 02 — N == 0 or N > 63                       -> E_INVAL
//     test 03 — N > caller's `fut_wait_max`            -> E_INVAL
//     test 04 — addr not 8-byte aligned                -> E_INVAL
//     test 05 — addr not a valid user address          -> E_BADADDR
//   The N-range check fires before any address is decoded, so we do
//   not need a valid backing var or any pair payload to reach it.
//
//   N == 0:
//     The libz wrapper `syscall.futexWaitVal` derives N from
//     `pairs.len / 2`; passing an empty slice issues the syscall with
//     bits 12-19 = 0. No vreg payload is read.
//
//   N == 64 (boundary just above the spec maximum of 63):
//     We cannot drive the wrapper at N == 64 — it would attempt to
//     spill 116 qwords through `issueStack`, whose bounded 16-slot pad
//     would panic at runtime. Instead bypass the wrapper via
//     `syscall.issueReg` with `extraCount(64)` so the count reaches
//     the kernel verbatim. The N > 63 gate fires before any pair is
//     decoded, so omitting the per-vreg payload is sound.
//
// Action
//   1. futexWaitVal(timeout=0, &.{})              — N == 0,  must return E_INVAL  (id 1)
//   2. issueReg(.futex_wait_val, count=64, .{v1=0}) — N == 64, must return E_INVAL  (id 2)
//
// Assertions
//   1: N == 0 path did not return E_INVAL.
//   2: N == 64 path did not return E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. N == 0 must return E_INVAL.
    const r_zero = syscall.futexWaitVal(0, &.{});
    if (r_zero.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // 2. N == 64 (> 63) must return E_INVAL. Bypass the libz wrapper
    // since it would attempt to spill 116 qwords through issueStack
    // and panic against the bounded 16-slot pad. The kernel's N gate
    // fires before any pair vreg is touched.
    const r_over = syscall.issueReg(.futex_wait_val, syscall.extraCount(64), .{
        .v1 = 0,
    });
    if (r_over.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
