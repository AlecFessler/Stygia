// Spec §[futex_wait_change] futex_wait_change — test 02.
//
// "[test 02] returns E_INVAL if N is 0 or N > 63."
//
// Strategy
//   §[futex_wait_change] encodes N (the number of (addr, target) pairs)
//   in bits 12-19 of the syscall word and requires 1 <= N <= 63. Either
//   bound violation must surface E_INVAL at the syscall ABI layer
//   regardless of whether the rest of the call would otherwise have
//   succeeded.
//
//   Test 01 (E_PERM if `fut_wait_max = 0` on the self-handle) is
//   neutralized because the runner-supplied self-handle for every
//   spawned test domain has `fut_wait_max = 63` (see
//   `runner/primary.zig` ceilings_outer construction). Test 03 (N
//   exceeds `fut_wait_max`) is structurally entangled with the upper
//   bound of test 02 — `fut_wait_max` is a 6-bit field capped at 63 by
//   §[capability_domain], so any N > 63 also exceeds `fut_wait_max`.
//   Both checks would fire for the N > 63 case; both return E_INVAL,
//   so the observable test-02 invariant still holds. The N = 0 case is
//   pure test 02: it cannot trip test 03 (zero never exceeds anything)
//   and the address-validation tests 04/05 are vacuously satisfied
//   when there are no addresses to check.
//
//   The libz `futexWaitChange` wrapper derives N from `pairs.len / 2`,
//   so an empty pair slice naturally produces N = 0 in the syscall
//   word. For N > 63 we bypass the wrapper via `syscall.issueReg`
//   directly with `extraCount(64)`; the kernel rejects on the bounds
//   check before reading any pair vreg, so leaving the payload zero
//   is safe.
//
// Action
//   1. futexWaitChange(timeout_ns = 0, pairs = &.{})
//      — N = 0 in syscall word bits 12-19; must return E_INVAL.
//   2. issueReg(.futex_wait_change, extraCount(64), .{ v1 = 0 })
//      — N = 64 in syscall word bits 12-19; must return E_INVAL.
//
// Assertions
//   1: N = 0 did not return E_INVAL.
//   2: N = 64 did not return E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Case A: N = 0. The libz wrapper computes N = pairs.len / 2 = 0
    // for an empty pair slice, so the syscall word's bits 12-19 are
    // zero. timeout_ns = 0 is non-blocking; the ABI bounds check fires
    // before any timeout / address handling.
    const empty_pairs: []const u64 = &.{};
    const a = syscall.futexWaitChange(0, empty_pairs);
    if (a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case B: N = 64. The libz wrapper would need 128 qwords in
    // `pairs` to express N = 64, exceeding both the register-only
    // path and the 16-slot stack pad. We bypass it via `issueReg` so
    // bits 12-19 of the syscall word carry 64 verbatim. The kernel's
    // N > 63 ABI check rejects before reading any pair vreg, so v2..
    // can stay zero.
    const b = syscall.issueReg(.futex_wait_change, syscall.extraCount(64), .{
        .v1 = 0,
    });
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
