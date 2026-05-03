// Spec §[futex_wait_val] futex_wait_val — test 06.
//
// "[test 06] returns E_TIMEOUT if the timeout expires before any pair's
//  `addr != expected` condition is met and before any watched address
//  is woken."
//
// Strategy
//   futex_wait_val blocks while every `(addr, expected)` pair satisfies
//   `*addr == expected`. To exercise the timeout path we have to:
//     1. Hand the syscall a single watched address whose current value
//        equals its expected value (so the entry-time fast path of
//        test 07, which fires when any `*addr != expected`, does not
//        apply — the call must actually block).
//     2. Refrain from issuing any `futex_wake` on that address (so the
//        wake path of test 08 does not fire).
//     3. Pass a finite, positive timeout (timeout_ns = 0 is the spec's
//        non-blocking poll, and u64::MAX is "indefinite"; neither lets
//        the timeout actually expire).
//
//   A stack-resident `u64` is naturally 8-byte aligned on x86-64 and
//   sits in the caller's user address space (the loader maps the
//   capability domain's stack as user-RW), so it satisfies the addr
//   alignment (test 04) and addr-validity (test 05) preconditions.
//
//   We seed the watched word with value 0 and pass expected = 0, so
//   `*addr == expected` is true at entry and stays true for the whole
//   call (no other EC ever writes to it). With no other EC issuing a
//   futex_wake on this address either, the only remaining return path
//   the spec defines is the timeout one.
//
//   We pick a 10-millisecond timeout (10_000_000 ns): comfortably above
//   any reasonable scheduling jitter on a TCG/KVM test host yet small
//   enough not to materially extend the suite runtime if many wait-val
//   tests trigger this path. This matches the analogous
//   futex_wait_change test 06.
//
//   N = 1 keeps the call within the register-passed argument fast path
//   (pairs.len = 2 fits in v2/v3 of `futexWaitVal`), and stays well
//   under the child capability domain's `fut_wait_max = 63` (see
//   runner/primary.zig). The self-handle's `fut_wait_max >= 1`
//   precondition (test 01) and the N <= fut_wait_max precondition
//   (test 03) are therefore both satisfied; N = 1 also satisfies the
//   `1..63` range (test 02).
//
// Action
//   1. Allocate a stack-local `var watched: u64 = 0`.
//   2. futex_wait_val(timeout_ns = 10_000_000,
//                     pairs = { &watched, expected = 0 }).
//   3. Assert vreg 1 == E_TIMEOUT.
//
// Assertions
//   1: futex_wait_val did not return E_TIMEOUT (vreg 1 mismatch).

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Naturally 8-byte aligned in this domain's user stack; satisfies
    // the alignment (test 04) and addr-validity (test 05) preconditions.
    var watched: u64 = 0;

    // expected == *watched so the entry-time fast path (test 07) does
    // not fire and the call has to block.
    const pairs = [_]u64{ @intFromPtr(&watched), 0 };
    const timeout_ns: u64 = 10_000_000; // 10 ms

    const result = syscall.futexWaitVal(timeout_ns, &pairs);

    if (result.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
