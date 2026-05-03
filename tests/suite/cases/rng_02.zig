// Spec §[rng] random — test 02.
//
// "[test 02] on success, vregs `[1..count]` contain qwords (the
//  CSPRNG-source guarantee in the prose above is a kernel
//  implementation contract, not a black-box-testable assertion)."
//
// Strategy
//   `random()` takes no caps and writes `count` qwords into vregs
//   `[1..count]`. Per spec line 2486 the syscall signature is
//   `random() -> [1..count] qwords`; vreg 1 is therefore a data slot,
//   not the conventional error slot. The §[error_codes] enumeration
//   confines error values to 1..15 (E_ABANDONED through E_TIMEOUT) —
//   so an unambiguous "the syscall did not fail" check is "v1 is not
//   in 1..15". A genuine random qword colliding with that 15-value
//   window has probability 15/2^64; treating any such collision as a
//   spurious test failure is acceptable per §[rng] test 02's own
//   parenthetical (the actual entropy quality is a kernel contract,
//   not a test concern).
//
//   The spec parenthetical explicitly disclaims any black-box check
//   on the values themselves (zeros, repeats, low-entropy patterns
//   would all be valid byte-patterns and tell us nothing about the
//   underlying CSPRNG). All this test can assert is that the call
//   succeeds and returns the syscall path that fills vregs `[1..N]`.
//
// Action
//   1. random(count = 4) — an arbitrary small valid count in 1..127.
//      Four covers enough vregs (v1..v4) to exercise the multi-vreg
//      fill path while staying inside the register-backed return
//      range (vregs 1..13 land in registers; the stack-spill path
//      kicks in beyond that).
//   2. Assert vreg 1 is not an error code per §[error_codes].
//
// Assertions
//   1: random returned an error code (1..15) in vreg 1.

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const result = syscall.random(4);

    // §[error_codes]: error codes occupy 1..15. Any value outside
    // that window in vreg 1 is a successful return whose bits are
    // the first random qword.
    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
