// Spec §[futex_wake] — test 04.
//
// "[test 04] on success, [1] is the number of ECs actually woken
//  (0..count)."
//
// Spec semantics
//   §[futex_wake]: "Wakes up to `count` ECs blocked in `futex_wait_val`
//   or `futex_wait_change` on the given address." The success
//   post-condition asserts that vreg [1] reports the exact number of
//   ECs actually woken, capped by the `count` argument and bounded
//   below by 0 when no ECs are parked on the address.
//
// Strategy
//   The non-trivial branch (woken == k for k > 0) requires a sibling
//   EC that has already entered `futex_wait_val` on the wake address
//   before this caller issues `futex_wake`. The current test runner
//   spawns each test as a single capability domain whose initial EC
//   executes `main`; arranging a parked sibling without racing its
//   wait-entry against this caller's wake requires futex_wait_val
//   plumbing the runner does not yet expose to a test.
//
//   SMOKE-DEGRADE: assert the lower endpoint of the spec's `0..count`
//   range — that `futex_wake` on a valid 8-byte-aligned user address
//   with no ECs parked on it returns success with `[1] = 0`. This is
//   sufficient to catch a kernel that returns a non-zero count, an
//   error word, or any non-zero value in vreg [1] when the wake had
//   no waiters to drain. The non-zero endpoint of the range will be
//   covered once the runner gains a way to spawn a parked sibling EC
//   (or this test is rewritten on top of `bind_event_route` / `recv`
//   to synchronize a parked sibling deterministically).
//
//   Choice of address: `cap_table_base` is the read-only handle-table
//   mapping (§[capabilities]) the kernel installs in every domain. It
//   is page-aligned (well above 8-byte aligned) and is a valid user
//   address in the caller's domain, so it satisfies test 02
//   (alignment) and test 03 (E_BADADDR) as inert prerequisites for
//   reaching this success path. The runner mints children with
//   `fut_wake = true` (see runner/primary.zig), so test 01 (E_PERM)
//   is also inert.
//
// Action
//   1. futex_wake(addr=cap_table_base, count=1) — must return OK
//      with [1] = 0.
//
// Assertions
//   1: futex_wake returned non-OK (vreg 1 carried an E_* code rather
//      than the woken count).
//   2: futex_wake returned a non-zero woken count even though no EC
//      was parked on the address.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[futex_wake] [1] addr: 8-byte-aligned user address in the
    // caller's domain. The handle-table base is page-aligned and
    // mapped into the caller's domain, so it satisfies both.
    const addr: u64 = cap_table_base;
    const count: u64 = 1;

    const result = syscall.futexWake(addr, count);

    // The kernel signals errors by placing an E_* code in vreg 1
    // (1..15 per §[error_codes]). A successful wake places the woken
    // count in vreg 1; for our no-parked-EC scenario that count must
    // be 0.
    if (errors.isError(result.v1)) {
        testing.fail(1);
        return;
    }

    if (result.v1 != 0) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
