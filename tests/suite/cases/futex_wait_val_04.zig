// Spec §[futex_wait_val] futex_wait_val — test 04.
//
// "[test 04] returns E_INVAL if any addr is not 8-byte aligned."
//
// Strategy
//   The §[futex_wait_val] gate order from the spec listing:
//     test 01 — E_PERM if self-handle `fut_wait_max` = 0
//     test 02 — E_INVAL if N == 0 or N > 63
//     test 03 — E_INVAL if N exceeds caller's `fut_wait_max`
//     test 04 — E_INVAL if any addr is not 8-byte aligned
//     test 05 — E_BADADDR if any addr is not a valid user address
//   To isolate the assertion under test, every other precondition
//   must hold: caller has `fut_wait_max = 63` (set by primary), N must
//   sit in [1, 63] and not exceed `fut_wait_max`, and at least one
//   addr must not be 8-byte aligned. To prevent the E_BADADDR gate
//   (test 05) from preempting, the unaligned addr must lie inside a
//   region that is a valid user address in the caller's domain.
//
//   The simplest in-domain valid user address available to a fresh
//   test is `cap_table_base` — the read-only handle-table mapping
//   passed to `_start` per §[create_capability_domain]. It is page-
//   aligned by construction; `cap_table_base + 1` is therefore both
//   in-domain valid (same page) and not 8-byte aligned (offset 1).
//
//   Two scenarios cover the "any" wording:
//     A. N = 1, single pair whose only addr is unaligned. Direct hit
//        on the gate.
//     B. N = 2, pair 0 aligned and pair 1 unaligned. The kernel must
//        scan all pairs and reject when any one is unaligned, not
//        only when the first is.
//
//   `timeout_ns` is set to 0 (non-blocking) so even if the alignment
//   gate were somehow elided the call would not stall the runner; the
//   spec lists test 04 ahead of any blocking behavior, so the gate
//   fires before the timeout path is consulted.
//
// Action
//   1. futex_wait_val(timeout=0, pairs={(cap_table_base+1, 0)})
//      — must return E_INVAL  (assertion 1)
//   2. futex_wait_val(timeout=0, pairs={(cap_table_base, 0),
//                                       (cap_table_base+1, 0)})
//      — must return E_INVAL  (assertion 2)
//
// Assertions
//   1: single-pair unaligned addr did not return E_INVAL.
//   2: multi-pair with one unaligned addr did not return E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Case A: single (addr, expected) pair whose addr is unaligned.
    // cap_table_base is page-aligned per §[capabilities]; +1 is in
    // the same valid user mapping and not 8-byte aligned.
    const r_single = syscall.futexWaitVal(0, &.{ cap_table_base + 1, 0 });
    if (r_single.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case B: two pairs, the first aligned, the second unaligned. The
    // gate must reject when ANY addr is unaligned, not only when the
    // first is. Both addrs are in the same valid user mapping so the
    // E_BADADDR gate (test 05) cannot preempt.
    const r_multi = syscall.futexWaitVal(0, &.{
        cap_table_base,     0,
        cap_table_base + 1, 0,
    });
    if (r_multi.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
