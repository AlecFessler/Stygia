// Spec §[create_vmar] — test 03.
//
// "[test 03] returns E_PERM if caps.max_sz exceeds the caller's
//  `vmar_inner_ceiling`'s max_sz."
//
// Faithful test rationale (and why this is a degraded smoke variant)
//   The runner (tests/suite/runner/primary.zig) mints every spec-test
//   domain with `vmar_inner_ceiling = 0x01FF`. That word covers VmarCap
//   bits 0-8 (move, copy, r, w, x, mmio, max_sz_lo, max_sz_hi, dma);
//   in particular both max_sz bits are set, so the ceiling's max_sz
//   field has the value 3.
//
//   A faithful "exceeds the ceiling's max_sz" test would set
//   caps.max_sz to a value strictly greater than the ceiling's
//   max_sz. With a 2-bit max_sz field there is no value greater than
//   3, so under the runner-provided ceiling no caps.max_sz value
//   exceeds it. Worse, max_sz = 3 is itself reserved (test 07,
//   E_INVAL), so caps.max_sz = 3 collides with a different failure
//   path and would not exercise this test's spec wording in any
//   case.
//
//   The runner ceiling is shared across the entire test manifest and
//   cannot be widened for one test, and there is currently no
//   exposed syscall that lets a child domain narrow its own
//   vmar_inner_ceiling below 3 before invoking create_vmar. Until such
//   a ceiling-restriction syscall lands, the faithful E_PERM path
//   for test 03 is unreachable from a userspace test domain.
//
//   This file lands a degraded *smoke* variant in place of the
//   faithful test: it issues a create_vmar with caps.max_sz = 2 and
//   every other gate avoided, mirroring the clean-success shape of
//   create_var_05 / create_var_07. Because caps.max_sz = 2 is below
//   the ceiling's 3, the kernel must accept the call and return a
//   VMAR handle (i.e. a non-error value); any error would indicate
//   the kernel rejected a max_sz that the ceiling permits.
//
//   When a ceiling-restriction syscall is added, this test should
//   be rewritten to: (a) narrow the calling domain's
//   vmar_inner_ceiling so its max_sz is < 2, then (b) invoke
//   create_vmar with caps.max_sz = 2 and assert E_PERM. See
//   create_var_05 for the clean-success skeleton this test borrows
//   and create_var_07 for the caps.max_sz = 3 / E_INVAL pattern.
//
// Strategy (degraded smoke variant)
//   To keep the call on the success path under the runner ceiling
//   we make every prior check pass:
//     - caller self-handle has `crvr` (test 01): the runner grants
//       it on every spawned test domain.
//     - caps.r/w/x ⊆ vmar_inner_ceiling.r/w/x (test 02): caps =
//       {r, w}, no x.
//     - caps.max_sz = 2 (1 GiB), strictly below ceiling.max_sz = 3
//       and below the reserved value 3 (test 07).
//     - caps.mmio = 0 (tests 04, 08, 11, 13).
//     - caps.dma = 0 (tests 12, 13, 14, 15, 22), so device_region
//       is unused and passed as 0.
//     - pages = 1 (test 05).
//     - preferred_base = 0 (test 06).
//     - props.sz = 0 (4 KiB), satisfying tests 09 and 10
//       (sz != 3 and 0 ≤ caps.max_sz = 2).
//     - props.cur_rwx = 0b011 ⊆ caps.{r, w} (test 16).
//     - all other bits zero (test 17).
//
// Action
//   create_vmar(caps={r, w, max_sz=2}, props={cur_rwx=0b011, sz=0,
//              cch=0}, pages=1, preferred_base=0, device_region=0)
//   must return success (vreg 1 not an error code).
//
// Assertion
//   1: create_vmar returned an error (degraded variant — kernel
//      rejected a max_sz that the runner-provided ceiling permits).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const vmar_caps = caps.VmarCap{
        .r = true,
        .w = true,
        .max_sz = 2, // 1 GiB; below ceiling's max_sz = 3, not reserved
    };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const result = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );

    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
