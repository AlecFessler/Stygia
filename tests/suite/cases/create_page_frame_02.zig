// Spec §[create_page_frame] — test 02.
//
// "[test 02] returns E_PERM if caps' r/w/x bits are not a subset of
//  the caller's `pf_ceiling.max_rwx`."
//
// Faithful test rationale (and why this is a degraded smoke variant)
//   The runner (tests/suite/runner/primary.zig) mints every spec-test
//   domain with `ceilings_inner = 0x001C_011F_3F01_FFFF`. Bits 32-39
//   of that word are the `pf_ceiling` byte, which carries the value
//   0x1F: bits 0-2 = max_rwx (r|w|x all permitted), bits 3-4 = max_sz
//   (= 3). See §[capability_domain] field0 and §[create_capability_domain]
//   [2] bits 32-34/35-36 for the ceiling layout.
//
//   A faithful "caps' r/w/x not a subset of pf_ceiling.max_rwx" test
//   would set at least one of caps.r / caps.w / caps.x while the
//   corresponding bit in pf_ceiling.max_rwx is clear. The runner's
//   pf_ceiling.max_rwx already permits all three bits, so under the
//   runner-provided ceiling no choice of caps.{r, w, x} can violate
//   the subset relation: the kernel must accept every combination.
//
//   The runner ceiling is shared across the entire test manifest and
//   cannot be narrowed for one test, and there is currently no
//   exposed syscall that lets a child domain restrict its own
//   pf_ceiling.max_rwx below 0b111 before invoking create_page_frame.
//   Until such a ceiling-restriction syscall lands, the faithful
//   E_PERM path for test 02 is unreachable from a userspace test
//   domain. This mirrors create_var_03's degraded-smoke rationale
//   for the var_inner_ceiling.max_sz analogue.
//
//   This file lands a degraded *smoke* variant in place of the
//   faithful test: it issues a create_page_frame with caps.r/w/x =
//   0b111 (the maximal r|w|x set), which is exactly equal to the
//   ceiling's max_rwx and therefore a subset of it. The kernel must
//   accept the call and return a page_frame handle; any error would
//   indicate the kernel rejected an r/w/x combination that the
//   runner ceiling permits.
//
//   When a ceiling-restriction syscall is added, this test should be
//   rewritten to: (a) narrow the calling domain's pf_ceiling.max_rwx
//   so at least one of r/w/x is clear, then (b) invoke
//   create_page_frame with that bit set and assert E_PERM.
//
// Strategy (degraded smoke variant)
//   To keep the call on the success path under the runner ceiling we
//   make every prior check pass:
//     - caller self-handle has `crpf` (test 01): the runner grants
//       it on every spawned test domain.
//     - caps.r/w/x = 0b111, which is ⊆ pf_ceiling.max_rwx = 0b111
//       (this test's gate).
//     - caps.max_sz = 0 (4 KiB), within pf_ceiling.max_sz = 3 and
//       not the reserved value (tests 03, 05).
//     - props.sz = 0 (4 KiB), satisfying tests 06 (sz != 3) and 07
//       (props.sz <= caps.max_sz).
//     - pages = 1 (test 04).
//     - all reserved bits zero (test 08).
//
// Action
//   create_page_frame(caps={r, w, x, max_sz=0}, props={sz=0},
//                     pages=1) must return success (vreg 1 not an
//                     error code).
//
// Assertion
//   1: create_page_frame returned an error (degraded variant —
//      kernel rejected an r/w/x combination that the runner-provided
//      ceiling permits).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const pf_caps = caps.PfCap{
        .r = true,
        .w = true,
        .x = true,
        .max_sz = 0, // 4 KiB; within ceiling's max_sz = 3, not reserved
    };
    const props: u64 = 0; // sz = 0 (4 KiB)

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        props,
        1, // pages
    );

    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
