// Spec §[create_page_frame] — test 03.
//
// "[test 03] returns E_PERM if caps.max_sz exceeds the caller's
//  `pf_ceiling.max_sz`."
//
// Faithful test rationale (and why this is a degraded smoke variant)
//   The runner (tests/suite/runner/primary.zig) mints every spec-test
//   domain with `ceilings_inner = 0x001C_011F_3F01_FFFF`. Bits 32-39
//   of that word are the `pf_ceiling` byte, which carries the value
//   0x1F: bits 0-2 = max_rwx (r|w|x all permitted), bits 3-4 = max_sz
//   (= 3). See §[capability_domain] field0 and §[create_capability_domain]
//   [2] bits 32-34/35-36 for the ceiling layout.
//
//   A faithful "caps.max_sz exceeds pf_ceiling.max_sz" test would
//   require caps.max_sz to be strictly greater than 3. But caps.max_sz
//   is a 2-bit field (§[page_frame] cap bits 5-6), so its maximum
//   representable value is 3 — exactly equal to pf_ceiling.max_sz
//   under the runner's ceiling. There is no encoding of caps.max_sz
//   that exceeds the runner's ceiling, so the faithful E_PERM path is
//   structurally unreachable from a userspace test domain.
//
//   The runner ceiling is shared across the entire test manifest and
//   cannot be narrowed for one test, and there is currently no
//   exposed syscall that lets a child domain restrict its own
//   pf_ceiling.max_sz below 3 before invoking create_page_frame.
//   Until such a ceiling-restriction syscall lands, the faithful
//   E_PERM path for test 03 is unreachable. This mirrors
//   create_page_frame_02's degraded-smoke rationale for the
//   pf_ceiling.max_rwx analogue.
//
//   This file lands a degraded *smoke* variant in place of the
//   faithful test: it issues a create_page_frame with caps.max_sz =
//   3 (the maximal encodable value), which is exactly equal to the
//   ceiling's max_sz and therefore satisfies the subset relation. The
//   kernel must accept the call and return a page_frame handle; any
//   error would indicate the kernel rejected a max_sz that the
//   runner ceiling permits. (Note: caps.max_sz = 3 is reserved per
//   test 05, so this smoke uses caps.max_sz = 2 — the highest
//   non-reserved value within the ceiling — to keep the call on the
//   success path.)
//
//   When a ceiling-restriction syscall is added, this test should be
//   rewritten to: (a) narrow the calling domain's pf_ceiling.max_sz
//   to a value < 3, then (b) invoke create_page_frame with
//   caps.max_sz strictly greater than the narrowed ceiling and assert
//   E_PERM.
//
// Strategy (degraded smoke variant)
//   To keep the call on the success path under the runner ceiling we
//   make every prior check pass:
//     - caller self-handle has `crpf` (test 01): the runner grants
//       it on every spawned test domain.
//     - caps.r/w/x = 0b111, which is ⊆ pf_ceiling.max_rwx = 0b111
//       (test 02).
//     - caps.max_sz = 2 (1 GiB cap), within pf_ceiling.max_sz = 3 and
//       not the reserved value 3 (this test's gate, plus test 05).
//     - props.sz = 0 (4 KiB), satisfying tests 06 (sz != 3) and 07
//       (props.sz <= caps.max_sz = 2).
//     - pages = 1 (test 04).
//     - all reserved bits zero (test 08).
//
// Action
//   create_page_frame(caps={r, w, x, max_sz=2}, props={sz=0},
//                     pages=1) must return success (vreg 1 not an
//                     error code).
//
// Assertion
//   1: create_page_frame returned an error (degraded variant —
//      kernel rejected a caps.max_sz that the runner-provided
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
        .max_sz = 2, // 1 GiB cap; within ceiling's max_sz = 3, not reserved
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
