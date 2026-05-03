// Spec §[map_pf] — test 05.
//
// "[test 05] returns E_INVAL if any offset is not aligned to the
//  VAR's `sz` page size."
//
// Strategy
//   To isolate the offset-alignment rejection in map_pf, every other
//   gate that could fire ahead of test 05 must stay inert with a
//   single (offset, page_frame) pair (N = 1):
//     - test 01 (VAR is invalid) — pass a freshly-minted regular VAR
//       handle.
//     - test 02 (page_frame is invalid) — pass a freshly-minted real
//       page_frame handle.
//     - test 03 (caps.mmio set) — caps = {r,w}, mmio = 0.
//     - test 04 (N == 0) — N = 1 (one pair).
//     - test 06 (pf.sz < VAR.sz) — both pf and VAR use sz = 0 (4 KiB),
//       so pf.sz == VAR.sz.
//     - test 07 (range exceeds VAR size) — VAR has 1 page (4 KiB) and
//       offset 0x1 is in-range (0x1 + 4 KiB <= 4 KiB is false, but the
//       range check is performed against an aligned offset which never
//       arises here because the alignment check fires first).
//       SPEC AMBIGUITY: §[map_pf] does not pin an evaluation order
//       between tests 05 and 07 when both could fire on the same input;
//       to make test 05 unambiguous we choose offset = 0x1, which is
//       1 byte and trivially in-range under any reasonable byte-range
//       semantics, while still being unaligned to 4 KiB.
//     - test 08 (overlap between pairs) — only one pair.
//     - test 09 (overlap with existing mapping) — fresh VAR has no
//       existing mappings.
//     - test 10 (VAR.map ∈ {2,3}) — fresh VAR has map = 0.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0 (sz=0), pages=1) — must
//      succeed; provides a valid pf for the pair so test 02 cannot
//      pre-empt the alignment check.
//   2. createVar(caps={r,w}, props=0b011, pages=1) — sz = 0 (4 KiB),
//      cur_rwx = r|w. Must return a valid VAR handle so test 01
//      cannot pre-empt the alignment check.
//   3. mapPf(var_handle, &.{ 0x1, pf_handle }) — offset 0x1 is 1 byte,
//      unaligned to the VAR's 4 KiB page size, so the kernel must
//      return E_INVAL per §[map_pf] test 05.
//
// Assertions
//   1: vreg 1 was not E_INVAL (the spec assertion under test).
//   2: createPageFrame returned an error code in vreg 1 — the
//      success-path precondition is broken so we cannot proceed to
//      verify the map_pf alignment path.
//   3: createVar returned an error code in vreg 1 — same precondition
//      issue.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a valid page_frame so map_pf's E_BADCAP-on-invalid-pf
    // check (test 02) cannot pre-empt the alignment rejection.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Build a regular VAR with sz = 0 (4 KiB) so that any non-4KiB
    // aligned offset trips test 05.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(3);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // offset = 0x1 (1 byte) — unaligned to the VAR's 4 KiB page size.
    const result = syscall.mapPf(var_handle, &.{ 0x1, pf_handle });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
