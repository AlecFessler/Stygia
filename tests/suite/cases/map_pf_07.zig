// Spec §[map_pf] — test 07.
//
// "[test 07] returns E_INVAL if any pair's range exceeds the VMAR's
//  size."
//
// Strategy
//   To isolate the per-pair range-overflow check we need every other
//   rejection path that could fire ahead of test 07 to be inert. With
//   a single pair (N = 1):
//     - test 01 (VMAR is invalid) — pass a freshly-minted regular VMAR
//       handle.
//     - test 02 (page_frame handle invalid) — pass a freshly-minted
//       page_frame handle.
//     - test 03 (caps.mmio set) — caps = {r,w}, mmio = 0.
//     - test 04 (N == 0) — N = 1.
//     - test 05 (offset misaligned to VMAR sz) — VMAR sz = 0 (4 KiB), so
//       offset = 0x1000 is page-aligned.
//     - test 06 (page_frame's sz smaller than VMAR's sz) — both sz = 0.
//     - test 10 (VMAR.map ∈ {2,3}) — fresh VMAR has map = 0.
//   Tests 08 and 09 cannot fire ahead of test 07 because (a) we pass a
//   single pair (no two-pair overlap) and (b) the VMAR is freshly
//   created with map = 0 and no existing installations.
//
//   With VMAR pages = 1 and sz = 0 the VMAR's total size is 4 KiB. A
//   pair (offset = 0x1000, pf) places the installed page at byte
//   range [0x1000, 0x2000) — fully past the VMAR's end. The kernel
//   must reject with E_INVAL per §[map_pf] test 07.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — must succeed
//      so the per-pair page_frame BADCAP check (test 02) does not
//      pre-empt the range check.
//   2. createVmar(caps={r,w}, props={sz=0, cur_rwx=0b011}, pages=1) —
//      must succeed so the VMAR BADCAP check (test 01) does not fire.
//   3. mapPf(vmar_handle, &.{ 0x1000, pf_handle }) — offset 0x1000 is
//      4 KiB-aligned (test 05 inert) but the resulting range
//      [0x1000, 0x2000) extends past the VMAR's 4 KiB total size.
//      Kernel must return E_INVAL.
//
// Assertions
//   1: vreg 1 was not E_INVAL after mapPf with an out-of-range pair
//      (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a valid page_frame so the per-pair page_frame BADCAP gate
    // (test 02) cannot pre-empt the range-overflow check.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Build a regular 1-page (4 KiB) VMAR. sz = 0 keeps offset = 0x1000
    // page-aligned (test 05 inert).
    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cv = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1 → total VMAR size = 4 KiB
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // offset = 0x1000 is page-aligned but the pair's range [0x1000,
    // 0x2000) extends past the VMAR's 4 KiB end. Kernel must reject
    // with E_INVAL per §[map_pf] test 07.
    const result = syscall.mapPf(vmar_handle, &.{ 0x1000, pf_handle });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
