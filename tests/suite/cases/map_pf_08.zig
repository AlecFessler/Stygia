// Spec §[map_pf] — test 08.
//
// "[test 08] returns E_INVAL if any two pairs' ranges overlap."
//
// Strategy
//   To isolate the intra-call overlap rejection we need every earlier
//   gate in §[map_pf] to be inert:
//     - test 01 (invalid VAR)         — pass a freshly-minted VAR.
//     - test 02 (invalid page_frame)  — every pair carries a real pf.
//     - test 03 (caps.mmio = 1)       — VAR caps = {r,w}, mmio = 0.
//     - test 04 (N == 0)              — N = 2.
//     - test 05 (offset misaligned)   — both offsets = 0, aligned to
//                                       any sz.
//     - test 06 (pf.sz < VAR.sz)      — both share sz = 0 (4 KiB).
//     - test 07 (range exceeds VAR)   — VAR pages = 2 (8 KiB) and each
//                                       pf pages = 2 (8 KiB). A pair at
//                                       offset 0 covers exactly [0,
//                                       8 KiB), which fits.
//     - test 09 (overlaps existing)   — fresh VAR has map = 0 with no
//                                       prior installations; only the
//                                       in-call overlap can fire.
//     - test 10 (map ∈ {2,3})         — fresh VAR has map = 0.
//
//   With VAR.size = 8 KiB and each pf covering 8 KiB, two pairs both
//   at offset 0 produce ranges [0, 8 KiB) and [0, 8 KiB) — identical,
//   so they overlap. Per §[map_pf] test 08 the kernel must return
//   E_INVAL.
//
//   Two distinct page_frame handles are used so the rejection cannot
//   be ascribed to anything other than range overlap (a hypothetical
//   "duplicate pf" check is not in the spec, but staying clear of it
//   keeps the signal unambiguous).
//
// Action
//   1. createPageFrame(caps={r,w}, props={sz=0}, pages=2) twice — both
//      must succeed.
//   2. createVar(caps={r,w}, props={sz=0, cur_rwx=0b011}, pages=2)
//      — must succeed.
//   3. mapPf(var, &.{ 0, pf_a, 0, pf_b }) — must return E_INVAL.
//
// Assertions
//   1: vreg 1 was not E_INVAL after mapPf with overlapping pairs (the
//      spec assertion under test).
//   2: a setup syscall (createPageFrame or createVar) returned an
//      error code, breaking the success-path precondition so we
//      cannot proceed to verify the map_pf overlap path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const pf_caps = caps.PfCap{ .r = true, .w = true };

    const cpf_a = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        2, // pages = 2 → 8 KiB page frame
    );
    if (testing.isHandleError(cpf_a.v1)) {
        testing.fail(2);
        return;
    }
    const pf_a: u64 = @as(u64, cpf_a.v1 & 0xFFF);

    const cpf_b = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        2,
    );
    if (testing.isHandleError(cpf_b.v1)) {
        testing.fail(2);
        return;
    }
    const pf_b: u64 = @as(u64, cpf_b.v1 & 0xFFF);

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        2, // pages = 2 → 8 KiB VAR
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // Two pairs, both at offset 0 with distinct 8-KiB page_frames.
    // Each pair's range is [0, 8 KiB); the ranges are identical and
    // therefore overlap.
    const result = syscall.mapPf(var_handle, &.{ 0, pf_a, 0, pf_b });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
