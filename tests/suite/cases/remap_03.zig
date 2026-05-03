// Spec §[remap] — test 03.
//
// "[test 03] returns E_INVAL if [2] new_cur_rwx is not a subset of
//  [1]'s caps r/w/x."
//
// Strategy
//   The check under test compares the requested `new_cur_rwx` (bits
//   0..2 of vreg 2) against the VAR handle's own r/w/x cap bits. To
//   isolate it from the other E_INVAL paths in remap, we drive the
//   VAR into a state where every other precondition is satisfied:
//     - map must be 1 or 3 so test 02 does not fire,
//     - caps.dma must be 0 so test 05 does not fire,
//     - reserved bits in [2] must be zero so test 06 does not fire,
//     - for map = 1, the requested bits must be a subset of every
//       installed page_frame's r/w/x so test 04 does not fire.
//
//   Setup:
//     1. createPageFrame(caps={r,w,x}, props=0, pages=1) — gives the
//        page_frame the full r|w|x cap surface so test 04 cannot fire
//        when we request r|w|x on the VAR.
//     2. createVar(caps={r,w}, props=0b011, pages=1) — VAR.caps has
//        only r and w; x is missing. caps.mmio = 0 and caps.dma = 0,
//        so test 05 cannot fire either. props=0b011 sets the initial
//        cur_rwx to r|w with sz=0; pf-backed VARs accept that.
//     3. mapPf(var, &.{ 0, pf }) — drives map from 0 to 1 per
//        §[map_pf] test 11, defeating test 02.
//
//   Action:
//     remap(var, new_cur_rwx = 0b111) — bit 2 (x) is requested but
//     VAR.caps.x is 0, so the kernel must surface E_INVAL per
//     §[remap] test 03. All reserved bits in vreg 2 are zero.
//
// Assertions
//   1: vreg 1 was not E_INVAL after the remap call (the spec
//      assertion under test).
//   2: a setup syscall returned an error (createPageFrame, createVar,
//      or mapPf) — the precondition for the assertion is broken so
//      we cannot proceed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page_frame with caps = r|w|x. Granting x on the
    // page_frame means §[remap] test 04 (map=1 subset-of-pf-caps) is
    // satisfied for any new_cur_rwx in {r,w,x}, so the only check
    // left to fail is the VAR-caps subset check from test 03.
    const pf_caps = caps.PfCap{ .r = true, .w = true, .x = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: VAR with caps = r|w only (no x), caps.dma = 0,
    // caps.mmio = 0. props = 0b011 → cur_rwx = r|w, sz = 0, cch = 0.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install the page_frame at offset 0. §[map_pf] test 11:
    // `map` transitions 0 -> 1 on success, defeating §[remap] test 02.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mr.v1 != 0) {
        testing.fail(2);
        return;
    }

    // Step 4: remap with new_cur_rwx = 0b111 (r|w|x). VAR.caps.x = 0,
    // so the requested bits are not a subset of [1]'s caps r/w/x —
    // §[remap] test 03 must surface E_INVAL.
    const result = syscall.remap(var_handle, 0b111);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
