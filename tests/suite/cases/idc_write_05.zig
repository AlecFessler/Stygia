// Spec §[idc_write] — test 05.
//
// "[test 05] returns E_INVAL if [2] + count*8 exceeds the VMAR's size."
//
// Strategy
//   The size-bound gate compares `[2] offset + count * 8` against the
//   VMAR's byte size (`page_count * sz`). Earlier §[idc_write] gates must
//   all clear so the size check is what fires:
//     - test 01 (E_BADCAP): [1] is a real VMAR handle from create_vmar.
//     - test 02 (E_PERM):   [1] carries the `w` cap.
//     - test 03 (E_INVAL):  [2] is 8-byte aligned (0xFF8 = 4088).
//     - test 04 (E_INVAL):  count = 2 satisfies 1 <= count <= 125.
//     - test 06 (E_INVAL):  no reserved bits set in [1] or [2].
//
//   With those clear, choose a VMAR of exactly 4 KiB (pages = 1, sz = 0)
//   and offset 0xFF8 with count = 2. Then 0xFF8 + 2 * 8 = 0x1008 exceeds
//   0x1000 (the VMAR's size) by 8 bytes — the minimum overrun that still
//   keeps offset 8-byte aligned and count in range.
//
//   We mapPf a backing page_frame at offset 0 first so the VMAR is in
//   `map = 1` rather than `map = 0`. The size-bound check is independent
//   of `map`, but installing a backing keeps the VMAR in a "normal,
//   writable" shape and matches the debugger-style use of idc_write.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backing for the
//      mapPf; must succeed.
//   2. createVmar(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0}, pages=1,
//                preferred_base=0, device_region=0) — must succeed; gives
//      a 4 KiB VMAR with caps.w = 1.
//   3. mapPf(var, &.{ 0, pf }) — must succeed; installs the backing at
//      offset 0.
//   4. idcWrite(var, 0xFF8, &.{ 0xDEADBEEF, 0xCAFEBABE }) — must return
//      E_INVAL because 0xFF8 + 2 * 8 = 0x1008 > 0x1000 (the VMAR's byte
//      size).
//
// Assertions
//   1: vreg 1 was not E_INVAL after the idc_write call (the spec
//      assertion under test).
//   2: a setup syscall (createPageFrame, createVmar, or mapPf) returned
//      an error — the precondition for the assertion is broken so we
//      cannot proceed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: real page_frame for the install. caps={r,w} matches the
    // VMAR's cur_rwx so the mapping is permitted.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
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

    // Step 2: regular VMAR, exactly one 4 KiB page. caps.w is required
    // for the §[idc_write] perm gate (test 02); caps.r lets the same
    // VMAR receive a readable page_frame mapping in step 3 without
    // tripping a perm mismatch on cur_rwx.
    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1 → byte size = 0x1000
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install the page_frame at offset 0. The VMAR's `map`
    // transitions 0 -> 1; the size-bound idc_write gate is independent
    // of map, but a backed VMAR is the ordinary debugger-write shape.
    const mr = syscall.mapPf(vmar_handle, &.{ 0, pf_handle });
    if (errors.isError(mr.v1)) {
        testing.fail(2);
        return;
    }

    // Step 4: idc_write at offset 0xFF8, count = 2. 0xFF8 is 8-byte
    // aligned (test 03 clear) and count = 2 is in [1, 125] (test 04
    // clear). The write range is [0xFF8, 0x1008) — 0x1008 exceeds the
    // VMAR's 0x1000-byte size by 8, which §[idc_write] test 05 demands
    // surfaces as E_INVAL.
    const result = syscall.idcWrite(vmar_handle, 0xFF8, &.{ 0xDEADBEEF, 0xCAFEBABE });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
