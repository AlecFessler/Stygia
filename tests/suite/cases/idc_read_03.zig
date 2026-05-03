// Spec §[idc_read] idc_read — test 03.
//
// "[test 03] returns E_INVAL if [2] offset is not 8-byte aligned."
//
// Strategy
//   The check under test is the offset alignment gate: vreg 2 must be
//   a multiple of 8. To isolate it from the other E_INVAL paths in
//   idc_read, every other precondition must be satisfied:
//     - [1] must be a valid VAR handle with the `r` cap (defeats
//       tests 01 and 02),
//     - count must be in [1, 125] (defeats test 04),
//     - offset + count*8 must fit within the VAR's size (defeats
//       test 05),
//     - reserved bits in [1] and [2] must be zero (defeats test 06).
//
//   Setup:
//     1. createPageFrame(caps={r,w}, props=0, pages=1) — provides
//        backing storage so the VAR is non-empty.
//     2. createVar(caps={r,w}, props=0, pages=1) — VAR.caps has `r`
//        (defeats test 02), sz=0 (4 KiB), pages=1 → size = 4096 bytes.
//     3. mapPf(var, &.{ 0, pf }) — install the page_frame so the VAR
//        has live backing for the read path the kernel may exercise
//        before/after the alignment check (the alignment check itself
//        is purely on the offset value, but other E_INVAL gates may
//        consult mapping state).
//
//   Action:
//     idcRead(var, offset = 1, count = 1). offset = 1 is not a
//     multiple of 8, so the alignment gate must fire E_INVAL per
//     §[idc_read] test 03. count = 1 keeps test 04 inactive; with
//     offset = 1 the byte range 1..9 still fits inside the 4096-byte
//     VAR, so test 05 cannot preempt. No reserved bits are set in
//     either vreg.
//
// Assertions
//   1: vreg 1 was not E_INVAL after the idc_read call (the spec
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

    // Step 1: page_frame with caps = r|w. Provides backing for the
    // VAR so the only E_INVAL the kernel can surface in this test is
    // the offset-alignment gate.
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

    // Step 2: VAR with caps = r|w (the `r` cap defeats §[idc_read]
    // test 02). props = 0 → cur_rwx = 0, sz = 0, cch = 0. pages = 1
    // gives a 4 KiB VAR, large enough that offset = 1, count = 1
    // (byte range 1..9) does not trip §[idc_read] test 05.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0, // props: cur_rwx = 0, sz = 0 (4 KiB), cch = 0
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install the page_frame at offset 0 so the VAR has live
    // backing. The alignment gate under test is independent of map
    // state, but installing a page_frame removes any ambiguity about
    // which E_INVAL path the kernel exercises first.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mr.v1 != 0) {
        testing.fail(2);
        return;
    }

    // Step 4: idc_read with offset = 1 (not 8-byte aligned), count = 1.
    // Per §[idc_read] test 03, the kernel must return E_INVAL.
    const result = syscall.idcRead(var_handle, 1, 1);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
