// Spec §[remap] — test 07.
//
// "[test 07] on success, [1].field1 `cur_rwx` is set to [2] new_cur_rwx."
//
// Strategy
//   Build a regular VAR (caps={r,w}, props={cur_rwx=0b011, sz=0,
//   cch=0}, pages=1, preferred_base=0, device_region=0) so the new
//   handle starts with cur_rwx = 0b011 in field1. Per §[map_pf]
//   test 11, installing a page_frame transitions `map` from 0 to 1
//   without otherwise touching `cur_rwx`. After mapPf, snapshot the
//   handle and assert cur_rwx is still 0b011 (precondition for the
//   transition under test).
//
//   Then call remap([1] var, [2] new_cur_rwx = 0b001) — a strict
//   subset of caps.r/w/x = {r,w} = 0b011, so none of the rejection
//   paths in §[remap] tests 01-06 fire and the kernel must take the
//   success branch. The snapshotted page_frame's r/w/x caps are also
//   {r,w} = 0b011, so 0b001 is also a subset of the intersection
//   demanded by §[remap] test 04. caps.dma = 0, so test 05 cannot
//   fire either, and only bits 0-2 are set in new_cur_rwx so test 06
//   cannot fire.
//
//   Per §[remap] test 09, the handle's field0/field1 snapshot is
//   refreshed from the kernel's authoritative state as a side effect
//   of every remap call (regardless of outcome). So we can drive the
//   assertion via readCap on the test's own cap table without an
//   explicit `sync`.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `cur_rwx` at bits 36-38 is a 3-bit field; mask it via
//     (field1 >> 36) & 0b111.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — pf.
//   2. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0) — var.
//   3. mapPf(var, &.{ 0, pf }) — must succeed; transitions map to 1.
//   4. readCap(self, var) — confirm cur_rwx is still 0b011 (precondition).
//   5. remap(var, 0b001) — must return OK.
//   6. readCap(self, var) — cur_rwx must now equal 0b001 (assertion).
//
// Assertions
//   1: setup failed — createPageFrame, createVar, or mapPf returned
//      an error, or the snapshot after mapPf didn't show cur_rwx =
//      0b011 (the precondition for the transition under test).
//   2: remap returned a non-OK error code (success precondition for
//      the assertion broken).
//   3: after the success-path remap, field1 `cur_rwx` did not equal
//      the new_cur_rwx (0b001) the syscall was given — the spec
//      assertion under test failed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CUR_RWX_SHIFT: u6 = 36;
const CUR_RWX_MASK: u64 = 0b111;

const INITIAL_CUR_RWX: u64 = 0b011; // r|w
const NEW_CUR_RWX: u64 = 0b001; // r only

fn curRwxField(field1: u64) u64 {
    return (field1 >> CUR_RWX_SHIFT) & CUR_RWX_MASK;
}

pub fn main(cap_table_base: u64) void {
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf: u64 = @as(u64, cpf.v1 & 0xFFF);

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = INITIAL_CUR_RWX; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Install the page_frame so map = 1 (remap requires map ∈ {1,3} per
    // §[remap] test 02). Offset 0 fits inside the 1-page VAR.
    const r_map = syscall.mapPf(var_handle, &.{ 0, pf });
    if (errors.isError(r_map.v1)) {
        testing.fail(1);
        return;
    }

    // Precondition: after mapPf, cur_rwx must still match what we
    // passed via props on createVar. mapPf doesn't touch cur_rwx (per
    // §[var] field1 layout it only flips `map` to 1).
    const cap_pre = caps.readCap(cap_table_base, var_handle);
    if (curRwxField(cap_pre.field1) != INITIAL_CUR_RWX) {
        testing.fail(1);
        return;
    }

    // remap to a strict subset of caps.r/w/x (and of the installed
    // page_frame's r/w/x caps): 0b001 = r only. None of §[remap]
    // tests 01-06's rejection paths fire, so the kernel must succeed.
    const r_remap = syscall.remap(var_handle, NEW_CUR_RWX);
    if (errors.isError(r_remap.v1)) {
        testing.fail(2);
        return;
    }

    // Per §[remap] test 09, the handle's field1 snapshot is refreshed
    // as a side effect of remap, so readCap observes the new state
    // directly without a separate sync.
    const cap_post = caps.readCap(cap_table_base, var_handle);
    if (curRwxField(cap_post.field1) != NEW_CUR_RWX) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
