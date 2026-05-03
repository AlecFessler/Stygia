// Spec §[idc_read] — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `r` cap."
//
// Strategy
//   To isolate the missing-`r` cap gate we must satisfy every other
//   idc_read precondition:
//     - test 01 (invalid VAR handle) — pass a freshly-minted VAR.
//     - test 03 (offset not 8-byte aligned) — use offset = 0.
//     - test 04 (count 0 or > 125) — use count = 1.
//     - test 05 ([2] + count*8 > VAR size) — VAR is 1 page (4 KiB),
//       reading 8 bytes at offset 0 stays well inside.
//     - test 06 (reserved bits in [1] or [2]) — `syscall.idcRead`
//       packs the 12-bit handle id into the low bits of the syscall
//       word; offset 0 has no reserved bits set.
//
//   That leaves the missing `r` cap as the only spec-mandated failure
//   path. We mint the VAR with caps = { w } only — no r — which is
//   permitted by §[create_var]:
//     - test 02 (caps.r/w/x ⊆ var_inner_ceiling.r/w/x): { w } is a
//       subset of the root domain's ceiling, which serial.zig minted
//       with r|w (and any superset including w).
//     - test 16 (props.cur_rwx ⊆ caps.r/w/x): set cur_rwx = 0b010
//       (w only) which matches caps.w with no r/x set.
//   All remaining create_var gates are neutralised by the standard
//   prelude shared with create_var_05/06 (mmio = 0, dma = 0, max_sz =
//   0, sz = 0, cch = 0, pages = 1, preferred_base = 0,
//   device_region = 0).
//
// Action
//   1. createVar(caps={w}, props={cur_rwx=0b010, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0)
//      → VAR handle whose caps lack `r`.
//   2. idcRead(var, offset=0, count=1) — must return E_PERM because
//      [1] does not have the `r` cap.
//
// Assertion
//   1: idcRead did not return E_PERM when [1] lacked the `r` cap
//      (also covers the precondition path: if createVar itself
//      errored, the assertion id 1 surfaces just the same).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // VAR caps with `w` only — no `r`. This is the cap configuration
    // under test for idc_read's `r` requirement.
    const var_caps = caps.VarCap{ .w = true };
    const props: u64 = 0b010; // cur_rwx = w only; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1 (defeats create_var test 05; 4 KiB > 8 bytes)
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        // Precondition broke: cannot exercise idc_read's r-cap gate
        // without a valid VAR. Surface as the spec assertion.
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // idc_read with offset=0 (aligned, defeats test 03), count=1
    // (defeats test 04, and 8 bytes < 4 KiB defeats test 05).
    // Reserved bits in the syscall words are zero by construction.
    // The only remaining failure path is the missing `r` cap.
    const result = syscall.idcRead(var_handle, 0, 1);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
