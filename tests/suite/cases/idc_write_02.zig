// Spec §[idc_write] — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `w` cap."
//
// Strategy
//   To isolate the missing-`w` cap gate we must satisfy every other
//   idc_write precondition:
//     - test 01 (invalid VMAR handle) — pass a freshly-minted VMAR.
//     - test 03 (offset not 8-byte aligned) — use offset = 0.
//     - test 04 (count 0 or > 125) — use count = 1 (one qword).
//     - test 05 ([2] + count*8 > VMAR size) — VMAR is 1 page (4 KiB),
//       writing 8 bytes at offset 0 stays well inside.
//     - test 06 (reserved bits in [1] or [2]) — `syscall.idcWrite`
//       packs the 12-bit handle id into the low bits of the syscall
//       word; offset 0 has no reserved bits set.
//
//   That leaves the missing `w` cap as the only spec-mandated failure
//   path. We mint the VMAR with caps = { r } only — no w — which is
//   permitted by §[create_vmar]:
//     - test 02 (caps.r/w/x ⊆ vmar_inner_ceiling.r/w/x): { r } is a
//       subset of the root domain's ceiling, which serial.zig minted
//       with r|w (and any superset including r).
//     - test 16 (props.cur_rwx ⊆ caps.r/w/x): set cur_rwx = 0b001
//       (r only) which matches caps.r with no w/x set.
//   All remaining create_vmar gates are neutralised by the standard
//   prelude shared with idc_read_02 (mmio = 0, dma = 0, max_sz = 0,
//   sz = 0, cch = 0, pages = 1, preferred_base = 0, device_region = 0).
//
// Action
//   1. createVmar(caps={r}, props={cur_rwx=0b001, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0)
//      → VMAR handle whose caps lack `w`.
//   2. idcWrite(var, offset=0, qwords=&.{0}) — must return E_PERM
//      because [1] does not have the `w` cap.
//
// Assertion
//   1: idcWrite did not return E_PERM when [1] lacked the `w` cap
//      (also covers the precondition path: if createVmar itself
//      errored, the assertion id 1 surfaces just the same).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // VMAR caps with `r` only — no `w`. This is the cap configuration
    // under test for idc_write's `w` requirement.
    const vmar_caps = caps.VmarCap{ .r = true };
    const props: u64 = 0b001; // cur_rwx = r only; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1 (defeats idc_write test 05; 4 KiB > 8 bytes)
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        // Precondition broke: cannot exercise idc_write's w-cap gate
        // without a valid VMAR. Surface as the spec assertion.
        testing.fail(1);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // idc_write with offset=0 (aligned, defeats test 03), count=1
    // (defeats test 04, and 8 bytes < 4 KiB defeats test 05).
    // Reserved bits in the syscall words are zero by construction.
    // The only remaining failure path is the missing `w` cap.
    const payload = [_]u64{0};
    const result = syscall.idcWrite(vmar_handle, 0, &payload);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
