// Spec §[unmap] — test 02.
//
// "[test 02] returns E_INVAL if [1].field1 `map` is 0 (nothing to unmap)."
//
// Strategy
//   To isolate the `map == 0` check we need [1] to be a valid VMAR handle
//   so the §[unmap] test 01 BADCAP gate clears, but the VMAR's `map` field
//   must still be 0 so the §[unmap] test 02 E_INVAL path fires.
//
//   §[var] specifies that a regular VMAR (caps.mmio = 0, caps.dma = 0)
//   created without explicit mapping starts at `map = 0` — the first
//   faulted access transitions it to `map = 3` (demand). A VMAR that has
//   just been minted by `create_vmar` and never accessed therefore
//   satisfies the precondition.
//
//   Calling `unmap` with N = 0 (empty selectors slice, "unmap
//   everything") on this fresh VMAR exercises only the gate under test:
//     - test 01 (invalid VMAR handle) — VMAR is freshly minted, valid.
//     - test 03 (map == 2 and N > 0) — N = 0, and map = 0 anyway.
//     - tests 04-07 (per-selector validation) — N = 0, no selectors to
//       validate.
//   That leaves test 02's `map == 0` gate as the only firing path.
//
// Action
//   1. createVmar(caps={r,w}, props=0b011, pages=1) — must return a VMAR
//      handle in vreg 1 (assertion 2 guards this precondition).
//   2. unmap(vmar_handle, &.{}) — must return E_INVAL because the VMAR's
//      field1 `map` is 0.
//
// Assertions
//   1: vreg 1 was not E_INVAL (the spec assertion under test).
//   2: createVmar returned an error code — the success-path precondition
//      is broken so we cannot proceed to verify the unmap E_INVAL path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(2);
        return;
    }

    const vmar_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    const result = syscall.unmap(vmar_handle, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
