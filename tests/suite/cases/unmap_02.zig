// Spec §[unmap] — test 02.
//
// "[test 02] returns E_INVAL if [1].field1 `map` is 0 (nothing to unmap)."
//
// Strategy
//   To isolate the `map == 0` check we need [1] to be a valid VAR handle
//   so the §[unmap] test 01 BADCAP gate clears, but the VAR's `map` field
//   must still be 0 so the §[unmap] test 02 E_INVAL path fires.
//
//   §[var] specifies that a regular VAR (caps.mmio = 0, caps.dma = 0)
//   created without explicit mapping starts at `map = 0` — the first
//   faulted access transitions it to `map = 3` (demand). A VAR that has
//   just been minted by `create_var` and never accessed therefore
//   satisfies the precondition.
//
//   Calling `unmap` with N = 0 (empty selectors slice, "unmap
//   everything") on this fresh VAR exercises only the gate under test:
//     - test 01 (invalid VAR handle) — VAR is freshly minted, valid.
//     - test 03 (map == 2 and N > 0) — N = 0, and map = 0 anyway.
//     - tests 04-07 (per-selector validation) — N = 0, no selectors to
//       validate.
//   That leaves test 02's `map == 0` gate as the only firing path.
//
// Action
//   1. createVar(caps={r,w}, props=0b011, pages=1) — must return a VAR
//      handle in vreg 1 (assertion 2 guards this precondition).
//   2. unmap(var_handle, &.{}) — must return E_INVAL because the VAR's
//      field1 `map` is 0.
//
// Assertions
//   1: vreg 1 was not E_INVAL (the spec assertion under test).
//   2: createVar returned an error code — the success-path precondition
//      is broken so we cannot proceed to verify the unmap E_INVAL path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

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
        testing.fail(2);
        return;
    }

    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    const result = syscall.unmap(var_handle, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
