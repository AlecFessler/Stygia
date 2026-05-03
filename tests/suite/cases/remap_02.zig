// Spec §[remap] — test 02.
//
// "[test 02] returns E_INVAL if [1].field1 `map` is 0 or 2 (no pf or
//  demand mapping to remap)."
//
// Strategy
//   The assertion has two branches: `map = 0` (no mapping yet) and
//   `map = 2` (mmio installation). The `map = 2` branch requires a
//   successful map_mmio, which in turn requires a usable device_region —
//   not available in the v0 mock runner. The `map = 0` branch fully
//   exercises the gate under test, since the kernel reaches the same
//   E_INVAL path regardless of which non-{1,3} value `map` holds. Cover
//   the `map = 2` branch as future work once map_mmio is reachable.
//
//   §[var] specifies that a regular VAR (caps.mmio = 0, caps.dma = 0)
//   created via create_var starts at `map = 0`; the first faulted access
//   transitions it to `map = 3` (demand). A freshly minted VAR that has
//   never been touched therefore satisfies the precondition.
//
//   Calling `remap` on this VAR with new_cur_rwx = 0b011 (r|w) — a
//   subset of caps.r|w — exercises only the gate under test:
//     - test 01 (invalid VAR handle) — VAR is freshly minted, valid.
//     - test 03 (rwx not a subset of caps.r/w/x) — 0b011 ⊆ caps.r|w.
//     - test 04 (map = 1 and rwx not a subset of pf intersect) —
//       map = 0, branch not taken.
//     - test 05 (caps.dma and x bit) — caps.dma = 0, x bit clear.
//     - test 06 (reserved bits in [2]) — only bits 0..2 set.
//   That leaves test 02's `map = 0` gate as the only firing path.
//
// Action
//   1. createVar(caps={r,w}, props=0b011, pages=1) — must return a VAR
//      handle in vreg 1 (assertion 2 guards this precondition).
//   2. remap(var_handle, 0b011) — must return E_INVAL because the VAR's
//      field1 `map` is 0.
//
// Assertions
//   1: vreg 1 was not E_INVAL (the spec assertion under test).
//   2: createVar returned an error code — the success-path precondition
//      is broken so we cannot proceed to verify the remap E_INVAL path.

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

    const result = syscall.remap(var_handle, 0b011);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
