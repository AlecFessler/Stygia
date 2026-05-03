// Spec §[unmap] — test 08.
//
// "[test 08] on success, when N is 0, all installations or
//  demand-allocated pages are removed and `map` is set to 0."
//
// Strategy
//   Build a regular VAR (caps.mmio = 0, caps.dma = 0) starting at
//   `map = 0` per §[var] line 877, then drive it to `map = 1` via a
//   single map_pf installation. Per §[map_pf] test 14, the VAR
//   handle's field0/field1 snapshot is refreshed from the kernel's
//   authoritative state on every map_pf call, so a readCap right
//   after mapPf observes `map = 1` without needing an explicit sync.
//
//   Then issue `unmap(var, &.{})` with an empty selector list, which
//   per §[unmap] (syscall word bits 12-19: N = 0) means "unmap
//   everything". Per §[unmap] test 12, field0/field1 are refreshed
//   on every unmap regardless of result, so a follow-up readCap
//   observes the post-unmap snapshot directly.
//
//   This drives only the `map = 1 -> 0` leg; the `map = 2 -> 0`
//   device clearing leg is covered by §[unmap] test 09 in a
//   separate test file.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `map` is a 2-bit field at bits 39-40; mask via
//     (field1 >> 39) & 0b11.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — pf.
//   2. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=2, preferred_base=0, device_region=0) — must
//      succeed; gives a regular VAR in `map = 0`.
//   3. mapPf(var, &.{ 0, pf }) — must succeed, drives `map = 1`.
//   4. readCap(self) — confirm `map` field is 1 before unmap.
//   5. unmap(var, &.{}) — N = 0, "unmap everything"; must succeed.
//   6. readCap(self) — `map` field must now be 0 (the assertion
//      under test).
//
// Assertions
//   1: setup failed — createPageFrame, createVar, mapPf returned an
//      error, or the post-mapPf snapshot did not show `map = 1`, or
//      the unmap call itself returned an error.
//   2: after `unmap(var, &.{})` (N = 0, unmap everything), field1
//      `map` did not equal 0 — the spec's "set to 0" assertion
//      failed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const MAP_SHIFT: u6 = 39;
const MAP_MASK: u64 = 0b11;

fn mapField(field1: u64) u64 {
    return (field1 >> MAP_SHIFT) & MAP_MASK;
}

pub fn main(cap_table_base: u64) void {
    // Single page_frame for the single map_pf installation. One page
    // is enough to drive `map = 0 -> 1`.
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

    // Regular VAR: caps.mmio = 0, caps.dma = 0; per §[var] line 877
    // it starts at `map = 0`. Two pages so the spec phrasing "all
    // installations" has more than the bare minimum to remove (the
    // assertion is "everything is gone, map = 0", and starting from
    // a multi-page VAR makes the empty-selector contract explicit).
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        2,
        0,
        0,
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Drive `map = 0 -> 1` with a single map_pf installation at
    // offset 0. Per §[map_pf] test 14, the snapshot in the cap table
    // is refreshed as a side effect of this call.
    const r_map = syscall.mapPf(var_handle, &.{ 0, pf });
    if (errors.isError(r_map.v1)) {
        testing.fail(1);
        return;
    }

    const cap_pre = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_pre.field1) != 1) {
        testing.fail(1);
        return;
    }

    // The assertion under test: with N = 0 (empty selector list,
    // syscall word bits 12-19 = 0), unmap removes "all installations
    // or demand-allocated pages" and sets `map` to 0.
    const r_unmap = syscall.unmap(var_handle, &.{});
    if (errors.isError(r_unmap.v1)) {
        testing.fail(1);
        return;
    }

    // Per §[unmap] test 12, field0/field1 are refreshed from the
    // kernel's authoritative state as a side effect of every unmap
    // call, so this readCap observes the post-unmap snapshot.
    const cap_post = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_post.field1) != 0) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
