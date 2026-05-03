// Spec §[map_pf] — test 11.
//
// "[test 11] on success, [1].field1 `map` becomes 1 if it was 0;
//  otherwise stays 1."
//
// Strategy
//   Per §[var] line 877, a regular VAR (caps.mmio = 0, caps.dma = 0)
//   created without explicit mapping starts at `map = 0`. Per §[map_pf]
//   test 14, the VAR handle's field0 / field1 snapshot is refreshed
//   from the kernel's authoritative state on every map_pf call. So we
//   can drive the assertion using only readCap on the test's own cap
//   table, without needing an explicit `sync`.
//
//   Two-pages-of-4-KiB VAR so we can fire two non-overlapping map_pf
//   calls with offsets 0 and 0x1000 — the second call exercises the
//   "otherwise stays 1" leg without re-using the first call's range
//   (which would trip §[map_pf] test 09 for overlap with an existing
//   mapping). Two distinct page_frames keep the second pair clean of
//   the prior installation.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `map` at bits 39-40 is a 2-bit field. Mask it via
//     (field1 >> 39) & 0b11.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) twice — pf1, pf2.
//   2. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=2, preferred_base=0, device_region=0) — must
//      succeed; gives a regular VAR in `map = 0`.
//   3. readCap(self) — confirm `map` field is 0 before any map_pf.
//   4. mapPf(var_handle, &.{ 0, pf1 }) — must succeed (vreg 1 == OK).
//   5. readCap(self) — `map` field must now be 1 (0 -> 1 transition,
//      the assertion under test).
//   6. mapPf(var_handle, &.{ 0x1000, pf2 }) — must succeed; offset
//      0x1000 is non-overlapping with the prior offset-0 installation,
//      so test 09 cannot fire.
//   7. readCap(self) — `map` field must still be 1 ("otherwise stays
//      1" leg).
//
// Assertions
//   1: setup failed — createPageFrame, createVar, or one of the two
//      mapPf calls returned an error, or the freshly-created VAR's
//      field1 `map` was not 0.
//   2: after the first mapPf at offset 0, field1 `map` did not equal
//      1 — the spec's 0 -> 1 transition assertion failed.
//   3: after the second mapPf at offset 0x1000, field1 `map` did not
//      stay at 1 — the spec's "otherwise stays 1" assertion failed.

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
    // Two distinct page_frames so the second map_pf at offset 0x1000
    // doesn't re-use pf1 (and so the spec is exercised with clean
    // independent installations).
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf1 = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf1.v1)) {
        testing.fail(1);
        return;
    }
    const pf1: u64 = @as(u64, cpf1.v1 & 0xFFF);

    const cpf2 = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf2.v1)) {
        testing.fail(1);
        return;
    }
    const pf2: u64 = @as(u64, cpf2.v1 & 0xFFF);

    // Regular VAR: caps.mmio = 0, caps.dma = 0; per §[var] line 877
    // it starts at `map = 0`. Two pages so offsets 0 and 0x1000 both
    // fit inside the VAR's range.
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

    // Sanity: a fresh regular VAR must report `map = 0` per §[var]
    // line 877. createVar's success path also writes field1 to the
    // caller's slot, so readCap on the table observes the freshly
    // installed snapshot. If this is not 0, the precondition for the
    // 0 -> 1 transition assertion is broken.
    const cap_pre = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_pre.field1) != 0) {
        testing.fail(1);
        return;
    }

    // First map_pf: drives `map` from 0 to 1 (the assertion under
    // test, leg 1). Per §[map_pf] test 14, the snapshot in the
    // caller's cap table is refreshed from the kernel's authoritative
    // state as a side effect of this call.
    const r1 = syscall.mapPf(var_handle, &.{ 0, pf1 });
    if (errors.isError(r1.v1)) {
        testing.fail(1);
        return;
    }

    const cap_after_first = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_after_first.field1) != 1) {
        testing.fail(2);
        return;
    }

    // Second map_pf at a non-overlapping offset: `map` must stay at 1
    // (the assertion under test, leg 2). Offset 0x1000 is the second
    // 4 KiB page in this 2-page VAR; it does not overlap the prior
    // offset-0 installation, so §[map_pf] test 09 (overlap with an
    // existing mapping) cannot preempt the success path.
    const r2 = syscall.mapPf(var_handle, &.{ 0x1000, pf2 });
    if (errors.isError(r2.v1)) {
        testing.fail(1);
        return;
    }

    const cap_after_second = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_after_second.field1) != 1) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
