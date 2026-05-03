// Spec §[unmap] — test 10.
//
// "[test 10] on success, when N > 0 and `map` is 1, only the specified
//  page_frames are removed; `map` stays 1 unless every installed
//  page_frame has been removed, in which case it becomes 0."
//
// Strategy
//   Per §[var] line 877 a regular VAR (caps.mmio = 0, caps.dma = 0)
//   created without explicit mapping starts at `map = 0`. After two
//   `map_pf` calls the VAR has two installed page_frames at offsets 0
//   and 0x1000, with `map = 1` (§[map_pf] test 11). Per §[unmap]
//   test 12 the caller's field0/field1 snapshot is refreshed from the
//   kernel's authoritative state on every `unmap` call, so the
//   assertions can be driven via `readCap` on the test's own cap table.
//
//   Two-page VAR + two distinct page_frames so the first `unmap` (which
//   removes only pf_a) leaves pf_b installed and the VAR's `map` must
//   stay 1 — exercising the "only the specified page_frames are
//   removed" leg. The second `unmap` removes pf_b — the last installed
//   page_frame — and `map` must drop to 0, exercising the "every
//   installed page_frame has been removed" leg.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `map` at bits 39-40 is a 2-bit field. Mask it via
//     (field1 >> 39) & 0b11.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) twice — pf_a, pf_b.
//   2. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=2, preferred_base=0, device_region=0).
//   3. mapPf(var, &.{ 0, pf_a, 0x1000, pf_b }) — both pages installed,
//      drives `map` to 1.
//   4. unmap(var, &.{ pf_a }) — removes pf_a only; pf_b stays
//      installed. `map` must remain 1.
//   5. unmap(var, &.{ pf_b }) — removes the remaining page_frame.
//      `map` must transition to 0.
//
// Assertions
//   1: setup failed — createPageFrame, createVar, or the seeding mapPf
//      returned an error.
//   2: after unmap of pf_a (one of two installed page_frames), field1
//      `map` was not 1 — the "stays 1 while installations remain"
//      leg failed.
//   3: after unmap of pf_b (the last installed page_frame), field1
//      `map` was not 0 — the "becomes 0 when all removed" leg failed.

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
    const pf_caps = caps.PfCap{ .r = true, .w = true };

    const cpf_a = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf_a.v1)) {
        testing.fail(1);
        return;
    }
    const pf_a: u64 = @as(u64, cpf_a.v1 & 0xFFF);

    const cpf_b = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf_b.v1)) {
        testing.fail(1);
        return;
    }
    const pf_b: u64 = @as(u64, cpf_b.v1 & 0xFFF);

    // Regular VAR (caps.mmio = 0, caps.dma = 0). Two pages so the two
    // 4-KiB page_frames fit at non-overlapping offsets 0 and 0x1000.
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

    // Seed both pages in a single map_pf call (§[map_pf] supports
    // multiple (offset, page_frame) pairs). On success this puts the
    // VAR in `map = 1` with two installed page_frames.
    const r_seed = syscall.mapPf(var_handle, &.{ 0, pf_a, 0x1000, pf_b });
    if (errors.isError(r_seed.v1)) {
        testing.fail(1);
        return;
    }

    // First unmap: remove pf_a only. pf_b is still installed at offset
    // 0x1000, so per §[unmap] test 10 `map` must stay at 1. Per test
    // 12 the caller's field1 snapshot is refreshed by this call.
    const r_first = syscall.unmap(var_handle, &.{pf_a});
    if (errors.isError(r_first.v1)) {
        testing.fail(2);
        return;
    }

    const cap_after_first = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_after_first.field1) != 1) {
        testing.fail(2);
        return;
    }

    // Second unmap: remove pf_b — the last installed page_frame. Per
    // §[unmap] test 10 `map` must transition from 1 to 0.
    const r_second = syscall.unmap(var_handle, &.{pf_b});
    if (errors.isError(r_second.v1)) {
        testing.fail(3);
        return;
    }

    const cap_after_second = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_after_second.field1) != 0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
