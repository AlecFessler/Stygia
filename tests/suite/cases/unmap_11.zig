// Spec §[unmap] — test 11.
//
// "[test 11] on success, when N > 0 and `map` is 3, only the pages at
//  the specified offsets are freed; `map` stays 3 unless every demand-
//  allocated page has been freed, in which case it becomes 0."
//
// Strategy
//   Per §[var]: a regular VMAR (caps.mmio = 0, caps.dma = 0) starts at
//   `map = 0`; the first faulted access transitions it to `map = 3`
//   with a demand page installed at the faulting offset. Faulting at
//   a second offset on the same VMAR keeps `map = 3` and installs a
//   second demand page. Per §[unmap] test 12 the caller's
//   field0/field1 snapshot is refreshed from the kernel's authoritative
//   state on every `unmap` call, so the assertions below can be driven
//   via `readCap` on the caller's own cap table.
//
//   Two-page VMAR + two demand-fault offsets so the first `unmap`
//   (which removes only the page at offset 0) leaves the page at
//   offset 0x1000 installed and the VMAR's `map` must stay 3 —
//   exercising the "only the pages at the specified offsets are freed"
//   leg. The second `unmap` removes the last demand page and `map`
//   must drop to 0, exercising the "every demand-allocated page has
//   been freed" leg.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `map` at bits 39-40 is a 2-bit field. Mask via
//     (field1 >> 39) & 0b11.
//
// Action
//   1. createVmar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=2, preferred_base=0, device_region=0). Records
//                the chosen base in field0 (cvar.v2).
//   2. Volatile stores at VMAR.base[0] and VMAR.base[0x1000/8] (one
//      qword per page). Each fault triggers `demandAlloc`
//      (kernel/memory/vmar.zig §demandAlloc); the first transitions
//      `map` 0 -> 3, the second keeps `map = 3` and installs a second
//      demand page. After this the VMAR is in `map = 3` with two
//      demand pages installed at offsets 0 and 0x1000.
//   3. unmap(var, &.{ 0 }) — frees the page at offset 0 only; the
//      page at 0x1000 remains. `map` must stay 3.
//   4. unmap(var, &.{ 0x1000 }) — frees the last remaining demand
//      page. `map` must transition from 3 to 0.
//
// Assertions
//   1: setup failed — createVmar returned an error.
//   2: after unmap of offset 0 (one of two demand pages installed),
//      field1 `map` was not 3 — the "stays 3 while demand pages
//      remain" leg failed.
//   3: after unmap of offset 0x1000 (the last demand page), field1
//      `map` was not 0 — the "becomes 0 when all freed" leg failed.

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
    // Step 1: regular VMAR (caps.mmio = 0, caps.dma = 0). Two pages
    // so the two demand offsets at 0 and 0x1000 are both in-range.
    // cur_rwx = r|w so the demand stores below are permitted by the
    // page-fault permission check.
    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        2, // pages = 2
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const vmar_base: u64 = cvar.v2;

    // Step 2: drive `map` 0 -> 3 with two demand pages installed at
    // offsets 0 and 0x1000. The volatile stores force real memory
    // accesses; the kernel's page-fault handler runs `demandAlloc`
    // for each. After both stores the VMAR has two installed demand
    // pages and `map = 3`.
    const qword_ptr: [*]volatile u64 = @ptrFromInt(vmar_base);
    qword_ptr[0] = 0;
    // 0x1000 / 8 = 512 qwords offset for the second page's first qword.
    qword_ptr[512] = 0;

    // Step 3: unmap the demand page at offset 0; the page at 0x1000
    // remains. Per §[unmap] test 11 `map` must stay at 3. Per test
    // 12 the caller's field1 snapshot is refreshed by this call.
    const r_first = syscall.unmap(vmar_handle, &.{0});
    if (errors.isError(r_first.v1)) {
        testing.fail(2);
        return;
    }

    const cap_after_first = caps.readCap(cap_table_base, vmar_handle);
    if (mapField(cap_after_first.field1) != 3) {
        testing.fail(2);
        return;
    }

    // Step 4: unmap the remaining demand page at offset 0x1000. Per
    // §[unmap] test 11 `map` must transition from 3 to 0 once every
    // demand-allocated page has been freed.
    const r_second = syscall.unmap(vmar_handle, &.{0x1000});
    if (errors.isError(r_second.v1)) {
        testing.fail(3);
        return;
    }

    const cap_after_second = caps.readCap(cap_table_base, vmar_handle);
    if (mapField(cap_after_second.field1) != 0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
