// Spec §[unmap] — test 07.
//
// "[test 07] returns E_NOENT if [1].field1 `map` is 3 and no
//  demand-allocated page exists at any offset selector."
//
// Strategy
//   To isolate the `map = 3` not-installed gate every earlier §[unmap]
//   gate must be inert:
//     - test 01 (invalid VMAR)        — pass a freshly-minted VMAR.
//     - test 02 (map = 0)             — drive `map` to 3 via a demand
//                                       fault before issuing `unmap`.
//     - test 03 (map = 2 + N > 0)     — caps.mmio = 0, never reaches 2.
//     - tests 04, 05 (map = 1 arms)   — n/a on `map = 3`.
//     - test 06 (misaligned offset)   — selector we pass is page-
//                                       aligned (4 KiB).
//
//   Per §[var]: a regular VMAR (caps.mmio = 0, caps.dma = 0) starts at
//   `map = 0`; the first faulted access transitions it to `map = 3`
//   with a demand page installed at the faulting offset. We reserve
//   two pages (so the VMAR.base + 0x1000 selector is in-range), then
//   fault at offset 0 only — this yields `map = 3` with a single
//   demand page at offset 0, and offset 0x1000 left empty.
//
//   With those gates inert, `unmap(var, &.{ 0x1000 })` is the
//   minimum probe of test 07: 0x1000 is page-aligned (passes the
//   test 06 gate), in range (page index 1 of a 2-page VMAR), and not
//   currently demand-allocated. The kernel must return E_NOENT.
//
// Action
//   1. createVmar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=2, preferred_base=0, device_region=0). Records
//                the chosen base in field0 (cvar.v2). Two pages so
//                offset 0x1000 is a legal in-range probe.
//   2. Volatile store at VMAR.base[0] — kernel demand-faults; allocates
//      a zero-filled page at offset 0; `map` bumps from 0 to 3.
//   3. unmap(var, &.{ 0x1000 }) — page-aligned, in-range, no demand
//      page installed. Per §[unmap] test 07 must return E_NOENT.
//
// Assertions
//   1: vreg 1 was not E_NOENT after `unmap` with a missing-demand-page
//      offset on a `map = 3` VMAR (the spec assertion under test).
//   2: a setup syscall returned an error code, breaking the
//      success-path precondition.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: regular VMAR (caps.mmio = 0, caps.dma = 0). Two pages
    // so the test 07 probe at offset 0x1000 is in-range. cur_rwx =
    // r|w so the demand store below is permitted by the page-fault
    // permission check.
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
        testing.fail(2);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const vmar_base: u64 = cvar.v2;

    // Step 2: drive `map` 0 -> 3 by faulting at offset 0 only. The
    // volatile store forces a real memory access; the kernel's
    // page-fault handler runs `demandAlloc` (kernel/memory/vmar.zig
    // §demandAlloc) and installs a zero-filled page at offset 0.
    // Offset 0x1000 is left untouched: the test 07 probe expects no
    // demand page there.
    const qword_ptr: [*]volatile u64 = @ptrFromInt(vmar_base);
    qword_ptr[0] = 0;

    // Step 3: unmap at a page-aligned, in-range offset where no demand
    // page exists. 0x1000 is the second page of a 2-page VMAR; only
    // offset 0 was faulted in above. Per §[unmap] test 07 the kernel
    // must reject with E_NOENT.
    const result = syscall.unmap(vmar_handle, &.{0x1000});

    if (result.v1 != @intFromEnum(errors.Error.E_NOENT)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
