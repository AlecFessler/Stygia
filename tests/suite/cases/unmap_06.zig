// Spec §[unmap] — test 06.
//
// "[test 06] returns E_INVAL if [1].field1 `map` is 3 and any offset
//  selector is not aligned to [1]'s `sz`."
//
// Strategy
//   To isolate the `map = 3` alignment gate every earlier §[unmap] gate
//   must be inert:
//     - test 01 (invalid VMAR)         — pass a freshly-minted VMAR.
//     - test 02 (map = 0)              — drive `map` to 3 via a demand
//                                        fault before issuing `unmap`.
//     - test 03 (map = 2 + N > 0)      — VMAR caps.mmio = 0, so a
//                                        demand fault transitions to
//                                        `map = 3`, never to 2.
//     - tests 04, 05 (map = 1 selector — n/a on `map = 3`.
//                    validation)
//
//   Per §[var]: a regular VMAR (caps.mmio = 0, caps.dma = 0) starts at
//   `map = 0`; the first faulted access transitions it to `map = 3`
//   (demand) — the kernel allocates a fresh zero-filled page_frame and
//   installs it at the faulting offset. We trigger that transition by
//   issuing a volatile store through `VMAR.base` (reported in field0
//   per §[create_vmar] test 19). After the store completes the kernel
//   has installed a demand page at offset 0 and `map` is 3.
//
//   With `map = 3` reached we issue `unmap(vmar, &.{ misaligned })`
//   where `misaligned` is a non-page-aligned byte offset. The VMAR's
//   `sz = 0` is 4 KiB, so any offset whose low 12 bits are non-zero
//   trips the alignment gate. The selector we pick (1) is the smallest
//   value that is unambiguously misaligned and is not a valid handle
//   id either — the test 06 alignment check is the only signal.
//
// Action
//   1. createVmar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                 pages=1, preferred_base=0, device_region=0). Records
//                 the chosen base in field0 (cvar.v2).
//   2. Volatile store at VMAR.base[0] — kernel demand-faults on first
//      access; allocates a zero-filled page at offset 0 and bumps
//      `map` from 0 to 3 per §[var].
//   3. unmap(var, &.{ 1 }) — selector 1 is a sub-page-aligned byte
//      offset against `sz = 0` (4 KiB pages). Per §[unmap] test 06
//      the kernel must return E_INVAL.
//
// Assertions
//   1: vreg 1 was not E_INVAL after `unmap` with a misaligned offset
//      on a `map = 3` VMAR (the spec assertion under test).
//   2: a setup syscall returned an error code, breaking the
//      success-path precondition.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: regular VMAR (caps.mmio = 0, caps.dma = 0). Starts at
    // `map = 0` per §[var]. cur_rwx = r|w so the demand store below
    // is permitted by the page-fault permission check.
    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const vmar_base: u64 = cvar.v2;

    // Step 2: drive `map` 0 -> 3. The volatile store forces the
    // optimizer to emit a real memory access; the kernel's
    // page-fault handler runs `demandAlloc` (kernel/memory/vmar.zig
    // §demandAlloc), installs a zero-filled page at offset 0, and
    // bumps `v.map` to .demand. After this line the VMAR is in
    // `map = 3` with one demand page installed at offset 0.
    const qword_ptr: [*]volatile u64 = @ptrFromInt(vmar_base);
    qword_ptr[0] = 0;

    // Step 3: unmap with a misaligned byte offset. Selector value 1
    // is < `sz_bytes` (4096) and has its low 12 bits set, so it
    // fails the `offset & (sz_bytes - 1) == 0` alignment check the
    // kernel enforces on `map = 3` selectors.
    const result = syscall.unmap(vmar_handle, &.{1});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
