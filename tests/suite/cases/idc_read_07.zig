// Spec §[idc_read] — test 07.
//
// "[test 07] on success, vregs `[3..2+count]` contain the qwords from
//  the VMAR starting at [2] offset."
//
// Strategy
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backing storage
//      for the VMAR. The page_frame's r|w intersect with the VMAR's
//      cur_rwx = r|w to yield effective r|w under §[map_pf] test 12,
//      so CPU stores into VMAR.base[..] reach the same physical bytes
//      that idc_read will later observe.
//   2. createVmar(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0}, pages=1,
//      preferred_base=0, device_region=0) — regular VMAR (caps.dma = 0,
//      caps.mmio = 0) in `map = 0` whose base vaddr is reported in
//      field0 (cvar.v2) per §[create_vmar] test 19.
//   3. mapPf(var, &.{ 0, pf }) — installs the page_frame at offset 0
//      of the VMAR, transitioning `map` 0 -> 1 per §[map_pf] test 11.
//      After this call, CPU writes through VMAR.base hit the page_frame
//      and idc_read on the same VMAR observes the same bytes.
//   4. Plant two distinct sentinel qwords at VMAR.base[0] and
//      VMAR.base[1] via volatile pointer writes (the volatile cast
//      keeps the optimizer from eliding the stores). The values are
//      arbitrary 64-bit patterns that cannot collide with the page
//      frame's zero-fill or with low-magnitude error codes returned
//      from idc_read on the failure path.
//   5. idcRead(vmar_handle, /*offset=*/0, /*count=*/2). Per §[idc_read]
//      lines 1141 and 1155, count goes in the syscall word's bits
//      12-19 and the dequeued qwords land in the caller's vregs 3 and
//      4 in offset order — got.regs.v3 = qword at offset 0, got.regs.v4
//      = qword at offset 8.
//   6. Assert got.regs.v1 == 0 (success — vreg 1 is the syscall return
//      slot per the kernel-syscall-ABI convention used by every other
//      test in this suite) and that v3 / v4 match the planted
//      sentinels. Any mismatch indicates either the wrong qwords were
//      copied, the offset arithmetic is off, or the contents weren't
//      flushed through the VMAR's mapping at the time of the read.
//
// Action
//   See Strategy.
//
// Assertions
//   1: setup failed — createPageFrame, createVmar, or mapPf returned an
//      error. Folded into one id because all three are required for
//      the probe to be meaningful.
//   2: idcRead returned an error in vreg 1 (not the success path the
//      assertion under test governs).
//   3: vreg 3 did not equal the sentinel planted at VMAR.base[0].
//   4: vreg 4 did not equal the sentinel planted at VMAR.base[8].

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SENTINEL_LO: u64 = 0xDEADBEEF_CAFEBABE;
const SENTINEL_HI: u64 = 0x12345678_9ABCDEF0;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page_frame with caps={r, w}. Intersection with the
    // VMAR's cur_rwx = r|w yields effective r|w on the mapped range,
    // so CPU stores below land in the page_frame and idc_read sees
    // them.
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
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VMAR with caps={r, w} and cur_rwx = r|w. The `r`
    // cap is the gate idc_read requires per §[idc_read] line 1147.
    // The kernel chooses the base; field0 (cvar.v2) reports it.
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
        testing.fail(1);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    // Step 3: install the page_frame at offset 0. Effective perms on
    // VMAR.base[0..4096] become (r|w) ∩ (r|w) = r|w; CPU writes succeed
    // and idc_read on the same VMAR observes them.
    const mr = syscall.mapPf(vmar_handle, &.{ 0, pf_handle });
    if (errors.isError(mr.v1)) {
        testing.fail(1);
        return;
    }

    // Step 4: plant two distinct qword sentinels at VMAR.base[0] and
    // VMAR.base[8]. Volatile keeps the optimizer from constant-folding
    // the writes away under ReleaseSmall.
    const qword_ptr: [*]volatile u64 = @ptrFromInt(var_base);
    qword_ptr[0] = SENTINEL_LO;
    qword_ptr[1] = SENTINEL_HI;

    // Step 5: idc_read 2 qwords starting at offset 0. Per §[idc_read]
    // lines 1138 and 1155, the kernel pauses every EC in the VMAR's
    // owning domain for the duration of the call (a no-op here — the
    // caller is the only EC), reads count*8 bytes from VMAR.base +
    // offset, and stores them into vregs 3..2+count in offset order.
    const got = syscall.idcRead(vmar_handle, 0, 2);

    // Step 6a: success leg under test. Vreg 1 carries the syscall
    // return; non-zero, low-magnitude values are spec error codes per
    // §[error_codes].
    if (errors.isError(got.v1)) {
        testing.fail(2);
        return;
    }

    // Step 6b: vreg 3 must equal the qword at offset 0.
    if (got.v3 != SENTINEL_LO) {
        testing.fail(3);
        return;
    }

    // Step 6c: vreg 4 must equal the qword at offset 8.
    if (got.v4 != SENTINEL_HI) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
