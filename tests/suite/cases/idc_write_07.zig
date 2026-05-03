// Spec §[idc_write] — test 07.
//
// "[test 07] on success, the qwords from vregs `[3..2+count]` are
//  written into the VAR starting at [2] offset."
//
// Strategy
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backing storage
//      for the VAR. The page_frame's r|w intersect with the VAR's
//      cur_rwx = r|w to yield effective r|w under §[map_pf] test 12,
//      so CPU loads through VAR.base[..] observe the same physical
//      bytes that idc_write commits.
//   2. createVar(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0}, pages=1,
//      preferred_base=0, device_region=0) — regular VAR (caps.dma = 0,
//      caps.mmio = 0) in `map = 0` whose base vaddr is reported in
//      field0 (cvar.v2) per §[create_var] test 19.
//   3. mapPf(var, &.{ 0, pf }) — installs the page_frame at offset 0
//      of the VAR, transitioning `map` 0 -> 1 per §[map_pf] test 11.
//      After this call, idc_write writes to the VAR commit to the
//      page_frame and CPU loads through VAR.base see them.
//   4. idcWrite(var_handle, /*offset=*/0, /*qwords=*/&.{ SENTINEL_LO,
//      SENTINEL_HI }). Per §[idc_write] lines 1163 and 1166, count
//      goes in the syscall word's bits 12-19; the qwords come from
//      the caller's vregs 3..2+count and the kernel writes them into
//      VAR.base + offset in offset order — vreg 3 -> offset 0,
//      vreg 4 -> offset 8.
//   5. Read VAR.base[0] and VAR.base[1] back through a volatile u64
//      pointer (the volatile cast keeps the optimizer from folding
//      these loads against the planted constants under ReleaseSmall),
//      and assert each matches its sentinel. Sentinels are arbitrary
//      64-bit patterns chosen to avoid colliding with the page
//      frame's zero-fill or with low-magnitude error codes.
//
// Action
//   See Strategy.
//
// Assertions
//   1: setup failed — createPageFrame, createVar, or mapPf returned an
//      error. Folded into one id because all three are required for
//      the probe to be meaningful.
//   2: idcWrite returned an error in vreg 1 (not the success path the
//      assertion under test governs).
//   3: VAR.base[0] did not equal the sentinel passed in vreg 3.
//   4: VAR.base[8] did not equal the sentinel passed in vreg 4.

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
    // VAR's cur_rwx = r|w yields effective r|w on the mapped range,
    // so idc_write below commits and CPU loads observe the result.
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

    // Step 2: regular VAR with caps={r, w} and cur_rwx = r|w. The `w`
    // cap is the gate idc_write requires per §[idc_write] line 1173.
    // The kernel chooses the base; field0 (cvar.v2) reports it.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    // Step 3: install the page_frame at offset 0. Effective perms on
    // VAR.base[0..4096] become (r|w) ∩ (r|w) = r|w; idc_write commits
    // to the page_frame and CPU loads through VAR.base see them.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (errors.isError(mr.v1)) {
        testing.fail(1);
        return;
    }

    // Step 4: idc_write 2 qwords starting at offset 0. Per §[idc_write]
    // lines 1163 and 1170, the kernel pauses every EC in the VAR's
    // owning domain for the duration of the call (a no-op here — the
    // caller is the only EC), reads count qwords from vregs 3..2+count,
    // and writes them into VAR.base + offset in offset order
    // (vreg 3 -> offset 0, vreg 4 -> offset 8).
    const got = syscall.idcWrite(var_handle, 0, &.{ SENTINEL_LO, SENTINEL_HI });

    // Step 5a: success leg under test. Vreg 1 carries the syscall
    // return; non-zero, low-magnitude values are spec error codes per
    // §[error_codes].
    if (errors.isError(got.v1)) {
        testing.fail(2);
        return;
    }

    // Step 5b: read the planted bytes back through a volatile pointer.
    // Volatile keeps the optimizer from folding these loads against
    // the constant values written via the syscall path under
    // ReleaseSmall.
    const qword_ptr: [*]volatile u64 = @ptrFromInt(var_base);

    // Step 5c: VAR.base[0] must equal the qword passed in vreg 3.
    if (qword_ptr[0] != SENTINEL_LO) {
        testing.fail(3);
        return;
    }

    // Step 5d: VAR.base[8] must equal the qword passed in vreg 4.
    if (qword_ptr[1] != SENTINEL_HI) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
