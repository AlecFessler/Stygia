// Spec §[unmap] — test 05.
//
// "[test 05] returns E_NOENT if [1].field1 `map` is 1 and any
//  page_frame selector is not currently installed in [1]."
//
// Strategy
//   To isolate the not-installed gate every earlier §[unmap] gate
//   must be inert:
//     - test 01 (invalid VAR)         — pass a freshly-minted VAR.
//     - test 02 (map == 0)            — install a pf first so the
//                                       VAR's `map` becomes 1.
//     - test 03 (map == 2 with N > 0) — VAR caps.mmio = 0, so the
//                                       map_pf path takes us to
//                                       `map = 1`, never to 2.
//     - test 04 (invalid pf handle)   — the selector we pass is the
//                                       handle of a real, kernel-
//                                       valid page_frame; just one
//                                       that has not been installed
//                                       in this VAR.
//
//   With those gates inert the only signal left is "page_frame
//   selector exists, is a real handle, but is not currently
//   installed in [1]" — exactly §[unmap] test 05.
//
//   We mint two distinct page_frames (pf_a, pf_b), install pf_a in
//   the VAR (so `map = 1` and the not-installed gate is reachable),
//   and call `unmap(var, &.{ pf_b })`. pf_b is a valid page_frame
//   handle, but it was never installed in this VAR, so the kernel
//   must take the test-05 leg and return E_NOENT.
//
// Action
//   1. createPageFrame(caps={r,w}, props={sz=0}, pages=1) — pf_a.
//   2. createPageFrame(caps={r,w}, props={sz=0}, pages=1) — pf_b.
//   3. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0).
//   4. mapPf(var, &.{ 0, pf_a }) — must succeed; transitions VAR
//      from `map = 0` to `map = 1` so the §[unmap] test-02 gate
//      cannot preempt test 05.
//   5. unmap(var, &.{ pf_b }) — must return E_NOENT (pf_b is a
//      valid page_frame but is not installed in this VAR).
//
// Assertions
//   1: vreg 1 was not E_NOENT after unmap with an uninstalled
//      page_frame selector (the spec assertion under test).
//   2: a setup syscall (createPageFrame, createVar, or mapPf)
//      returned an error code, breaking the success-path
//      precondition so we cannot proceed to verify the unmap
//      not-installed path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const pf_caps = caps.PfCap{ .r = true, .w = true };

    // Step 1: pf_a — the page_frame we'll install in the VAR so
    // `map` transitions from 0 to 1.
    const cpf_a = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf_a.v1)) {
        testing.fail(2);
        return;
    }
    const pf_a: u64 = @as(u64, cpf_a.v1 & 0xFFF);

    // Step 2: pf_b — a real, kernel-valid page_frame handle that
    // we will never install in the VAR. This is the selector that
    // must trigger §[unmap] test 05's E_NOENT.
    const cpf_b = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf_b.v1)) {
        testing.fail(2);
        return;
    }
    const pf_b: u64 = @as(u64, cpf_b.v1 & 0xFFF);

    // Step 3: regular 1-page VAR (caps.mmio = 0, caps.dma = 0).
    // Per §[var] it starts at `map = 0`.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0; cch = 0
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

    // Step 4: install pf_a at offset 0. After this the VAR's `map`
    // is 1, so §[unmap] test 02 (map == 0) can no longer fire.
    const install = syscall.mapPf(var_handle, &.{ 0, pf_a });
    if (install.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 5: unmap with a single page_frame selector pointing at
    // pf_b. pf_b is a valid handle but was never installed in the
    // VAR — §[unmap] test 05 demands E_NOENT.
    const result = syscall.unmap(var_handle, &.{pf_b});

    if (result.v1 != @intFromEnum(errors.Error.E_NOENT)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
