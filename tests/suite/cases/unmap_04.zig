// Spec §[unmap] — test 04.
//
// "[test 04] returns E_BADCAP if [1].field1 `map` is 1 and any selector
//  is not a valid page_frame handle."
//
// Strategy
//   We need a VAR whose `map` field is 1 (pf-installed) so the unmap
//   dispatch routes to the page_frame-handle selector path. Per
//   §[map_pf] test 11, a successful map_pf transitions `map` from 0
//   to 1. Setup:
//     1. createPageFrame(caps={r,w}, props=0, pages=1) — provides a
//        real page_frame for the install.
//     2. createVar(caps={r,w}, props={cur_rwx=r|w, sz=0}, pages=1) —
//        regular VAR, starts at `map = 0`.
//     3. mapPf(var, &.{ 0, pf }) — installs at offset 0; `map` becomes
//        1. After this, the only legal selectors for unmap are valid
//        page_frame handle ids (per §[unmap]: "map = 1 (pf):
//        page_frame handles to unmap").
//
//   To trigger test 04 we then call unmap with N = 1 and a selector
//   that points to an empty handle slot. Slot 4095 (HANDLE_TABLE_MAX
//   - 1) is guaranteed empty by the create_capability_domain table
//   layout (slot 0 = self, 1 = initial EC, 2 = self-IDC, 3 = result
//   port; nothing else has been installed at slot 4095). Passing it
//   as the unmap selector forces the kernel to look up an empty slot
//   as a page_frame, which must surface E_BADCAP.
//
//   Test 02 (E_INVAL on map=0) cannot fire because we drove map to 1.
//   Test 03 (E_INVAL on map=2 with N>0) cannot fire because map=1.
//   Test 05 (E_NOENT for valid-but-not-installed) requires the
//   selector to reference a real page_frame that simply isn't
//   currently installed; an empty slot is not a valid handle, so
//   E_BADCAP must precede E_NOENT.
//
// Action
//   1. createPageFrame — must return a valid handle in v1.
//   2. createVar — must return a valid VAR handle in v1.
//   3. mapPf(var, &.{ 0, pf }) — must succeed (v1 == 0); drives
//      map = 1.
//   4. unmap(var, &.{ 4095 }) — slot 4095 is empty. Kernel must
//      return E_BADCAP because the selector is not a valid
//      page_frame handle.
//
// Assertions
//   1: vreg 1 was not E_BADCAP after the unmap call (the spec
//      assertion under test).
//   2: setup syscall returned an error (createPageFrame, createVar,
//      or mapPf) — the precondition for the assertion is broken so
//      we cannot proceed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: real page_frame for the install. caps={r,w} is enough;
    // the unmap selector under test is unrelated to this handle.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VAR (caps.mmio=0, caps.dma=0). Starts at
    // `map = 0` per §[var]; map_pf will drive it to 1.
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
        testing.fail(2);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install the page_frame at offset 0. §[map_pf] test 11:
    // `map` transitions 0 -> 1 on success.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mr.v1 != 0) {
        testing.fail(2);
        return;
    }

    // Step 4: unmap with a single selector pointing at an empty handle
    // slot. Slot 4095 is guaranteed empty by the
    // create_capability_domain table layout, so it is not a valid
    // page_frame handle. The kernel must return E_BADCAP per
    // §[unmap] test 04.
    const empty_slot: u64 = @as(u64, caps.HANDLE_TABLE_MAX - 1);
    const result = syscall.unmap(var_handle, &.{empty_slot});

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
