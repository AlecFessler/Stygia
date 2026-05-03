// Spec §[map_mmio] — test 02.
//
// "[test 02] returns E_BADCAP if [2] is not a valid device_region
// handle."
//
// Strategy
//   §[map_mmio] orders BADCAP gates: test 01 rejects an invalid VAR
//   handle in [1], test 02 rejects an invalid device_region handle
//   in [2]. To isolate the [2] gate we need a *valid* MMIO VAR in
//   [1] so test 01 cannot fire ahead.
//
//   The MMIO VAR is built without an actual map_mmio call. Per
//   §[var]:
//     - caps.mmio = 1 requires props.sz = 0 (create_var test 08),
//       caps.x = 0 (test 11), caps.dma = 0 (test 13).
//     - cch = 1 (uc) is required for mmio.
//   The same construction is used by runner/serial.zig and
//   map_pf_03.zig. With caps = {r, w, mmio} and props = {sz=0,
//   cch=1, cur_rwx=0b011} the create_var prelude succeeds and the
//   VAR sits in `map = 0` with `caps.mmio = 1`.
//
//   For [2] we use slot 4095 — the maximum 12-bit handle id.
//   The child capability domain's table is populated by the kernel
//   at create_capability_domain time (slots 0/1/2 are self / initial
//   EC / self-IDC; passed_handles begin at 3) so slot 4095 is
//   guaranteed empty and therefore invalid as a device_region
//   handle. The same trick is used by map_pf_01.zig.
//
// Action
//   1. createVar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//      cur_rwx=0b011}, pages=1, preferred_base=0, device_region=0)
//      — must succeed, gives a valid MMIO VAR.
//   2. mapMmio(mmio_var_handle, 4095) — must return E_BADCAP in
//      vreg 1.
//
// Assertions
//   1: vreg 1 was not E_BADCAP after mapMmio with an invalid
//      device_region handle.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a valid MMIO VAR so map_mmio's E_BADCAP-on-invalid-VAR
    // check (test 01) cannot pre-empt the [2] BADCAP rejection.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVar(
        @as(u64, mmio_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const mmio_var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout, so it is invalid as a device_region handle. The
    // [2] BADCAP gate must fire even though [1] is a valid MMIO VAR.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const mm = syscall.mapMmio(mmio_var_handle, empty_slot);
    if (mm.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
