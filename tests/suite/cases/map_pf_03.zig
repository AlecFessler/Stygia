// Spec §[map_pf] — test 03.
//
// "[test 03] returns E_PERM if [1].caps has `mmio` set (mmio VARs
// accept only `map_mmio`)."
//
// Strategy
//   To isolate the caps.mmio rejection in map_pf we need:
//     - a valid page_frame handle so test 02 (E_BADCAP for an
//       invalid pf in any pair) does not fire ahead of test 03;
//     - a valid VAR handle whose caps carry mmio = 1, so test 01
//       (E_BADCAP for an invalid VAR) does not fire either.
//
//   The MMIO VAR is built without an actual map_mmio call. Per
//   §[var]:
//     - caps.mmio = 1 requires props.sz = 0 (create_var test 08),
//       caps.x = 0 (test 11), caps.dma = 0 (test 13).
//     - The root domain's var_inner_ceiling permits mmio (the same
//       construction is used by runner/serial.zig).
//   With caps = {r, w, mmio} and props = {sz=0, cch=1 (uc),
//   cur_rwx=0b011} the create_var prelude succeeds and we get a VAR
//   handle in `map = 0` state with `caps.mmio = 1`. No map_mmio is
//   needed — the spec's test 03 turns purely on `caps.mmio`, not on
//   the field1 `map` state.
//
//   With both prerequisites in hand we issue map_pf on the MMIO VAR
//   with one (offset, page_frame) pair (offset = 0, the staged pf).
//   The kernel must reject with E_PERM before consulting any of the
//   later checks (N == 0, alignment, range, overlap, map state).
//
// Action
//   1. createPageFrame(caps={r,w}, props={sz=0}, pages=1) — must
//      succeed.
//   2. createVar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//      cur_rwx=0b011}, pages=1, preferred_base=0, device_region=0)
//      — must succeed.
//   3. mapPf(mmio_var_handle, &.{ 0, pf_handle }) — must return
//      E_PERM in vreg 1.
//
// Assertions
//   1: vreg 1 was not E_PERM after mapPf on an MMIO VAR.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a valid page_frame so map_pf's E_BADCAP-on-invalid-pf
    // check (test 02) cannot pre-empt the caps.mmio rejection.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // Build an MMIO-capable VAR (no map_mmio needed — test 03 turns
    // on caps.mmio, not on field1 map state).
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

    const mp = syscall.mapPf(mmio_var_handle, &.{ 0, pf_handle });
    if (mp.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
