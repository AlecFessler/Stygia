// Spec §[map_pf] — test 06.
//
// "[test 06] returns E_INVAL if any page_frame's `sz` is smaller
//  than the VAR's `sz`."
//
// Strategy
//   To isolate the page_frame-sz < VAR-sz rejection we need every
//   earlier rejection path to be inert. With one (offset, pf) pair:
//     - test 01 (VAR is invalid)        — pass a freshly-minted VAR.
//     - test 02 (pf in pair invalid)    — pass a freshly-minted pf.
//     - test 03 (caps.mmio set)         — caps = {r, w}, mmio = 0.
//     - test 04 (N == 0)                — N = 1.
//     - test 05 (offset misaligned)     — offset = 0 is aligned to any
//                                         sz, including the VAR's
//                                         2 MiB sz.
//     - test 10 (VAR.map ∈ {2, 3})      — fresh VAR has map = 0.
//   Tests 07/08/09 (range exceeds VAR, in-call overlap, overlap with
//   existing mapping) all reason about the (offset, pf) extents. With
//   pf.sz = 0 (4 KiB) and VAR pages = 1 × 2 MiB, the pair covers
//   [0, 4 KiB) which is well inside the 2 MiB VAR — those gates are
//   inert ahead of test 06.
//
//   The runner's ceilings (see runner/primary.zig) set
//   var_inner_ceiling.max_sz = 1 (2 MiB, encoded in 0x01FF) and
//   pf_ceiling.max_sz = 3 (4 KiB / 2 MiB / 1 GiB / reserved, encoded
//   in 0x1F). caps.max_sz on the VAR must be ≥ props.sz to pass test
//   10 of create_var; we pick caps.max_sz = 1 to mirror props.sz
//   exactly without exceeding the ceiling.
//
// Action
//   1. createPageFrame(caps={r, w}, props={sz = 0}, pages = 1) —
//      a 4 KiB page frame for the pair (assertion 1 guards this).
//   2. createVar(caps={r, w, max_sz = 1}, props={cur_rwx = 0b011,
//      sz = 1, cch = 0}, pages = 1, preferred_base = 0,
//      device_region = 0) — a 2 MiB VAR (assertion 1 guards this).
//      §[create_var] does not require physical contiguity at create
//      time; only later mapping installs page_frames, so the request
//      should succeed under v0 v_addr_space allocation.
//   3. mapPf(var_handle, &.{ 0, pf_handle }) — offset 0 is aligned to
//      the VAR's 2 MiB sz, but pf.sz = 0 < VAR.sz = 1, so the kernel
//      must return E_INVAL per §[map_pf] test 06.
//
// Assertion
//   1: vreg 1 was not E_INVAL after mapPf with pf.sz < VAR.sz, or a
//      precondition (createPageFrame / createVar) failed and the
//      exercised path could not be reached.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a 4 KiB page_frame so map_pf's earlier BADCAP and N == 0
    // gates cannot pre-empt the sz check we are exercising.
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

    // 2 MiB VAR. caps.max_sz = 1 lets props.sz = 1 satisfy test 10 of
    // create_var; the runner-supplied var_inner_ceiling permits
    // max_sz up to 1.
    const var_caps_word = caps.VarCap{
        .r = true,
        .w = true,
        .max_sz = 1, // 2 MiB; matches props.sz below
    };
    const props: u64 = (1 << 3) | // sz = 1 (2 MiB)
        0b011; // cur_rwx = r | w; cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        props,
        1, // pages = 1 → one 2 MiB page
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // pf.sz = 0 (4 KiB) is strictly smaller than VAR.sz = 1 (2 MiB).
    // offset = 0 is aligned to 2 MiB so test 05 cannot fire ahead of
    // test 06.
    const mp = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mp.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
