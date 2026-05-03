// Spec §[create_var] — test 16.
//
// "[test 16] returns E_INVAL if props.cur_rwx is not a subset of caps.r/w/x."
//
// Strategy
//   To isolate the cur_rwx ⊄ caps.r/w/x check we must satisfy every
//   other create_var-prelude check, mirroring create_var_05.zig:
//     - caller self-handle has `crvr` (root_service grants this).
//     - caps.r/w/x ⊆ var_inner_ceiling.r/w/x (test 02): use only r,w
//       which the root domain's ceiling permits.
//     - caps.max_sz ≤ ceiling.max_sz (test 03): leave max_sz = 0.
//     - caps.mmio (tests 04, 08, 11, 13): leave mmio = 0.
//     - caps.dma (tests 12, 13, 14, 15, 22): leave dma = 0; pass
//       device_region = 0 since dma is off.
//     - caps.max_sz != 3 (test 07): max_sz = 0 satisfies this.
//     - props.sz != 3 (test 09), sz ≤ caps.max_sz (test 10): use
//       props.sz = 0 (4 KiB) which satisfies both.
//     - preferred_base aligned (test 06): use preferred_base = 0.
//     - pages != 0 (test 05): pages = 1.
//     - reserved bits clean (test 17): all unused fields zero.
//   That leaves cur_rwx ⊄ caps.r/w/x as the only spec-mandated
//   failure path. Set caps = {r, w} (no x) and cur_rwx = 0b111
//   (r|w|x). Bit 2 (x) of cur_rwx is set but caps.x is not, so the
//   subset check must reject and return E_INVAL.
//
// Action
//   1. createVar(caps={r,w}, props={sz=0, cch=0, cur_rwx=0b111},
//                pages=1, preferred_base=0, device_region=0)
//      — must return E_INVAL in vreg 1.
//
// Assertion
//   1: vreg 1 was not E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b111; // cur_rwx = r|w|x; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (cv.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
