// Spec §[create_var] — test 05.
//
// "[test 05] returns E_INVAL if [3] pages is 0."
//
// Strategy
//   To isolate the pages == 0 check we must make every other
//   create_var-prelude check pass:
//     - caller self-handle has `crvr` (the root_service launches every
//       test domain with the full self-cap set, so this is satisfied
//       implicitly — see runner/serial.zig which calls create_var the
//       same way).
//     - caps.r/w/x ⊆ var_inner_ceiling.r/w/x (test 02): use only r,w
//       which the root domain's ceiling permits (serial.zig uses the
//       same combination plus mmio).
//     - caps.max_sz ≤ ceiling.max_sz (test 03): leave max_sz = 0.
//     - caps.mmio (test 04, 08, 11, 13): leave mmio = 0.
//     - caps.dma (test 12, 13, 14, 15, 22): leave dma = 0, and pass
//       device_region = 0 since dma is off.
//     - caps.max_sz != 3 (test 07): max_sz = 0 satisfies this.
//     - props.sz != 3 (test 09), sz ≤ caps.max_sz (test 10): use
//       props.sz = 0 (4 KiB) which satisfies both.
//     - preferred_base aligned (test 06): use preferred_base = 0 so
//       the kernel chooses.
//     - props.cur_rwx ⊆ caps.r/w/x (test 16): cur_rwx = 0b011 (r|w)
//       matches caps.{r,w}.
//     - reserved bits clean (test 17): all unused fields zero.
//   That leaves pages = 0 as the only spec-mandated failure path.
//
// Action
//   1. createVar(caps={r,w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=0, preferred_base=0, device_region=0)
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
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        0, // pages = 0 — the spec violation under test
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (cv.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
