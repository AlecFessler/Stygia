// Spec §[create_var] — test 14.
//
// "[test 14] returns E_BADCAP if caps.dma = 1 and [5] is not a valid
//  device_region handle."
//
// Strategy
//   To isolate the BADCAP-on-[5] check we must make every
//   create_var-prelude check that runs ahead of it pass:
//     - caller self-handle has `crvr` (root_service launches every test
//       domain with the full self-cap set — see runner/primary.zig).
//     - caps.r/w/x ⊆ var_inner_ceiling.r/w/x (test 02): the runner's
//       ceilings_inner = 0x001C_011F_3F01_FFFF places var_inner_ceiling
//       at field0 bits 8-23 = 0x01FF, which permits r, w, and dma. We
//       use only r|w here (no x) so test 12 (caps.dma = 1 and caps.x
//       set → E_INVAL) cannot fire.
//     - caps.max_sz ≤ ceiling.max_sz (test 03): leave max_sz = 0.
//     - caps.mmio (tests 04, 08, 11, 13): leave mmio = 0 so the mmio
//       paths — including test 13 (mmio = 1 and dma = 1 → E_INVAL) —
//       cannot trigger.
//     - caps.max_sz != 3 (test 07): max_sz = 0 satisfies this.
//     - props.sz != 3 (test 09), sz ≤ caps.max_sz (test 10): use
//       props.sz = 0 (4 KiB) which satisfies both.
//     - preferred_base aligned (test 06): use preferred_base = 0.
//     - props.cur_rwx ⊆ caps.r/w/x (test 16): cur_rwx = 0b011 (r|w)
//       matches caps.{r,w}.
//     - reserved bits clean (test 17): all unused fields zero.
//     - pages != 0 (test 05): use pages = 1.
//   With caps.dma = 1 set, the kernel must validate [5]. The child
//   capability domain's table is populated by the kernel at
//   create_capability_domain time — slot 0 self, slot 1 initial EC,
//   slot 2 self-IDC, slot 3+ passed_handles (only the result port at
//   slot 3 here). Slot 4095 (the maximum 12-bit handle id) is
//   guaranteed unminted, so it cannot be a valid device_region handle.
//   The only spec-mandated outcome is E_BADCAP.
//
// Action
//   1. createVar(caps={r, w, dma}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=4095)
//      — must return E_BADCAP in vreg 1.
//
// Assertion
//   1: vreg 1 was not E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true, .dma = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const invalid_dev: u64 = caps.HANDLE_TABLE_MAX - 1; // slot 4095, unminted

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1 (avoids test 05)
        0, // preferred_base = kernel chooses
        invalid_dev,
    );
    if (cv.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
