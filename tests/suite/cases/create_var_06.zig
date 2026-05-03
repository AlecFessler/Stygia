// Spec §[create_var] — test 06.
//
// "[test 06] returns E_INVAL if [4] preferred_base is nonzero and not
//  aligned to the page size encoded in props.sz."
//
// Strategy
//   To isolate the preferred_base alignment check, every other
//   create_var-prelude check must pass:
//     - caller self-handle has `crvr` (root_service launches every
//       test domain with the full self-cap set — see runner/serial.zig).
//     - caps.r/w/x ⊆ var_inner_ceiling.r/w/x (test 02): use {r, w}
//       which the root domain's ceiling permits.
//     - caps.max_sz ≤ ceiling.max_sz (test 03): leave max_sz = 0.
//     - caps.mmio (tests 04, 08, 11, 13): leave mmio = 0.
//     - caps.dma (tests 12, 13, 14, 15, 22): leave dma = 0, and pass
//       device_region = 0 since dma is off.
//     - caps.max_sz != 3 (test 07): max_sz = 0 satisfies this.
//     - props.sz != 3 (test 09), sz ≤ caps.max_sz (test 10): use
//       props.sz = 0 (4 KiB) which satisfies both.
//     - pages != 0 (test 05): use pages = 1.
//     - props.cur_rwx ⊆ caps.r/w/x (test 16): cur_rwx = 0b011 (r|w)
//       matches caps.{r, w}.
//     - reserved bits clean (test 17): all unused fields zero.
//
//   With every other gate neutralized, the only spec-mandated failure
//   here is preferred_base = 0x1001: nonzero and not 4 KiB-aligned
//   (the page size encoded by props.sz = 0).
//
// Action
//   create_var(
//     caps   = {r, w},
//     props  = cur_rwx=0b011, sz=0 (4 KiB), cch=0,
//     pages  = 1,
//     pref_b = 0x1001,                  // 1 byte off 4 KiB alignment
//     dev    = 0,
//   )
//   -> must return E_INVAL in vreg 1
//
// Assertion
//   result.v1 == E_INVAL  (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const result = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0x1001, // preferred_base — nonzero, misaligned vs 4 KiB
        0, // device_region = unused (caps.dma = 0)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
