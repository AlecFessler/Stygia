// Spec §[create_var] create_var — test 10.
//
// "[test 10] returns E_INVAL if props.sz exceeds caps.max_sz."
//
// Strategy
//   Pick a `caps`/`props` pair where caps.max_sz is strictly less than
//   props.sz, and where every other spec-mandated failure path is
//   neutralized so test 10's gate is the only one that can fire.
//
//   caps:    {r=1, w=1, max_sz=0}      → caps.max_sz = 0 (cap = 4 KiB only)
//   props:   sz=1, cur_rwx=0b011        → props.sz = 1 (2 MiB)
//   pages=1, preferred_base=0, device=0 → minimal valid layout
//
//   Cross-check against the other tests in this section:
//
//     - test 01 (E_PERM, missing crvr on self): the runner-provided
//       self-handle has `crvr` set (see runner/primary.zig), so this
//       cannot fire.
//     - test 02 (E_PERM, r/w/x not subset of var_inner_ceiling.r/w/x):
//       the runner sets var_inner_ceiling = 0x01FF (all VAR-cap bits
//       set, including r, w, x), so {r,w} is trivially a subset.
//     - test 03 (E_PERM, caps.max_sz exceeds var_inner_ceiling.max_sz):
//       runner's var_inner_ceiling.max_sz = 3 (all bits set); caps
//       value of 0 is the floor. No fire.
//     - test 04 (E_PERM, caps.mmio = 1 without ceiling permission):
//       caps.mmio = 0 here.
//     - test 05 (E_INVAL, pages = 0): pages = 1 here.
//     - test 06 (E_INVAL, preferred_base nonzero misaligned):
//       preferred_base = 0 here.
//     - test 07 (E_INVAL, caps.max_sz = 3): caps.max_sz = 0 here.
//     - test 08 (E_INVAL, caps.mmio = 1 and props.sz != 0):
//       caps.mmio = 0 here.
//     - test 09 (E_INVAL, props.sz = 3): props.sz = 1 here.
//     - test 11 (E_INVAL, caps.mmio = 1 and caps.x set): mmio=0, x=0.
//     - test 12 (E_INVAL, caps.dma = 1 and caps.x set): dma=0, x=0.
//     - test 13 (E_INVAL, caps.mmio = 1 and caps.dma = 1): both 0.
//     - test 14 (E_BADCAP, caps.dma = 1 with bad device_region):
//       caps.dma = 0 so the device_region argument is ignored.
//     - test 15 (E_PERM, caps.dma = 1 missing dma cap): caps.dma = 0.
//     - test 16 (E_INVAL, props.cur_rwx not subset of caps.r/w/x):
//       props.cur_rwx = 0b011 (r|w), caps r=1,w=1 → trivially subset.
//     - test 17 (E_INVAL, reserved bits): all reserved bits are zero in
//       both [1] and [2].
//
//   With every other path neutralized, the only spec-mandated failure
//   here is props.sz (1) > caps.max_sz (0), which must surface E_INVAL.
//
// Action
//   create_var(
//     caps   = {r, w, max_sz=0},
//     props  = cur_rwx=0b011, sz=1, cch=0,
//     pages  = 1,
//     pref_b = 0,
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

    const var_caps = caps.VarCap{
        .r = true,
        .w = true,
        .max_sz = 0, // 4 KiB ceiling on the page size encoded in props.sz
    };
    const props: u64 = (0 << 5) | // cch = 0 (wb)
        (1 << 3) | // sz = 1 (2 MiB) — exceeds caps.max_sz (0 = 4 KiB)
        0b011; // cur_rwx = r|w (subset of caps r/w)

    const result = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = 0 (kernel chooses)
        0, // device_region = none (caps.dma = 0)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
