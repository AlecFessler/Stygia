// Spec §[create_var] — test 09.
//
// "[test 09] returns E_INVAL if props.sz is 3 (reserved)."
//
// Strategy
//   `props` (vreg 2) packs cur_rwx (bits 0-2), sz (bits 3-4), and cch
//   (bits 5-6). The `sz` field is a 2-bit page-size enum: 0=4 KiB,
//   1=2 MiB, 2=1 GiB, 3=reserved. Setting sz=3 must produce E_INVAL.
//
//   Other reject paths must NOT fire ahead of this one, or the kernel
//   could return their error code instead of test 09's E_INVAL:
//     - test 01 (E_PERM no `crvr` on self): the runner grants `crvr`
//       to spawned tests via `child_self` in runner/primary.zig, so
//       the caller has it.
//     - test 02 (E_PERM caps.r/w/x not subset of var_inner_ceiling):
//       runner's var_inner_ceiling = 0x01FF includes r|w|x|max_sz=3|
//       dma; we set caps.r|caps.w only, both within the ceiling.
//     - test 03 (E_PERM caps.max_sz exceeds ceiling): runner's
//       ceiling.max_sz = 3, so caps.max_sz = 2 is within the bound.
//     - test 04 (E_PERM mmio not in ceiling): we leave caps.mmio = 0.
//     - test 05 (E_INVAL pages = 0): we pass pages = 1.
//     - test 06 (E_INVAL preferred_base misaligned): we pass
//       preferred_base = 0 (kernel chooses).
//     - test 07 (E_INVAL caps.max_sz = 3): we set caps.max_sz = 2.
//     - test 08 (E_INVAL mmio=1 and props.sz != 0): caps.mmio = 0.
//     - test 11 (E_INVAL mmio=1 and caps.x set): caps.mmio = 0.
//     - test 12 (E_INVAL dma=1 and caps.x set): caps.dma = 0.
//     - test 13 (E_INVAL mmio=1 and dma=1): caps.mmio = 0, caps.dma = 0.
//     - test 14/15 (dma path checks): caps.dma = 0, so [5] is ignored.
//     - test 16 (E_INVAL props.cur_rwx not subset of caps.r/w/x):
//       cur_rwx = r|w (0b011) ⊆ caps.r|w.
//     - test 17 (E_INVAL reserved bits in [1] or [2]): caps reserved
//       (bits 11-15) are 0 via VarCap defaults; props reserved (bits
//       7-63) are 0 since we only fill cur_rwx, sz, cch.
//
//   SPEC OVERLAP — test 10 vs test 09
//     The spec defines both:
//       test 09: E_INVAL if props.sz is 3 (reserved)
//       test 10: E_INVAL if props.sz exceeds caps.max_sz
//     With caps.max_sz = 2 and props.sz = 3, both predicates are true
//     simultaneously. There is no choice of caps.max_sz that isolates
//     test 09 cleanly: making caps.max_sz = 3 (so sz=3 doesn't exceed
//     it) would itself fire test 07 (E_INVAL caps.max_sz reserved).
//     The kernel may dispatch in either order; both produce E_INVAL,
//     which is the only outcome this test asserts on.
//
// Action
//   1. create_var(caps={r,w,max_sz=2}, props=(sz=3, cur_rwx=r|w),
//                 pages=1, preferred_base=0, device_region=0)
//   2. expect vreg 1 == E_INVAL
//
// Assertions
//   1: create_var returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // caps: r=1, w=1, max_sz=2 (1 GiB). max_sz=2 keeps test 07 from
    // firing while still being a valid value covered by the runner's
    // var_inner_ceiling (max_sz field = 3).
    const var_caps = caps.VarCap{
        .r = true,
        .w = true,
        .max_sz = 2,
    };

    // props layout per §[create_var] [2]:
    //   bits 0-2: cur_rwx
    //   bits 3-4: sz
    //   bits 5-6: cch
    //   bits 7-63: reserved (must be 0 to dodge test 17)
    // sz = 3 (reserved) is the field this test exercises. cch = 0
    // (write-back) is the simplest legal cache value. cur_rwx = r|w
    // (0b011) is a subset of caps.r|w, dodging test 16.
    const props: u64 = (0 << 5) | // cch = 0
        (3 << 3) | // sz = 3 (reserved — the value under test)
        0b011; // cur_rwx = r|w

    const result = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages — nonzero (test 05 guard)
        0, // preferred_base — kernel chooses (test 06 guard)
        0, // device_region — caps.dma = 0 so this is ignored
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
