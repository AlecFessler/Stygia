// Spec §[create_var] create_var — test 08.
//
// "[test 08] returns E_INVAL if caps.mmio = 1 and props.sz != 0."
//
// Strategy
//   MMIO VARs back device register windows; the kernel's own MMIO
//   mapping path operates exclusively in 4 KiB units, so the spec
//   pins `props.sz = 0` whenever `caps.mmio = 1`. Any non-zero
//   props.sz on an MMIO VAR must produce E_INVAL.
//
//   Other reject paths must NOT fire ahead of this one, or the
//   kernel could legitimately return their error code instead of
//   test 08's E_INVAL:
//     - test 01 (E_PERM no `crvr` on self): the runner grants
//       `crvr` to spawned tests via `child_self` in
//       runner/primary.zig.
//     - test 02 (E_PERM caps.r/w/x not subset of var_inner_ceiling):
//       runner's var_inner_ceiling = 0x01FF includes r|w|x|mmio,
//       and we set caps.r|caps.w only — both within the ceiling.
//     - test 03 (E_PERM caps.max_sz exceeds ceiling): we leave
//       caps.max_sz = 0, well within the ceiling's max_sz = 3.
//     - test 04 (E_PERM mmio not in ceiling): the runner's
//       var_inner_ceiling has mmio set, so this gate passes.
//     - test 05 (E_INVAL pages = 0): we pass pages = 1.
//     - test 06 (E_INVAL preferred_base misaligned): we pass
//       preferred_base = 0 (kernel chooses).
//     - test 07 (E_INVAL caps.max_sz = 3): caps.max_sz = 0.
//     - test 09 (E_INVAL props.sz = 3): we set props.sz = 1
//       (2 MiB — non-zero but not the reserved value), which
//       satisfies test 08's predicate without tripping test 09.
//     - test 10 (E_INVAL props.sz exceeds caps.max_sz): with
//       caps.max_sz = 0 and props.sz = 1, the spec also defines
//       this gate as firing. Both predicates produce E_INVAL,
//       which is the only outcome this test asserts on; the kernel
//       may dispatch in either order.
//     - test 11 (E_INVAL mmio=1 and caps.x set): caps.x = 0.
//     - test 12 (E_INVAL dma=1 and caps.x set): caps.dma = 0.
//     - test 13 (E_INVAL mmio=1 and dma=1): caps.dma = 0.
//     - test 14/15 (dma path checks): caps.dma = 0, so [5] is
//       ignored.
//     - test 16 (E_INVAL props.cur_rwx not subset of caps.r/w/x):
//       props.cur_rwx = r|w (0b011) ⊆ caps.r|w.
//     - test 17 (E_INVAL reserved bits in [1] or [2]): caps
//       reserved bits are 0 via VarCap defaults; props reserved
//       bits 7-63 are 0 since we only fill cur_rwx, sz, cch.
//
// Action
//   create_var(caps={r,w,mmio}, props={cur_rwx=0b011, sz=1, cch=0},
//              pages=1, preferred_base=0, device_region=0)
//
// Assertions
//   1: result.v1 != E_INVAL — kernel did not reject mmio with
//      props.sz != 0.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps_word = caps.VarCap{
        .r = true,
        .w = true,
        .mmio = true,
    };

    // props layout per §[create_var] [2]:
    //   bits 0-2: cur_rwx
    //   bits 3-4: sz
    //   bits 5-6: cch
    //   bits 7-63: reserved (must be 0 to dodge test 17)
    // sz = 1 (2 MiB) is the non-zero, non-reserved value that
    // exercises test 08 while sidestepping test 09 (sz = 3).
    // cur_rwx = r|w (0b011) is a subset of caps.r|w, dodging
    // test 16. cch = 0 (write-back) is the simplest legal value.
    const props: u64 = (0 << 5) | // cch = 0
        (1 << 3) | // sz = 1 (2 MiB — non-zero, the field under test)
        0b011; // cur_rwx = r|w

    const result = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
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
