// Spec §[create_page_frame] — test 06.
//
// "[test 06] returns E_INVAL if props.sz is 3 (reserved)."
//
// Strategy
//   `props` (vreg 2) packs the 2-bit page-size enum `sz` at bits 0-1
//   (§[create_page_frame] [2]: "bits 0-1: sz — page size (immutable);
//   bits 2-63: _reserved"). The `sz` enum is shared with the page_frame
//   handle layout: 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved (§[page_frame]
//   field0 sz). Setting props.sz = 3 must return E_INVAL.
//
//   Other reject paths must NOT fire ahead of this one, or the kernel
//   could return their error code instead of test 06's E_INVAL:
//     - test 01 (E_PERM no `crpf` on self): the runner grants `crpf`
//       to spawned tests via `child_self` in runner/primary.zig, so
//       the caller has it.
//     - test 02 (E_PERM caps.r/w/x not subset of pf_ceiling.max_rwx):
//       runner's pf_ceiling.max_rwx = 0b111 (r|w|x); we set caps.r and
//       caps.w only, both within the ceiling.
//     - test 03 (E_PERM caps.max_sz exceeds pf_ceiling.max_sz): runner's
//       pf_ceiling.max_sz = 3, so caps.max_sz = 2 is within the bound.
//     - test 04 (E_INVAL pages = 0): we pass pages = 1.
//     - test 05 (E_INVAL caps.max_sz = 3): we set caps.max_sz = 2.
//     - test 08 (E_INVAL reserved bits in [1] or [2]): PfCap defaults
//       leave bits 8-15 zero; props' bits 2-63 are zero since we only
//       fill the sz field.
//
//   SPEC OVERLAP — test 06 vs test 07
//     The spec defines both:
//       test 06: E_INVAL if props.sz is 3 (reserved)
//       test 07: E_INVAL if props.sz exceeds caps.max_sz
//     With caps.max_sz = 2 and props.sz = 3, both predicates are true
//     simultaneously. There is no choice of caps.max_sz that isolates
//     test 06 cleanly: making caps.max_sz = 3 (so sz=3 doesn't exceed
//     it) would itself fire test 05 (E_INVAL caps.max_sz reserved).
//     The kernel may dispatch in either order; both produce E_INVAL,
//     which is the only outcome this test asserts on. This mirrors the
//     create_var_09 vs create_var_10 overlap.
//
// Action
//   1. create_page_frame(caps={r,w,max_sz=2}, props=(sz=3), pages=1)
//   2. expect vreg 1 == E_INVAL
//
// Assertions
//   1: create_page_frame returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // caps: r=1, w=1, max_sz=2 (1 GiB). max_sz=2 keeps test 05 from
    // firing while still being a valid value covered by the runner's
    // pf_ceiling (max_sz field = 3).
    const pf_caps = caps.PfCap{
        .r = true,
        .w = true,
        .max_sz = 2,
    };

    // props layout per §[create_page_frame] [2]:
    //   bits 0-1: sz
    //   bits 2-63: reserved (must be 0 to dodge test 08)
    // sz = 3 (reserved) is the field this test exercises.
    const props: u64 = 3;

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        props,
        1, // pages — nonzero (test 04 guard)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
