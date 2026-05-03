// Spec §[create_var] — test 24.
//
// "[test 24] on success, when [4] preferred_base = 0, the assigned
//  base address lies within the ASLR zone (see §[address_space])."
//
// Strategy
//   With preferred_base = 0 the kernel chooses the base. Spec
//   §[address_space] pins that choice to the ASLR zone, which on
//   x86-64 is `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)`. Drive
//   the standard create_var success prelude (caps={r,w}, props.sz=0,
//   cur_rwx=r|w, pages=1) and assert the returned base falls in that
//   half-open range.
//
//   Other create_var failure paths neutralized:
//     - test 01 (E_PERM no `crvr`): runner grants `crvr`.
//     - tests 02-17: caps={r,w}, props.sz=0, cur_rwx=0b011, no
//       mmio/dma, no reserved bits, pages=1, base=0.
//
// Action
//   1. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0)
//      — must succeed; vreg 2 carries the assigned base.
//   2. base in [0x1000, 0x0000_1000_0000_0000).
//
// Assertions
//   1: createVar returned an error word in vreg 1.
//   2: assigned base lies outside the ASLR zone.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const ASLR_LO: u64 = 0x0000_0000_0000_1000;
const ASLR_HI: u64 = 0x0000_1000_0000_0000;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages
        0, // preferred_base — kernel chooses (must land in ASLR zone)
        0, // device_region
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }

    const base: u64 = cv.v2;
    if (base < ASLR_LO or base >= ASLR_HI) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
