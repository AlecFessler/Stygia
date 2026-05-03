// Spec §[create_var] — test 23.
//
// "[test 23] returns E_INVAL if [4] preferred_base is nonzero and the
//  requested range does not lie wholly within the static zone (see
//  §[address_space])."
//
// Strategy
//   The static zone starts at 0x0000_1000_0000_0000 on x86-64 (spec
//   §[address_space]); anything below that is the ASLR zone. A
//   preferred_base in the ASLR zone — but page-aligned and not zero —
//   exercises this exact rule: the range is a valid VA, it doesn't
//   trip the alignment check (test 06), it doesn't trip the
//   pages == 0 check (test 05), and the only spec-mandated rejection
//   is "not wholly within the static zone".
//
//   Other create_var failure paths neutralized:
//     - test 01 (E_PERM no `crvr`): runner grants `crvr` on the
//       child's self-handle.
//     - test 02 (E_PERM caps r/w/x not subset): caps = {r, w} are in
//       the runner's var_inner_ceiling.
//     - tests 03, 04, 07-17: caps = {r, w}, props.sz = 0,
//       cur_rwx = 0b011, no mmio/dma, all reserved bits zero.
//     - test 06 (E_INVAL not aligned): preferred_base = 0x1000 is
//       page-aligned.
//
// Action
//   1. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0x1000, device_region=0)
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
        1, // pages
        0x1000, // preferred_base — first page of ASLR zone, NOT in static zone
        0, // device_region
    );
    if (cv.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
