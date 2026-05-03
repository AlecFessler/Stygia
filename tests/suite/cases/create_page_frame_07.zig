// Spec §[create_page_frame] create_page_frame — test 07.
//
// "[test 07] returns E_INVAL if props.sz exceeds caps.max_sz."
//
// Strategy
//   Pick a `caps`/`props` pair where caps.max_sz is strictly less than
//   props.sz, and where every other spec-mandated failure path is
//   neutralized so test 07's gate is the only one that can fire.
//
//   caps:    {r=1, w=1, max_sz=0}      → caps.max_sz = 0 (4 KiB ceiling)
//   props:   sz=1                       → props.sz = 1 (2 MiB)
//   pages=1                             → minimal valid pages
//
//   Cross-check against the other tests in this section:
//
//     - test 01 (E_PERM, missing crpf on self): the runner-provided
//       self-handle has `crpf` set (see runner/primary.zig), so this
//       cannot fire.
//     - test 02 (E_PERM, r/w/x not subset of pf_ceiling.max_rwx):
//       runner mints pf_ceiling.max_rwx = 0b111, so {r,w} is trivially
//       a subset.
//     - test 03 (E_PERM, caps.max_sz exceeds pf_ceiling.max_sz):
//       runner's pf_ceiling.max_sz = 3 (all bits set); caps value of
//       0 is the floor. No fire.
//     - test 04 (E_INVAL, pages = 0): pages = 1 here.
//     - test 05 (E_INVAL, caps.max_sz = 3): caps.max_sz = 0 here.
//     - test 06 (E_INVAL, props.sz = 3): props.sz = 1 here.
//     - test 08 (E_INVAL, reserved bits): all reserved bits are zero
//       in both [1] and [2].
//
//   With every other path neutralized, the only spec-mandated failure
//   here is props.sz (1) > caps.max_sz (0), which must surface E_INVAL.
//
// Action
//   create_page_frame(
//     caps  = {r, w, max_sz=0},
//     props = sz=1,
//     pages = 1,
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

    const pf_caps = caps.PfCap{
        .r = true,
        .w = true,
        .max_sz = 0, // 4 KiB ceiling on the page size encoded in props.sz
    };
    // §[create_page_frame] [2] props: bits 0-1 = sz. sz = 1 (2 MiB)
    // exceeds caps.max_sz (0 = 4 KiB).
    const props: u64 = 1;

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        props,
        1, // pages = 1
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
