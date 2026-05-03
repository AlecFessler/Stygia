// Spec §[create_page_frame] — test 04.
//
// "[test 04] returns E_INVAL if [3] pages is 0."
//
// Strategy
//   To isolate the pages == 0 check we must make every other
//   create_page_frame-prelude check pass:
//     - caller self-handle has `crpf` (test 01): the runner grants
//       it on every spawned test domain (see runner/primary.zig).
//     - caps.r/w/x ⊆ pf_ceiling.max_rwx (test 02): use only r,w which
//       the runner ceiling permits (max_rwx = 0b111).
//     - caps.max_sz ≤ pf_ceiling.max_sz (test 03): leave max_sz = 0,
//       within the runner's ceiling.max_sz = 3.
//     - caps.max_sz != 3 (test 05): max_sz = 0 satisfies this.
//     - props.sz != 3 (test 06): props.sz = 0 satisfies this.
//     - props.sz ≤ caps.max_sz (test 07): props.sz = 0, caps.max_sz =
//       0 satisfies this.
//     - reserved bits clean (test 08): all unused fields zero.
//   That leaves pages = 0 as the only spec-mandated failure path.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=0)
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

    const pf_caps = caps.PfCap{ .r = true, .w = true };

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), reserved bits clean
        0, // pages = 0 — the spec violation under test
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
