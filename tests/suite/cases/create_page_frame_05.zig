// Spec §[create_page_frame] create_page_frame — test 05.
//
// "[test 05] returns E_INVAL if caps.max_sz is 3 (reserved)."
//
// Strategy
//   §[page_frame] PfCap defines `max_sz` as a 2-bit field encoding the
//   largest page size the page_frame's holder may select for a backing
//   page. Values 0/1/2 select 4 KiB / 2 MiB / 1 GiB; value 3 is
//   _reserved and must be rejected with E_INVAL.
//
//   To isolate the reserved-max_sz check we make every prior check
//   pass:
//     - the runner-spawned domain's self-handle holds `crpf` (test 01)
//     - caps.r/w/x are within the runner-provided pf_ceiling.max_rwx
//       (= 0b111); we leave them all clear here, which is trivially a
//       subset (test 02)
//     - max_sz value 3 sits at-or-below pf_ceiling.max_sz (= 3); the
//       kernel's reserved-value check must therefore be ordered before
//       the ceiling comparison (or the ceiling itself must reject 3),
//       so this branch is the spec-mandated failure path even when the
//       ceiling permits "3" (test 03)
//     - pages = 1 (test 04)
//     - props.sz = 0 (4 KiB) so test 06 (sz != 3) and test 07
//       (props.sz <= caps.max_sz) cannot fire
//     - all reserved bits zero (test 08)
//
//   `lib.caps.PfCap` declares `max_sz: u2`, so the typed wrapper
//   accepts value 3 directly via @bitCast — no raw-u16 bypass needed.
//
// Action
//   create_page_frame(caps={max_sz=3}, props=0, pages=1) must return
//   E_INVAL.
//
// Assertion
//   1: create_page_frame did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const pf_caps = caps.PfCap{
        .max_sz = 3, // reserved
    };
    const props: u64 = 0; // sz = 0 (4 KiB), reserved bits clean

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        props,
        1, // pages
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
