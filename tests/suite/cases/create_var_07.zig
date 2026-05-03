// Spec §[create_var] create_var — test 07.
//
// "[test 07] returns E_INVAL if caps.max_sz is 3 (reserved)."
//
// Strategy
//   §[var] defines `caps.max_sz` as a 2-bit field encoding the largest
//   page size the VAR may hold. Values 0/1/2 select 4 KiB / 2 MiB /
//   1 GiB; value 3 is _reserved and must be rejected with E_INVAL.
//
//   To isolate the reserved-max_sz check we make every prior check
//   pass:
//     - the root service self-handle holds `crvr` (test 01)
//     - caps.r/w are within the root's var_inner_ceiling and no x is
//       requested (test 02)
//     - max_sz value 3 is at-or-below any ceiling because the ceiling
//       is itself <= 3; in practice the kernel's reserved-value check
//       must be ordered before the ceiling comparison (or the ceiling
//       must itself reject 3), so this branch is the spec-mandated
//       failure path even when the ceiling permits "3"
//     - caps.mmio = 0 so test 04 cannot fire
//     - pages = 1 (test 05)
//     - preferred_base = 0 so test 06 cannot fire
//     - props.sz = 0 so test 08/09/10 cannot fire (sz=0 != 3, and
//       0 does not exceed any max_sz, reserved or otherwise)
//     - caps.dma = 0 so tests 12/14/15 cannot fire
//     - props.cur_rwx = 0b011 (r|w) is a subset of caps.r/w (test 16)
//     - all other bits are zero (test 17)
//
//   `lib.caps.VarCap` declares `max_sz: u2`, so the typed wrapper
//   accepts value 3 directly via @bitCast — no raw-u16 bypass needed.
//
// Action
//   create_var(caps={r, w, max_sz=3}, props={cur_rwx=0b011, sz=0,
//              cch=0}, pages=1, preferred_base=0, device_region=0)
//   must return E_INVAL.
//
// Assertion
//   1: create_var did not return E_INVAL.

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
        .max_sz = 3, // reserved
    };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0; cch = 0

    const result = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages
        0, // preferred_base
        0, // device_region
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
