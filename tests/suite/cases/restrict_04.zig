// Spec §[capabilities] restrict — test 04.
//
// "[test 04] returns E_PERM if the handle is a VAR handle and [2].caps'
//  restart_policy (bits 9-10) numeric value exceeds the handle's current
//  restart_policy."
//
// Strategy
//   restart_policy on a VAR handle is a 2-bit numeric enum in cap bits
//   9-10 (0=free, 1=decommit, 2=preserve, 3=snapshot) that uses
//   numeric monotonicity, not bitwise subset semantics. Test 04 is the
//   VAR-handle analogue of test 03 (which covers the EC-handle path).
//
//   Mint a regular VAR (mmio=0, dma=0) with `restart_policy = 0`
//   (free) plus r/w. Then call restrict, keeping every other cap bit
//   identical, but raising restart_policy to 1 (decommit). The new
//   numeric value (1) exceeds the current (0); the kernel must reject
//   with E_PERM.
//
//   Choices that keep create_var off the other E_INVAL/E_PERM paths:
//     - caps.r = caps.w = true, no x/mmio/dma — within
//       var_inner_ceiling = 0x01FF granted by the runner.
//     - props.cur_rwx = 0b011 (r|w) — subset of caps.r/w/x (test 16).
//     - props.sz = 0 (4 KiB), caps.max_sz = 0 — no sz mismatch
//       (tests 07, 09, 10), and 4 KiB is within the inner ceiling.
//     - props.cch = 0 (wb).
//     - pages = 1 — nonzero (test 05).
//     - preferred_base = 0 — kernel chooses (test 06 inert).
//     - device_region = 0 — ignored when caps.dma = 0.
//
// Action
//   1. create_var(caps={r,w,rp=0}, props={cur_rwx=r|w}, pages=1, ...)
//   2. restrict(var, caps={r,w,rp=1})
//
// Assertions
//   1: setup syscall failed (create_var returned an error word)
//   2: restrict returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 0,
    };
    // §[create_var] props word: cur_rwx in bits 0-2, sz in bits 3-4,
    // cch in bits 5-6. cur_rwx = r|w = 0b011; sz = 0 (4 KiB); cch = 0 (wb).
    const props: u64 = 0b011;
    const cvar = syscall.createVar(
        @as(u64, initial.toU16()),
        props,
        1, // pages
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    const expanded = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 1,
    };
    const new_caps_word: u64 = @as(u64, expanded.toU16());
    const result = syscall.restrict(var_handle, new_caps_word);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
