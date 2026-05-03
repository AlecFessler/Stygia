// Spec §[create_var] create_var — test 12.
//
// "[test 12] returns E_INVAL if caps.dma = 1 and caps.x is set."
//
// Strategy
//   §[var]: "`mmio` and `dma` are mutually exclusive. `dma` VARs
//   cannot have `x` set." Test 12 enforces the latter half of that
//   rule for the create path: requesting a DMA-flagged VAR whose
//   handle caps include `x` must be rejected with E_INVAL.
//
//   The runner-supplied child domain has self-handle caps including
//   `crvr` (see runner/primary.zig spawnOne) and a `var_inner_ceiling`
//   = 0x01FF (bits 0..8 set: move, copy, r, w, x, mmio, max_sz[0..1],
//   dma — see §[create_capability_domain] field0 layout). So r/w/x
//   plus dma are individually permitted by the ceiling, isolating the
//   E_INVAL path on the dma+x combination rather than on a missing
//   ceiling permission.
//
//   We construct the syscall args so every prior gate in the
//   create_var test list passes:
//     * pages = 1                              (test 05: not zero)
//     * preferred_base = 0                     (test 06: kernel chooses)
//     * caps.max_sz = 0                        (test 07: not 3)
//     * caps.mmio = 0                          (tests 04, 08, 11, 13 inert)
//     * props.sz = 0                           (test 09: not 3, test 10: <= max_sz)
//     * props.cur_rwx = 0b111                  (test 16: subset of caps.r/w/x)
//     * no reserved bits set in [1] or [2]     (test 17)
//
//   That leaves test 12 as the first gate the kernel must trip. The
//   spec also exposes test 14 (E_BADCAP if caps.dma = 1 and [5] is
//   not a valid device_region handle), and we pass [5] = 0 which is
//   the SLOT_SELF id — never a device_region. Test 12 is a pure
//   content-validation check on [1] that does not require
//   dereferencing [5], so the kernel must report E_INVAL ahead of
//   the E_BADCAP path.
//
// Action
//   create_var(caps={r,w,x,dma}, props={cur_rwx=0b111, sz=0, cch=0},
//              pages=1, preferred_base=0, device_region=0)
//   must return E_INVAL.
//
// Assertions
//   1: vreg 1 is not E_INVAL on the dma+x create_var.

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
        .x = true,
        .dma = true,
    };
    const caps_word: u64 = @as(u64, var_caps.toU16());
    const props: u64 = 0b111; // cur_rwx = r|w|x; sz = 0; cch = 0.

    const result = syscall.createVar(
        caps_word,
        props,
        1, // pages
        0, // preferred_base — kernel chooses
        0, // device_region — irrelevant; test 12 fires first
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
