// Spec §[create_vmar] create_vmar — test 11.
//
// "[test 11] returns E_INVAL if caps.mmio = 1 and caps.x is set."
//
// Strategy
//   `mmio` and `x` are mutually exclusive on a VMAR's caps because an
//   MMIO range backs device registers, not executable code. The kernel
//   must reject any `create_vmar` whose [1] caps word has both bits set,
//   regardless of which other bits are populated.
//
//   The runner (runner/primary.zig) installs the test domain with
//   `vmar_inner_ceiling = 0x01FF` covering bits 0-8 of the VmarCap layout,
//   so r/w/x and mmio are all permitted by the caller's ceiling. That
//   keeps tests 02 (rwx-subset) and 04 (mmio-not-permitted) from
//   firing before the mmio+x check is reached.
//
//   Per §[create_vmar], when `caps.mmio = 1` the spec also requires
//   `props.sz = 0` (test 08). We set props.sz = 0 to keep that path
//   clean. props.cur_rwx is set to a subset of caps.r/w/x (test 16),
//   pages = 1 is non-zero (test 05), and dma is left clear so tests
//   12 (dma+x), 13 (mmio+dma), 14 (dma+invalid devreg), and 15
//   (dma+missing dma cap) cannot intercept. caps.max_sz = 0 avoids
//   tests 03/07/10. Reserved bits are clear (test 17 silent).
//
//   With every other gate satisfied, the only remaining failure mode
//   is the mmio+x rule — the kernel must surface E_INVAL.
//
// Action
//   create_vmar(caps={r,w,x,mmio}, props={cur_rwx=0b111, sz=0, cch=0},
//              pages=1, preferred_base=0, device_region=0)
//
// Assertion
//   1: result.v1 != E_INVAL — kernel did not reject mmio+x with E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps_word = caps.VmarCap{
        .r = true,
        .w = true,
        .x = true,
        .mmio = true,
    };

    // props: cur_rwx = 0b111 (subset of caps.r/w/x), sz = 0 (4 KiB,
    // mandatory when caps.mmio = 1), cch = 0.
    const props: u64 = 0b111;

    const result = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        1, // pages
        0, // preferred_base = kernel chooses
        0, // device_region (unused; caps.dma = 0)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
