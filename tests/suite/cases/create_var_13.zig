// Spec §[create_var] create_var — test 13.
//
// "[test 13] returns E_INVAL if caps.mmio = 1 and caps.dma = 1."
//
// Strategy
//   `mmio` and `dma` are mutually exclusive on a VAR's caps. An MMIO
//   VAR is bound to a port_io / mmio device_region by `map_mmio`; a
//   DMA VAR routes the bound device's IOMMU accesses to page_frames.
//   A single VAR cannot serve both roles, so the kernel must reject
//   any `create_var` whose [1] caps word has both bits set.
//
//   The runner (runner/primary.zig) installs the test domain with a
//   permissive `var_inner_ceiling`, so r/w and mmio are permitted by
//   the caller's ceiling — tests 02 (rwx subset) and 04 (mmio not
//   permitted) cannot intercept.
//
//   Tests 11 (mmio+x) and 12 (dma+x) are sidestepped by leaving
//   caps.x clear and using cur_rwx = 0b011 (r|w only).
//
//   Test 14 (dma=1 with invalid device_region handle) and test 15
//   (dma=1 with [5] missing the `dma` cap) target the same dma=1
//   path. The kernel must surface the mmio+dma E_INVAL before any
//   device_region lookup, since the caps word is statically
//   contradictory regardless of [5].
//
//   props.sz = 0 keeps test 08 silent (caps.mmio = 1 ⇒ sz = 0). pages
//   = 1 satisfies test 05. caps.max_sz = 0 satisfies tests 03/07/10.
//   props.cur_rwx ⊆ caps.{r,w} satisfies test 16. Reserved bits are
//   clear (test 17). preferred_base = 0 lets the kernel choose
//   (test 06 silent).
//
// Action
//   create_var(caps={r,w,mmio,dma}, props={cur_rwx=0b011, sz=0, cch=0},
//              pages=1, preferred_base=0, device_region=0)
//
// Assertion
//   1: result.v1 != E_INVAL — kernel did not reject mmio+dma with
//      E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps_word = caps.VarCap{
        .r = true,
        .w = true,
        .mmio = true,
        .dma = true,
    };

    // props: cur_rwx = 0b011 (r|w, subset of caps.r/w), sz = 0
    // (4 KiB, mandatory when caps.mmio = 1), cch = 0.
    const props: u64 = 0b011;

    const result = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        props,
        1, // pages
        0, // preferred_base = kernel chooses
        0, // device_region (caps.dma = 1 but mmio+dma is rejected
        //                  before the device handle is consulted)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
