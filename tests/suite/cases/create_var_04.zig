// Spec §[create_var] — test 04.
//
// "[test 04] returns E_PERM if caps.mmio = 1 and the caller's
//  `var_inner_ceiling` does not permit mmio."
//
// FAITHFUL E_PERM PATH IS UNREACHABLE UNDER THE CURRENT RUNNER.
//   The mock runner in `tests/suite/runner/primary.zig` mints child
//   capability domains with `var_inner_ceiling = 0x01FF`, which
//   includes mmio (bit 5 within the 16-bit var_inner_ceiling, i.e. u64
//   bit 13 of `ceilings_inner`). Per §[create_capability_domain] [2],
//   a child cannot widen its ceiling beyond the parent's, so a test
//   spawned by this runner cannot construct a domain whose
//   `var_inner_ceiling` lacks mmio. Test 04's guard therefore cannot
//   fire as long as this runner is the test harness — the parent
//   already permits mmio.
//
//   This file lands a degraded smoke variant that exercises the
//   ordering of mmio-related gates instead. With caps.mmio = 1 and
//   props.sz = 1 (4 KiB → 2 MiB), the only spec-mandated rejection
//   that can possibly fire is test 08:
//     "returns E_INVAL if caps.mmio = 1 and props.sz != 0".
//   Test 04 itself cannot fire because the runner permits mmio in the
//   ceiling. The remaining mmio-adjacent gates are all dodged:
//     - test 11 (caps.mmio=1 and caps.x set): caps.x = 0.
//     - test 13 (caps.mmio=1 and caps.dma=1): caps.dma = 0.
//   So the kernel's only legal answer is E_INVAL via test 08, which
//   is what this file asserts. When the runner is later upgraded to
//   spawn a child with a stripped-mmio ceiling, this file should be
//   rewritten to the faithful E_PERM shape.
//
// Strategy
//   Mirror the mmio createVar shape from runner/serial.zig (cch=1 uc,
//   pages=1, var_caps with r|w|mmio) but flip props.sz from 0 to 1 so
//   the mmio-specific sz=0 invariant trips. Per the comment block in
//   serial.zig, that is the single-page MMIO arrangement the kernel
//   accepts. Other guards are dodged the same way the other create_var
//   tests dodge them:
//     - test 01 (no `crvr`): runner grants `crvr` to spawned tests.
//     - test 02 (caps.r/w/x ⊄ ceiling.r/w/x): caps.r,w only.
//     - test 03 (caps.max_sz > ceiling.max_sz): caps.max_sz = 0.
//     - test 04 (faithful): unreachable; see header above.
//     - test 05 (pages = 0): pages = 1.
//     - test 06 (preferred_base misaligned): preferred_base = 0.
//     - test 07 (caps.max_sz = 3): caps.max_sz = 0.
//     - test 09 (props.sz = 3): props.sz = 1.
//     - test 10 (props.sz > caps.max_sz): with caps.mmio = 1 the spec
//       mandates props.sz = 0, so test 08 must take precedence; once
//       this file is rewritten to a faithful E_PERM the props.sz = 0
//       form will dodge this naturally.
//     - test 11 (mmio + caps.x): caps.x = 0.
//     - test 12 (dma + caps.x): caps.x = 0, caps.dma = 0.
//     - test 13 (mmio + dma): caps.dma = 0.
//     - test 14/15 (dma+device_region paths): caps.dma = 0; [5] = 0.
//     - test 16 (cur_rwx ⊄ caps.r/w/x): cur_rwx = r|w ⊆ caps.r|w.
//     - test 17 (reserved bits): all unused fields zero.
//
// Action
//   create_var(caps={r,w,mmio}, props={cur_rwx=r|w, sz=1, cch=1},
//              pages=1, preferred_base=0, device_region=0)
//   must return E_INVAL (test 08 — the only legal rejection in this
//   degraded variant).
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
        .mmio = true,
    };
    // props layout per §[create_var] [2]:
    //   bits 0-2: cur_rwx
    //   bits 3-4: sz
    //   bits 5-6: cch
    //   bits 7-63: reserved
    // sz = 1 with mmio = 1 is the violation under test (test 08). cch
    // = 1 (uc) matches the cache type runner/serial.zig uses for its
    // own MMIO VAR.
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (1 << 3) | // sz = 1 (2 MiB) — must be 0 when mmio = 1
        0b011; // cur_rwx = r|w

    const result = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages — nonzero (test 05 guard)
        0, // preferred_base — kernel chooses (test 06 guard)
        0, // device_region — caps.dma = 0 so this is ignored
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
