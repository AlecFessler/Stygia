// Spec §[map_mmio] — test 03.
//
// "[test 03] returns E_PERM if [1] does not have the `mmio` cap."
//
// Strategy
//   To isolate the caps.mmio rejection in map_mmio we need:
//     - a valid VAR handle so test 01 (E_BADCAP for an invalid VAR)
//       does not fire ahead of test 03.
//     - the VAR's `caps.mmio` bit must be 0 — that is the spec
//       violation under test.
//   Test 02 (E_BADCAP for an invalid device_region) is the only
//   earlier check that could pre-empt this assertion. The test
//   domain has no device_region handles, so [2] is forced to an
//   unused slot id (4095). Per the spec's own per-syscall test
//   list, E_PERM (test 03) follows the handle-validity gates
//   (tests 01, 02). The kernel's gate order is therefore expected
//   to consult [2]'s handle validity before [1]'s caps.mmio bit,
//   which would surface E_BADCAP rather than E_PERM. This test
//   asserts E_PERM regardless: a successful run confirms the
//   kernel checks [1]'s caps.mmio independently of [2]'s validity;
//   a failure here is a spec-vs-kernel ordering disagreement worth
//   surfacing.
//
//   The non-mmio VAR is built with caps = {r, w}, props.sz = 0
//   (4 KiB), props.cch = 0, props.cur_rwx = 0b011 (r|w), pages = 1
//   — the same construction as create_var_05's positive prelude.
//   No prior map_* call is needed; test 03 turns purely on
//   `caps.mmio = 0`, not on the field1 `map` state.
//
// Action
//   1. createVar(caps={r,w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0)
//      — must succeed.
//   2. mapMmio(var_handle, 4095) — must return E_PERM in vreg 1.
//
// Assertion
//   1: vreg 1 was not E_PERM after mapMmio on a non-mmio VAR.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a non-mmio VAR — caps.mmio = 0 is the spec violation
    // under test; every other create_var precondition is satisfied.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // [2] = 4095: the test domain holds no device_region handles,
    // so this slot is unallocated. The spec's test ordering puts
    // E_BADCAP for an invalid [2] (test 02) ahead of E_PERM (test
    // 03); a passing assertion here means the kernel checks
    // caps.mmio before consulting [2].
    const mm = syscall.mapMmio(var_handle, 4095);
    if (mm.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
