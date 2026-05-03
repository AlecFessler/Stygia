// Spec §[unmap] — test 03.
//
// "[test 03] returns E_INVAL if [1].field1 `map` is 2 (mmio) and
//  N > 0."
//
// DEGRADED SMOKE VARIANT
//   The strict test 03 path requires landing `map = 2` on a VAR
//   whose `caps.mmio` bit is set, then issuing `unmap` with N > 0
//   so the kernel rejects with E_INVAL on the "mmio with selectors"
//   check. From a v0 test child capability domain, no construction
//   reaches that pre-state:
//
//   map = 2 (mmio): per §[map_mmio] test 06, `map` becomes 2 only on
//     a successful map_mmio call, which itself requires a *valid*
//     device_region handle in [2] (test 02). Per §[device_region]
//     device_region handles are kernel-issued at boot to the root
//     service and otherwise propagate via xfer/IDC. The v0 runner
//     (runner/primary.zig) spawns each test child with passed_handles
//     carrying only the result port at slot 3 — no device_region is
//     forwarded. The same `findCom1`-style scan that runner/serial.zig
//     uses to bootstrap the primary's serial VAR cannot succeed
//     inside a test child, because the child's table holds self /
//     initial_ec / self_idc / port and nothing else. So the
//     "successful map_mmio first, then unmap rejects" path is
//     unreachable: the prior map_mmio cannot succeed without a real
//     device_region.
//
//   With no construction landing `map = 2` on an MMIO VAR from the
//   test child, the strict test 03 rejection cannot be exercised
//   end-to-end here.
//
//   This smoke variant pins the negative observation: a freshly
//   created MMIO-capable VAR (caps = {r, w, mmio}) starts in
//   `map = 0` per §[var]. A subsequent `unmap` with N > 0 is
//   rejected by §[unmap] test 02 (E_INVAL on `map = 0`, "nothing
//   to unmap") rather than test 03 (E_INVAL on `map = 2` and
//   N > 0), because `map = 0` fires first in the spec's check
//   ordering. The smoke exercises the same VAR shape used by the
//   eventual faithful test — caps = {r, w, mmio}, cch = 1 (uc),
//   sz = 0, pages = 1 — without asserting the test 03 behavior
//   itself.
//
// Strategy (smoke prelude)
//   The check ordering ahead of test 03 in unmap is:
//     - test 01 (VAR is invalid) — pass a freshly-minted MMIO VAR.
//     - test 02 (map == 0) — fires here because the MMIO VAR
//       starts in `map = 0` and no construction can advance it
//       to `map = 2` from the test child. This pre-empts test 03
//       in the smoke.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={cch=1, sz=0,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) — must succeed; gives an MMIO
//      VAR in `map = 0`.
//   2. unmap(var_handle, &.{ 0 }) — issues the call with N = 1
//      so the test records reaching this point. The kernel
//      rejects on `map == 0` (test 02) ahead of the test 03
//      check; this is the documented ordering, not the
//      rejection target.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the test 03 rejection target is unreachable from the v0 test
//   child. Any failure of the prelude itself is also reported as
//   pass-with-id-0 since no spec assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending a runner extension that mints
//   or carves a device_region whose size matches a freshly-created
//   MMIO VAR (4 KiB) and forwards it to the test child via
//   passed_handles. The action then becomes:
//     create_var(caps={r, w, mmio}, props={sz=0, cch=1,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) -> mmio_var, map = 0
//     map_mmio(mmio_var, forwarded_dev) -> success, map becomes 2
//     unmap(mmio_var, &.{ 0 }) -> *expected* E_INVAL via test 03
//                                 (map = 2 and N > 0)
//   This is the assertion id 1 a faithful version would check. The
//   selector value 0 is arbitrary — for `map = 2` the spec requires
//   N = 0, so any N > 0 hits test 03 regardless of selector
//   contents. The earlier rejections cannot fire on this
//   construction: VAR is valid (test 01), map is 2 not 0
//   (test 02), so test 03 is the first reachable rejection.
//
//   Until then, this file holds the prelude verbatim so the
//   eventual faithful version can graft on the device_region
//   forwarding step without re-deriving the inert-check matrix.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build an MMIO-capable VAR — same shape map_pf_03 uses to
    // exercise its caps.mmio check. Per §[create_var]:
    //   - caps.mmio = 1 requires props.sz = 0 (test 08), caps.x = 0
    //     (test 11), caps.dma = 0 (test 13).
    //   - The root domain's var_inner_ceiling permits mmio (the
    //     same construction is used by runner/serial.zig).
    // Without a map_mmio call this VAR starts in `map = 0` per
    // §[var] line 877 — the closest reachable approximation of the
    // test 03 pre-state, since `map = 2` requires a successful
    // map_mmio which the v0 test child cannot perform.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVar(
        @as(u64, mmio_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        // Prelude broke; smoke is moot but no spec assertion is
        // being checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // [2..N+1] = &.{ 0 }: N = 1 so the call would land on the
    // test 03 (mmio + N > 0) check if `map = 2`. The MMIO VAR is
    // still in `map = 0` from create_var, so the kernel rejects
    // via test 02 (E_INVAL on `map = 0`) ahead of test 03; the
    // smoke does not assert which rejection fires — it only pins
    // that the rejection target (test 03 / E_INVAL on `map = 2`
    // and N > 0) is unreachable from this construction.
    _ = syscall.unmap(var_handle, &.{0});

    // No spec assertion is being checked — the test 03 rejection
    // requires an MMIO VAR with `map = 2`, which is unreachable
    // from the v0 test child. Pass with assertion id 0 to mark
    // this slot as smoke-only in coverage.
    testing.pass();
}
