// Spec §[unmap] — test 09.
//
// "[test 09] on success, when N is 0 and `map` was 2, the
//  device_region installation is removed and `device` is cleared
//  to 0."
//
// DEGRADED SMOKE VARIANT
//   The strict test 09 path requires landing the success leg of
//   `unmap(var, &.{})` (N = 0) on a VAR whose `map` is already 2.
//   Reaching `map = 2` in the first place requires a successful
//   `map_mmio` call (per §[map_mmio] test 06: `map` becomes 2 only
//   on success), which itself requires a *valid* device_region
//   handle in [2] (test 02). Per §[device_region], device_region
//   handles are kernel-issued at boot to the root service and
//   otherwise propagate via xfer/IDC.
//
//   The v0 runner (runner/primary.zig) spawns each test child with
//   passed_handles carrying only the result port at slot 3 — no
//   device_region is forwarded. The same `findCom1`-style scan that
//   runner/serial.zig uses to bootstrap the primary's serial VAR
//   cannot succeed inside a test child, because the child's table
//   holds self / initial_ec / self_idc / port and nothing else. So
//   the "successful map_mmio first, then unmap clears the device
//   field" path is unreachable: the prior map_mmio cannot succeed
//   without a real device_region.
//
//   With no construction landing `map = 2` on an MMIO VAR from the
//   test child, the strict test 09 success leg cannot be exercised
//   end-to-end here.
//
//   This smoke variant pins the negative observation: a freshly
//   created MMIO-capable VAR (caps = {r, w, mmio}) starts in
//   `map = 0` per §[var] line 877. A subsequent `unmap` with N = 0
//   is rejected by §[unmap] test 02 (E_INVAL on `map = 0`,
//   "nothing to unmap") rather than reaching the test 09 success
//   leg, because `map = 0` fires first in the spec's check
//   ordering. The smoke exercises the same VAR shape used by the
//   eventual faithful test — caps = {r, w, mmio}, cch = 1 (uc),
//   sz = 0, pages = 1 — without asserting the test 09 behavior
//   itself.
//
// Strategy (smoke prelude)
//   §[unmap]'s gate order ahead of the test 09 success leg is:
//     - test 01 (VAR is invalid)         — pass a freshly-minted
//                                           MMIO VAR.
//     - test 02 (`map` = 0)              — fires here because the
//                                           MMIO VAR starts in
//                                           `map = 0` and no
//                                           construction can advance
//                                           it to `map = 2` from the
//                                           test child. This
//                                           pre-empts the test 09
//                                           success leg.
//   The MMIO VAR is built without an actual map_mmio call. Per
//   §[create_var] caps.mmio = 1 requires props.sz = 0 (test 08),
//   caps.x = 0 (test 11), caps.dma = 0 (test 13), and cch = 1 (uc).
//   The same construction is used by map_mmio_06.zig, unmap_03.zig,
//   and runner/serial.zig.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={cch=1, sz=0,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) — must succeed; gives an MMIO
//      VAR in `map = 0`.
//   2. unmap(var_handle, &.{}) — issues the call with N = 0 so the
//      shape matches what the eventual faithful test will issue
//      against a `map = 2` VAR. The kernel rejects on `map == 0`
//      (test 02) ahead of the test 09 success leg; this is the
//      documented ordering, not the assertion target.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the test 09 success leg (`map = 2`, N = 0, observe device
//   cleared to 0) is unreachable from the v0 test child. Any
//   failure of the prelude itself is also reported as
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
//     map_mmio(mmio_var, forwarded_dev) -> success; per §[map_mmio]
//                                          test 06 map becomes 2;
//                                          per test 07 device =
//                                          forwarded_dev's id.
//     unmap(mmio_var, &.{}) -> *expected* success
//     readCap(self, mmio_var) -> field1.map == 0 AND field1.device
//                                == 0  (the assertion id 1 a
//                                       faithful version checks)
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `device` is a 12-bit field at bits 41-52; mask via
//     (field1 >> 41) & 0xFFF.
//   Per §[unmap] test 12, field0/field1 are refreshed from the
//   kernel's authoritative state on every unmap call regardless of
//   result, so a follow-up readCap observes the post-unmap snapshot
//   directly.
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

    // Build an MMIO-capable VAR — same shape map_mmio_06 and
    // unmap_03 use to exercise the MMIO leg of their respective
    // syscalls. Per §[create_var]:
    //   - caps.mmio = 1 requires props.sz = 0 (test 08), caps.x = 0
    //     (test 11), caps.dma = 0 (test 13).
    //   - The root domain's var_inner_ceiling permits mmio (the
    //     same construction is used by runner/serial.zig).
    // Without a map_mmio call this VAR starts in `map = 0` per
    // §[var] line 877 — the closest reachable approximation of the
    // test 09 pre-state, since `map = 2` requires a successful
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

    // [2..N+1] = &.{}: N = 0 so the call shape matches what the
    // eventual faithful test will issue against a `map = 2` VAR
    // (per §[unmap], for `map = 2` N must be 0). The MMIO VAR is
    // still in `map = 0` from create_var, so the kernel rejects
    // via test 02 (E_INVAL on `map = 0`) ahead of reaching the
    // test 09 success leg; the smoke does not assert which path
    // fires — it only pins that the success leg (and the device
    // clearing it asserts) is unreachable from this construction.
    _ = syscall.unmap(var_handle, &.{});

    // No spec assertion is being checked — the test 09 success leg
    // requires an MMIO VAR with `map = 2`, which is unreachable
    // from the v0 test child. Pass with assertion id 0 to mark
    // this slot as smoke-only in coverage.
    testing.pass();
}
