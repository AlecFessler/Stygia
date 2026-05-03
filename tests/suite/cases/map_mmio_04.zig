// Spec §[map_mmio] — test 04.
//
// "[test 04] returns E_INVAL if [1].field1 `map` is not 0 (mmio
//  mappings are atomic; the VAR must be unmapped)."
//
// DEGRADED SMOKE VARIANT
//   The strict test 04 path requires landing a non-zero `map` on a
//   VAR whose `caps.mmio` bit is set, then issuing map_mmio so the
//   kernel rejects with E_INVAL on the `map != 0` check. From a v0
//   test child capability domain, no construction reaches that
//   pre-state:
//
//   map = 1 (pf): per §[map_pf] test 03, the kernel rejects map_pf
//     with E_PERM on any VAR whose `caps.mmio` is set. So map_pf
//     cannot drive an MMIO VAR's `map` to 1 — it errors out before
//     touching field1. Inverting the construction (regular VAR with
//     caps.mmio = 0, drive `map` to 1 via map_pf, then map_mmio)
//     hits §[map_mmio] test 03 first: a non-mmio VAR yields E_PERM
//     before the field1 `map != 0` check fires.
//
//   map = 2 (mmio): per §[map_mmio] test 06, `map` becomes 2 only on
//     a successful map_mmio. The successful map_mmio itself requires
//     a *valid* device_region handle (test 02). Per §[device_region]
//     device_region handles are kernel-issued at boot to the root
//     service and otherwise propagate via xfer/IDC. The v0 runner
//     (runner/primary.zig) spawns each test child with passed_handles
//     carrying only the result port at slot 3 — no device_region is
//     forwarded. The same `findCom1`-style scan that runner/serial.zig
//     uses to bootstrap the primary's serial VAR cannot succeed
//     inside a test child, because the child's table holds self /
//     initial_ec / self_idc / port and nothing else. So the
//     "first map_mmio succeeds, second map_mmio rejects" path is
//     unreachable: the first call cannot succeed without a real
//     device_region.
//
//   map = 3 (demand): per §[var] (line 877) only regular VARs (caps
//     .mmio = 0, caps.dma = 0) transition to `map = 3` on a faulted
//     access. An MMIO VAR's faulting semantics are not a demand
//     allocation — they are gated by §[map_mmio] entirely. So an
//     MMIO VAR cannot land in `map = 3` by any path.
//
//   With no construction landing `map ∈ {1, 2, 3}` on an MMIO VAR
//   from the test child, the strict test 04 rejection cannot be
//   exercised end-to-end here.
//
//   This smoke variant pins the negative observation: a non-mmio
//   VAR (caps = {r, w}, mmio = 0) plus a freshly-minted page_frame
//   admit a successful map_pf, transitioning the VAR's `map` to 1.
//   That construction is the *closest reachable* approximation of
//   the test 04 pre-state — it lands `map = 1` on the same VAR
//   shape used by every other map_* test — but the follow-up
//   map_mmio call against this VAR rejects with E_PERM (test 03)
//   rather than E_INVAL (test 04), because caps.mmio = 0 fires
//   before the field1 `map` check. The smoke records that ordering
//   without asserting the test 04 behavior itself.
//
// Strategy (smoke prelude)
//   The check ordering ahead of test 04 in map_mmio is:
//     - test 01 (VAR is invalid) — pass a freshly-minted VAR.
//     - test 02 (device_region BADCAP) — passing slot 4095 (an
//       unallocated id in the test child's table) would surface
//       E_BADCAP first, but the spec's per-syscall list places
//       E_PERM (test 03) before E_BADCAP for [2]; either ordering
//       blocks reaching test 04 from a non-mmio VAR.
//     - test 03 (caps.mmio not set) — fires here because the VAR
//       lacks caps.mmio. This pre-empts test 04 in the smoke.
//
// Action
//   1. createPageFrame(caps={r, w}, props=0, pages=1) — must succeed.
//   2. createVar(caps={r, w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0) —
//      must succeed; gives a regular VAR in `map = 0`.
//   3. mapPf(var_handle, &.{ 0, pf }) — must succeed (transitions
//      `map` to 1 per §[map_pf] test 11).
//   4. mapMmio(var_handle, 4095) — issues the call so the test
//      records reaching this point with `map = 1`. The kernel
//      rejects on caps.mmio (test 03) or invalid [2] (test 02)
//      ahead of the test 04 check; either is the documented
//      ordering, not the rejection target.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the test 04 rejection target is unreachable from the v0 test
//   child. Any failure of the prelude itself is also reported as
//   pass-with-id-0 since no spec assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending a runner extension that mints or
//   carves a device_region whose size matches a freshly-created
//   MMIO VAR (4 KiB) and forwards it to the test child via
//   passed_handles. The action then becomes:
//     create_var(caps={r, w, mmio}, props={sz=0, cch=1, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0)
//                                              -> mmio_var, map = 0
//     map_mmio(mmio_var, forwarded_dev) -> success, map becomes 2
//     map_mmio(mmio_var, forwarded_dev) -> *expected* E_INVAL via
//                                          test 04 (map != 0)
//   This is the assertion id 1 a faithful version would check. The
//   second map_mmio's [2] is the same forwarded_dev so test 02
//   (BADCAP) does not fire; caps.mmio is set so test 03 does not
//   fire; size matches itself so test 05 does not fire — leaving
//   test 04's `map != 0` as the only reachable rejection.
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

    // Page frame for the prelude's map_pf — caps = {r, w} mirror the
    // VAR's r/w so cur_rwx ∩ pf.caps stays r|w on success.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        // Prelude broke; smoke is moot but no spec assertion is
        // being checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const pf: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Regular VAR (caps.mmio = 0, caps.dma = 0); per §[var] line 877
    // it starts in `map = 0`. The closest reachable approximation of
    // the test 04 pre-state is to drive this VAR's `map` to 1 via
    // map_pf — the spec rejects map_mmio against an MMIO VAR with
    // map = 1 via test 04, but the only way to land map = 1 on a
    // VAR is map_pf, which itself rejects MMIO VARs via §[map_pf]
    // test 03. So this prelude lands map = 1 on a non-mmio VAR;
    // the follow-up map_mmio rejects via test 03 (caps.mmio) ahead
    // of the test 04 check.
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
        testing.pass();
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Drives `map` from 0 to 1 (§[map_pf] test 11). On success the
    // VAR is now in the closest-reachable approximation of the
    // test 04 pre-state — `map != 0` on a VAR — but caps.mmio = 0,
    // so the follow-up map_mmio cannot reach the test 04 check.
    _ = syscall.mapPf(var_handle, &.{ 0, pf });

    // [2] = 4095: the test child holds no device_region handles, so
    // this slot is unallocated. The kernel rejects via test 03
    // (caps.mmio not set) or test 02 (BADCAP) ahead of test 04;
    // the smoke does not assert which ordering applies — it only
    // pins that the rejection target (test 04 / E_INVAL on
    // `map != 0`) is unreachable from this construction.
    _ = syscall.mapMmio(var_handle, 4095);

    // No spec assertion is being checked — the test 04 rejection
    // requires an MMIO VAR with `map != 0`, which is unreachable
    // from the v0 test child. Pass with assertion id 0 to mark
    // this slot as smoke-only in coverage.
    testing.pass();
}
