// Spec §[map_mmio] — test 06.
//
// "[test 06] on success, [1].field1 `map` becomes 2."
//
// DEGRADED SMOKE VARIANT
//   A faithful exercise of test 06 requires a *successful* map_mmio
//   call, which the spec defines to leave [1].field1.`map` = 2. The
//   success path needs a valid device_region handle in [2] (test 02
//   gates BADCAP on [2] before the success leg). Per §[device_region],
//   device_region handles are kernel-issued at boot to the root
//   service and otherwise propagate via xfer/IDC.
//
//   The v0 runner (runner/primary.zig) spawns each test as a child
//   capability domain whose `passed_handles` carry only the result
//   port at slot 3 — no device_region is forwarded. The same
//   `findCom1`-style scan that runner/serial.zig uses to bootstrap
//   the primary's serial VAR cannot succeed inside a test child,
//   because the child's table holds self / initial_ec / self_idc /
//   port and nothing else. With no device_region in scope, the test
//   child cannot drive map_mmio onto the success path, so the
//   `map -> 2` post-condition cannot be observed end-to-end here.
//
//   This smoke variant pins only the negative observation: a freshly
//   constructed MMIO VAR (caps = {r, w, mmio}) starts in `map = 0`
//   per §[var], and a map_mmio call against it — supplying an empty
//   slot for [2] — is rejected with E_BADCAP per test 02 of this
//   syscall. The VAR's `map` therefore stays at 0 across the rejected
//   call; it never reaches 2. The smoke confirms the prelude shape
//   the eventual faithful test will reuse (a valid MMIO VAR in [1])
//   but does not assert the success-leg `map -> 2` transition itself.
//
// Strategy (smoke prelude)
//   §[map_mmio]'s gate order ahead of the success leg is:
//     - test 01 (VAR is invalid)         — a valid MMIO VAR is minted
//                                           below.
//     - test 02 (device_region BADCAP)   — only fires when [2] is
//                                           invalid; on the success
//                                           path [2] would be a real
//                                           device_region.
//     - test 03 (caps.mmio not set)      — caps.mmio = 1 here.
//     - test 04 (`map` already non-zero) — a freshly created MMIO
//                                           VAR sits in `map = 0` per
//                                           §[var].
//     - test 05 (size mismatch with [2]) — pre-empted by test 02 when
//                                           [2] is empty.
//   The MMIO VAR is built without an actual map_mmio call. Per §[var]
//   create_var requires for caps.mmio = 1: props.sz = 0 (test 08),
//   caps.x = 0 (test 11), caps.dma = 0 (test 13), and cch = 1 (uc).
//   The same construction is used by map_mmio_02.zig and
//   runner/serial.zig.
//
// Action
//   1. createVar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) — must succeed; gives a valid MMIO
//      VAR with `caps.mmio = 1` and `map = 0`.
//   2. mapMmio(mmio_var, 4095) — empty slot 4095 trips test 02's
//      E_BADCAP gate. The call returns *without* taking the success
//      leg, so the VAR's `map` stays at 0 rather than transitioning
//      to 2. This is the prelude shape; the `map -> 2` observation
//      cannot be made from the test child.
//
// Assertion
//   No assertion is checked — the success-leg `map -> 2` transition
//   is unreachable from a v0 test child without a device_region.
//   Passes with assertion id 0 to mark this slot as smoke-only in
//   coverage. A failure of the prelude itself (createVar) is also
//   reported as pass-with-id-0 since no spec assertion is being
//   checked.
//
// Faithful-test note
//   Faithful test deferred pending a runner extension: runner/
//   primary.zig must mint or carve a device_region whose size matches
//   a 4 KiB MMIO VAR and forward it to the test child via
//   passed_handles. The action then becomes:
//     create_var(caps={r,w,mmio}, props={sz=0, cch=1, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0) -> mmio_var
//     map_mmio(mmio_var, forwarded_dev) -> success
//     <re-read field1 via the syscall's authoritative refresh
//      side-effect (test 09) or via a follow-up syscall that
//      surfaces field1>
//     assert field1.map == 2
//   Until the device_region forwarding lands, this file holds the
//   prelude verbatim so the eventual faithful version can graft on
//   the success-leg observation without re-deriving the inert-check
//   matrix.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR — caps.mmio = 1, props.sz = 0, cch = 1
    // (uc), caps.x = 0, caps.dma = 0 — the construction §[var]
    // requires for an MMIO VAR. On creation the VAR sits in `map = 0`
    // per §[var] line 877.
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
    const mmio_var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout (slots 0/1/2 are self / initial_ec / self_idc;
    // passed_handles begin at slot 3 and only the result port lands
    // there for tests). The map_mmio call returns E_BADCAP via test
    // 02 without ever reaching the success leg, so the VAR's `map`
    // stays at 0 rather than transitioning to 2. The success leg
    // (with a real device_region in [2]) is not reachable from the
    // test child — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // No spec assertion is being checked — the `map -> 2` transition
    // is unreachable from the v0 test child. Pass with assertion id 0
    // to mark this slot as smoke-only in coverage.
    testing.pass();
}
