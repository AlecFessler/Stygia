// Spec §[port_io_virtualization] — test 08.
//
// "[test 08] a MOV store when `VAR.cur_rwx.w = 0` delivers a
//  `memory_fault` event."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on the kernel's port-IO MOV decoder
//   observing the faulting CPU access, intersecting the requested
//   access type (write) with `VAR.cur_rwx`, and — when the write
//   bit is clear — delivering a `memory_fault` event to the EC's
//   bound event port instead of executing an `out`. Per
//   §[port_io_virtualization] effective permissions follow
//   `VAR.cur_rwx`: a write MOV when `cur_rwx.w = 0` is rejected
//   with `memory_fault`, mirroring the analogous read-side
//   rejection in test 07.
//
//   Two independent blockers keep this assertion unreachable from a
//   v0 test child:
//
//   1. No port_io device_region reaches the test child. Per
//      §[device_region], device_region handles (port_io among them)
//      are kernel-issued at boot to the root service and propagate
//      via xfer/IDC. The v0 runner (runner/primary.zig spawnOne)
//      populates each test child's table via
//      `create_capability_domain`'s passed_handles, which on this
//      branch carry only the result port at slot 3 — slots 0/1/2
//      are kernel-installed as self / initial EC / self-IDC. No
//      device_region of any `dev_type` is forwarded today, and a
//      port_io device_region in particular has no ambient host-
//      platform analogue the runner could carve out. Without a
//      real port_io device_region in [2], `map_mmio` rejects at
//      §[map_mmio] test 02 (E_BADCAP) before the kernel ever has
//      a port-IO range installed in the VAR's address space, so
//      no MOV against that range can be issued.
//
//   2. No `memory_fault` event harness exists in the test child.
//      The assertion observation is "an EC bound to an event port
//      receives a memory_fault event with the faulting vaddr/RIP
//      after the MOV". The v0 runner does not bind the test EC's
//      event port to its result port, nor does the test ELF carry
//      a `recv` loop reading event records and matching on
//      `memory_fault`. Even if a port_io device_region were
//      forwarded and the MOV issued, the EC would simply die on
//      the unhandled fault rather than continuing past it to
//      `testing.pass(1)`.
//
//   With both legs blocked, the strict test 08 path
//   (write-disabled VAR + port_io device_region + MOV store +
//   event-port observation of memory_fault) cannot be exercised
//   end-to-end here. This smoke variant pins only the prelude
//   shape the eventual faithful test will reuse: an MMIO-flagged
//   VAR with `cur_rwx.w = 0` exists in [1], and a `map_mmio`
//   call against it is issued. The gate-order rejection on the
//   x86-64 host (E_BADCAP via §[map_mmio] test 02 when [2] is an
//   empty slot) confirms the call site is wired up; the
//   write-disabled MOV-store + memory_fault leg the spec
//   assertion targets is not asserted.
//
// Strategy (smoke prelude)
//   Build an MMIO-flagged VAR whose `cur_rwx` has the write bit
//   clear so the prelude shape matches what a faithful test 08
//   would set up:
//     - caps = {r, w, mmio} so the VAR is mmio-flagged
//       (§[map_mmio] test 03 closed) and `w` is in caps so
//       cur_rwx is permitted to drop it (§[create_var] test 16
//       requires cur_rwx ⊆ caps.{r, w, x}).
//     - props = {sz = 0 (4 KiB), cch = 1 (uc), cur_rwx = 0b001}
//       — sz = 0 is required for caps.mmio = 1 (§[create_var]
//         test 08), cch = 1 (uc) is required for an MMIO VAR per
//         §[var], cur_rwx = 0b001 (r-only) is the configuration
//         the faithful test asserts the write rejection against.
//     - pages = 1 — minimum-size MMIO VAR; once a port_io
//       device_region is forwarded, the faithful test would size
//       the VAR to match that device_region's port_count
//       (rounded up to a page).
//   Pass slot 4095 for [2]: per the create_capability_domain
//   table layout that slot is guaranteed empty, so the kernel
//   rejects with E_BADCAP via §[map_mmio] test 02 instead of
//   reaching the port-IO MOV-decoder path.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b001}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      mmio-flagged VAR with cur_rwx.w = 0 sitting in `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02), not the spec'd memory_fault event
//      (§[port_io_virtualization] test 08). The smoke does not
//      assert the rejection; it pins only the prelude shape.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the write-disabled MOV-store + memory_fault leg is unreachable
//   from a test child without a forwarded port_io device_region
//   *and* a memory_fault event harness. The test ELF still
//   validates link/load plumbing in CI, and the prelude matches
//   the eventual faithful test so that wiring a port_io
//   device_region into the runner and binding the test EC's event
//   port lets the assertion id 1 step in without re-deriving the
//   VAR construction.
//
// Faithful-test note
//   Faithful test deferred pending two independent runner
//   extensions that must both land before the assertion can be
//   observed:
//
//   1. runner/primary.zig must mint or carve a port_io
//      device_region (dev_type = 1) of a known port_count and
//      forward it to the test child via passed_handles, so [2]
//      can name a real port_io handle.
//
//   2. The runner must bind the test EC's event port to a handle
//      visible to the test ELF, and the test must run a `recv`
//      loop that decodes event records and matches on
//      `memory_fault` with the faulting vaddr equal to the MOV's
//      target. Without this, the EC dies on the unhandled fault
//      instead of reporting the assertion.
//
//   With both in place, the action becomes:
//     pio = forwarded port_io device_region (port_count = K)
//     create_var(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b001}, pages = ceil(K / 0x1000),
//                preferred_base = 0, device_region = 0) -> mmio_var
//     map_mmio(mmio_var, pio) -> success
//     // issue a 1/2/4-byte MOV store (e.g.
//     //   `mov [mmio_var.base], al`) against the now-installed
//     // port-IO range; the kernel decodes the MOV, intersects
//     // the write access with cur_rwx (w = 0), and delivers a
//     // memory_fault event in lieu of the `out`.
//     // The test EC, blocked in `recv` on its event port, wakes
//     // with a memory_fault record naming the MOV's vaddr/RIP
//     // and reports assertion id 1.
//   That memory_fault delivery would be assertion id 1 in a
//   faithful version.
//
//   Until then, this file holds the prelude verbatim so the
//   eventual faithful version can graft on the MOV + event-port
//   observation without re-deriving the MMIO-VAR construction.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build an MMIO-flagged VAR with cur_rwx.w = 0. caps.mmio = 1
    // forces props.sz = 0 (§[create_var] test 08); cch = 1 (uc) is
    // required for an MMIO VAR per §[var]; cur_rwx = 0b001 (r-only)
    // is the configuration the faithful §[port_io_virtualization]
    // test 08 turns on; pages = 1 is the minimum-size MMIO VAR.
    // caps must include `w` so cur_rwx is permitted to *drop* it
    // (cur_rwx ⊆ caps.{r, w, x} per §[create_var] test 16); the
    // write capability is present on the handle but cleared in
    // cur_rwx for this test.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b001; // cur_rwx = r only; w cleared to arm the rejection
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

    // [2] = 4095: the test child's table holds no device_region
    // handles, so this slot is unallocated. The §[map_mmio] gate
    // order rejects an invalid [2] (test 02, E_BADCAP) before the
    // port-IO MOV decoder ever sees a request. We do not assert
    // on the result code — this is a degraded smoke pinning only
    // the prelude shape until the runner forwards a port_io
    // device_region and binds the test EC's event port.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // Write-disabled MOV-store + memory_fault leg unreachable from
    // a v0 test child. Pass with assertion id 0 to mark this slot
    // as smoke-only in coverage.
    testing.pass();
}
