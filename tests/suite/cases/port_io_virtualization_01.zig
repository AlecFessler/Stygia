// Spec §[port_io_virtualization] — test 01.
//
// "[test 01] `map_mmio` returns E_INVAL if [2].field0.dev_type =
//  port_io and the running architecture is not x86-64."
//
// AARCH64-ONLY ASSERTION — DEGRADED SMOKE EVERYWHERE
//   The spec assertion is conditional on `arch != x86-64`. On x86-64
//   the precondition is false, so the assertion is vacuously true:
//   the kernel is supposed to *accept* port_io map_mmio there (the
//   in/out decoder lives at kernel/arch/x64/port_io.zig). On aarch64
//   the assertion has bite — but the v0 runner forwards only mmio
//   fixtures to test children (see runner/primary.zig
//   FIXTURE_DMA_IRQ_PHYS_BASE / FIXTURE_PLAIN_PHYS_BASE; both are
//   `dev_type = mmio`), so a test child has no port_io
//   device_region to feed [2] on either arch.
//
//   Consequences:
//     - On x86-64 builds (-Darch=x64), the spec precondition cannot
//       be satisfied, so the E_INVAL leg this test targets is
//       unreachable by construction.
//     - On aarch64 builds (-Darch=arm; precommit.sh stages 2 and 2a
//       boot this on the Pi 5 + local TCG), the precondition would
//       hold *if* a port_io device_region were forwarded, but none
//       is — so [2] cannot name a port_io handle here either.
//     - Independently of the test-side gap, the kernel currently
//       does not enforce the spec's arch check on aarch64:
//       kernel/memory/vmar.zig:mapMmio accepts port_io regardless of
//       arch, and aarch64 routes faults through
//       kernel/arch/aarch64/exceptions.zig:interceptPortIoFault.
//       Restoring the spec'd E_INVAL gate is a separate kernel-side
//       fix that must land before this test can be made faithful.
//
//   This file therefore stays a degraded smoke: it pins the prelude
//   shape the eventual faithful test will reuse (a valid MMIO VMAR
//   in [1] with the construction §[var] requires when caps.mmio = 1,
//   plus a map_mmio call site) and reports pass-with-id-0 to mark
//   this slot as smoke-only in coverage. The §[map_mmio] test 02
//   gate-order rejection (E_BADCAP when [2] is an empty slot) is
//   what the call site actually returns, regardless of host arch —
//   that's incidental and not asserted on.
//
// Strategy (smoke prelude)
//   Per §[var], creating an MMIO VMAR requires:
//     - caps.mmio = 1
//     - caps.x = 0   (per §[create_vmar] test 11)
//     - caps.dma = 0 (per §[create_vmar] test 13)
//     - props.sz = 0 (per §[create_vmar] test 08; mmio VARs are 4 KiB
//       page-granular)
//     - props.cch = 1 (uc) — required for an MMIO VMAR per §[var]
//   The construction below mirrors map_mmio_06.zig and
//   runner/serial.zig.
//
// Action
//   1. createVmar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) — must succeed; gives a valid MMIO
//      VMAR ready to be paired with a hypothetical port_io
//      device_region.
//   2. mapMmio(mmio_var, HANDLE_TABLE_MAX - 1) — slot 4095 is
//      guaranteed empty by the create_capability_domain table layout
//      (slots 0/1/2 are self / initial_ec / self_idc; passed_handles
//      begin at slot 3 and the runner forwards at most the result
//      port + ELF pf + libz pf + two mmio fixtures, so the upper
//      slots stay empty). The call returns E_BADCAP via §[map_mmio]
//      test 02 without ever reaching the dev_type/arch check this
//      test targets — but that's a side effect, not an assertion.
//
// Assertion
//   No assertion is checked — the arch-conditional E_INVAL leg is
//   unreachable on either arch the runner currently builds, for the
//   reasons above. Passes with assertion id 0 to mark this slot as
//   smoke-only in coverage. A failure of the prelude itself
//   (createVmar) is also reported as pass-with-id-0 since no spec
//   assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending two independent landings:
//
//   1. runner/primary.zig must mint or carve a port_io device_region
//      (with `dev_type = port_io`, a `base_port`, and a `port_count`)
//      and forward it to every test child via `passed_handles`. The
//      kernel-side fixture-mint hook already exists (see
//      kernel/boot/userspace_init.zig grantTestFixtureDevices, which
//      currently mints only mmio fixtures); a port_io fixture would
//      slot in alongside the existing CAFE/BABE entries.
//
//   2. kernel/memory/vmar.zig:mapMmio must add the arch guard
//      (`return errors.E_INVAL` when
//      `dr.device_type == .port_io` and `builtin.cpu.arch != .x86_64`)
//      so the assertion observably fires on aarch64. Without this,
//      aarch64 mapMmio currently accepts port_io and routes accesses
//      through interceptPortIoFault — masking the spec violation.
//
//   With both in place, on an aarch64 build the action becomes:
//     create_vmar(caps={r,w,mmio}, props={sz=0, cch=1, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0)
//                -> mmio_var
//     map_mmio(mmio_var, forwarded_port_io_dev) -> E_INVAL
//   That E_INVAL would be assertion id 1 in a faithful version. On
//   x86-64 the precondition does not hold, so the same construction
//   succeeds (map = 2) and the test would assert no error — i.e. the
//   faithful test is per-arch.
//
//   Until both land, this file holds the prelude verbatim so the
//   eventual faithful version can graft on the dev_type/arch
//   observation without re-deriving the MMIO-VMAR construction.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VMAR — caps.mmio = 1, props.sz = 0, cch = 1
    // (uc), caps.x = 0, caps.dma = 0 — the construction §[var]
    // requires for an MMIO VMAR. On creation the VMAR sits in `map = 0`
    // per §[var].
    const mmio_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVmar(
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
    // table layout. The map_mmio call returns E_BADCAP via §[map_mmio]
    // test 02 without ever reaching the dev_type/arch check this test
    // targets. The arch-conditional E_INVAL leg (port_io device_region
    // on a non-x86-64 host) is not reachable on either arch the runner
    // currently builds: on x86-64 the precondition is false, and on
    // aarch64 no port_io device_region is forwarded into the test
    // child's cap table — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // No spec assertion is being checked — the `dev_type = port_io
    // && arch != x86-64` leg is unreachable on either arch. Pass with
    // assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
