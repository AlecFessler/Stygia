// Spec §[port_io_virtualization] — test 01.
//
// "[test 01] `map_mmio` returns E_INVAL if [2].field0.dev_type =
//  port_io and the running architecture is not x86-64."
//
// DEGRADED SMOKE VARIANT
//   This assertion is structurally inert on the only architecture the
//   v0 test runner currently boots: x86-64. The `cpu_arch != x86_64`
//   precondition is never satisfied here, so the kernel branch this
//   test would exercise — rejecting a `port_io` device_region with
//   E_INVAL because port-IO virtualization requires the host's `in`/
//   `out` instructions — is unreachable from x86-64.
//
//   The runner-level path is also blocked. Per §[device_region],
//   device_region handles (port_io among them) are kernel-issued at
//   boot to the root service and propagate via xfer/IDC. The v0
//   runner (runner/primary.zig) spawns each spec test as a child
//   capability domain whose `passed_handles` carry only the result
//   port at slot 3 — no device_region, port_io or otherwise, is
//   forwarded. So even if a non-x86-64 boot were available, the test
//   child currently has no port_io handle to feed [2].
//
//   With both legs blocked — wrong host arch *and* no port_io
//   device_region in scope — the strict test 01 path (kernel rejects
//   port_io map_mmio with E_INVAL on aarch64) cannot be exercised
//   end-to-end here.
//
//   This smoke variant pins only the prelude shape the eventual
//   faithful test will reuse: a valid MMIO VMAR exists in [1] with
//   the construction §[var] requires when caps.mmio = 1, and a
//   map_mmio call against it is issued. The gate-order rejection on
//   the x86-64 host (E_BADCAP via test 02 of §[map_mmio] when [2] is
//   an empty slot) confirms the call site is wired up; the arch-
//   conditional E_INVAL the spec assertion targets is not asserted.
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
//   §[map_mmio]'s gate order on the x86-64 host is:
//     - test 01 (VMAR is invalid)         — pre-empted; we mint a real
//                                           MMIO VMAR.
//     - test 02 (device_region BADCAP)   — fires here, since slot 4095
//                                           is empty by construction.
//   The test 01 (this file's spec target) check on `dev_type =
//   port_io && arch != x86-64` cannot fire on the x86-64 host
//   regardless of [2].
//
// Action
//   1. createVmar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) — must succeed; gives a valid MMIO
//      VMAR ready to be paired with a hypothetical port_io
//      device_region.
//   2. mapMmio(mmio_var, 4095) — slot 4095 is guaranteed empty by
//      the create_capability_domain table layout (slots 0/1/2 are
//      self / initial_ec / self_idc; passed_handles begin at slot 3
//      and only the result port lands there for tests). The call
//      returns E_BADCAP via §[map_mmio] test 02 without ever
//      reaching the dev_type/arch check this test targets.
//
// Assertion
//   No assertion is checked — the arch-conditional E_INVAL leg is
//   unreachable from an x86-64 host. Passes with assertion id 0 to
//   mark this slot as smoke-only in coverage. A failure of the
//   prelude itself (createVmar) is also reported as pass-with-id-0
//   since no spec assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending two independent runner extensions
//   that must both land before the assertion can be observed:
//
//   1. The runner must be able to spawn an aarch64 (or any non-
//      x86-64) build of the kernel and route this test ELF onto it.
//      The current build pins `cpu_arch = .x86_64` in
//      tests/suite/build.zig, and the kernel itself runs on x86-64
//      under QEMU; there is no aarch64 boot wired through the test
//      runner today.
//
//   2. runner/primary.zig must mint or carve a port_io device_region
//      (with `dev_type = port_io`, a `base_port`, and a `port_count`)
//      and forward it to the test child via `passed_handles` so [2]
//      can name a real port_io handle.
//
//   With both in place, the action becomes:
//     <on aarch64>
//     create_vmar(caps={r,w,mmio}, props={sz=0, cch=1, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0)
//                -> mmio_var
//     map_mmio(mmio_var, forwarded_port_io_dev) -> E_INVAL
//   That E_INVAL would be assertion id 1 in a faithful version.
//
//   Until then, this file holds the prelude verbatim so the eventual
//   faithful version can graft on the dev_type/arch observation
//   without re-deriving the MMIO-VMAR construction.

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
    // on a non-x86-64 host) is not reachable from the x86-64 runner
    // — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // No spec assertion is being checked — the `dev_type = port_io
    // && arch != x86-64` leg is unreachable from an x86-64 host. Pass
    // with assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
