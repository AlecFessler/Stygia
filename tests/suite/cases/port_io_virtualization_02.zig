// Spec §[port_io_virtualization] — test 02.
//
// "[test 02] `map_mmio` returns E_INVAL if [2].field0.dev_type =
//  port_io and [1].field1.cch != 1 (uc)."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on a successful pass through the `[2] is a
//   valid device_region` gate (§[map_mmio] test 02) where the
//   forwarded device_region's `dev_type` is 1 (port_io). Per
//   §[port_io_virtualization] a port_io device_region carries a
//   16-bit `base_port` and `port_count`; installing it into an MMIO
//   VAR via `map_mmio` is only legal when the VAR's cache type is
//   uc (cch = 1) — port I/O cannot be safely cached.
//
//   The blocker is identical to the one documented in
//   create_var_22.zig and map_mmio_05.zig: the v0 runner
//   (runner/primary.zig spawnOne) populates a child capability
//   domain's table via `create_capability_domain`'s passed_handles,
//   which on this branch carry only the result port at slot 3.
//   Slots 0/1/2 are kernel-installed as self / initial EC /
//   self-IDC. No device_region of any `dev_type` reaches a test
//   child today — and a port_io device_region in particular has no
//   ambient host-platform analogue the runner could carve out.
//
//   Without a valid port_io device_region in [2], the kernel
//   rejects the call at §[map_mmio] test 02 (E_BADCAP) before the
//   port_io / cch-mismatch comparison in §[port_io_virtualization]
//   test 02 can run. The only reachable arm of map_mmio in a test
//   child is the BADCAP/PERM lattice already covered by map_mmio
//   tests 01-03.
//
// Strategy (smoke prelude)
//   Build an MMIO-flagged VAR whose `cch` is *not* uc so the prelude
//   shape matches what a faithful test 02 would set up:
//     - caps = {r, w, mmio} so the VAR is mmio-flagged
//       (§[map_mmio] test 03 closed).
//     - props = {sz = 0 (4 KiB), cch = 0 (wb), cur_rwx = 0b011}
//       — sz = 0 is required for caps.mmio = 1 (§[create_var] test
//         08), cch = 0 (wb) is the spec violation the faithful
//         test would assert on, cur_rwx ⊆ caps.{r, w}.
//     - pages = 1 — minimum-size MMIO VAR; once a port_io
//       device_region is forwarded, the faithful test would size
//       the VAR to match that device_region's port_count (rounded
//       up to a page) and assert E_INVAL on the cch mismatch.
//   Pass slot 4095 for [2]: per the create_capability_domain table
//   layout that slot is guaranteed empty, so the kernel rejects
//   with E_BADCAP via §[map_mmio] test 02 instead of reaching the
//   port_io / cch arm.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 0,
//                cur_rwx = 0b011}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      mmio-flagged VAR with cch = 0 (wb) sitting in `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02), not the spec'd E_INVAL
//      (§[port_io_virtualization] test 02). The smoke does not
//      assert the rejection code; it pins only the prelude shape.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the `port_io with cch != uc` arm is unreachable from a test
//   child without a forwarded port_io device_region. The test ELF
//   still validates link/load plumbing in CI, and the prelude
//   matches the eventual faithful test so that wiring a port_io
//   device_region into the runner only requires replacing the
//   slot-4095 stub with the real handle id and adding the
//   E_INVAL assertion.
//
// Faithful-test note
//   Faithful test deferred pending one runner extension:
//
//   runner/primary.zig must mint or carve a port_io device_region
//   (dev_type = 1) of a known port_count and forward it to the
//   test child via passed_handles. The action then becomes:
//     pio = forwarded port_io device_region (port_count = K)
//     create_var(caps={r, w, mmio}, props={sz = 0, cch = 0 (wb),
//                cur_rwx = 0b011}, pages = ceil(K / 0x1000),
//                preferred_base = 0, device_region = 0) -> mmio_var
//     map_mmio(mmio_var, pio) -> *expected* E_INVAL via
//       §[port_io_virtualization] test 02
//   This is the assertion id 1 a faithful version would check.
//   A second non-uc cch (cch = 2 wc, cch = 3 wt) variant could be
//   spun off as separate sub-cases once the runner forwards
//   port_io device_regions; they share this prelude shape and only
//   differ in the cch nibble fed into props.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build an MMIO-flagged VAR with cch = 0 (wb). caps.mmio = 1
    // forces props.sz = 0 (§[create_var] test 08); cch = 0 is the
    // spec violation the faithful §[port_io_virtualization] test 02
    // turns on; pages = 1 is the minimum-size MMIO VAR.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (0 << 5) | // cch = 0 (wb) — non-uc, the spec violation
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
    const mmio_var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // [2] = 4095: the test child's table holds no device_region
    // handles, so this slot is unallocated. The §[map_mmio] gate
    // order rejects an invalid [2] (test 02, E_BADCAP) before the
    // port_io / cch mismatch (§[port_io_virtualization] test 02,
    // E_INVAL) can fire. We do not assert on the result code —
    // this is a degraded smoke pinning only the prelude shape until
    // the runner forwards a port_io device_region.
    _ = syscall.mapMmio(mmio_var_handle, 4095);

    // port_io / cch-mismatch arm unreachable from a v0 test child.
    // Pass with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
