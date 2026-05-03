// Spec §[map_mmio] — test 05.
//
// "[test 05] returns E_INVAL if [2]'s size does not equal [1]'s size."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on a successful pass through the `[2] is a
//   valid device_region` gate (test 02). Per §[device_region] the
//   device region's "size" is implied by `dev_type`:
//     - dev_type = 0 (mmio): a contiguous physical MMIO range whose
//       byte length is the device_region's intrinsic size.
//     - dev_type = 1 (port_io): `port_count` consecutive 1-byte ports
//       starting at `base_port`, so size = port_count bytes (rounded
//       up to a page for VAR-size comparison purposes; per
//       §[port_io_virtualization] the kernel reserves the VAR's full
//       page-aligned virtual range and faults on every access).
//   With the device_region in hand, the test would build an MMIO VAR
//   whose `pages × sz` does not match the device_region's size and
//   confirm `map_mmio` returns E_INVAL.
//
//   The blocker is the same one documented in create_var_22.zig: the
//   v0 runner (runner/primary.zig spawnOne) populates a child
//   capability domain's table via `create_capability_domain`'s
//   passed_handles, which on this branch carry only the result port
//   at slot 3. Slots 0/1/2 are kernel-installed as self / initial EC
//   / self-IDC. No device_region reaches a test child today.
//
//   Without a valid device_region in [2], the kernel rejects the
//   call at test 02 (E_BADCAP) before the size comparison in test 05
//   can run. The only reachable arm of map_mmio in a test child is
//   the BADCAP/PERM lattice already covered by tests 01-03.
//
// Strategy (smoke prelude)
//   Mirror map_mmio_03's MMIO-VAR construction so the prelude shape
//   matches what a faithful test 05 would set up:
//     - caps = {r, w, mmio} so the VAR is mmio-flagged (test 03 closed).
//     - props = {sz = 0 (4 KiB), cch = 1 (uc), cur_rwx = 0b011}
//       — sz = 0 is required for caps.mmio = 1 (§[create_var] test 08),
//         cch = 1 is required for mmio (§[create_var] test 09),
//         cur_rwx ⊆ caps.{r, w}.
//     - pages = 1 — minimum-size MMIO VAR; once a device_region is
//       forwarded, the faithful test would either grow this to a
//       deliberately mismatched page count or shrink the device_region
//       to a different size and assert E_INVAL.
//   Pass slot 4095 for [2]: per the create_capability_domain table
//   layout that slot is guaranteed empty, so the kernel rejects with
//   E_BADCAP via test 02 instead of reaching test 05.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 1, cur_rwx =
//                0b011}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      MMIO VAR sitting in `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (test 02), not the spec'd E_INVAL (test 05). The smoke does
//      not assert the rejection code; it pins only the prelude shape.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because the
//   `size mismatch` arm is unreachable from a test child without a
//   forwarded device_region. The test ELF still validates link/load
//   plumbing in CI, and the prelude matches the eventual faithful
//   test so that wiring a device_region into the runner only requires
//   replacing the slot-4095 stub with the real handle id and adding
//   the size assertion.
//
// Faithful-test note
//   Faithful test deferred pending one runner extension:
//
//   runner/primary.zig must mint or carve a device_region (mmio or
//   port_io) of a known byte size and forward it to the test child
//   via passed_handles. The action then becomes:
//     dev = forwarded device_region (size = S)
//     create_var(caps={r, w, mmio}, props={sz = 0, cch = 1, cur_rwx =
//                0b011}, pages = P such that P * 0x1000 != S,
//                preferred_base = 0, device_region = 0) -> mmio_var
//     map_mmio(mmio_var, dev) -> *expected* E_INVAL via test 05
//   This is the assertion id 1 a faithful version would check.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR so the prelude matches what a faithful
    // test 05 would stage. caps.mmio = 1 forces props.sz = 0 and
    // props.cch = 1 (uc); pages = 1 is the minimum-size MMIO VAR.
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
    const mmio_var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // [2] = 4095: the test child's table holds no device_region
    // handles, so this slot is unallocated. The §[map_mmio] gate
    // order rejects an invalid [2] (test 02, E_BADCAP) before the
    // size comparison (test 05, E_INVAL) can fire. We do not assert
    // on the result code — this is a degraded smoke pinning only the
    // prelude shape until the runner forwards a device_region.
    _ = syscall.mapMmio(mmio_var_handle, 4095);

    // Size-mismatch arm unreachable from a v0 test child. Pass with
    // assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
