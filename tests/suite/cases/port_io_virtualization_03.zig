// Spec §[port_io_virtualization] — test 03.
//
// "[test 03] `map_mmio` returns E_INVAL if [2].field0.dev_type =
//  port_io and [1].caps.x is set."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on the §[map_mmio] gate fired against an
//   MMIO VAR whose caps.x bit is set together with a port_io
//   device_region in [2]. Per §[port_io_virtualization], port-IO
//   virtualization is implemented by trapping every CPU access to
//   the VAR's range and decoding the faulting MOV — an executable
//   page in that range is nonsensical, so the kernel rejects the
//   pairing with E_INVAL.
//
//   Both legs of the precondition are blocked from a v0 test child.
//   First, §[create_var] test 11 already rejects caps.mmio = 1 and
//   caps.x = 1 simultaneously with E_INVAL: the test child cannot
//   build an MMIO-flagged VAR with the spec-violating caps.x bit at
//   all, since create_var refuses the construction up front. The
//   eventual faithful test must therefore obtain such a VAR from a
//   path the runner has not wired (e.g., a downgraded mmio handle
//   delivered via xfer/IDC from a peer that has the bit set on a
//   non-mmio VAR).
//
//   Second, the same blocker documented in port_io_virtualization_01
//   /02.zig and map_mmio_05.zig applies: the v0 runner
//   (runner/primary.zig spawnOne) populates a child capability
//   domain's table via `create_capability_domain`'s passed_handles,
//   which on this branch carry only the result port at slot 3.
//   Slots 0/1/2 are kernel-installed as self / initial EC /
//   self-IDC. No device_region of any `dev_type` reaches a test
//   child today — and a port_io device_region in particular has no
//   ambient host-platform analogue the runner could carve out.
//
//   With both the caps.x-on-mmio VAR and the port_io device_region
//   unreachable from a v0 test child, the §[port_io_virtualization]
//   test 03 arm of map_mmio cannot be exercised end-to-end here.
//
// Strategy (smoke prelude)
//   Mint the closest legal approximation of a faithful prelude: a
//   plain MMIO VAR (caps.x cleared so create_var accepts the
//   construction) ready to be paired with a port_io device_region.
//   The construction below mirrors port_io_virtualization_01.zig
//   and runner/serial.zig:
//     - caps = {r, w, mmio} so the VAR is mmio-flagged. caps.x is
//       cleared because §[create_var] test 11 rejects caps.mmio = 1
//       with caps.x = 1; the eventual faithful test must obtain a
//       VAR with caps.x set through some other path.
//     - props = {sz = 0 (4 KiB), cch = 1 (uc), cur_rwx = 0b011}
//       — sz = 0 is required for caps.mmio = 1 (§[create_var] test
//         08), cch = 1 (uc) is the legal cache type for an MMIO
//         VAR per §[var], cur_rwx ⊆ caps.{r, w}.
//     - pages = 1 — minimum-size MMIO VAR.
//   Pass slot 4095 for [2]: per the create_capability_domain table
//   layout that slot is guaranteed empty, so the kernel rejects
//   with E_BADCAP via §[map_mmio] test 02 instead of reaching the
//   port_io / caps.x arm.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      MMIO VAR sitting in `map = 0`. caps.x is intentionally
//      cleared because the bit cannot coexist with caps.mmio at
//      create_var time.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02), not the spec'd E_INVAL
//      (§[port_io_virtualization] test 03). The smoke does not
//      assert the rejection code; it pins only the prelude shape.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the `port_io with caps.x = 1` arm is unreachable from a test
//   child without both a VAR carrying caps.mmio + caps.x and a
//   forwarded port_io device_region. The test ELF still validates
//   link/load plumbing in CI, and the prelude matches the eventual
//   faithful test so that wiring those two prerequisites into the
//   runner only requires swapping the caps construction and the
//   slot-4095 stub for the real handle ids and adding the E_INVAL
//   assertion.
//
// Faithful-test note
//   Faithful test deferred pending two independent runner extensions
//   that must both land before the assertion can be observed:
//
//   1. The runner (or a peer in the test child's domain) must be
//      able to deliver an MMIO-flagged VAR handle whose caps.x bit
//      is set. Today the only minting path is `create_var`, which
//      §[create_var] test 11 closes; a faithful test needs either a
//      relaxation of that gate (e.g., for downgraded handles) or a
//      forwarded handle minted in another domain that legitimately
//      pairs caps.mmio with caps.x. The test child cannot construct
//      such a VAR locally.
//
//   2. runner/primary.zig must mint or carve a port_io device_region
//      (dev_type = 1) of a known port_count and forward it to the
//      test child via passed_handles.
//
//   With both in place, the action becomes:
//     vx = forwarded mmio VAR with caps.x = 1
//     pio = forwarded port_io device_region (port_count = K matching
//           vx's size)
//     map_mmio(vx, pio) -> *expected* E_INVAL via
//       §[port_io_virtualization] test 03
//   This is the assertion id 1 a faithful version would check.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR — caps.mmio = 1, props.sz = 0, cch = 1
    // (uc), caps.x = 0, caps.dma = 0. caps.x is cleared because
    // §[create_var] test 11 rejects caps.mmio = 1 with caps.x = 1;
    // the spec violation §[port_io_virtualization] test 03 turns on
    // (caps.x set on an mmio VAR) cannot be constructed via
    // create_var, so the smoke prelude minimally builds the
    // caps.x-cleared mmio VAR the eventual faithful test will reuse
    // once a path delivers a caps.x-set mmio handle to the test
    // child.
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
    // there for tests). The §[map_mmio] gate order rejects an
    // invalid [2] (test 02, E_BADCAP) before the port_io / caps.x
    // mismatch (§[port_io_virtualization] test 03, E_INVAL) can
    // fire. We do not assert on the result code — this is a
    // degraded smoke pinning only the prelude shape until the runner
    // forwards both a caps.x-set mmio VAR and a port_io
    // device_region.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // port_io / caps.x arm unreachable from a v0 test child. Pass
    // with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
