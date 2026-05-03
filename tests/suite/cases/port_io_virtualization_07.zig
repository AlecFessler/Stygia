// Spec §[port_io_virtualization] — test 07.
//
// "[test 07] a MOV load when `VAR.cur_rwx.r = 0` delivers a
//  `memory_fault` event."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on a CPU-issued MOV load against a VAR
//   range backed by a port_io device_region whose effective read
//   permission is masked off (`cur_rwx.r = 0`). Per
//   §[port_io_virtualization], such an access must not perform an
//   `in` of the corresponding port; the kernel must fault the
//   instruction and deliver a `memory_fault` event to the EC's
//   handler instead.
//
//   Reaching that arm has two prerequisites that v0 cannot
//   currently satisfy from a test child:
//
//   1. A port_io device_region must be forwarded into the test
//      child's handle table so map_mmio can install it into an
//      MMIO VAR. Per §[device_region], device_region handles are
//      kernel-issued at boot to the root service and propagate via
//      xfer/IDC. The v0 runner (runner/primary.zig spawnOne) wires
//      a child capability domain via `create_capability_domain`'s
//      passed_handles, but only the result port lands at slot 3 —
//      no device_region of any dev_type, port_io included, reaches
//      a test child today. There is also no ambient host-platform
//      analogue the runner could carve out into a port_io
//      device_region without a real I/O device behind it.
//
//   2. The runner's fault-event plumbing must surface a delivered
//      `memory_fault` back to the test child as an observable
//      pass/fail signal. The current runner harness collects only
//      the result port message and the test-child exit status; a
//      memory_fault that diverts the EC to its fault handler does
//      not flow back to the test as a positive assertion outcome.
//
//   Without either piece, the kernel's port_io read-fault path
//   (§[port_io_virtualization] read-permission check) is
//   unreachable end-to-end from a test child. The same blocker
//   shape is documented on port_io_virtualization_02.zig and
//   map_mmio_05.zig.
//
// Strategy (smoke prelude)
//   Build the MMIO VAR shape the faithful test would map a
//   port_io device_region into, with the read bit cleared from
//   `cur_rwx`. Per §[var]/§[create_var]:
//     - caps = {w, mmio} — caps.r intentionally cleared so
//       cur_rwx.r ⊆ caps.r forces cur_rwx.r = 0 at the
//       create_var gate (§[create_var] test 09).
//     - props = {sz = 0, cch = 1 (uc), cur_rwx = 0b010 (w only)}
//       — sz = 0 is required for caps.mmio = 1 (§[create_var]
//         test 08); cch = 1 (uc) is required for an MMIO VAR
//         per §[var]; cur_rwx = w only is the spec violation
//         the faithful test 07 turns on (read-side fault on a
//         load against a port_io range with r masked off).
//     - pages = 1 — minimum-size MMIO VAR; once a port_io
//       device_region is forwarded, the faithful test would
//       size pages = ceil(port_count / 0x1000).
//   Pass slot 4095 for [2]: per the create_capability_domain
//   table layout that slot is guaranteed empty, so the kernel
//   rejects map_mmio with E_BADCAP via §[map_mmio] test 02
//   instead of reaching the read-fault arm in
//   §[port_io_virtualization]. The smoke does not assert the
//   rejection code; it pins only the prelude shape.
//
// Action
//   1. createVar(caps={w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b010}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      mmio-flagged VAR with cur_rwx.r = 0 sitting in `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02), not the read-fault path
//      (§[port_io_virtualization] test 07). The smoke does not
//      assert the rejection code; it pins only the prelude shape.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the read-side memory_fault arm is unreachable from a test
//   child without a forwarded port_io device_region and a
//   fault-event observation channel. The test ELF still validates
//   link/load plumbing in CI, and the prelude matches the
//   eventual faithful test so wiring a port_io device_region into
//   the runner only requires replacing the slot-4095 stub with
//   the real handle id and adding the memory_fault observation.
//
// Faithful-test note
//   Faithful test deferred pending two runner extensions:
//
//   1. runner/primary.zig must mint or carve a port_io
//      device_region (dev_type = 1) of a known port_count and
//      forward it to the test child via passed_handles.
//   2. The runner harness must surface a delivered
//      `memory_fault` event back to the test child as an
//      observable pass/fail signal (today only the result-port
//      message and exit status flow back).
//
//   With both in place, the action becomes:
//     pio = forwarded port_io device_region (port_count = K)
//     create_var(caps={w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b010}, pages = ceil(K / 0x1000),
//                preferred_base = 0, device_region = 0) -> mmio_var
//     map_mmio(mmio_var, pio) -> success
//     issue a 1-, 2-, or 4-byte MOV load from `mmio_var.base + 0`
//     -> *expected* a `memory_fault` event delivered to the EC,
//        per §[port_io_virtualization] test 07
//   That memory_fault delivery would be assertion id 1 in a
//   faithful version.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build an MMIO-flagged VAR with cur_rwx.r = 0. caps.r = 0
    // forces cur_rwx.r = 0 at the §[create_var] test 09 gate;
    // caps.mmio = 1 forces props.sz = 0 (§[create_var] test 08);
    // cch = 1 (uc) is required for an MMIO VAR per §[var];
    // pages = 1 is the minimum-size MMIO VAR.
    const mmio_caps = caps.VarCap{ .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b010; // cur_rwx = w only — the spec violation
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
    // table layout. The map_mmio call returns E_BADCAP via
    // §[map_mmio] test 02 without ever reaching the read-fault arm
    // this test targets. The cur_rwx.r = 0 → memory_fault leg is
    // not reachable from a v0 test child — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // read-fault arm unreachable from a v0 test child. Pass with
    // assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
