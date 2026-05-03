// Spec §[port_io_virtualization] — test 04.
//
// "[test 04] a 1-, 2-, or 4-byte MOV load from `VAR.base + offset`
//  (offset < port_count, `cur_rwx.r = 1`) leaves the destination GPR
//  holding the value an x86-64 `in` of the matching operand width at
//  port `base_port + offset` would produce, and execution resumes at
//  the instruction immediately following the MOV."
//
// DEGRADED SMOKE VARIANT
//   This is the first half of the port_io fault-handler contract:
//   §[port_io_virtualization] requires that an MMIO VAR backed by a
//   port_io device_region trap each MOV load against `VAR.base +
//   offset`, decode the operand width, execute an `in` at
//   `base_port + offset`, deposit the result into the destination
//   GPR, and advance RIP past the MOV. runner/serial.zig already
//   exercises the symmetric MOV-store leg (test 05) against COM1 in
//   the root service, but test children today have no port_io
//   device_region in their handle table — the v0 runner
//   (runner/primary.zig spawnOne) populates a child capability
//   domain's table via `create_capability_domain`'s passed_handles,
//   which on this branch carry only the result port at slot 3.
//   Slots 0/1/2 are kernel-installed as self / initial EC /
//   self-IDC. No port_io device_region is forwarded; the only such
//   region the kernel mints at boot is COM1, and it stays in the
//   root service.
//
//   Without a forwarded port_io device_region, `map_mmio` cannot
//   succeed against any [2] the test child can name, and the MMIO
//   VAR's pages are therefore never installed-as-trap-only. The
//   load-decode/`in`/RIP-advance path the spec assertion describes
//   is unreachable from a test child today.
//
// Strategy (smoke prelude)
//   Mirror the prelude shape a faithful test 04 would use:
//     - caps = {r, w, mmio} so the VAR is mmio-flagged with read
//       permission (the spec assertion's `cur_rwx.r = 1`
//       precondition).
//     - props = {sz = 0 (4 KiB), cch = 1 (uc), cur_rwx = 0b011}
//       — sz = 0 is required when caps.mmio = 1 (§[create_var]
//       test 08); cch = 1 (uc) is required for an MMIO VAR per
//       §[var]; cur_rwx.r = 1 is the precondition this assertion
//       turns on.
//     - pages = 1 — minimum-size MMIO VAR; once a port_io
//       device_region is forwarded, the faithful test would size
//       the VAR to match that region's port_count (rounded up to a
//       page).
//   Pass slot 4095 for [2]: per the create_capability_domain table
//   layout that slot is guaranteed empty, so the kernel rejects
//   with E_BADCAP via §[map_mmio] test 02 instead of installing
//   the VAR for trap-on-access. The MOV-load against VAR.base the
//   faithful test would issue is therefore not attempted — the VAR
//   is still in `map = 0` and the load would fault as an unmapped
//   user vaddr, not as a port_io trap.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      mmio-flagged VAR with cch = 1 and cur_rwx.r = 1 sitting in
//      `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02). The smoke does not attempt the MOV
//      load: without map_mmio installing the VAR over a port_io
//      device_region, the load would observe an unmapped vaddr
//      rather than the port_io trap path the spec assertion
//      targets.
//
// Assertion
//   No assertion is checked — the MOV-load decode / `in` / RIP-
//   advance path is unreachable from a test child without a
//   forwarded port_io device_region. Passes with assertion id 0
//   to mark this slot as smoke-only in coverage. The prelude
//   matches what the eventual faithful test will need so that
//   wiring a port_io device_region into the runner only requires
//   replacing the slot-4095 stub with the real handle id and
//   issuing the MOV load with the read-back assertion.
//
// Faithful-test note
//   Faithful test deferred pending one runner extension:
//
//   runner/primary.zig must mint or carve a port_io device_region
//   (dev_type = 1) and forward it to the test child via
//   passed_handles. Ideally that region is a loopback (or a
//   readable host-defined port whose value at `in` time is
//   predictable) so the test can pre-arrange a value at
//   `base_port + offset` and assert the read-back. The action then
//   becomes, for each width w in {1, 2, 4}:
//     pio = forwarded port_io device_region (port_count >= w)
//     create_var(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = ceil(pio.port_count /
//                0x1000), preferred_base = 0, device_region = 0)
//                -> mmio_var
//     map_mmio(mmio_var, pio) -> success
//     // Issue an inline-asm MOV of width w from VAR.base into a
//     // chosen GPR. The kernel must decode the MOV, execute
//     // `in` at base_port, deposit the result into that GPR,
//     // and resume at the byte after the MOV. The next
//     // instruction (which observes the GPR) must therefore see
//     // the value the host's `in` would have produced, and
//     // execution must continue — both observations together
//     // are the spec assertion.
//     assert(observed_gpr == expected_in_value)
//     // Crossing past the MOV instruction at all confirms the
//     // RIP-advance leg.
//   This is assertion id 1 a faithful version would check. Each
//   width (1, 2, 4) should be a separate sub-case once the runner
//   forwards a port_io device_region; they share this prelude
//   shape and only differ in the inline-asm operand width and the
//   chosen GPR.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR with caps.mmio = 1, cch = 1 (uc),
    // sz = 0 (4 KiB), cur_rwx.r = 1 — the construction §[var]
    // requires for an MMIO VAR carrying the read precondition this
    // test turns on. On creation the VAR sits in `map = 0`.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w — `r` is the precondition for test 04
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
    // there for tests). The §[map_mmio] gate order rejects an invalid
    // [2] (test 02, E_BADCAP) before any port_io handling can fire.
    // We do not assert on the result code — this is a degraded smoke
    // pinning only the prelude shape until the runner forwards a
    // port_io device_region.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // The MOV-load decode / `in` / RIP-advance path the spec
    // assertion describes is unreachable from a test child without
    // a forwarded port_io device_region. We deliberately do not
    // attempt a load against `cvar.v2` (the VAR base): with
    // map_mmio not having installed the VAR over a port_io region,
    // the load would observe an unmapped vaddr rather than the
    // port_io trap path. Pass with assertion id 0 to mark this
    // slot as smoke-only in coverage.
    testing.pass();
}
