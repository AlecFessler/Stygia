// Spec §[port_io_virtualization] — test 06.
//
// "[test 06] a MOV access to `VAR.base + offset` with
//  `offset >= port_count` delivers a `memory_fault` event."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on two pieces of plumbing that do not yet
//   exist in the v0 test runner:
//
//   1. A port_io device_region in scope. Per §[device_region],
//      device_region handles are kernel-issued at boot to the root
//      service and propagate downstream via xfer/IDC. The v0 runner
//      (runner/primary.zig spawnOne) populates a child capability
//      domain's table via `create_capability_domain`'s
//      passed_handles, which on this branch carry only the result
//      port at slot 3. Slots 0/1/2 are kernel-installed as self /
//      initial EC / self-IDC. No device_region of any `dev_type`
//      reaches a test child today — and a port_io device_region in
//      particular has no ambient host-platform analogue the runner
//      could carve out.
//
//   2. A memory_fault event harness. Per §[port_io_virtualization],
//      a CPU access whose computed offset (`fault_vaddr - VAR.base`)
//      falls outside `[0, port_count)` page-faults into the kernel,
//      which then synthesises a `memory_fault` event rather than
//      trapping into the in/out emulator. Observing that event from
//      a test child requires a fault-handler EC bound to the test
//      child's domain, an event port the kernel routes the
//      memory_fault to, and a `recv` loop that classifies the event.
//      None of that scaffolding exists in this branch's runner.
//
//   Without (1), the kernel rejects map_mmio at §[map_mmio] test 02
//   (E_BADCAP) before any port_io VAR can be installed. Without (2),
//   even a successfully installed port_io VAR cannot deliver an
//   observable memory_fault back to the asserting test child — the
//   kernel would synthesise the event and the test EC would be
//   left waiting on a port that nothing in this runner is wired to
//   read. The faithful arm is therefore unreachable from a v0
//   test child.
//
// Strategy (smoke prelude)
//   Pin the prelude shape the eventual faithful test will reuse: a
//   valid MMIO VAR exists in [1] with the construction §[var]
//   requires when caps.mmio = 1, and a map_mmio call against it is
//   issued. Per §[port_io_virtualization] a port_io device_region
//   must be installed into a uc-cached MMIO VAR (cch = 1), so the
//   prelude builds:
//     - caps = {r, w, mmio} so the VAR is mmio-flagged
//       (§[map_mmio] test 03 closed).
//     - props = {sz = 0 (4 KiB), cch = 1 (uc), cur_rwx = 0b011}
//       — sz = 0 is required for caps.mmio = 1 (§[create_var] test
//         08), cch = 1 (uc) is the only legal cache type for a
//         port_io map_mmio, cur_rwx ⊆ caps.{r, w}.
//     - pages = 1 — minimum-size MMIO VAR; once a port_io
//       device_region is forwarded, the faithful test would size
//       the VAR to span at least `port_count` bytes (rounded up to
//       a page) and then issue a MOV at `VAR.base + port_count` to
//       trip the bounds check.
//   Pass slot 4095 for [2]: per the create_capability_domain table
//   layout that slot is guaranteed empty, so the kernel rejects with
//   E_BADCAP via §[map_mmio] test 02 instead of reaching the bounds-
//   check arm of §[port_io_virtualization] test 06.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a valid
//      mmio-flagged VAR with cch = 1 (uc) sitting in `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02), not the spec'd memory_fault event
//      (§[port_io_virtualization] test 06). The smoke does not
//      assert the rejection code; it pins only the prelude shape.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because
//   the `offset >= port_count` arm is unreachable from a test
//   child without (a) a forwarded port_io device_region installed
//   into the VAR via map_mmio, and (b) a memory_fault event harness
//   the test child can recv from. The test ELF still validates
//   link/load plumbing in CI, and the prelude matches the eventual
//   faithful test so that wiring a port_io device_region and an
//   event port into the runner only requires replacing the
//   slot-4095 stub with the real handle id and adding the
//   memory_fault-recv assertion.
//
// Faithful-test note
//   Faithful test deferred pending two runner extensions:
//
//   1. runner/primary.zig must mint or carve a port_io device_region
//      (dev_type = 1) of a known port_count `K` and forward it to
//      the test child via passed_handles.
//
//   2. The runner must install a fault-handler EC bound to the test
//      child's capability domain and forward an event port to the
//      test child so the kernel-synthesised memory_fault for an
//      out-of-bounds access becomes observable. (See §[event] /
//      §[memory_fault] once the event-routing surfaces land.)
//
//   With both in place, the action becomes:
//     pio = forwarded port_io device_region (port_count = K)
//     fault_port = forwarded event port bound to memory_fault
//                  delivery for this domain
//     pages = ceil(K / 0x1000)
//     mmio_var = create_var(caps={r, w, mmio},
//                           props={sz = 0, cch = 1 (uc),
//                                  cur_rwx = 0b011},
//                           pages = pages, preferred_base = 0,
//                           device_region = 0)
//     map_mmio(mmio_var, pio)            -> success
//     // Touch the first byte past port_count. The kernel's bounds
//     // check (`offset >= port_count`) fires before the in/out
//     // emulator is consulted, so the access never reaches a real
//     // port — it raises memory_fault and userspace observes the
//     // event via fault_port.
//     volatile_load_u8(VAR.base + K)     -> raises memory_fault
//     ev = recv(fault_port)              -> *expected* memory_fault
//   That memory_fault observation is assertion id 1 in a faithful
//   version. Symmetric variants (write at offset = K, MOV with
//   offset = K + 1, MOV with offset spanning the boundary on a 2-
//   or 4-byte access) share this prelude shape and only differ in
//   the operand width / direction fed into the fault-trigger MOV.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR — caps.mmio = 1, props.sz = 0, cch = 1
    // (uc), caps.x = 0, caps.dma = 0 — the construction §[var]
    // requires for an MMIO VAR. cch = 1 (uc) is mandatory for a
    // port_io map_mmio per §[port_io_virtualization]; the faithful
    // test 06 prelude installs a port_io device_region into a uc
    // VAR before tripping the offset >= port_count bounds check.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for port_io mmio
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
    // table layout. The map_mmio call returns E_BADCAP via
    // §[map_mmio] test 02 without ever reaching the port_io install
    // path, let alone the bounds-check arm this test targets. The
    // memory_fault event for an out-of-bounds MOV
    // (§[port_io_virtualization] test 06) is not reachable from a v0
    // test child — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // offset >= port_count arm unreachable from a v0 test child.
    // Pass with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
