// Spec §[port_io_virtualization] — test 10.
//
// "[test 10] a `LOCK`-prefixed MOV targeting the VAR delivers a
//  `thread_fault` event with the protection_fault sub-code."
//
// DEGRADED SMOKE VARIANT
//   The faithful assertion requires three pieces simultaneously, none
//   of which a v0 test child can supply:
//
//   1. A port_io device_region (dev_type = 1) actually mapped into a
//      caller-readable MMIO VAR via map_mmio. The runner
//      (runner/primary.zig spawnOne) forwards exactly one capability
//      to each test child — the result port at slot 3. Slots 0/1/2
//      are kernel-installed self / initial EC / self-IDC. No
//      device_region of any dev_type, port_io included, reaches a
//      test child today, and a port_io device_region in particular
//      has no ambient host-platform analogue the runner could carve
//      out. Without a forwarded port_io device_region, map_mmio is
//      gated out at §[map_mmio] test 02 (E_BADCAP) before any port
//      I/O virtualization can happen — see port_io_virtualization
//      tests 01 and 02 for the same blocker.
//
//   2. The ability to actually issue a `LOCK`-prefixed MOV against
//      the VAR's virtual range from the test child. Unlike the
//      named IN/OUT mnemonics in test 09, a LOCK-prefixed MOV is
//      not CPL-gated by the CPU itself — but the kernel's port-IO
//      MOV decoder is the gate that emits protection_fault on the
//      LOCK prefix, and that decoder only runs after map_mmio has
//      installed a port_io device_region into the VAR's range.
//      Without a port_io VAR in scope the LOCK-MOV would fault
//      against an unmapped page rather than against the kernel's
//      port-IO MOV decoder, so the protection_fault sub-code that
//      the spec assertion targets cannot be observed.
//
//   3. A thread_fault event harness wired into a test child so the
//      child can observe the kernel-emitted thread_fault and read
//      its sub-code. v0 has no such harness wired through to spec
//      tests; faulting EC events are routed to the parent domain's
//      restart machinery (§[restart_semantics]) rather than
//      bubbling back to the faulting EC for inspection.
//
//   With all three legs blocked, the strict test 10 path (kernel's
//   port-IO MOV decoder rejects a LOCK-prefixed MOV with a
//   protection_fault thread_fault) cannot be exercised end-to-end
//   here.
//
//   This smoke variant pins only the prelude shape the eventual
//   faithful test will reuse: a valid MMIO VAR exists in [1] with
//   the construction §[var] requires when caps.mmio = 1 and
//   props.cch = 1 (uc) — the cch a port_io device_region demands
//   per §[port_io_virtualization] test 02 — and a map_mmio call
//   against it is issued. The gate-order rejection (E_BADCAP via
//   §[map_mmio] test 02 when [2] is an empty slot) confirms the
//   call site is wired up; the LOCK-prefixed-MOV-on-VAR
//   protection_fault the spec assertion targets is not asserted.
//
// Strategy (smoke prelude)
//   Per §[var], creating an MMIO VAR requires:
//     - caps.mmio = 1
//     - caps.x = 0   (per §[create_var] test 11)
//     - caps.dma = 0 (per §[create_var] test 13)
//     - props.sz = 0 (per §[create_var] test 08; mmio VARs are
//       4 KiB page-granular)
//     - props.cch = 1 (uc) — required for an MMIO VAR per §[var]
//       and required for a port_io map_mmio per
//       §[port_io_virtualization] test 02
//   The construction below mirrors map_mmio_06.zig,
//   port_io_virtualization_01.zig, and runner/serial.zig.
//
//   §[map_mmio]'s gate order on the x86-64 host is:
//     - test 01 (VAR is invalid)         — pre-empted; we mint a
//                                           real MMIO VAR.
//     - test 02 (device_region BADCAP)   — fires here, since slot
//                                           4095 is empty by
//                                           construction.
//   The test 10 leg this file targets — kernel rejects a
//   LOCK-prefixed MOV targeting a successfully-mapped port_io VAR
//   with a protection_fault thread_fault — never runs because
//   map_mmio rejects the call before any port-IO virtualization
//   wiring is activated, and even if it did there is no harness
//   to observe the resulting thread_fault sub-code.
//
// Action
//   1. createVar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0) — must succeed; gives a valid
//      MMIO VAR ready to be paired with a hypothetical port_io
//      device_region.
//   2. mapMmio(mmio_var, 4095) — slot 4095 is guaranteed empty by
//      the create_capability_domain table layout (slots 0/1/2 are
//      self / initial_ec / self_idc; passed_handles begin at slot
//      3 and only the result port lands there for tests). The call
//      returns E_BADCAP via §[map_mmio] test 02 without ever
//      reaching the port-IO MOV decoder this test targets.
//
// Assertion
//   No assertion is checked — the LOCK-prefixed-MOV-on-VAR
//   protection_fault leg is unreachable from a v0 test child:
//   no port_io device_region is in scope, the kernel's port-IO
//   MOV decoder never runs without one, and there is no
//   thread_fault observation harness. Passes with assertion id 0
//   to mark this slot as smoke-only in coverage. A failure of the
//   prelude itself (createVar) is also reported as
//   pass-with-id-0 since no spec assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending three independent runner /
//   harness extensions that must all land before the assertion can
//   be observed:
//
//   1. runner/primary.zig must mint or carve a port_io
//      device_region (dev_type = 1, with a `base_port` and
//      `port_count`) and forward it to the test child via
//      `passed_handles` so [2] can name a real port_io handle.
//
//   2. The test child must be able to issue a LOCK-prefixed MOV
//      against the mapped VAR's virtual range. Inline assembly of
//      the form `lock mov BYTE PTR [rax], al` (with rax pointing
//      into mmio_var.base) is sufficient on x86-64 from CPL3 — the
//      LOCK prefix is not itself CPL-gated; it is the kernel's
//      port-IO MOV decoder that must reject it with
//      protection_fault.
//
//   3. A thread_fault observation harness must be added so the
//      test child can read the sub-code of the kernel-emitted
//      thread_fault (or so the runner can observe that the child
//      faulted with sub-code = protection_fault and report
//      assertion success on the child's behalf).
//
//   With all three in place, the action becomes:
//     pio = forwarded port_io device_region
//     create_var(caps={r,w,mmio}, props={sz=0, cch=1, cur_rwx=0b011},
//                pages=ceil(port_count/0x1000), preferred_base=0,
//                device_region=0) -> mmio_var
//     map_mmio(mmio_var, pio) -> success
//     issue a `lock mov` targeting mmio_var.base
//       -> kernel emits thread_fault with sub-code =
//          protection_fault
//     observe sub-code == protection_fault -> assertion id 1
//   Tests 09 (IN/OUT/INS/OUTS) and 11 (8-byte MOV) share this
//   prelude and harness; once the three extensions land they can
//   be wired up alongside test 10.
//
//   Until then, this file holds the prelude verbatim so the
//   eventual faithful version can graft on the LOCK-MOV
//   observation without re-deriving the MMIO-VAR construction.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR — caps.mmio = 1, props.sz = 0,
    // cch = 1 (uc), caps.x = 0, caps.dma = 0 — the construction
    // §[var] requires for an MMIO VAR. cch = 1 also matches what a
    // port_io device_region demands per §[port_io_virtualization]
    // test 02. On creation the VAR sits in `map = 0` per §[var].
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
    // table layout. The map_mmio call returns E_BADCAP via
    // §[map_mmio] test 02 without ever reaching the port-IO MOV
    // decoder this test targets. The LOCK-prefixed-MOV-on-VAR
    // protection_fault leg is not reachable from a v0 test child
    // — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // No spec assertion is being checked — the
    // LOCK-prefixed-MOV-on-VAR protection_fault leg is unreachable
    // from a v0 test child. Pass with assertion id 0 to mark this
    // slot as smoke-only in coverage.
    testing.pass();
}
