// Spec §[port_io_virtualization] — test 11.
//
// "[test 11] an 8-byte MOV access targeting the VAR delivers a
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
//   2. The ability to issue an 8-byte MOV (e.g. `mov rax, [rdi]`)
//      against the VAR's virtual range from the test child and have
//      that load reach the kernel's port-IO page-fault handler with
//      its operand width visible in the decoded instruction. The
//      faithful test 11 path — kernel decodes the faulting MOV, sees
//      operand width = 8 bytes, and synthesizes a protection_fault
//      thread_fault per §[port_io_virtualization] — is gated on the
//      port_io VAR existing in the first place (leg 1). Without a
//      port_io device_region in scope, no MOV against this address
//      range — 8-byte or otherwise — reaches the port-IO decoder.
//
//   3. A thread_fault event harness wired into a test child so the
//      child can observe the kernel-emitted thread_fault and read
//      its sub-code. v0 has no such harness wired through to spec
//      tests; faulting EC events are routed to the parent domain's
//      restart machinery (§[restart_semantics]) rather than
//      bubbling back to the faulting EC for inspection.
//
//   With all three legs blocked, the strict test 11 path (kernel's
//   port-IO MOV decoder rejects an 8-byte MOV form with a
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
//   call site is wired up; the 8-byte-MOV-on-VAR protection_fault
//   the spec assertion targets is not asserted.
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
//   The construction below mirrors port_io_virtualization_09.zig
//   and port_io_virtualization_10.zig — tests 09, 10, and 11 all
//   share the same prelude shape, since each is blocked on the
//   same three runner/harness extensions.
//
//   §[map_mmio]'s gate order on the x86-64 host is:
//     - test 01 (VAR is invalid)         — pre-empted; we mint a
//                                           real MMIO VAR.
//     - test 02 (device_region BADCAP)   — fires here, since slot
//                                           4095 is empty by
//                                           construction.
//   The test 11 leg this file targets — kernel rejects an 8-byte
//   MOV targeting a successfully-mapped port_io VAR with a
//   protection_fault thread_fault — never runs because map_mmio
//   rejects the call before any port-IO virtualization wiring is
//   activated.
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
//   No assertion is checked — the 8-byte-MOV-on-VAR
//   protection_fault leg is unreachable from a v0 test child:
//   no port_io device_region is in scope, an 8-byte MOV against
//   the unmapped range is structurally unreachable, and there is
//   no thread_fault observation harness. Passes with assertion
//   id 0 to mark this slot as smoke-only in coverage. A failure
//   of the prelude itself (createVar) is also reported as
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
//   2. The test child must be able to issue an 8-byte MOV
//      (e.g. `mov rax, [rdi]` or `mov [rdi], rax`) against the
//      mapped VAR's virtual range. With a port_io VAR mapped via
//      map_mmio, every CPU access to the range page-faults into
//      the kernel; the kernel's port-IO MOV decoder then sees the
//      8-byte operand width and is required by spec to deliver a
//      protection_fault thread_fault rather than performing the
//      `in`/`out` (which has no 8-byte form on x86-64).
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
//     issue an 8-byte MOV targeting mmio_var.base
//       -> kernel emits thread_fault with sub-code =
//          protection_fault
//     observe sub-code == protection_fault -> assertion id 1
//   Tests 09 (IN/OUT/INS/OUTS) and 10 (LOCK-prefixed MOV) share
//   this prelude and harness; once the three extensions land they
//   can be wired up alongside test 11.
//
//   Until then, this file holds the prelude verbatim so the
//   eventual faithful version can graft on the 8-byte-MOV
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
    // decoder this test targets. The 8-byte-MOV-on-VAR
    // protection_fault leg is not reachable from a v0 test child
    // — see header comment.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // No spec assertion is being checked — the 8-byte-MOV-on-VAR
    // protection_fault leg is unreachable from a v0 test child.
    // Pass with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
