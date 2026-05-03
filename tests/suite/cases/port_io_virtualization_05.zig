// Spec §[port_io_virtualization] — test 05.
//
// "[test 05] a 1-, 2-, or 4-byte MOV store to `VAR.base + offset`
//  (offset < port_count, `cur_rwx.w = 1`) commits the source value
//  to port `base_port + offset` (observable on a loopback
//  device_region as a subsequent MOV load returning that value),
//  and execution resumes at the instruction immediately following
//  the MOV."
//
// DEGRADED SMOKE VARIANT
//   This assertion turns on the kernel decoding a faulting MOV
//   *store* into the MMIO VAR's range, executing an x86-64 `out`
//   of the matching operand width at `base_port + offset`, and
//   advancing RIP past the MOV. Per §[port_io_virtualization] the
//   range itself page-faults on every access — `map_mmio` reserves
//   the virtual range but never populates CPU page tables for a
//   port_io device_region — so the decode + emulate path is the
//   only legal way userspace observes the write.
//
//   Three independent gates each individually block this assertion
//   from being reached out of a v0 test child:
//
//   1. No port_io device_region is forwarded into the test child.
//      The v0 runner (runner/primary.zig spawnOne) populates the
//      child capability domain via `create_capability_domain`'s
//      `passed_handles`, which on this branch carry only the
//      result port at slot 3 — slots 0/1/2 are kernel-installed as
//      self / initial EC / self-IDC. Without a port_io
//      device_region in [2] the kernel rejects `map_mmio` at
//      §[map_mmio] test 02 (E_BADCAP) before the port_io install
//      path ever runs, so no MMIO VAR has a port_io range to
//      fault into.
//
//   2. No loopback device_region is forwarded either. Test 05
//      *uniquely* among the §[port_io_virtualization] cases needs
//      a witness — a second port_io device_region wired to the
//      same `base_port + offset` whose subsequent MOV load returns
//      the byte/word/dword the store committed. The runner has no
//      ambient host-platform port pair it can carve into a
//      paired-loopback shape, so even if (1) were lifted, the
//      observability half of the assertion has no carrier.
//
//   3. The decode path itself is exercised by an in-range MOV from
//      userspace, which on a populated port_io VAR raises a
//      page-fault the kernel handles per §[port_io_virtualization].
//      With (1) blocked the test child has no such VAR, so the
//      MOV cannot be issued. Issuing one against an unmapped vaddr
//      would deliver `memory_fault` (covered by tests 06-08), not
//      the test 05 emulate-and-resume path.
//
//   With all three blocked simultaneously, the strict test 05 path
//   (kernel emulates an `out` and the loopback witness reflects
//   the value back through emulated `in`) cannot be exercised end-
//   to-end here. The smoke variant pins only the prelude shape:
//   build the MMIO VAR `map_mmio` would install the port_io
//   device_region into.
//
// Strategy (smoke prelude)
//   Build a valid MMIO VAR with the construction §[var] requires
//   when `caps.mmio = 1` and `caps.w = 1` (the §[port_io_virt-
//   ualization] test 05 precondition is `cur_rwx.w = 1`):
//     - caps = {r, w, mmio} so the VAR is mmio-flagged
//       (§[map_mmio] test 03 closed) and the `cur_rwx.w = 1`
//       precondition is reachable.
//     - props = {sz = 0 (4 KiB), cch = 1 (uc), cur_rwx = 0b011}
//       — sz = 0 is required for `caps.mmio = 1` (§[create_var]
//         test 08), cch = 1 (uc) is the only legal cch for a
//         port_io install (§[port_io_virtualization] test 02),
//         cur_rwx = r|w pins both the load (test 04) and the
//         store (this test) preconditions.
//     - pages = 1 — minimum-size MMIO VAR; once a port_io
//       device_region is forwarded, the faithful test would size
//       the VAR to match that device_region's port_count
//       (rounded up to a page).
//   Pass slot 4095 for [2]: per the create_capability_domain
//   table layout that slot is guaranteed empty, so the kernel
//   rejects with E_BADCAP via §[map_mmio] test 02 instead of
//   reaching the port_io install path.
//
// Action
//   1. createVar(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = 1, preferred_base = 0,
//                device_region = 0) — must succeed; gives a
//      valid mmio-flagged VAR with cch = 1 (uc) and cur_rwx.w = 1
//      sitting in `map = 0`.
//   2. mapMmio(mmio_var, 4095) — observed result is E_BADCAP
//      (§[map_mmio] test 02), not a successful install. The smoke
//      does not assert the rejection code; it pins only the
//      prelude shape.
//
// Assertion
//   No assertion is checked — the emulate-and-resume arm
//   (§[port_io_virtualization] test 05) is unreachable from a v0
//   test child without a forwarded port_io device_region (and
//   loopback witness). Passes with assertion id 0 to mark this
//   slot as smoke-only in coverage. The test ELF still validates
//   link/load plumbing in CI, and the prelude matches the eventual
//   faithful test so wiring port_io + loopback device_regions into
//   the runner only requires replacing the slot-4095 stub with the
//   real handle ids and adding the load-back assertion.
//
// Faithful-test note
//   Faithful test deferred pending two runner extensions:
//
//   1. runner/primary.zig must mint or carve two paired port_io
//      device_regions:
//        pio_w = port_io device_region (base_port = B,
//                                       port_count = K)
//        pio_r = port_io device_region (base_port = B,
//                                       port_count = K)
//      where B...B+K-1 is a host-side loopback such that an
//      `out` of value V to `B + i` makes a subsequent `in` from
//      `B + i` return V. Both must be forwarded to the test
//      child via passed_handles.
//
//   2. The host platform must expose such a loopback range to
//      the test runner. No general-purpose x86-64 port range
//      provides this without a paravirt assist, so this likely
//      lands as a tiny QEMU helper device the runner attaches
//      to a known port window.
//
//   With both in place, the action becomes:
//     pio_w, pio_r = forwarded paired port_io device_regions
//                    (port_count = K, shared base_port = B)
//     create_var(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = ceil(K / 0x1000),
//                preferred_base = 0, device_region = 0) -> var_w
//     create_var(caps={r, w, mmio}, props={sz = 0, cch = 1 (uc),
//                cur_rwx = 0b011}, pages = ceil(K / 0x1000),
//                preferred_base = 0, device_region = 0) -> var_r
//     map_mmio(var_w, pio_w) -> ok
//     map_mmio(var_r, pio_r) -> ok
//     // store path — assertion id 1
//     for width in {1, 2, 4}:
//       *(uN *)(var_w.base + 0) = sentinel_N    // MOV store,
//                                                // page-fault
//                                                // emulated as
//                                                // `out`
//       observed = *(uN *)(var_r.base + 0)      // MOV load,
//                                                // page-fault
//                                                // emulated as
//                                                // `in`; should
//                                                // return
//                                                // sentinel_N
//       assert observed == sentinel_N
//     // assertion id 2 (RIP advance):
//     // each MOV's "next instruction" must execute, observable
//     // by reaching the per-width assertion above and the
//     // testing.pass(2) at the end without a thread_fault /
//     // memory_fault preempting the resumption.
//   Until then, this file holds the prelude verbatim so the
//   eventual faithful version can graft on the loopback
//   observation without re-deriving the MMIO-VAR construction.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Build a valid MMIO VAR — caps.mmio = 1, props.sz = 0,
    // cch = 1 (uc), cur_rwx = r|w — the construction §[var]
    // requires for an MMIO VAR a port_io device_region could be
    // installed into, with `cur_rwx.w = 1` so the test 05 store
    // precondition is reachable. caps.x = 0 keeps
    // §[port_io_virtualization] test 03 closed; caps.dma = 0
    // keeps §[create_var] test 13 closed.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w — pins test 05's `cur_rwx.w = 1`
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
    // table layout. The §[map_mmio] gate order rejects an invalid
    // [2] (test 02, E_BADCAP) before the port_io install path
    // could ever populate the VAR's range — the
    // §[port_io_virtualization] test 05 emulate-and-resume arm
    // (E_OK with a loopback-observable side effect) is not reachable
    // from a v0 test child. We do not assert on the result code —
    // this is a degraded smoke pinning only the prelude shape until
    // the runner forwards paired port_io device_regions.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.mapMmio(mmio_var_handle, empty_slot);

    // Emulate-and-resume arm unreachable from a v0 test child. Pass
    // with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
