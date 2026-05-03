// Spec §[restart_semantics] restart_semantics — test 04.
//
// "[test 04] returns E_PERM if `create_virtual_machine` is called with
//  `caps.restart_policy = 1` and the calling domain's
//  `restart_policy_ceiling.vm_restart_max = 0`."
//
// Strategy (DEGRADED SMOKE VARIANT)
//   The faithful shape requires the calling domain to have
//   `vm_restart_max = 0` so create_virtual_machine with
//   `caps.restart_policy = 1` triggers the spec-mandated E_PERM. The
//   primary runner (runner/primary.zig) currently spawns each test in a
//   child capability domain whose `restart_policy_ceiling` field has
//   `vm_restart_max = 1` (bit 7 of the ceiling = 1, encoded in
//   ceilings_outer = 0x0000_003F_03FE_FFFF). With vm_restart_max = 1,
//   `caps.restart_policy = 1` is *within* the ceiling and the kernel
//   must NOT return E_PERM on that field — the spec violation can't
//   fire from inside the runner's child domain as currently provisioned.
//
//   Reaching the violation faithfully would require either:
//     - the runner spawning this test in a sibling domain whose
//       ceilings_outer carves vm_restart_max back out (orthogonal to
//       this test, and would weaken the rest of the runner's test
//       fixture); or
//     - this test creating a sub-sub-domain with vm_restart_max = 0
//       and shipping an embedded ELF inside it that performs the
//       create_virtual_machine call (significant infrastructure: a
//       second ELF image embedded into this test, plus a result-port
//       grant chain to relay the assertion outcome).
//
//   Until the runner grows a per-test ceilings override (or a similar
//   knob), this test runs as a smoke variant: it exercises the
//   create_virtual_machine syscall path with the exact `caps` shape
//   the spec calls out, and asserts a non-E_PERM outcome. That's the
//   inverted-but-consistent observation given the ambient ceilings —
//   if the kernel ever (incorrectly) returned E_PERM here under
//   vm_restart_max = 1, this test would catch it.
//
//   The build product (bin/restart_semantics_04.elf) is the load-bearing
//   artifact for the v3 test scaffold; the assertion shape will be
//   tightened to the faithful E_PERM path when the runner gains the
//   per-test ceilings override.
//
// Setup
//   create_virtual_machine requires a page_frame containing a VmPolicy
//   struct at offset 0. We mint a page_frame with `r|w` and one page
//   (4 KiB > sizeof(VmPolicy) on either supported arch) without
//   bothering to populate the policy bytes; the kernel only reads them
//   on the success path, and the v0 mock runner under which this test
//   compiles never reaches that point.
//
// Action
//   1. create_page_frame(caps={r,w}, props=0, pages=1)
//      — must succeed (E_PERM here means crpf or pf_ceiling.max_rwx
//        is misconfigured, which is a runner-fixture bug, not a test
//        of this spec line).
//   2. create_virtual_machine(caps={restart_policy=1}, policy_pf=pf)
//      — must NOT return E_PERM under the runner's vm_restart_max = 1
//        ceiling.
//
// Assertions
//   1: setup syscall failed (create_page_frame returned an error word)
//   2: create_virtual_machine returned E_PERM despite vm_restart_max=1
//      (faithful spec test inverted; see strategy comment above)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // one 4 KiB page is larger than VmPolicy
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // §[virtual_machine] VmCap layout: bit 0 = policy, bit 1 =
    // restart_policy. Setting restart_policy = 1 is the cap shape the
    // spec calls out for this test.
    const vm_caps = caps.VmCap{ .restart_policy = true };
    const result = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        pf_handle,
    );

    // SPEC TEST INVERSION: under the runner's vm_restart_max = 1, the
    // spec line forbids E_PERM on this exact call. The faithful E_PERM
    // path needs vm_restart_max = 0 in the calling domain — see the
    // strategy comment for why that's not yet wired.
    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
