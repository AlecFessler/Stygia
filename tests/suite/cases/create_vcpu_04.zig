// Spec §[create_vcpu] — test 04.
//
// "[test 04] returns E_BADCAP if [2] is not a valid VM handle."
//
// Strategy
//   To isolate the [2] VM-handle BADCAP check, every other rejection
//   path the kernel could fire ahead of it must be inert:
//     - test 01 (caller's self-handle lacks `crec`) — the runner grants
//       `crec` on the test domain's self-handle (runner/primary.zig).
//     - test 02 (caps not a subset of the VM's owning domain's
//       `ec_inner_ceiling`) — caps = 0 is a subset of any ceiling,
//       and resolving the owning domain's ceiling requires the [2]
//       handle to first resolve to a VM, so on an empty slot this
//       check cannot fire ahead of the BADCAP probe in any case.
//     - test 03 (priority exceeds caller's priority ceiling) — caps[1]
//       priority field = 0, which can never exceed any ceiling.
//     - test 07 (reserved bits in [1]) — caps[1] = 0 leaves all
//       reserved bits clear.
//   The kernel cannot validate [4] (test 05) without first having to
//   resolve [2]; spec test ordering (04 before 05) implies [2] is
//   checked before [4]. We pass exit_port = 0 (the self-handle slot)
//   to avoid the ambiguity entirely — even if the kernel were to
//   validate [4] first, the only listed E_BADCAP outcomes for the
//   syscall are [2] and [4] BADCAP, both of which collapse to the
//   same error code that this test asserts.
//
//   The test capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0 → self
//     slot 1 → initial EC
//     slot 2 → self-IDC
//     slot 3 → result port (the only passed_handle from the runner)
//   Slot 4095 — the maximum 12-bit handle id — is therefore guaranteed
//   to be empty (same construction used by create_virtual_machine_04
//   and map_pf_02).
//
// Action
//   1. createVcpu(caps = 0, vm_handle = slot 4095, affinity = 0,
//                 exit_port = 0)
//      — slot 4095 is empty by construction, so the kernel must return
//        E_BADCAP per §[create_vcpu] test 04.
//
// Assertions
//   1: createVcpu did not return E_BADCAP (the spec assertion under
//      test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.createVcpu(
        0, // [1] caps = 0 — clean reserved bits, priority 0
        empty_slot, // [2] vm_handle — empty slot, the bit under test
        0, // [3] affinity = 0 (any core)
        0, // [4] exit_port — see header note on ordering
    );

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
