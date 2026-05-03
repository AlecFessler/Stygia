// Spec §[create_virtual_machine] — test 04.
//
// "[test 04] returns E_BADCAP if [2] is not a valid page frame handle."
//
// Strategy
//   To isolate the page_frame BADCAP check, every other rejection path
//   the kernel could fire ahead of the [2] handle-validity check must
//   be inert:
//     - test 01 (caller's self-handle lacks `crvm`) — the runner grants
//       `crvm` on the test domain's self-handle (runner/primary.zig).
//     - test 02 (caps not a subset of `vm_ceiling`) — caps = 0 is a
//       subset of any ceiling.
//     - test 08 (reserved bits in [1]) — caps = 0 leaves all reserved
//       bits clear.
//   The kernel cannot dereference `policy_page_frame` (tests 05-07)
//   without first resolving slot [2] to a page_frame handle, so those
//   checks cannot fire ahead of the BADCAP probe on an empty slot.
//
//   The test capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0 → self
//     slot 1 → initial EC
//     slot 2 → self-IDC
//     slot 3 → result port (the only passed_handle from the runner)
//   Slot 4095 — the maximum 12-bit handle id — is therefore guaranteed
//   to be empty (same construction used by map_pf_02 and restrict_01).
//
// Action
//   1. createVirtualMachine(caps = 0, policy_pf = slot 4095)
//      — slot 4095 is empty by construction, so the kernel must return
//        E_BADCAP per §[create_virtual_machine] test 04.
//
// Assertions
//   1: createVirtualMachine did not return E_BADCAP (the spec
//      assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.createVirtualMachine(0, empty_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
