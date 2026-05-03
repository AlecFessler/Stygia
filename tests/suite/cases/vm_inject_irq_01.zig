// Spec §[vm_inject_irq] vm_inject_irq — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid VM handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid
//   as a VM handle.
//
// Action
//   1. vm_inject_irq(invalid_vm_slot, irq_num = 0, assert = 1) —
//      must return E_BADCAP because the VM slot is empty. The BADCAP
//      gate on [1] must fire before any validation of [2] or [3].
//
// Assertions
//   1: vm_inject_irq returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [1] must fire before any
    // validation of irq_num or assert_word.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.vmInjectIrq(empty_slot, 0, 1);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
