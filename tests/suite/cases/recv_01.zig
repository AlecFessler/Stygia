// Spec §[recv] recv — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid port handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   Every other slot is empty by construction. Slot 4095 — the maximum
//   12-bit handle id — is therefore guaranteed to be invalid as a port
//   handle.
//
//   The §[recv] gate order rejects an invalid [1] before consulting
//   any port-state, so passing an empty slot id observes E_BADCAP
//   without needing further setup.
//
// Action
//   1. recv(invalid_port_slot) — must return E_BADCAP because [1]
//      (the port slot) is empty.
//
// Assertions
//   1: recv returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [1] fires before any other
    // checks against the port.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.recv(empty_slot, 0);

    if (result.regs.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
