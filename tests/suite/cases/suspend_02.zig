// Spec §[suspend] suspend — test 02.
//
// "[test 02] returns E_BADCAP if [2] is not a valid port handle."
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
//   as a port handle.
//
//   To exercise the [2] BADCAP gate we must pass a valid EC handle
//   for [1]; otherwise the [1] BADCAP gate (test 01) would preempt
//   it. Slot 1 is the initial EC for this domain and is guaranteed
//   valid as an EC handle.
//
// Action
//   1. suspend(self_ec, invalid_port_slot) — must return E_BADCAP
//      because the port slot is empty.
//
// Assertions
//   1: suspend returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 1 is the initial EC — guaranteed a valid EC handle by the
    // create_capability_domain table layout. Slot 4095 is guaranteed
    // empty, so referencing it as a port handle must trip E_BADCAP.
    const self_ec: u12 = 1;
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.suspendEc(self_ec, empty_slot, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
