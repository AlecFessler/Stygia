// Spec §[suspend] suspend — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid EC handle."
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
//   as an EC handle.
//
//   §[suspend] test 02 says E_BADCAP fires if [2] is not a valid port
//   handle. To exercise the [1] BADCAP gate without [2] preempting it,
//   pass slot 2 (the self-IDC port, guaranteed valid) for [2]. The
//   BADCAP gate on [1] must fire before [2] is dereferenced; the
//   `bind` cap status of slot 2 is irrelevant once [1] is rejected.
//
// Action
//   1. suspend(invalid_ec_slot, self_idc_port) — must return E_BADCAP
//      because the EC slot is empty.
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

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on [1] must fire before any
    // validation of [2], so the port slot's caps are irrelevant.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;
    const self_idc_port: u12 = 2;

    const result = syscall.suspendEc(empty_slot, self_idc_port, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
