// Spec §[reply] reply — test 01.
//
// "[test 01] returns E_BADCAP if `reply_handle_id` is not a valid reply
//  handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be empty,
//   so it cannot reference a valid reply handle.
//
//   Per §[reply], "no self-handle cap required — the reply handle
//   itself authorizes the operation," and the error precedence puts
//   the reply_handle_id validity check ahead of any other gate.
//   Calling reply on an empty slot must therefore return E_BADCAP.
//
//   Under the new §[reply] ABI the reply_handle_id rides in the
//   syscall word (bits 12-23). The libz `syscall.reply` wrapper
//   handles that encoding, so the test only needs to call the typed
//   wrapper with a u12 — same as before.
//
// Action
//   1. reply(invalid_slot) — must return E_BADCAP because
//      reply_handle_id does not reference a valid reply handle.
//
// Assertions
//   1: reply returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The BADCAP gate on reply_handle_id must fire
    // before any other checks.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.reply(empty_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
