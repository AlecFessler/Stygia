// Spec §[create_execution_context] — test 07.
//
// "[test 07] returns E_BADCAP if [4] is nonzero and not a valid IDC
//  handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   Every other slot is empty by construction. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid.
//
//   `[4]` is the target IDC handle: 0 means "target = self", any
//   nonzero value must resolve to a valid IDC handle with `crec` or
//   the kernel rejects the call. With slot 4095 (empty) the resolution
//   itself fails before the cap check, so the kernel must return
//   E_BADCAP per test 07. The other early-error paths are kept clean
//   so they cannot fire ahead of BADCAP:
//     - caller's self-handle has `crec` (root domain holds all rights)
//       → test 01 does not fire.
//     - target = empty slot, so no caps comparison runs (tests 02,
//       04, 05 inapplicable when handle resolution itself fails).
//     - priority = 0 → test 06 does not fire.
//     - stack_pages = 1 (nonzero) → test 08 does not fire.
//     - affinity = 0 (any core) → test 09 does not fire.
//     - reserved bits in [1] are zero → test 10 does not fire.
//
// Action
//   create_execution_context(caps_word, entry, 1, invalid_idc, 0)
//
// Assertion
//   1: result.v1 != E_BADCAP

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31, priority in 32-33. priority=0 keeps the
    // call within the caller's pri ceiling. caps content does not
    // matter — the kernel rejects on the [4] handle lookup before any
    // caps subset check runs.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const caps_word: u64 = @as(u64, ec_caps.toU16());

    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // Slot 4095 is the highest 12-bit handle id and is never populated
    // by `create_capability_domain` (only slots 0..3 are filled here).
    const invalid_idc: u64 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        invalid_idc,
        0,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
