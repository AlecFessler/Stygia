// Spec §[create_capability_domain] create_capability_domain — test 21.
//
// "[test 21] on success, the new domain's handle table contains the
//  initial EC at slot 1 with caps = the `ec_inner_ceiling` supplied in
//  [2]."
//
// Strategy
//   This test runs *as* the new capability domain spawned by the
//   primary runner. The runner's `spawnOne` (tests/suite/runner/
//   primary.zig) is the create_capability_domain caller; the success
//   path landed us here, executing the initial EC of the freshly-minted
//   domain. By construction:
//     - `cap_table_base` is this domain's read-only view of its own
//       capability table (§[capabilities] domain self handle).
//     - Slot 1 of that table is the initial-EC handle (§[capability_
//       domain] / SLOT_INITIAL_EC in libz/caps.zig).
//   So the post-condition the spec line names is observable from inside
//   the new domain by simply reading slot 1.
//
//   The runner's ceilings_inner word encodes `ec_inner_ceiling` in bits
//   0-7. It passes 0xFF there (see primary.zig: `ceilings_inner =
//   0x001C_011F_3F01_FFFF`, low byte = 0xFF). Per the spec line, slot
//   1's caps field must therefore equal 0xFF. The test asserts:
//     - slot 1 is non-empty / not an error encoding,
//     - its handle type is execution_context (§[capabilities] type tag),
//     - its caps field equals the runner-provided ec_inner_ceiling.
//
//   No syscall side effects are needed: the static handle layout
//   (word0 carries id/type/caps in bits 0-11/12-15/48-63) is set at
//   create_capability_domain time and not kernel-mutable, so a fresh
//   `readCap` is authoritative without `sync` (same reasoning as
//   restrict_06).
//
// Action
//   1. readCap(cap_table_base, SLOT_INITIAL_EC)
//   2. assert handleType == execution_context
//   3. assert caps == ec_inner_ceiling supplied by the spawner (0xFF)
//
// Assertions
//   1: slot 1's handle type is not execution_context
//   2: slot 1's caps field does not equal the supplied ec_inner_ceiling
//
// Note on coupling: the expected caps value (0xFF) is hard-coded here
// to match the runner's `ceilings_inner` word in primary.zig. If the
// runner's spawn parameters change, this constant must be updated in
// lockstep — there is no inter-process channel by which the test can
// learn the spawner's chosen value, since the spec rule is exactly
// that the initial EC's caps mirror what the spawner asked for.

const lib = @import("lib");

const caps = lib.caps;
const testing = lib.testing;

// The runner's primary spawns each test with `ec_inner_ceiling = 0xFF`
// (low 8 bits of `ceilings_inner`). Per §[create_capability_domain] the
// initial-EC handle the kernel installs at slot 1 must carry exactly
// this 16-bit caps field (the 8-bit ec_inner_ceiling zero-extended).
const EXPECTED_EC_INNER_CEILING: u16 = 0x00FF;

pub fn main(cap_table_base: u64) void {
    const slot1 = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);

    if (slot1.handleType() != caps.HandleType.execution_context) {
        testing.fail(1);
        return;
    }

    if (slot1.caps() != EXPECTED_EC_INNER_CEILING) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
