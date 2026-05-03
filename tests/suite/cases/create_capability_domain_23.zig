// Spec §[create_capability_domain] create_capability_domain — test 23.
//
// "[test 23] on success, passed handles occupy slots 3+ of the new
//  domain's handle table in the order supplied, each with the caps
//  specified in its entry."
//
// Strategy
//   This test runs *as* the new capability domain spawned by the
//   primary runner. The runner's `spawnOne`
//   (tests/suite/runner/primary.zig) is the create_capability_domain
//   caller; the success path landed us here, executing the initial EC
//   of the freshly-minted domain. By construction:
//     - `cap_table_base` is this domain's read-only view of its own
//       capability table (§[capabilities] domain self handle).
//     - Slot 3 (`SLOT_FIRST_PASSED` in libz/caps.zig) is the first
//       passed handle the spawner installed.
//   So the post-condition the spec line names is observable from inside
//   the new domain by simply reading slot 3 (the runner passes exactly
//   one handle).
//
//   The runner passes a single passed-handle entry: the result port,
//   with caps = `{xfer = true, bind = true}` (see primary.zig:
//   `child_port_caps`). Per §[port], `PortCap` lays out
//   `move=bit0, copy=bit1, xfer=bit2, recv=bit3, bind=bit4`, so the
//   expected 16-bit caps word is `0b10100 = 0x14`. The handle type at
//   slot 3 must be `port` (§[capabilities] type tag = 6).
//
//   No syscall side effects are needed: the static handle layout
//   (word0 carries id/type/caps in bits 0-11/12-15/48-63) is set at
//   create_capability_domain time and not kernel-mutable, so a fresh
//   `readCap` is authoritative without `sync` (same reasoning as
//   restrict_06 / create_capability_domain_21).
//
// Order check
//   The runner only passes one handle, so "in the order supplied" is
//   trivially satisfied by the entry landing at SLOT_FIRST_PASSED. The
//   ordering portion of the spec line is fully exercised once a
//   multi-handle runner spawn becomes feasible; for now the v0 runner's
//   single-entry payload pins only the slot-3 placement and caps. A
//   future iteration that passes ≥2 handles can extend this test to
//   walk slot 3, slot 4, ... and assert each in turn.
//
// Action
//   1. readCap(cap_table_base, SLOT_FIRST_PASSED)
//   2. assert handleType == port
//   3. assert caps == {xfer=true, bind=true}.toU16()
//
// Assertions
//   1: slot 3's handle type is not port
//   2: slot 3's caps field does not equal the supplied entry caps
//
// Note on coupling: the expected caps value here mirrors the runner's
// `child_port_caps` in primary.zig. If the runner's spawn parameters
// change, this constant must be updated in lockstep — there is no
// inter-process channel by which the test can learn the spawner's
// chosen value, since the spec rule is exactly that the slot-3 handle's
// caps mirror what the spawner asked for.

const lib = @import("lib");

const caps = lib.caps;
const testing = lib.testing;

// Mirrors `child_port_caps` in tests/suite/runner/primary.zig:
//   PortCap{ .xfer = true, .bind = true }
// Per §[port] layout (move=0, copy=1, xfer=2, recv=3, bind=4) this is
// the 16-bit value 0b0000_0000_0001_0100 = 0x0014.
const EXPECTED_PASSED_CAPS: u16 = blk: {
    const c = caps.PortCap{ .xfer = true, .bind = true };
    break :blk c.toU16();
};

pub fn main(cap_table_base: u64) void {
    const slot3 = caps.readCap(cap_table_base, caps.SLOT_FIRST_PASSED);

    if (slot3.handleType() != caps.HandleType.port) {
        testing.fail(1);
        return;
    }

    if (slot3.caps() != EXPECTED_PASSED_CAPS) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
