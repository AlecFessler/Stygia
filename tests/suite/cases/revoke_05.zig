// Spec §[capabilities] revoke — test 05.
//
// "[test 05] revoke([1]) does not release [1] itself."
//
// Strategy
//   The spec prose above the test list states explicitly: "The target
//   handle itself is not released — use `delete` for that." Revoke
//   walks the descendant chain rooted at [1] and applies the
//   type-specific delete behavior to each descendant, but the target
//   slot survives the call.
//
//   Mint a fresh port handle. The freshly-minted handle has no
//   descendants (no `copy` has happened), so revoke has no chain to
//   walk — the only observable effect under test is "did the target
//   slot survive?" which is the precise post-condition for test 05.
//
//   Confirm survival by reading the slot back out of the read-only
//   cap-table mapping. Per §[capabilities], an empty slot has word0 =
//   0; its handle-type tag (bits 12-15) therefore decodes to
//   `capability_domain_self` (the 0-valued tag in HandleType). A slot
//   that still references the port keeps the port type tag (= 6).
//   Asserting `handleType() == .port` is the cleanest survivability
//   probe and matches the readCap pattern used by restrict_06.
//
// Action
//   1. create_port(caps = {bind, recv}) — must succeed (sets up the
//      target handle and gives it caps the runner's port_ceiling
//      grants per §[create_port]).
//   2. revoke(port) — must return OK in vreg 1.
//   3. readCap(cap_table_base, port) — assert handleType() == .port.
//
// Assertions
//   1: setup failed (create_port returned an error word in vreg 1).
//   2: revoke itself returned non-OK in vreg 1.
//   3: post-revoke slot no longer decodes as a port handle (released).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const initial = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const result = syscall.revoke(port_handle);
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, port_handle);
    if (cap.handleType() != .port) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
