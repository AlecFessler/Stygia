// Spec §[capabilities] revoke — test 06.
//
// "[test 06] revoke([1]) does not release any handle on the copy ancestor
//  side of [1]."
//
// Spec semantics
//   revoke walks DOWN the copy chain (descendants) but never UP it
//   (ancestors). Concretely: if domain X has a port and domain Y
//   receives a copy of that port from X, then Y holds the descendant
//   and X holds the ancestor. If Y issues revoke on its own copy, the
//   spec requires that X's original handle be untouched — the chain
//   walk only releases derivations of [1], not its parent.
//
// Strategy (degraded variant)
//   The faithful test would look like:
//     1. domain X creates port P (ancestor)
//     2. X spawns child Y with P passed via move=0 (copy)
//     3. Y revokes its received copy of P
//     4. X observes that its slot for P is still alive
//
//   The current test infrastructure embeds each test ELF directly in
//   the primary's manifest and spawns each as a single capability
//   domain. There is no path for a test ELF to embed a second ELF and
//   spawn it as a grandchild of the primary, so step 2 above is not
//   reachable from a single-file test today. Faithfully exercising
//   this assertion needs a "two-level test" infra extension: a test
//   that ships its own child ELF, stages it into a page frame at
//   runtime, and calls create_capability_domain on that page frame.
//   revoke 03 and revoke 04 face the same gap (multi-domain copy
//   chains) and have been deferred for the same reason.
//
//   In the meantime we land the trivially-decidable single-domain
//   case: a freshly-minted port has no copy ancestors anywhere in the
//   system, so the "no ancestor handle is released" requirement is
//   vacuously satisfied. We assert that the call succeeds and the
//   target's own slot survives (which is also the explicit subject of
//   revoke 05). This narrows the spec rule to "revoke does not
//   release the target itself" — a strict subset of test 06's claim
//   — and leaves the cross-domain ancestor preservation case for the
//   multi-domain test infra.
//
// Action
//   1. create_port(caps = {bind, recv})             — must succeed
//   2. revoke(port)                                  — must return OK
//   3. readCap(cap_table_base, port)                 — must still be a
//      valid port handle (handleType == .port, id matches)
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: revoke itself returned non-success in vreg 1
//   3: the target's slot is no longer a port handle (i.e., revoke
//      released [1] itself, contradicting the "ancestor side" rule
//      since a freshly-minted port IS its own ancestor end of the
//      chain)

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
    if (cap.handleType() != .port or cap.id() != port_handle) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
