// Spec §[capabilities] revoke — test 04.
//
// "[test 04] a handle that was copied from [1] and then subsequently
//  moved is released by revoke([1])."
//
// The faithful test requires three capability domains so the chain
// {original in X, copy in Y, moved-from-Y-into-Z} can exist
// simultaneously, plus a way for X to observe that Z's handle is
// released after revoke. Building that out of a single test ELF
// needs:
//   - X spawns child Y with the port copied to it (passed_handles
//     entry with move=0).
//   - Y spawns grandchild Z, passing Y's copy handle with move=1 so
//     Z holds a moved-after-copy descendant of X's original.
//   - Z observes its own handle's status after X calls revoke.
//   - Z reports back to X over a separate result port.
// None of that infrastructure (multi-ELF nesting, cross-domain result
// reporting beyond the primary↔test result port) exists in the v0
// runner. Spawning a separate sub-ELF from inside a test, and the
// "Z reports to X" channel for cross-domain observation, are
// prerequisites the runner does not yet provide.
//
// Degraded smoke variant
//   The kernel-side mechanism revoke 04 exercises is the same code
//   path revoke 03 walks (`copy ancestor → derived holders are
//   released`). The 04-specific bit is that the chain must survive a
//   `move` that re-parents the descendant from one domain to another
//   without orphaning it.
//
//   Without nested-spawn + cross-domain reporting we cannot construct
//   that ancestry chain in user space. Instead this test exercises
//   the success-path shape: revoke on a freshly minted port (no
//   descendants) returns OK, and the target itself remains usable per
//   §[revoke] test 05 ("revoke([1]) does not release [1] itself").
//
//   When nested-spawn + reporting land, this test should be replaced
//   with the full chain-of-three observation. The doc comment here
//   marks the gap explicitly so the upgrade is not lost.
//
// Action
//   1. create_port(caps={move,copy,bind,recv}) — must succeed
//   2. revoke(port)                            — must return OK
//   3. recv(port) is intentionally *not* called (would block; see
//      restrict_07 for the same reasoning around recv on a still-bound
//      port). Instead, re-use the handle via `restrict` to a strict
//      subset of its caps; that path returns E_BADCAP if the handle
//      slot was wrongly released and OK otherwise, validating that
//      revoke did not release the target.
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: revoke returned non-OK
//   3: handle was released by revoke (post-revoke restrict returned
//      E_BADCAP, contradicting §[revoke] test 05's invariant relied
//      on for this smoke check)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{
        .move = true,
        .copy = true,
        .bind = true,
        .recv = true,
    };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const revoke_result = syscall.revoke(port_handle);
    if (revoke_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // §[revoke] test 05: revoke does not release the target. Probe by
    // restricting the handle to a strict subset of its current caps.
    // If revoke had wrongly released the slot, the kernel would return
    // E_BADCAP; on the well-formed path this returns OK.
    const reduced = caps.PortCap{ .bind = true };
    const restrict_result = syscall.restrict(port_handle, @as(u64, reduced.toU16()));
    if (restrict_result.v1 == @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
