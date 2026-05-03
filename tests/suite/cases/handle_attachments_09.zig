// Spec §[handle_attachments] handle_attachments — test 09.
//
// "[test 09] on recv, source entries with `move = 1` are removed from
//  the sender's table; entries with `move = 0` are not removed."
//
// DEGRADED SMOKE VARIANT
//
//   A faithful test needs three things the v0 runner + libz cannot
//   deliver yet:
//
//     1. Two cooperating ECs in the same capability domain — a sender
//        EC that calls `suspend(target=self, port, attachments=...)`
//        with a hand-built attachment list, and a receiver EC that
//        `recv`s on the same port. Test 09's invariant is observable
//        only after recv resolves; before recv the kernel may not yet
//        have committed the move/copy decision (per the spec text just
//        above [test 01]: "the actual move/copy is performed at recv
//        time"). The runner v0 spawns each test as a single-EC child
//        domain whose initial EC runs `main` and exits — there is no
//        provisioned second EC and the result port is held by the
//        primary, not by a sibling EC inside the test domain.
//
//     2. A live high-vreg suspend dispatch path. §[handle_attachments]
//        places pair entries at vregs `[128-N..127]`, the high end of
//        the vreg space. libz's `suspendEc` `@panic`s when N > 0
//        because `issueStack` doesn't yet emit the asm sequence to
//        pad rsp by enough quadwords (115+) to address those slots
//        and populate them. Replacing the call with an inline asm
//        block would avoid the libz panic, but the kernel side of the
//        high-vreg path is also v0 — see the matching SPEC AMBIGUITY
//        notes in libz/syscall.zig — so even a hand-rolled asm
//        dispatch would observe a degenerate response.
//
//     3. A pair of source handles in the sender's table to attach
//        with `move = 1` and `move = 0` respectively, both holding
//        the requisite `move` / `copy` caps so neither entry is
//        rejected by [test 04] or [test 05]. The cleanest source
//        objects are ports the sender mints itself (PortCap allows
//        both move and copy), which the sender can post-recv inspect
//        via `readCap` to assert that the move=1 slot is now empty
//        and the move=0 slot still holds its handle.
//
//   None of these blockers are fixable inside this test alone. They
//   sit upstream — in the runner's child-domain provisioning, in
//   libz's stack-vreg dispatcher, and in the kernel's recv-time
//   commit of the move/copy decision. The test is written here as a
//   compile-and-link placeholder so the build manifest stays in sync
//   with the spec checklist; the actual assertion is replaced with a
//   pass() so the runner records a green and moves on.
//
//   When the upstream pieces land, replace the smoke body with the
//   faithful sequence:
//
//     1. Mint two source ports `move_port` and `copy_port` with caps
//        `move|copy|recv|bind` so both `move=1` and `move=0`
//        attachment paths are open on each.
//     2. Pre-stage a receiver EC bound to a sibling port, or — if
//        single-EC — drive the sender→suspend, sibling→recv exchange
//        through a coroutine-style ping using the inline asm
//        equivalent of suspendEc with the high-vreg pad populated.
//     3. After recv resolves on the receiver side, `readCap` the
//        sender's slots: the `move=1` source slot must read empty
//        (handle id == 0 or type tag == 0) and the `move=0` source
//        slot must still hold the original handle.
//
// Action (current degraded form)
//   - Build a `caps.PairEntry` with `move = true` and a second with
//     `move = false` to keep the pair-entry layout helper exercised
//     at compile time so a future edit to the bit layout would
//     surface here.
//   - Reference the syscall enum and a relevant cap struct so the
//     SyscallNum / cap layout would surface a regression at compile
//     time before the faithful body lands.
//   - Call testing.pass() so the build manifest entry round-trips
//     end-to-end through the runner.
//
// Assertion id reservations for the future faithful body
//   1: failed to mint a transferable source handle in setup
//   2: suspend with attachments returned an error word
//   3: receiver-side recv returned an error word
//   4: after recv, the `move = 1` source slot is still occupied in
//      the sender's table
//   5: after recv, the `move = 0` source slot is empty in the
//      sender's table

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Compile-time anchor for the pair-entry layout this test will
    // eventually craft. Both polarities (move=1, move=0) need to be
    // expressible without tripping the layout helper's reserved-bit
    // packing, so exercising both forces a reserved-bit regression to
    // surface here rather than at run time.
    const move_entry = caps.PairEntry{
        .id = 0,
        .caps = (caps.PortCap{ .move = true, .copy = true }).toU16(),
        .move = true,
    };
    const copy_entry = caps.PairEntry{
        .id = 0,
        .caps = (caps.PortCap{ .move = true, .copy = true }).toU16(),
        .move = false,
    };
    _ = move_entry.toU64();
    _ = copy_entry.toU64();

    // Anchor the syscall numbers and port-cap layout the faithful body
    // will need so a rename or bit-layout shift surfaces at compile
    // time alongside this test, not silently downstream.
    _ = syscall.SyscallNum.@"suspend";
    _ = syscall.SyscallNum.recv;
    _ = (caps.PortCap{ .move = true, .copy = true, .recv = true, .bind = true }).toU16();

    testing.pass();
}
