// Spec §[reply] reply — test 20.
//
// "[test 20] on success when `pair_count > 0`, source pair entries with
//  `move = 1` are removed from the caller's table; entries with
//  `move = 0` are not removed."
//
// Strategy
//   The assertion needs a witness pair: at least one source handle
//   transferred via `move = 1` (whose slot must be released after the
//   call) and at least one transferred via `move = 0` (whose slot must
//   survive). The smallest faithful exercise is N = 2 with one entry
//   of each polarity.
//
//   To exercise reply with pair_count > 0 we need a live reply handle
//   in the caller's table. Following the §[reply] / §[recv] pipeline:
//
//     1. Mint a port with `bind | recv | xfer` caps. `xfer` on the
//        port is what makes the kernel mint the resulting reply
//        handle with `xfer` set (per §[reply] handle-ABI prose), which
//        reply test 09 says is required to consume it with
//        pair_count > 0 at all.
//     2. Mint a sibling thread W with `susp | term`, restart_policy = 0.
//        susp lets us queue W on the port; term + rp=0 keeps W's
//        cleanup contained inside this test process (no restart
//        fallback can re-resurrect W and surprise the recv path).
//     3. suspend(W, port) — non-blocking on the test thread because [1] !=
//        self per §[suspend]; queues W as a suspended sender on the
//        port.
//     4. recv(port) — returns immediately with W as the dequeued
//        sender. The syscall word's `reply_handle_id` field
//        (bits 32-43) is the handle we feed to reply.
//
//   For the source pair entries we use freshly-minted ports as donors.
//   Ports are the cheapest non-thread handle the test process has rights
//   to mint (the runner grants `crpt`), and they let us craft the
//   exact source-cap shape each `move` polarity needs:
//
//     - Donor M: caps = `{move, copy, xfer, bind}`. Pair entry
//       requests `{xfer, bind}` with `move = 1`. The source has
//       `move`, so §[handle_attachments] test 04 / reply test 14 are
//       not what fires; the entry caps are a strict subset of the
//       source's caps so test 03 / reply test 13 are not what fires
//       either.
//     - Donor C: caps = `{copy, xfer, bind}` (no move). Pair entry
//       requests `{xfer, bind}` with `move = 0`. The source has
//       `copy`, so reply test 15 is not what fires.
//
//   reply's pair entries live at the *high* end of the vreg space —
//   vregs [128-N..127] per §[handle_attachments]. For N = 2 that's
//   vreg 126 and vreg 127. The libz `replyTransfer` wrapper owns the
//   arch-specific high-vreg syscall frame.
//
//   Post-call probe: we use `restrict(donor, donor_initial_caps)` to
//   distinguish "slot still valid" from "slot released". Restrict on
//   a still-valid handle with the same caps it already has is a no-op
//   that returns OK; restrict on a released slot returns E_BADCAP
//   (§[capabilities] delete test 03 establishes the same probe
//   pattern). We pick `donor_initial_caps` so the new caps are a
//   subset of the source caps and no reserved bits are set, ruling
//   out E_PERM / E_INVAL responses.
//
// DEGRADED — kernel pair-attachment transfer is currently stubbed
//   `kernel/sched/port.zig` ignores pair_count and falls through to
//   plain `reply()`. The validation in `kernel/syscall/reply.zig`
//   does enforce reserved-bit / xfer / dup-source checks, but the
//   actual pair-entry transfer (slot moves from the caller's table to
//   the resumed thread's table) is unimplemented. On the v0 kernel the
//   move=1 source slot will NOT be released, so assertion id 6 will
//   fire with the donor still resolvable. The faithful body is left
//   in place so that when the kernel's pair-attachment transfer lands
//   this test passes without further edits; until then the failure at
//   assertion id 6 is the expected degraded signal.
//
// Action
//   1. create_port(caps={move, copy, xfer, recv, bind})  — recv-side port
//   2. create_thread(caps={susp, term, rp=0}) — sibling thread W
//   3. suspend(W, port)                                  — must return OK
//   4. recv(port)                                        — must return OK
//   5. create_port(caps={move, copy, xfer, bind})        — donor M
//   6. create_port(caps={copy, xfer, bind})              — donor C
//   7. reply(reply_handle, pair_count=2, [
//        { id = donor_M, caps = {xfer, bind}, move = 1 },
//        { id = donor_C, caps = {xfer, bind}, move = 0 },
//      ])                                                — must return OK
//   8. probe donor M slot: restrict(donor_M, ...)        — must return E_BADCAP
//   9. probe donor C slot: restrict(donor_C, ...)        — must return OK
//
// Assertion ids
//   1: setup port creation (recv side) failed
//   2: sibling thread creation failed
//   3: suspend(W, port) did not return OK
//   4: recv did not return OK
//   5: donor port creation failed (either M or C)
//   6: reply did not return OK (DEGRADED: fires on v0 kernel which
//      returns reply()'s value but skips the pair-entry transfer; or
//      fires later when the slot probe shows the move=1 donor is still
//      resolvable)
//   7: post-call probe found donor M still resolvable
//      (move=1 source not removed — spec line under test)
//   8: post-call probe found donor C released
//      (move=0 source incorrectly removed)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Local halt-forever entry. libz `testing.dummyEntry` uses bare `hlt`,
// which only assembles on x86. Arch-dispatched twin keeps the test
// compiling on aarch64.
fn localDummyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported target architecture"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: recv-side port. xfer is the cap that makes the minted
    // reply handle carry xfer (required by reply test 09).
    const recv_port_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp_recv = syscall.createPort(@as(u64, recv_port_caps.toU16()));
    if (testing.isHandleError(cp_recv.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp_recv.v1 & 0xFFF);

    // Step 2: sibling thread W. susp queues it on the port; term keeps
    // cleanup contained; restart_policy = 0 (kill) so the runner-
    // granted thread_restart_max (=2) ceiling is trivially satisfied and
    // no restart fallback re-resurrects W.
    const w_caps = caps.ThreadCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const thread_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
    const cec = syscall.createThread(
        thread_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. Returns immediately because W is already queued
    // and the test thread holds the port's bind cap (no E_CLOSED) and the
    // process has plenty of free slots (no E_FULL).
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall-word return layout: reply_handle_id at bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: donor M — a port with move + copy + xfer + bind. The pair
    // entry below requests {xfer, bind} with move = 1; this donor has
    // `move`, so reply test 14 is not what fires. `recv` is added to
    // satisfy create_port's structural rule (must include `recv` and
    // one of `{suspend, bind}`); the entry caps subset (test 13) still
    // holds because entry.caps = {xfer, bind} ⊆ donor caps.
    const donor_m_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp_m = syscall.createPort(@as(u64, donor_m_caps.toU16()));
    if (testing.isHandleError(cp_m.v1)) {
        testing.fail(5);
        return;
    }
    const donor_m: u12 = @truncate(cp_m.v1 & 0xFFF);

    // Step 6: donor C — a port with copy (but no move). The pair
    // entry below requests {xfer, bind} with move = 0; the donor has
    // `copy`, so reply test 15 is not what fires. `recv` is added to
    // satisfy create_port's structural rule (must include `recv` and
    // one of `{suspend, bind}`).
    const donor_c_caps = caps.PortCap{
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp_c = syscall.createPort(@as(u64, donor_c_caps.toU16()));
    if (testing.isHandleError(cp_c.v1)) {
        testing.fail(5);
        return;
    }
    const donor_c: u12 = @truncate(cp_c.v1 & 0xFFF);

    // Build the two pair entries. PairEntry's u64 bit layout matches
    // §[handle_attachments] verbatim. The entry caps {xfer, bind} are
    // a strict subset of each donor's caps so reply test 13 (subset
    // check) is not what fires.
    const entry_caps = caps.PortCap{ .xfer = true, .bind = true };
    const pair_m = (caps.PairEntry{
        .id = donor_m,
        .caps = entry_caps.toU16(),
        .move = true,
    }).toU64();
    const pair_c = (caps.PairEntry{
        .id = donor_c,
        .caps = entry_caps.toU16(),
        .move = false,
    }).toU64();

    // Step 7: reply with pair_count = 2. Per §[reply], pair entries
    // are listed in vreg order [128-N..127]. For N = 2, pair_m is
    // pair_entries[0] and pair_c is pair_entries[1], matching the
    // assertion-id pairing below.
    const pairs = [_]u64{ pair_m, pair_c };
    const reply_result = syscall.replyTransfer(reply_handle_id, pairs[0..]);
    if (reply_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 8: probe donor M. After a successful reply with move = 1
    // the donor's slot must be released. restrict on a
    // released slot returns E_BADCAP (cf. §[capabilities] delete
    // test 03). The new caps we pass are a subset of the donor's
    // initial caps so on a still-valid slot restrict would return OK
    // (success), distinguishing the two states cleanly.
    const probe_m = syscall.restrict(donor_m, @as(u64, donor_m_caps.toU16()));
    if (probe_m.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(7);
        return;
    }

    // Step 9: probe donor C. After a successful reply with move = 0
    // the donor's slot must remain. restrict with the same
    // caps it already has is a no-op that returns OK on a live slot.
    const probe_c = syscall.restrict(donor_c, @as(u64, donor_c_caps.toU16()));
    if (probe_c.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(8);
        return;
    }

    testing.pass();
}
