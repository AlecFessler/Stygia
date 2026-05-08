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
//     2. Mint a sibling EC W with `susp | term`, restart_policy = 0.
//        susp lets us queue W on the port; term + rp=0 keeps W's
//        cleanup contained inside this test domain (no restart
//        fallback can re-resurrect W and surprise the recv path).
//     3. suspend(W, port) — non-blocking on the test EC because [1] !=
//        self per §[suspend]; queues W as a suspended sender on the
//        port.
//     4. recv(port) — returns immediately with W as the dequeued
//        sender. The syscall word's `reply_handle_id` field
//        (bits 32-43) is the handle we feed to reply.
//
//   For the source pair entries we use freshly-minted ports as donors.
//   Ports are the cheapest non-EC handle the test domain has rights
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
//   vreg 126 and vreg 127, which spec §[syscall_abi] places at
//   [rsp + (126-13)*8 = +904] and [rsp + (127-13)*8 = +912] *after*
//   the syscall word is pushed onto the stack at [rsp+0]. The libz
//   `reply` wrapper covers only the bare-reply path, so we issue the
//   syscall directly via inline asm.
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
//   the resumed EC's table) is unimplemented. On the v0 kernel the
//   move=1 source slot will NOT be released, so assertion id 6 will
//   fire with the donor still resolvable. The faithful body is left
//   in place so that when the kernel's pair-attachment transfer lands
//   this test passes without further edits; until then the failure at
//   assertion id 6 is the expected degraded signal.
//
// Action
//   1. create_port(caps={move, copy, xfer, recv, bind})  — recv-side port
//   2. create_execution_context(caps={susp, term, rp=0}) — sibling EC W
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
//   2: sibling EC creation failed
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

    // Step 2: sibling EC W. susp queues it on the port; term keeps
    // cleanup contained; restart_policy = 0 (kill) so the runner-
    // granted ec_restart_max (=2) ceiling is trivially satisfied and
    // no restart fallback re-resurrects W.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
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
    // and the test EC holds the port's bind cap (no E_CLOSED) and the
    // domain has plenty of free slots (no E_FULL).
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall-word return layout: reply_handle_id at bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: donor M — a port with full move + copy + xfer + bind.
    // The pair entry below requests {xfer, bind} with move = 1; this
    // donor has `move`, so reply test 14 is not what fires.
    const donor_m_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
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
    // `copy`, so reply test 15 is not what fires.
    const donor_c_caps = caps.PortCap{
        .copy = true,
        .xfer = true,
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

    // Step 7: reply with pair_count = 2. Per §[handle_attachments]
    // pair entries live at vregs [128-N..127] — the high end of the
    // vreg space. For N = 2 that's vreg 126 and vreg 127, which the
    // spec §[syscall_abi] places at [rsp + (N-13)*8] *after* the
    // syscall word push:
    //   vreg 126 → [rsp + 113*8] = [rsp + 904]
    //   vreg 127 → [rsp + 114*8] = [rsp + 912]
    //
    // The libz `reply` wrapper covers only the bare-reply path, so we
    // emit the asm directly. Layout when SYSCALL executes:
    //   [rsp + 0]   = syscall_word (52 | (N << 12) = 0x2034 for N=2)
    //   [rsp + 8]   = vreg 14   (zero — first slot in the pad)
    //   ...
    //   [rsp + 904] = vreg 126  (pair_m)
    //   [rsp + 912] = vreg 127  (pair_c)
    // Total stack carved out: 920 = 8 (word) + 114 * 8 (vregs 14..127).
    //
    // Per §[reply] the pair entries are listed in the order
    // [128-N..127]; the call site treats vreg (128-N) as
    // pair_entries[0]. For N = 2 that's vreg 126 = pair_entries[0],
    // vreg 127 = pair_entries[1]. We place pair_m at vreg 126 so the
    // first entry is the move=1 donor and pair_c at vreg 127 so the
    // second is the move=0 donor — matches the assertion-id pairing
    // below.
    const N: u64 = 2;
    // Per §[reply] ABI: bits 0-11 = syscall_num, bits 12-19 =
    // pair_count, bits 20-31 = reply_handle_id.
    const syscall_word: u64 =
        (@as(u64, @intFromEnum(syscall.SyscallNum.reply)) & 0xFFF) |
        (N << 12) |
        ((@as(u64, reply_handle_id) & 0xFFF) << 20);

    // Stash the values the asm needs to write into the high-vreg pad
    // in a small memory-backed buffer keyed by [scratch+offset]. Using
    // a single base register for all loads keeps the asm's register
    // pressure minimal — one scratch (`rdx`, restored from the kernel
    // result anyway) is all we need now that the reply_handle_id rides
    // in the syscall word rather than rax.
    var scratch: [3]u64 = .{ syscall_word, pair_m, pair_c };

    var rax_out: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\ subq $920, %%rsp
                \\ movq 0(%%rdx), %%rcx
                \\ movq %%rcx, 0(%%rsp)
                \\ movq 8(%%rdx), %%rcx
                \\ movq %%rcx, 904(%%rsp)
                \\ movq 16(%%rdx), %%rcx
                \\ movq %%rcx, 912(%%rsp)
                \\ syscall
                \\ addq $920, %%rsp
                : [out_rax] "={rax}" (rax_out),
                : [base] "{rdx}" (&scratch),
                : .{ .rcx = true, .rdx = true, .r11 = true, .memory = true });
        },
        .aarch64 => {
            // aarch64: vreg 126 = [sp + 760], vreg 127 = [sp + 768];
            // reserve 784 bytes. scratch[0]=word, [1]=pair_m, [2]=pair_c.
            asm volatile (
                \\ sub sp, sp, #784
                \\ ldr x13, [%[base], #0]
                \\ str x13, [sp]
                \\ ldr x13, [%[base], #8]
                \\ str x13, [sp, #760]
                \\ ldr x13, [%[base], #16]
                \\ str x13, [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [out] "={x0}" (rax_out),
                : [base] "r" (&scratch),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    if (rax_out != @intFromEnum(errors.Error.OK)) {
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
