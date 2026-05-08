// Spec §[handle_attachments] handle_attachments — test 09.
//
// "[test 09] on recv, source entries with `move = 1` are removed from
//  the sender's table; entries with `move = 0` are not removed."
//
// Strategy
//   Mirrors test 08's single-EC suspend-self-with-recv harness, but
//   with TWO attachment entries: one with `move = 1` and one with
//   `move = 0`. Both source handles are minted in the test EC's own
//   table (single-CD case), so the recv-time source-slot clear runs
//   inline in `port.deliverEvent` against the receiver's CD lock and
//   the assertion is observable directly via `readCap` on the test
//   EC's slot ids.
//
//   Source object choice: EC handles. EC handles are non-IDC and
//   their caps install verbatim, matching test 08's choice. We need
//   two distinct source slots so the move=1 / move=0 polarities can
//   be inspected independently. Both sources are minted with
//   `{move, copy, saff}` so both polarities of test 04/05 are
//   honored (move=1 needs `move`; move=0 needs `copy`).
//
//   Vreg layout for N=2: per §[handle_attachments] entries occupy
//   `[128-N..127]`, so vreg 126 and vreg 127. Per the §[syscall_abi]
//   stack-vreg formula, vreg N at `[user_sp + (N-13)*8]`. After the
//   syscall-word push, the offsets become 904 (vreg 126) and 912
//   (vreg 127). The hand-rolled asm reserves 912 bytes for the
//   high-vreg pad, writes both pair words at offsets 896 and 904
//   pre-push (which become 904 and 912 post-push), pushes the
//   syscall word, syscalls, and unwinds.
//
//   Per the spec, source-slot clear runs at recv time. After recv()
//   returns, `readCap` on the move=1 source slot must show an empty
//   slot (handleType == none / 0) and the move=0 source slot must
//   still hold its EC handle.
//
// Pre-call gates the test must clear so no other error masks the
// assertion under test:
//   - the runner-minted self-handle carries `crpt` and `crec`, so
//     create_port and create_execution_context can run.
//   - the runner-granted ec_inner_ceiling (0xFF) lets a freshly
//     minted EC carry move|copy|saff|spri|term|susp|read|write —
//     this test only uses {move, copy, saff, susp, term} subsets.
//   - restart_policy = 0 (kill) on every minted EC stays within the
//     runner's `ec_restart_max = 2` ceiling.
//
// Action
//   1. create_port(caps={bind, recv, xfer, suspend}) → P.
//   2. create_execution_context(target=self, caps={term, susp,
//      restart_policy=0}) → W (suspend target).
//   3. create_execution_context(target=self, caps={move, copy,
//      saff, restart_policy=0}) → C_move (move=1 source).
//   4. create_execution_context(target=self, caps={move, copy,
//      saff, restart_policy=0}) → C_copy (move=0 source).
//   5. Build PairEntry{C_move, caps={move, copy, saff}, move=1} and
//      PairEntry{C_copy, caps={move, copy, saff}, move=0}.
//   6. Issue suspend(W, P) with pair_count=2 via inline asm.
//   7. recv(P) → drains the suspension event with both entries
//      installed in the receiver's table at [tstart, tstart+1]
//      and the move=1 source slot cleared.
//   8. readCap(cap_table, c_move_handle): handleType == none.
//   9. readCap(cap_table, c_copy_handle): handleType == execution_context.
//
// Assertions
//   1: setup port creation failed.
//   2: setup W creation failed.
//   3: setup C_move creation failed.
//   4: setup C_copy creation failed.
//   5: suspend with N=2 attachments did not return OK in v1.
//   6: recv did not return OK.
//   7: receiver syscall word's pair_count != 2.
//   8: move=1 source slot still occupied after recv (move was a no-op).
//   9: move=0 source slot empty after recv (copy was treated as move).

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

fn dummyEntry() callconv(.c) noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

// Issue suspend with two attachments at vregs 126 and 127. Layout:
//   - subq $912 reserves 912 bytes for vregs 14..127 (114 * 8).
//   - pre-push: pair_v126 at 896(rsp), pair_v127 at 904(rsp). After
//     pushq rcx the addresses shift by 8 → vreg 126 lands at 904
//     ((126-13)*8) and vreg 127 at 912 ((127-13)*8). Perfect.
//   - addq $920 unwinds (912 reserved + 8 word push).
fn suspendWithTwoAttachmentsX64(
    word: u64,
    w_handle: u64,
    port_handle: u64,
    pair_v126: u64,
    pair_v127: u64,
) u64 {
    var ret_v1: u64 = undefined;
    asm volatile (
        \\ subq $912, %%rsp
        \\ movq %%rsi, 896(%%rsp)
        \\ movq %%rdx, 904(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $920, %%rsp
        : [ret] "={rax}" (ret_v1),
        : [word] "{rcx}" (word),
          [v1in] "{rax}" (w_handle),
          [v2in] "{rbx}" (port_handle),
          [v126] "{rsi}" (pair_v126),
          [v127] "{rdx}" (pair_v127),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
    return ret_v1;
}

// AArch64 has a parallel layout: vreg 14 at [sp + 0] *post* word
// store, vreg N at [sp + (N-14)*8 + 8]. We reserve 912 bytes,
// write the word at offset 0 and pair entries at offsets that
// correspond to vregs 126 and 127.
fn suspendWithTwoAttachmentsArm(
    word: u64,
    w_handle: u64,
    port_handle: u64,
    pair_v126: u64,
    pair_v127: u64,
) u64 {
    var ret_v1: u64 = undefined;
    // Layout after `sub sp, #912`:
    //   - sp+0    = word (vreg 0)
    //   - sp+8..  = vregs 14..  per (N-13)*8 in the v0 ABI.
    // vreg 126 → sp+904, vreg 127 → sp+912. We reserved 912 so 912
    // is one slot past — bump reservation to 920 to fit vreg 127.
    asm volatile (
        \\ sub sp, sp, #920
        \\ str %[v126], [sp, #904]
        \\ str %[v127], [sp, #912]
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #920
        : [ret] "={x0}" (ret_v1),
        : [word] "r" (word),
          [v1in] "{x0}" (w_handle),
          [v2in] "{x1}" (port_handle),
          [v126] "r" (pair_v126),
          [v127] "r" (pair_v127),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return ret_v1;
}

pub fn main(cap_table_base: u64) void {
    // Step 1: result port with bind+recv+xfer+suspend.
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: W (suspend target).
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const entry: u64 = @intFromPtr(&dummyEntry);
    const cec_w = syscall.createExecutionContext(
        @as(u64, w_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_w.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec_w.v1 & 0xFFF);

    // Step 3: C_move — source for the move=1 entry. Needs `move` cap
    // (test 04 gate) and `copy` cap on the source for symmetry; the
    // entry's caps are installed verbatim on the receiver.
    const c_caps = caps.EcCap{
        .move = true,
        .copy = true,
        .saff = true,
        .restart_policy = 0,
    };
    const cec_move = syscall.createExecutionContext(
        @as(u64, c_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_move.v1)) {
        testing.fail(3);
        return;
    }
    const c_move_handle: u12 = @truncate(cec_move.v1 & 0xFFF);

    // Step 4: C_copy — source for the move=0 entry.
    const cec_copy = syscall.createExecutionContext(
        @as(u64, c_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_copy.v1)) {
        testing.fail(4);
        return;
    }
    const c_copy_handle: u12 = @truncate(cec_copy.v1 & 0xFFF);

    // Step 5: build pair entries. The entry's caps must be a subset
    // of the source's caps (test 03), and move/copy bits on the
    // source must authorize the polarity (tests 04/05).
    const entry_caps = caps.EcCap{ .move = true, .copy = true, .saff = true };
    const pair_move = caps.PairEntry{
        .id = c_move_handle,
        .caps = entry_caps.toU16(),
        .move = true,
    };
    const pair_copy = caps.PairEntry{
        .id = c_copy_handle,
        .caps = entry_caps.toU16(),
        .move = false,
    };

    // Step 6: issue suspend(W, P) with pair_count=2. Place pair_move
    // at vreg 126, pair_copy at vreg 127. Order within the
    // attachment range is implementation-defined per spec — what
    // matters is that the recv-side cap-table check finds BOTH the
    // installed handle (test 08 path) and the source-clear semantics
    // (test 09 path).
    const suspend_word: u64 = syscall.buildWord(.@"suspend", syscall.extraCount(2));
    const ret_v1: u64 = switch (builtin.cpu.arch) {
        .x86_64 => suspendWithTwoAttachmentsX64(
            suspend_word,
            @as(u64, w_handle),
            @as(u64, port_handle),
            pair_move.toU64(),
            pair_copy.toU64(),
        ),
        .aarch64 => suspendWithTwoAttachmentsArm(
            suspend_word,
            @as(u64, w_handle),
            @as(u64, port_handle),
            pair_move.toU64(),
            pair_copy.toU64(),
        ),
        else => @compileError("unsupported arch"),
    };
    if (ret_v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 7: recv(P) drains the suspension event. The kernel
    // performs the move/copy at this point per §[handle_attachments].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }
    const word = got.word;
    const pair_count: u64 = (word >> 12) & 0xFF;
    if (pair_count != 2) {
        testing.fail(7);
        return;
    }

    // Step 8: the move=1 source slot must now be empty in the
    // sender's (= test EC's, single-CD) table. `clearAndFreeSlot`
    // zeros the entire user_table entry, so word0 == 0 is the
    // post-clear signature. (The HandleType enum has no `none`
    // tag — empty slots decode to type=0/id=0/caps=0, indistinguishable
    // from slot 0's SELF handle by tag alone, hence the explicit
    // word0 check.)
    const move_src_after = caps.readCap(cap_table_base, @as(u32, c_move_handle));
    if (move_src_after.word0 != 0) {
        testing.fail(8);
        return;
    }

    // Step 9: the move=0 source slot must STILL hold its EC handle.
    const copy_src_after = caps.readCap(cap_table_base, @as(u32, c_copy_handle));
    if (copy_src_after.handleType() != .execution_context) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
