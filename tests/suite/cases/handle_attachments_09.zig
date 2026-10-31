// Spec §[handle_attachments] handle_attachments — test 09.
//
// "[test 09] on recv, source entries with `move = 1` are removed from
//  the sender's table; entries with `move = 0` are not removed."
//
// Strategy
//   Mirrors test 08's single-thread suspend-self-with-recv harness, but
//   with TWO attachment entries: one with `move = 1` and one with
//   `move = 0`. Both source handles are minted in the test thread's own
//   table (single-CD case), so the recv-time source-slot clear runs
//   inline in `port.deliverEvent` against the receiver's CD lock and
//   the assertion is observable directly via `readCap` on the test
//   thread's slot ids.
//
//   Source object choice: thread handles. thread handles are non-IDC and
//   their caps install verbatim, matching test 08's choice. We need
//   two distinct source slots so the move=1 / move=0 polarities can
//   be inspected independently. Both sources are minted with
//   `{move, copy, saff}` so both polarities of test 04/05 are
//   honored (move=1 needs `move`; move=0 needs `copy`).
//
//   Vreg layout for N=2: per §[handle_attachments] entries occupy
//   `[128-N..127]`, so vreg 126 and vreg 127. Per §[syscall_abi]'s
//   per-arch vreg-ABI, vreg N (firstStackVreg() ≤ N ≤ 127) lives at
//   `[user_sp + (N - firstStackVreg() + 1) * 8]` at syscall time.
//   firstStackVreg() is comptime per arch — 14 on x86-64 (vregs 1..13
//   = GPRs), 32 on aarch64 (vregs 1..31 = x0..x30). So the entry
//   offsets diverge per arch and the inline asm must comptime-derive
//   them rather than hardcode either side's numbers; the kernel
//   reader (kernel/syscall/port.zig:validatePairEntries) uses the
//   same formula via cpu.firstStackVreg(), so deriving the writer
//   offsets the same way keeps reader and writer locked together
//   even if the ABI changes.
//
//   Per the spec, source-slot clear runs at recv time. After recv()
//   returns, `readCap` on the move=1 source slot must show an empty
//   slot (handleType == none / 0) and the move=0 source slot must
//   still hold its thread handle.
//
// Pre-call gates the test must clear so no other error masks the
// assertion under test:
//   - the runner-minted self-handle carries `crpt` and `crec`, so
//     create_port and create_thread can run.
//   - the runner-granted thread_inner_ceiling (0xFF) lets a freshly
//     minted thread carry move|copy|saff|spri|term|susp|read|write —
//     this test only uses {move, copy, saff, susp, term} subsets.
//   - restart_policy = 0 (kill) on every minted thread stays within the
//     runner's `thread_restart_max = 2` ceiling.
//
// Action
//   1. create_port(caps={bind, recv, xfer, suspend}) → P.
//   2. create_thread(target=self, caps={term, susp,
//      restart_policy=0}) → W (suspend target).
//   3. create_thread(target=self, caps={move, copy,
//      saff, restart_policy=0}) → C_move (move=1 source).
//   4. create_thread(target=self, caps={move, copy,
//      saff, restart_policy=0}) → C_copy (move=0 source).
//   5. Build PairEntry{C_move, caps={move, copy, saff}, move=1} and
//      PairEntry{C_copy, caps={move, copy, saff}, move=0}.
//   6. Issue suspend(W, P) with pair_count=2 via inline asm.
//   7. recv(P) → drains the suspension event with both entries
//      installed in the receiver's table at [tstart, tstart+1]
//      and the move=1 source slot cleared.
//   8. readCap(cap_table, c_move_handle): handleType == none.
//   9. readCap(cap_table, c_copy_handle): handleType == thread.
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
const std = @import("std");
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

// firstStackVreg per arch, mirroring kernel/arch/dispatch/cpu.zig:firstStackVreg().
// The kernel reader (kernel/syscall/port.zig:validatePairEntries) reads vreg N at
// `[user_sp + (N - firstStackVreg() + 1) * 8]`; the writer here MUST place
// entries at the same offset or the reader sees uninitialized stack.
const first_stack_vreg: u64 = switch (builtin.cpu.arch) {
    .x86_64 => 14,
    .aarch64 => 32,
    else => @compileError("unsupported arch"),
};

// Post-syscall-prologue offsets of the pair-entry vregs from user SP. On both
// arches the syscall-time SP points at the syscall word (vreg 0); high vregs
// land at `(N - first_stack_vreg + 1) * 8`. x86-64 reaches that SP via
// `subq $reserved; ...; pushq word`; aarch64 reaches it via
// `sub sp, sp, #(reserved); str word, [sp, #0]`.
const v126_off: u64 = (126 - first_stack_vreg + 1) * 8;
const v127_off: u64 = (127 - first_stack_vreg + 1) * 8;

// x86-64 stack-frame sizing.
//   - Pre-push reservation must cover vreg 127's post-push slot. After `pushq`,
//     a write that landed at `(N-13)*8` post-push was written at `(N-13)*8 - 8`
//     pre-push (relative to the pre-push rsp).
//   - Total stack delta = pre-push reservation + 8 (the word push).
const x64_pre_push_reserve: u64 = v127_off; // 912 (= (127-14+1)*8)
const x64_pre_push_v126_off: u64 = v126_off - 8; // 896
const x64_pre_push_v127_off: u64 = v127_off - 8; // 904
const x64_total_unwind: u64 = x64_pre_push_reserve + 8; // 920

// aarch64 stack-frame sizing.
//   - sp must remain 16-byte aligned across the syscall (AArch64 PCS).
//   - Reservation must cover vreg 127's slot at offset v127_off plus the 8-byte
//     entry itself; round up to a multiple of 16.
const arm_reserve: u64 = (v127_off + 8 + 15) & ~@as(u64, 15); // 784 (= round_up_16(776))

fn suspendWithTwoAttachmentsX64(
    word: u64,
    w_handle: u64,
    port_handle: u64,
    pair_v126: u64,
    pair_v127: u64,
) u64 {
    var ret_v1: u64 = undefined;
    asm volatile (std.fmt.comptimePrint(
            \\ subq ${[reserve]d}, %%rsp
            \\ movq %%rsi, {[pre_v126]d}(%%rsp)
            \\ movq %%rdx, {[pre_v127]d}(%%rsp)
            \\ pushq %%rcx
            \\ syscall
            \\ addq ${[unwind]d}, %%rsp
        , .{
            .reserve = x64_pre_push_reserve,
            .pre_v126 = x64_pre_push_v126_off,
            .pre_v127 = x64_pre_push_v127_off,
            .unwind = x64_total_unwind,
        })
        : [ret] "={rax}" (ret_v1),
        : [word] "{rcx}" (word),
          [v1in] "{rax}" (w_handle),
          [v2in] "{rbx}" (port_handle),
          [v126] "{rsi}" (pair_v126),
          [v127] "{rdx}" (pair_v127),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
    return ret_v1;
}

fn suspendWithTwoAttachmentsArm(
    word: u64,
    w_handle: u64,
    port_handle: u64,
    pair_v126: u64,
    pair_v127: u64,
) u64 {
    var ret_v1: u64 = undefined;
    // Layout after `sub sp, sp, #arm_reserve`:
    //   - sp+0       = word (vreg 0)
    //   - sp+v126_off = pair_v126 (vreg 126)
    //   - sp+v127_off = pair_v127 (vreg 127)
    asm volatile (std.fmt.comptimePrint(
            \\ sub sp, sp, #{[reserve]d}
            \\ str %[v126], [sp, #{[v126]d}]
            \\ str %[v127], [sp, #{[v127]d}]
            \\ str %[word], [sp]
            \\ svc #0
            \\ add sp, sp, #{[reserve]d}
        , .{
            .reserve = arm_reserve,
            .v126 = v126_off,
            .v127 = v127_off,
        })
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
    const w_caps = caps.ThreadCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const entry: u64 = @intFromPtr(&dummyEntry);
    const created_thread_w = syscall.createThread(
        @as(u64, w_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(created_thread_w.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(created_thread_w.v1 & 0xFFF);

    // Step 3: C_move — source for the move=1 entry. Needs `move` cap
    // (test 04 gate) and `copy` cap on the source for symmetry; the
    // entry's caps are installed verbatim on the receiver.
    const c_caps = caps.ThreadCap{
        .move = true,
        .copy = true,
        .saff = true,
        .restart_policy = 0,
    };
    const created_thread_move = syscall.createThread(
        @as(u64, c_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(created_thread_move.v1)) {
        testing.fail(3);
        return;
    }
    const c_move_handle: u12 = @truncate(created_thread_move.v1 & 0xFFF);

    // Step 4: C_copy — source for the move=0 entry.
    const created_thread_copy = syscall.createThread(
        @as(u64, c_caps.toU16()),
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(created_thread_copy.v1)) {
        testing.fail(4);
        return;
    }
    const c_copy_handle: u12 = @truncate(created_thread_copy.v1 & 0xFFF);

    // Step 5: build pair entries. The entry's caps must be a subset
    // of the source's caps (test 03), and move/copy bits on the
    // source must authorize the polarity (tests 04/05).
    const entry_caps = caps.ThreadCap{ .move = true, .copy = true, .saff = true };
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
    // sender's (= test thread's, single-CD) table. `clearAndFreeSlot`
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

    // Step 9: the move=0 source slot must STILL hold its thread handle.
    const copy_src_after = caps.readCap(cap_table_base, @as(u32, c_copy_handle));
    if (copy_src_after.handleType() != .thread) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
