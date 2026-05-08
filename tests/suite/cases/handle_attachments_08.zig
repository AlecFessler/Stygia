// Spec §[handle_attachments] — test 08.
//
// "[test 08] on recv, the receiver's syscall word `pair_count` equals
//  `N` and the next `N` table slots `[tstart, tstart+N)` contain the
//  inserted handles, each with caps = entry.caps intersected with
//  `idc_rx` for IDC handles, or entry.caps verbatim for other handle
//  types."
//
// Strategy
//   The assertion is a recv-time observable: when a sender attaches N
//   handles to a `suspend`, a successful recv of that suspension event
//   must populate the receiver's syscall word with `pair_count = N`
//   and `tstart = S`, and the receiver's cap table at slots [S, S+N)
//   must hold the inserted handles with the correct caps.
//
//   The simplest single-EC witness uses the same shape as
//   `terminate_07`: the test EC is both sender and receiver. It mints
//   a port P with bind+recv+xfer, an EC W as the suspend target (so
//   the suspending EC = the test EC itself, the syscall caller, per
//   §[handle_attachments] entry-id-validation wording), and a
//   "carry" EC C used solely as the attachment source. It then issues
//   `suspend(W, P, [pair_entry{C, caps=copy|saff, move=0}])`, which
//   queues W on P with the attachment metadata bound to the
//   suspending EC's pair vregs, and follows with `recv(P)`.
//
//   Per §[suspend] "[1] may reference the calling EC; the syscall
//   returns after the calling EC is resumed" — when [1] != self, the
//   call simply queues the target without blocking the caller. So the
//   test EC stays runnable, recv returns immediately, and the kernel
//   has time to insert the attachment into the receiver's table at a
//   contiguous slot range.
//
//   Choice of attachment type: an EC handle, not an IDC handle. The
//   spec line under test gives two formulations — IDC handles install
//   with caps intersected with idc_rx, "or entry.caps verbatim for
//   other handle types." The verbatim arm is the tighter assertion
//   (an exact equality, no intersection sieve), and EC handles
//   trivially fall on that arm. C is minted with caps {copy=1,
//   saff=1} so the entry's caps={copy=1, saff=1} is trivially a
//   subset of the source's current caps (test 03 gate) and the
//   source has the `copy` cap (test 05 gate, since move=0).
//
//   Choice of port caps on P: bind+recv+xfer. xfer is mandatory by
//   test 01 ("returns E_PERM if `N > 0` and the port handle does
//   not have the `xfer` cap"). bind lets `suspend` queue W on P;
//   recv lets the test EC dequeue. The test EC remains a live
//   bind-cap holder so recv does not return E_CLOSED.
//
//   The vreg layout for an attached handle on suspend lives in the
//   high vregs: per §[handle_attachments] "When `N > 0`, the entries
//   occupy vregs `[128-N..127]`." With N=1, the entry occupies vreg
//   127 alone. Per §[syscall_abi]'s vreg-ABI (libz/syscall.zig
//   header), vreg 127 lives at `[rsp + (127-13)*8] = [rsp + 912]` at
//   syscall time. libz's `suspendEc` panics on N > 0 (the high-vreg
//   stack pad is not yet wired through the generic helper), so this
//   test issues the syscall via a hand-written inline asm sequence:
//   reserve 912 bytes for vregs 14..127, write the pair entry at
//   offset 904 (which becomes 912 after the word push), push the
//   syscall word, syscall, and unwind.
//
//   On recv, §[event_state] / §[recv] specify the receiver's syscall
//   word return layout: pair_count in bits 12-19, tstart in bits
//   20-31, reply_handle_id in bits 32-43, event_type in bits 44-48.
//   The test reads those fields off the recv's returned word, then
//   reads the cap table at slot tstart and verifies (a) the slot
//   carries an EC handle and (b) its caps field equals the
//   verbatim entry caps.
//
// Pre-call gates the test must clear so no other error can mask the
// assertion under test:
//   - the runner-minted self-handle carries `crpt` and `crec` (see
//     runner/primary.zig: `child_self.crpt`, `crec` = true), so
//     create_port and create_execution_context can run.
//   - the runner-granted port_ceiling (0x1C = xfer|recv|bind) lets
//     the new port carry all three caps the suspend / recv / xfer
//     pre-checks need.
//   - the runner-granted ec_inner_ceiling (0xFF) lets a freshly
//     minted EC carry move|copy|saff|spri|term|susp|read|write —
//     the test only uses {copy, saff, susp, term} subsets.
//   - restart_policy = 0 (kill) on every minted EC keeps creation
//     inside the runner-granted `ec_restart_max = 2` ceiling and
//     prevents any restart_semantics fallback from masking failure.
//
// Action
//   1. create_port(caps={bind, recv, xfer}) → P.
//   2. create_execution_context(target=self, caps={term, susp,
//      restart_policy=0}) → W (the suspend target; never executes
//      meaningfully — entry = dummyEntry).
//   3. create_execution_context(target=self, caps={copy, saff,
//      restart_policy=0}) → C (the attachment source; never
//      executes meaningfully — entry = dummyEntry).
//   4. Build a PairEntry{ id=C, caps=EcCap{.copy=1, .saff=1}.toU16(),
//      move=0 } and stage it for vreg 127.
//   5. Issue `suspend(W, P)` with pair_count=1 in the syscall word
//      and the entry at vreg 127 via inline asm.
//   6. recv(P), capture the return word, decode pair_count, tstart,
//      reply_handle_id.
//   7. Verify pair_count == 1.
//   8. Read cap_table[tstart], verify handleType == execution_context
//      and caps == 0x06 (copy + saff).
//
// Assertions
//   1: setup port creation failed (createPort returned an error word).
//   2: setup W creation failed (createExecutionContext returned an
//      error word).
//   3: setup C creation failed (createExecutionContext returned an
//      error word).
//   4: suspend with N=1 attachment did not return OK in v1.
//   5: recv did not return OK.
//   6: receiver syscall word's pair_count != 1.
//   7: inserted slot's handle type is not execution_context.
//   8: inserted slot's caps != entry.caps verbatim (0x06).
//   9: invoking saff on the delivered handle did not return OK —
//      proves the handle resolves to a live EC and the receiver
//      is the new owner (not just a stale ref). Spec
//      §[handle_attachments] requires the delivered handle to be a
//      fully usable copy, so an op authorized by the entry's caps
//      must succeed against it.

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

fn suspendWithOneAttachmentX64(word: u64, w_handle: u64, port_handle: u64, pair_word: u64) u64 {
    var ret_v1: u64 = undefined;
    asm volatile (
        \\ subq $912, %%rsp
        \\ movq %%rdx, 904(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $920, %%rsp
        : [ret] "={rax}" (ret_v1),
        : [word] "{rcx}" (word),
          [v1in] "{rax}" (w_handle),
          [v2in] "{rbx}" (port_handle),
          [pair] "{rdx}" (pair_word),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
    return ret_v1;
}

fn suspendWithOneAttachmentArm(word: u64, w_handle: u64, port_handle: u64, pair_word: u64) u64 {
    var ret_v1: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #784
        \\ str %[pair], [sp, #768]
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [ret] "={x0}" (ret_v1),
        : [word] "r" (word),
          [v1in] "{x0}" (w_handle),
          [v2in] "{x1}" (port_handle),
          [pair] "r" (pair_word),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return ret_v1;
}

pub fn main(cap_table_base: u64) void {
    // Step 1: mint the result port with bind+recv+xfer. xfer is the
    // mandatory cap for handle attachments per §[handle_attachments]
    // test 01.
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

    // Step 2: mint W (the suspend target). term + susp let the test
    // queue/destroy W; restart_policy = 0 keeps the call inside the
    // runner-granted ceiling.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const w_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&dummyEntry);
    const cec_w = syscall.createExecutionContext(
        w_caps_word,
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

    // Step 3: mint C (the carry/attachment source). copy + saff are
    // the caps we will request to be installed verbatim on the
    // receiver side; copy is required as the source-side gate per
    // §[handle_attachments] test 05 (move=0 path).
    const c_caps = caps.EcCap{
        .copy = true,
        .saff = true,
        .restart_policy = 0,
    };
    const c_caps_word: u64 = @as(u64, c_caps.toU16());
    const cec_c = syscall.createExecutionContext(
        c_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_c.v1)) {
        testing.fail(3);
        return;
    }
    const c_handle: u12 = @truncate(cec_c.v1 & 0xFFF);

    // Step 4: build the pair entry. The entry's caps field carries
    // the caps the kernel will install verbatim on the receiver-side
    // handle (EC, non-IDC). bits 0-11 = id, bits 16-31 = caps,
    // bit 32 = move, all others reserved (= 0).
    const entry_caps = caps.EcCap{ .copy = true, .saff = true };
    const pair = caps.PairEntry{
        .id = c_handle,
        .caps = entry_caps.toU16(),
        .move = false,
    };
    const pair_word: u64 = pair.toU64();

    // Step 5: issue suspend(W, P) with pair_count=1 in the syscall
    // word and the pair entry at vreg 127. Hand-rolled because
    // libz's suspendEc panics on N>0 (high-vreg stack pad not yet
    // wired). Layout details:
    //
    //   - vreg 0 (syscall word) lives at [rsp + 0] at syscall time.
    //   - vreg 14 lives at [rsp + 8]; vreg N (14 <= N <= 127) lives
    //     at [rsp + (N-13)*8]. So vreg 127 lives at [rsp + 912].
    //   - We reserve 912 bytes for vregs 14..127 (114 slots * 8),
    //     write the pair entry into the slot that will land at
    //     offset 912 after the word push, push the word, syscall,
    //     and unwind.
    //
    // syscall word: syscall_num = 14 (suspend) in bits 0-11,
    // pair_count = 1 in bits 12-19. Other bits reserved = 0.
    const suspend_word: u64 = syscall.buildWord(.@"suspend", syscall.extraCount(1));

    const ret_v1: u64 = switch (builtin.cpu.arch) {
        .x86_64 => suspendWithOneAttachmentX64(suspend_word, @as(u64, w_handle), @as(u64, port_handle), pair_word),
        .aarch64 => suspendWithOneAttachmentArm(suspend_word, @as(u64, w_handle), @as(u64, port_handle), pair_word),
        else => @compileError("unsupported arch"),
    };

    if (ret_v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 6: recv(P). The port has the test EC as a live bind-cap
    // holder and W queued as a suspended sender, so recv returns
    // immediately. The kernel has had its chance to perform the
    // attachment move/copy at recv time per §[handle_attachments].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 7: decode the receiver's syscall word per §[recv] /
    // §[event_state]. pair_count in bits 12-19, tstart in bits
    // 20-31, reply_handle_id in bits 32-43.
    const word = got.word;
    const pair_count: u64 = (word >> 12) & 0xFF;
    const tstart: u64 = (word >> 20) & 0xFFF;

    if (pair_count != 1) {
        testing.fail(6);
        return;
    }

    // Step 8: read the inserted handle and verify type + caps. EC
    // is a non-IDC handle so caps install verbatim per the spec line
    // under test.
    const inserted = caps.readCap(cap_table_base, @as(u32, @intCast(tstart)));
    if (inserted.handleType() != .execution_context) {
        testing.fail(7);
        return;
    }
    if (inserted.caps() != entry_caps.toU16()) {
        testing.fail(8);
        return;
    }

    // Step 9: liveness probe. Without an op against the delivered
    // handle, the assertions above only inspect cap_table fields —
    // a kernel that didn't actually bump the source EC's refcount
    // would still pass. Invoke `affinity` (authorized by the entry's
    // `saff` cap) on the delivered slot. The call should return OK,
    // proving the handle resolves to a live EC and the receiver-side
    // refcount took.
    const inserted_slot: u12 = @intCast(tstart);
    // affinity_mask = 1 (single-core, smallest valid mask).
    const aff_regs = syscall.affinity(inserted_slot, 1);
    if (aff_regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
