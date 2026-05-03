// Spec §[reply] reply — test 18.
//
// "[test 18] returns E_FULL if `pair_count > 0` and the resumed EC's
//  domain handle table cannot accommodate N contiguous slots; the
//  reply handle is NOT consumed and the caller's table is unchanged."
//
// Strategy
//   Materialize a reply handle inside the test EC, then trigger the
//   E_FULL path by saturating the handle table before the call.
//
//   The test EC owns both sides of the suspend/recv pipeline:
//     1. Mint a port with `bind | recv | xfer`. The xfer cap on the
//        recv'ing port is what the kernel uses (per §[reply]) to mint
//        the reply handle's own xfer cap, which reply with
//        pair_count > 0 requires.
//     2. Mint a sibling EC W with `term | susp` and restart_policy = 0
//        (kill). The test EC is in the same capability domain as W, so
//        "the resumed EC's domain handle table" in the spec line under
//        test is the same physical table the test EC writes to.
//     3. suspend(W, port) — non-blocking on the test EC since [1] != self.
//        Queues W as a suspended sender on the port.
//     4. recv(port) — returns immediately (the test EC still holds the
//        port's bind cap; an event is queued). The syscall word's
//        reply_handle_id field carries the reply slot id; per §[reply]
//        the reply handle is minted with `xfer = 1` because the recv'ing
//        port had `xfer`.
//
//   For the attachment we need a single source handle (N = 1) whose
//   caps satisfy the pair-entry validation. The runner-imposed
//   ec_inner_ceiling allows the move/copy bits on EC handles, so
//   create_execution_context can mint a witness EC S with caps =
//   {copy = 1}. The pair entry references S with `caps = 0, move = 0`
//   — caps = 0 is trivially a subset of S's caps, and move = 0 needs
//   the source to have the `copy` cap, which S does. (The runner's
//   port_ceiling does not allow `copy` on port handles, so port
//   handles cannot serve here.)
//
//   Saturating the table is done as in acquire_ecs_04: repeated
//   create_port({}) until E_FULL is observed, confirming zero free
//   slots remain. After saturation a reply with pair_count = 1 must
//   return E_FULL because no contiguous run of 1 slot exists for the
//   transferred handle.
//
//   Verification of the "reply handle NOT consumed; caller's table
//   unchanged" half of the assertion uses `sync` — sync returns
//   E_BADCAP on a stale handle and OK on a live one (sync's own
//   [test 01]). If the reply handle was wrongly consumed,
//   sync(reply_handle_id) would return E_BADCAP. If S was wrongly
//   removed from the caller's table (the move = 0 path mustn't remove
//   anything anyway, but we are checking the broader "table unchanged"
//   half), sync(s_handle) would return E_BADCAP.
//
//   SPEC AMBIGUITY: §[reply] [test 18] does not pin which ordering
//   the kernel uses to detect E_FULL relative to the `reply handle
//   is consumed` and `move = 1 source removed` side effects of the
//   success path. We treat the spec wording at face value — the
//   kernel must roll back any partial work before returning E_FULL.
//   Using move = 0 here narrows the test to the reply-handle-
//   consumption check plus a sync of the source; a future test
//   exercising move = 1 sources can extend the verification to
//   source removal.
//
//   Inline asm vs libz: libz `reply` covers only the bare-reply
//   path. We open-code the syscall here:
//     - Reserve a 920-byte pad covering vregs 14..127 plus the
//       syscall word slot at [rsp+0]. vreg N >= 14 lives at
//       [rsp + (N-13)*8].
//     - vreg 127 (the only attachment for N = 1) lives at [rsp+912].
//     - Syscall word = syscall_num (52) | (pair_count << 12) |
//                      (reply_handle_id << 20)
//       per §[reply]; vregs 1..13 are not used for plumbing the
//       handle.
//
// Action
//   1. create_port({bind, recv, xfer})              — must succeed
//   2. create_execution_context(W,
//        caps={term, susp, rp=0}, target=self)      — must succeed
//   3. suspend(W, port)                             — must return OK
//   4. recv(port)                                   — must return OK,
//      yielding reply_handle_id in the syscall word
//   5. create_execution_context(S,
//        caps={copy}, target=self)                  — must succeed
//   6. saturate the table via create_port({}) loop  — must observe
//      E_FULL within HANDLE_TABLE_MAX iterations
//   7. inline-asm reply(reply, pair_count=1, [s,move=0,caps=0])
//                                                   — must return E_FULL
//   8. sync(reply_handle_id)                        — must NOT return
//      E_BADCAP (proves the reply handle was not consumed)
//   9. sync(s_handle)                               — must NOT return
//      E_BADCAP (proves the source remains in the caller's table)
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup W creation failed
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: setup S creation failed
//   6: handle table did not saturate before HANDLE_TABLE_MAX iterations
//   7: reply returned something other than E_FULL
//   8: sync(reply_handle_id) returned E_BADCAP — reply handle was
//      consumed
//   9: sync(s_handle) returned E_BADCAP — caller's table changed

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

// Inline asm reply with pair_count = 1 and a single high-vreg attachment
// at vreg 127. See the file-level comment for the stack layout rationale.
//
// Stack layout during the syscall:
//   [rsp+0]        — syscall word (vreg 0); carries reply_handle_id
//   [rsp+8..904]   — vregs 14..126, unused for pair_count=1
//   [rsp+912]      — vreg 127, the single pair entry
//
// Register layout:
//   rcx — pinned to the syscall word constant (carries syscall_num,
//         pair_count, and reply_handle_id per the §[reply] ABI); the
//         syscall instruction clobbers it with the return RIP.
//   r11 — clobbered by the syscall RFLAGS save.
//
// `[pair] "r"` lets Zig pick any free GPR. With rcx pinned, the
// compiler will allocate one of the syscall-ignored input vreg slots
// (rbx/rdx/r8/...); since reply doesn't read those, the transient
// stomp is invisible to the kernel.
fn replyOne(reply_handle: u12, pair_entry: u64) u64 {
    // Per §[reply] ABI: bits 0-11 = syscall_num, bits 12-19 =
    // pair_count, bits 20-31 = reply_handle_id.
    const word: u64 =
        (@as(u64, @intFromEnum(syscall.SyscallNum.reply)) & 0xFFF) |
        (@as(u64, 1) << 12) |
        ((@as(u64, reply_handle) & 0xFFF) << 20);

    switch (builtin.cpu.arch) {
        .x86_64 => {
            var v1_out: u64 = undefined;
            asm volatile (
                \\ subq $920, %%rsp
                \\ movq %%rcx, (%%rsp)
                \\ movq %[pair], 912(%%rsp)
                \\ syscall
                \\ addq $920, %%rsp
                : [v1] "={rax}" (v1_out),
                : [word] "{rcx}" (word),
                  [pair] "r" (pair_entry),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return v1_out;
        },
        .aarch64 => {
            // aarch64: vreg 127 = [sp + 768]; reserve 784 bytes.
            var x0_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[word], [sp]
                \\ str %[pair], [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1] "={x0}" (x0_out),
                : [word] "r" (word),
                  [pair] "r" (pair_entry),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
            return x0_out;
        },
        else => @compileError("unsupported target architecture"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the result port. xfer must be set so the kernel
    // mints the reply handle with the xfer cap (§[reply] prose).
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. term lets the test eventually destroy W on
    // teardown if needed; susp lets the test queue W onto the port via
    // suspend. restart_policy = 0 keeps the call inside the runner-
    // granted ec_outer_ceiling.restart_max and prevents any restart
    // fallback from re-running W.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const w_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
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

    // Step 3: queue W on the port as a suspended sender.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The port has the test EC as a live bind-cap holder
    // and W queued as a suspension event, so recv returns immediately
    // with the reply handle id encoded in the syscall word per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: mint S — the source handle to attach. copy=1 lets the
    // pair entry reference S with move = 0. We don't need to do
    // anything else with S; it just sits in the table as a valid
    // handle id whose caps include the copy bit.
    const s_caps = caps.EcCap{
        .copy = true,
        .restart_policy = 0,
    };
    const s_caps_word: u64 = @as(u64, s_caps.toU16());
    const cec_s = syscall.createExecutionContext(
        s_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_s.v1)) {
        testing.fail(5);
        return;
    }
    const s_handle: u12 = @truncate(cec_s.v1 & 0xFFF);

    // Step 6: saturate the handle table. create_port with no caps mints
    // a port that takes a slot but holds no rights — the cheapest filler.
    // Bound the loop at HANDLE_TABLE_MAX so a misbehaving kernel cannot
    // hang the test.
    const empty_port_caps_word: u64 = @as(u64, (caps.PortCap{}).toU16());
    var saturated: bool = false;
    var i: u32 = 0;
    while (i < caps.HANDLE_TABLE_MAX) {
        const cp_filler = syscall.createPort(empty_port_caps_word);
        if (cp_filler.v1 == @intFromEnum(errors.Error.E_FULL)) {
            saturated = true;
            break;
        }
        i += 1;
    }
    if (!saturated) {
        testing.fail(6);
        return;
    }

    // Step 7: build the pair entry and call reply with pair_count = 1.
    // caps field = 0 is trivially a subset of S's caps; move = 0 with
    // copy on S satisfies the move/copy gating. Reserved bits are
    // zeroed by the PairEntry packed-struct. Saturated table forces
    // E_FULL.
    const pair_entry = (caps.PairEntry{
        .id = s_handle,
        .caps = 0,
        .move = false,
    }).toU64();

    const rt_result = replyOne(reply_handle_id, pair_entry);
    if (rt_result != @intFromEnum(errors.Error.E_FULL)) {
        testing.fail(7);
        return;
    }

    // Step 8: prove the reply handle was not consumed. sync's only
    // failure path on a clean handle id (no reserved bits set) is
    // E_BADCAP for an invalid handle. A live reply handle returns OK
    // from sync.
    const sync_reply = syscall.sync(reply_handle_id);
    if (sync_reply.v1 == @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(8);
        return;
    }

    // Step 9: prove the caller's table is unchanged at the source.
    // The move = 0 path itself never removes the source on success,
    // but the spec line under test makes the broader claim that the
    // table is unchanged on this E_FULL path. Sync the source handle
    // to confirm it still resolves.
    const sync_src = syscall.sync(s_handle);
    if (sync_src.v1 == @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
