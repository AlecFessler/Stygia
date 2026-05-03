// Spec §[reply_transfer] — test 07.
//
// "[test 07] returns E_PERM if any pair entry with `move = 1` references
//  a source handle that lacks the `move` cap."
//
// Strategy
//   The assertion needs the kernel to reach the per-entry move-cap
//   check with a pair entry whose `move` flag is set against a source
//   handle that does NOT carry the `move` cap. Earlier gates in the
//   §[reply_transfer] error ladder must all clear:
//     test 01 (E_BADCAP):    [1] is a real reply handle (from recv)
//     test 02 (E_PERM xfer): port carries `xfer`, so the minted reply
//                            handle's xfer cap is set
//     test 03 (E_INVAL N):   N = 1 is in [1, 63]
//     test 04 (E_INVAL res): reserved bits in [1] and the entry are 0
//     test 05 (E_BADCAP id): entry.id = w_handle, valid in caller
//     test 06 (E_PERM sub):  entry.caps is a subset of W's caps
//     test 08 (E_PERM copy): only fires when move = 0; entry has move = 1,
//                            so the copy-cap rule doesn't apply
//     test 09 (E_INVAL dup): N = 1, no duplicates possible
//
//   Producing a reply handle with `xfer` follows the established
//   sibling pipeline (reply_transfer_02/05/06): mint a port with
//   `xfer | recv | bind`, mint a worker EC W as a suspended sender,
//   then `recv` to dequeue. Per §[reply] the kernel sets `xfer = 1` on
//   the minted reply handle iff the recv'ing port had the `xfer` cap.
//
//   Producing a source handle that lacks `move` but still satisfies
//   test 06: mint W with caps = {susp, term, restart_policy = 0}. W's
//   `move` bit is intentionally cleared — that is the precise bit test
//   07 trips on. `susp` is required so the suspend in step 3 doesn't
//   trip §[suspend]'s [1] cap gate; `term` is included as cleanup
//   hygiene at the end. The pair entry's caps field is set to {susp}
//   only — a strict subset of W's caps, so test 06 passes ahead of
//   test 07. The pair entry's `move` flag is set to 1 to activate the
//   move-cap check.
//
//   `reply_transfer` with N > 0 is not yet wired in libz (the wrapper
//   panics — the high-vreg push isn't implemented yet). Issue the
//   syscall directly via inline asm matching the sibling pattern in
//   reply_transfer_04/06: vreg 127 lands at [rsp + (127-13)*8] =
//   [rsp + 912] when the kernel reads the stack frame, so we reserve
//   a 920-byte pad — syscall word at offset 0, vreg 127 at offset 912.
//
// Action
//   1. createPort(caps = {xfer, recv, bind}) — must succeed; xfer
//      propagates into the reply handle so test 02 doesn't fire.
//   2. createExecutionContext(target = self,
//        caps = {susp, term, restart_policy = 0}) — must succeed; the
//      omitted `move` cap on W is the assertion trip wire.
//   3. suspend(W, port) — must return OK; queues W as a suspended
//      sender on the port. Non-blocking on the test EC because
//      [1] != self per §[suspend].
//   4. recv(port) — must return OK; the syscall word carries the
//      reply_handle_id in bits 32-43 per §[recv].
//   5. reply_transfer(reply,
//        [{ id = w_handle, move = 1, caps = {susp} }]) — must return
//      E_PERM (the spec assertion under test). Issued via inline asm
//      because libz's replyTransfer panics on N > 0.
//   6. terminate(W) — best-effort cleanup. Spec test 07 doesn't pin
//      consumption of [1] on the failing path, but the assertion has
//      already been reported by then.
//
// Assertions
//   1: createPort failed (precondition).
//   2: createExecutionContext failed (precondition).
//   3: suspend(W, port) did not return OK (precondition).
//   4: recv(port) did not return OK (precondition).
//   5: reply_transfer returned something other than E_PERM (the spec
//      assertion under test).

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

// Issue reply_transfer with N=1 and one pair entry at vreg 127.
// On x86 vreg 127 = [rsp + 912]; on aarch64 vreg 127 = [sp + 768].
fn replyTransferOnePair(reply_handle_id: u12, pair_entry: u64) u64 {
    const word: u64 = 53 |
        (@as(u64, 1) << 12) |
        ((@as(u64, reply_handle_id) & 0xFFF) << 20);
    switch (builtin.cpu.arch) {
        .x86_64 => {
            var rax: u64 = undefined;
            asm volatile (
                \\ subq $920, %%rsp
                \\ movq %%rcx, (%%rsp)
                \\ movq %[entry], 912(%%rsp)
                \\ syscall
                \\ addq $920, %%rsp
                : [rax] "={rax}" (rax),
                : [word] "{rcx}" (word),
                  [entry] "{rdi}" (pair_entry),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return rax;
        },
        .aarch64 => {
            var x0_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[word], [sp]
                \\ str %[entry], [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1] "={x0}" (x0_out),
                : [word] "r" (word),
                  [entry] "r" (pair_entry),
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

    // Step 1: mint the port. xfer is what gets propagated into the
    // minted reply handle's caps per §[reply] ("xfer = 1 if and only
    // if the recv'ing port had the xfer cap"). recv lets us dequeue
    // the suspension; bind lets W's `suspend` reach this port.
    const port_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. susp lets the test queue W onto the port via
    // suspend (§[suspend] [1] cap). term is cleanup hygiene only.
    // restart_policy = 0 keeps the call inside the runner-granted
    // ec_inner_ceiling. `move` is intentionally omitted — that is
    // exactly the bit reply_transfer test 07 looks for when the pair
    // entry below sets `move = 1`.
    const w_caps = caps.EcCap{
        .susp = true,
        .term = true,
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

    // Step 3: queue W as a suspended sender on the port. Per
    // §[suspend], when [1] != self the call simply queues the target
    // and returns OK without blocking the caller.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: dequeue W. The recv syscall word's reply_handle_id is at
    // bits 32-43 per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: build a pair entry with move = 1 against a source W whose
    // caps lack the `move` bit. entry.caps = {susp} is a strict subset
    // of W's {susp, term}, so reply_transfer test 06's subset gate
    // passes. test 08 only fires for move = 0. That funnels the
    // kernel into reply_transfer test 07 — the move = 1 source-cap
    // check — which must surface E_PERM because W does not carry the
    // `move` cap.
    const entry_caps = caps.EcCap{
        .susp = true,
    };
    const pair = caps.PairEntry{
        .id = w_handle,
        .caps = entry_caps.toU16(),
        .move = true, // <-- the bit that activates test 07
    };
    const pair_u64: u64 = pair.toU64();

    const rax = replyTransferOnePair(reply_handle_id, pair_u64);
    if (rax != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(5);
        return;
    }

    // Hygiene: tear W down. Spec test 07 doesn't pin reply-handle
    // consumption on the failing path, but consumption isn't required
    // for the assertion under test. We don't probe the reply handle
    // further — the assertion has already fired.
    _ = syscall.terminate(w_handle);

    testing.pass();
}
