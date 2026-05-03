// Spec §[reply] reply — test 13.
//
// "[test 13] returns E_PERM if any pair entry's caps are not a subset
//  of the source handle's current caps."
//
// Strategy
//   The assertion needs:
//     (a) A reply handle in the caller's table with the `xfer` cap set
//         (so test 09 doesn't fire first).
//     (b) A pair entry that survives test 11 (no reserved bits) and
//         test 12 (valid source id), and whose `move`/`copy` choice is
//         consistent with the source handle's caps so that tests 14/15
//         don't fire first, but whose `caps` field has at least one
//         bit set that the source handle does *not* carry — which is
//         exactly the test 13 trip wire.
//
//   Producing (a) follows the same pipeline used by terminate_07: mint
//   a port with `xfer | recv | bind` (so the kernel issues a reply
//   handle with `xfer = 1` per §[reply] handle ABI), mint a worker EC
//   `W` with `susp | term`, `suspend(W, port)` to queue W as a
//   suspended sender, then `recv(port)` to dequeue it. The recv
//   syscall word carries `reply_handle_id` in bits 32-43 per §[recv].
//   `term` on W is included so the test ELF has a clean exit path
//   (terminate at the end) but is not required for the assertion.
//
//   Producing (b): reuse W as the source handle. W's caps are
//   {susp = 1, term = 1, copy = 1, restart_policy = 0} — `copy` lets
//   the kernel satisfy reply test 15 (move = 0 needs `copy` on the
//   source); `term`/`susp` give the source a non-empty cap set to
//   compare a subset against. The pair entry is encoded with
//   `move = 0` and `caps = {copy = 1, term = 1, susp = 1, write = 1}`
//   — `write` (bit 7) is *not* set on W, so the entry's caps are not
//   a subset of W's current caps. The earlier gates clear:
//     - test 01 (E_BADCAP):    [1] is the reply handle from recv
//     - test 09 (E_PERM xfer): port had `xfer`, so the reply has it
//     - test 10 (E_INVAL N):   pair_count = 1 is in [1, 63]
//     - test 11 (E_INVAL res): reserved bits in the entry are 0
//     - test 12 (E_BADCAP id): entry.id = w_handle, valid in caller
//     - test 14 (E_PERM move): entry.move = 0, so the move-cap rule
//                              does not apply
//     - test 15 (E_PERM copy): source W has `copy = 1`, so the move=0
//                              copy-cap rule is satisfied
//     - test 16 (E_INVAL dup): only one entry, no duplicates possible
//
//   That leaves test 13 as the first remaining gate, so the kernel
//   must surface E_PERM (or fall through into a non-error success
//   path on a buggy implementation, in which case this test fails).
//
//   The libz `reply` wrapper covers only the bare-reply path. We open-
//   code the syscall here: vreg 127 must land at `[rsp + 912]` when
//   the kernel reads it (= (127 - 13) * 8 above the syscall word at
//   `[rsp]`). Allocating 920 bytes of scratch covers the word at
//   offset 0 plus vreg 127 at offset 912; intermediate vregs the
//   kernel will not read are left undefined.
//
// Action
//   1. createPort(caps = {xfer, recv, bind}) — must succeed; xfer is
//      what propagates to the reply handle so test 09 doesn't fire
//      ahead of test 13.
//   2. createExecutionContext(target = self, caps = {susp, term,
//      copy, restart_policy = 0}) — must succeed; W's `copy` bit
//      keeps reply test 15 happy when the entry has move = 0.
//   3. suspend(W, port) — must return OK; queues W as a suspended
//      sender on the port.
//   4. recv(port) — must return OK; the syscall word carries
//      reply_handle_id in bits 32-43.
//   5. reply(reply, pair_count = 1, [{ id = w_handle, move = 0,
//      caps = {copy, term, susp, write} }]) — must return E_PERM
//      (the spec assertion under test). Issued via inline asm because
//      libz's `reply` wrapper covers only the bare-reply path.
//   6. terminate(W) — best-effort cleanup (W still in suspended/
//      reply-pending state if the kernel didn't consume the reply on
//      the failing path, but the test outcome has already been
//      reported by then — terminate is purely hygiene).
//
// Assertions
//   1: createPort failed (precondition for the assertion under test).
//   2: createExecutionContext failed (precondition).
//   3: suspend(W, port) did not return OK (precondition).
//   4: recv(port) did not return OK (precondition).
//   5: reply returned something other than E_PERM (the spec assertion
//      under test).

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

// Issue reply with pair_count=1 and one pair entry at vreg 127.
// On x86 vreg 127 = [rsp + 912]; on aarch64 vreg 127 = [sp + 768].
// Returns the kernel-supplied error code in vreg 1.
fn replyOnePair(reply_handle_id: u12, pair_entry: u64) u64 {
    const word: u64 = @as(u64, @intFromEnum(syscall.SyscallNum.reply)) |
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
    // the suspension; bind lets W's suspend reach this port.
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

    // Step 2: mint W. susp lets the test queue W on the port via
    // suspend. copy keeps reply test 15 (move = 0 needs the copy cap
    // on the source) satisfied so test 13 fires first. term lets the
    // test tear W down at the end. restart_policy = 0 stays inside
    // ec_inner_ceiling.
    const w_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .copy = true,
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

    // Step 4: dequeue W. The recv syscall word's reply_handle_id is
    // at bits 32-43 per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: build a pair entry whose caps are NOT a subset of W's
    // current caps. W has {susp, term, copy}; entry adds `write`
    // (EcCap bit 7) which W lacks. move = 0, so the source's `copy`
    // bit (which W has) clears reply test 15 ahead of test 13.
    const entry_caps = caps.EcCap{
        .copy = true,
        .term = true,
        .susp = true,
        .write = true, // <-- NOT a subset bit
    };
    const pair = caps.PairEntry{
        .id = w_handle,
        .caps = entry_caps.toU16(),
        .move = false,
    };
    const pair_u64: u64 = pair.toU64();

    const rax = replyOnePair(reply_handle_id, pair_u64);
    if (rax != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(5);
        return;
    }

    // Hygiene: tear W down. Spec test 18 says on the E_FULL path the
    // reply handle is NOT consumed; the spec doesn't pin consumption
    // for the test 13 path explicitly, but consumption isn't required
    // for the assertion. We don't probe the reply handle further —
    // the assertion under test has already fired.
    _ = syscall.terminate(w_handle);

    testing.pass();
}
