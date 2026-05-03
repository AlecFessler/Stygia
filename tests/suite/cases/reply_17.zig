// Spec §[reply] reply — test 17.
//
// "[test 17] returns E_TERM if the suspended EC was terminated before
//  reply could deliver and `pair_count > 0`; the reply handle is
//  consumed and no handle transfer occurs."
//
// Strategy
//   The assertion needs a witness shape:
//     (a) A reply handle in the caller's table whose recorded suspended
//         sender is some EC W, with the `xfer` cap so reply with
//         pair_count > 0 can be invoked at all.
//     (b) A pair entry that would otherwise be valid — id refers to a
//         live source handle in the caller's domain, caps are a subset
//         of the source's caps, and the source carries the per-move
//         right (`copy` for move=0). This isolates the failure to the
//         "suspended EC was terminated" path: every other validation
//         the kernel performs prior to attempting the resume passes.
//     (c) After terminate(W) succeeds, reply with pair_count = 1 on
//         the reply handle must return E_TERM and the spec line under
//         test requires that no handle transfer occurs.
//
//   The test EC owns both ends of the pipeline: it mints a port with
//   bind+recv+xfer caps (xfer is what mints the reply handle with the
//   `xfer` cap per §[reply]: "kernel mints reply handle with move=1,
//   copy=0, and xfer=1 if and only if the recv'ing port had the xfer
//   cap"). It then mints a sibling EC W with caps
//   {term, susp} and restart_policy=0 so it is a one-shot terminable
//   target. Per §[suspend] "[1] may reference the calling EC; the
//   syscall returns after the calling EC is resumed" — when [1] is
//   *not* the calling EC the call simply suspends the target without
//   blocking the caller. So the test EC stays runnable, and W is
//   queued as a suspended sender on the port.
//
//   `recv(port)` then returns immediately (no E_CLOSED, since the test
//   EC still holds the port handle with its `bind` cap; no E_FULL,
//   since the test's domain has plenty of free slots). The kernel
//   hands back the reply handle id in the recv syscall word; that id
//   is the handle the spec line under test refers to.
//
//   For the pair entry source, the test mints a *separate* dummy EC D
//   carrying caps {copy} so the pair entry can name D as a valid
//   transferable source under the `move=0` (copy) path. D never
//   executes meaningfully — it sits at dummyEntry. The test does not
//   care whether D is actually copied into W's domain; the spec line
//   under test mandates that on E_TERM, no transfer occurs.
//
//   `terminate(W)` then destroys W. With W destroyed, the reply
//   handle's recorded suspended sender is gone.
//
//   `reply(reply_handle, pair_count=1, [pair])` is then the probe.
//   The spec line under test demands E_TERM.
//
//   SPEC AMBIGUITY: §[terminate] [test 07] separately asserts that
//   reply handles whose suspended sender was the terminated EC return
//   E_ABANDONED on subsequent operations — i.e., the same scenario
//   names a different error code. The two spec lines read in tension:
//   reply test 17 names E_TERM for the pair-attachment path, while
//   terminate test 07 names E_ABANDONED for any subsequent operation
//   on the marked reply handle. This test enforces the wording of
//   reply test 17 verbatim — accept only E_TERM — since the
//   assertion under test is the authority for *this* test file. If
//   the spec is later reconciled to E_ABANDONED for the pair-
//   attachment path, this test's expected error code is the line that
//   needs to change, mirroring the note already present in
//   terminate_07.zig.
//
//   SPEC AMBIGUITY: the spec line says "[1] is consumed and no handle
//   transfer occurs." Verifying "no handle transfer occurs" requires
//   inspecting the resumed EC's domain after the call — but on E_TERM
//   the resumed EC does not exist (it was terminated). The "no handle
//   transfer" wording is presumably defensive for implementations
//   where partial transfer might have begun before the termination
//   check; with W gone there is no observable resumed-domain state to
//   probe. This test therefore asserts only the error code; the "[1]
//   is consumed" half is structurally implied by the error path being
//   "consumes [1]" per the spec text, but not separately probed here
//   because a probe would need a follow-on operation on the now-
//   missing handle, which conflates this test with reply test 01
//   (E_BADCAP on stale ids).
//
// Action
//   1. create_port(caps={bind, recv, xfer})    — must succeed
//   2. create_execution_context(target=self,
//        caps={term, susp, rp=0}, entry=dummy) — must succeed (W)
//   3. create_execution_context(target=self,
//        caps={copy, rp=0}, entry=dummy)       — must succeed (D)
//   4. suspend(W, port)                        — must return OK
//      (non-blocking on the test EC since [1] != self; queues W as a
//      suspended sender on the port)
//   5. recv(port)                              — must return OK and
//      yield a reply_handle_id in the syscall word
//   6. terminate(W)                            — must return OK
//   7. reply(reply_handle_id, pair_count=1, pair[0]=PairEntry{
//        id=D_handle, caps={copy}, move=0
//      })                                      — must return E_TERM
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed for W (returned an error word)
//   3: setup EC creation failed for D (returned an error word)
//   4: suspend itself did not return OK
//   5: recv did not return OK
//   6: terminate did not return OK
//   7: reply on the now-marked handle returned something other than
//      E_TERM

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

// Inline-asm reply wrapper for pair_count = 1. The libz `reply` wrapper
// covers only the bare-reply path; the high-vreg pair-entry path (vregs
// [128-N..127]) requires a 920-byte stack pad to address vreg 127 from
// rsp. This local helper hard-codes the pair_count=1 case the test
// needs.
//
//   vreg 0   = [rsp + 0]                  (syscall word)
//   vreg 14  = [rsp + 8]
//   ...
//   vreg 127 = [rsp + 912]                (last stack-spilled vreg)
//
// Total reservation = 8 (word) + 114 * 8 (vregs 14..127) = 920 bytes.
// For pair_count=1 only vreg 127 is meaningful; vregs 14..126 are
// reserved-zero per the spec ABI (kernel does not consult them).
//
// Syscall word: bits 0-11 = syscall_num (52 = reply); bits 12-19 =
// pair_count (1..63 per §[reply] [test 10]).
fn replyOneEntry(reply_handle: u12, pair_entry: u64) errors.Error {
    // Syscall word per §[reply] ABI: bits 0-11 = syscall_num (52);
    // bits 12-19 = pair_count (1); bits 20-31 = reply_handle_id.
    const word: u64 =
        (@as(u64, @intFromEnum(syscall.SyscallNum.reply)) & 0xFFF) |
        ((@as(u64, 1) & 0xFF) << 12) |
        ((@as(u64, reply_handle) & 0xFFF) << 20);

    switch (builtin.cpu.arch) {
        .x86_64 => {
            var ov1: u64 = undefined;
            asm volatile (
                \\ subq $920, %%rsp
                \\ movq %%rsp, %%rdx
                \\ addq $8, %%rdx
                \\ movq $113, %%rcx
                \\ 1:
                \\ movq $0, (%%rdx)
                \\ addq $8, %%rdx
                \\ decq %%rcx
                \\ jnz 1b
                \\ movq %[pair], 912(%%rsp)
                \\ movq %[word], (%%rsp)
                \\ syscall
                \\ addq $920, %%rsp
                : [v1] "={rax}" (ov1),
                : [word] "r" (word),
                  [pair] "r" (pair_entry),
                : .{ .rcx = true, .rdx = true, .r11 = true, .memory = true });
            return @enumFromInt(ov1);
        },
        .aarch64 => {
            // aarch64: vreg 127 = [sp + 768]; reserve 784 bytes.
            var x0_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ mov x13, sp
                \\ mov x14, #97
                \\1: str xzr, [x13]
                \\ add x13, x13, #8
                \\ subs x14, x14, #1
                \\ b.ne 1b
                \\ str %[pair], [sp, #768]
                \\ str %[word], [sp]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1] "={x0}" (x0_out),
                : [word] "r" (word),
                  [pair] "r" (pair_entry),
                : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true,
                     .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true,
                     .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true,
                     .x29 = true, .x30 = true, .memory = true });
            return @enumFromInt(x0_out);
        },
        else => @compileError("unsupported target architecture"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port with xfer included so the reply handle
    // minted at recv carries the `xfer` cap (§[reply]). Without xfer,
    // reply with pair_count > 0 would short-circuit on test 09
    // (E_PERM, no xfer cap) before reaching the suspended-sender check.
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
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. term lets the test eventually destroy W; susp
    // lets the test queue W onto the port via suspend. restart_policy
    // = 0 (kill) keeps the call inside the runner-granted ceiling.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15;
    // priority/target_caps default to 0 which stays inside the runner
    // pri ceiling (3) and is irrelevant when target = self.
    const w_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
    const w_cec = syscall.createExecutionContext(
        w_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(w_cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: caps.HandleId = @truncate(w_cec.v1 & 0xFFF);

    // Step 3: mint D, the pair-entry source. copy=true is the only
    // cap the test exercises on D — the pair entry is constructed
    // with caps={copy} and move=0, which §[handle_attachments] [test
    // 05] gates on the source's `copy` cap. restart_policy=0 keeps
    // the create call inside the runner ceiling.
    const d_caps = caps.EcCap{
        .copy = true,
        .restart_policy = 0,
    };
    const d_caps_word: u64 = @as(u64, d_caps.toU16());
    const d_cec = syscall.createExecutionContext(
        d_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(d_cec.v1)) {
        testing.fail(3);
        return;
    }
    const d_handle: caps.HandleId = @truncate(d_cec.v1 & 0xFFF);

    // Step 4: queue W as a suspended sender on the port. Per
    // §[suspend] this returns immediately when [1] != self.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: recv. The port has the test EC as a live bind-cap holder
    // and W queued as a suspension event, so recv returns immediately
    // with the reply handle id encoded in the syscall word per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits
    // 32-43 (12 bits).
    const reply_handle_id: caps.HandleId = @truncate((got.word >> 32) & 0xFFF);

    // Step 6: terminate W. With W destroyed, the reply handle's
    // recorded suspended sender is no longer alive; reply with
    // pair_count > 0 must surface E_TERM per the spec line under test.
    const term_result = syscall.terminate(w_handle);
    if (term_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 7: probe via reply with pair_count=1 and a single valid
    // pair entry naming D with move=0 and caps={copy}. Pair entry
    // encoding per §[handle_attachments]: bits 0-11 = source id,
    // 12-15 reserved, 16-31 = caps to install, bit 32 = move, 33-63
    // reserved.
    const pair = caps.PairEntry{
        .id = d_handle,
        .caps = (caps.EcCap{ .copy = true }).toU16(),
        .move = false,
    };
    const result = replyOneEntry(reply_handle_id, pair.toU64());
    if (result != errors.Error.E_TERM) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
