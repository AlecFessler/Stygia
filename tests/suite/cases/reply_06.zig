// Spec §[reply] reply — test 06.
//
// "[test 06] on success when the originating EC handle did not have
//  the `write` cap, the resumed EC's state matches its pre-suspension
//  state, ignoring any modifications made by the receiver."
//
// Strategy
//   The witness needs three things:
//     (a) A reply handle for a sender W that the test EC owns, where
//         the EC handle used to suspend W lacks `write` so the spec
//         line under test applies.
//     (b) A way to write "modifications" into the receiver's event-
//         state vregs between recv and reply. §[event_state] is a 1:1
//         vreg map: the receiver's vreg N at reply time becomes vreg
//         N of the resumed EC iff the originating EC handle had the
//         `write` cap. Issuing `reply` directly via `issueReg` lets us
//         pin specific sentinel values into the vregs the kernel
//         reads when consuming the reply.
//     (c) An observation channel for W's state after resume, so the
//         test can prove the modifications were *not* applied.
//
//   For (c) we exploit the same `read` capability the receiver uses
//   to inspect W's state on recv. With `read` on W's handle, a recv
//   exposes W's GPRs in the receiver's vregs (§[event_state] / §[recv]
//   test 11). So:
//
//     1. suspend(W) → recv → snapshot W's GPRs as G1 (the pre-
//        suspension state, the spec's reference baseline).
//     2. reply with sentinel non-zero values placed into vregs that
//        map to W's rbx..r15. Without `write`, those modifications
//        must be discarded.
//     3. suspend(W) again → recv → snapshot G2.
//     4. Assert G2 == G1. W's entry is `dummyEntry` (`while(true)hlt`),
//        and `hlt` does not perturb GPRs — so any divergence between
//        G1 and G2 can only come from kernel-applied modifications,
//        which the spec line forbids when `write` is absent.
//
//   Notes on vreg coverage:
//     - vreg 1 is overwritten by recv's syscall-result code (OK), so
//       the receiver never sees W's rax through it; we don't compare v1.
//     - vregs 2..13 map to rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12,
//       r13, r14, r15 in W (per libz/syscall.zig's vreg→GPR table).
//       We compare all of these. Picking sentinels for several of
//       them keeps the test sensitive even if one register happens
//       to coincide with W's startup value.
//     - Under the new ABI the reply_handle_id rides in the syscall
//       word (bits 12-23) rather than in vreg 1, so the entire
//       register-backed vreg band 1..13 is available for receiver
//       state mods at reply time — including vreg 1 itself.
//
// Action
//   1. create_port(caps={bind, recv})         — must succeed
//   2. create_execution_context(target=self,
//        caps={term, susp, read, rp=0})        — must succeed
//      (write cap deliberately *not* set; this is the originating
//       EC handle the spec line conditions on.)
//   3. suspend(W, port)                        — must return OK
//   4. recv(port)                              — must return OK;
//                                                 capture G1 = vregs.
//   5. issueReg(.reply, replyExtra(rid),
//        .{ v1=S, v2=S, v3=S, ..., v13=S })    — must return OK.
//      (rid rides in syscall-word bits 12-23 under the new ABI;
//       S = a sentinel pattern distinct from 0 and from any plausible
//       startup value; OR'd with a per-slot tag so each slot is
//       independently distinguishable.)
//   6. suspend(W, port) again                  — must return OK
//   7. recv(port)                              — must return OK;
//                                                 capture G2.
//   8. Assert G2 == G1 across vregs 2..13.
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: first suspend did not return OK
//   4: first recv did not return OK
//   5: reply did not return OK
//   6: second suspend did not return OK
//   7: second recv did not return OK
//   8: G2 differs from G1 in any vreg that should be unchanged
//      (which would mean the receiver's modifications leaked through
//      despite the missing `write` cap)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Architecture-portable no-op EC entry. Equivalent to
// libz testing.dummyEntry, defined locally so the body's idle
// instruction can be selected per arch (`hlt` on x86-64,
// `wfe` on aarch64) without touching libz.
fn dummyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfe"),
            else => @compileError("unsupported arch"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind + recv are the only caps the test
    // exercises; these stay inside the runner-granted port_ceiling
    // (xfer/recv/bind = 0x1C).
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W with read+susp+term but *no* write. The missing
    // `write` is the spec-line precondition that drives this test.
    // restart_policy = 0 (kill) keeps the call inside the runner's
    // restart_policy_ceiling.ec_restart_max.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .read = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&dummyEntry);
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

    // Step 3: queue W as a suspended sender on the port. Non-blocking
    // because [1] != self.
    const sus1 = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. Reply handle id rides in the syscall word; W's
    // GPRs ride in vregs 2..13 because W's handle has `read`.
    const got1 = syscall.recv(port_handle, 0);
    if (got1.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const rid1: u12 = @truncate((got1.word >> 32) & 0xFFF);
    const g1 = got1.regs;

    // Step 5: reply with non-zero sentinel values pinned into every
    // register-backed vreg. Each slot gets a distinct tag so that any
    // single leaked write would diverge from G1 in a recognizable way.
    // Under the new ABI the reply_handle_id rides in syscall-word bits
    // 12-23, so vreg 1 is also free to carry a sentinel — we issue
    // directly via issueReg to seed the full register-backed band.
    // With `write` absent, the kernel must discard all sentinels and
    // leave W's state untouched.
    const SENTINEL_BASE: u64 = 0xA1B2C3D4E5F60000;
    const reply_extra: u64 = (@as(u64, rid1) & 0xFFF) << 12;
    const reply_result = syscall.issueReg(.reply, reply_extra, .{
        .v1 = SENTINEL_BASE | 0x01,
        .v2 = SENTINEL_BASE | 0x02,
        .v3 = SENTINEL_BASE | 0x03,
        .v4 = SENTINEL_BASE | 0x04,
        .v5 = SENTINEL_BASE | 0x05,
        .v6 = SENTINEL_BASE | 0x06,
        .v7 = SENTINEL_BASE | 0x07,
        .v8 = SENTINEL_BASE | 0x08,
        .v9 = SENTINEL_BASE | 0x09,
        .v10 = SENTINEL_BASE | 0x0A,
        .v11 = SENTINEL_BASE | 0x0B,
        .v12 = SENTINEL_BASE | 0x0C,
        .v13 = SENTINEL_BASE | 0x0D,
    });
    if (reply_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 6: re-suspend W. After reply W resumed into `dummyEntry`'s
    // hlt loop, which does not perturb GPRs; suspending again captures
    // exactly the post-reply state of W.
    const sus2 = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus2.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 7: recv again. G2 reflects W's current state.
    const got2 = syscall.recv(port_handle, 0);
    if (got2.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }
    const g2 = got2.regs;

    // Step 8: assert pre-suspension state preserved across the
    // intervening reply. Compare every register-backed vreg the
    // receiver gets to see (v2..v13). v1 is the kernel's syscall
    // result code, not a faithful reflection of W's rax, so it's
    // excluded from the comparison.
    if (g2.v2 != g1.v2 or
        g2.v3 != g1.v3 or
        g2.v4 != g1.v4 or
        g2.v5 != g1.v5 or
        g2.v6 != g1.v6 or
        g2.v7 != g1.v7 or
        g2.v8 != g1.v8 or
        g2.v9 != g1.v9 or
        g2.v10 != g1.v10 or
        g2.v11 != g1.v11 or
        g2.v12 != g1.v12 or
        g2.v13 != g1.v13)
    {
        testing.fail(8);
        return;
    }

    testing.pass();
}
