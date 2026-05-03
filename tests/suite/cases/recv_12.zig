// Spec §[recv] recv — test 12.
//
// "[test 12] on success when the suspending EC handle did not have the
//  `read` cap, all event-state vregs are zeroed."
//
// Strategy
//   The shape mirrors recv_07/08: the test EC owns both ends. It
//   mints a port P with {bind, recv}, then mints a worker EC W with
//   {susp} and explicitly *without* the `read` cap. It calls
//   `suspend(W, P)` which is non-blocking on the test EC because
//   [1] != self per §[suspend]: W is queued as a suspended sender on
//   P and control returns immediately. The test EC then `recv`s on P.
//
//   Per §[event_state]: "When the EC handle that triggered the event
//   held the `read` and/or `write` cap, the kernel exposes the
//   suspended EC's state through the vreg layout at recv time and
//   consumes modifications on reply." The contrapositive is the spec
//   line under test: when the triggering EC handle did *not* have
//   `read`, the event-state vregs that would otherwise carry that
//   state are zeroed.
//
//   The Regs returned by `recv` capture vregs 1..13 — the GPR slots
//   that on x86-64 hold the suspended EC's rax, rbx, rdx, rbp, rsi,
//   rdi, r8, r9, r10, r12, r13, r14, r15 per §[event_state]. W's
//   entry function is `dummyEntry` which immediately executes `hlt`
//   in a loop; on entry the calling convention puts the entry
//   function's argv-style state into the GPRs and the `hlt`
//   instruction's RIP into the saved RIP slot — non-zero values that
//   would be visible if the kernel did *not* zero the vregs. With
//   `read` denied, every vreg in the GPR window must read back as
//   zero. We probe all 13 GPR vregs and fail on the first non-zero
//   one. The reply_handle_id field (bits 32-43 of the syscall word)
//   is used as a positive gate that recv took the success branch —
//   a non-zero reply_handle_id witnesses that the kernel reached the
//   reply-handle-mint step (and therefore the vreg-write step also
//   ran), so the all-zero reading is not a side effect of recv
//   short-circuiting on an error.
//
//   Pre-call gates the test must clear so no other failure path can
//   mask the assertion under test:
//     - §[create_port] test 01: runner self-handle has `crpt`.
//     - §[create_port] test 02: caps {bind,recv} = 0x18 ⊆ runner
//       port_ceiling 0x1C.
//     - §[create_execution_context] test 01: runner self-handle has
//       `crec`. test 03/06/08/09/10: caps subset of ec_inner_ceiling,
//       priority 0, stack_pages 1, affinity 0, reserved bits clear.
//     - §[recv] test 01: P is valid. test 02: P has `recv`. test 03:
//       reserved bits clear in [1]. test 04: P has live bind-cap
//       holders (this test EC) and a queued event. test 06: the test
//       child's table has plenty of free slots; reply takes one slot,
//       no attached handles, well under the limit.
//     - §[suspend] test 03 (E_PERM): W has `susp`. test 06 (E_INVAL,
//       vCPU): W is a regular EC. test 07 (E_INVAL, already
//       suspended): W has not been suspended before this call.
//
// Action
//   1. create_port(caps={bind, recv})           — must succeed
//   2. create_execution_context(target=self,
//        caps={susp, restart_policy=0})         — must succeed; note
//      EcCap{} defaults `read = false`, so omitting `read` from the
//      caps struct is the spec line precondition under test
//      (entry = dummyEntry; W never executes meaningfully — it is
//      suspended before scheduling matters)
//   3. suspend(W, port)                         — must return OK
//      (non-blocking on the test EC since [1] != self; queues W as a
//      suspended sender on the port)
//   4. recv(port)                               — must return OK
//   5. assert syscall word's reply_handle_id != 0 (positive gate
//      that the kernel took the success branch and therefore the
//      vreg-write step also ran)
//   6. assert each of vregs 1..13 == 0 — the spec line under test
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: recv's reply_handle_id was zero — the kernel did not reach
//      the success branch, so the all-zero vreg reading is not a
//      witness for the spec line
//   6: at least one of vregs 1..13 (GPR window per §[event_state])
//      was non-zero even though the suspending EC handle did not
//      have the `read` cap — the spec line under test is violated

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind keeps the port alive for recv (no
    // E_CLOSED on the cap path); recv lets the test invoke recv on
    // it. xfer is intentionally omitted — this test never attaches
    // handles, so xfer is unnecessary, and omitting it shrinks the
    // attack surface for unrelated gates.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W — the EC the test will queue on the port. susp
    // lets the test queue W via suspend. restart_policy = 0 (kill)
    // keeps the call inside the runner-granted ceiling. Critically,
    // `read = false` (the EcCap default) is the precondition for
    // the spec line under test: the EC handle the suspender uses
    // must not have `read`, otherwise §[event_state] would expose
    // the suspended EC's state through the vregs and test 12's
    // post-condition (all event-state vregs zero) would not hold.
    const w_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Per
    // §[suspend], when [1] is not the calling EC the call returns
    // immediately after queueing — control returns to this test EC
    // and recv on the same port can dequeue W on the next step.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The port has the test EC as a live bind-cap
    // holder and W queued as a suspension event, so recv returns
    // immediately with the syscall word and vregs populated per
    // §[recv] / §[event_state].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: positive gate. §[recv] syscall word return layout puts
    // reply_handle_id in bits 32-43. A non-zero reply_handle_id
    // witnesses that recv installed a reply handle in the caller's
    // table — i.e. it took the success branch and therefore reached
    // the vreg-write step. If reply_handle_id were zero we could not
    // distinguish "kernel zeroed the vregs because no read cap" from
    // "kernel never wrote the vregs because some other gate fired."
    const reply_handle_id: u64 = (got.word >> 32) & 0xFFF;
    if (reply_handle_id == 0) {
        testing.fail(5);
        return;
    }

    // Step 6: the spec line under test. §[event_state] x86-64 vreg
    // table puts the suspended EC's GPRs (rax, rbx, rdx, rbp, rsi,
    // rdi, r8, r9, r10, r12, r13, r14, r15) in vregs 1..13. Without
    // the `read` cap on the EC handle that triggered the event,
    // every one of these slots must read back as zero. The kernel
    // also zeros the higher event-state vregs (RIP/RFLAGS/RSP/etc.
    // at vregs 14..18 and the event-specific payload at 19..127),
    // but those live on the receiver's stack and are not captured
    // by the Regs return type. The 13 GPR slots are sufficient: if
    // the kernel skipped the read-cap gate, the suspended EC's
    // halt-loop GPRs (rip into rcx-via-syscall side effects, the
    // entry-function argv state, etc.) would be observable here.
    const v_array = [_]u64{
        got.regs.v1,  got.regs.v2,  got.regs.v3,
        got.regs.v4,  got.regs.v5,  got.regs.v6,
        got.regs.v7,  got.regs.v8,  got.regs.v9,
        got.regs.v10, got.regs.v11, got.regs.v12,
        got.regs.v13,
    };
    var i: usize = 0;
    while (i < v_array.len) {
        if (v_array[i] != 0) {
            testing.fail(6);
            return;
        }
        i += 1;
    }

    testing.pass();
}
