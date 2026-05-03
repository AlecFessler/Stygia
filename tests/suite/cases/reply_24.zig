// Spec §[reply] reply — test 24.
//
// "[test 24] on success when `recv_port_handle_id != 0`, after the
//  suspended EC is resumed the caller is parked on the named port and
//  a subsequent event delivered on that port wakes the caller with the
//  recv return contract — syscall word packed with the new
//  `reply_handle_id` / `event_type` / `pair_count` / `tstart`, and
//  vregs 1..13 carrying the suspending EC's state."
//
// Strategy
//   The recv-mode reply path needs THREE actors so that the test EC can
//   observe both the resume of the original sender AND the wakeup from
//   the freshly-named port:
//
//     - Test EC mints port_A (caps={bind,recv}) and port_B
//       (caps={bind,recv}). xfer is unnecessary because the test issues
//       reply with pair_count = 0 and we never attach handles.
//     - Test EC mints sibling W with caps={susp,term} priority 1.
//       W's job is to self-suspend on port_A so the test EC can recv on
//       it; that recv mints reply_handle_A in the test EC's table.
//     - Test EC mints sibling X with caps={susp,term} priority 1.
//       X's job is to self-suspend on port_B *after* the test EC has
//       parked itself on port_B via the recv-mode reply, so that the
//       wakeup the test EC observes is X's suspension event (not a
//       race with W's still-running tail).
//     - Cross-EC handle ids and start-gates ride in shared module-scope
//       globals; the siblings spin on `g_ready_w` / `g_ready_x` until
//       the test EC has installed the handles and given them the go
//       signal. Same single-domain in-process mailbox pattern as
//       reply_transfer_12.zig.
//     - Self-suspend is open-coded in inline asm (syscall_num=14) so
//       the test EC can sequence the start gates and observe a real
//       cross-EC suspend handoff.
//     - The test EC then issues `syscall.replyRecv(reply_handle_A,
//       port_B)` (the new spec-v3 unified-reply libz wrapper). The
//       kernel atomically: consumes reply_handle_A and resumes W, then
//       parks the test EC on port_B as if it had immediately invoked
//       `recv(port_B, 0)`. Once X self-suspends on port_B, the test
//       EC's parked recv wakes with the §[event_state] return contract.
//
// Action
//   1. create_port port_A — must succeed
//   2. create_port port_B — must succeed
//   3. create_execution_context W — must succeed
//   4. create_execution_context X — must succeed
//   5. release W via g_ready_w → W self-suspends on port_A
//   6. recv(port_A, 0) — get reply_handle_A
//   7. release X via g_ready_x
//   8. replyRecv(reply_handle_A, port_B) — atomic resume W + park on B
//   9. observe recv contract on the post-recv syscall word
//
// SPEC AMBIGUITY: spec §[event_type] enumerates `suspension = 4`, but
// libz does not export the EventType enum (the kernel keeps it private
// in `kernel/sched/execution_context.zig`). The test hard-codes 4 with
// a comment per §[event_type] until libz grows a typed wrapper.
//
// SPEC AMBIGUITY: spec §[event_state] tabulates the recv return word's
// _reserved low 12 bits and reserved bits 56-63. The test treats those
// as zero-or-don't-care — the assertions key off pair_count / tstart /
// reply_handle_id / event_type only.
//
// Assertions
//   1: setup — create_port for port_A returned an error word
//   2: setup — create_port for port_B returned an error word
//   3: setup — create_execution_context for W returned an error
//   4: setup — create_execution_context for X returned an error
//   5: recv on port_A did not return OK
//   6: recv on port_A returned reply_handle_id == 0
//   7: replyRecv did not return OK in vreg 1
//   8: post-recv syscall word event_type field != suspension (4)
//   9: post-recv syscall word reply_handle_id field == 0 (kernel did
//      not mint a fresh reply handle for X's suspension event)
//   10: post-recv syscall word pair_count field != 0 (X attached
//       nothing, but the kernel populated pair_count anyway)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[event_type]: suspension = 4. libz does not export EventType.
const EVENT_TYPE_SUSPENSION: u8 = 4;

// Cross-EC channel. Test EC + siblings share the same address space
// (single domain, single ELF). Same in-process mailbox pattern as
// reply_transfer_12.zig.
var g_port_a_handle: u64 = 0;
var g_port_b_handle: u64 = 0;
var g_w_self_handle: u64 = 0;
var g_x_self_handle: u64 = 0;
var g_ready_w: u32 = 0;
var g_ready_x: u32 = 0;

fn selfSuspendOnPort(self_ec_id: u64, port_id: u64) void {
    // syscall_num = 14 (.suspend). vreg 0 = syscall word, vreg 1 =
    // self EC handle, vreg 2 = port handle. No attachments. After
    // resume we don't care about any return — the sibling exits to
    // the parked-forever loop.
    const word_in: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\ pushq %%rcx
                \\ syscall
                \\ popq %%rcx
                :
                : [wi] "{rcx}" (word_in),
                  [v1i] "{rax}" (self_ec_id),
                  [v2i] "{rbx}" (port_id),
                : .{
                    .rcx = true,
                    .rax = true,
                    .rbx = true,
                    .rdx = true,
                    .rbp = true,
                    .rsi = true,
                    .rdi = true,
                    .r8 = true,
                    .r9 = true,
                    .r10 = true,
                    .r11 = true,
                    .r12 = true,
                    .r13 = true,
                    .r14 = true,
                    .r15 = true,
                    .memory = true,
                });
        },
        .aarch64 => {
            asm volatile (
                \\ sub sp, sp, #16
                \\ str %[wi], [sp]
                \\ svc #0
                \\ add sp, sp, #16
                :
                : [wi] "r" (word_in),
                  [v1i] "{x0}" (self_ec_id),
                  [v2i] "{x1}" (port_id),
                : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true,
                     .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true,
                     .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true,
                     .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true,
                     .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true,
                     .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true,
                     .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }
}

fn parkForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfe"),
            else => @compileError("unsupported target architecture"),
        }
    }
}

fn siblingW_entry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &g_ready_w, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }

    selfSuspendOnPort(g_w_self_handle, g_port_a_handle);
    parkForever();
}

fn siblingX_entry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &g_ready_x, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }

    selfSuspendOnPort(g_x_self_handle, g_port_b_handle);
    parkForever();
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Mint port_A with bind|recv. We don't need xfer because
    //    pair_count = 0 across this whole test.
    const port_caps_word = caps.PortCap{ .recv = true, .bind = true };
    const cp_a = syscall.createPort(@as(u64, port_caps_word.toU16()));
    if (testing.isHandleError(cp_a.v1)) {
        testing.fail(1);
        return;
    }
    const port_a: HandleId = @truncate(cp_a.v1 & 0xFFF);

    // 2. Mint port_B with bind|recv. Same caps as port_A.
    const cp_b = syscall.createPort(@as(u64, port_caps_word.toU16()));
    if (testing.isHandleError(cp_b.v1)) {
        testing.fail(2);
        return;
    }
    const port_b: HandleId = @truncate(cp_b.v1 & 0xFFF);

    // 3. Mint sibling W with susp|term. priority = 1 so W can be
    //    dispatched alongside the test EC (also priority 1) — without
    //    it, W sits at idle and never reaches its self-suspend.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, ec_caps.toU16()) | (@as(u64, 1) << 32);
    const cec_w = syscall.createExecutionContext(
        ec_caps_word,
        @intFromPtr(&siblingW_entry),
        1, // stack_pages
        0, // target = self
        0, // affinity
    );
    if (testing.isHandleError(cec_w.v1)) {
        testing.fail(3);
        return;
    }
    const w_ec: HandleId = @truncate(cec_w.v1 & 0xFFF);

    // 4. Mint sibling X with the same cap profile.
    const cec_x = syscall.createExecutionContext(
        ec_caps_word,
        @intFromPtr(&siblingX_entry),
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_x.v1)) {
        testing.fail(4);
        return;
    }
    const x_ec: HandleId = @truncate(cec_x.v1 & 0xFFF);

    // Hand the siblings their handle ids before unleashing them.
    @atomicStore(u64, &g_port_a_handle, @as(u64, port_a), .release);
    @atomicStore(u64, &g_port_b_handle, @as(u64, port_b), .release);
    @atomicStore(u64, &g_w_self_handle, @as(u64, w_ec), .release);
    @atomicStore(u64, &g_x_self_handle, @as(u64, x_ec), .release);

    // 5. Release W. W self-suspends on port_A; the kernel queues a
    //    suspension event there.
    @atomicStore(u32, &g_ready_w, 1, .release);

    // 6. recv on port_A. Returns the reply_handle for W's suspension.
    const got_a = syscall.recv(port_a, 0);
    if (got_a.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }
    const reply_handle_a: HandleId = @truncate((got_a.word >> 32) & 0xFFF);
    if (reply_handle_a == 0) {
        testing.fail(6);
        return;
    }

    // 7. Release X *before* replyRecv parks us — X is a sibling, and
    //    its self-suspend on port_B is the wakeup we'll observe. If we
    //    released X earlier, X could race with W and end up queued on
    //    port_B before we even arm the recv side; that would still
    //    work (kernel buffers the event), but releasing here keeps the
    //    sequencing readable.
    @atomicStore(u32, &g_ready_x, 1, .release);

    // 8. Atomic reply-then-recv. resumes W (consumes reply_handle_a),
    //    then parks the test EC on port_b waiting for the next event.
    //    X's self-suspend on port_b feeds that recv. Returned word /
    //    regs follow §[recv]'s return contract.
    const rr = syscall.replyRecv(reply_handle_a, port_b);

    // 9. The reply-then-recv must succeed in vreg 1.
    if (rr.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    // 10. Decode the §[event_state] return word fields.
    //   bits 12-19: pair_count
    //   bits 32-43: reply_handle_id (the new one for X's event)
    //   bits 44-48: event_type
    const event_type: u8 = @truncate((rr.word >> 44) & 0x1F);
    const new_reply_handle_id: u12 = @truncate((rr.word >> 32) & 0xFFF);
    const pair_count: u8 = @truncate((rr.word >> 12) & 0xFF);

    // event_type must be `suspension` (X self-suspended).
    if (event_type != EVENT_TYPE_SUSPENSION) {
        testing.fail(8);
        return;
    }
    // The kernel must have minted a fresh reply handle for X's
    // suspension event in the test EC's table.
    if (new_reply_handle_id == 0) {
        testing.fail(9);
        return;
    }
    // X attached nothing on its self-suspend, so pair_count == 0.
    if (pair_count != 0) {
        testing.fail(10);
        return;
    }

    testing.pass();
}
