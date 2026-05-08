// Spec §[reply] reply — test 22.
//
// "[test 22] returns E_BADCAP when `recv_port_handle_id != 0` and that
//  slot does not name a valid port handle in the caller's domain; the
//  reply handle is NOT consumed and the caller does not park."
//
// Strategy
//   To exercise the recv-port gate we must arrive at the reply syscall
//   with a real reply handle in the caller's table — otherwise the
//   reply-handle gate (test 01) would fire first. Pipeline (single
//   domain, test EC owns both ends):
//
//     1. mint port with caps = {bind, recv}     — xfer not needed since
//        pair_count = 0, but bind is required for suspend (§[suspend]
//        [2] cap) and recv lets the test EC dequeue the suspension.
//     2. mint EC W with caps = {susp}, target = self, restart_policy = 0.
//     3. suspend(W, port)                        — queues W as a
//        suspended sender; non-blocking on the test EC since
//        [1] != self per §[suspend].
//     4. recv(port, 0)                           — returns immediately
//        with the reply handle id encoded in syscall word bits 32-43.
//     5. unified reply syscall with pair_count = 0 and
//        recv_port_handle_id = 4095. Slot 4095 is guaranteed empty by
//        the create_capability_domain table layout (slot 0 = self,
//        1 = initial EC, 2 = self-IDC, 3+ = passed_handles), so it
//        cannot name a valid port handle. The kernel must return
//        E_BADCAP and must NOT consume the reply handle.
//
//   libz has no bare-reply wrapper that takes a recv_port_handle_id, so
//   the syscall is dispatched via raw inline asm. The expected return
//   shape is the bare error-code-in-vreg-1 form because we EXPECT the
//   call to fail before parking: per §[reply], "On any error before the
//   caller parks (invalid reply, invalid port, sender E_TERM, etc.) the
//   caller does NOT park and the recv side has no effect."
//
// Action
//   1. create_port(caps = {bind, recv})          — must succeed
//   2. create_execution_context(target = self,
//        caps = {susp, restart_policy = 0})      — must succeed
//   3. suspend(W, port)                          — must return OK
//   4. recv(port, 0)                             — must return OK and
//      hand back a non-zero reply_handle_id
//   5. reply(reply_handle_id, recv_port = 4095)  — must return E_BADCAP
//      and leave the reply handle slot intact
//
// Assertions
//   1: setup port creation failed
//   2: setup EC creation failed
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: recv returned reply_handle_id == 0
//   6: reply did not return E_BADCAP
//   7: reply consumed the reply handle slot

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

pub fn main(cap_table_base: u64) void {
    // Step 1: mint port with bind|recv. xfer not needed (pair_count = 0).
    const port_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: HandleId = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. susp lets us queue W onto the port via suspend.
    // restart_policy = 0 (kill) keeps the call inside the runner-granted
    // ceiling.
    const w_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
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
    const w_handle: HandleId = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Since
    // [1] = W != self, the call returns immediately without blocking
    // the test EC (§[suspend]).
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
    const reply_handle_id: HandleId = @truncate((got.word >> 32) & 0xFFF);
    if (reply_handle_id == 0) {
        testing.fail(5);
        return;
    }

    // Step 5: probe the recv-port gate. Slot 4095 is guaranteed empty
    // (create_capability_domain table layout — see reply_01.zig). The
    // unified reply syscall word per §[reply]:
    //   bits  0-11: syscall_num (52 = reply)
    //   bits 12-19: pair_count (0)
    //   bits 20-31: reply_handle_id
    //   bits 32-43: recv_port_handle_id (non-zero triggers recv mode)
    //
    // We dispatch via raw inline asm because libz has no bare-reply
    // wrapper that accepts recv_port_handle_id, and we want the bare
    // error-code-in-vreg-1 return shape (we EXPECT this to fail before
    // parking, so the recv-style return contract does not apply).
    const empty_recv_port: u64 = caps.HANDLE_TABLE_MAX - 1;
    const word: u64 =
        @as(u64, @intFromEnum(syscall.SyscallNum.reply)) |
        (@as(u64, reply_handle_id) << 20) |
        (empty_recv_port << 32);

    var rax_out: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\ pushq %%rcx
                \\ syscall
                \\ popq %%rcx
                : [v1] "={rax}" (rax_out),
                : [w] "{rcx}" (word),
                : .{
                    .rcx = true,
                    .rdx = true,
                    .rbx = true,
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
                \\ str %[w], [sp]
                \\ svc #0
                \\ add sp, sp, #16
                : [v1] "={x0}" (rax_out),
                : [w] "r" (word),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    if (rax_out != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(6);
        return;
    }

    // Reply handle must NOT be consumed — the recv-port gate fired
    // before any reply-side state change.
    const reply_slot = caps.readCap(cap_table_base, @as(u32, reply_handle_id));
    if (reply_slot.handleType() != .reply) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
