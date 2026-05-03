// Spec §[reply] reply — test 23.
//
// "[test 23] returns E_PERM when `recv_port_handle_id != 0` and the
//  named port handle does not have the `recv` cap; the reply handle is
//  NOT consumed and the caller does not park."
//
// Strategy
//   §[reply] caps required: "`recv` cap on the named port when
//   `recv_port_handle_id != 0`." With recv-mode requested but the named
//   port lacking the `recv` cap, the kernel must reject the call with
//   E_PERM, leave the reply handle in the caller's table, and skip the
//   atomic park step.
//
//   Pipeline (test EC owns both ports + W):
//     1. mint port_A with caps = {bind, recv}    — used to obtain a
//        reply handle via the suspend → recv choreography.
//     2. mint port_B with caps = {bind} only     — no recv cap. This
//        is the port we'll name in the recv-mode reply word.
//     3. mint sibling EC W with caps = {susp, restart_policy = 0} and
//        target = self so it runs in the test EC's address space.
//     4. suspend(W, port_A)                      — queues W as a
//        suspended sender on port_A; non-blocking on the test EC since
//        [1] != self per §[suspend].
//     5. recv(port_A, 0)                         — returns immediately
//        with reply_handle_id in syscall-word bits 32-43.
//     6. issue unified reply via raw asm with reply_handle_id (bits
//        20-31) and recv_port_handle_id = port_B (bits 32-43). The
//        kernel must check the recv cap on port_B before parking, so
//        no event needs to ever fire on port_B.
//     7. assert E_PERM and that the reply handle is still typed
//        `reply` in the caller's table.
//
//   The unified reply word layout per §[reply]:
//     bits  0-11: syscall_num (52)
//     bits 12-19: pair_count (0 here — bare reply)
//     bits 20-31: reply_handle_id
//     bits 32-43: recv_port_handle_id
//
//   libz's typed `reply` wrapper does not yet expose recv-mode, so the
//   call is dispatched directly via inline asm on each arch. This also
//   exercises the L4-style fast path's classifier on the recv-mode
//   reply word.
//
// Action
//   1. create_port(caps = {bind, recv})          — must succeed (port_A)
//   2. create_port(caps = {bind})                — must succeed (port_B)
//   3. create_execution_context(target = self,
//        caps = {susp, restart_policy = 0})      — must succeed
//   4. suspend(W, port_A)                        — must return OK
//   5. recv(port_A, 0)                           — must return OK
//   6. raw-asm reply(reply_handle_id,
//                   recv_port_handle_id = port_B) — must return E_PERM
//   7. readCap(reply_handle_id).handleType() == .reply
//
// Assertions
//   1: setup port_A creation failed
//   2: setup port_B creation failed
//   3: setup EC creation failed
//   4: suspend did not return OK
//   5: recv did not return OK
//   6: recv-mode reply returned something other than E_PERM
//   7: reply handle was consumed (slot no longer typed `reply`)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Step 1: mint port_A with bind + recv. bind keeps the port alive
    // for the recv on the test-EC side, recv lets the test EC dequeue
    // the suspension event and obtain a reply handle.
    const port_a_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp_a = syscall.createPort(@as(u64, port_a_caps.toU16()));
    if (testing.isHandleError(cp_a.v1)) {
        testing.fail(1);
        return;
    }
    const port_a_handle: u12 = @truncate(cp_a.v1 & 0xFFF);

    // Step 2: mint port_B with bind only — no recv cap. This is the
    // port the recv-mode reply will name; the missing recv cap is the
    // assertion under test.
    const port_b_caps = caps.PortCap{ .bind = true };
    const cp_b = syscall.createPort(@as(u64, port_b_caps.toU16()));
    if (testing.isHandleError(cp_b.v1)) {
        testing.fail(2);
        return;
    }
    const port_b_handle: u12 = @truncate(cp_b.v1 & 0xFFF);

    // Step 3: mint sibling EC W. susp lets the test EC queue W onto
    // port_A via suspend. restart_policy = 0 (kill) keeps the call
    // inside the runner-granted ec_restart_max ceiling.
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
        testing.fail(3);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 4: queue W as a suspended sender on port_A. [1] = W != self,
    // so the call returns immediately without blocking the test EC.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_a_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: recv on port_A. The test EC holds port_A's bind cap
    // (alive) and W is queued, so recv returns immediately with the
    // minted reply handle id in syscall-word bits 32-43.
    const got = syscall.recv(port_a_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 6: dispatch the recv-mode reply directly. libz's typed
    // `reply` wrapper covers only the bare-reply case; recv-mode and
    // attachment-bearing forms ride raw inline asm. The word packs
    // syscall_num (52) at bits 0-11, pair_count = 0 at bits 12-19,
    // reply_handle_id at bits 20-31, and recv_port_handle_id =
    // port_B at bits 32-43 per §[reply]. The kernel must observe
    // port_B's missing recv cap and reject with E_PERM before
    // consuming the reply handle or parking the caller.
    const word: u64 =
        @as(u64, @intFromEnum(syscall.SyscallNum.reply)) |
        (@as(u64, reply_handle_id) << 20) |
        (@as(u64, port_b_handle) << 32);

    var rax_out: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\ pushq %%rcx
                \\ syscall
                \\ popq %%rcx
                : [v1] "={rax}" (rax_out),
                : [w] "{rcx}" (word),
                : .{ .rcx = true, .rdx = true, .rbx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
        },
        .aarch64 => {
            asm volatile (
                \\ sub sp, sp, #16
                \\ str %[w], [sp]
                \\ svc #0
                \\ add sp, sp, #16
                : [v1] "={x0}" (rax_out),
                : [w] "r" (word),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    if (rax_out != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(6);
        return;
    }

    // Step 7: the reply handle must NOT have been consumed. The
    // capability table is mapped read-only in the holding domain, so
    // re-reading the slot via readCap reflects the kernel's authoritative
    // view; a `reply` HandleType means the slot still holds the live
    // reply handle.
    const slot = caps.readCap(cap_table_base, reply_handle_id);
    if (slot.handleType() != .reply) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
