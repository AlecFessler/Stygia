// §[restart_semantics]: a restart-cap process survives a specified exit
// trigger, and a restart_at_entry worker runs its entry again. The runner
// grants these tests the restart cap; each test creates a nested child and
// observes it from outside across the restart boundary. The worker first
// suspends on the parent's work port. The child initial thread suspends on a
// separate trigger port. After the parent receives and replies to both,
// the initial thread faults or voluntarily exits. A restart re-enters the worker,
// delivering a second work event; teardown closes the work port instead.
// Assertion 11 is the restart witness.
const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CHILD_CRIPC: u8 = 0x07;
const CHILD_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED;
const SELF_ELF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1;
const LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2;
const TRIGGER_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED + 3;
// TCG can delay one of several contending child threads for seconds during
// repeated runs. Stay below the runner's 30-second per-case timeout.
const TIMEOUT_NS: u64 = 10_000_000_000;

fn spinForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"),
            .aarch64 => asm volatile ("yield"),
            else => @compileError("unsupported restart test architecture"),
        }
    }
}

fn workerEntry() callconv(.c) noreturn {
    // `self` resolves the worker's own handle without depending on the
    // handle-slot chosen by create_thread. A newly runnable worker can
    // start before its creator finishes minting that handle; retry E_NOENT
    // until the creator's cap-table write becomes visible.
    var own = syscall.self();
    while (own.v1 == @intFromEnum(errors.Error.E_NOENT)) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"),
            .aarch64 => asm volatile ("yield"),
            else => unreachable,
        }
        own = syscall.self();
    }
    if (testing.isHandleError(own.v1)) spinForever();
    const own_handle: caps.HandleId = @truncate(own.v1 & 0xFFF);
    const result = syscall.suspendThread(own_handle, CHILD_PORT, &.{});
    if (result.v1 == @intFromEnum(errors.Error.E_ABANDONED)) {
        // The parent deletes the second reply handle to ask this child to
        // exit. Drop restart first, so cleanup does not restart it again.
        _ = syscall.restrict(caps.SLOT_SELF, 0);
        _ = syscall.delete(caps.SLOT_SELF);
        spinForever();
    }
    if (result.v1 != @intFromEnum(errors.Error.OK)) spinForever();
    spinForever();
}

pub const Trigger = enum { fault, self_delete };

fn childMain(comptime trigger: Trigger) void {
    const worker_caps = caps.ThreadCap{ .susp = true, .restart_policy = 1 };
    const created = syscall.createThread(
        @as(u64, worker_caps.toU16()),
        @intFromPtr(&workerEntry),
        1,
        0,
        0,
    );
    if (testing.isHandleError(created.v1)) spinForever();

    // The parent releases this suspension only after it has received the
    // worker's first event. No shared .bss mailbox is needed, so repeated
    // ELF spawns cannot cross-talk through their staged page frame.
    const go = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, TRIGGER_PORT, &.{});
    if (go.v1 != @intFromEnum(errors.Error.OK)) spinForever();
    switch (trigger) {
        .fault => {
            switch (builtin.cpu.arch) {
                .x86_64 => asm volatile ("int3"),
                .aarch64 => asm volatile ("brk #0"),
                else => unreachable,
            }
            spinForever();
        },
        // Returning to _start drops the self-handle, which is the
        // voluntary process-exit path under test.
        .self_delete => return,
    }
}

fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}

pub fn run(comptime cause: Trigger, cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const my_cripc: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);
    if (my_cripc == CHILD_CRIPC) return childMain(cause);

    const port_caps = caps.PortCap{
        .copy = true,
        .bind = true,
        .recv = true,
        .@"suspend" = true,
        .restart_policy = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) return fail(1);
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);
    const trigger_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true };
    const trigger = syscall.createPort(@as(u64, trigger_caps.toU16()));
    if (testing.isHandleError(trigger.v1)) return fail(2);
    const trigger_handle: caps.HandleId = @truncate(trigger.v1 & 0xFFF);

    const child_self = caps.SelfCap{ .crec = true, .crvr = true, .restart = true, .pri = 3 };
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x5C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_01FE_FFFF;
    const passed = [_]u64{
        (caps.PassedHandle{
            .id = port_handle,
            .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16(),
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = SELF_ELF,
            .caps = (caps.PfCap{ .r = true }).toU16(),
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = LIBZ_PF,
            .caps = (caps.PfCap{ .r = true, .x = true }).toU16(),
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = trigger_handle,
            .caps = (caps.PortCap{ .@"suspend" = true }).toU16(),
            .move = false,
        }).toU64(),
    };
    const child = syscall.createProcess(
        @as(u64, child_self.toU16()),
        ceilings_inner,
        ceilings_outer,
        SELF_ELF,
        0,
        &passed,
    );
    if (testing.isHandleError(child.v1)) return fail(3);

    // Only the child now holds bind. If it is destroyed instead of
    // restarted, the next recv returns E_CLOSED and this test fails.
    const drop_bind = syscall.restrict(port_handle, (caps.PortCap{ .recv = true }).toU16());
    if (drop_bind.v1 != @intFromEnum(errors.Error.OK)) return fail(4);

    const first = syscall.recv(port_handle, TIMEOUT_NS);
    if (first.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(5);
    const first_reply: caps.HandleId = @truncate((first.word >> 32) & 0xFFF);
    if (first_reply == 0) return fail(6);
    if (syscall.reply(first_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(7);

    const armed = syscall.recv(trigger_handle, TIMEOUT_NS);
    if (armed.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(8);
    const trigger_reply: caps.HandleId = @truncate((armed.word >> 32) & 0xFFF);
    if (trigger_reply == 0) return fail(9);
    if (syscall.reply(trigger_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(10);

    const second = syscall.recv(port_handle, TIMEOUT_NS);
    if (second.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(11);
    const second_reply: caps.HandleId = @truncate((second.word >> 32) & 0xFFF);
    if (second_reply == 0) return fail(12);
    if (syscall.delete(second_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(13);

    const closed = syscall.recv(port_handle, TIMEOUT_NS);
    if (closed.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) return fail(14);
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.pass();
}
