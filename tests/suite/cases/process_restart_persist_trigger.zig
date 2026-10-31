// A policy-2 thread that itself faults has retired; it cannot be the sole
// survivor keeping its process live after the restart decision.
const builtin = @import("builtin");
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CHILD_CRIPC: u8 = 0x07;
const ENTRY: caps.HandleId = caps.SLOT_FIRST_PASSED;
const ELF: caps.HandleId = ENTRY + 1;
const LIBZ: caps.HandleId = ENTRY + 2;
const TIMEOUT_NS: u64 = 2_000_000_000;
var armed: bool = false;

fn pause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => @compileError("unsupported architecture"),
    }
}
fn spin() noreturn {
    while (true) pause();
}
fn handle(word: u64) ?caps.HandleId {
    if (testing.isHandleError(word) or word == 0) return null;
    return @truncate(word & 0xFFF);
}
fn ownHandle() caps.HandleId {
    var own = syscall.self();
    while (own.v1 == @intFromEnum(errors.Error.E_NOENT)) {
        pause();
        own = syscall.self();
    }
    return handle(own.v1) orelse spin();
}
fn fault() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => unreachable,
    }
    spin();
}
fn worker() callconv(.c) noreturn {
    while (!@atomicLoad(bool, &armed, .acquire)) pause();
    if (syscall.suspendThread(ownHandle(), ENTRY, &.{}).v1 != @intFromEnum(errors.Error.OK)) spin();
    fault();
}
fn child() noreturn {
    const worker_caps = caps.ThreadCap{ .susp = true, .restart_policy = 2 };
    _ = handle(syscall.createThread(worker_caps.toU16(), @intFromPtr(&worker), 1, 0, 0).v1) orelse spin();
    _ = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, ENTRY, &.{});
    @atomicStore(bool, &armed, true, .release);
    const hold_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    const hold = handle(syscall.createPort(hold_caps.toU16()).v1) orelse spin();
    _ = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, hold, &.{});
    spin();
}
fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}
pub fn main(base: u64) void {
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (@as(u8, @truncate(self.field0 >> 24)) == CHILD_CRIPC) child();

    const port_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true, .restart_policy = true };
    const entry_port = handle(syscall.createPort(port_caps.toU16()).v1) orelse return fail(1);
    const passed = [_]u64{
        (caps.PassedHandle{ .id = entry_port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = ELF, .caps = (caps.PfCap{ .r = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = LIBZ, .caps = (caps.PfCap{ .r = true, .x = true }).toU16(), .move = false }).toU64(),
    };
    const inner: u64 = @as(u64, 0xFF) | (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) | (@as(u64, 0x1F) << 32) |
        (@as(u64, 1) << 40) | (@as(u64, 0x5C) << 48);
    _ = handle(syscall.createProcess(
        (caps.SelfCap{ .crec = true, .crvr = true, .crpt = true, .restart = true, .pri = 3 }).toU16(),
        inner,
        0x0000_003F_01FE_FFFF,
        ELF,
        0,
        &passed,
    ).v1) orelse return fail(2);
    if (syscall.restrict(entry_port, (caps.PortCap{ .recv = true }).toU16()).v1 != @intFromEnum(errors.Error.OK)) return fail(3);
    const first = syscall.recv(entry_port, TIMEOUT_NS);
    if (first.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(4);
    const setup_reply: caps.HandleId = @truncate((first.word >> 32) & 0xFFF);
    if (setup_reply == 0 or syscall.reply(setup_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(5);
    const second = syscall.recv(entry_port, TIMEOUT_NS);
    if (second.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(7);
    const reply: caps.HandleId = @truncate((second.word >> 32) & 0xFFF);
    if (reply == 0 or syscall.reply(reply).v1 != @intFromEnum(errors.Error.OK)) return fail(8);
    const closed = syscall.recv(entry_port, TIMEOUT_NS);
    if (closed.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) return fail(6);
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.pass();
}
