// Queued-sender reply return: a sender already parked before recv must
// resume with OK in vreg 1. A missing saved-frame write instead returns
// the sender's original thread handle id from suspend([1]).
const builtin = @import("builtin");
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

var ready_port: caps.HandleId = 0;
var request_port: caps.HandleId = 0;
var observed_port: caps.HandleId = 0;

fn pause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => @compileError("unsupported architecture"),
    }
}

fn worker() callconv(.c) noreturn {
    var own = syscall.self();
    while (own.v1 == @intFromEnum(errors.Error.E_NOENT)) {
        pause();
        own = syscall.self();
    }
    if (testing.isHandleError(own.v1)) while (true) pause();
    const id: caps.HandleId = @truncate(own.v1 & 0xFFF);
    _ = syscall.suspendThread(id, ready_port, &.{});
    const resumed = syscall.suspendThread(id, request_port, &.{});
    // A completion event gives the observer a scheduling-independent
    // witness of the saved-frame return code, including on fast Pi cores.
    _ = syscall.issueRawCaptureWord(0, .{ .v1 = id, .v2 = observed_port, .v3 = resumed.v1 });
    while (true) pause();
}

fn handle(word: u64) ?caps.HandleId {
    if (testing.isHandleError(word) or word == 0) return null;
    return @truncate(word & 0xFFF);
}

fn take(port: caps.HandleId) ?caps.HandleId {
    const event = syscall.recv(port, 5_000_000_000);
    if (event.regs.v1 != @intFromEnum(errors.Error.OK)) return null;
    const reply: caps.HandleId = @truncate((event.word >> 32) & 0xFFF);
    return if (reply == 0) null else reply;
}

fn fail(id: u64) void {
    testing.fail(id);
}

pub fn main(_: u64) void {
    const port_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    ready_port = handle(syscall.createPort(port_caps.toU16()).v1) orelse return fail(1);
    request_port = handle(syscall.createPort(port_caps.toU16()).v1) orelse return fail(2);
    observed_port = handle(syscall.createPort(port_caps.toU16()).v1) orelse return fail(9);
    const thread_caps = caps.ThreadCap{ .susp = true, .read = true };
    const thread = handle(syscall.createThread(thread_caps.toU16(), @intFromPtr(&worker), 1, 0, 0).v1) orelse return fail(3);
    const ready = take(ready_port) orelse return fail(4);
    if (syscall.reply(ready).v1 != @intFromEnum(errors.Error.OK)) return fail(5);
    // The worker runs through the second suspend and parks before this
    // call returns. recv therefore consumes a queued sender.
    _ = syscall.yieldThread(thread);
    const reply = take(request_port) orelse return fail(6);
    if (syscall.reply(reply).v1 != @intFromEnum(errors.Error.OK)) return fail(7);
    const observed = syscall.recv(observed_port, 5_000_000_000);
    if (observed.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(8);
    if (observed.regs.v3 != @intFromEnum(errors.Error.OK)) return fail(80 + observed.regs.v3);
    testing.pass();
}
