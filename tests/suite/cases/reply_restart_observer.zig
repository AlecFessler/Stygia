// §[restart_semantics] reply_policy: the parent watches a suspended caller
// while a child process faults holding its reply handle.
const builtin = @import("builtin");
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;
const CHILD_CRIPC: u8 = 0x07;
const EVENT: caps.HandleId = caps.SLOT_FIRST_PASSED;
const ELF: caps.HandleId = EVENT + 1;
const LIBZ: caps.HandleId = EVENT + 2;
const REQUEST: caps.HandleId = EVENT + 3;
const TIMEOUT_NS: u64 = 10_000_000_000;
const MARKER: u16 = (caps.PortCap{ .recv = true, .@"suspend" = true, .restart_policy = true }).toU16();
var worker_request: caps.HandleId = 0;
var worker_observe: caps.HandleId = 0;
var restart_worker_base: u64 = 0;
var restart_worker_hold: caps.HandleId = 0;
var restart_worker_started: bool = false;
fn ok(x: u64) bool {
    return x == @intFromEnum(errors.Error.OK);
}
fn handle(x: u64) ?caps.HandleId {
    if (testing.isHandleError(x) or x == 0) return null;
    return @truncate(x & 0xFFF);
}
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
fn ownHandle() caps.HandleId {
    var own = syscall.self();
    while (own.v1 == @intFromEnum(errors.Error.E_NOENT)) {
        pause();
        own = syscall.self();
    }
    if (testing.isHandleError(own.v1)) spin();
    return @truncate(own.v1 & 0xFFF);
}
fn fault() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => unreachable,
    }
    spin();
}
fn marker(base: u64) bool {
    var slot: u32 = 3;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(base, slot);
        if (cap.word0 != 0 and cap.handleType() == .port and cap.caps() == MARKER) return true;
    }
    return false;
}
fn pendingReply(base: u64) ?caps.HandleId {
    var slot: u32 = 3;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(base, slot);
        if (cap.word0 != 0 and cap.handleType() == .reply) return @intCast(slot);
    }
    return null;
}
fn notify(code: u64) u64 {
    const sent = syscall.issueRawCaptureWord(0, .{ .v1 = ownHandle(), .v2 = EVENT, .v3 = code });
    return sent.regs.v1;
}
fn child(comptime keep: bool, base: u64) noreturn {
    if (marker(base)) {
        const reply_cap = pendingReply(base);
        const status = notify(if ((reply_cap != null) == keep) 100 else 31);
        if (!ok(status)) spin();
        if (keep) {
            if (!ok(syscall.reply(reply_cap.?).v1)) spin();
        }
        _ = syscall.restrict(caps.SLOT_SELF, 0);
        _ = syscall.delete(caps.SLOT_SELF);
        spin();
    }
    _ = handle(syscall.createPort(MARKER).v1) orelse {
        _ = notify(11);
        spin();
    };
    restart_worker_base = base;
    const entry = struct {
        fn run() callconv(.c) noreturn {
            if (!@atomicLoad(bool, &restart_worker_started, .acquire)) {
                @atomicStore(bool, &restart_worker_started, true, .release);
                _ = syscall.suspendThread(ownHandle(), restart_worker_hold, &.{});
                spin();
            }
            child(keep, restart_worker_base);
        }
    }.run;
    const hold_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    restart_worker_hold = handle(syscall.createPort(hold_caps.toU16()).v1) orelse {
        _ = notify(15);
        spin();
    };
    const worker_caps = caps.ThreadCap{ .susp = true, .read = true, .restart_policy = 1 };
    _ = handle(syscall.createThread(worker_caps.toU16(), @intFromPtr(&entry), 1, 0, 0).v1) orelse {
        _ = notify(14);
        spin();
    };
    // Blocking receive gives the lower-priority worker a dispatch turn on
    // single-core TCG as well as SMP. It also proves the old worker is
    // suspended before the fault triggers restart.
    const holding = syscall.recv(restart_worker_hold, TIMEOUT_NS);
    if (!ok(holding.regs.v1)) {
        _ = notify(16);
        spin();
    }
    const hold_reply: caps.HandleId = @truncate((holding.word >> 32) & 0xFFF);
    if (hold_reply == 0 or !ok(syscall.delete(hold_reply).v1)) {
        _ = notify(17);
        spin();
    }
    if (!ok(notify(1))) spin();
    const request = syscall.recv(REQUEST, TIMEOUT_NS);
    if (!ok(request.regs.v1)) {
        _ = notify(12);
        spin();
    }
    const held: caps.HandleId = @truncate((request.word >> 32) & 0xFFF);
    if (held == 0 or pendingReply(base) == null) {
        _ = notify(13);
        spin();
    }
    if (!ok(notify(2))) spin();
    // The reply handle is now held in this process. A fault must apply
    // reply_policy before either the caller or restarted entry proceeds.
    fault();
}
fn worker() callconv(.c) noreturn {
    const own = syscall.self();
    if (testing.isHandleError(own.v1)) spin();
    const id: caps.HandleId = @truncate(own.v1 & 0xFFF);
    const result = syscall.suspendThread(id, worker_request, &.{});
    const sent = syscall.issueRawCaptureWord(0, .{ .v1 = id, .v2 = worker_observe, .v3 = result.v1 });
    if (!ok(sent.regs.v1)) spin();
    spin();
}
fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}
pub fn run(comptime keep: bool, base: u64) void {
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (@as(u8, @truncate(self.field0 >> 24)) == CHILD_CRIPC) child(keep, base);
    const event_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true, .restart_policy = true };
    const event = handle(syscall.createPort(event_caps.toU16()).v1) orelse return fail(1);
    const req_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true, .restart_policy = true };
    const request = handle(syscall.createPort(req_caps.toU16()).v1) orelse return fail(2);
    const observer = handle(syscall.createPort((caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true }).toU16()).v1) orelse return fail(3);
    const passed = [_]u64{
        (caps.PassedHandle{ .id = event, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = ELF, .caps = (caps.PfCap{ .r = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = LIBZ, .caps = (caps.PfCap{ .r = true, .x = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = request, .caps = (caps.PortCap{ .recv = true, .restart_policy = true }).toU16(), .move = false }).toU64(),
    };
    const inner: u64 = @as(u64, 0xFF) | (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) | (@as(u64, 0x1F) << 32) |
        (@as(u64, 1) << 40) | (@as(u64, 0x5C) << 48);
    const proc = syscall.createProcess((caps.SelfCap{ .crec = true, .crvr = true, .crpf = true, .crvm = true, .crpt = true, .restart = true, .reply_policy = keep, .pri = 3 }).toU16(), inner, 0x0000_003F_01FE_FFFF, ELF, 0, &passed);
    if (handle(proc.v1) == null) return fail(4);
    if (!ok(syscall.restrict(event, (caps.PortCap{ .recv = true }).toU16()).v1)) return fail(5);
    const ready = syscall.recv(event, TIMEOUT_NS);
    if (!ok(ready.regs.v1)) return fail(60 + ready.regs.v1);
    if (ready.regs.v3 != 1) return fail(600 + ready.regs.v3);
    const ready_reply: caps.HandleId = @truncate((ready.word >> 32) & 0xFFF);
    if (ready_reply == 0 or !ok(syscall.reply(ready_reply).v1)) return fail(7);
    worker_request = request;
    worker_observe = observer;
    const worker_cap = caps.ThreadCap{ .susp = true, .read = true };
    if (handle(syscall.createThread(worker_cap.toU16(), @intFromPtr(&worker), 1, 0, 0).v1) == null) return fail(8);
    const armed = syscall.recv(event, TIMEOUT_NS);
    if (!ok(armed.regs.v1)) return fail(9);
    if (armed.regs.v3 != 2) return fail(90 + armed.regs.v3);
    const armed_reply: caps.HandleId = @truncate((armed.word >> 32) & 0xFFF);
    if (armed_reply == 0 or !ok(syscall.reply(armed_reply).v1)) return fail(91);
    const restarted = syscall.recv(event, TIMEOUT_NS);
    if (!ok(restarted.regs.v1)) return fail(92);
    if (restarted.regs.v3 != 100) return fail(93 + restarted.regs.v3);
    const restart_reply: caps.HandleId = @truncate((restarted.word >> 32) & 0xFFF);
    if (restart_reply == 0 or !ok(syscall.reply(restart_reply).v1)) return fail(10);
    const outcome = syscall.recv(observer, TIMEOUT_NS);
    if (!ok(outcome.regs.v1)) return fail(11);
    const observed = outcome.regs.v3;
    const worker_reply: caps.HandleId = @truncate((outcome.word >> 32) & 0xFFF);
    if (worker_reply != 0) _ = syscall.delete(worker_reply);
    if (observed != @intFromEnum(if (keep) errors.Error.OK else errors.Error.E_REFUSED)) return fail(120 + observed);
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.pass();
}
