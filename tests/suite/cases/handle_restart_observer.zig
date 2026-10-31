// Parent-observed §[restart_semantics] handle policies. A kept private port
// marks re-entry; the child checks its own read-only cap table after restart.
// The parent's recv endpoint distinguishes restart from process teardown.
const builtin = @import("builtin");
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub const Kind = enum { page_frame, device_region, port, virtual_machine, ipc };
const CHILD_CRIPC: u8 = 0x07;
const PORT: caps.HandleId = caps.SLOT_FIRST_PASSED;
const ELF: caps.HandleId = PORT + 1;
const LIBZ: caps.HandleId = PORT + 2;
const DEVICE: caps.HandleId = PORT + 3;
const TIMEOUT_NS: u64 = 10_000_000_000;
const MARKER: u16 = (caps.PortCap{ .recv = true, .@"suspend" = true, .restart_policy = true }).toU16();
var worker_base: u64 = 0;

fn ownHandle() caps.HandleId {
    var own = syscall.self();
    while (own.v1 == @intFromEnum(errors.Error.E_NOENT)) {
        pause();
        own = syscall.self();
    }
    if (testing.isHandleError(own.v1)) spin();
    return @truncate(own.v1 & 0xFFF);
}

fn handle(value: u64) ?caps.HandleId {
    if (testing.isHandleError(value) or value == 0) return null;
    return @truncate(value & 0xFFF);
}
fn ok(value: u64) bool {
    return value == @intFromEnum(errors.Error.OK);
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
fn fault() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => unreachable,
    }
    spin();
}
fn typeOf(comptime kind: Kind) caps.HandleType {
    return switch (kind) {
        .page_frame => .page_frame,
        .device_region => .device_region,
        .port => .port,
        .virtual_machine => .virtual_machine,
        .ipc => .process,
    };
}
fn targetCaps(comptime kind: Kind, comptime keep: bool) u16 {
    return switch (kind) {
        .page_frame => (caps.PfCap{ .r = true, .w = true, .restart_policy = keep }).toU16(),
        .device_region => (caps.DeviceCap{ .dma = true, .restart_policy = keep }).toU16(),
        .port => (caps.PortCap{ .bind = true, .recv = true, .restart_policy = keep }).toU16(),
        .virtual_machine => (caps.VmCap{ .restart_policy = keep }).toU16(),
        .ipc => (caps.IpcCap{ .copy = true, .crec = true, .restart_policy = keep }).toU16(),
    };
}
fn count(cap_table_base: u64, kind: caps.HandleType, requested: u16) u32 {
    var n: u32 = 0;
    var slot: u32 = if (kind == .process) 2 else 3;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(cap_table_base, slot);
        if (cap.word0 != 0 and cap.handleType() == kind and cap.caps() == requested) n += 1;
    }
    return n;
}
fn report(code: u64) void {
    const sent = syscall.issueRawCaptureWord(0, .{ .v1 = ownHandle(), .v2 = PORT, .v3 = code });
    if (sent.regs.v1 == @intFromEnum(errors.Error.E_ABANDONED)) {
        _ = syscall.restrict(caps.SLOT_SELF, 0);
        _ = syscall.delete(caps.SLOT_SELF);
    }
    if (!ok(sent.regs.v1)) spin();
}
fn stage(comptime kind: Kind, comptime keep: bool) u64 {
    if (kind == .device_region or kind == .ipc) return 0; // present at child creation
    if (kind == .page_frame) {
        _ = handle(syscall.createPageFrame(targetCaps(kind, keep), 0, 1).v1) orelse return 11;
    } else if (kind == .port) {
        _ = handle(syscall.createPort(targetCaps(kind, keep)).v1) orelse return 12;
    } else if (kind == .virtual_machine) {
        // A fresh page frame is zero-filled: an empty VmPolicy is valid.
        const policy = handle(syscall.createPageFrame((caps.PfCap{ .r = true, .w = true }).toU16(), 0, 1).v1) orelse return 13;
        _ = handle(syscall.createVirtualMachine(targetCaps(kind, keep), policy).v1) orelse return 14;
    }
    return 0;
}
fn child(comptime kind: Kind, comptime keep: bool, base: u64) noreturn {
    if (count(base, .port, MARKER) != 0) {
        const observed = count(base, typeOf(kind), targetCaps(kind, keep));
        report(if ((observed != 0) == keep) 100 else 31);
        spin();
    }
    const setup = stage(kind, keep);
    if (setup != 0) report(setup);
    if (count(base, typeOf(kind), targetCaps(kind, keep)) != 1) report(15);
    _ = handle(syscall.createPort(MARKER).v1) orelse report(16);
    report(1);
    fault();
}

fn startChild(comptime kind: Kind, comptime keep: bool, base: u64) noreturn {
    worker_base = base;
    const entry = struct {
        fn run() callconv(.c) noreturn {
            child(kind, keep, worker_base);
        }
    }.run;
    const worker_caps = caps.ThreadCap{ .susp = true, .read = true, .restart_policy = 1 };
    const worker = handle(syscall.createThread(worker_caps.toU16(), @intFromPtr(&entry), 1, 0, 0).v1) orelse spin();
    _ = syscall.yieldThread(worker);
    const hold_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    const hold = handle(syscall.createPort(hold_caps.toU16()).v1) orelse spin();
    _ = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, hold, &.{});
    spin();
}
fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}
pub fn run(comptime kind: Kind, comptime keep: bool, base: u64) void {
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (@as(u8, @truncate(self.field0 >> 24)) == (if (kind == .ipc) @as(u8, if (keep) 0x26 else 0x06) else CHILD_CRIPC)) startChild(kind, keep, base);
    const port_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true, .restart_policy = true };
    const port = handle(syscall.createPort(port_caps.toU16()).v1) orelse return fail(1);
    var passed: [5]u64 = undefined;
    passed[0] = (caps.PassedHandle{ .id = port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16(), .move = false }).toU64();
    passed[1] = (caps.PassedHandle{ .id = ELF, .caps = (caps.PfCap{ .r = true }).toU16(), .move = false }).toU64();
    passed[2] = (caps.PassedHandle{ .id = LIBZ, .caps = (caps.PfCap{ .r = true, .x = true }).toU16(), .move = false }).toU64();
    var len: usize = 3;
    if (kind == .device_region) {
        var source: caps.HandleId = 0;
        {
            var slot: u32 = DEVICE;
            while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
                const cap = caps.readCap(base, slot);
                if (cap.word0 != 0 and cap.handleType() == .device_region and
                    (cap.caps() & (caps.DeviceCap{ .dma = true }).toU16()) != 0)
                {
                    source = @intCast(slot);
                    break;
                }
            }
            if (source == 0) return fail(2);
        }
        passed[len] = (caps.PassedHandle{ .id = source, .caps = targetCaps(kind, keep), .move = false }).toU64();
        len += 1;
    }
    const inner: u64 = @as(u64, 0xFF) | (@as(u64, 0x01FF) << 8) |
        (@as(u64, if (kind == .ipc) @as(u8, if (keep) 0x26 else 0x06) else CHILD_CRIPC) << 24) | (@as(u64, 0x1F) << 32) |
        (@as(u64, 1) << 40) | (@as(u64, 0x5C) << 48);
    const proc = syscall.createProcess((caps.SelfCap{ .crec = true, .crvr = true, .crpf = true, .crvm = true, .crpt = true, .restart = true, .pri = 3 }).toU16(), inner, 0x0000_003F_01FE_FFFF, ELF, 0, passed[0..len]);
    if (handle(proc.v1) == null) return fail(3);
    if (!ok(syscall.restrict(port, (caps.PortCap{ .recv = true }).toU16()).v1)) return fail(4);
    const first = syscall.recv(port, TIMEOUT_NS);
    if (!ok(first.regs.v1)) return fail(5);
    const reply1: caps.HandleId = @truncate((first.word >> 32) & 0xFFF);
    if (reply1 == 0) return fail(6);
    if (first.regs.v3 != 1) return fail(first.regs.v3);
    if (!ok(syscall.reply(reply1).v1)) return fail(7);
    const second = syscall.recv(port, TIMEOUT_NS);
    if (!ok(second.regs.v1)) return fail(8); // E_CLOSED proves teardown, not restart
    const reply2: caps.HandleId = @truncate((second.word >> 32) & 0xFFF);
    if (reply2 == 0) return fail(9);
    const result = second.regs.v3;
    _ = syscall.delete(reply2);
    if (result != 100) return fail(result);
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.pass();
}
