// Foreign terminate versus a policy-1 worker crossing process restart.
// The parent receives a copied thread handle as an attachment, so its
// terminate call is independent of the child's handle table and lifetime.
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
const TRIGGER: caps.HandleId = ENTRY + 3;
const TIMEOUT_NS: u64 = 10_000_000_000;
const Mode = enum { before, after, race };
var armed: bool = false;
var race_go: bool = false;
var race_target: caps.HandleId = 0;
var race_port: caps.HandleId = 0;
var race_result: u64 = 0;

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
fn workerEntry() callconv(.c) noreturn {
    // The first generation is suspended remotely before the initial
    // thread arms this flag. A policy-1 replacement enters here after
    // restart and sends the second parent-visible event.
    while (!@atomicLoad(bool, &armed, .acquire)) pause();
    _ = syscall.suspendThread(ownHandle(), ENTRY, &.{});
    spin();
}
fn raceTerminator() callconv(.c) noreturn {
    while (!@atomicLoad(bool, &race_go, .acquire)) pause();
    const result = syscall.terminate(race_target).v1;
    @atomicStore(u64, &race_result, result, .release);
    _ = syscall.suspendThread(ownHandle(), race_port, &.{});
    spin();
}

// libz's suspend wrapper intentionally has no high-vreg attachment path.
// Pair entry 127 sits at the ABI's final stack vreg on both architectures.
fn suspendAttached(word: u64, target: u64, port: u64, pair: u64) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => blk: {
            var ret: u64 = undefined;
            asm volatile (
                \\ subq $912, %%rsp
                \\ movq %%rdx, 904(%%rsp)
                \\ pushq %%rcx
                \\ syscall
                \\ addq $920, %%rsp
                : [ret] "={rax}" (ret),
                : [word] "{rcx}" (word),
                  [v1in] "{rax}" (target),
                  [v2in] "{rbx}" (port),
                  [pair] "{rdx}" (pair),
                : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
            break :blk ret;
        },
        .aarch64 => blk: {
            var ret: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[pair], [sp, #768]
                \\ str %[word], [sp]
                \\ svc #0
                \\ add sp, sp, #784
                : [ret] "={x0}" (ret),
                : [word] "r" (word),
                  [v1in] "{x0}" (target),
                  [v2in] "{x1}" (port),
                  [pair] "r" (pair),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
            break :blk ret;
        },
        else => unreachable,
    };
}

fn child(base: u64) noreturn {
    _ = base;
    const worker_caps = caps.ThreadCap{ .copy = true, .term = true, .susp = true, .restart_policy = 1 };
    const worker = handle(syscall.createThread(worker_caps.toU16(), @intFromPtr(&workerEntry), 1, 0, 0).v1) orelse spin();
    const attached = caps.PairEntry{ .id = worker, .caps = (caps.ThreadCap{ .term = true }).toU16(), .move = false };
    const word = syscall.buildWord(.@"suspend", syscall.extraCount(1));
    if (suspendAttached(word, worker, ENTRY, attached.toU64()) != @intFromEnum(errors.Error.OK)) spin();
    @atomicStore(bool, &armed, true, .release);
    if (syscall.suspendThread(caps.SLOT_INITIAL_THREAD, TRIGGER, &.{}).v1 != @intFromEnum(errors.Error.OK)) spin();
    fault();
}

fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}
fn makePort(xfer: bool, keep: bool) ?caps.HandleId {
    const cap = caps.PortCap{ .copy = true, .bind = true, .recv = true, .xfer = xfer, .@"suspend" = true, .restart_policy = keep };
    return handle(syscall.createPort(cap.toU16()).v1);
}
pub fn run(comptime terminate_first: bool, base: u64) void {
    runMode(if (terminate_first) .before else .after, base);
}
pub fn runRace(base: u64) void {
    runMode(.race, base);
}
fn runMode(comptime mode: Mode, base: u64) void {
    var race_winner: u64 = 0;
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (@as(u8, @truncate(self.field0 >> 24)) == CHILD_CRIPC) child(base);

    const entry_port = makePort(true, true) orelse return fail(1);
    const trigger_port = makePort(false, false) orelse return fail(2);
    const passed = [_]u64{
        (caps.PassedHandle{ .id = entry_port, .caps = (caps.PortCap{ .bind = true, .xfer = true, .@"suspend" = true, .restart_policy = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = ELF, .caps = (caps.PfCap{ .r = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = LIBZ, .caps = (caps.PfCap{ .r = true, .x = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = trigger_port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true }).toU16(), .move = false }).toU64(),
    };
    const inner: u64 = @as(u64, 0xFF) | (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) | (@as(u64, 0x1F) << 32) |
        (@as(u64, 1) << 40) | (@as(u64, 0x5C) << 48);
    const created = syscall.createProcess(
        (caps.SelfCap{ .crec = true, .crvr = true, .restart = true, .pri = 3 }).toU16(),
        inner,
        0x0000_003F_01FE_FFFF,
        ELF,
        0,
        &passed,
    );
    const process = handle(created.v1) orelse return fail(30 + created.v1);
    if (syscall.restrict(entry_port, (caps.PortCap{ .recv = true }).toU16()).v1 != @intFromEnum(errors.Error.OK)) return fail(4);
    if (syscall.restrict(trigger_port, (caps.PortCap{ .recv = true }).toU16()).v1 != @intFromEnum(errors.Error.OK)) return fail(5);

    const first = syscall.recv(entry_port, TIMEOUT_NS);
    if (first.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(6);
    if (((first.word >> 12) & 0xFF) != 1) return fail(7);
    const foreign: caps.HandleId = @truncate((first.word >> 20) & 0xFFF);
    if (foreign == 0 or caps.readCap(base, foreign).handleType() != .thread) return fail(8);
    const first_reply: caps.HandleId = @truncate((first.word >> 32) & 0xFFF);
    if (first_reply == 0) return fail(20);
    const trigger = syscall.recv(trigger_port, TIMEOUT_NS);
    if (trigger.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(9);
    const trigger_reply: caps.HandleId = @truncate((trigger.word >> 32) & 0xFFF);
    if (trigger_reply == 0) return fail(10);

    if (mode == .before) {
        if (syscall.terminate(foreign).v1 != @intFromEnum(errors.Error.OK)) return fail(11);
        if (syscall.reply(first_reply).v1 != @intFromEnum(errors.Error.E_ABANDONED)) return fail(14);
        if (syscall.reply(trigger_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(12);
        const closed = syscall.recv(entry_port, TIMEOUT_NS);
        if (closed.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) return fail(13);
    } else if (mode == .after) {
        if (syscall.reply(trigger_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(15);
        const again = syscall.recv(entry_port, TIMEOUT_NS);
        if (again.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(16);
        if (syscall.reply(first_reply).v1 != @intFromEnum(errors.Error.E_TERM)) return fail(18);
        if (syscall.terminate(foreign).v1 != @intFromEnum(errors.Error.E_TERM)) return fail(17);
        const again_reply: caps.HandleId = @truncate((again.word >> 32) & 0xFFF);
        if (again_reply == 0 or syscall.delete(again_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(19);
    } else {
        // The helper and child fault are released by the same parent. Its
        // completion event witnesses the foreign terminate result; the
        // retained child bind port then witnesses the corresponding process
        // outcome without treating a timeout as proof.
        const completion = makePort(false, false) orelse return fail(21);
        race_target = foreign;
        race_port = completion;
        race_result = @intFromEnum(errors.Error.E_NOENT);
        @atomicStore(bool, &race_go, false, .release);
        const helper_caps = caps.ThreadCap{ .susp = true };
        _ = handle(syscall.createThread(helper_caps.toU16(), @intFromPtr(&raceTerminator), 1, 0, 0).v1) orelse return fail(22);
        @atomicStore(bool, &race_go, true, .release);
        if (syscall.reply(trigger_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(23);
        const done = syscall.recv(completion, TIMEOUT_NS);
        if (done.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(24);
        const done_reply: caps.HandleId = @truncate((done.word >> 32) & 0xFFF);
        if (done_reply == 0 or syscall.reply(done_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(25);
        const result = @atomicLoad(u64, &race_result, .acquire);
        if (result == @intFromEnum(errors.Error.OK)) {
            race_winner = 1;
            const closed = syscall.recv(entry_port, TIMEOUT_NS);
            if (closed.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) return fail(26);
            if (syscall.reply(first_reply).v1 != @intFromEnum(errors.Error.E_ABANDONED)) return fail(27);
        } else if (result == @intFromEnum(errors.Error.E_TERM)) {
            race_winner = 2;
            const again = syscall.recv(entry_port, TIMEOUT_NS);
            if (again.regs.v1 != @intFromEnum(errors.Error.OK)) return fail(28);
            if (syscall.reply(first_reply).v1 != @intFromEnum(errors.Error.E_TERM)) return fail(29);
            if (syscall.sync(process).v1 != @intFromEnum(errors.Error.OK)) return fail(32);
            const again_reply: caps.HandleId = @truncate((again.word >> 32) & 0xFFF);
            if (again_reply == 0 or syscall.delete(again_reply).v1 != @intFromEnum(errors.Error.OK)) return fail(30);
        } else {
            return fail(31 + result);
        }
    }
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    if (mode == .race) {
        testing.report(testing.PASS_CODE, race_winner);
    } else {
        testing.pass();
    }
}
