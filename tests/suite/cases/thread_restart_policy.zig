// Parent-observed §[restart_semantics] thread-policy probes. The parent owns
// every recv endpoint and keeps a reply to the target's pre-restart suspend.
// A separate restart_at_entry witness proves the child really restarted before
// asserting kill or persist; setup errors have their own failure IDs.
const builtin = @import("builtin");
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub const Policy = enum(u2) { kill = 0, restart_at_entry = 1, persist = 2 };
const CHILD_CRIPC: u8 = 0x07;
const ENTRY: caps.HandleId = caps.SLOT_FIRST_PASSED;
// The ELF loader requires the ELF and libz frames in slots 5 and 6.
const SELF_ELF: caps.HandleId = ENTRY + 1;
const LIBZ_PF: caps.HandleId = ENTRY + 2;
const CONTINUE: caps.HandleId = ENTRY + 3;
const WITNESS: caps.HandleId = ENTRY + 4;
const TRIGGER: caps.HandleId = ENTRY + 5;
const TIMEOUT_NS: u64 = 10_000_000_000;
const STACK_MARK: u64 = 0x68a3_92c4_f17b_5e0d;

fn pause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => @compileError("unsupported architecture"),
    }
}
fn spinForever() noreturn {
    while (true) pause();
}
fn die() noreturn {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    _ = syscall.delete(caps.SLOT_SELF);
    spinForever();
}
fn ownHandle() caps.HandleId {
    var own = syscall.self();
    while (own.v1 == @intFromEnum(errors.Error.E_NOENT)) {
        pause();
        own = syscall.self();
    }
    if (testing.isHandleError(own.v1)) spinForever();
    return @truncate(own.v1 & 0xFFF);
}
fn targetEntry() callconv(.c) noreturn {
    // Volatile local forces a real stack access after the blocked syscall.
    // A persisted thread must keep this frame and its stack page intact.
    var stack_mark: u64 = STACK_MARK;
    const stack_ptr: *volatile u64 = &stack_mark;
    const first = syscall.suspendThread(ownHandle(), ENTRY, &.{});
    if (first.v1 == @intFromEnum(errors.Error.E_ABANDONED)) die();
    if (first.v1 != @intFromEnum(errors.Error.OK)) spinForever();
    if (stack_ptr.* != STACK_MARK) spinForever();
    const next = syscall.suspendThread(ownHandle(), CONTINUE, &.{});
    if (next.v1 == @intFromEnum(errors.Error.E_ABANDONED)) die();
    spinForever();
}
fn witnessEntry() callconv(.c) noreturn {
    const event = syscall.suspendThread(ownHandle(), WITNESS, &.{});
    if (event.v1 == @intFromEnum(errors.Error.E_ABANDONED)) die();
    spinForever();
}
fn childMain(comptime policy: Policy) void {
    const target = syscall.createThread(
        @as(u64, (caps.ThreadCap{ .susp = true, .restart_policy = @intFromEnum(policy) }).toU16()),
        @intFromPtr(&targetEntry),
        1,
        0,
        0,
    );
    if (testing.isHandleError(target.v1)) spinForever();
    if (policy != .restart_at_entry) {
        const witness = syscall.createThread(
            @as(u64, (caps.ThreadCap{ .susp = true, .restart_policy = 1 }).toU16()),
            @intFromPtr(&witnessEntry),
            1,
            0,
            0,
        );
        if (testing.isHandleError(witness.v1)) spinForever();
    }
    const go = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, TRIGGER, &.{});
    if (go.v1 != @intFromEnum(errors.Error.OK)) spinForever();
    // The target is already blocked and observed by the parent.
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => unreachable,
    }
    spinForever();
}
fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}
fn makePort() ?caps.HandleId {
    const result = syscall.createPort(@as(u64, (caps.PortCap{
        .copy = true,
        .bind = true,
        .recv = true,
        .@"suspend" = true,
        .restart_policy = true,
    }).toU16()));
    if (testing.isHandleError(result.v1)) return null;
    return @truncate(result.v1 & 0xFFF);
}
fn take(port: caps.HandleId) ?caps.HandleId {
    const event = syscall.recv(port, TIMEOUT_NS);
    if (event.regs.v1 != @intFromEnum(errors.Error.OK)) return null;
    const reply: caps.HandleId = @truncate((event.word >> 32) & 0xFFF);
    return if (reply == 0) null else reply;
}
pub fn run(comptime policy: Policy, cap_table_base: u64) void {
    runImpl(policy, false, cap_table_base);
}

pub fn runReplyRace(cap_table_base: u64) void {
    runImpl(.restart_at_entry, true, cap_table_base);
}

fn runImpl(comptime policy: Policy, comptime race_reply: bool, cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const my_cripc: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);
    if (my_cripc == CHILD_CRIPC) return childMain(policy);

    const entry_port = makePort() orelse return fail(1);
    const continue_port = makePort() orelse return fail(2);
    const witness_port = makePort() orelse return fail(3);
    const trigger_port = makePort() orelse return fail(4);
    const passed = [_]u64{
        (caps.PassedHandle{ .move = false, .id = entry_port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16() }).toU64(),
        (caps.PassedHandle{ .move = false, .id = SELF_ELF, .caps = (caps.PfCap{ .r = true }).toU16() }).toU64(),
        (caps.PassedHandle{ .move = false, .id = LIBZ_PF, .caps = (caps.PfCap{ .r = true, .x = true }).toU16() }).toU64(),
        (caps.PassedHandle{ .move = false, .id = continue_port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16() }).toU64(),
        (caps.PassedHandle{ .move = false, .id = witness_port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16() }).toU64(),
        (caps.PassedHandle{ .move = false, .id = trigger_port, .caps = (caps.PortCap{ .@"suspend" = true }).toU16() }).toU64(),
    };
    const ceilings_inner: u64 = @as(u64, 0xFF) | (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) | (@as(u64, 0x1F) << 32) |
        (@as(u64, 1) << 40) | (@as(u64, 0x5C) << 48);
    const child = syscall.createProcess(
        @as(u64, (caps.SelfCap{ .crec = true, .crvr = true, .restart = true, .pri = 3 }).toU16()),
        ceilings_inner,
        0x0000_003F_01FE_FFFF,
        caps.SLOT_FIRST_PASSED + 1,
        0,
        &passed,
    );
    if (testing.isHandleError(child.v1)) return fail(5);
    // The parent's recv-only handles cannot keep bind alive after teardown.
    if (syscall.restrict(entry_port, (caps.PortCap{ .recv = true }).toU16()).v1 != @intFromEnum(errors.Error.OK)) return fail(6);
    if (syscall.restrict(continue_port, (caps.PortCap{ .recv = true }).toU16()).v1 != @intFromEnum(errors.Error.OK)) return fail(7);
    if (syscall.restrict(witness_port, (caps.PortCap{ .recv = true }).toU16()).v1 != @intFromEnum(errors.Error.OK)) return fail(8);
    const first = take(entry_port) orelse return fail(9);
    const witness_first: ?caps.HandleId = if (policy == .restart_at_entry) null else take(witness_port) orelse return fail(10);
    if (witness_first) |handle| {
        if (syscall.reply(handle).v1 != @intFromEnum(errors.Error.OK)) return fail(11);
    }
    const armed = take(trigger_port) orelse return fail(12);
    if (syscall.reply(armed).v1 != @intFromEnum(errors.Error.OK)) return fail(13);
    // Releasing the faulting initial thread and then the blocked worker
    // without an intervening rendezvous races restart against reply
    // delivery. Check the reply result only after observing the restart.
    const raced_code = if (race_reply) syscall.reply(first).v1 else 0;

    if (policy == .restart_at_entry) {
        // No reply to the original suspend: a second entry event proves
        // reset of the blocked frame to the original entry point.
        const again = take(entry_port) orelse return fail(14);
        if (race_reply and raced_code != @intFromEnum(errors.Error.OK) and
            raced_code != @intFromEnum(errors.Error.E_TERM)) return fail(23);
        if (syscall.delete(again).v1 != @intFromEnum(errors.Error.OK)) return fail(15);
        if (!race_reply) _ = syscall.delete(first);
    } else {
        const witnessed = take(witness_port) orelse return fail(14);
        if (policy == .kill) {
            // A still-blocked or persisted target yields OK. A killed
            // target yields E_TERM on its pre-restart reply handle.
            if (syscall.reply(first).v1 != @intFromEnum(errors.Error.E_TERM)) return fail(16);
            const absent = syscall.recv(entry_port, 5_000_000_000);
            if (absent.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) return fail(17);
        } else {
            // The old suspended frame and stack survived. Releasing that
            // exact pre-restart reply must reach CONTINUE, not ENTRY.
            if (syscall.reply(first).v1 != @intFromEnum(errors.Error.OK)) return fail(18);
            const continued = take(continue_port) orelse return fail(19);
            if (syscall.delete(continued).v1 != @intFromEnum(errors.Error.OK)) return fail(20);
            const absent = syscall.recv(entry_port, 5_000_000_000);
            // Deleting the continuation reply may make the worker drop
            // the process self-handle before this receive completes. A
            // closed port and a timeout both exclude re-entry at ENTRY.
            if (absent.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT) and
                absent.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) return fail(21);
        }
        if (syscall.delete(witnessed).v1 != @intFromEnum(errors.Error.OK)) return fail(22);
    }
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.pass();
}
