// Spec §[suspend] test 12: a valid target handle's priority and affinity
// snapshots are refreshed on both error and success paths.
//
// A suspend attachment copies the target thread handle into this same
// process. Mutating the thread through the copy leaves the original slot
// stale. The subsequent suspend must bring that original slot up to date.
// This distinguishes a real refresh from merely preserving an already
// synchronized snapshot.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

fn worker() callconv(.c) noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"),
            .aarch64 => asm volatile ("yield"),
            else => @compileError("unsupported arch"),
        }
    }
}

// PairEntry for N=1 occupies vreg 127. Both instruction sequences mirror
// handle_attachments_08 and the kernel's firstStackVreg layout.
fn suspendWithCopyX64(word: u64, target: u64, port: u64, pair: u64) u64 {
    var result: u64 = undefined;
    asm volatile (
        \\ subq $912, %%rsp
        \\ movq %%rdx, 904(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $920, %%rsp
        : [result] "={rax}" (result),
        : [word] "{rcx}" (word),
          [target] "{rax}" (target),
          [port] "{rbx}" (port),
          [pair] "{rdx}" (pair),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
    return result;
}

fn suspendWithCopyArm(word: u64, target: u64, port: u64, pair: u64) u64 {
    var result: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #784
        \\ str %[pair], [sp, #768]
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [result] "={x0}" (result),
        : [word] "r" (word),
          [target] "{x0}" (target),
          [port] "{x1}" (port),
          [pair] "r" (pair),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return result;
}

fn checkSnapshot(base: u64, slot: u12, priority: u64, affinity: u64) bool {
    const cap = caps.readCap(base, slot);
    return cap.handleType() == .thread and cap.field0 == priority and cap.field1 == affinity;
}

pub fn main(cap_table_base: u64) void {
    // Keep the initial suspend on this caller's core. After that first
    // suspend, the target stays parked on the port while its alias
    // changes priority and affinity, so it cannot starve the caller.
    const own_core = testing.currentCoreId();
    const pinned_affinity: u64 = @as(u64, 1) << @truncate(own_core);
    const sibling_bit: u64 = if (own_core == 0) 2 else 1;
    const widened_affinity = pinned_affinity | sibling_bit;
    if (syscall.affinity(caps.SLOT_INITIAL_THREAD, pinned_affinity).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(19);
    _ = syscall.yieldThread(0);
    if (testing.currentCoreId() != own_core) return testing.fail(20);

    const port_caps = caps.PortCap{ .bind = true, .recv = true, .xfer = true, .@"suspend" = true };
    const created_port = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(created_port.v1)) return testing.fail(1);
    const port: u12 = @truncate(created_port.v1 & 0xFFF);

    const thread_caps = caps.ThreadCap{ .copy = true, .susp = true, .spri = true, .saff = true };
    const created_thread = syscall.createThread(@as(u64, thread_caps.toU16()), @intFromPtr(&worker), 1, 0, pinned_affinity);
    if (testing.isHandleError(created_thread.v1)) return testing.fail(2);
    const source: u12 = @truncate(created_thread.v1 & 0xFFF);
    if (!checkSnapshot(cap_table_base, source, 0, pinned_affinity)) return testing.fail(3);

    const pair = caps.PairEntry{ .id = source, .caps = thread_caps.toU16(), .move = false };
    const word = syscall.buildWord(.@"suspend", syscall.extraCount(1));
    const suspended = switch (builtin.cpu.arch) {
        .x86_64 => suspendWithCopyX64(word, source, port, pair.toU64()),
        .aarch64 => suspendWithCopyArm(word, source, port, pair.toU64()),
        else => @compileError("unsupported arch"),
    };
    if (suspended != @intFromEnum(errors.Error.OK)) return testing.fail(4);

    const received = syscall.recv(port, 0);
    if (((received.word >> 12) & 0xFF) != 1 or ((received.word >> 44) & 0x1F) != 4) return testing.fail(5);
    const alias: u12 = @truncate((received.word >> 20) & 0xFFF);
    const reply_id: u12 = @truncate((received.word >> 32) & 0xFFF);
    if (alias == source or caps.readCap(cap_table_base, alias).handleType() != .thread) return testing.fail(6);

    // Change both authoritative fields through the alias. The source slot
    // must remain stale until suspend takes it as [1].
    if (syscall.priority(alias, 2).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(8);
    if (syscall.affinity(alias, widened_affinity).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(9);
    if (!checkSnapshot(cap_table_base, source, 0, pinned_affinity)) return testing.fail(10);
    if (!checkSnapshot(cap_table_base, alias, 2, widened_affinity)) return testing.fail(11);

    // Valid [1], invalid [2]. No later call may refresh source before the
    // direct read below.
    const empty_port: u12 = caps.HANDLE_TABLE_MAX - 1;
    if (syscall.suspendThread(source, empty_port, &.{}).v1 != @intFromEnum(errors.Error.E_BADCAP)) return testing.fail(12);
    if (!checkSnapshot(cap_table_base, source, 2, widened_affinity)) return testing.fail(13);

    // Lower the parked target's priority and repin it before reply, so
    // its resumed spin loop cannot outrank this test thread. The source
    // slot still holds the snapshot from the error leg; a successful
    // suspend must refresh both fields again.
    if (syscall.priority(alias, 0).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(14);
    if (syscall.affinity(alias, pinned_affinity).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(15);
    if (!checkSnapshot(cap_table_base, source, 2, widened_affinity)) return testing.fail(16);
    if (syscall.reply(reply_id).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(17);
    if (syscall.suspendThread(source, port, &.{}).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(18);
    if (!checkSnapshot(cap_table_base, source, 0, pinned_affinity)) return testing.fail(21);

    testing.pass();
}
