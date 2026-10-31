// Parent-observed VMAR restart probes for §[restart_semantics] and §[snapshot].
// The child stages a VMAR at a fixed static-zone address, posts READY, then
// faults. An explicit restart_at_entry worker re-enters after the initial
// thread (whose slot-1 restart policy is necessarily 0) is killed.
// A kept marker port distinguishes re-entry without relying on ELF globals.
// The parent owns the only recv endpoint. Expected-termination cases also
// run a stable snapshot-copy control through the same restart path.
const builtin = @import("builtin");
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub const Mode = enum {
    free,
    decommit,
    preserve,
    snapshot_copy,
    snapshot_replace,
    snapshot_missing,
    snapshot_pf_write,
    snapshot_pf_shared,
    snapshot_demand_write,
    snapshot_multi_page_pf,
    snapshot_mixed_page_sizes,
};
const CHILD_CRIPC: u8 = 0x07;
const CONTROL_CRIPC: u8 = 0x06;
const PORT: caps.HandleId = caps.SLOT_FIRST_PASSED;
const ELF: caps.HandleId = PORT + 1;
const LIBZ: caps.HandleId = PORT + 2;
const BASE: u64 = 0x0000_1000_0001_0000;
const SRC_A: u64 = BASE + 0x1000;
const SRC_B: u64 = BASE + 0x2000;
const DST: u64 = BASE + 0x3000;
const A: u64 = 0x7134_a5c2_690d_8be1;
const B: u64 = 0xb83e_4f16_c927_50ad;
const OLD: u64 = 0xe291_70ab_5c43_d68f;
const HUGE_SRC: u64 = 0x0000_1000_0020_0000;
const HUGE_DST: u64 = HUGE_SRC + 0x200000;
const TIMEOUT_NS: u64 = 10_000_000_000;
const MARKER_CAPS: u16 = (caps.PortCap{ .recv = true, .restart_policy = true }).toU16();
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

fn pause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => @compileError("unsupported restart test architecture"),
    }
}
fn spin() noreturn {
    while (true) pause();
}
fn handle(result: u64) ?caps.HandleId {
    if (testing.isHandleError(result) or result == 0) return null;
    return @truncate(result & 0xFFF);
}
fn ok(result: u64) bool {
    return result == @intFromEnum(errors.Error.OK);
}
fn word(addr: u64) *volatile u64 {
    return @ptrFromInt(addr);
}
fn vmar(policy: u2, addr: u64, writable: bool) ?caps.HandleId {
    return vmarPages(policy, addr, writable, 1);
}
fn vmarPages(policy: u2, addr: u64, writable: bool, pages: u64) ?caps.HandleId {
    const vc = caps.VmarCap{ .r = true, .w = true, .restart_policy = policy };
    return handle(syscall.createVmar(vc.toU16(), if (writable) 3 else 1, pages, addr, 0).v1);
}
fn hasMap(cap_table_base: u64, id: caps.HandleId, expected: u64) bool {
    if (!ok(syscall.sync(id).v1)) return false;
    return ((caps.readCap(cap_table_base, id).field1 >> 39) & 3) == expected;
}
fn find(cap_table_base: u64, kind: caps.HandleType, addr: u64) ?caps.HandleId {
    var slot: u32 = 3;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(cap_table_base, slot);
        if (cap.word0 != 0 and cap.handleType() == kind and cap.field0 == addr)
            return @intCast(slot);
    }
    return null;
}
fn hasMarker(cap_table_base: u64) bool {
    var slot: u32 = 3;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(cap_table_base, slot);
        if (cap.word0 != 0 and cap.handleType() == .port and cap.caps() == MARKER_CAPS)
            return true;
    }
    return false;
}
fn reportChild(code: u64) void {
    const sent = syscall.issueRawCaptureWord(0, .{ .v1 = ownHandle(), .v2 = PORT, .v3 = code });
    if (sent.regs.v1 == @intFromEnum(errors.Error.E_ABANDONED)) {
        _ = syscall.restrict(caps.SLOT_SELF, 0);
        _ = syscall.delete(caps.SLOT_SELF);
        spin();
    }
    if (!ok(sent.regs.v1)) spin();
}
fn fault() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => unreachable,
    }
    spin();
}
fn stage(comptime mode: Mode, cap_table_base: u64) u64 {
    if (mode == .snapshot_mixed_page_sizes) {
        // Leave an empty 4 KiB leaf table under the same VA. A later 2 MiB
        // block must replace that table after its demand page is removed.
        const small = vmar(0, HUGE_SRC, true) orelse return 75;
        word(HUGE_SRC).* = OLD;
        if (!ok(syscall.delete(small).v1)) return 76;
        const vc = caps.VmarCap{ .r = true, .w = true, .max_sz = 1, .restart_policy = 2 };
        const src = handle(syscall.createVmar(vc.toU16(), 3 | (1 << 3), 1, HUGE_SRC, 0).v1) orelse return 61;
        const pf_caps = caps.PfCap{ .r = true, .w = true, .max_sz = 1, .restart_policy = true };
        const pf = handle(syscall.createPageFrame(pf_caps.toU16(), 1, 1).v1) orelse return 62;
        if (!ok(syscall.mapPf(src, &.{ 0, pf }).v1)) return 63;
        word(HUGE_SRC).* = A;
        word(HUGE_SRC + 0x1000).* = B;
        word(HUGE_SRC + 0x1ff000).* = OLD;
        if (!ok(syscall.remap(src, 1).v1)) return 64;
        if (word(HUGE_SRC).* != A or word(HUGE_SRC + 0x1000).* != B or word(HUGE_SRC + 0x1ff000).* != OLD) return 65;
        if (!ok(syscall.unmap(src, &.{pf}).v1)) return 66;
        if (!ok(syscall.mapPf(src, &.{ 0, pf }).v1)) return 67;
        if (!ok(syscall.remap(src, 1).v1)) return 68;
        if (word(HUGE_SRC).* != A or word(HUGE_SRC + 0x1000).* != B or word(HUGE_SRC + 0x1ff000).* != OLD) return 69;
        const target = vmarPages(3, HUGE_DST, true, 512) orelse return 70;
        word(HUGE_DST).* = 0;
        word(HUGE_DST + 0x1000).* = 0;
        word(HUGE_DST + 0x1ff000).* = 0;
        if (!ok(syscall.snapshot(target, src).v1)) return 71;
        return 0;
    }
    if (mode == .snapshot_multi_page_pf) {
        const src = vmarPages(2, SRC_A, true, 2) orelse return 51;
        const pf = handle(syscall.createPageFrame((caps.PfCap{ .r = true, .w = true, .restart_policy = true }).toU16(), 0, 2).v1) orelse return 52;
        if (!ok(syscall.mapPf(src, &.{ 0, pf }).v1)) return 53;
        word(SRC_A).* = A;
        word(SRC_A + 0x1000).* = B;
        if (word(SRC_A).* != A or word(SRC_A + 0x1000).* != B) return 54;
        if (!ok(syscall.remap(src, 1).v1)) return 55;
        const target = vmarPages(3, DST, true, 2) orelse return 56;
        word(DST).* = OLD;
        word(DST + 0x1000).* = OLD;
        if (!ok(syscall.snapshot(target, src).v1)) return 57;
        return 0;
    }
    if (mode == .free or mode == .decommit or mode == .preserve) {
        const policy: u2 = switch (mode) {
            .free => 0,
            .decommit => 1,
            .preserve => 2,
            else => unreachable,
        };
        const region = vmar(policy, BASE, true) orelse return 11;
        word(BASE).* = A;
        if (word(BASE).* != A) return 12;
        if (!hasMap(cap_table_base, region, 3)) return 33;
        return 0;
    }
    const src = vmar(2, SRC_A, true) orelse return 13;
    word(SRC_A).* = A;
    if (word(SRC_A).* != A) return 14;
    if (!hasMap(cap_table_base, src, 3)) return 34;
    const target = vmar(3, DST, true) orelse return 15;
    word(DST).* = OLD;
    if (word(DST).* != OLD) return 16;
    if (!hasMap(cap_table_base, target, 3)) return 35;
    if (mode == .snapshot_pf_write or mode == .snapshot_pf_shared) {
        // Demand pages cannot be map_pf'd. Recreate the source as a PF map.
        if (!ok(syscall.delete(src).v1)) return 17;
        const pf_src = vmar(2, SRC_A, mode == .snapshot_pf_write) orelse return 18;
        const pf = handle(syscall.createPageFrame((caps.PfCap{ .r = true, .w = true, .restart_policy = true }).toU16(), 0, 1).v1) orelse return 19;
        if (!ok(syscall.mapPf(pf_src, &.{ 0, pf }).v1)) return 20;
        if (!hasMap(cap_table_base, pf_src, 1)) return 36;
        if (mode == .snapshot_pf_shared) {
            const second = vmar(2, SRC_B, false) orelse return 21;
            if (!ok(syscall.mapPf(second, &.{ 0, pf }).v1)) return 22;
            const synced = syscall.sync(pf);
            if (!ok(synced.v1)) return 23;
            if ((caps.readCap(cap_table_base, pf).field1 & 0xFFFF_FFFF) < 2) return 37;
        }
        if (!ok(syscall.snapshot(target, pf_src).v1)) return 24;
        return 0;
    }
    if (mode != .snapshot_demand_write and !ok(syscall.remap(src, 1).v1)) return 25;
    if (mode == .snapshot_replace) {
        const b = vmar(2, SRC_B, true) orelse return 26;
        word(SRC_B).* = B;
        if (!ok(syscall.remap(b, 1).v1)) return 27;
        if (!ok(syscall.snapshot(target, src).v1)) return 28;
        if (!ok(syscall.snapshot(target, b).v1)) return 29;
    } else {
        if (!ok(syscall.snapshot(target, src).v1)) return 30;
    }
    if (mode == .snapshot_missing and !ok(syscall.delete(src).v1)) return 31;
    return 0;
}
fn verify(comptime mode: Mode, cap_table_base: u64) u64 {
    if (mode == .free) {
        if (find(cap_table_base, .virtual_memory_address_region, BASE) != null) return 41;
        _ = vmar(0, BASE, false) orelse return 42; // reservation was freed
        return 0;
    }
    const addr = if (mode == .decommit or mode == .preserve) BASE else if (mode == .snapshot_mixed_page_sizes) HUGE_DST else DST;
    const id = find(cap_table_base, .virtual_memory_address_region, addr) orelse return 43;
    if (!ok(syscall.sync(id).v1)) return 44;
    const cap = caps.readCap(cap_table_base, id);
    if (mode == .decommit) {
        if ((cap.field1 >> 39) & 3 != 0) return 45;
        if (word(BASE).* != 0) return 46;
    } else {
        if (mode == .snapshot_multi_page_pf) {
            if (word(DST).* != A) return 48;
            if (word(DST + 0x1000).* != B) return 49;
            return 0;
        }
        if (mode == .snapshot_mixed_page_sizes) {
            if (word(HUGE_DST).* != A) return 72;
            if (word(HUGE_DST + 0x1000).* != B) return 73;
            if (word(HUGE_DST + 0x1ff000).* != OLD) return 74;
            return 0;
        }
        const expected: u64 = if (mode == .snapshot_replace) B else A;
        if (word(addr).* != expected) return 47;
    }
    return 0;
}
fn child(comptime mode: Mode, cap_table_base: u64) noreturn {
    if (hasMarker(cap_table_base)) {
        reportChild(100 + verify(mode, cap_table_base));
        spin();
    }
    const setup = stage(mode, cap_table_base);
    if (setup != 0) {
        reportChild(setup);
        spin();
    }
    _ = handle(syscall.createPort(MARKER_CAPS).v1) orelse {
        reportChild(32);
        spin();
    };
    reportChild(1); // parent has observed all pre-restart state
    fault();
}

fn startChild(comptime mode: Mode, base: u64) noreturn {
    worker_base = base;
    const entry = struct {
        fn run() callconv(.c) noreturn {
            child(mode, worker_base);
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
const Outcome = struct { code: u64, closed: bool };
fn observe(comptime control: bool) Outcome {
    const port_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true, .restart_policy = true };
    const created = syscall.createPort(port_caps.toU16());
    const port = handle(created.v1) orelse return .{ .code = 1, .closed = false };
    const passed = [_]u64{
        (caps.PassedHandle{ .id = port, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true, .restart_policy = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = ELF, .caps = (caps.PfCap{ .r = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = LIBZ, .caps = (caps.PfCap{ .r = true, .x = true }).toU16(), .move = false }).toU64(),
    };
    const inner: u64 = @as(u64, 0xFF) | (@as(u64, 0x01FF) << 8) |
        (@as(u64, if (control) CONTROL_CRIPC else CHILD_CRIPC) << 24) | (@as(u64, 0x1F) << 32) |
        (@as(u64, 1) << 40) | (@as(u64, 0x5C) << 48);
    const proc = syscall.createProcess((caps.SelfCap{ .crec = true, .crvr = true, .crpf = true, .crpt = true, .restart = true, .pri = 3 }).toU16(), inner, 0x0000_003F_01FE_FFFF, ELF, 0, &passed);
    if (testing.isHandleError(proc.v1)) return .{ .code = 2, .closed = false };
    if (!ok(syscall.restrict(port, (caps.PortCap{ .recv = true }).toU16()).v1)) return .{ .code = 3, .closed = false };
    const first = syscall.recv(port, TIMEOUT_NS);
    if (!ok(first.regs.v1)) return .{ .code = 4, .closed = false };
    const first_reply: caps.HandleId = @truncate((first.word >> 32) & 0xFFF);
    if (first_reply == 0) return .{ .code = 5, .closed = false };
    if (first.regs.v3 != 1) {
        _ = syscall.delete(first_reply);
        return .{ .code = first.regs.v3, .closed = false };
    }
    if (!ok(syscall.reply(first_reply).v1)) return .{ .code = 6, .closed = false };
    const second = syscall.recv(port, TIMEOUT_NS);
    if (second.regs.v1 == @intFromEnum(errors.Error.E_CLOSED)) return .{ .code = 0, .closed = true };
    if (!ok(second.regs.v1)) return .{ .code = 7, .closed = false };
    const second_reply: caps.HandleId = @truncate((second.word >> 32) & 0xFFF);
    if (second_reply == 0) return .{ .code = 8, .closed = false };
    const result = second.regs.v3;
    _ = syscall.delete(second_reply);
    return .{ .code = result, .closed = false };
}
pub fn run(comptime mode: Mode, cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const my_cripc: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);
    if (my_cripc == CONTROL_CRIPC) startChild(.snapshot_copy, cap_table_base);
    if (my_cripc == CHILD_CRIPC)
        startChild(mode, cap_table_base);
    const terminate = mode == .snapshot_missing or mode == .snapshot_pf_write or
        mode == .snapshot_pf_shared or mode == .snapshot_demand_write;
    const result = observe(false);
    // code 0 means the child's sole bind cap closed; code 100 is its
    // successful post-restart report. Setup and verification errors have
    // separate nonzero codes.
    if (result.code != 0 and result.code != 100) return fail(result.code);
    if (terminate) {
        if (!result.closed) return fail(101);
        // Teardown is expected only once restart itself is demonstrated.
        // This control child has the same restart cap, entry policy, and
        // snapshot target, with a stable source instead of a bad one.
        const control = observe(true);
        if (control.closed or control.code != 100) return fail(1);
    } else {
        if (result.closed or result.code != 100) return fail(102);
    }
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.pass();
}
fn fail(id: u64) void {
    _ = syscall.restrict(caps.SLOT_SELF, 0);
    testing.fail(id);
}
