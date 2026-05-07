// Phase 4b — first Zag-target Zig binary that imports `std`.
//
// Goal: prove std.io / std.os.zag.write routes correctly through to
// the COM1 byte-write loop our zag_write_console export performs.
// This is the first time a Zag-target binary uses the patched
// std-on-Zag instead of inlining its own syscall asm everywhere.
//
// Cap-table layout from root_service:
//   [3] COM1 device_region (port_io 0x3F8/8)

const std = @import("std");

// ── Cap-table layout (mirrors libz/caps.zig) ────────────────────────
const Cap = extern struct { word0: u64, field0: u64, field1: u64 };
const HandleType = enum(u4) {
    capability_domain_self = 0,
    capability_domain = 1,
    execution_context = 2,
    page_frame = 3,
    virtual_memory_address_region = 4,
    device_region = 5,
    port = 6,
    reply = 7,
    virtual_machine = 8,
    timer = 9,
    _,
};
const SLOT_SELF: u12 = 0;
const SLOT_FIRST_PASSED: u32 = 3;
const HANDLE_TABLE_MAX: u32 = 4096;

const SYS_DELETE: u12 = 16;
const SYS_CREATE_VMAR: u12 = 32;
const SYS_MAP_MMIO: u12 = 34;

const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

const DevType = enum(u4) { mmio = 0, port_io = 1, _ };

fn capHandleType(c: Cap) HandleType {
    return @enumFromInt(@as(u4, @truncate((c.word0 >> 12) & 0xF)));
}

fn capDevType(c: Cap) DevType {
    return @enumFromInt(@as(u4, @truncate(c.field0 & 0xF)));
}

fn capDevPort(c: Cap) u16 {
    return @truncate((c.field0 >> 4) & 0xFFFF);
}

fn capDevPortCount(c: Cap) u16 {
    return @truncate((c.field0 >> 20) & 0xFFFF);
}

fn buildWord(num: u12, extra: u64) u64 {
    return (@as(u64, num) & 0xFFF) | (extra & ~@as(u64, 0xFFF));
}

const Regs = struct {
    v1: u64 = 0,
    v2: u64 = 0,
    v3: u64 = 0,
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
    v8: u64 = 0,
    v9: u64 = 0,
    v10: u64 = 0,
    v11: u64 = 0,
    v12: u64 = 0,
    v13: u64 = 0,
};

fn issueRaw(word: u64, in: Regs) Regs {
    var ov1: u64 = undefined;
    var ov2: u64 = undefined;
    var ov3: u64 = undefined;
    var ov5: u64 = undefined;
    var ov6: u64 = undefined;
    var ov7: u64 = undefined;
    var ov8: u64 = undefined;
    var ov9: u64 = undefined;
    var ov10: u64 = undefined;
    var ov11: u64 = undefined;
    var ov12: u64 = undefined;
    var ov13: u64 = undefined;
    var rbp_save: u64 = undefined;
    const iv4_mem: u64 = in.v4;
    var ov4_mem: u64 = undefined;
    asm volatile (
        \\ movq %%rbp, %[rbp_save]
        \\ movq %[iv4_mem], %%rbp
        \\ subq $16, %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ addq $16, %%rsp
        \\ movq %%rbp, %[ov4_mem]
        \\ movq %[rbp_save], %%rbp
        : [v1] "={rax}" (ov1),
          [v2] "={rbx}" (ov2),
          [v3] "={rdx}" (ov3),
          [v5] "={rsi}" (ov5),
          [v6] "={rdi}" (ov6),
          [v7] "={r8}" (ov7),
          [v8] "={r9}" (ov8),
          [v9] "={r10}" (ov9),
          [v10] "={r12}" (ov10),
          [v11] "={r13}" (ov11),
          [v12] "={r14}" (ov12),
          [v13] "={r15}" (ov13),
          [rbp_save] "+m" (rbp_save),
          [ov4_mem] "=m" (ov4_mem),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (in.v1),
          [iv2] "{rbx}" (in.v2),
          [iv3] "{rdx}" (in.v3),
          [iv4_mem] "m" (iv4_mem),
          [iv5] "{rsi}" (in.v5),
          [iv6] "{rdi}" (in.v6),
          [iv7] "{r8}" (in.v7),
          [iv8] "{r9}" (in.v8),
          [iv9] "{r10}" (in.v9),
          [iv10] "{r12}" (in.v10),
          [iv11] "{r13}" (in.v11),
          [iv12] "{r14}" (in.v12),
          [iv13] "{r15}" (in.v13),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return .{
        .v1 = ov1,
        .v2 = ov2,
        .v3 = ov3,
        .v4 = ov4_mem,
        .v5 = ov5,
        .v6 = ov6,
        .v7 = ov7,
        .v8 = ov8,
        .v9 = ov9,
        .v10 = ov10,
        .v11 = ov11,
        .v12 = ov12,
        .v13 = ov13,
    };
}

fn findCom1(cap_table_base: u64) ?u12 {
    var slot: u32 = SLOT_FIRST_PASSED;
    while (slot < HANDLE_TABLE_MAX) : (slot += 1) {
        const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
        const c = tbl[slot];
        if (capHandleType(c) != .device_region) continue;
        if (capDevType(c) != .port_io) continue;
        if (capDevPort(c) != COM1_BASE_PORT) continue;
        if (capDevPortCount(c) != COM1_PORT_COUNT) continue;
        return @truncate(slot);
    }
    return null;
}

var sink: ?[*]volatile u8 = null;

fn initSink(cap_table_base: u64) void {
    const com1 = findCom1(cap_table_base) orelse return;
    const vmar_caps: u64 = (1 << 2) | (1 << 3) | (1 << 5);
    const props: u64 = (1 << 5) | (0 << 3) | 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps,
        .v2 = props,
        .v3 = 1,
    });
    if (cv.v1 < 16) return;
    const vh: u12 = @truncate(cv.v1 & 0xFFF);
    const vbase = cv.v2;
    const mm = issueRaw(buildWord(SYS_MAP_MMIO, 0), .{ .v1 = vh, .v2 = com1 });
    if (mm.v1 != 0) return;
    sink = @ptrFromInt(vbase);
}

// ── Bridge functions std.os.zag declares as extern. The patched
//    stdlib calls these from posix.write/exit/etc. We define them
//    here in user code; the linker resolves at static-link time.

export fn zag_write_console(buf: [*]const u8, count: usize) callconv(.c) usize {
    const p = sink orelse return count;
    var i: usize = 0;
    while (i < count) : (i += 1) p[0] = buf[i];
    return count;
}

export fn zag_exit(status: u8) callconv(.c) noreturn {
    _ = status;
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
}

// Stubs for fs/mmap externs declared in std.os.zag.zig — never called
// by this Phase-4b smoke test but the linker may want them present.
const Stat = std.os.zag.Stat;
export fn zag_fs_openat(
    dir_fd: i32,
    path_ptr: [*]const u8,
    path_len: usize,
    flags: u32,
    mode: u32,
) callconv(.c) i64 {
    _ = .{ dir_fd, path_ptr, path_len, flags, mode };
    return -1;
}
export fn zag_fs_read(fd: i32, buf_ptr: [*]u8, buf_len: usize, offset: i64) callconv(.c) i64 {
    _ = .{ fd, buf_ptr, buf_len, offset };
    return -1;
}
export fn zag_fs_write(fd: i32, buf_ptr: [*]const u8, buf_len: usize, offset: i64) callconv(.c) i64 {
    _ = .{ fd, buf_ptr, buf_len, offset };
    return -1;
}
export fn zag_fs_lseek(fd: i32, offset: i64, whence: c_int) callconv(.c) i64 {
    _ = .{ fd, offset, whence };
    return -1;
}
export fn zag_fs_mkdirat(dir_fd: i32, path_ptr: [*]const u8, path_len: usize, mode: u32) callconv(.c) i32 {
    _ = .{ dir_fd, path_ptr, path_len, mode };
    return -1;
}
export fn zag_fs_unlinkat(dir_fd: i32, path_ptr: [*]const u8, path_len: usize) callconv(.c) i32 {
    _ = .{ dir_fd, path_ptr, path_len };
    return -1;
}
export fn zag_fs_statat(dir_fd: i32, path_ptr: [*]const u8, path_len: usize, stat_out: *Stat) callconv(.c) i32 {
    _ = .{ dir_fd, path_ptr, path_len, stat_out };
    return -1;
}
export fn zag_fs_truncate(path_ptr: [*]const u8, path_len: usize, size: i64) callconv(.c) i32 {
    _ = .{ path_ptr, path_len, size };
    return -1;
}
export fn zag_fs_ftruncate(fd: i32, size: i64) callconv(.c) i32 {
    _ = .{ fd, size };
    return -1;
}
export fn zag_fs_close(fd: i32) callconv(.c) i32 {
    _ = fd;
    return 0;
}
export fn zag_fs_fstat(fd: i32, stat_out: *Stat) callconv(.c) i32 {
    _ = .{ fd, stat_out };
    return -1;
}
export fn zag_mmap_anon(pages: usize) callconv(.c) u64 {
    _ = pages;
    return 0;
}
export fn zag_munmap(addr: u64, pages: usize) callconv(.c) i32 {
    _ = .{ addr, pages };
    return 0;
}

// Renamed from `main` so std's start.zig doesn't auto-export
// `_start`=zag_start when this file already provides its own legacy
// `_start`. Auto-export only triggers on `pub fn main`.
fn appMain() !void {
    // First confirm the bare posix path works.
    const msg1 = "[zig_hello_std] hello via std.posix.write\n";
    _ = try std.posix.write(2, msg1);

    // Now via std.fs.File.writeAll — uses writev internally but skips
    // the buffered std.io.Writer / seek/lseek dance.
    try std.fs.File.stderr().writeAll("[zig_hello_std] hello via std.fs.File.writeAll\n");

    // Now exercise the buffered Writer (fs.File.Writer + Io.Writer
    // interface). Requires lseek-on-stderr to return ESPIPE so the
    // Writer treats it as non-seekable.
    {
        const m = "[zig_hello_std] before buffered Writer\n";
        _ = std.posix.write(2, m) catch {};
    }
    var buf: [256]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    w.interface.writeAll("[zig_hello_std] hello via buffered std.io.Writer\n") catch {
        _ = std.posix.write(2, "[zig_hello_std] buffered writeAll WriteFailed\n") catch {};
    };
    w.interface.flush() catch {
        _ = std.posix.write(2, "[zig_hello_std] buffered flush WriteFailed\n") catch {};
    };
    {
        const m = "[zig_hello_std] after buffered Writer\n";
        _ = std.posix.write(2, m) catch {};
    }
}

export fn _start(cap_table_base: u64) callconv(.c) noreturn {
    initSink(cap_table_base);
    // Direct COM1 print to confirm _start ran at all, before main()
    // potentially traps in std machinery.
    if (sink) |p| {
        const banner = "[zig_hello_std] _start running\n";
        var i: usize = 0;
        while (i < banner.len) : (i += 1) p[0] = banner[i];
    }
    appMain() catch {};
    if (sink) |p| {
        const banner = "[zig_hello_std] main returned\n";
        var i: usize = 0;
        while (i < banner.len) : (i += 1) p[0] = banner[i];
    }
    zag_exit(0);
}
