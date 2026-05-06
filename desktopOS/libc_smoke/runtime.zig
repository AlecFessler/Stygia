// Minimal Zag runtime providing all `zag_*` externs libc.a needs.
//
// Cap-table layout this runtime accepts (any subset, identified by
// handle type, scanning slot >= SLOT_FIRST_PASSED):
//   port[0]                          → fs_port
//   page_frame[0]                    → fs_scratch  (>= 16 pages)
//   device_region matching COM1      → COM1
//
// `zag_init(cap_table_base)` must be called before any libc I/O. The
// patched `lib/std/start.zig` calls it before transferring to main().
//
// Override std's default panic so debug-mode safety checks compile
// without dragging in dumpStackTrace → selfExePath chain (same trick
// as libz/libc/src/libc.zig).

pub const panic = @import("std").debug.no_panic;

// ── Spec slots / syscall numbers ─────────────────────────────────────
const SLOT_SELF: u12 = 0;
const SLOT_INITIAL_EC: u12 = 1;
const SLOT_FIRST_PASSED: u32 = 3;
const HANDLE_TABLE_MAX: u32 = 4096;

const SYS_SUSPEND: u12 = 14;
const SYS_DELETE: u12 = 16;
const SYS_CREATE_VMAR: u12 = 32;
const SYS_MAP_PF: u12 = 33;
const SYS_MAP_MMIO: u12 = 34;
const SYS_CREATE_PAGE_FRAME: u12 = 40;

const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

// ── FS protocol (mirrors desktopOS/protocols/fs_ops.zig) ─────────────
const FS_OP_LOOKUP: u64 = 1;
const FS_OP_STAT: u64 = 2;
const FS_OP_PREAD: u64 = 3;
const FS_OP_PWRITE: u64 = 4;
const FS_OP_TRUNCATE: u64 = 5;
const FS_OP_CREATE_FILE: u64 = 6;
const FS_OP_UNLINK: u64 = 7;
const FS_OP_MKDIR: u64 = 8;
const FS_SCRATCH_PAGES: u64 = 16;
const FS_SCRATCH_BYTES: u64 = FS_SCRATCH_PAGES * 4096;
const FS_PATH_MAX: usize = 4096;

// POSIX open flags (Linux-compat values, what libc passes through)
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;

// errno values
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const EIO: i64 = 5;
const ENOSYS: i64 = 38;

// ── Capability decoding ──────────────────────────────────────────────
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

// Spec §[syscall_abi] x86-64: 13 vregs spread across rax/rbx/rdx/rbp +
// rsi/rdi/r8/r9/r10/r12/r13/r14/r15 (rcx holds the syscall word). %rbp
// is reused as a frame pointer by the no-LLVM Zig backend, so we
// stash/restore it around the syscall via a stack slot.
//
// Mirrors desktopOS/zig_hello/main.zig issueRaw exactly — every vreg
// register is bound as both an input AND an output so the kernel's
// write-back is observed and the compiler's register allocator
// understands the clobber.
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

// ── Inbound discovery ────────────────────────────────────────────────
const Inbound = struct {
    com1: u12 = 0,
    fs_port: u12 = 0,
    fs_scratch: u12 = 0,
    have_com1: bool = false,
    have_fs: bool = false,
};

fn findInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var got_ports: u8 = 0;
    var got_pfs: u8 = 0;
    var slot: u32 = SLOT_FIRST_PASSED;
    while (slot < HANDLE_TABLE_MAX) {
        const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
        const c = tbl[slot];
        switch (capHandleType(c)) {
            .port => {
                if (got_ports == 0) {
                    inv.fs_port = @truncate(slot);
                    inv.have_fs = true;
                }
                got_ports += 1;
            },
            .page_frame => {
                if (got_pfs == 0) inv.fs_scratch = @truncate(slot);
                got_pfs += 1;
            },
            .device_region => {
                if (capDevType(c) == .port_io and capDevPort(c) == COM1_BASE_PORT) {
                    inv.com1 = @truncate(slot);
                    inv.have_com1 = true;
                }
            },
            else => {},
        }
        slot += 1;
    }
    if (got_pfs == 0) inv.have_fs = false;
    return inv;
}

// ── Runtime state ────────────────────────────────────────────────────
var inbound: Inbound = .{};
var com1_sink: ?[*]volatile u8 = null;
var fs_scratch_va: u64 = 0;

fn setupCom1() void {
    if (!inbound.have_com1) return;
    const vmar_caps: u64 = (1 << 2) | (1 << 3) | (1 << 5);
    const props: u64 = (1 << 5) | 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{ .v1 = vmar_caps, .v2 = props, .v3 = 1 });
    if (cv.v1 < 16) return;
    const vh: u12 = @truncate(cv.v1 & 0xFFF);
    const mm = issueRaw(buildWord(SYS_MAP_MMIO, 0), .{ .v1 = vh, .v2 = inbound.com1 });
    if (mm.v1 != 0) return;
    com1_sink = @ptrFromInt(cv.v2);
}

fn setupFsScratch() void {
    if (!inbound.have_fs) return;
    const vmar_caps: u64 = (1 << 2) | (1 << 3);
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{ .v1 = vmar_caps, .v2 = props, .v3 = FS_SCRATCH_PAGES });
    if (cv.v1 < 16) return;
    const vh: u12 = @truncate(cv.v1 & 0xFFF);
    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{ .v1 = vh, .v2 = 0, .v3 = inbound.fs_scratch });
    if (mp.v1 != 0) return;
    fs_scratch_va = cv.v2;
}

export fn zag_init(cap_table_base: u64) callconv(.c) void {
    inbound = findInbound(cap_table_base);
    setupCom1();
    setupFsScratch();
}

// Back-compat shim: libc.a's old console init still calls this name.
export fn zag_init_com1() callconv(.c) void {
    // No-op: zag_init handles COM1 setup. Kept so any object compiled
    // against the older extern signature still links.
}

// ── Console output ───────────────────────────────────────────────────
export fn zag_write_console(buf: [*]const u8, count: usize) callconv(.c) usize {
    const p = com1_sink orelse return count;
    var i: usize = 0;
    while (i < count) {
        p[0] = buf[i];
        i += 1;
    }
    return count;
}

export fn zag_exit(status: u8) callconv(.c) noreturn {
    _ = status;
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
}

// ── fd table — (path, pos) on top of stateless fs_ops ────────────────
//
// Keep this small for now: 8 entries × 256B path = 2 KB BSS. Bigger
// arrays can hit weird codegen issues with the no-LLVM backend on
// Zag-target binaries (BSS/data-zero handling regressions surface
// here first).
const MAX_OPEN: usize = 8;
const FD_BASE: i32 = 100; // sit above stdin/stdout/stderr
const FD_PATH_MAX: usize = 256;

const OpenFile = extern struct {
    in_use: u8 = 0,
    pad0: [7]u8 = .{ 0, 0, 0, 0, 0, 0, 0 },
    path_len: u64 = 0,
    pos: u64 = 0,
    flags: u32 = 0,
    pad1: u32 = 0,
    path: [FD_PATH_MAX]u8 = @splat(0),
};

var fdtab: [MAX_OPEN]OpenFile = @splat(OpenFile{});

fn allocFd() i32 {
    var i: usize = 0;
    while (i < MAX_OPEN) {
        if (fdtab[i].in_use == 0) {
            fdtab[i].in_use = 1;
            return FD_BASE + @as(i32, @intCast(i));
        }
        i += 1;
    }
    return -@as(i32, @intCast(EMFILE));
}

fn fdLookup(fd: i32) ?*OpenFile {
    if (fd < FD_BASE) return null;
    const idx: usize = @intCast(fd - FD_BASE);
    if (idx >= MAX_OPEN) return null;
    if (fdtab[idx].in_use == 0) return null;
    return &fdtab[idx];
}

// ── fs IPC primitives ────────────────────────────────────────────────
fn writePathScratch(path: [*]const u8, len: usize) bool {
    if (len == 0 or len > FS_PATH_MAX) return false;
    if (fs_scratch_va == 0) return false;
    const buf: [*]u8 = @ptrFromInt(fs_scratch_va);
    var i: usize = 0;
    while (i < len) {
        buf[i] = path[i];
        i += 1;
    }
    return true;
}

fn fsLookup(path: [*]const u8, len: usize) bool {
    if (!writePathScratch(path, len)) return false;
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_LOOKUP,
        .v4 = len,
    });
    return r.v1 == 0;
}

fn fsStatSize(path: [*]const u8, len: usize) ?u64 {
    if (!writePathScratch(path, len)) return null;
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_STAT,
        .v4 = len,
    });
    if (r.v1 != 0) return null;
    return r.v4;
}

fn fsCreateFile(path: [*]const u8, len: usize, mode: u64) u64 {
    if (!writePathScratch(path, len)) return 10; // invalid
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_CREATE_FILE,
        .v4 = len,
        .v5 = mode,
    });
    return r.v1;
}

fn fsTruncate(path: [*]const u8, len: usize, new_size: u64) u64 {
    if (!writePathScratch(path, len)) return 10;
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_TRUNCATE,
        .v4 = len,
        .v5 = new_size,
    });
    return r.v1;
}

fn fsUnlink(path: [*]const u8, len: usize) u64 {
    if (!writePathScratch(path, len)) return 10;
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_UNLINK,
        .v4 = len,
    });
    return r.v1;
}

fn fsMkdir(path: [*]const u8, len: usize, mode: u64) u64 {
    if (!writePathScratch(path, len)) return 10;
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_MKDIR,
        .v4 = len,
        .v5 = mode,
    });
    return r.v1;
}

const FsPread = struct { status: u64, bytes: u64, data_off: u64 };
fn fsPread(path: [*]const u8, len: usize, off: u64, max: u64) FsPread {
    if (!writePathScratch(path, len)) return .{ .status = 10, .bytes = 0, .data_off = 0 };
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_PREAD,
        .v4 = len,
        .v5 = off,
        .v6 = max,
    });
    return .{ .status = r.v1, .bytes = r.v2, .data_off = r.v3 };
}

const FsPwrite = struct { status: u64, bytes: u64, new_size: u64 };
fn fsPwrite(path: [*]const u8, len: usize, off: u64, data: [*]const u8, data_len: usize) FsPwrite {
    if (!writePathScratch(path, len)) return .{ .status = 10, .bytes = 0, .new_size = 0 };
    const data_off: usize = (len + 7) & ~@as(usize, 7);
    if (data_off + data_len > FS_SCRATCH_BYTES) return .{ .status = 10, .bytes = 0, .new_size = 0 };
    const buf: [*]u8 = @ptrFromInt(fs_scratch_va + data_off);
    var i: usize = 0;
    while (i < data_len) {
        buf[i] = data[i];
        i += 1;
    }
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, inbound.fs_port),
        .v3 = FS_OP_PWRITE,
        .v4 = len,
        .v5 = off,
        .v6 = data_off,
        .v7 = data_len,
    });
    return .{ .status = r.v1, .bytes = r.v2, .new_size = r.v3 };
}

// ── libc fs hooks (the contract posix_io.zig consumes) ───────────────
//
//   negative return = -errno; non-negative = success value.

export fn zag_fs_openat(path: [*]const u8, len: usize, flags: u32, mode: u32) callconv(.c) i64 {
    if (!inbound.have_fs) return -ENOSYS;
    const exists = fsLookup(path, len);
    const want_create = (flags & O_CREAT) != 0;
    const want_excl = (flags & O_EXCL) != 0;
    if (!exists and !want_create) return -ENOENT;
    if (exists and want_create and want_excl) return -EEXIST;
    if (!exists) {
        if (fsCreateFile(path, len, mode) != 0) return -EIO;
    } else if ((flags & O_TRUNC) != 0 and (flags & (O_WRONLY | O_RDWR)) != 0) {
        _ = fsTruncate(path, len, 0);
    }
    const fd = allocFd();
    if (fd < 0) return @intCast(fd);
    const f = fdLookup(fd) orelse return -EMFILE;
    var i: usize = 0;
    const cap = if (len > FD_PATH_MAX) FD_PATH_MAX else len;
    while (i < cap) {
        f.path[i] = path[i];
        i += 1;
    }
    f.path_len = cap;
    f.pos = 0;
    f.flags = flags;
    if ((flags & O_APPEND) != 0) {
        if (fsStatSize(@ptrCast(&f.path), f.path_len)) |s| f.pos = s;
    }
    return @intCast(fd);
}

const PREAD_CHUNK: u64 = 32 * 1024;

export fn zag_fs_read(fd: i32, buf: [*]u8, len: usize, off: i64) callconv(.c) i64 {
    if (!inbound.have_fs) return -ENOSYS;
    if (len == 0) return 0;
    const f = fdLookup(fd) orelse return -EBADF;
    const use_pos = (off < 0);
    var cur: u64 = if (use_pos) f.pos else @intCast(off);
    var total: usize = 0;
    var remaining = len;
    while (remaining > 0) {
        const want: u64 = if (remaining > PREAD_CHUNK) PREAD_CHUNK else @intCast(remaining);
        const r = fsPread(@ptrCast(&f.path), f.path_len, cur, want);
        if (r.status != 0) return -EIO;
        if (r.bytes == 0) break;
        const src: [*]const u8 = @ptrFromInt(fs_scratch_va + r.data_off);
        var i: u64 = 0;
        while (i < r.bytes) {
            buf[total + @as(usize, @intCast(i))] = src[@as(usize, @intCast(i))];
            i += 1;
        }
        total += @intCast(r.bytes);
        cur += r.bytes;
        remaining -= @intCast(r.bytes);
        if (r.bytes < want) break; // short read = EOF
    }
    if (use_pos) f.pos = cur;
    return @intCast(total);
}

export fn zag_fs_write(fd: i32, buf: [*]const u8, len: usize, off: i64) callconv(.c) i64 {
    if (!inbound.have_fs) return -ENOSYS;
    if (len == 0) return 0;
    const f = fdLookup(fd) orelse return -EBADF;
    const use_pos = (off < 0);
    var cur: u64 = if (use_pos) f.pos else @intCast(off);
    var total: usize = 0;
    var remaining = len;
    // pwrite must fit (path_len + data_len) into FS_SCRATCH_BYTES;
    // path occupies `(path_len + 7) & ~7` bytes, leaving the rest for data.
    const path_block: usize = (f.path_len + 7) & ~@as(usize, 7);
    var max_chunk: usize = @intCast(FS_SCRATCH_BYTES);
    if (path_block + 8 < max_chunk) max_chunk -= path_block + 8;
    const CHUNK: usize = if (max_chunk > 32 * 1024) 32 * 1024 else max_chunk;
    while (remaining > 0) {
        const want = if (remaining > CHUNK) CHUNK else remaining;
        const r = fsPwrite(@ptrCast(&f.path), f.path_len, cur, buf + total, want);
        if (r.status != 0) return -EIO;
        if (r.bytes == 0) break;
        total += @intCast(r.bytes);
        cur += r.bytes;
        remaining -= @intCast(r.bytes);
        if (r.bytes < want) break;
    }
    if (use_pos) f.pos = cur;
    return @intCast(total);
}

export fn zag_fs_close(fd: i32) callconv(.c) i32 {
    const f = fdLookup(fd) orelse return -@as(i32, @intCast(EBADF));
    f.in_use = 0;
    f.path_len = 0;
    f.pos = 0;
    f.flags = 0;
    return 0;
}

export fn zag_fs_lseek(fd: i32, off: i64, whence: c_int) callconv(.c) i64 {
    const f = fdLookup(fd) orelse return -EBADF;
    const new_pos: i64 = switch (whence) {
        0 => off, // SEEK_SET
        1 => @as(i64, @intCast(f.pos)) + off, // SEEK_CUR
        2 => blk: {
            const sz = fsStatSize(@ptrCast(&f.path), f.path_len) orelse return -EIO;
            break :blk @as(i64, @intCast(sz)) + off;
        },
        else => return -EINVAL,
    };
    if (new_pos < 0) return -EINVAL;
    f.pos = @intCast(new_pos);
    return @intCast(f.pos);
}

// Linux-style stat layout — matches what posix_io.zig's `Stat` shape expects
// (it just reserves 144 bytes; our layout fits).
const Stat = extern struct {
    dev: u64 = 0,
    ino: u64 = 0,
    nlink: u64 = 1,
    mode: u32 = 0o100644,
    uid: u32 = 0,
    gid: u32 = 0,
    pad0: u32 = 0,
    rdev: u64 = 0,
    size: i64 = 0,
    blksize: i64 = 4096,
    blocks: i64 = 0,
    atime: i64 = 0,
    atime_nsec: i64 = 0,
    mtime: i64 = 0,
    mtime_nsec: i64 = 0,
    ctime: i64 = 0,
    ctime_nsec: i64 = 0,
    pad: [3]i64 = .{ 0, 0, 0 },
};

fn fillStat(st_anyopaque: *anyopaque, sz: u64) void {
    const out: *Stat = @ptrCast(@alignCast(st_anyopaque));
    out.* = .{};
    out.size = @intCast(sz);
    out.blocks = @intCast((sz + 511) / 512);
}

export fn zag_fs_fstat(fd: i32, st: *anyopaque) callconv(.c) i32 {
    const f = fdLookup(fd) orelse return -@as(i32, @intCast(EBADF));
    const sz = fsStatSize(@ptrCast(&f.path), f.path_len) orelse return -@as(i32, @intCast(EIO));
    fillStat(st, sz);
    return 0;
}

export fn zag_fs_stat(path: [*]const u8, len: usize, st: *anyopaque) callconv(.c) i32 {
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    const sz = fsStatSize(path, len) orelse return -@as(i32, @intCast(ENOENT));
    fillStat(st, sz);
    return 0;
}

export fn zag_fs_unlink(path: [*]const u8, len: usize) callconv(.c) i32 {
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    return if (fsUnlink(path, len) == 0) 0 else -@as(i32, @intCast(EIO));
}

export fn zag_fs_mkdir(path: [*]const u8, len: usize, mode: u32) callconv(.c) i32 {
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    return if (fsMkdir(path, len, mode) == 0) 0 else -@as(i32, @intCast(EIO));
}

export fn zag_fs_truncate(path: [*]const u8, len: usize, size: i64) callconv(.c) i32 {
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    if (size < 0) return -@as(i32, @intCast(EINVAL));
    return if (fsTruncate(path, len, @intCast(size)) == 0) 0 else -@as(i32, @intCast(EIO));
}

export fn zag_fs_ftruncate(fd: i32, size: i64) callconv(.c) i32 {
    const f = fdLookup(fd) orelse return -@as(i32, @intCast(EBADF));
    if (size < 0) return -@as(i32, @intCast(EINVAL));
    return if (fsTruncate(@ptrCast(&f.path), f.path_len, @intCast(size)) == 0) 0 else -@as(i32, @intCast(EIO));
}

// ── Anonymous mmap (heap backing, demand-paged via eager pf+VMAR) ────
//
// Spec §[var] says demand-paged VMARs are the canonical anon-mmap, but
// kernel/memory/vmar.zig demandAlloc still returns E_NOMEM as of
// 2026-05-06. So we allocate a page_frame eagerly + map_pf into a fresh
// VMAR. Switch to demand-paged when the kernel implementation lands.

const HEAP_TABLE_LEN: usize = 64;
const HeapEntry = struct {
    base: u64 = 0,
    vmar: u12 = 0,
    pf: u12 = 0,
};
var heap_table: [HEAP_TABLE_LEN]HeapEntry = .{HeapEntry{}} ** HEAP_TABLE_LEN;

fn heapTablePush(base: u64, vmar: u12, pf: u12) bool {
    var i: usize = 0;
    while (i < HEAP_TABLE_LEN) {
        if (heap_table[i].base == 0) {
            heap_table[i] = .{ .base = base, .vmar = vmar, .pf = pf };
            return true;
        }
        i += 1;
    }
    return false;
}

const HeapTake = struct { vmar: u12, pf: u12 };
fn heapTableTake(base: u64) ?HeapTake {
    var i: usize = 0;
    while (i < HEAP_TABLE_LEN) {
        if (heap_table[i].base == base) {
            const e = heap_table[i];
            heap_table[i] = .{};
            return .{ .vmar = e.vmar, .pf = e.pf };
        }
        i += 1;
    }
    return null;
}

export fn zag_mmap_anon(pages: usize) callconv(.c) u64 {
    if (pages == 0) return 0;
    const pf_caps: u64 = (1 << 2) | (1 << 3);
    const cpf = issueRaw(buildWord(SYS_CREATE_PAGE_FRAME, 0), .{
        .v1 = pf_caps,
        .v2 = 0,
        .v3 = pages,
    });
    if (cpf.v1 < 16) return 0;
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    const vmar_caps: u64 = (1 << 2) | (1 << 3);
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps,
        .v2 = props,
        .v3 = pages,
    });
    if (cv.v1 < 16) {
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, pf_handle) });
        return 0;
    }
    const vmar_handle: u12 = @truncate(cv.v1 & 0xFFF);
    const base = cv.v2;

    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{
        .v1 = vmar_handle,
        .v2 = 0,
        .v3 = pf_handle,
    });
    if (mp.v1 != 0) {
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, vmar_handle) });
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, pf_handle) });
        return 0;
    }

    if (!heapTablePush(base, vmar_handle, pf_handle)) {
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, vmar_handle) });
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, pf_handle) });
        return 0;
    }
    return base;
}

export fn zag_munmap(addr: u64, pages: usize) callconv(.c) i32 {
    _ = pages;
    const t = heapTableTake(addr) orelse return -1;
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, t.vmar) });
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, t.pf) });
    return 0;
}
