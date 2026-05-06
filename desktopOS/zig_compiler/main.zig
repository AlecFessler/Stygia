// Phase 4e — "compiler" stage of the Zig-on-Zag pipeline.
//
// This is a Zag-target ELF (built by the patched no-LLVM Zig 0.15.2 for
// `-target x86_64-zag-none`). It reads /hello.zig as "source", reads the
// existing /hello2.elf as the "compiled" output bytes, and writes those
// bytes to /hello.elf — proving that a process running inside Zag
// userspace can produce ELFs on disk that another process can later
// load and spawn.
//
// The "compilation" is deliberately a hardcoded byte copy: the point of
// Phase 4e is the ARCHITECTURAL pipeline (compiler-on-Zag → ELF-on-disk
// → spawn-from-disk), not actual codegen. Real codegen will land when
// the upstream patched Zig compiler can self-build for the .zag target
// (Phase 4c blocker tracked separately).
//
// Cap-table layout when zig_hello spawns us:
//   [3] COM1 device_region (port_io 0x3F8/8) — debug sink only.
//   [4] fs_port — typed-IPC port to the SQL-FS server.
//   [5] io_scratch page_frame (16 pages = 64 KiB) — fs IPC payload.

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
const SLOT_INITIAL_EC: u12 = 1;
const SLOT_FIRST_PASSED: u32 = 3;
const HANDLE_TABLE_MAX: u32 = 4096;

const SYS_SUSPEND: u12 = 14;
const SYS_DELETE: u12 = 16;
const SYS_CREATE_VMAR: u12 = 32;
const SYS_MAP_PF: u12 = 33;
const SYS_MAP_MMIO: u12 = 34;

const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

// Mirrors desktopOS/protocols/fs_ops.zig.
const FS_OP_PREAD: u64 = 3;
const FS_OP_PWRITE: u64 = 4;
const FS_OP_CREATE_FILE: u64 = 6;
const FS_OP_UNLINK: u64 = 7;
const FS_SCRATCH_PAGES: u64 = 16;

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

// Spec §[syscall_abi] — vreg 4 lives on %rbp. Stack-resident scratch
// slot pattern (see desktopOS/zig_hello/main.zig issueRaw for the
// detailed rationale).
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

const Inbound = struct {
    com1: u12 = 0,
    fs_port: u12 = 0,
    fs_scratch: u12 = 0,
    have_com1: bool = false,
    have_fs: bool = false,
};

fn findInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var slot: u32 = SLOT_FIRST_PASSED;
    while (slot < HANDLE_TABLE_MAX) : (slot += 1) {
        const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
        const c = tbl[slot];
        switch (capHandleType(c)) {
            .device_region => {
                if (capDevType(c) == .port_io and
                    capDevPort(c) == COM1_BASE_PORT and
                    capDevPortCount(c) == COM1_PORT_COUNT)
                {
                    inv.com1 = @truncate(slot);
                    inv.have_com1 = true;
                }
            },
            .port => {
                inv.fs_port = @truncate(slot);
            },
            .page_frame => {
                inv.fs_scratch = @truncate(slot);
            },
            else => {},
        }
        if (inv.have_com1 and inv.fs_port != 0 and inv.fs_scratch != 0) break;
    }
    inv.have_fs = (inv.fs_port != 0 and inv.fs_scratch != 0);
    return inv;
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

fn print(s: []const u8) void {
    const p = sink orelse return;
    var i: usize = 0;
    while (i < s.len) : (i += 1) p[0] = s[i];
}

fn formatU64(buf: []u8, n: u64) []u8 {
    if (n == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    var v = n;
    var i: usize = 0;
    while (v != 0) : (i += 1) {
        buf[i] = @intCast('0' + (v % 10));
        v /= 10;
    }
    var lo: usize = 0;
    var hi: usize = i - 1;
    while (lo < hi) {
        const t = buf[lo];
        buf[lo] = buf[hi];
        buf[hi] = t;
        lo += 1;
        hi -= 1;
    }
    return buf[0..i];
}

fn printNum(prefix: []const u8, n: u64) void {
    var sb: [32]u8 = undefined;
    const ss = formatU64(&sb, n);
    print(prefix);
    print(ss);
    print("\n");
}

fn mapPfRw(pf_handle: u12, pages: u64) ?u64 {
    const vmar_caps: u64 = (1 << 2) | (1 << 3);
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps,
        .v2 = props,
        .v3 = pages,
    });
    if (cv.v1 < 16) return null;
    const vmar_handle: u12 = @truncate(cv.v1 & 0xFFF);
    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{
        .v1 = vmar_handle,
        .v2 = 0,
        .v3 = pf_handle,
    });
    if (mp.v1 != 0) return null;
    return cv.v2;
}

const FsReadResult = struct { status: u64, bytes_read: u64, data_off: u64 };

fn fsPread(port: u12, scratch_va: u64, path: []const u8, offset: u64, max_len: u64) FsReadResult {
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    var i: usize = 0;
    while (i < path.len) : (i += 1) buf[i] = path[i];
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, port),
        .v3 = FS_OP_PREAD,
        .v4 = path.len,
        .v5 = offset,
        .v6 = max_len,
    });
    return .{ .status = r.v1, .bytes_read = r.v2, .data_off = r.v3 };
}

const FsCreateResult = struct { status: u64, inode: u64 };

fn fsCreateFile(port: u12, scratch_va: u64, path: []const u8, mode: u64) FsCreateResult {
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    var i: usize = 0;
    while (i < path.len) : (i += 1) buf[i] = path[i];
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, port),
        .v3 = FS_OP_CREATE_FILE,
        .v4 = path.len,
        .v5 = mode,
    });
    return .{ .status = r.v1, .inode = r.v2 };
}

const FsWriteResult = struct { status: u64, bytes_written: u64, new_size: u64 };

fn fsPwrite(port: u12, scratch_va: u64, path: []const u8, offset: u64, data: []const u8) FsWriteResult {
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    var i: usize = 0;
    while (i < path.len) : (i += 1) buf[i] = path[i];
    const data_off = path.len;
    var j: usize = 0;
    while (j < data.len) : (j += 1) buf[data_off + j] = data[j];
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, port),
        .v3 = FS_OP_PWRITE,
        .v4 = path.len,
        .v5 = offset,
        .v6 = data_off,
        .v7 = data.len,
    });
    return .{ .status = r.v1, .bytes_written = r.v2, .new_size = r.v3 };
}

fn fsUnlink(port: u12, scratch_va: u64, path: []const u8) u64 {
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    var i: usize = 0;
    while (i < path.len) : (i += 1) buf[i] = path[i];
    const r = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, port),
        .v3 = FS_OP_UNLINK,
        .v4 = path.len,
    });
    return r.v1;
}

fn zagExit() noreturn {
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
}

// Buffer for the "compiled" ELF bytes. Lives in .bss so it doesn't
// blow the per-EC kernel stack (default ~64 KiB).
var elf_buf: [60 * 1024]u8 = undefined;

// Extracted message from /hello.zig — the first quoted string literal.
var msg_buf: [128]u8 = undefined;
var msg_len: usize = 0;

// Banner the prebaked output ELF (zig_hello2) prints. Each occurrence
// in the file gets overwritten with `[compiled] <msg>...\n`.
const BANNER_PREFIX = "[zig_hello2]";
const BANNER_LEN: usize = 76; // total chars including trailing '\n'
const NEW_PREFIX = "[compiled] ";

fn extractFirstQuoted(src: [*]const u8, src_len: usize) usize {
    var start: ?usize = null;
    var i: usize = 0;
    while (i < src_len) : (i += 1) {
        if (src[i] == '"') {
            if (start) |s| {
                const end = i;
                if (end <= s + 1) return 0;
                const n = end - s - 1;
                const copy_n = if (n > msg_buf.len) msg_buf.len else n;
                var k: usize = 0;
                while (k < copy_n) : (k += 1) msg_buf[k] = src[s + 1 + k];
                return copy_n;
            }
            start = i;
        }
    }
    return 0;
}

fn patchBanner(buf: []u8, msg_n: usize) usize {
    var hits: usize = 0;
    if (buf.len < BANNER_LEN) return 0;
    const limit = buf.len - BANNER_LEN;
    var i: usize = 0;
    while (i <= limit) : (i += 1) {
        var k: usize = 0;
        var ok = true;
        while (k < BANNER_PREFIX.len) : (k += 1) {
            if (buf[i + k] != BANNER_PREFIX[k]) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        var w: usize = 0;
        while (w < NEW_PREFIX.len) : (w += 1) buf[i + w] = NEW_PREFIX[w];
        const msg_room: usize = BANNER_LEN - NEW_PREFIX.len - 1;
        const cap = if (msg_n < msg_room) msg_n else msg_room;
        var j: usize = 0;
        while (j < cap) : (j += 1) buf[i + NEW_PREFIX.len + j] = msg_buf[j];
        var s: usize = NEW_PREFIX.len + cap;
        while (s < BANNER_LEN - 1) : (s += 1) buf[i + s] = ' ';
        buf[i + BANNER_LEN - 1] = '\n';
        hits += 1;
    }
    return hits;
}

export fn _start(cap_table_base: u64) callconv(.c) noreturn {
    initSink(cap_table_base);
    print("[zig_compiler] alive\n");

    const inv = findInbound(cap_table_base);
    if (!inv.have_fs) {
        print("[zig_compiler] no fs handles; aborting\n");
        zagExit();
    }

    const fs_va = mapPfRw(inv.fs_scratch, FS_SCRATCH_PAGES) orelse {
        print("[zig_compiler] fs scratch mapPf failed\n");
        zagExit();
    };

    // Read /hello.zig and pull the first quoted string out of it. That
    // becomes the banner of the spawned binary — i.e. the source
    // controls the output's printed message.
    const src = fsPread(inv.fs_port, fs_va, "/hello.zig", 0, 60 * 1024);
    if (src.status != 0) {
        printNum("[zig_compiler] /hello.zig pread status=", src.status);
        zagExit();
    }
    printNum("[zig_compiler] read /hello.zig bytes=", src.bytes_read);
    const src_ptr: [*]const u8 = @ptrFromInt(fs_va + src.data_off);
    msg_len = extractFirstQuoted(src_ptr, @intCast(src.bytes_read));
    if (msg_len == 0) {
        print("[zig_compiler] no quoted string in /hello.zig\n");
        zagExit();
    }
    printNum("[zig_compiler] extracted message len=", msg_len);

    // Read /hello2.elf — template binary; we'll patch its banner.
    const out = fsPread(inv.fs_port, fs_va, "/hello2.elf", 0, 60 * 1024);
    if (out.status != 0) {
        printNum("[zig_compiler] /hello2.elf pread status=", out.status);
        zagExit();
    }
    printNum("[zig_compiler] template /hello2.elf bytes=", out.bytes_read);

    // Copy out from io_scratch — next fsPwrite reuses the same region.
    const out_src: [*]const u8 = @ptrFromInt(fs_va + out.data_off);
    var k: u64 = 0;
    while (k < out.bytes_read) : (k += 1) elf_buf[k] = out_src[k];

    // Patch every banner instance in the buffer.
    const hits = patchBanner(elf_buf[0..out.bytes_read], msg_len);
    printNum("[zig_compiler] patched banner instances=", hits);
    if (hits == 0) {
        print("[zig_compiler] FAILED: no banner found to patch\n");
        zagExit();
    }

    // Write /hello.elf (idempotent — unlink any prior, then create+write).
    _ = fsUnlink(inv.fs_port, fs_va, "/hello.elf");
    const cr = fsCreateFile(inv.fs_port, fs_va, "/hello.elf", 0o644);
    if (cr.status != 0) {
        printNum("[zig_compiler] /hello.elf create status=", cr.status);
        zagExit();
    }

    const wr = fsPwrite(inv.fs_port, fs_va, "/hello.elf", 0, elf_buf[0..out.bytes_read]);
    if (wr.status != 0 or wr.bytes_written != out.bytes_read) {
        printNum("[zig_compiler] /hello.elf pwrite status=", wr.status);
        printNum("[zig_compiler] /hello.elf bytes_written=", wr.bytes_written);
        zagExit();
    }
    printNum("[zig_compiler] wrote /hello.elf bytes=", wr.bytes_written);

    print("[zig_compiler] compiled /hello.zig -> /hello.elf\n");
    zagExit();
}
