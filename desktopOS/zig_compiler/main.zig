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

// Banner the prebaked output ELF (zig_hello2) prints. Each occurrence
// in the file gets overwritten with `[<tag>] <banner> <pad> \n`.
const BANNER_PREFIX = "[zig_hello2]";
const BANNER_LEN: usize = 76; // total chars including trailing '\n'

// Strings extracted from /hello.zig — the first two quoted literals.
// First → tag (becomes the bracketed prefix), second → banner body.
var tag_buf: [32]u8 = undefined;
var tag_len: usize = 0;
var banner_buf: [128]u8 = undefined;
var banner_len: usize = 0;

// Integers extracted from /hello.zig — first three decimal literals
// after the second quoted string. seed → " seed=<n>" suffix in the
// banner string AND patched into the binary's seed_value sentinel;
// mult → patched into the mult_value sentinel; repeat → patched into
// the repeat_value sentinel (drives spawned binary's runtime loop count).
var seed_int: u64 = 0;
var seed_found: bool = false;
var mult_int: u64 = 0;
var mult_found: bool = false;
var repeat_int: u64 = 0;
var repeat_found: bool = false;
var op_int: u64 = 0;
var op_found: bool = false;
var step_int: u64 = 0;
var step_found: bool = false;
var skip_int: u64 = 0;
var skip_found: bool = false;
var inner_int: u64 = 0;
var inner_found: bool = false;
// Source u64 array (after the 6 scalar consts). Up to 4 entries.
const VALUES_MAX: usize = 4;
var values_buf: [VALUES_MAX]u64 = .{ 0, 0, 0, 0 };
var values_count: usize = 0;

// Extract up to two quoted-string literals from `src[0..src_len]` and
// the first decimal integer that appears after the second quoted
// string. Returns the number of strings found (0, 1, or 2). The int
// is reported via `seed_found` / `seed_int`.
fn extractSourceFields(src: [*]const u8, src_len: usize) usize {
    var found: usize = 0;
    var in_str = false;
    var str_start: usize = 0;
    var after_second: ?usize = null;
    var i: usize = 0;
    while (i < src_len) : (i += 1) {
        if (src[i] != '"') continue;
        if (!in_str) {
            in_str = true;
            str_start = i;
            continue;
        }
        in_str = false;
        const end = i;
        if (end <= str_start + 1) continue;
        const n = end - str_start - 1;
        if (found == 0) {
            const cap = if (n > tag_buf.len) tag_buf.len else n;
            var k: usize = 0;
            while (k < cap) : (k += 1) tag_buf[k] = src[str_start + 1 + k];
            tag_len = cap;
            found = 1;
        } else if (found == 1) {
            const cap = if (n > banner_buf.len) banner_buf.len else n;
            var k: usize = 0;
            while (k < cap) : (k += 1) banner_buf[k] = src[str_start + 1 + k];
            banner_len = cap;
            found = 2;
            after_second = end + 1;
            break;
        }
    }
    // Scan for decimal int literals after the second quoted string.
    // Skips digits that are part of an identifier (e.g. "u64" type
    // suffix) by requiring the preceding char to NOT be alphanumeric
    // or underscore.
    if (after_second) |start| {
        var j: usize = start;
        var ints_found: u8 = 0;
        while (j < src_len) {
            const c = src[j];
            if (c < '0' or c > '9') {
                j += 1;
                continue;
            }
            // Reject digits that follow an identifier char — those
            // are part of "u64", "i32", "x123" etc. rather than int literals.
            if (j > 0) {
                const prev = src[j - 1];
                const is_ident_char = (prev >= 'a' and prev <= 'z') or
                    (prev >= 'A' and prev <= 'Z') or
                    (prev >= '0' and prev <= '9') or
                    prev == '_';
                if (is_ident_char) {
                    // Skip the rest of this identifier-attached digit run.
                    while (j < src_len) : (j += 1) {
                        const d = src[j];
                        if (d < '0' or d > '9') break;
                    }
                    continue;
                }
            }
            var v: u64 = 0;
            while (j < src_len) : (j += 1) {
                const d = src[j];
                if (d < '0' or d > '9') break;
                v = v * 10 + (@as(u64, d) - '0');
            }
            if (ints_found == 0) {
                seed_int = v;
                seed_found = true;
                ints_found = 1;
            } else if (ints_found == 1) {
                mult_int = v;
                mult_found = true;
                ints_found = 2;
            } else if (ints_found == 2) {
                repeat_int = v;
                repeat_found = true;
                ints_found = 3;
            } else if (ints_found == 3) {
                op_int = v;
                op_found = true;
                ints_found = 4;
            } else if (ints_found == 4) {
                step_int = v;
                step_found = true;
                ints_found = 5;
            } else if (ints_found == 5) {
                skip_int = v;
                skip_found = true;
                ints_found = 6;
            } else if (ints_found == 6) {
                inner_int = v;
                inner_found = true;
                ints_found = 7;
            } else if (values_count < VALUES_MAX) {
                values_buf[values_count] = v;
                values_count += 1;
            } else {
                break;
            }
        }
    }
    return found;
}

// Find every occurrence of the 8-byte sentinel (little-endian) and
// replace it with `value` as little-endian u64. Returns hit count.
const SEED_SENTINEL: u64 = 0xCAFEBABE_DEADBEEF;
const MULT_SENTINEL: u64 = 0xCAFEBABE_FACE0001;
const REPEAT_SENTINEL: u64 = 0xCAFEBABE_C0FFEE01;
const OP_SENTINEL: u64 = 0xCAFEBABE_05E1EC70;
const STEP_SENTINEL: u64 = 0xCAFEBABE_57E90001;
const SKIP_SENTINEL: u64 = 0xCAFEBABE_5C1A0001;
const INNER_SENTINEL: u64 = 0xCAFEBABE_19E70001;
// Compiler-computed checksum target — XOR of every scalar source int.
// The compiler computes this from the parsed values and patches it,
// so the spawned binary can verify the patch chain end-to-end.
const CHECKSUM_SENTINEL: u64 = 0xCAFEBABE_C5E60001;
// Compiler-computed array product target — wrapping product of every
// parsed values_buf entry (1 if no array values).
const ARRAY_PRODUCT_SENTINEL: u64 = 0xCAFEBABE_AB10D001;

// Per-element sentinels for the source-defined u64 array (must
// match zig_hello2/main.zig values_arr initializers exactly).
const VALUES_LEN_SENTINEL: u64 = 0xCAFEBABE_A8B70042;
const VALUES_ELEM_SENTINELS = [_]u64{
    0xCAFEBABE_A8B70000,
    0xCAFEBABE_A8B70001,
    0xCAFEBABE_A8B70002,
    0xCAFEBABE_A8B70003,
};

fn patchU64Sentinel(buf: []u8, sentinel: u64, value: u64) usize {
    var hits: usize = 0;
    if (buf.len < 8) return 0;
    const limit = buf.len - 8;
    var i: usize = 0;
    while (i <= limit) : (i += 1) {
        var got: u64 = 0;
        var k: u6 = 0;
        while (k < 8) : (k += 1) {
            got |= @as(u64, buf[i + k]) << (k * 8);
        }
        if (got != sentinel) continue;
        var w: u6 = 0;
        while (w < 8) : (w += 1) {
            buf[i + w] = @truncate((value >> (w * 8)) & 0xFF);
        }
        hits += 1;
        i += 7;
    }
    return hits;
}

fn patchBanner(buf: []u8) usize {
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

        // Layout: '[' <tag> ']' ' ' <banner> [' seed=' <int>] <pad> '\n'
        var w: usize = 0;
        buf[i + w] = '[';
        w += 1;
        const tag_cap = if (tag_len > 30) 30 else tag_len;
        var j: usize = 0;
        while (j < tag_cap) : (j += 1) {
            buf[i + w] = tag_buf[j];
            w += 1;
        }
        buf[i + w] = ']';
        w += 1;
        buf[i + w] = ' ';
        w += 1;

        // Banner body — leave room for seed suffix + trailing '\n'.
        var seed_str_buf: [24]u8 = undefined;
        var seed_str: []const u8 = &.{};
        if (seed_found) {
            const tail = formatU64(&seed_str_buf, seed_int);
            const seed_pre = " seed=";
            // Build " seed=<int>" in seed_str_buf in two passes (we
            // already have the int at the start of the buf; shift it).
            var combined: [24]u8 = undefined;
            var ci: usize = 0;
            while (ci < seed_pre.len) : (ci += 1) combined[ci] = seed_pre[ci];
            var ti: usize = 0;
            while (ti < tail.len and ci < combined.len) : (ti += 1) {
                combined[ci] = tail[ti];
                ci += 1;
            }
            // Re-pack into seed_str_buf for slice safety.
            var pi: usize = 0;
            while (pi < ci) : (pi += 1) seed_str_buf[pi] = combined[pi];
            seed_str = seed_str_buf[0..ci];
        }

        const reserved_tail: usize = seed_str.len + 1; // +1 for '\n'
        const body_room: usize = if (BANNER_LEN > w + reserved_tail) BANNER_LEN - w - reserved_tail else 0;
        const body_cap = if (banner_len > body_room) body_room else banner_len;
        j = 0;
        while (j < body_cap) : (j += 1) {
            buf[i + w] = banner_buf[j];
            w += 1;
        }
        var s: usize = 0;
        while (s < seed_str.len and w < BANNER_LEN - 1) : (s += 1) {
            buf[i + w] = seed_str[s];
            w += 1;
        }
        while (w < BANNER_LEN - 1) : (w += 1) buf[i + w] = ' ';
        buf[i + w] = '\n';
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
    const found = extractSourceFields(src_ptr, @intCast(src.bytes_read));
    if (found < 2) {
        printNum("[zig_compiler] need 2 quoted strings, found=", found);
        zagExit();
    }
    printNum("[zig_compiler] extracted tag len=", tag_len);
    printNum("[zig_compiler] extracted banner len=", banner_len);
    if (seed_found) {
        printNum("[zig_compiler] extracted seed=", seed_int);
    } else {
        print("[zig_compiler] no seed int in source\n");
    }
    if (mult_found) {
        printNum("[zig_compiler] extracted mult=", mult_int);
    }
    if (repeat_found) {
        printNum("[zig_compiler] extracted repeat=", repeat_int);
    }
    if (op_found) {
        printNum("[zig_compiler] extracted op=", op_int);
    }
    if (step_found) {
        printNum("[zig_compiler] extracted step=", step_int);
    }
    if (skip_found) {
        printNum("[zig_compiler] extracted skip_idx=", skip_int);
    }
    if (inner_found) {
        printNum("[zig_compiler] extracted inner=", inner_int);
    }
    if (values_count > 0) {
        printNum("[zig_compiler] extracted values count=", values_count);
        var vi: usize = 0;
        while (vi < values_count) : (vi += 1) {
            printNum("[zig_compiler]   values[i]=", values_buf[vi]);
        }
    }

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
    const hits = patchBanner(elf_buf[0..out.bytes_read]);
    printNum("[zig_compiler] patched banner instances=", hits);
    if (hits == 0) {
        print("[zig_compiler] FAILED: no banner found to patch\n");
        zagExit();
    }

    // Patch the runtime sentinels — u64s in the binary read via
    // volatile loads at runtime. Source values drive real memory
    // contents, not just text. The spawned binary multiplies the
    // two patched values and prints the product.
    if (seed_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], SEED_SENTINEL, seed_int);
        printNum("[zig_compiler] patched seed sentinel hits=", h);
    }
    if (mult_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], MULT_SENTINEL, mult_int);
        printNum("[zig_compiler] patched mult sentinel hits=", h);
    } else {
        print("[zig_compiler] no second int (mult) in source\n");
    }
    if (repeat_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], REPEAT_SENTINEL, repeat_int);
        printNum("[zig_compiler] patched repeat sentinel hits=", h);
    } else {
        print("[zig_compiler] no third int (repeat) in source\n");
    }
    if (op_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], OP_SENTINEL, op_int);
        printNum("[zig_compiler] patched op sentinel hits=", h);
    } else {
        print("[zig_compiler] no fourth int (op) in source\n");
    }
    if (step_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], STEP_SENTINEL, step_int);
        printNum("[zig_compiler] patched step sentinel hits=", h);
    } else {
        print("[zig_compiler] no fifth int (step) in source\n");
    }
    if (skip_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], SKIP_SENTINEL, skip_int);
        printNum("[zig_compiler] patched skip sentinel hits=", h);
    } else {
        print("[zig_compiler] no sixth int (skip_idx) in source\n");
    }
    if (inner_found) {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], INNER_SENTINEL, inner_int);
        printNum("[zig_compiler] patched inner sentinel hits=", h);
    } else {
        print("[zig_compiler] no seventh int (inner) in source\n");
    }
    // Compute checksum from parsed source ints — XOR of every scalar.
    // Always patch (even if some ints missing — those contribute 0).
    {
        const checksum: u64 =
            seed_int ^ mult_int ^ repeat_int ^ op_int ^
            step_int ^ skip_int ^ inner_int;
        printNum("[zig_compiler] computed checksum=", checksum);
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], CHECKSUM_SENTINEL, checksum);
        printNum("[zig_compiler] patched checksum hits=", h);
    }
    // Compile-time product over parsed array values — wrapping multiply,
    // identity 1. Spawned binary recomputes the same reduction.
    {
        var product: u64 = 1;
        var pi: usize = 0;
        while (pi < values_count) : (pi += 1) {
            product *%= values_buf[pi];
        }
        printNum("[zig_compiler] computed array_product=", product);
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], ARRAY_PRODUCT_SENTINEL, product);
        printNum("[zig_compiler] patched array_product hits=", h);
    }
    // Always patch the array length (even if 0) so the spawned binary
    // doesn't iterate against the raw sentinel.
    {
        const h = patchU64Sentinel(elf_buf[0..out.bytes_read], VALUES_LEN_SENTINEL, values_count);
        printNum("[zig_compiler] patched values_len hits=", h);
    }
    {
        var vi: usize = 0;
        while (vi < values_count and vi < VALUES_ELEM_SENTINELS.len) : (vi += 1) {
            const h = patchU64Sentinel(elf_buf[0..out.bytes_read], VALUES_ELEM_SENTINELS[vi], values_buf[vi]);
            printNum("[zig_compiler]   patched values_arr slot hits=", h);
        }
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
