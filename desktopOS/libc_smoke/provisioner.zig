// Provisioner — populates the SQL FS at boot from an in-memory bundle
// of files staged by root_service. Reads the bundle from a cap-passed
// page_frame, walks entries (mkdir + create+write per file), then
// signals root_service via a dedicated done_port.
//
// Cap-table layout root_service hands us (in order, from SLOT_FIRST_PASSED):
//   [3] fs_port        (xfer|bind)            ← consumed by runtime.o
//   [4] io_scratch     (r+w, 16 pages)        ← consumed by runtime.o
//   [5] COM1           (port_io device)       ← consumed by runtime.o
//   [6] bundle_pf      (r, sized to bundle)   ← us
//   [7] done_port      (xfer|bind)            ← us
//
// Bundle wire format mirrors desktopOS/tools/make_lib_bundle.zig:
//
//   per entry:
//     u8  kind          0=file, 1=dir, 0xFF=end
//     u8  reserved
//     u16 path_len
//     u32 content_len
//     [path_len]u8 path
//     [content_len]u8 content (omitted for dirs)

const std = @import("std");

extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn exit(status: c_int) callconv(.c) noreturn;

// Defined by runtime.o + libc.a.
extern fn zag_fs_openat(path: [*]const u8, len: usize, flags: u32, mode: u32) callconv(.c) i64;
extern fn zag_fs_write(fd: i32, buf: [*]const u8, len: usize, off: i64) callconv(.c) i64;
extern fn zag_fs_close(fd: i32) callconv(.c) i32;
extern fn zag_fs_mkdir(path: [*]const u8, len: usize, mode: u32) callconv(.c) i32;

// ── Cap table primitives mirrored from runtime.zig ────────────────────
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

const O_WRONLY: u32 = 1;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;

fn capHandleType(c: Cap) HandleType {
    return @enumFromInt(@as(u4, @truncate((c.word0 >> 12) & 0xF)));
}

fn capPfPages(c: Cap) u64 {
    // page_frame field0 layout: bits 0..31 = page_count, bits 32..33 = sz.
    return c.field0 & 0xFFFFFFFF;
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

fn buildWord(num: u12, extra: u64) u64 {
    return (@as(u64, num) & 0xFFF) | (extra & ~@as(u64, 0xFFF));
}

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

// Find the SECOND page_frame (bundle) and SECOND port (done_port).
// Runtime.o consumes the first of each for fs_scratch + fs_port.
const Extras = struct {
    bundle_pf: u12 = 0,
    bundle_pages: u64 = 0,
    done_port: u12 = 0,
    have_bundle: bool = false,
    have_done: bool = false,
};

fn findExtras(cap_table_base: u64) Extras {
    var ex: Extras = .{};
    var pf_seen: u32 = 0;
    var pt_seen: u32 = 0;
    var slot: u32 = SLOT_FIRST_PASSED;
    while (slot < HANDLE_TABLE_MAX) : (slot += 1) {
        const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
        const c = tbl[slot];
        switch (capHandleType(c)) {
            .page_frame => {
                pf_seen += 1;
                if (pf_seen == 2) {
                    ex.bundle_pf = @truncate(slot);
                    ex.bundle_pages = capPfPages(c);
                    ex.have_bundle = true;
                }
            },
            .port => {
                pt_seen += 1;
                if (pt_seen == 2) {
                    ex.done_port = @truncate(slot);
                    ex.have_done = true;
                }
            },
            else => {},
        }
    }
    return ex;
}

fn mapBundle(bundle_pf: u12, pages: u64) ?[*]const u8 {
    const vmar_caps: u64 = (1 << 2) | (1 << 3); // r + w bits
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{ .v1 = vmar_caps, .v2 = props, .v3 = pages });
    if (cv.v1 < 16) return null;
    const vh: u12 = @truncate(cv.v1 & 0xFFF);
    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{ .v1 = vh, .v2 = 0, .v3 = bundle_pf });
    if (mp.v1 != 0) return null;
    return @ptrFromInt(cv.v2);
}

const KIND_FILE: u8 = 0;
const KIND_DIR: u8 = 1;
const KIND_END: u8 = 0xFF;

const FS_OP_MKDIR: u64 = 8;

// We need a small scratch path-buffer for null-termination when calling
// libc-style functions. Bundle paths are NOT null-terminated.
var path_scratch: [4096]u8 = @splat(0);

fn writeOneFile(path: []const u8, content: []const u8) bool {
    // openat needs raw ptr+len (no null term required for our wrapper).
    const fd = zag_fs_openat(path.ptr, path.len, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return false;
    if (content.len > 0) {
        const w = zag_fs_write(@intCast(fd), content.ptr, content.len, -1);
        if (w < 0 or @as(usize, @intCast(w)) != content.len) {
            _ = zag_fs_close(@intCast(fd));
            return false;
        }
    }
    return zag_fs_close(@intCast(fd)) == 0;
}

fn writeMkdir(path: []const u8) bool {
    const rc = zag_fs_mkdir(path.ptr, path.len, 0o755);
    // Treat EEXIST (-17) as success (the dir is already there).
    return rc == 0 or rc == -17;
}

pub fn main() void {
    _ = printf("[provisioner] alive\n");

    const cap_table_base = @import("std").os.zag.cap_table_base;
    const ex = findExtras(cap_table_base);
    if (!ex.have_bundle) {
        _ = printf("[provisioner] FATAL: no bundle pf in cap table\n");
        exit(1);
    }
    if (!ex.have_done) {
        _ = printf("[provisioner] WARN: no done_port; will exit without signal\n");
    }
    _ = printf("[provisioner] bundle_pf slot=%u pages=%llu\n", @as(c_uint, ex.bundle_pf), @as(c_ulonglong, ex.bundle_pages));

    const bundle_ptr = mapBundle(ex.bundle_pf, ex.bundle_pages) orelse {
        _ = printf("[provisioner] FATAL: mapBundle failed\n");
        exit(2);
    };

    var off: usize = 0;
    var n_files: usize = 0;
    var n_dirs: usize = 0;
    while (true) {
        const kind = bundle_ptr[off];
        off += 1;
        if (kind == KIND_END) break;
        // skip reserved
        off += 1;
        const path_len: usize = @as(usize, bundle_ptr[off]) | (@as(usize, bundle_ptr[off + 1]) << 8);
        off += 2;
        const content_len: usize =
            @as(usize, bundle_ptr[off]) |
            (@as(usize, bundle_ptr[off + 1]) << 8) |
            (@as(usize, bundle_ptr[off + 2]) << 16) |
            (@as(usize, bundle_ptr[off + 3]) << 24);
        off += 4;
        const path_ptr: [*]const u8 = bundle_ptr + off;
        off += path_len;
        const content_ptr: [*]const u8 = bundle_ptr + off;
        off += content_len;

        const path = path_ptr[0..path_len];
        // null-terminate path into scratch for printf
        {
            var i: usize = 0;
            while (i < path.len and i < path_scratch.len - 1) : (i += 1) {
                path_scratch[i] = path[i];
            }
            path_scratch[i] = 0;
        }
        if (kind == KIND_DIR) {
            if (!writeMkdir(path)) {
                _ = printf("[provisioner] FATAL: mkdir failed for %s\n", @as([*:0]const u8, @ptrCast(&path_scratch[0])));
                exit(4);
            }
            n_dirs += 1;
        } else if (kind == KIND_FILE) {
            const content = content_ptr[0..content_len];
            _ = printf("[prov] file %u %s (%u bytes)\n", @as(c_uint, @intCast(n_files)), @as([*:0]const u8, @ptrCast(&path_scratch[0])), @as(c_uint, @intCast(content.len)));
            if (!writeOneFile(path, content)) {
                _ = printf("[provisioner] FATAL: write failed for %s\n", @as([*:0]const u8, @ptrCast(&path_scratch[0])));
                exit(3);
            }
            n_files += 1;
        }
        if ((n_files + n_dirs) % 50 == 0 and (n_files + n_dirs) > 0) {
            _ = printf("[provisioner] progress: %u files / %u dirs\n", @as(c_uint, @intCast(n_files)), @as(c_uint, @intCast(n_dirs)));
        }
    }

    _ = printf("[provisioner] done: %u files / %u dirs\n", @as(c_uint, @intCast(n_files)), @as(c_uint, @intCast(n_dirs)));

    if (ex.have_done) {
        _ = printf("[provisioner] signaling done_port\n");
        _ = issueRaw(buildWord(SYS_SUSPEND, 0), .{
            .v1 = @as(u64, SLOT_INITIAL_EC),
            .v2 = @as(u64, ex.done_port),
        });
    }

    _ = printf("[provisioner] exiting\n");
    exit(0);
}
