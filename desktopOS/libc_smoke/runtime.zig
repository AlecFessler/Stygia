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

const std = @import("std");
pub const panic = std.debug.no_panic;

// ── Spec slots / syscall numbers ─────────────────────────────────────
const SLOT_SELF: u12 = 0;
const SLOT_INITIAL_EC: u12 = 1;
const SLOT_FIRST_PASSED: u32 = 3;
const HANDLE_TABLE_MAX: u32 = 4096;

const SYS_SUSPEND: u12 = 14;
const SYS_DELETE: u12 = 16;
const SYS_CREATE_CAPABILITY_DOMAIN: u12 = 19;
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
const O_DIRECTORY: u32 = 0o200000;

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
    bundle_pf: u12 = 0,
    bundle_pages: u64 = 0,
    have_com1: bool = false,
    have_fs: bool = false,
    have_bundle: bool = false,
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
                if (got_pfs == 0) {
                    inv.fs_scratch = @truncate(slot);
                } else if (got_pfs == 1) {
                    inv.bundle_pf = @truncate(slot);
                    inv.bundle_pages = c.field0 & 0xFFFFFFFF;
                    inv.have_bundle = true;
                }
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

// ── In-memory bundle (lib/std + lib/compiler_rt + extras) ────────────
//
// When zig_compiler is spawned, root_service hands it a read-only
// page_frame containing a flat blob produced by tools/make_lib_bundle.
// Each entry: u8 kind (0=file, 1=dir, 0xFF=end), u8 reserved,
// u16 path_len, u32 content_len, [path_len]u8, [content_len]u8.
// Building a small index up front lets zag_fs_openat serve hits in
// O(N) without re-walking the bundle on every call.
const BUNDLE_MAX_ENTRIES: usize = 2048;

const BundleEntry = extern struct {
    kind: u8,
    pad: [7]u8 = .{ 0, 0, 0, 0, 0, 0, 0 },
    path_off: u32, // byte offset into bundle blob
    path_len: u32,
    content_off: u32,
    content_len: u32,
};

var bundle_va: u64 = 0;
var bundle_entries: [BUNDLE_MAX_ENTRIES]BundleEntry = @splat(BundleEntry{
    .kind = 0xFF,
    .path_off = 0,
    .path_len = 0,
    .content_off = 0,
    .content_len = 0,
});
var bundle_count: usize = 0;

fn setupBundle() void {
    if (!inbound.have_bundle) return;
    const vmar_caps: u64 = (1 << 2) | (1 << 3); // r + w bits in VmarCap
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps,
        .v2 = props,
        .v3 = inbound.bundle_pages,
    });
    if (cv.v1 < 16) return;
    const vh: u12 = @truncate(cv.v1 & 0xFFF);
    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{
        .v1 = vh,
        .v2 = 0,
        .v3 = inbound.bundle_pf,
    });
    if (mp.v1 != 0) return;
    bundle_va = cv.v2;

    const blob: [*]const u8 = @ptrFromInt(bundle_va);
    var off: u32 = 0;
    var i: usize = 0;
    while (i < BUNDLE_MAX_ENTRIES) {
        const kind = blob[off];
        off += 1;
        if (kind == 0xFF) break;
        off += 1; // reserved
        const path_len: u32 =
            @as(u32, blob[off]) |
            (@as(u32, blob[off + 1]) << 8);
        off += 2;
        const content_len: u32 =
            @as(u32, blob[off]) |
            (@as(u32, blob[off + 1]) << 8) |
            (@as(u32, blob[off + 2]) << 16) |
            (@as(u32, blob[off + 3]) << 24);
        off += 4;
        bundle_entries[i] = .{
            .kind = kind,
            .path_off = off,
            .path_len = path_len,
            .content_off = off + path_len,
            .content_len = content_len,
        };
        off += path_len + content_len;
        i += 1;
    }
    bundle_count = i;
}

fn bundlePathEq(entry: BundleEntry, path: [*]const u8, len: usize) bool {
    if (entry.path_len != len) return false;
    const blob: [*]const u8 = @ptrFromInt(bundle_va);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (blob[entry.path_off + i] != path[i]) return false;
    }
    return true;
}

fn bundleLookup(path: [*]const u8, len: usize) ?usize {
    if (bundle_va == 0) return null;
    var i: usize = 0;
    while (i < bundle_count) : (i += 1) {
        if (bundle_entries[i].kind == 0 and bundlePathEq(bundle_entries[i], path, len)) {
            return i;
        }
    }
    return null;
}

fn bundleLookupDir(path: [*]const u8, len: usize) bool {
    if (bundle_va == 0) return false;
    var i: usize = 0;
    while (i < bundle_count) : (i += 1) {
        if (bundle_entries[i].kind == 1 and bundlePathEq(bundle_entries[i], path, len)) {
            return true;
        }
    }
    return false;
}

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
    setupBundle();
    setupCacheDirs();
}

// Only run for binaries that received a lib bundle pf (i.e. the
// in-Zag zig compiler). Any other client of fs (verify_fs, fs_smoke)
// shares io_scratch with siblings; issuing extra mkdirs from their
// zag_init would race against concurrent ops and corrupt path bytes
// in scratch.
fn setupCacheDirs() void {
    if (!inbound.have_fs) return;
    if (!inbound.have_bundle) return;
    _ = fsMkdir("/zigcache", 9, 0o755);
    _ = fsMkdir("/zigglobal", 10, 0o755);
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

// Spawn an ELF that's already in our filesystem (e.g. just-emitted
// /hello.elf from the compiler) as a fresh capability domain. Returns 0
// on success, non-zero on failure. Caller still needs to wait or exit
// after — the kernel doesn't merge process lifetimes.
export fn zag_spawn_elf_path(path_ptr: [*]const u8, path_len: usize) callconv(.c) i32 {
    // Open + stat the file first so we know how many pages we need.
    const fd = zag_fs_openat(AT_FDCWD, path_ptr, path_len, O_RDONLY, 0);
    if (fd < 0) return -1;
    defer _ = zag_fs_close(@intCast(fd));

    var st: Stat = .{};
    if (zag_fs_fstat(@intCast(fd), &st) != 0) return -2;
    const size: u64 = @intCast(st.size);
    if (size == 0) return -3;
    const pages: u64 = (size + 4095) / 4096;

    // Page_frame for the child's text/data. RWX because we don't parse
    // PHDRs to give the kernel a per-page-perm hint; the kernel reads
    // PT_LOADs from the ELF and applies real page perms during the
    // createCapabilityDomain map.
    const pf_caps_rwx: u64 = (1 << 2) | (1 << 3) | (1 << 4); // r | w | x
    const cpf = issueRaw(buildWord(SYS_CREATE_PAGE_FRAME, 0), .{
        .v1 = pf_caps_rwx,
        .v2 = 0,
        .v3 = pages,
    });
    if (cpf.v1 < 16) return -4;
    const new_pf: u12 = @truncate(cpf.v1 & 0xFFF);

    // Map the new pf rw into our address space so we can read the file
    // contents into it. After the copy we drop the VMAR (the pf still
    // exists, owned by us until createCapabilityDomain consumes it).
    // VmarCap bits: 0=move, 1=copy, 2=r, 3=w, 4=x — see libz/caps.zig.
    const vmar_caps_rw: u64 = (1 << 2) | (1 << 3); // r | w
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps_rw,
        .v2 = 0b011, // anon-pf-backed VMAR
        .v3 = pages,
    });
    if (cv.v1 < 16) {
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, new_pf) });
        return -5;
    }
    const vmar: u12 = @truncate(cv.v1 & 0xFFF);
    const vmar_va: u64 = cv.v2;

    const pairs = [_]u64{ 0, @as(u64, new_pf) };
    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{
        .v1 = @as(u64, vmar),
        .v2 = pairs[0],
        .v3 = pairs[1],
    });
    if (mp.v1 != 0) {
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, vmar) });
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, new_pf) });
        return -6;
    }

    const dst: [*]u8 = @ptrFromInt(vmar_va);
    var off: u64 = 0;
    while (off < size) {
        const want: u64 = @min(size - off, 32 * 1024);
        const r = zag_fs_read(@intCast(fd), dst + off, @intCast(want), @intCast(off));
        if (r <= 0) {
            _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, vmar) });
            _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, new_pf) });
            return -7;
        }
        off += @intCast(r);
    }
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, vmar) });

    // Build the passed-handles list. Pass COM1 with copy semantics so
    // the parent (the compiler) can keep using it for diagnostic prints.
    // PassedHandle layout: [handle_id (12) | reserved (4) | caps (16) | move (1) | ...]
    const DEV_COPY: u16 = 1 << 1;
    var passed: [8]u64 = undefined;
    var pc: usize = 0;
    if (inbound.have_com1) {
        passed[pc] = @as(u64, inbound.com1) | (@as(u64, DEV_COPY) << 16);
        pc += 1;
    }

    // Child SelfCap: minimal — createVmar (for COM1 mapping) + delete-self timer.
    // No crcd; the child can't spawn further children.
    const CREC: u16 = 1 << 1;
    const CRVR: u16 = 1 << 2;
    const CRPF: u16 = 1 << 3;
    const CRPT: u16 = 1 << 5;
    const child_self: u64 = CREC | CRVR | CRPF | CRPT;
    // Permissive ceilings; kernel intersects with our domain's existing
    // ceilings so we can't actually exceed our own.
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    var regs: Regs = .{
        .v1 = child_self,
        .v2 = ceilings_inner,
        .v3 = ceilings_outer,
        .v4 = @as(u64, new_pf),
        .v5 = 0, // affinity = any core
    };
    if (pc >= 1) regs.v6 = passed[0];
    if (pc >= 2) regs.v7 = passed[1];
    if (pc >= 3) regs.v8 = passed[2];
    if (pc >= 4) regs.v9 = passed[3];
    const r = issueRaw(buildWord(SYS_CREATE_CAPABILITY_DOMAIN, 0), regs);
    if (r.v1 == 0) return -8;
    return 0;
}

// ── fd table — (path, pos) on top of stateless fs_ops ────────────────
//
// Three parallel tables + dir_fd path lookup:
//   - fdtab:        FDs in [FD_BASE, FD_BASE+MAX_OPEN) for fs IPC files
//   - bundle_fdtab: FDs in [BUNDLE_FD_BASE, BUNDLE_FD_BASE+MAX_BUNDLE_OPEN)
//                   for in-memory bundle reads (no IPC).
//   - synthetic dir fds in [DIR_FD_BASE, DIR_FD_BASE+MAX_DIR_OPEN) — one
//     per opened directory; we store the path so dir-fd-relative
//     openat/mkdirat calls can be composed to absolute paths.
const MAX_OPEN: usize = 256;
const FD_BASE: i32 = 100; // sit above stdin/stdout/stderr
const FD_PATH_MAX: usize = 256;
const MAX_BUNDLE_OPEN: usize = 1024;
const BUNDLE_FD_BASE: i32 = 1000;
const SYNTHETIC_DIR_FD: i32 = 9000; // for "/" only — pre-seeded
const DIR_FD_BASE: i32 = 5000;
const MAX_DIR_OPEN: usize = 256;
const AT_FDCWD: i32 = -100;
// Shim: cache paths return a "discard" fd. Writes succeed silently
// (data dropped); reads return EOF immediately. Compiler will then
// always cache-miss + recompute, but each cache op avoids the fs
// IPC throughput cap (~100 ms per op).
const DISCARD_FD: i32 = 7000;

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

const BundleFd = extern struct {
    in_use: u8 = 0,
    pad: [7]u8 = .{ 0, 0, 0, 0, 0, 0, 0 },
    entry_idx: u32 = 0,
    pad2: u32 = 0,
    pos: u64 = 0,
};
var bundle_fdtab: [MAX_BUNDLE_OPEN]BundleFd = @splat(BundleFd{});

const DirFd = extern struct {
    in_use: u8 = 0,
    pad: [7]u8 = .{ 0, 0, 0, 0, 0, 0, 0 },
    path_len: u64 = 0,
    path: [FD_PATH_MAX]u8 = @splat(0),
};
var dir_fdtab: [MAX_DIR_OPEN]DirFd = @splat(DirFd{});

fn allocDirFd(path: [*]const u8, len: usize) i32 {
    var i: usize = 0;
    while (i < MAX_DIR_OPEN) : (i += 1) {
        if (dir_fdtab[i].in_use == 0) {
            dir_fdtab[i].in_use = 1;
            const cap = if (len > FD_PATH_MAX) FD_PATH_MAX else len;
            var j: usize = 0;
            while (j < cap) : (j += 1) dir_fdtab[i].path[j] = path[j];
            dir_fdtab[i].path_len = cap;
            return DIR_FD_BASE + @as(i32, @intCast(i));
        }
    }
    return -@as(i32, @intCast(EMFILE));
}

fn dirFdLookup(fd: i32) ?*DirFd {
    if (fd < DIR_FD_BASE) return null;
    const idx: usize = @intCast(fd - DIR_FD_BASE);
    if (idx >= MAX_DIR_OPEN) return null;
    if (dir_fdtab[idx].in_use == 0) return null;
    return &dir_fdtab[idx];
}

// Compose dir_fd's stored path + "/" + sub_path into composed_buf,
// returning the slice. If dir_fd is AT_FDCWD or unknown OR sub_path is
// absolute, returns sub_path[0..sub_len] as-is.
var composed_buf: [FS_PATH_MAX]u8 = @splat(0);
var abs_buf: [FS_PATH_MAX]u8 = @splat(0);

fn ensureAbsolute(p: []const u8) []const u8 {
    if (p.len > 0 and p[0] == '/') return p;
    if (p.len + 1 > FS_PATH_MAX) return p;
    abs_buf[0] = '/';
    var i: usize = 0;
    while (i < p.len) : (i += 1) abs_buf[i + 1] = p[i];
    return abs_buf[0 .. p.len + 1];
}
fn composePath(dir_fd: i32, sub_path: [*]const u8, sub_len: usize) []const u8 {
    if (sub_len > 0 and sub_path[0] == '/') return sub_path[0..sub_len];
    // AT_FDCWD with relative path → treat as if cwd is "/" so the
    // bundle / fs lookups can match. The compiler often passes paths
    // like "ziglib/std/std.zig" or "hello.zig" with AT_FDCWD when
    // joining cwd ("" on Zag) + sub_path.
    if (dir_fd == AT_FDCWD) return ensureAbsolute(sub_path[0..sub_len]);
    if (dir_fd == SYNTHETIC_DIR_FD) {
        // SYNTHETIC_DIR_FD represents "/"; concat as "/sub".
        composed_buf[0] = '/';
        var j: usize = 0;
        while (j < sub_len and j + 1 < FS_PATH_MAX) : (j += 1) composed_buf[j + 1] = sub_path[j];
        return composed_buf[0 .. 1 + sub_len];
    }
    const d = dirFdLookup(dir_fd) orelse return sub_path[0..sub_len];
    const dlen: usize = @intCast(d.path_len);
    var i: usize = 0;
    while (i < dlen and i < FS_PATH_MAX) : (i += 1) composed_buf[i] = d.path[i];
    if (dlen > 0 and composed_buf[dlen - 1] != '/') {
        if (dlen + 1 < FS_PATH_MAX) {
            composed_buf[dlen] = '/';
            var j: usize = 0;
            while (j < sub_len and dlen + 1 + j < FS_PATH_MAX) : (j += 1) composed_buf[dlen + 1 + j] = sub_path[j];
            return composed_buf[0 .. dlen + 1 + sub_len];
        }
    }
    var j: usize = 0;
    while (j < sub_len and dlen + j < FS_PATH_MAX) : (j += 1) composed_buf[dlen + j] = sub_path[j];
    return composed_buf[0 .. dlen + sub_len];
}

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

fn allocBundleFd(entry_idx: u32) i32 {
    var i: usize = 0;
    while (i < MAX_BUNDLE_OPEN) : (i += 1) {
        if (bundle_fdtab[i].in_use == 0) {
            bundle_fdtab[i].in_use = 1;
            bundle_fdtab[i].entry_idx = entry_idx;
            bundle_fdtab[i].pos = 0;
            return BUNDLE_FD_BASE + @as(i32, @intCast(i));
        }
    }
    return -@as(i32, @intCast(EMFILE));
}

fn bundleFdLookup(fd: i32) ?*BundleFd {
    if (fd < BUNDLE_FD_BASE) return null;
    const idx: usize = @intCast(fd - BUNDLE_FD_BASE);
    if (idx >= MAX_BUNDLE_OPEN) return null;
    if (bundle_fdtab[idx].in_use == 0) return null;
    return &bundle_fdtab[idx];
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

// Debug trace of every openat call — prints "[ot] flags=NNN path\n"
// to COM1. Helps narrow down which file open is failing during the
// in-Zag compile bringup.
fn debugOpenTrace(path: [*]const u8, len: usize, flags: u32) void {
    if (com1_sink == null) return;
    const sink = com1_sink.?;
    const tag = "[ot] flags=";
    var i: usize = 0;
    while (i < tag.len) : (i += 1) sink[0] = tag[i];
    var shift: u5 = 12;
    while (true) {
        const nib: u32 = (flags >> shift) & 0xF;
        const c: u8 = if (nib < 10) '0' + @as(u8, @intCast(nib)) else 'a' + @as(u8, @intCast(nib - 10));
        sink[0] = c;
        if (shift == 0) break;
        shift -= 4;
    }
    sink[0] = ' ';
    var j: usize = 0;
    while (j < len) : (j += 1) sink[0] = path[j];
    sink[0] = '\n';
}

fn debugReturn(label: []const u8, code: u64) void {
    if (com1_sink == null) return;
    const sink = com1_sink.?;
    const tag = "[ret] ";
    var i: usize = 0;
    while (i < tag.len) : (i += 1) sink[0] = tag[i];
    var k: usize = 0;
    while (k < label.len) : (k += 1) sink[0] = label[k];
    sink[0] = '=';
    var shift: u6 = 60;
    while (true) {
        const nib: u64 = (code >> shift) & 0xF;
        const c: u8 = if (nib < 10) '0' + @as(u8, @intCast(nib)) else 'a' + @as(u8, @intCast(nib - 10));
        sink[0] = c;
        if (shift == 0) break;
        shift -= 4;
    }
    sink[0] = '\n';
}

// ── libc fs hooks (the contract posix_io.zig consumes) ───────────────
//
//   negative return = -errno; non-negative = success value.

fn isCachePath(p: []const u8) bool {
    if (p.len < 10) return false;
    if (p[0] == '/' and p[1] == 'z' and p[2] == 'i' and p[3] == 'g') {
        // /zigcache/* /zigglobal/*
        if (p.len >= 10 and p[4] == 'c' and p[5] == 'a' and p[6] == 'c' and
            p[7] == 'h' and p[8] == 'e' and p[9] == '/') return true;
        if (p.len >= 11 and p[4] == 'g' and p[5] == 'l' and p[6] == 'o' and
            p[7] == 'b' and p[8] == 'a' and p[9] == 'l' and p[10] == '/') return true;
    }
    return false;
}

export fn zag_fs_openat(dir_fd: i32, path_in: [*]const u8, len_in: usize, flags: u32, mode: u32) callconv(.c) i64 {
    const composed = composePath(dir_fd, path_in, len_in);
    const path: [*]const u8 = composed.ptr;
    const len: usize = composed.len;
    debugOpenTrace(path, len, flags);
    // Synthetic dir handle for "/" — that fd is global.
    if (len == 1 and path[0] == '/') {
        return @intCast(SYNTHETIC_DIR_FD);
    }
    // Cache paths → silent discard fd (skip fs IPC for throughput).
    if (isCachePath(composed)) {
        const want_create = (flags & O_CREAT) != 0;
        const want_dir = (flags & O_DIRECTORY) != 0;
        if (want_dir) return allocDirFd(path, len);
        if (!want_create and (flags & (O_WRONLY | O_RDWR)) == 0) {
            return -ENOENT;
        }
        return @intCast(DISCARD_FD);
    }
    // Bundle dir? Allocate a per-dir synthetic fd so subsequent
    // dir-fd-relative openats compose to absolute paths.
    if (bundleLookupDir(path, len)) {
        return allocDirFd(path, len);
    }
    // Bundle path? Read-only; reject write modes with EACCES.
    if (bundleLookup(path, len)) |idx| {
        const want_write = (flags & (O_WRONLY | O_RDWR)) != 0;
        if (want_write) return -EACCES;
        const fd = allocBundleFd(@intCast(idx));
        return @intCast(fd);
    }
    if (!inbound.have_fs) return -ENOSYS;
    const exists = fsLookup(path, len);
    const want_create = (flags & O_CREAT) != 0;
    const want_excl = (flags & O_EXCL) != 0;
    const want_dir = (flags & O_DIRECTORY) != 0;
    if (!exists and !want_create) return -ENOENT;
    if (exists and want_create and want_excl) return -EEXIST;
    // Caller asked for a dir handle (O_DIRECTORY) and the path exists —
    // hand back a per-dir synthetic fd so future dir-fd-relative
    // openat/mkdirat compose to absolute paths.
    if (want_dir and exists) {
        return allocDirFd(path, len);
    }
    if (!exists) {
        const cf_status = fsCreateFile(path, len, mode);
        if (cf_status != 0) {
            debugReturn("create_file failed", cf_status);
            return -EIO;
        }
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
    if (fd == DISCARD_FD) {
        _ = .{ buf, len, off };
        return 0; // EOF
    }
    if (len == 0) return 0;
    if (bundleFdLookup(fd)) |bf| {
        const entry = bundle_entries[bf.entry_idx];
        const start: u64 = if (off < 0) bf.pos else @intCast(off);
        if (start >= entry.content_len) return 0;
        const avail: u64 = entry.content_len - start;
        const want: u64 = if (len > avail) avail else len;
        const blob: [*]const u8 = @ptrFromInt(bundle_va);
        const src: [*]const u8 = blob + entry.content_off + start;
        var i: u64 = 0;
        while (i < want) : (i += 1) {
            buf[@as(usize, @intCast(i))] = src[@as(usize, @intCast(i))];
        }
        if (off < 0) bf.pos = start + want;
        return @intCast(want);
    }
    if (!inbound.have_fs) return -ENOSYS;
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
    if (fd == DISCARD_FD) {
        _ = .{ buf, off };
        return @intCast(len); // pretend full write
    }
    if (bundleFdLookup(fd)) |_| return -EACCES; // bundle is read-only
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
    if (fd == SYNTHETIC_DIR_FD or fd == DISCARD_FD) return 0;
    if (dirFdLookup(fd)) |d| {
        d.in_use = 0;
        d.path_len = 0;
        return 0;
    }
    if (bundleFdLookup(fd)) |bf| {
        bf.in_use = 0;
        bf.entry_idx = 0;
        bf.pos = 0;
        return 0;
    }
    const f = fdLookup(fd) orelse return -@as(i32, @intCast(EBADF));
    f.in_use = 0;
    f.path_len = 0;
    f.pos = 0;
    f.flags = 0;
    return 0;
}

export fn zag_fs_lseek(fd: i32, off: i64, whence: c_int) callconv(.c) i64 {
    if (fd == DISCARD_FD) {
        _ = .{ off, whence };
        return 0;
    }
    if (bundleFdLookup(fd)) |bf| {
        const entry = bundle_entries[bf.entry_idx];
        const new_pos: i64 = switch (whence) {
            0 => off,
            1 => @as(i64, @intCast(bf.pos)) + off,
            2 => @as(i64, @intCast(entry.content_len)) + off,
            else => return -EINVAL,
        };
        if (new_pos < 0) return -EINVAL;
        bf.pos = @intCast(new_pos);
        return @intCast(bf.pos);
    }
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
    if (fd == DISCARD_FD) {
        fillStat(st, 0);
        return 0;
    }
    if (bundleFdLookup(fd)) |bf| {
        fillStat(st, bundle_entries[bf.entry_idx].content_len);
        return 0;
    }
    const f = fdLookup(fd) orelse return -@as(i32, @intCast(EBADF));
    const sz = fsStatSize(@ptrCast(&f.path), f.path_len) orelse return -@as(i32, @intCast(EIO));
    fillStat(st, sz);
    return 0;
}

export fn zag_fs_stat(path: [*]const u8, len: usize, st: *anyopaque) callconv(.c) i32 {
    if (bundleLookup(path, len)) |idx| {
        fillStat(st, bundle_entries[idx].content_len);
        return 0;
    }
    if (bundleLookupDir(path, len)) {
        const out: *Stat = @ptrCast(@alignCast(st));
        out.* = .{};
        out.mode = 0o040755; // S_IFDIR | 0755
        return 0;
    }
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    const sz = fsStatSize(path, len) orelse return -@as(i32, @intCast(ENOENT));
    fillStat(st, sz);
    return 0;
}

export fn zag_fs_unlink(path: [*]const u8, len: usize) callconv(.c) i32 {
    return zag_fs_unlinkat(AT_FDCWD, path, len);
}

export fn zag_fs_unlinkat(dir_fd: i32, path_in: [*]const u8, len_in: usize) callconv(.c) i32 {
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    const composed = composePath(dir_fd, path_in, len_in);
    const status = fsUnlink(composed.ptr, composed.len);
    if (status == 0) return 0;
    if (status == 1) return -@as(i32, @intCast(ENOENT));
    return -@as(i32, @intCast(EIO));
}

export fn zag_fs_mkdir(path: [*]const u8, len: usize, mode: u32) callconv(.c) i32 {
    return zag_fs_mkdirat(AT_FDCWD, path, len, mode);
}

export fn zag_fs_mkdirat(dir_fd: i32, path_in: [*]const u8, len_in: usize, mode: u32) callconv(.c) i32 {
    const composed = composePath(dir_fd, path_in, len_in);
    if (isCachePath(composed)) return 0; // pretend mkdir under cache always succeeds
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    const status = fsMkdir(composed.ptr, composed.len, mode);
    if (status == 0) return 0;
    if (status == 7) return -17; // Status.exists → EEXIST
    if (status == 1) return -@as(i32, @intCast(ENOENT));
    if (status == 2) return -20; // Status.not_a_directory → ENOTDIR
    if (status == 12) return -22; // Status.bad_path → EINVAL
    return -@as(i32, @intCast(EIO));
}

export fn zag_fs_statat(dir_fd: i32, path_in: [*]const u8, len_in: usize, st: *anyopaque) callconv(.c) i32 {
    const composed = composePath(dir_fd, path_in, len_in);
    // Cache paths: report ENOENT for files, success-as-dir for /zigcache or /zigglobal themselves.
    if (isCachePath(composed)) {
        return -@as(i32, @intCast(ENOENT));
    }
    if (bundleLookup(composed.ptr, composed.len)) |idx| {
        fillStat(st, bundle_entries[idx].content_len);
        return 0;
    }
    if (bundleLookupDir(composed.ptr, composed.len) or
        (composed.len == 1 and composed.ptr[0] == '/'))
    {
        const out: *Stat = @ptrCast(@alignCast(st));
        out.* = .{};
        out.mode = 0o040755;
        return 0;
    }
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    const sz = fsStatSize(composed.ptr, composed.len) orelse return -@as(i32, @intCast(ENOENT));
    fillStat(st, sz);
    return 0;
}

export fn zag_fs_truncate(path: [*]const u8, len: usize, size: i64) callconv(.c) i32 {
    if (!inbound.have_fs) return -@as(i32, @intCast(ENOSYS));
    if (size < 0) return -@as(i32, @intCast(EINVAL));
    return if (fsTruncate(path, len, @intCast(size)) == 0) 0 else -@as(i32, @intCast(EIO));
}

export fn zag_fs_ftruncate(fd: i32, size: i64) callconv(.c) i32 {
    if (fd == DISCARD_FD) return 0;
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
    debugReturn("mmap_anon pages", pages);
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
    debugReturn("mmap_anon base", base);
    return base;
}

export fn zag_munmap(addr: u64, pages: usize) callconv(.c) i32 {
    _ = pages;
    const t = heapTableTake(addr) orelse return -1;
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, t.vmar) });
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, t.pf) });
    return 0;
}
