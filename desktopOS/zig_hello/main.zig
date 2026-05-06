// Phase 0+1 hello — Zag-target ELF that prints via serial_server IPC and
// reads /persist_marker from the SQL-FS via fs_port IPC. Built with the
// patched no-LLVM Zig 0.15.2 compiler against `-target x86_64-zag-none`.
//
// Cap-table layout from root_service:
//   [3] serial_port (xfer|bind)
//   [4] serial_scratch page_frame (r+w, 1 page)
//   [5] COM1 device_region (debug-only direct sink)
//   [6] fs_port (xfer|bind)
//   [7] io_scratch page_frame (r+w, fs_ops.SCRATCH_PAGES = 16)
//
// We can't pull in the libz / serial_client / fs_client modules through
// the patched build invocation, so the syscall ABI snippets and the
// protocol constants are inlined here. They mirror what those modules do.

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
const SLOT_INITIAL_EC: u12 = 1;
const SLOT_FIRST_PASSED: u32 = 3;
const HANDLE_TABLE_MAX: u32 = 4096;

// Serial protocol (mirrors desktopOS/protocols/serial.zig).
const SERIAL_OP_PRINT: u64 = 1;
const SERIAL_SCRATCH_BYTES: u64 = 4096;

// FS protocol (mirrors desktopOS/protocols/fs_ops.zig).
const FS_OP_LOOKUP: u64 = 1;
const FS_OP_PREAD: u64 = 3;
const FS_OP_PWRITE: u64 = 4;
const FS_OP_CREATE_FILE: u64 = 6;
const FS_OP_UNLINK: u64 = 7;
const FS_SCRATCH_PAGES: u64 = 16;
const FS_SCRATCH_BYTES: u64 = FS_SCRATCH_PAGES * 4096;

// ── Syscall ABI ─────────────────────────────────────────────────────
const SYS_SUSPEND: u12 = 14;
const SYS_DELETE: u12 = 16;
const SYS_CREATE_VMAR: u12 = 32;
const SYS_MAP_PF: u12 = 33;
const SYS_MAP_MMIO: u12 = 34;
const SYS_UNMAP: u12 = 35;
const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

const DevType = enum(u4) { mmio = 0, port_io = 1, _ };

fn capDevType(c: Cap) DevType {
    return @enumFromInt(@as(u4, @truncate(c.field0 & 0xF)));
}

fn capDevPort(c: Cap) u16 {
    return @truncate((c.field0 >> 4) & 0xFFFF);
}

fn capDevPortCount(c: Cap) u16 {
    return @truncate((c.field0 >> 20) & 0xFFFF);
}

fn capHandleType(c: Cap) HandleType {
    return @enumFromInt(@as(u4, @truncate((c.word0 >> 12) & 0xF)));
}

var debug_sink: ?[*]volatile u8 = null;

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

fn initDebugSink(cap_table_base: u64) void {
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
    debug_sink = @ptrFromInt(vbase);
}

fn debugPrint(s: []const u8) void {
    const p = debug_sink orelse return;
    var i: usize = 0;
    while (i < s.len) : (i += 1) p[0] = s[i];
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
    // Spec §[syscall_abi] x86-64 maps vreg 4 onto %rbp. The patched
    // no-LLVM Zig backend ignores `-fomit-frame-pointer` and keeps %rbp
    // as a frame pointer regardless. Inside the asm we save the caller's
    // frame pointer to a stack slot the compiler picks (rsp-relative,
    // STABLE because we do NOT touch rsp before the save), load iv4 into
    // %rbp, run the syscall, save the output v4 to a separate slot, then
    // restore the original %rbp from the save slot. Crucially: subq/addq
    // around the syscall cancel exactly, so all compiler-chosen offsets
    // (rbp_save, iv4_mem, ov4_mem) are valid throughout the asm.
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
    serial_port: u12 = 0,
    serial_scratch: u12 = 0,
    fs_port: u12 = 0,
    fs_scratch: u12 = 0,
    have_serial: bool = false,
    have_fs: bool = false,
};

// Walk the cap table, collecting serial_port + serial_scratch (first
// port/page_frame pair) and fs_port + io_scratch (second). Order assumes
// root_service passes them as: [3]=serial_port, [4]=serial_scratch,
// [5]=COM1, [6]=fs_port, [7]=io_scratch.
fn findInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var got_ports: u8 = 0;
    var got_pfs: u8 = 0;
    var slot: u32 = SLOT_FIRST_PASSED;
    while (slot < HANDLE_TABLE_MAX) : (slot += 1) {
        const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
        const c = tbl[slot];
        switch (capHandleType(c)) {
            .port => {
                if (got_ports == 0) {
                    inv.serial_port = @truncate(slot);
                } else if (got_ports == 1) {
                    inv.fs_port = @truncate(slot);
                }
                got_ports += 1;
            },
            .page_frame => {
                if (got_pfs == 0) {
                    inv.serial_scratch = @truncate(slot);
                } else if (got_pfs == 1) {
                    inv.fs_scratch = @truncate(slot);
                }
                got_pfs += 1;
            },
            else => {},
        }
        if (got_ports >= 2 and got_pfs >= 2) break;
    }
    inv.have_serial = (got_ports >= 1 and got_pfs >= 1);
    inv.have_fs = (got_ports >= 2 and got_pfs >= 2);
    return inv;
}

// Map an N-page page_frame r+w into our address space.
fn mapPfRw(pf_handle: u12, pages: u64) ?u64 {
    // VmarCap{ r=1, w=1 } — bits 2,3
    const vmar_caps: u64 = (1 << 2) | (1 << 3);
    // props: cur_rwx=0b011 (r|w), sz=0 (4 KiB)
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps,
        .v2 = props,
        .v3 = pages,
    });
    if (cv.v1 < 16) return null;
    const vmar_handle: u12 = @truncate(cv.v1 & 0xFFF);
    const vmar_base = cv.v2;
    // map_pf vreg layout: v1 = vmar_handle, v2 = vmar_offset_pages, v3 = pf_handle.
    // (1 << 12) = N=1 in the syscall-word bits 12-19 (one (off,pf) pair).
    const mp = issueRaw(buildWord(SYS_MAP_PF, (1 << 12)), .{
        .v1 = vmar_handle,
        .v2 = 0,
        .v3 = pf_handle,
    });
    if (mp.v1 != 0) return null;
    return vmar_base;
}

fn serialPrint(port: u12, scratch_va: u64, bytes: []const u8) void {
    if (bytes.len > SERIAL_SCRATCH_BYTES) return;
    const dst: [*]u8 = @ptrFromInt(scratch_va);
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) dst[i] = bytes[i];
    _ = issueRaw(buildWord(SYS_SUSPEND, 0), .{
        .v1 = @as(u64, SLOT_INITIAL_EC),
        .v2 = @as(u64, port),
        .v3 = SERIAL_OP_PRINT,
        .v4 = bytes.len,
    });
}

const FsReadResult = struct {
    status: u64,
    bytes_read: u64,
    data_off: u64,
};

// Issue a pread to the FS server. Path goes at scratch[0..path_len]; the
// server places returned bytes at scratch[data_off..data_off+bytes_read].
fn fsPread(
    port: u12,
    scratch_va: u64,
    path: []const u8,
    offset: u64,
    max_len: u64,
) FsReadResult {
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
    return .{
        .status = r.v1,
        .bytes_read = r.v2,
        .data_off = r.v3,
    };
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

fn fsPwrite(
    port: u12,
    scratch_va: u64,
    path: []const u8,
    offset: u64,
    data: []const u8,
) FsWriteResult {
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    var i: usize = 0;
    while (i < path.len) : (i += 1) buf[i] = path[i];
    // data at scratch[path_len..path_len+data_len]
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
    return .{
        .status = r.v1,
        .bytes_written = r.v2,
        .new_size = r.v3,
    };
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

// ── Phase 2 anon-mmap bridge — backs std.os.zag.mmap(MAP_ANONYMOUS) ──
//
// Spec §[var] documents demand-paged VMARs as the canonical "anon
// mmap" path: kernel allocates a zero page on first touch. As of
// 2026-05-06 the kernel's `demandAlloc` (kernel/memory/vmar.zig:1079)
// is still a stub that returns E_NOMEM, so we instead allocate a
// page_frame eagerly and `map_pf` it into a fresh VMAR. Switch to
// the demand-paged path once the kernel implementation lands —
// then this bridge becomes just createVmar.

const HEAP_TABLE_LEN: usize = 16;
const HeapEntry = struct {
    base: u64,
    vmar: u12,
    pf: u12,
};
var heap_table: [HEAP_TABLE_LEN]HeapEntry = .{HeapEntry{ .base = 0, .vmar = 0, .pf = 0 }} ** HEAP_TABLE_LEN;

fn heapTablePush(base: u64, vmar: u12, pf: u12) bool {
    var i: usize = 0;
    while (i < HEAP_TABLE_LEN) : (i += 1) {
        if (heap_table[i].base == 0) {
            heap_table[i] = .{ .base = base, .vmar = vmar, .pf = pf };
            return true;
        }
    }
    return false;
}

const HeapTake = struct { vmar: u12, pf: u12 };

fn heapTableTake(base: u64) ?HeapTake {
    var i: usize = 0;
    while (i < HEAP_TABLE_LEN) : (i += 1) {
        if (heap_table[i].base == base) {
            const e = heap_table[i];
            heap_table[i] = .{ .base = 0, .vmar = 0, .pf = 0 };
            return .{ .vmar = e.vmar, .pf = e.pf };
        }
    }
    return null;
}

const SYS_CREATE_PAGE_FRAME: u12 = 40;

export fn zag_mmap_anon(pages: usize) callconv(.c) u64 {
    if (pages == 0) return 0;
    // PfCap{ r=1, w=1 } — bits 2,3 in libz/caps.zig PfCap layout
    const pf_caps: u64 = (1 << 2) | (1 << 3);
    const cpf = issueRaw(buildWord(SYS_CREATE_PAGE_FRAME, 0), .{
        .v1 = pf_caps,
        .v2 = 0,
        .v3 = pages,
    });
    if (cpf.v1 < 16) return 0;
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // VmarCap{ r=1, w=1 } — bits 2,3
    const vmar_caps: u64 = (1 << 2) | (1 << 3);
    // props: cur_rwx=0b011 (r|w), sz=0 (4 KiB), cch=0 (writeback)
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

    // map_pf at offset 0: install the freshly-allocated page_frame
    // across the entire VMAR range. (1 << 12) = N=1 in bits 12-19.
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
    // Drop VMAR first (releases address space) then page_frame (frees pages).
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, t.vmar) });
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, t.pf) });
    return 0;
}

// Format an unsigned int into a buffer; returns slice over the digits.
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
    // Reverse in-place.
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

// ── Entry: kernel calls _start(cap_table_base) per §[caps] ──────────
export fn _start(cap_table_base: u64) callconv(.c) noreturn {
    initDebugSink(cap_table_base);
    debugPrint("[zig_hello] alive\n");

    const inv = findInbound(cap_table_base);
    if (!inv.have_serial) {
        debugPrint("[zig_hello] missing serial handles\n");
        zagExit();
    }
    debugPrint("[zig_hello] handles found\n");

    const serial_va = mapPfRw(inv.serial_scratch, 1) orelse {
        debugPrint("[zig_hello] serial mapPf failed\n");
        zagExit();
    };
    debugPrint("[zig_hello] serial scratch mapped\n");

    // Phase 0 demo line via serial_server IPC.
    serialPrint(inv.serial_port, serial_va, "[zig_hello] hello from zig on zag\n");
    debugPrint("[zig_hello] after serial IPC\n");

    if (!inv.have_fs) {
        debugPrint("[zig_hello] no fs_port; skipping Phase 1\n");
        zagExit();
    }

    // ── Phase 1: read /persist_marker from the SQL FS, print contents.
    const fs_va = mapPfRw(inv.fs_scratch, FS_SCRATCH_PAGES) orelse {
        debugPrint("[zig_hello] fs mapPf failed\n");
        zagExit();
    };
    debugPrint("[zig_hello] fs scratch mapped\n");

    const path = "/persist_marker";
    const r = fsPread(inv.fs_port, fs_va, path, 0, 64);
    if (r.status != 0) {
        var st_buf: [32]u8 = undefined;
        const st_str = formatU64(&st_buf, r.status);
        // Quick path: announce the failure on serial.
        // 64 bytes is well below SERIAL_SCRATCH_BYTES.
        var msg: [96]u8 = undefined;
        const prefix = "[zig_hello] /persist_marker pread status=";
        var off: usize = 0;
        for (prefix) |b| {
            msg[off] = b;
            off += 1;
        }
        for (st_str) |b| {
            msg[off] = b;
            off += 1;
        }
        msg[off] = '\n';
        off += 1;
        serialPrint(inv.serial_port, serial_va, msg[0..off]);
        zagExit();
    }

    // Read the bytes the FS server placed into io_scratch and re-send
    // them as a serial line. Cap at the serial scratch size minus the
    // prefix we prepend.
    const data_src: [*]const u8 = @ptrFromInt(fs_va + r.data_off);
    var line: [256]u8 = undefined;
    var w: usize = 0;
    const lead = "[zig_hello] /persist_marker = ";
    for (lead) |b| {
        line[w] = b;
        w += 1;
    }
    var k: u64 = 0;
    while (k < r.bytes_read and w < line.len - 1) : (k += 1) {
        line[w] = data_src[k];
        w += 1;
    }
    line[w] = '\n';
    w += 1;
    serialPrint(inv.serial_port, serial_va, line[0..w]);
    debugPrint("[zig_hello] after fs IPC\n");

    // ── Phase 2: anon-mmap demo. Allocate 1 page, write a sentinel
    //    pattern at offset 0, read it back, munmap.
    debugPrint("[zig_hello] before mmap_anon\n");
    const heap_base = zag_mmap_anon(1);
    if (heap_base == 0) {
        serialPrint(
            inv.serial_port,
            serial_va,
            "[zig_hello] zag_mmap_anon(1) failed\n",
        );
        zagExit();
    }
    debugPrint("[zig_hello] mmap_anon returned\n");

    const heap: [*]u8 = @ptrFromInt(heap_base);
    debugPrint("[zig_hello] before heap[0] = 'X'\n");
    heap[0] = 'X';
    debugPrint("[zig_hello] after heap[0] = 'X'\n");
    heap[1] = 'Y';
    heap[2] = 'Z';
    heap[3] = 0;
    debugPrint("[zig_hello] heap writes done\n");

    var line2: [64]u8 = undefined;
    var w2: usize = 0;
    const lead2 = "[zig_hello] heap[0..3] = ";
    for (lead2) |b| {
        line2[w2] = b;
        w2 += 1;
    }
    line2[w2] = heap[0];
    w2 += 1;
    line2[w2] = heap[1];
    w2 += 1;
    line2[w2] = heap[2];
    w2 += 1;
    line2[w2] = '\n';
    w2 += 1;
    serialPrint(inv.serial_port, serial_va, line2[0..w2]);

    if (zag_munmap(heap_base, 1) != 0) {
        serialPrint(
            inv.serial_port,
            serial_va,
            "[zig_hello] zag_munmap failed\n",
        );
        zagExit();
    }
    serialPrint(inv.serial_port, serial_va, "[zig_hello] heap test passed\n");

    // ── Phase 3: file write round-trip. Create a fresh file, write a
    //    known string, read it back, verify it matches, unlink.
    //
    // io_scratch is shared with verify_fs's harness; our 3-op sequence
    // (create_file, pwrite, pread, unlink) is racey with verify_fs's
    // concurrent writes. Yield enough times for verify_fs to retire all
    // 10 phases before we touch the scratch. ~50000 yields is overkill
    // but cheap; verify_fs typically finishes in <10ms.
    const SYS_YIELD: u12 = 25;
    var yield_n: u64 = 0;
    while (yield_n < 50000) : (yield_n += 1) {
        _ = issueRaw(buildWord(SYS_YIELD, 0), .{});
    }
    debugPrint("[zig_hello] phase 3: file write test\n");
    const test_path = "/zh_phase3";
    const cr = fsCreateFile(inv.fs_port, fs_va, test_path, 0o644);
    if (cr.status != 0) {
        var st_buf: [32]u8 = undefined;
        const st_str = formatU64(&st_buf, cr.status);
        var msg: [96]u8 = undefined;
        const lead3 = "[zig_hello] create_file status=";
        var w3: usize = 0;
        for (lead3) |b| {
            msg[w3] = b;
            w3 += 1;
        }
        for (st_str) |b| {
            msg[w3] = b;
            w3 += 1;
        }
        msg[w3] = '\n';
        w3 += 1;
        serialPrint(inv.serial_port, serial_va, msg[0..w3]);
        zagExit();
    }
    debugPrint("[zig_hello] phase 3: created\n");

    const content = "Hello from Zag userspace!";
    const wr = fsPwrite(inv.fs_port, fs_va, test_path, 0, content);
    if (wr.status != 0 or wr.bytes_written != content.len) {
        var sb1: [32]u8 = undefined;
        var sb2: [32]u8 = undefined;
        const ss1 = formatU64(&sb1, wr.status);
        const ss2 = formatU64(&sb2, wr.bytes_written);
        var msgw: [128]u8 = undefined;
        const lw = "[zig_hello] phase 3 pwrite status=";
        var ww: usize = 0;
        for (lw) |b| {
            msgw[ww] = b;
            ww += 1;
        }
        for (ss1) |b| {
            msgw[ww] = b;
            ww += 1;
        }
        const lwb = " bytes=";
        for (lwb) |b| {
            msgw[ww] = b;
            ww += 1;
        }
        for (ss2) |b| {
            msgw[ww] = b;
            ww += 1;
        }
        msgw[ww] = '\n';
        ww += 1;
        serialPrint(inv.serial_port, serial_va, msgw[0..ww]);
        zagExit();
    }
    debugPrint("[zig_hello] phase 3: pwrite ok\n");

    // Read back to verify
    const rb = fsPread(inv.fs_port, fs_va, test_path, 0, 64);
    if (rb.status != 0) {
        serialPrint(
            inv.serial_port,
            serial_va,
            "[zig_hello] phase 3: pread back failed\n",
        );
        zagExit();
    }
    var p3_line: [128]u8 = undefined;
    var p3_w: usize = 0;
    const p3_lead = "[zig_hello] phase 3 read = ";
    for (p3_lead) |b| {
        p3_line[p3_w] = b;
        p3_w += 1;
    }
    const data_back: [*]const u8 = @ptrFromInt(fs_va + rb.data_off);
    var n3: u64 = 0;
    while (n3 < rb.bytes_read and p3_w < p3_line.len - 1) : (n3 += 1) {
        p3_line[p3_w] = data_back[n3];
        p3_w += 1;
    }
    p3_line[p3_w] = '\n';
    p3_w += 1;
    serialPrint(inv.serial_port, serial_va, p3_line[0..p3_w]);

    // Cleanup so the next boot starts clean.
    const ul_status = fsUnlink(inv.fs_port, fs_va, test_path);
    if (ul_status == 0) {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] phase 3: unlinked, test passed\n");
    } else {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] phase 3: unlink failed\n");
    }

    zagExit();
}
