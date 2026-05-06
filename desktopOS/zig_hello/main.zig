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
const FS_SCRATCH_PAGES: u64 = 16;
const FS_SCRATCH_BYTES: u64 = FS_SCRATCH_PAGES * 4096;

// ── Syscall ABI ─────────────────────────────────────────────────────
const SYS_SUSPEND: u12 = 14;
const SYS_DELETE: u12 = 16;
const SYS_CREATE_VMAR: u12 = 32;
const SYS_MAP_PF: u12 = 33;
const SYS_MAP_MMIO: u12 = 34;
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

fn zagExit() noreturn {
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
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
    zagExit();
}
