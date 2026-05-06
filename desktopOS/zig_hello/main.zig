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
const SYS_CREATE_CAPABILITY_DOMAIN: u12 = 19;
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
    com1: u12 = 0,
    fs_port: u12 = 0,
    fs_scratch: u12 = 0,
    spawn_elf_pf: u12 = 0,
    compiler_elf_pf: u12 = 0,
    have_serial: bool = false,
    have_fs: bool = false,
    have_spawn: bool = false,
    have_compiler: bool = false,
    have_com1: bool = false,
};

// Walk the cap table. Convention from root_service spawn order:
//   [3] serial_port, [4] serial_scratch, [5] COM1 device_region,
//   [6] fs_port,     [7] io_scratch,     [8] zig_hello2 elf page_frame,
//   [9] zig_compiler elf page_frame.
// Identify by handle-type sequence: ports[0]=serial, ports[1]=fs;
// page_frames[0]=serial_scratch, [1]=io_scratch, [2]=spawn_elf_pf,
// [3]=compiler_elf_pf.
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
                } else if (got_pfs == 2) {
                    inv.spawn_elf_pf = @truncate(slot);
                } else if (got_pfs == 3) {
                    inv.compiler_elf_pf = @truncate(slot);
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
        if (got_ports >= 2 and got_pfs >= 4 and inv.have_com1) break;
    }
    inv.have_serial = (got_ports >= 1 and got_pfs >= 1);
    inv.have_fs = (got_ports >= 2 and got_pfs >= 2);
    inv.have_spawn = (got_pfs >= 3);
    inv.have_compiler = (got_pfs >= 4);
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

// Like mapPfRw but returns the vmar handle so the caller can drop the
// VMAR after copying bytes (keeping the PF alive for spawn).
const MapResult = struct { va: u64, vmar: u12 };

fn mapPfWithHandle(pf_handle: u12, pages: u64, props: u64) ?MapResult {
    const vmar_caps: u64 = (1 << 2) | (1 << 3);
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
    if (mp.v1 != 0) {
        _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, vmar_handle) });
        return null;
    }
    return .{ .va = cv.v2, .vmar = vmar_handle };
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

// PassedHandle encoding for createCapabilityDomain (mirrors
// libz/caps.zig PassedHandle):
//   bits 0-11   = handle id
//   bits 12-15  = reserved (zero)
//   bits 16-31  = caps word
//   bit  32     = move flag
//   bits 33-63  = reserved (zero)
fn passedHandle(id: u12, cap_word: u16, move: bool) u64 {
    return @as(u64, id) |
        (@as(u64, cap_word) << 16) |
        (@as(u64, @intFromBool(move)) << 32);
}

// SelfCap encoding (mirrors libz/caps.zig SelfCap):
//   crcd, crec, crvr, crpf, crvm, crpt, pmu, setwall, power, restart,
//   reply_policy, fut_wake, timer (bool bits), pri (u2 at top).
const CRCD: u16 = 1 << 0;
const CREC: u16 = 1 << 1;
const CRVR: u16 = 1 << 2;
const CRPF: u16 = 1 << 3;
const CRPT: u16 = 1 << 5;
const FUT_WAKE: u16 = 1 << 11;
const TIMER: u16 = 1 << 12;

// DeviceCap encoding: move, copy, dma, irq, restart_policy.
const DEV_MOVE: u16 = 1 << 0;
const DEV_COPY: u16 = 1 << 1;

// Spawn a child capability domain from a staged ELF page_frame and a
// list of pre-encoded passed handles. Returns the IDC handle of the
// new domain on success, 0 on failure.
fn spawnDomain(elf_pf: u12, passed: []const u64) u64 {
    // child SelfCap: minimum needed for our spawned hello binary —
    // crvr (createVmar for COM1 mapping) + crpt (timer). No crcd —
    // hello2 doesn't need to spawn further children.
    const child_self: u64 = CREC | CRVR | CRPF | CRPT;
    // Permissive ceilings; the kernel intersects with our domain's
    // existing ceilings, so we can't actually exceed our own.
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // createCapabilityDomain takes (caps, ceil_in, ceil_out, elf_pf,
    // affinity, passed[]). Vregs v1..v5 + passed handles starting at
    // v6. Up to 8 passed handles fit in registers (v6..v13).
    var regs = Regs{
        .v1 = child_self,
        .v2 = ceilings_inner,
        .v3 = ceilings_outer,
        .v4 = @as(u64, elf_pf),
        .v5 = 0, // affinity = 0 (any core)
    };
    if (passed.len >= 1) regs.v6 = passed[0];
    if (passed.len >= 2) regs.v7 = passed[1];
    if (passed.len >= 3) regs.v8 = passed[2];
    if (passed.len >= 4) regs.v9 = passed[3];
    if (passed.len >= 5) regs.v10 = passed[4];
    if (passed.len >= 6) regs.v11 = passed[5];
    if (passed.len >= 7) regs.v12 = passed[6];
    if (passed.len >= 8) regs.v13 = passed[7];
    const r = issueRaw(buildWord(SYS_CREATE_CAPABILITY_DOMAIN, 0), regs);
    return r.v1;
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

fn readU16Le(p: [*]const u8) u64 {
    return @as(u64, p[0]) | (@as(u64, p[1]) << 8);
}

fn readU64Le(p: [*]const u8) u64 {
    var v: u64 = 0;
    var i: u6 = 0;
    while (i < 8) : (i += 1) {
        v |= (@as(u64, p[i]) << (i * 8));
    }
    return v;
}

// ── Print helpers used by Phase 4d (kept as fns to dodge Zig's outer-
// scope shadow checks; main collected too many `var w` / `var msg`
// names in _start for further inline error sites). ───────────────────
fn printNumLine(port: u12, scratch_va: u64, prefix: []const u8, n: u64) void {
    var sb: [32]u8 = undefined;
    const ss = formatU64(&sb, n);
    var msg: [128]u8 = undefined;
    var i: usize = 0;
    for (prefix) |b| {
        msg[i] = b;
        i += 1;
    }
    for (ss) |b| {
        msg[i] = b;
        i += 1;
    }
    msg[i] = '\n';
    i += 1;
    serialPrint(port, scratch_va, msg[0..i]);
}

fn print2NumLine(
    port: u12,
    scratch_va: u64,
    prefix1: []const u8,
    n1: u64,
    prefix2: []const u8,
    n2: u64,
) void {
    var sb1: [32]u8 = undefined;
    var sb2: [32]u8 = undefined;
    const ss1 = formatU64(&sb1, n1);
    const ss2 = formatU64(&sb2, n2);
    var msg: [192]u8 = undefined;
    var i: usize = 0;
    for (prefix1) |b| {
        msg[i] = b;
        i += 1;
    }
    for (ss1) |b| {
        msg[i] = b;
        i += 1;
    }
    for (prefix2) |b| {
        msg[i] = b;
        i += 1;
    }
    for (ss2) |b| {
        msg[i] = b;
        i += 1;
    }
    msg[i] = '\n';
    i += 1;
    serialPrint(port, scratch_va, msg[0..i]);
}

// Round-trip the bytes of `src_pf` through the SQL FS at `dst_path`,
// then allocate a fresh page_frame and copy the read-back bytes into
// it. Returns the new pf handle (caps r+w+x) on success.
fn roundtripPfThroughDisk(
    inv: Inbound,
    serial_va: u64,
    fs_va: u64,
    src_pf: u12,
    dst_path: []const u8,
) ?u12 {
    const SRC_MAX_PAGES: u64 = 32;
    const src_map = mapPfWithHandle(src_pf, SRC_MAX_PAGES, 0b001) orelse {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] roundtrip: map src failed\n");
        return null;
    };
    const src: [*]const u8 = @ptrFromInt(src_map.va);

    const e_phoff: u64 = readU64Le(src + 0x20);
    const e_phentsize: u64 = readU16Le(src + 0x36);
    const e_phnum: u64 = readU16Le(src + 0x38);
    const e_shoff: u64 = readU64Le(src + 0x28);
    const e_shentsize: u64 = readU16Le(src + 0x3a);
    const e_shnum: u64 = readU16Le(src + 0x3c);
    var max_end: u64 = e_shoff + e_shentsize * e_shnum;
    var pi: u64 = 0;
    while (pi < e_phnum) : (pi += 1) {
        const ph_base: u64 = src_map.va + e_phoff + pi * e_phentsize;
        const ph: [*]const u8 = @ptrFromInt(ph_base);
        const p_offset: u64 = readU64Le(ph + 8);
        const p_filesz: u64 = readU64Le(ph + 32);
        const end: u64 = p_offset + p_filesz;
        if (end > max_end) max_end = end;
    }
    const elf_size: u64 = (max_end + 4095) & ~@as(u64, 4095);

    _ = fsUnlink(inv.fs_port, fs_va, dst_path);
    const cr = fsCreateFile(inv.fs_port, fs_va, dst_path, 0o644);
    if (cr.status != 0) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] roundtrip: create status=", cr.status);
        return null;
    }
    // io_scratch (16 pages = 64 KiB) limits each pwrite/pread to
    // scratch_size - path_len bytes. Chunk so binaries > ~60 KiB
    // (e.g. zig_compiler.elf) round-trip via multiple IPCs.
    const CHUNK: u64 = 32 * 1024;
    var off: u64 = 0;
    while (off < elf_size) {
        const remaining: u64 = elf_size - off;
        const this_chunk: u64 = if (remaining > CHUNK) CHUNK else remaining;
        const elf_slice = src[off .. off + this_chunk];
        const wr = fsPwrite(inv.fs_port, fs_va, dst_path, off, elf_slice);
        if (wr.status != 0 or wr.bytes_written != this_chunk) {
            print2NumLine(inv.serial_port, serial_va, "[zig_hello] roundtrip: pwrite status=", wr.status, " bytes=", wr.bytes_written);
            return null;
        }
        off += this_chunk;
    }
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, src_map.vmar) });

    return readDiskFileToFreshPf(inv, serial_va, fs_va, dst_path, elf_size);
}

// Read `path` from disk into a freshly-allocated page_frame (caps
// r+w+x). `max_bytes` caps the read length and determines the pf size.
// Returns the new pf handle on success.
fn readDiskFileToFreshPf(
    inv: Inbound,
    serial_va: u64,
    fs_va: u64,
    path: []const u8,
    max_bytes: u64,
) ?u12 {
    // Chunked pread — io_scratch is 64 KiB; each pread is capped at
    // 32 KiB so even with overhead the path + data slot fits.
    const CHUNK: u64 = 32 * 1024;
    const dst_pages: u64 = (max_bytes + 4095) / 4096;
    if (dst_pages == 0) return null;
    const pf_caps_rwx: u64 = (1 << 2) | (1 << 3) | (1 << 4);
    const cpf = issueRaw(buildWord(SYS_CREATE_PAGE_FRAME, 0), .{
        .v1 = pf_caps_rwx,
        .v2 = 0,
        .v3 = dst_pages,
    });
    if (cpf.v1 < 16) {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] readDisk: createPageFrame failed\n");
        return null;
    }
    const new_pf: u12 = @truncate(cpf.v1 & 0xFFF);
    const dst_map = mapPfWithHandle(new_pf, dst_pages, 0b011) orelse {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] readDisk: map dst failed\n");
        return null;
    };
    const dst: [*]u8 = @ptrFromInt(dst_map.va);

    var off: u64 = 0;
    var got_any: bool = false;
    while (off < max_bytes) {
        const remaining: u64 = max_bytes - off;
        const want: u64 = if (remaining > CHUNK) CHUNK else remaining;
        const rb = fsPread(inv.fs_port, fs_va, path, off, want);
        if (rb.status != 0) {
            printNumLine(inv.serial_port, serial_va, "[zig_hello] readDisk: pread status=", rb.status);
            return null;
        }
        if (rb.bytes_read == 0) break;
        const back_src: [*]const u8 = @ptrFromInt(fs_va + rb.data_off);
        var k: u64 = 0;
        while (k < rb.bytes_read) : (k += 1) dst[off + k] = back_src[k];
        off += rb.bytes_read;
        got_any = true;
        if (rb.bytes_read < want) break; // short read — EOF
    }
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, dst_map.vmar) });
    if (!got_any) return null;
    return new_pf;
}

// PortCap bits (mirrors libz/caps.zig PortCap): move(0), copy(1),
// recv(2), xfer(3), bind(4).
const PORT_COPY: u16 = 1 << 1;
const PORT_XFER: u16 = 1 << 3;
const PORT_BIND: u16 = 1 << 4;
// PfCap bits: move(0), copy(1), r(2), w(3), x(4).
const PF_COPY: u16 = 1 << 1;
const PF_R: u16 = 1 << 2;
const PF_W: u16 = 1 << 3;

// Spawn the zig_compiler with the caps it needs to print, do fs IPC,
// and run. Returns the IDC handle on success.
fn spawnCompilerDomain(inv: Inbound, compiler_pf: u12) u64 {
    const child_self: u64 = CREC | CRVR | CRPF | CRPT;
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    var passed: [4]u64 = undefined;
    passed[0] = passedHandle(inv.com1, DEV_MOVE | DEV_COPY, false);
    passed[1] = passedHandle(inv.fs_port, PORT_COPY | PORT_XFER | PORT_BIND, false);
    passed[2] = passedHandle(inv.fs_scratch, PF_COPY | PF_R | PF_W, false);

    const regs = Regs{
        .v1 = child_self,
        .v2 = ceilings_inner,
        .v3 = ceilings_outer,
        .v4 = @as(u64, compiler_pf),
        .v5 = 0,
        .v6 = passed[0],
        .v7 = passed[1],
        .v8 = passed[2],
    };
    const r = issueRaw(buildWord(SYS_CREATE_CAPABILITY_DOMAIN, 0), regs);
    return r.v1;
}

// ── Phase 4e: stage compiler+source on disk, spawn the compiler from
//    disk, let it produce /hello.elf, then load and spawn /hello.elf.
//    The full "compiler-on-Zag → ELF-on-disk → spawn-from-disk" loop.
fn runPhase4e(inv: Inbound, serial_va: u64, fs_va: u64) void {
    if (!inv.have_compiler) {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] 4e: no compiler pf; skip\n");
        return;
    }
    serialPrint(inv.serial_port, serial_va, "[zig_hello] phase 4e: compile + spawn from disk\n");

    // 1. Stage /hello.zig source bytes. The compiler extracts:
    //      tag      → first quoted string  (bracketed prefix)
    //      banner   → second quoted string (body)
    //      seed     → first decimal int after the second string
    //      mult     → second decimal int after the second string
    //      repeat   → third decimal int after the second string
    //      op_name  → third quoted string ("mul"|"add"|"sub"|"xor")
    //                 — compiler maps this to op int and OVERRIDES op
    //      op       → fourth decimal int (0=mul, 1=add, 2=sub, 3=xor)
    //                 — used as fallback if op_name unknown/missing
    //      step     → fifth decimal int — added to result per iteration
    //      skip_idx → sixth decimal int — iter loop skips i==skip_idx
    //      inner    → seventh decimal int — inner loop count per outer iter
    //      values   → remaining decimal ints (up to 4) become a u64 array
    //    Output banner: "[<tag>] <banner> seed=<n>".
    //    Spawned binary BRANCHES on op_value to compute base, then
    //    loops `repeat` times skipping iter `skip_idx` and printing
    //    "[runtime] iter=N result=base+N*step", then prints values
    //    array + sum/max reduction.
    // Source includes // line comments with DECOY values that would
    // hijack the parser without comment handling: a fake `op_name =
    // "mul"` ahead of the real "xor", and decoy ints (999, 888) that
    // would shift every scalar by two slots.
    const src_bytes =
        "pub const tag = \"compiled-on-zag\";\n" ++
        "pub const banner = \"hello from Zag userspace,\";\n" ++
        "// pub const op_name = \"mul\"; // decoy — must be skipped\n" ++
        "pub const op_name = \"xor\";\n" ++
        "// distractor ints: 999 888 — must NOT become seed/mult\n" ++
        "pub const seed = 100 * 13 + 38;\n" ++
        "pub const mult = seed - 1300;\n" ++
        "pub const repeat = 4;\n" ++
        "pub const op = 1;\n" ++
        "pub const step = 7;\n" ++
        "pub const skip_idx = 2;\n" ++
        "pub const inner = 3;\n" ++
        "pub const values = [_]u64{ seed, mult, 300 };\n";
    _ = fsUnlink(inv.fs_port, fs_va, "/hello.zig");
    const cs = fsCreateFile(inv.fs_port, fs_va, "/hello.zig", 0o644);
    if (cs.status != 0) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] 4e: hello.zig create=", cs.status);
        return;
    }
    const ws = fsPwrite(inv.fs_port, fs_va, "/hello.zig", 0, src_bytes);
    if (ws.status != 0) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] 4e: hello.zig pwrite=", ws.status);
        return;
    }

    // 2. Round-trip zig_compiler.elf to /zig_compiler.elf and get a
    //    fresh pf populated with the disk-read bytes.
    const compiler_pf = roundtripPfThroughDisk(
        inv,
        serial_va,
        fs_va,
        inv.compiler_elf_pf,
        "/zig_compiler.elf",
    ) orelse return;

    // 3. Spawn zig_compiler with COM1 + fs_port + io_scratch (shared
    //    scratch is OK because we yield before touching fs again).
    const idc_c = spawnCompilerDomain(inv, compiler_pf);
    if (idc_c < 16) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] 4e: spawn compiler err=", idc_c);
        return;
    }
    printNumLine(inv.serial_port, serial_va, "[zig_hello] 4e: spawned compiler idc=", idc_c & 0xFFF);

    // 4. Yield enough to let zig_compiler retire its 4 fs IPCs and
    //    produce /hello.elf. fs IPC is fast; 200k yields is gross
    //    overkill but guarantees we don't race the scratch buffer.
    const SYS_YIELD: u12 = 25;
    var y: u64 = 0;
    while (y < 200000) : (y += 1) {
        _ = issueRaw(buildWord(SYS_YIELD, 0), .{});
    }

    // 5. Read /hello.elf from disk into a fresh pf and spawn it. The
    //    output ELF was written by zig_compiler in this very boot.
    const hello_pf = readDiskFileToFreshPf(
        inv,
        serial_va,
        fs_va,
        "/hello.elf",
        60 * 1024,
    ) orelse {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] 4e: load /hello.elf failed\n");
        return;
    };

    var passed_out: [4]u64 = undefined;
    passed_out[0] = passedHandle(inv.com1, DEV_MOVE | DEV_COPY, false);
    const idc_h = spawnDomain(hello_pf, passed_out[0..1]);
    if (idc_h < 16) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] 4e: spawn /hello.elf err=", idc_h);
        return;
    }
    serialPrint(
        inv.serial_port,
        serial_va,
        "[zig_hello] phase 4e: full pipeline ok (compiler-on-Zag wrote /hello.elf, we spawned it)\n",
    );
}

// ── Phase 4d: round-trip zig_hello2 through disk and spawn it. ──────
fn runPhase4d(inv: Inbound, serial_va: u64, fs_va: u64) void {
    debugPrint("[zig_hello] phase 4d: disk round-trip\n");

    const ELF2_MAX_PAGES: u64 = 16;
    const src_map = mapPfWithHandle(inv.spawn_elf_pf, ELF2_MAX_PAGES, 0b001) orelse {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] 4d: map src failed\n");
        return;
    };
    const src: [*]const u8 = @ptrFromInt(src_map.va);

    // Parse ELF64 to determine total file size. Section headers can sit
    // mid-file with LOAD content following them, so walk both PHDRs and
    // SHDRs and take the max ending offset, then round up to a page.
    const e_phoff: u64 = readU64Le(src + 0x20);
    const e_phentsize: u64 = readU16Le(src + 0x36);
    const e_phnum: u64 = readU16Le(src + 0x38);
    const e_shoff: u64 = readU64Le(src + 0x28);
    const e_shentsize: u64 = readU16Le(src + 0x3a);
    const e_shnum: u64 = readU16Le(src + 0x3c);
    var max_end: u64 = e_shoff + e_shentsize * e_shnum;
    var pi: u64 = 0;
    while (pi < e_phnum) : (pi += 1) {
        const ph_base: u64 = src_map.va + e_phoff + pi * e_phentsize;
        const ph: [*]const u8 = @ptrFromInt(ph_base);
        const p_offset: u64 = readU64Le(ph + 8);
        const p_filesz: u64 = readU64Le(ph + 32);
        const end: u64 = p_offset + p_filesz;
        if (end > max_end) max_end = end;
    }
    const elf_size: u64 = (max_end + 4095) & ~@as(u64, 4095);
    printNumLine(inv.serial_port, serial_va, "[zig_hello] 4d: elf_size=", elf_size);

    // Write ELF to disk. fs scratch = 64 KiB; current ELF ~20 KiB so a
    // single pwrite suffices. Unlink first to be idempotent.
    const dpath = "/hello2.elf";
    _ = fsUnlink(inv.fs_port, fs_va, dpath);
    const cr2 = fsCreateFile(inv.fs_port, fs_va, dpath, 0o644);
    if (cr2.status != 0) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] 4d: create_file status=", cr2.status);
        return;
    }

    const elf_slice = src[0..elf_size];
    const wr2 = fsPwrite(inv.fs_port, fs_va, dpath, 0, elf_slice);
    if (wr2.status != 0 or wr2.bytes_written != elf_size) {
        print2NumLine(
            inv.serial_port,
            serial_va,
            "[zig_hello] 4d: pwrite status=",
            wr2.status,
            " bytes=",
            wr2.bytes_written,
        );
        return;
    }

    // Drop the source mapping; the underlying pf still belongs to us.
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, src_map.vmar) });

    // Read back from disk into io_scratch.
    const rb2 = fsPread(inv.fs_port, fs_va, dpath, 0, elf_size);
    if (rb2.status != 0 or rb2.bytes_read != elf_size) {
        print2NumLine(
            inv.serial_port,
            serial_va,
            "[zig_hello] 4d: pread back status=",
            rb2.status,
            " bytes=",
            rb2.bytes_read,
        );
        return;
    }

    // Allocate a fresh page_frame, sized to fit the read-back ELF, with
    // r+w+x caps so the kernel can map text r-x and data r-w from it
    // during createCapabilityDomain.
    const dst_pages: u64 = (rb2.bytes_read + 4095) / 4096;
    const pf_caps_rwx: u64 = (1 << 2) | (1 << 3) | (1 << 4);
    const cpf2 = issueRaw(buildWord(SYS_CREATE_PAGE_FRAME, 0), .{
        .v1 = pf_caps_rwx,
        .v2 = 0,
        .v3 = dst_pages,
    });
    if (cpf2.v1 < 16) {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] 4d: createPageFrame failed\n");
        return;
    }
    const new_pf: u12 = @truncate(cpf2.v1 & 0xFFF);

    // Map fresh pf RW, copy bytes from io_scratch into it, drop VMAR.
    const dst_map = mapPfWithHandle(new_pf, dst_pages, 0b011) orelse {
        serialPrint(inv.serial_port, serial_va, "[zig_hello] 4d: map dst failed\n");
        return;
    };
    const dst: [*]u8 = @ptrFromInt(dst_map.va);
    const back_src: [*]const u8 = @ptrFromInt(fs_va + rb2.data_off);
    var ck: u64 = 0;
    while (ck < rb2.bytes_read) : (ck += 1) dst[ck] = back_src[ck];
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = @as(u64, dst_map.vmar) });

    // Spawn child capability domain from the disk-loaded pf, passing a
    // fresh COM1 cap (copy not move — we kept it across Phase 4a).
    var p4d_passed: [4]u64 = undefined;
    p4d_passed[0] = passedHandle(inv.com1, DEV_MOVE | DEV_COPY, false);
    const idc2 = spawnDomain(new_pf, p4d_passed[0..1]);
    if (idc2 < 16) {
        printNumLine(inv.serial_port, serial_va, "[zig_hello] 4d: spawn err=", idc2);
        return;
    }
    serialPrint(
        inv.serial_port,
        serial_va,
        "[zig_hello] phase 4d: disk-load spawn ok\n",
    );
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
        // First-boot race: verify_fs hasn't created the marker yet. We
        // don't gate Phase 4 on Phase 1; just announce and skip.
        printNumLine(inv.serial_port, serial_va, "[zig_hello] /persist_marker pread (skipped) status=", r.status);
    } else {
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
    }
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
    // io_scratch is shared with verify_fs's harness; our fs-touching
    // phases (3, 4d, 4e) all race with verify_fs's concurrent writes.
    // Yield enough times for verify_fs to retire all 10 phases before
    // we touch the scratch. The yield budget needs to span Phase 3 +
    // 4d + 4e because each does its own fs IPC chain — under load
    // verify_fs can stretch well past 100ms.
    const SYS_YIELD: u12 = 25;
    var yield_n: u64 = 0;
    while (yield_n < 500000) : (yield_n += 1) {
        _ = issueRaw(buildWord(SYS_YIELD, 0), .{});
    }
    debugPrint("[zig_hello] phase 3: file write test\n");
    phase3: {
        const test_path = "/zh_phase3";
        // Idempotent: clear any leftover entry from a previous boot or
        // from verify_fs's overlapping phases (which can leave stale
        // names). Fresh-disk runs always have nothing here, so unlink's
        // not_found return is fine.
        _ = fsUnlink(inv.fs_port, fs_va, test_path);
        const cr = fsCreateFile(inv.fs_port, fs_va, test_path, 0o644);
        if (cr.status != 0) {
            printNumLine(inv.serial_port, serial_va, "[zig_hello] phase 3 create status=", cr.status);
            break :phase3;
        }
        debugPrint("[zig_hello] phase 3: created\n");

        const content = "Hello from Zag userspace!";
        const wr = fsPwrite(inv.fs_port, fs_va, test_path, 0, content);
        if (wr.status != 0 or wr.bytes_written != content.len) {
            print2NumLine(inv.serial_port, serial_va, "[zig_hello] phase 3 pwrite status=", wr.status, " bytes=", wr.bytes_written);
            break :phase3;
        }
        debugPrint("[zig_hello] phase 3: pwrite ok\n");

        const rb = fsPread(inv.fs_port, fs_va, test_path, 0, 64);
        if (rb.status != 0) {
            printNumLine(inv.serial_port, serial_va, "[zig_hello] phase 3 pread status=", rb.status);
            break :phase3;
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

        const ul_status = fsUnlink(inv.fs_port, fs_va, test_path);
        if (ul_status == 0) {
            serialPrint(inv.serial_port, serial_va, "[zig_hello] phase 3: unlinked, test passed\n");
        } else {
            serialPrint(inv.serial_port, serial_va, "[zig_hello] phase 3: unlink failed\n");
        }
    }

    // ── Phase 4a: spawn a child capability domain from the staged
    //    zig_hello2 ELF page_frame. Passes the COM1 device cap so the
    //    spawned domain can print on its own.
    if (!inv.have_spawn or !inv.have_com1) {
        serialPrint(
            inv.serial_port,
            serial_va,
            "[zig_hello] phase 4a: missing spawn handles; skipping\n",
        );
        zagExit();
    }
    debugPrint("[zig_hello] phase 4a: spawning child domain\n");

    var passed: [4]u64 = undefined;
    passed[0] = passedHandle(inv.com1, DEV_MOVE | DEV_COPY, false);
    const idc = spawnDomain(inv.spawn_elf_pf, passed[0..1]);
    if (idc < 16) {
        var sb: [32]u8 = undefined;
        const ss = formatU64(&sb, idc);
        var msg: [96]u8 = undefined;
        const lead4 = "[zig_hello] phase 4a: createCapabilityDomain err=";
        var w4: usize = 0;
        for (lead4) |b| {
            msg[w4] = b;
            w4 += 1;
        }
        for (ss) |b| {
            msg[w4] = b;
            w4 += 1;
        }
        msg[w4] = '\n';
        w4 += 1;
        serialPrint(inv.serial_port, serial_va, msg[0..w4]);
        zagExit();
    }
    var idc_buf: [32]u8 = undefined;
    const idc_str = formatU64(&idc_buf, idc & 0xFFF);
    var p4_line: [96]u8 = undefined;
    var p4_w: usize = 0;
    const p4_lead = "[zig_hello] phase 4a: spawned hello2 idc=";
    for (p4_lead) |b| {
        p4_line[p4_w] = b;
        p4_w += 1;
    }
    for (idc_str) |b| {
        p4_line[p4_w] = b;
        p4_w += 1;
    }
    p4_line[p4_w] = '\n';
    p4_w += 1;
    serialPrint(inv.serial_port, serial_va, p4_line[0..p4_w]);

    // ── Phase 4d: round-trip the same ELF through disk, then spawn from
    //    the disk-read bytes. This is the core "load ELF from disk and
    //    run" primitive that the Zig-compiler-on-Zag demo needs.
    runPhase4d(inv, serial_va, fs_va);

    // ── Phase 4e: full compile+spawn pipeline through disk. Builds on
    //    Phase 4d's primitive but adds the chain: zig_compiler runs as
    //    a child capability domain, writes /hello.elf, and we then
    //    load+spawn /hello.elf from disk.
    runPhase4e(inv, serial_va, fs_va);

    zagExit();
}
