// Phase 0 hello — Zag-target ELF that prints "hello" via the new
// userspace serial_server. Built with the patched no-LLVM Zig compiler
// against `-target x86_64-zag-none`.
//
// Cap-table layout from root_service:
//   [3] serial_port (xfer|bind)
//   [4] serial_scratch page_frame (r+w, 1 page)
//   [5] COM1 device_region (debug-only direct sink; remove once IPC path lit)
//
// We can't pull in the libz / serial_client modules through the patched
// build invocation, so the syscall ABI snippets and the protocol
// constants are inlined here. They mirror what those modules do.

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

fn capHandleType(c: Cap) HandleType {
    return @enumFromInt(@as(u4, @truncate((c.word0 >> 12) & 0xF)));
}

// Discover the inbound serial_port + scratch_pf by type. The
// root_service spawn order pins them at SLOT_FIRST_PASSED + 0 (port)
// and +1 (page_frame), but scan-by-type keeps zig_hello robust if
// future spawn orderings change the slot layout.
fn findHandles(cap_table_base: u64, port: *u12, scratch_pf: *u12) bool {
    var got_port = false;
    var got_pf = false;
    var slot: u32 = SLOT_FIRST_PASSED;
    while (slot < HANDLE_TABLE_MAX) : (slot += 1) {
        const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
        const c = tbl[slot];
        switch (capHandleType(c)) {
            .port => if (!got_port) {
                port.* = @truncate(slot);
                got_port = true;
            },
            .page_frame => if (!got_pf) {
                scratch_pf.* = @truncate(slot);
                got_pf = true;
            },
            else => {},
        }
        if (got_port and got_pf) return true;
    }
    return false;
}

// Map the scratch page_frame r+w into our address space.
fn mapScratch(pf_handle: u12) ?u64 {
    // VmarCap{ r=1, w=1 } — bits 2,3
    const vmar_caps: u64 = (1 << 2) | (1 << 3);
    // props: cur_rwx=0b011 (r|w), sz=0 (4 KiB)
    const props: u64 = 0b011;

    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{
        .v1 = vmar_caps,
        .v2 = props,
        .v3 = 1,
    });
    if (cv.v1 < 16) return null;
    const vmar_handle: u12 = @truncate(cv.v1 & 0xFFF);
    const vmar_base = cv.v2;

    // map_pf vreg layout: v1 = vmar_handle, v2 = vmar_offset_pages, v3 = pf_handle.
    // Spec §[map_pf] uses (vmar_off, pf_handle) pairs starting at v2.
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

fn zagExit() noreturn {
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
}

// ── Entry: kernel calls _start(cap_table_base) per §[caps] ──────────
// SystemV AMD64: rdi = first arg = cap_table_base. callconv(.c) makes
// the input convention explicit even on non-Linux freestanding.
export fn _start(cap_table_base: u64) callconv(.c) noreturn {
    initDebugSink(cap_table_base);
    debugPrint("[zig_hello] alive\n");

    var port: u12 = 0;
    var scratch_pf: u12 = 0;
    if (!findHandles(cap_table_base, &port, &scratch_pf)) {
        debugPrint("[zig_hello] findHandles failed\n");
        zagExit();
    }
    debugPrint("[zig_hello] handles found\n");

    const va = mapScratch(scratch_pf) orelse {
        debugPrint("[zig_hello] mapScratch failed\n");
        zagExit();
    };
    debugPrint("[zig_hello] scratch mapped\n");

    const msg = "[zig_hello] hello from zig on zag\n";
    serialPrint(port, va, msg);
    debugPrint("[zig_hello] after IPC\n");
    zagExit();
}
