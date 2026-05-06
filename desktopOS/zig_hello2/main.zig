// Phase 4a — spawn target. Built by the patched no-LLVM Zig compiler
// against `-target x86_64-zag-none`, embedded into zig_hello.elf, and
// spawned by zig_hello via createCapabilityDomain at runtime.
//
// Cap-table layout (from the spawning zig_hello):
//   [3] COM1 device_region (port_io 0x3F8/8) — debug sink only.
//
// The point of this binary is only to demonstrate that one Zag-target
// userspace process can load + spawn another. Prints a distinctive
// banner to COM1 and self-deletes.

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

fn print(s: []const u8) void {
    const p = sink orelse return;
    var i: usize = 0;
    while (i < s.len) : (i += 1) p[0] = s[i];
}

// Sentinel u64s patched by zig_compiler before spawn. Volatile loads
// in _start defeat constant-folding, forcing real memory reads so the
// patched values are what the binary observes at runtime. Each
// sentinel is unique enough to locate via byte-search in the ELF.
var seed_value: u64 = 0xCAFEBABE_DEADBEEF;
var mult_value: u64 = 0xCAFEBABE_FACE0001;
var repeat_value: u64 = 0xCAFEBABE_C0FFEE01;

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

export fn _start(cap_table_base: u64) callconv(.c) noreturn {
    initSink(cap_table_base);
    print("[zig_hello2] hello from a Zag-target ELF spawned by another Zag-target ELF\n");

    // Volatile loads force real memory reads so the compiler can't
    // fold the sentinel initializers at compile time.
    const seed_ptr: *volatile u64 = &seed_value;
    const mult_ptr: *volatile u64 = &mult_value;
    const repeat_ptr: *volatile u64 = &repeat_value;
    const v_seed = seed_ptr.*;
    const v_mult = mult_ptr.*;
    const v_repeat = repeat_ptr.*;
    const product: u64 = v_seed *% v_mult;

    printLine("[runtime] seed=", v_seed);
    printLine("[runtime] mult=", v_mult);
    printLine("[runtime] repeat=", v_repeat);

    // Source-driven control flow: loop iteration count comes from a
    // source-file constant that flows through the compiler into a
    // patched .data sentinel and out through a volatile load. Cap to
    // 8 so an unpatched sentinel (Phase 4a/4d) caps at a reasonable
    // value rather than spamming the serial log.
    const cap: u64 = if (v_repeat > 8) 8 else v_repeat;
    var i: u64 = 0;
    while (i < cap) {
        printIterLine(i, product);
        i += 1;
    }

    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
}

fn printIterLine(iter: u64, product: u64) void {
    var ib: [32]u8 = undefined;
    const is = formatU64(&ib, iter);
    var pb: [32]u8 = undefined;
    const ps = formatU64(&pb, product);
    var line: [80]u8 = undefined;
    var w: usize = 0;
    const prefix = "[runtime] iter=";
    for (prefix) |b| {
        line[w] = b;
        w += 1;
    }
    for (is) |b| {
        line[w] = b;
        w += 1;
    }
    const mid = " product=";
    for (mid) |b| {
        line[w] = b;
        w += 1;
    }
    for (ps) |b| {
        line[w] = b;
        w += 1;
    }
    line[w] = '\n';
    w += 1;
    print(line[0..w]);
}

fn printLine(prefix: []const u8, n: u64) void {
    var sb: [32]u8 = undefined;
    const ss = formatU64(&sb, n);
    var line: [80]u8 = undefined;
    var w: usize = 0;
    for (prefix) |b| {
        line[w] = b;
        w += 1;
    }
    for (ss) |b| {
        line[w] = b;
        w += 1;
    }
    line[w] = '\n';
    w += 1;
    print(line[0..w]);
}
