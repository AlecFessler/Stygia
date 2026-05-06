// Minimal Zag runtime providing all zag_* externs libc.a needs.
// COM1 setup is hardcoded for now — assume root spawns us with COM1
// at slot 3 of the cap table.

const SLOT_SELF: u12 = 0;
const SLOT_COM1: u12 = 3;
const SYS_DELETE: u12 = 16;
const SYS_CREATE_VMAR: u12 = 32;
const SYS_MAP_MMIO: u12 = 34;

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
          [rbp_save] "+m" (rbp_save),
          [ov4_mem] "=m" (ov4_mem),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (in.v1),
          [iv2] "{rbx}" (in.v2),
          [iv3] "{rdx}" (in.v3),
          [iv4_mem] "m" (iv4_mem),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
    _ = .{ ov4_mem, rbp_save };
    return .{ .v1 = ov1, .v2 = ov2 };
}

var com1_sink: ?[*]volatile u8 = null;

export fn zag_init_com1() callconv(.c) void {
    const vmar_caps: u64 = (1 << 2) | (1 << 3) | (1 << 5);
    const props: u64 = (1 << 5) | 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{ .v1 = vmar_caps, .v2 = props, .v3 = 1 });
    if (cv.v1 < 16) return;
    const vh: u12 = @truncate(cv.v1 & 0xFFF);
    const vbase = cv.v2;
    const mm = issueRaw(buildWord(SYS_MAP_MMIO, 0), .{ .v1 = vh, .v2 = SLOT_COM1 });
    if (mm.v1 != 0) return;
    com1_sink = @ptrFromInt(vbase);
}

export fn zag_write_console(buf: [*]const u8, count: usize) callconv(.c) usize {
    const p = com1_sink orelse return count;
    var i: usize = 0;
    while (i < count) : (i += 1) p[0] = buf[i];
    return count;
}

export fn zag_exit(status: u8) callconv(.c) noreturn {
    _ = status;
    _ = issueRaw(buildWord(SYS_DELETE, 0), .{ .v1 = SLOT_SELF });
    while (true) asm volatile ("hlt");
}

export fn zag_fs_openat(path: [*]const u8, len: usize, flags: u32, mode: u32) callconv(.c) i64 {
    _ = .{ path, len, flags, mode };
    return -38;
}
export fn zag_fs_read(fd: i32, buf: [*]u8, len: usize, off: i64) callconv(.c) i64 {
    _ = .{ fd, buf, len, off };
    return -38;
}
export fn zag_fs_write(fd: i32, buf: [*]const u8, len: usize, off: i64) callconv(.c) i64 {
    _ = .{ fd, buf, len, off };
    return -38;
}
export fn zag_fs_close(fd: i32) callconv(.c) i32 {
    _ = fd;
    return 0;
}
export fn zag_fs_fstat(fd: i32, st: *anyopaque) callconv(.c) i32 {
    _ = .{ fd, st };
    return -38;
}
export fn zag_fs_stat(path: [*]const u8, len: usize, st: *anyopaque) callconv(.c) i32 {
    _ = .{ path, len, st };
    return -38;
}
export fn zag_fs_unlink(path: [*]const u8, len: usize) callconv(.c) i32 {
    _ = .{ path, len };
    return -38;
}
export fn zag_fs_lseek(fd: i32, off: i64, whence: c_int) callconv(.c) i64 {
    _ = .{ fd, off, whence };
    return -38;
}
export fn zag_fs_mkdir(path: [*]const u8, len: usize, mode: u32) callconv(.c) i32 {
    _ = .{ path, len, mode };
    return -38;
}

export fn zag_mmap_anon(pages: usize) callconv(.c) u64 {
    const vmar_caps: u64 = (1 << 2) | (1 << 3) | (1 << 5);
    const props: u64 = 0b011;
    const cv = issueRaw(buildWord(SYS_CREATE_VMAR, 0), .{ .v1 = vmar_caps, .v2 = props, .v3 = pages });
    if (cv.v1 < 16) return 0;
    return cv.v2;
}

export fn zag_munmap(addr: u64, pages: usize) callconv(.c) i32 {
    _ = .{ addr, pages };
    return 0;
}
