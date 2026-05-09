// mman — mmap / munmap / mprotect / madvise.
//
// Anonymous mmap routes through stygia_mmap_anon (the consumer ELF
// provides this, talking to the kernel's VMAR + page_frame caps).
// File-backed mmap is unsupported; return MAP_FAILED.

const PAGE: usize = 4096;
const MAP_ANONYMOUS: c_int = 0x20;
const MAP_FAILED: usize = ~@as(usize, 0);

extern fn __errno_location() callconv(.c) *c_int;
extern fn stygia_mmap_anon(pages: usize) callconv(.c) u64;
extern fn stygia_munmap(addr: u64, pages: usize) callconv(.c) i32;

fn fail(err: c_int) usize {
    __errno_location().* = err;
    return MAP_FAILED;
}

fn mmap_impl(addr: ?*anyopaque, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) usize {
    _ = .{ addr, prot };
    if ((flags & MAP_ANONYMOUS) == 0 or fd != -1 or offset != 0) {
        return fail(38); // ENOSYS
    }
    const pages = (length + PAGE - 1) / PAGE;
    const va = stygia_mmap_anon(pages);
    if (va == 0) return fail(12); // ENOMEM
    return va;
}

export fn mmap(addr: ?*anyopaque, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) callconv(.c) usize {
    return mmap_impl(addr, length, prot, flags, fd, offset);
}
export fn mmap64(addr: ?*anyopaque, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) callconv(.c) usize {
    return mmap_impl(addr, length, prot, flags, fd, offset);
}

export fn munmap(addr: ?*anyopaque, length: usize) callconv(.c) c_int {
    if (addr == null) return 0;
    const pages = (length + PAGE - 1) / PAGE;
    return stygia_munmap(@intFromPtr(addr.?), pages);
}

export fn mprotect(addr: ?*anyopaque, length: usize, prot: c_int) callconv(.c) c_int {
    _ = .{ addr, length, prot };
    return 0; // VMARs already have full r/w/x; no demotion path yet.
}

export fn madvise(addr: ?*anyopaque, length: usize, advice: c_int) callconv(.c) c_int {
    _ = .{ addr, length, advice };
    return 0; // No-op; legitimate caller-hint that we ignore.
}
export fn posix_madvise(addr: ?*anyopaque, length: usize, advice: c_int) callconv(.c) c_int {
    return madvise(addr, length, advice);
}

// shm_open / shm_unlink — Stygia has no POSIX shm. Stub ENOSYS.
export fn shm_open(name: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    _ = .{ name, flags, mode };
    __errno_location().* = 38;
    return -1;
}
export fn shm_unlink(name: [*:0]const u8) callconv(.c) c_int {
    _ = name;
    __errno_location().* = 38;
    return -1;
}
