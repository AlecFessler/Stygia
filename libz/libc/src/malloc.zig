// malloc — minimal page-bucket allocator.
//
// First cut: each malloc returns whole-page allocations from zag_mmap_anon
// with a 16-byte header storing the original allocation size. free walks
// back to the header and zag_munmap's the page set. Wasteful (a 32-byte
// allocation occupies a full 4 KiB page) but correct and trivial.
//
// realloc allocates fresh + copies. calloc zeros (zag_mmap_anon already
// returns zero-fill demand-paged memory, so it's a no-op). aligned_alloc
// over-allocates and rounds.
//
// Promotion to a real size-class allocator is straightforward once
// we're convinced the cross-build links. PORT_CHECKLIST tracks it.

extern fn zag_mmap_anon(pages: usize) callconv(.c) u64;
extern fn zag_munmap(addr: u64, pages: usize) callconv(.c) i32;
extern fn __errno_location() callconv(.c) *c_int;

const PAGE: usize = 4096;
const HEADER_SIZE: usize = 16;

const Header = extern struct {
    size: usize, // requested (user-visible) bytes
    pages: usize, // pages backing the allocation, including header page
};

fn allocPages(pages: usize) ?u64 {
    return if (zag_mmap_anon(pages) != 0) zag_mmap_anon(pages) else null;
}

fn allocSized(req: usize) ?[*]u8 {
    const total = req + HEADER_SIZE;
    const pages = (total + PAGE - 1) / PAGE;
    const va = zag_mmap_anon(pages);
    if (va == 0) {
        __errno_location().* = 12; // ENOMEM
        return null;
    }
    const hdr_ptr: *Header = @ptrFromInt(va);
    hdr_ptr.* = .{ .size = req, .pages = pages };
    return @ptrFromInt(va + HEADER_SIZE);
}

fn headerOf(ptr: *anyopaque) *Header {
    return @ptrFromInt(@intFromPtr(ptr) - HEADER_SIZE);
}

export fn malloc(n: usize) callconv(.c) ?[*]u8 {
    if (n == 0) return null;
    return allocSized(n);
}

export fn free(ptr: ?*anyopaque) callconv(.c) void {
    const p = ptr orelse return;
    // Guard against empty-slice sentinels and other small bogus
    // addresses. Our zag_mmap_anon always returns page-aligned bases,
    // so the user pointer is at exactly base+16. Anything below the
    // first user page (or not at the +16 offset) is not a real
    // allocation — silently ignore. This makes free() safe on the
    // 0xaaaa-pattern empty-slice ptrs the no-LLVM backend produces.
    const addr = @intFromPtr(p);
    if (addr < 0x10000) return;
    if ((addr & 0xFFF) != HEADER_SIZE) return;
    const h = headerOf(p);
    const base = @intFromPtr(h);
    _ = zag_munmap(base, h.pages);
}

export fn calloc(nmemb: usize, size: usize) callconv(.c) ?[*]u8 {
    // Detect overflow.
    const total: usize = nmemb * size;
    if (size != 0 and total / size != nmemb) {
        __errno_location().* = 12;
        return null;
    }
    return allocSized(total); // zag_mmap_anon zero-fills demand-paged.
}

export fn realloc(ptr: ?*anyopaque, n: usize) callconv(.c) ?[*]u8 {
    if (ptr == null) return malloc(n);
    if (n == 0) {
        free(ptr);
        return null;
    }
    const p = ptr.?;
    const h = headerOf(p);
    if (h.size >= n) return @ptrCast(p);
    const new_p = malloc(n) orelse return null;
    var i: usize = 0;
    const src: [*]const u8 = @ptrCast(p);
    while (i < h.size) : (i += 1) new_p[i] = src[i];
    free(ptr);
    return new_p;
}

export fn posix_memalign(memptr: *?*anyopaque, alignment: usize, size: usize) callconv(.c) c_int {
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) return 22; // EINVAL
    // Page-aligned allocations (the common case for alignment > 16).
    if (alignment <= 16) {
        const p = malloc(size) orelse return 12;
        memptr.* = @ptrCast(p);
        return 0;
    }
    if (alignment <= PAGE) {
        // Allocate full-page bucket; result is page-aligned by construction.
        const pages = (size + PAGE - 1) / PAGE + 1; // +1 for header page
        const va = zag_mmap_anon(pages);
        if (va == 0) return 12;
        const user_va = (va + PAGE) - (HEADER_SIZE);
        const aligned_va = user_va & ~(alignment - 1);
        // Re-anchor header just before aligned_va.
        const h: *Header = @ptrFromInt(aligned_va - HEADER_SIZE);
        h.* = .{ .size = size, .pages = pages };
        memptr.* = @ptrFromInt(aligned_va);
        return 0;
    }
    return 22;
}

export fn aligned_alloc(alignment: usize, size: usize) callconv(.c) ?[*]u8 {
    var p: ?*anyopaque = null;
    if (posix_memalign(&p, alignment, size) != 0) return null;
    return @ptrCast(p);
}

export fn malloc_usable_size(ptr: ?*anyopaque) callconv(.c) usize {
    const p = ptr orelse return 0;
    return headerOf(p).size;
}

// mallinfo2: glibc heap-stats API; LLVM uses it for memory accounting
// in some passes. Return zeros — accurate enough for "we didn't track."
const MallInfo2 = extern struct {
    arena: usize = 0,
    ordblks: usize = 0,
    smblks: usize = 0,
    hblks: usize = 0,
    hblkhd: usize = 0,
    usmblks: usize = 0,
    fsmblks: usize = 0,
    uordblks: usize = 0,
    fordblks: usize = 0,
    keepcost: usize = 0,
};

export fn mallinfo2() callconv(.c) MallInfo2 {
    return .{};
}
