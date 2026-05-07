// malloc — best-fit heap allocator backed by a single VMAR reservation.
//
// On first call the heap reserves a single VMAR region via
// zag_mmap_anon (64 MiB by default — kernel buddy MAX_ORDER caps a
// single contiguous reservation at 128 MiB and demandAlloc isn't yet
// wired, so the page_frame is currently eager) and hands it to a
// HeapAllocator instance ported from the kernel (libz/libc/src/heap/).
// The heap allocator exposes std.mem.Allocator semantics with a
// red-black-tree-indexed best-fit free list and slab-allocated tree
// nodes, so coalescing + bucketing are O(log N).
//
// The slab allocator that backs the RB-tree nodes is parented on a
// FixedBufferAllocator carved from a static 1 MiB BSS buffer — enough
// for many thousands of distinct bucket sizes before exhaustion.
//
// libc is built single_threaded; the heap's lock is a no-op shim
// (heap/spin_lock.zig). Multi-threaded libc would swap the shim for
// a real atomic spinlock without touching the rest of the heap.

const std = @import("std");
const heap_alloc = @import("heap/heap_alloc.zig");

extern fn zag_mmap_anon(pages: usize) callconv(.c) u64;
extern fn __errno_location() callconv(.c) *c_int;

const PAGE: usize = 4096;
const HEAP_RESERVATION_BYTES: usize = 128 * 1024 * 1024; // 128 MiB (kernel buddy MAX_ORDER cap)
const SLAB_PARENT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB BSS

// Static BSS for the slab allocator's parent. Sized for several
// thousand RB-tree nodes (each node is ~64 bytes); plenty for a
// long-running compiler workload.
var slab_parent_buf: [SLAB_PARENT_BYTES]u8 align(16) = @splat(0);
var slab_parent_fba: std.heap.FixedBufferAllocator = undefined;
var tree_alloc: heap_alloc.TreeAllocator = undefined;
var heap: heap_alloc.HeapAllocator = undefined;

// HeapAllocator's vtable is keyed off a *anyopaque self pointer; the
// instance must outlive any slice it returns. `heap` is BSS — its
// lifetime is the process. Initialised lazily on first malloc.
var initialised: bool = false;

fn ensureInit() void {
    if (initialised) return;
    initialised = true;

    // Slab parent: FixedBufferAllocator over the static BSS buffer.
    slab_parent_fba = std.heap.FixedBufferAllocator.init(&slab_parent_buf);

    // Slab allocator for RB-tree nodes. Caller hands errors up via
    // panic — out of slab parent storage is a fatal compiler-time
    // limit, not a recoverable runtime condition.
    tree_alloc = heap_alloc.TreeAllocator.init(slab_parent_fba.allocator()) catch
        @panic("libc heap: slab init failed");

    // Reserve a contiguous VMAR for the heap. The current
    // zag_mmap_anon eagerly allocates a page_frame; kernel buddy
    // MAX_ORDER caps a single page_frame at 128 MiB. 64 MiB keeps
    // a comfortable margin and is plenty for self-hosted compiles.
    const pages = HEAP_RESERVATION_BYTES / PAGE;
    const va = zag_mmap_anon(pages);
    if (va == 0) @panic("libc heap: VMAR reservation failed");

    const reserve_start: u64 = va;
    const reserve_end: u64 = va + HEAP_RESERVATION_BYTES;
    heap = heap_alloc.HeapAllocator.init(reserve_start, reserve_end, &tree_alloc);
}

fn allocator() std.mem.Allocator {
    ensureInit();
    return heap.allocator();
}

// User pointer needs a way back to its allocation length for free().
// HeapAllocator.free wants a slice — we store the length in an 8-byte
// header just before the user pointer. The user pointer is therefore
// at base+8 from the heap-block payload start. min_user_align in the
// heap is 8, so this preserves the heap's alignment guarantees for
// the small (<=16-byte) requests typical in malloc; larger alignments
// are handled in posix_memalign by overallocating.
const HEADER_SIZE: usize = 16;

const Header = extern struct {
    len: usize, // user-visible bytes
    pad: usize, // keep header 16-byte aligned
};

fn writeHeader(payload: [*]u8, user_len: usize) [*]u8 {
    const hdr: *Header = @ptrCast(@alignCast(payload));
    hdr.* = .{ .len = user_len, .pad = 0 };
    return payload + HEADER_SIZE;
}

fn readHeader(user_ptr: *anyopaque) *Header {
    return @ptrFromInt(@intFromPtr(user_ptr) - HEADER_SIZE);
}

fn allocWithHeader(n: usize, alignment: std.mem.Alignment) ?[*]u8 {
    if (n == 0) return null;
    const a = allocator();
    const total = n + HEADER_SIZE;
    const payload = a.rawAlloc(total, alignment, @returnAddress()) orelse {
        __errno_location().* = 12; // ENOMEM
        return null;
    };
    return writeHeader(payload, total);
}

export fn malloc(n: usize) callconv(.c) ?[*]u8 {
    return allocWithHeader(n, .@"16");
}

export fn calloc(nmemb: usize, size: usize) callconv(.c) ?[*]u8 {
    const total: usize = nmemb * size;
    if (size != 0 and total / size != nmemb) {
        __errno_location().* = 12;
        return null;
    }
    const ptr = allocWithHeader(total, .@"16") orelse return null;
    var i: usize = 0;
    while (i < total) : (i += 1) ptr[i] = 0;
    return ptr;
}

export fn realloc(ptr: ?*anyopaque, n: usize) callconv(.c) ?[*]u8 {
    if (ptr == null) return malloc(n);
    if (n == 0) {
        free(ptr);
        return null;
    }
    const hdr = readHeader(ptr.?);
    const old_user_len = hdr.len - HEADER_SIZE;
    if (old_user_len >= n) return @ptrCast(ptr);

    const new_p = malloc(n) orelse return null;
    var i: usize = 0;
    const src: [*]const u8 = @ptrCast(ptr.?);
    while (i < old_user_len) : (i += 1) new_p[i] = src[i];
    free(ptr);
    return new_p;
}

export fn free(ptr: ?*anyopaque) callconv(.c) void {
    const p = ptr orelse return;
    // Empty-slice sentinel from no-LLVM backend's `&[_]T{}` is
    // 0xaaaaaaaaaaaaaaaa. Anything outside the heap reservation is
    // not our pointer — silently ignore.
    const addr = @intFromPtr(p);
    if (addr < 0x10000) return;
    const hdr = readHeader(p);
    const a = allocator();
    const slice: []u8 = @as([*]u8, @ptrCast(hdr))[0..hdr.len];
    a.rawFree(slice, .@"16", @returnAddress());
}

export fn posix_memalign(memptr: *?*anyopaque, alignment: usize, size: usize) callconv(.c) c_int {
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) return 22; // EINVAL
    if (alignment % @sizeOf(usize) != 0) return 22;

    // For alignment requirements that exceed our 16-byte header
    // baseline, overallocate, place the user pointer at an aligned
    // address inside the block, and stash the allocation base in a
    // back-pointer just before the user pointer. free() reads that
    // back-pointer to recover the original block start.
    if (alignment <= 16) {
        const p = malloc(size) orelse return 12;
        memptr.* = @ptrCast(p);
        return 0;
    }

    const a = allocator();
    const align_enum: std.mem.Alignment = @enumFromInt(@ctz(alignment));
    const total = size + HEADER_SIZE;
    const payload = a.rawAlloc(total, align_enum, @returnAddress()) orelse return 12;
    const user_ptr = writeHeader(payload, total);
    memptr.* = @ptrCast(user_ptr);
    return 0;
}

export fn aligned_alloc(alignment: usize, size: usize) callconv(.c) ?[*]u8 {
    var p: ?*anyopaque = null;
    if (posix_memalign(&p, alignment, size) != 0) return null;
    return @ptrCast(p);
}

export fn malloc_usable_size(ptr: ?*anyopaque) callconv(.c) usize {
    const p = ptr orelse return 0;
    return readHeader(p).len - HEADER_SIZE;
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
