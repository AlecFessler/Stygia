const std = @import("std");
const stygia = @import("stygia");

const bitmap_freelist = stygia.memory.allocators.bitmap_freelist;
const intrusive_freelist = stygia.memory.allocators.intrusive_freelist;

pub const BuddyAllocator = struct {
    start_addr: u64,
    end_addr: u64,
    init_allocator: std.mem.Allocator,
    page_pair_orders: []PagePairOrders = undefined,
    bitmap: BitmapFreeList = undefined,
    freelists: [NUM_ORDERS]IntrusiveFreeList = [_]IntrusiveFreeList{IntrusiveFreeList{}} ** NUM_ORDERS,
    /// Static total page count, established by `addRegion`. Accessed
    /// via `totalPageCount()` for the `sys_info` syscall (§2.15.2).
    total_pages: u64 = 0,
    /// Current free page count across all order-N freelists. Incremented
    /// in `free`/`addRegion` and decremented in `alloc`. Does **not** account
    /// for pages that were allocated from the buddy but are sitting in
    /// `pmm.PhysicalMemoryManager`'s per-core page caches — those are
    /// observed as free by userspace and must be added back in by
    /// `pmm.freePageCount()` (§21 "pmm.freePageCount").
    free_pages: u64 = 0,

    pub fn init(
        start_addr: u64,
        end_addr: u64,
        init_allocator: std.mem.Allocator,
    ) !BuddyAllocator {
        std.debug.assert(end_addr > start_addr);
        const aligned_start = std.mem.alignForward(u64, start_addr, PAGE_SIZE);
        const aligned_end = std.mem.alignBackward(u64, end_addr, PAGE_SIZE);
        std.debug.assert(aligned_end > aligned_start);

        var self: BuddyAllocator = .{
            .start_addr = aligned_start,
            .end_addr = aligned_end,
            .init_allocator = init_allocator,
        };

        const total_bytes = aligned_end - aligned_start;
        const num_pages = total_bytes / PAGE_SIZE;
        const num_pairs = std.math.divCeil(u64, num_pages, 2) catch unreachable;

        const initially_free = false;
        self.bitmap = try BitmapFreeList.init(
            aligned_start,
            PAGE_SIZE,
            num_pages,
            initially_free,
            init_allocator,
        );
        errdefer self.bitmap.deinit();

        self.page_pair_orders = try init_allocator.alloc(PagePairOrders, num_pairs);
        errdefer init_allocator.free(self.page_pair_orders);
        @memset(self.page_pair_orders, .{
            .even = 0,
            .odd = 0,
        });

        return self;
    }

    pub fn addRegion(
        self: *BuddyAllocator,
        start_addr: u64,
        end_addr: u64,
    ) void {
        std.debug.assert(end_addr > start_addr);
        const aligned_start = std.mem.alignForward(u64, start_addr, PAGE_SIZE);
        const aligned_end = std.mem.alignBackward(u64, end_addr, PAGE_SIZE);
        std.debug.assert(aligned_end > aligned_start);

        const num_pages = (aligned_end - aligned_start) / PAGE_SIZE;
        self.total_pages += num_pages;
        self.free_pages += num_pages;

        // Bulk path: directly compute the largest aligned buddy blocks that
        // tile the contiguous range, avoiding per-page free() + recursiveMerge.
        // For each position, find the highest order block that is both
        // naturally aligned (relative to self.start_addr) and fits within
        // the remaining range. Then attempt to merge each placed block with
        // its buddy (which may have been freed by a prior addRegion call)
        // to maintain the coalescing invariant.
        var current_addr = aligned_start;
        while (current_addr < aligned_end) {
            const remaining = aligned_end - current_addr;
            const rel = current_addr - self.start_addr;

            // Find the highest order we can place here:
            // 1) Block size must fit in remaining space
            // 2) Address must be naturally aligned for that order
            //    (relative to allocator base)
            // 3) Block must not extend past allocator end_addr
            var order: u4 = MAX_ORDER;
            while (order > 0) {
                const block_size = ORDERS[order];
                if (block_size <= remaining and
                    (rel & (block_size - 1)) == 0 and
                    current_addr + block_size <= self.end_addr)
                {
                    break;
                }
                order -= 1;
            }

            self.setOrder(current_addr, order);
            self.bitmap.setBit(current_addr, 1);
            self.freelists[order].push(@ptrFromInt(current_addr));

            // Attempt to merge this block with its buddy recursively,
            // handling the case where a prior addRegion freed adjacent memory.
            self.mergeFromFreelist(current_addr);

            current_addr += ORDERS[order];
        }
    }

    pub fn deinit(self: *BuddyAllocator) void {
        self.init_allocator.free(self.page_pair_orders);
        self.bitmap.deinit();
    }

    /// Allocate a `len`-byte block whose size is a power-of-two multiple
    /// of `PAGE_SIZE`. Returns null if no block is available at the
    /// required order. `len` is asserted to be page-aligned; callers
    /// compute the block size by rounding up to the next power of two.
    pub fn allocBlock(self: *BuddyAllocator, len: u64) ?[*]u8 {
        std.debug.assert(len % PAGE_SIZE == 0);
        std.debug.assert(len > 0);
        const num_pages = len / PAGE_SIZE;
        std.debug.assert((num_pages & (num_pages - 1)) == 0);
        const order: u4 = @intCast(@ctz(num_pages));
        std.debug.assert(order < NUM_ORDERS);

        const addr = self.recursiveSplit(order) orelse return null;
        self.bitmap.setBit(addr, 0);

        // Accounting for pmm.freePageCount (§14, §21). Every successful
        // alloc removes `num_pages` pages from the free pool.
        if (self.free_pages >= num_pages) {
            self.free_pages -= num_pages;
        } else {
            self.free_pages = 0;
        }

        return @ptrFromInt(addr);
    }

    /// Return a power-of-two block previously returned by `allocBlock`
    /// (or by `splitAllocation`) to the freelist, coalescing with its
    /// buddy where possible.
    pub fn freeBlock(self: *BuddyAllocator, buf: []u8) void {
        const addr = @intFromPtr(buf.ptr);
        const result = self.recursiveMerge(addr);
        self.bitmap.setBit(result.addr, 1);
        self.freelists[result.order].push(@ptrFromInt(result.addr));

        // Accounting for pmm.freePageCount (§14, §21). `buf.len` covers the
        // full allocated block regardless of whether `recursiveMerge` then
        // coalesced with a sibling; the coalesced sibling was already
        // counted when it was originally freed.
        const num_pages = buf.len / PAGE_SIZE;
        self.free_pages += num_pages;
    }

    pub fn splitAllocation(
        self: *BuddyAllocator,
        addr: u64,
        split_order: u4,
    ) FreeListBatch {
        const order = self.getOrder(addr);
        std.debug.assert(split_order < order);

        var batch: FreeListBatch = .{};

        var current_addr = addr;
        const end_addr = addr + ORDERS[order];
        const block_size = ORDERS[split_order];
        while (current_addr < end_addr) {
            self.setOrder(current_addr, split_order);
            self.bitmap.setBit(current_addr, 0);
            batch.push(@ptrFromInt(current_addr));
            current_addr += block_size;
        }

        return batch;
    }

    fn recursiveSplit(self: *BuddyAllocator, order: u4) ?u64 {
        const addr_ptr = self.freelists[order].pop() orelse {
            if (order == MAX_ORDER) return null;

            const higher = order + 1;
            const recursive_addr = self.recursiveSplit(higher) orelse return null;

            const rel = recursive_addr - self.start_addr;
            const buddy = self.start_addr + (rel ^ ORDERS[order]);

            if (self.start_addr <= buddy and buddy < self.end_addr) {
                self.setOrder(buddy, order);
                self.bitmap.setBit(buddy, 1);
                self.freelists[order].push(@ptrFromInt(buddy));
            }

            self.setOrder(recursive_addr, order);
            return recursive_addr;
        };

        const addr = @intFromPtr(addr_ptr);
        return addr;
    }

    /// Attempt to merge a block that is already on its freelist with its
    /// buddy. Used by the bulk addRegion path where blocks are placed
    /// directly and may be mergeable with blocks from a prior addRegion.
    fn mergeFromFreelist(self: *BuddyAllocator, addr: u64) void {
        var current = addr;
        while (true) {
            const order = self.getOrder(current);
            if (order == MAX_ORDER) return;

            const rel = current - self.start_addr;
            const buddy = self.start_addr + (rel ^ ORDERS[order]);

            if (buddy < self.start_addr or buddy >= self.end_addr) return;
            if (!self.bitmap.isFree(buddy)) return;
            if (self.getOrder(buddy) != order) return;

            // Both current and buddy are free at the same order — merge.
            // Remove both from the freelist.
            const removed_buddy = self.freelists[order].popSpecific(@ptrFromInt(buddy));
            std.debug.assert(removed_buddy != null);
            const removed_self = self.freelists[order].popSpecific(@ptrFromInt(current));
            std.debug.assert(removed_self != null);

            const lower = @min(current, buddy);
            const upper = @max(current, buddy);
            self.bitmap.setBit(lower, 1);
            self.bitmap.setBit(upper, 0);

            const higher = order + 1;
            self.setOrder(lower, higher);
            self.freelists[higher].push(@ptrFromInt(lower));
            current = lower;
        }
    }

    fn recursiveMerge(self: *BuddyAllocator, addr: u64) struct { addr: u64, order: u4 } {
        const order = self.getOrder(addr);
        if (order == MAX_ORDER) return .{ .addr = addr, .order = order };

        const rel = addr - self.start_addr;
        const buddy = self.start_addr + (rel ^ ORDERS[order]);
        const buddy_out_of_bounds = buddy < self.start_addr or buddy >= self.end_addr;

        if (buddy_out_of_bounds) {
            return .{ .addr = addr, .order = order };
        }

        const is_buddy_free = self.bitmap.isFree(buddy);
        if (!is_buddy_free) {
            return .{ .addr = addr, .order = order };
        }

        const buddy_order = self.getOrder(buddy);
        if (buddy_order != order) {
            return .{ .addr = addr, .order = order };
        }

        const removed = self.freelists[order].popSpecific(@ptrFromInt(buddy));
        std.debug.assert(removed != null);

        const lower_half = @min(addr, buddy);
        const upper_half = @max(addr, buddy);

        self.bitmap.setBit(lower_half, 0);
        self.bitmap.setBit(upper_half, 0);

        const higher = order + 1;
        self.setOrder(lower_half, higher);
        return self.recursiveMerge(lower_half);
    }

    fn getOrder(self: *BuddyAllocator, addr: u64) u4 {
        const page_idx = (addr - self.start_addr) / PAGE_SIZE;
        const pair_idx = page_idx / 2;
        const is_odd = page_idx % 2 == 1;
        if (is_odd) {
            return self.page_pair_orders[pair_idx].odd;
        } else {
            return self.page_pair_orders[pair_idx].even;
        }
    }

    fn setOrder(self: *BuddyAllocator, addr: u64, order: u4) void {
        const page_idx = (addr - self.start_addr) / PAGE_SIZE;
        const pair_idx = page_idx / 2;
        const is_odd = page_idx % 2 == 1;
        if (is_odd) {
            self.page_pair_orders[pair_idx].odd = order;
        } else {
            self.page_pair_orders[pair_idx].even = order;
        }
    }

    pub const AllocationMap = std.HashMap(
        u64,
        struct { size: u64, order: u4 },
        std.hash_map.AutoContext(u64),
        std.hash_map.default_max_load_percentage,
    );

    pub fn validateState(self: *BuddyAllocator, allocations: *AllocationMap) bool {
        const Helper = struct {
            fn fail(reason: []const u8, ctx: struct {
                start_addr: u64 = 0,
                end_addr: u64 = 0,
                page_size: u64 = 0,
                order: u64 = 0,
                addr: u64 = 0,
                end: u64 = 0,
                buddy: u64 = 0,
                expected_order: u64 = 0,
                extra_a: u64 = 0,
                extra_b: u64 = 0,
            }) bool {
                std.debug.print(
                    "\n[Buddy Validate Failed]\nreason={s}\nstart={x} end={x} page_size={d}\norder={d} addr={x} end={x} buddy={x} expected_order={d}\nextra_a={x} extra_b={x}\n",
                    .{
                        reason,
                        ctx.start_addr,
                        ctx.end_addr,
                        ctx.page_size,
                        ctx.order,
                        ctx.addr,
                        ctx.end,
                        ctx.buddy,
                        ctx.expected_order,
                        ctx.extra_a,
                        ctx.extra_b,
                    },
                );
                return false;
            }

            fn isAligned(x: u64, a: u64) bool {
                return (x & (a - 1)) == 0;
            }
        };

        const start = self.start_addr;
        const end = self.end_addr;

        if (!(end > start))
            return Helper.fail("end_addr <= start_addr", .{ .start_addr = start, .end_addr = end });
        if (!Helper.isAligned(start, PAGE_SIZE))
            return Helper.fail("start_addr not PAGE_SIZE aligned", .{ .start_addr = start, .page_size = PAGE_SIZE });
        if (!Helper.isAligned(end, PAGE_SIZE))
            return Helper.fail("end_addr not PAGE_SIZE aligned", .{ .end_addr = end, .page_size = PAGE_SIZE });

        // Collect every free block (base -> order) to (a) spot duplicates and
        // (b) let page-scan cheaply verify membership.
        var free_map = std.AutoHashMap(u64, u4).init(self.init_allocator);
        defer free_map.deinit();

        var order: u64 = 0;
        while (order < NUM_ORDERS) {
            const blk_size = ORDERS[order];
            var node = self.freelists[order].head;

            while (node) |n| {
                const base = @intFromPtr(n);
                const end_addr = base + blk_size;

                if (base < start or end_addr > end)
                    return Helper.fail("free block out of bounds", .{
                        .start_addr = start,
                        .end_addr = end,
                        .order = order,
                        .addr = base,
                        .end = end_addr,
                    });

                if (!Helper.isAligned(base, PAGE_SIZE))
                    return Helper.fail("free block not page aligned", .{
                        .addr = base,
                        .page_size = PAGE_SIZE,
                        .order = order,
                    });

                // Free-list node must reflect "free" in bitmap and order table at the base page.
                if (!self.bitmap.isFree(base))
                    return Helper.fail("bitmap says allocated but in freelist", .{
                        .addr = base,
                        .order = order,
                    });
                if (self.getOrder(base) != order)
                    return Helper.fail("getOrder(base) != freelist order", .{
                        .addr = base,
                        .order = order,
                        .extra_a = self.getOrder(base),
                    });

                // No duplicate base addresses across all freelists.
                if (free_map.contains(base))
                    return Helper.fail("duplicate free node address across freelists", .{
                        .addr = base,
                        .order = order,
                        .extra_a = free_map.get(base).?,
                    });
                free_map.put(base, @intCast(order)) catch
                    return Helper.fail("OOM inserting into free_map", .{ .order = order });

                // Interior pages of a free block must *not* be individually marked free.
                var inner = base + PAGE_SIZE;
                while (inner < end_addr) {
                    if (self.bitmap.isFree(inner))
                        return Helper.fail("interior page of a free block marked free", .{
                            .addr = inner,
                            .order = order,
                            .extra_a = base,
                            .extra_b = end_addr,
                        });
                    inner += PAGE_SIZE;
                }

                node = n.next;
            }
            order += 1;
        }

        // Page-level scan
        const total_pages = (end - start) / PAGE_SIZE;
        var page_idx: u64 = 0;
        while (page_idx < total_pages) {
            const addr = start + page_idx * PAGE_SIZE;
            const ord: u64 = self.getOrder(addr);
            const is_free = self.bitmap.isFree(addr);

            if (!is_free) {
                // Not free: either allocated base, interior of a larger allocation,
                // or interior of a free block (which should never be marked free anyway).
                if (allocations.get(addr)) |info| {
                    const num_pages = info.size / PAGE_SIZE;
                    if (num_pages == 0 or (num_pages & (num_pages - 1)) != 0)
                        return Helper.fail("allocation size not power-of-two pages", .{
                            .addr = addr,
                            .extra_a = info.size,
                        });
                    const expected: u64 = @ctz(num_pages);
                    if (ord != expected)
                        return Helper.fail("allocated page order mismatch", .{
                            .addr = addr,
                            .order = ord,
                            .expected_order = expected,
                        });
                }
                page_idx += 1;
                continue;
            }

            // Bitmap says free: must not appear in allocations map.
            if (allocations.contains(addr))
                return Helper.fail("bitmap says free but recorded as allocated", .{ .addr = addr, .order = ord });

            // Free page must be present as a freelist base (use free_map from pass 1).
            if (!free_map.contains(addr))
                return Helper.fail("free page not found in freelists", .{ .addr = addr, .order = ord });

            // Buddy coalescing invariant: two free buddies of same order should not coexist.
            if (ord < (NUM_ORDERS - 1)) {
                const size = ORDERS[ord];
                const buddy = start + (((addr - start) ^ size));
                if (!(buddy < start or buddy >= end)) {
                    if (self.bitmap.isFree(buddy) and self.getOrder(buddy) == ord) {
                        return Helper.fail("coalescing missed: both buddies free at same order", .{
                            .addr = addr,
                            .buddy = buddy,
                            .order = ord,
                        });
                    }
                }
            }
            page_idx += 1;
        }

        return true;
    }
};

pub const Page = struct {
    bytes: [PAGE_SIZE]u8 align(PAGE_SIZE),

    comptime {
        std.debug.assert(@sizeOf(Page) == PAGE_SIZE);
        std.debug.assert(@alignOf(Page) == PAGE_SIZE);
    }
};

const PagePairOrders = packed struct {
    even: u4,
    odd: u4,

    comptime {
        std.debug.assert(@sizeOf(PagePairOrders) == 1);
    }
};

const using_popSpecific = true;
const link_to_list = false;
pub const FreeListBatch = intrusive_freelist.IntrusiveFreeList(
    *Page,
    !using_popSpecific,
    link_to_list,
);

const using_getNextFree = false;
const BitmapFreeList = bitmap_freelist.BitmapFreeList(using_getNextFree);

const IntrusiveFreeList = intrusive_freelist.IntrusiveFreeList(
    *Page,
    using_popSpecific,
    link_to_list,
);

// MAX_ORDER=15 → max single allocation = 2^15 * 4 KiB = 128 MiB. Bumped
// from 14 (64 MiB) to accommodate the cross-compiled Zig compiler ELF
// (~70 MiB stripped → rounded up to 128 MiB / order 15). Stays within
// u4 (which can represent 0-15).
const MAX_ORDER = 15;
const NUM_ORDERS = MAX_ORDER + 1;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]u64 = undefined;
    for (0..NUM_ORDERS) |i| {
        arr[i] = (1 << i) * PAGE_SIZE;
    }
    break :blk arr;
};
const PAGE_SIZE = 4096;

test "buddy allocator init fails with failing allocator" {
    const allocator = std.testing.failing_allocator;

    var test_allocator = std.testing.allocator;
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        5 * ORDERS[10],
    );
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + 5 * ORDERS[10];

    try std.testing.expectError(
        error.OutOfMemory,
        BuddyAllocator.init(
            start_addr,
            end_addr,
            allocator,
        ),
    );
}

test "out of bounds buddy handling - fragmentation recovery" {
    var test_allocator = std.testing.allocator;

    const total_size = ORDERS[10] + ORDERS[6];
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(ORDERS[10]),
        total_size,
    );
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    var allocations = BuddyAllocator.AllocationMap.init(test_allocator);
    defer allocations.deinit();

    try std.testing.expect(buddy.validateState(&allocations));

    const order_10_ptr = buddy.allocBlock(ORDERS[10]).?;
    try allocations.put(@intFromPtr(order_10_ptr), .{ .size = ORDERS[10], .order = 10 });
    try std.testing.expect(buddy.validateState(&allocations));

    const order_4_ptr = buddy.allocBlock(ORDERS[4]).?;
    const order_4_addr = @intFromPtr(order_4_ptr);
    try allocations.put(order_4_addr, .{ .size = ORDERS[4], .order = 4 });
    try std.testing.expect(buddy.validateState(&allocations));

    try std.testing.expectEqual(@as(u4, 4), buddy.getOrder(order_4_addr));

    buddy.freeBlock(order_4_ptr[0..ORDERS[4]]);
    _ = allocations.remove(order_4_addr);
    try std.testing.expect(buddy.validateState(&allocations));

    try std.testing.expectEqual(@as(u4, 6), buddy.getOrder(order_4_addr));

    buddy.freeBlock(order_10_ptr[0..ORDERS[10]]);
    _ = allocations.remove(@intFromPtr(order_10_ptr));
    try std.testing.expect(buddy.validateState(&allocations));
}

test "recursiveMerge coalesces adjacent buddies and returns final state" {
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        ORDERS[1],
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    const addr1 = buddy.recursiveSplit(0).?;
    const addr2 = buddy.recursiveSplit(0).?;

    try std.testing.expect(buddy.getOrder(addr1) == 0);
    try std.testing.expect(buddy.getOrder(addr2) == 0);

    buddy.bitmap.setBit(addr1, 1);
    buddy.freelists[0].push(@ptrFromInt(addr1));

    buddy.bitmap.setBit(addr2, 1);
    const result = buddy.recursiveMerge(addr2);

    const expected_lower = @min(addr1, addr2);
    try std.testing.expectEqual(expected_lower, result.addr);
    try std.testing.expectEqual(@as(u4, 1), result.order);
}

test "recursiveSplit splits larger blocks into smaller ones" {
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        ORDERS[1],
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    try std.testing.expect(buddy.freelists[1].head != null);
    try std.testing.expect(buddy.freelists[0].head == null);

    const addr1 = buddy.recursiveSplit(0).?;

    try std.testing.expectEqual(@as(u4, 0), buddy.getOrder(addr1));

    try std.testing.expect(buddy.freelists[0].head != null);
    try std.testing.expect(buddy.freelists[1].head == null);

    const addr2 = buddy.recursiveSplit(0).?;
    try std.testing.expectEqual(@as(u4, 0), buddy.getOrder(addr2));

    try std.testing.expect(buddy.freelists[0].head == null);

    const diff = if (addr2 > addr1) addr2 - addr1 else addr1 - addr2;
    try std.testing.expectEqual(ORDERS[0], diff);
}

test "split allocation handles order changes correctly" {
    const test_allocator = std.testing.allocator;
    const total_size: u64 = 2 * ORDERS[10];
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        total_size,
    );
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    var allocations = BuddyAllocator.AllocationMap.init(test_allocator);
    defer allocations.deinit();

    var freelist: FreeListBatch = .{};

    const allocation = buddy.allocBlock(ORDERS[10]).?;
    try allocations.put(@intFromPtr(allocation), .{ .size = ORDERS[10], .order = 10 });
    try std.testing.expect(buddy.validateState(&allocations));

    _ = allocations.remove(@intFromPtr(allocation));
    var split = buddy.splitAllocation(@intFromPtr(allocation), 0);
    var count: u64 = 0;
    while (split.pop()) |page| {
        count += 1;
        freelist.push(page);
        try allocations.put(@intFromPtr(page), .{ .size = ORDERS[0], .order = 0 });
    }
    try std.testing.expect(buddy.validateState(&allocations));
    try std.testing.expect(count == 1024);

    while (freelist.pop()) |page| {
        _ = allocations.remove(@intFromPtr(page));
        const page_slice: []u8 = @as([*]u8, @ptrCast(page))[0..PAGE_SIZE];
        buddy.freeBlock(page_slice);
        try std.testing.expect(buddy.validateState(&allocations));
    }
}

test "split region logic with buddy allocator" {
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        ORDERS[6] + ORDERS[0] + ORDERS[4],
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[6] + ORDERS[0] + ORDERS[4];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, start_addr + ORDERS[6]);
    buddy.addRegion(start_addr + ORDERS[6] + ORDERS[0], start_addr + ORDERS[6] + ORDERS[0] + ORDERS[4]);

    const first_alloc = start_addr;
    const second_alloc = start_addr + ORDERS[6] + ORDERS[0];

    try std.testing.expect(first_alloc + ORDERS[6] != second_alloc);

    var allocations = BuddyAllocator.AllocationMap.init(allocator);
    defer allocations.deinit();

    const order_5_ptr = buddy.allocBlock(ORDERS[5]).?;
    try allocations.put(@intFromPtr(order_5_ptr), .{ .size = ORDERS[5], .order = 5 });
    try std.testing.expect(buddy.validateState(&allocations));

    const order_2_ptr = buddy.allocBlock(ORDERS[2]).?;
    try allocations.put(@intFromPtr(order_2_ptr), .{ .size = ORDERS[2], .order = 2 });
    try std.testing.expect(buddy.validateState(&allocations));

    try std.testing.expect(@intFromPtr(order_5_ptr) >= first_alloc);
    try std.testing.expect(@intFromPtr(order_5_ptr) + ORDERS[5] <= first_alloc + ORDERS[6]);

    try std.testing.expect(@intFromPtr(order_2_ptr) >= second_alloc);
    try std.testing.expect(@intFromPtr(order_2_ptr) + ORDERS[2] <= second_alloc + ORDERS[4]);

    try std.testing.expect(buddy.validateState(&allocations));
}
