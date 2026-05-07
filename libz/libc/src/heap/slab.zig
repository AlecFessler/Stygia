const std = @import("std");
const builtin = @import("builtin");

const intrusive_freelist = @import("intrusive_freelist.zig");

const SpinLock = @import("spin_lock.zig").SpinLock;

const DBG = builtin.mode == .Debug;

pub fn SlabAllocator(
    comptime T: type,
    comptime stack_bootstrap: bool,
    comptime stack_size: usize,
    comptime allocation_chunk_size: usize,
    comptime use_lock: bool,
) type {
    if (stack_bootstrap) {
        std.debug.assert(stack_size > 0);
    } else {
        std.debug.assert(stack_size == 0);
    }
    std.debug.assert(allocation_chunk_size > 0);

    const AllocHeader = struct {
        const Self = @This();
        ptr: [*]T,
        len: usize,
        next: ?*Self,
    };

    return struct {
        const Self = @This();
        const using_popSpecific = false;
        const link_to_list = false;
        const IntrusiveFreeList = intrusive_freelist.IntrusiveFreeList(*T, using_popSpecific, link_to_list);

        allocations: if (DBG) i64 else void,
        backing_allocator: std.mem.Allocator,
        stack_array: if (stack_bootstrap) [stack_size]T else void,
        stack_idx: if (stack_bootstrap) usize else void,
        freelist: IntrusiveFreeList = .{},
        alloc_headers: ?*AllocHeader = null,
        lock: if (use_lock) SpinLock else void = if (use_lock) .{} else {},

        pub fn init(
            backing_allocator: std.mem.Allocator,
        ) !Self {
            var self: Self = .{
                .allocations = if (DBG) 0,
                .stack_array = if (stack_bootstrap) [_]T{std.mem.zeroes(T)} ** stack_size,
                .stack_idx = if (stack_bootstrap) 0,
                .backing_allocator = backing_allocator,
            };

            if (!stack_bootstrap) {
                const slice = try self.backing_allocator.alloc(T, allocation_chunk_size);
                errdefer self.backing_allocator.free(slice);
                for (slice) |*slab| {
                    self.freelist.push(slab);
                }

                const alloc_header = try self.backing_allocator.create(AllocHeader);
                alloc_header.* = .{
                    .ptr = slice.ptr,
                    .len = slice.len,
                    .next = self.alloc_headers,
                };
                self.alloc_headers = alloc_header;
            }

            return self;
        }

        pub fn deinit(self: *Self) void {
            if (DBG) std.debug.assert(self.allocations == 0);

            while (self.alloc_headers) |alloc_header| {
                self.alloc_headers = alloc_header.next;
                const slice = alloc_header.ptr[0..alloc_header.len];
                self.backing_allocator.free(slice);
                self.backing_allocator.destroy(alloc_header);
            }
        }

        pub fn allocator(self: *Self) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn alloc(
            ptr: *anyopaque,
            len: usize,
            alignment: std.mem.Alignment,
            ret_addr: usize,
        ) ?[*]u8 {
            _ = ret_addr;

            std.debug.assert(alignment.toByteUnits() == @as(usize, @intCast(@alignOf(T))));
            std.debug.assert(len == @as(usize, @intCast(@sizeOf(T))));

            const self: *Self = @ptrCast(@alignCast(ptr));
            if (use_lock) self.lock.lock();
            defer if (use_lock) self.lock.unlock();

            if (stack_bootstrap and self.stack_idx < stack_size) {
                const slab = &self.stack_array[self.stack_idx];
                self.stack_idx += 1;
                if (DBG) self.allocations += 1;
                return @ptrCast(slab);
            }

            const maybe_slab = self.freelist.pop();
            if (maybe_slab) |slab| {
                if (DBG) self.allocations += 1;
                return @ptrCast(slab);
            }

            const slice = self.backing_allocator.alloc(T, allocation_chunk_size) catch return null;

            const alloc_header = self.backing_allocator.create(AllocHeader) catch {
                self.backing_allocator.free(slice);
                return null;
            };
            alloc_header.* = .{
                .ptr = slice.ptr,
                .len = slice.len,
                .next = self.alloc_headers,
            };
            self.alloc_headers = alloc_header;

            const new_slab = &slice[0];
            for (slice[1..]) |*slab| {
                self.freelist.push(slab);
            }

            if (DBG) self.allocations += 1;
            return @ptrCast(new_slab);
        }

        fn resize(
            ptr: *anyopaque,
            memory: []u8,
            alignment: std.mem.Alignment,
            new_len: usize,
            ret_addr: usize,
        ) bool {
            _ = ptr;
            _ = memory;
            _ = alignment;
            _ = new_len;
            _ = ret_addr;
            return false;
        }

        fn remap(
            ptr: *anyopaque,
            memory: []u8,
            alignment: std.mem.Alignment,
            new_len: usize,
            ret_addr: usize,
        ) ?[*]u8 {
            _ = ptr;
            _ = memory;
            _ = alignment;
            _ = new_len;
            _ = ret_addr;
            return null;
        }

        fn free(
            ptr: *anyopaque,
            buf: []u8,
            alignment: std.mem.Alignment,
            ret_addr: usize,
        ) void {
            _ = alignment;
            _ = ret_addr;
            const self: *Self = @ptrCast(@alignCast(ptr));
            const slab: *T = @ptrCast(@alignCast(buf.ptr));

            if (use_lock) self.lock.lock();
            defer if (use_lock) self.lock.unlock();

            if (DBG) self.allocations -= 1;
            if (DBG) std.debug.assert(self.allocations >= 0);

            self.freelist.push(slab);
        }
    };
}

const TestType = struct { data: u64, pad: u64 };

test "stack exhaustion and transition" {
    const stack_bootstrap = true;
    const stack_size = 4;
    const allocation_chunk_size = 8;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
        false,
    ).init(test_allocator);
    defer slab_allocator.deinit();

    const allocator = slab_allocator.allocator();

    var stack_objs: [stack_size]*TestType = undefined;
    for (0..stack_size) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        stack_objs[i] = obj;
    }

    const heap_obj = try allocator.create(TestType);
    heap_obj.* = .{ .data = 999, .pad = 0 };

    for (stack_objs) |ptr| allocator.destroy(ptr);
    allocator.destroy(heap_obj);
}

test "stack bootstrap stress test" {
    const stack_bootstrap = true;
    const stack_size = 4;
    const allocation_chunk_size = 16;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
        false,
    ).init(test_allocator);
    defer slab_allocator.deinit();

    const allocator = slab_allocator.allocator();

    const stack_start = @intFromPtr(&slab_allocator.stack_array[0]);
    const stack_end = stack_start + stack_size * @sizeOf(TestType);
    const isFromStack = struct {
        fn check(ptr: *TestType, start: usize, end: usize) bool {
            const addr = @intFromPtr(ptr);
            return addr >= start and addr < end;
        }
    }.check;

    var stack_count: usize = 0;
    var heap_count: usize = 0;
    var objs: [100]*TestType = undefined;

    for (0..100) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;

        if (isFromStack(obj, stack_start, stack_end)) {
            stack_count += 1;
        } else {
            heap_count += 1;
        }
    }

    try std.testing.expect(stack_count == stack_size);
    try std.testing.expect(heap_count == 100 - stack_size);

    for (objs) |ptr| allocator.destroy(ptr);
}

test "allocation failure with exhausted stack" {
    const stack_bootstrap = true;
    const stack_size = 3;
    const allocation_chunk_size = 8;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
        false,
    ).init(test_allocator);
    defer slab_allocator.deinit();

    const allocator = slab_allocator.allocator();

    var stack_objs: [stack_size]*TestType = undefined;
    for (0..stack_size) |i| {
        const obj = try allocator.create(TestType);
        stack_objs[i] = obj;
    }

    var failing_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    const failing_alloc = failing_allocator.allocator();
    slab_allocator.backing_allocator = failing_alloc;

    const result = allocator.create(TestType);
    try std.testing.expect(result == error.OutOfMemory);

    slab_allocator.backing_allocator = test_allocator;

    for (stack_objs) |ptr| allocator.destroy(ptr);
}

test "basic create destroy cycle" {
    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 16;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
        false,
    ).init(test_allocator);
    defer slab_allocator.deinit();

    const allocator = slab_allocator.allocator();

    const obj1 = try allocator.create(TestType);
    obj1.* = .{ .data = 42, .pad = 0 };

    const obj2 = try allocator.create(TestType);
    obj2.* = .{ .data = 84, .pad = 0 };

    try std.testing.expect(obj1.data == 42);
    try std.testing.expect(obj2.data == 84);

    allocator.destroy(obj1);
    allocator.destroy(obj2);

    const obj3 = try allocator.create(TestType);
    const obj4 = try allocator.create(TestType);

    try std.testing.expect(obj3 == obj2);
    try std.testing.expect(obj4 == obj1);

    allocator.destroy(obj3);
    allocator.destroy(obj4);
}

test "memory leak detection" {
    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 32;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
        false,
    ).init(test_allocator);
    defer slab_allocator.deinit();

    const allocator = slab_allocator.allocator();

    var objs: [200]*TestType = undefined;
    for (0..200) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;
        try std.testing.expect(obj.data == i);
    }

    for (objs) |ptr| allocator.destroy(ptr);
}
