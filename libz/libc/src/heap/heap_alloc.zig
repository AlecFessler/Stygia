const std = @import("std");
const builtin = @import("builtin");

const intrusive_freelist = @import("intrusive_freelist.zig");
const rbt = @import("red_black_tree.zig");
const slab_alloc = @import("slab.zig");

const SpinLock = @import("spin_lock.zig").SpinLock;

pub const AllocFooter = packed struct(u64) {
    header: u64,
};

pub const AllocHeader = packed struct(u64) {
    is_free: bool,
    bucket_size: u63,
};

pub const AllocPadding = packed struct(u64) {
    header_offset: u64,
};

pub const HeapAllocator = struct {
    reserve_start: u64,
    commit_end: u64,
    reserve_end: u64,
    free_tree: RedBlackTree,
    lock: SpinLock = .{},

    pub fn init(
        reserve_start: u64,
        reserve_end: u64,
        tree_allocator: *TreeAllocator,
    ) HeapAllocator {
        std.debug.assert(std.mem.isAligned(reserve_start, @alignOf(AllocHeader)));
        return .{
            .reserve_start = reserve_start,
            .commit_end = reserve_start,
            .reserve_end = reserve_end,
            .free_tree = RedBlackTree.init(tree_allocator.allocator()),
        };
    }

    pub fn deinit(self: *HeapAllocator) void {
        self.free_tree.deinit();
    }

    pub fn allocator(self: *HeapAllocator) std.mem.Allocator {
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

        const self: *HeapAllocator = @ptrCast(@alignCast(ptr));
        self.lock.lock();
        defer self.lock.unlock();

        std.debug.assert(std.mem.isAligned(self.commit_end, header_align));

        const user_size: u64 = @max(min_user_size, @as(u64, @intCast(len)));
        const user_align: u64 = @max(min_user_align, @as(u64, @intCast(alignment.toByteUnits())));

        var block_base: u64 = 0;
        var user_block_base: u64 = 0;
        var block_end: u64 = 0;
        var bucket_size: u64 = 0;

        const upper_bound_iterations = 10_000;
        var outer_iterations: u64 = 0;
        const key = TreeEntry{ .bucket_size = user_size, .freelist = undefined };
        var maybe_tree_entry = findBestFitLowerBound(self.free_tree.root, key);
        tree_walk: while (maybe_tree_entry) |tree_entry| {
            if (dbg) {
                outer_iterations += 1;
                if (outer_iterations >= upper_bound_iterations) @panic("Non exitting loop");
            }

            var inner_iterations: u64 = 0;
            var maybe_list_entry: ?*Freelist.FreeNode = tree_entry.data.freelist.head;
            list_walk: while (maybe_list_entry) |list_entry| {
                if (dbg) {
                    inner_iterations += 1;
                    if (inner_iterations >= upper_bound_iterations) @panic("Non exitting loop");
                }

                block_base, user_block_base, block_end, bucket_size = getBlockMetadata(
                    @intCast(@intFromPtr(list_entry)),
                    user_size,
                    user_align,
                );

                const header: *AllocHeader = @ptrFromInt(block_base);
                std.debug.assert(header.is_free);

                const suitable_block = bucket_size <= header.bucket_size;
                if (!suitable_block) {
                    maybe_list_entry = list_entry.next;
                    continue :list_walk;
                }

                const footer_ptr: *AllocFooter = @ptrFromInt(block_end - footer_size);
                @prefetch(footer_ptr, .{});

                const list_entry_base = block_base + prefix_size;
                _ = tree_entry.data.freelist.popSpecific(@ptrFromInt(list_entry_base)).?;
                const bucket_is_now_empty = tree_entry.data.freelist.head == null;
                if (bucket_is_now_empty) {
                    _ = self.free_tree.removeFromPtr(tree_entry);
                }

                const split_size = header.bucket_size - bucket_size;
                const can_split = split_size >= min_block_size;
                if (can_split) {
                    var split_block_base: u64 = undefined;
                    var split_entry_base: u64 = undefined;
                    var split_footer_base: u64 = undefined;
                    var split_bucket_size: u64 = undefined;
                    split_block_base, split_entry_base, split_footer_base, split_bucket_size = getSplitBlockMetadata(
                        block_base,
                        bucket_size,
                        split_size,
                    );

                    const split_header: *AllocHeader = @ptrFromInt(split_block_base);
                    split_header.is_free = true;
                    split_header.bucket_size = @intCast(split_bucket_size);

                    const split_footer: *AllocFooter = @ptrFromInt(split_footer_base);
                    split_footer.header = split_block_base;

                    const split_entry: *FreelistEntry = @ptrFromInt(split_entry_base);
                    self.treeInsert(split_bucket_size, split_entry);

                    block_end = split_block_base;
                } else {
                    bucket_size = header.bucket_size;
                    block_end = block_base + prefix_size + bucket_size;
                }
                break :tree_walk;
            }
            maybe_tree_entry = findInOrderSuccessor(tree_entry);
            bucket_size = 0;
        }

        if (bucket_size == 0) {
            const list_entry = self.commit_end + prefix_size;
            block_base, user_block_base, block_end, bucket_size = getBlockMetadata(
                list_entry,
                user_size,
                user_align,
            );
            if (block_end > self.reserve_end) return null;
            self.commit_end += prefix_size + bucket_size;
        }

        const padding_base = user_block_base - padding_size;
        std.debug.assert(std.mem.isAligned(
            padding_base,
            padding_align,
        ));

        const footer_base = block_end - footer_size;
        std.debug.assert(std.mem.isAligned(
            footer_base,
            footer_align,
        ));

        const header: *AllocHeader = @ptrFromInt(block_base);
        header.is_free = false;
        header.bucket_size = @intCast(bucket_size);

        const padding: *AllocPadding = @ptrFromInt(padding_base);
        const header_offset = user_block_base - block_base;
        padding.header_offset = header_offset;

        const footer: *AllocFooter = @ptrFromInt(footer_base);
        footer.header = block_base;

        return @ptrFromInt(user_block_base);
    }

    fn findBestFitLowerBound(
        maybe_root: ?*RedBlackTree.Node,
        key: TreeEntry,
    ) ?*RedBlackTree.Node {
        const upper_bound_iterations = 10_000;
        var num_iterations: u64 = 0;

        var best_fit_lower_bound: ?*RedBlackTree.Node = null;
        var maybe_tree_entry = maybe_root;
        while (maybe_tree_entry) |tree_entry| {
            if (dbg) {
                num_iterations += 1;
                if (num_iterations >= upper_bound_iterations) @panic("Non exitting loop");
            }

            switch (TreeEntry.cmpFn(tree_entry.data, key)) {
                .lt => maybe_tree_entry = tree_entry.getChild(.right),
                else => {
                    best_fit_lower_bound = tree_entry;
                    maybe_tree_entry = tree_entry.getChild(.left);
                },
            }
        }
        return best_fit_lower_bound;
    }

    inline fn getBlockMetadata(
        freelist_entry_base: u64,
        user_size: u64,
        user_align: u64,
    ) struct {
        u64,
        u64,
        u64,
        u64,
    } {
        const block_base = freelist_entry_base - prefix_size;
        std.debug.assert(std.mem.isAligned(
            block_base,
            header_align,
        ));

        const user_block_base = std.mem.alignForward(u64, freelist_entry_base, user_align);
        const user_block_end = user_block_base + user_size;

        const footer_base = std.mem.alignForward(u64, user_block_end, footer_align);

        const block_end = footer_base + footer_size;
        std.debug.assert(std.mem.isAligned(
            block_end,
            header_align,
        ));

        const bucket_size = block_end - freelist_entry_base;

        return .{
            block_base,
            user_block_base,
            block_end,
            bucket_size,
        };
    }

    fn getSplitBlockMetadata(
        block_base: u64,
        bucket_size: u64,
        split_size: u64,
    ) struct {
        u64,
        u64,
        u64,
        u64,
    } {
        std.debug.assert(split_size >= min_block_size);

        const split_block_base = block_base + prefix_size + bucket_size;
        std.debug.assert(std.mem.isAligned(
            split_block_base,
            header_align,
        ));

        const split_block_ptr: [*]u8 = @ptrFromInt(split_block_base);
        @prefetch(split_block_ptr, .{});

        const split_bucket_size = split_size - prefix_size;

        const split_entry_base = split_block_base + prefix_size;
        std.debug.assert(std.mem.isAligned(
            split_entry_base,
            freelist_entry_align,
        ));

        const split_block_end = split_block_base + split_size;
        std.debug.assert(std.mem.isAligned(
            split_block_end,
            header_align,
        ));

        const split_footer_base = split_block_end - footer_size;
        std.debug.assert(std.mem.isAligned(
            split_footer_base,
            footer_align,
        ));

        return .{
            split_block_base,
            split_entry_base,
            split_footer_base,
            split_bucket_size,
        };
    }

    fn findInOrderSuccessor(tree_entry: *RedBlackTree.Node) ?*RedBlackTree.Node {
        const upper_bound_iterations = 10_000;
        var num_iterations: u64 = 0;

        if (tree_entry.getChild(.right)) |right_child| {
            var iterator = right_child;
            while (iterator.getChild(.left)) |left_child| {
                if (dbg) {
                    num_iterations += 1;
                    if (num_iterations >= upper_bound_iterations) @panic("Non exitting loop");
                }

                iterator = left_child;
            }
            return iterator;
        } else {
            var maybe_parent = tree_entry.parent;
            var child: *RedBlackTree.Node = tree_entry;
            while (maybe_parent) |parent| {
                if (dbg) {
                    num_iterations += 1;
                    if (num_iterations >= upper_bound_iterations) @panic("Non exitting loop");
                }

                const is_left_child = parent.getChild(.left) == child;
                if (is_left_child) return parent;
                child = parent;
                maybe_parent = parent.parent;
            }
            return null;
        }
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

        const self: *HeapAllocator = @ptrCast(@alignCast(ptr));
        self.lock.lock();
        defer self.lock.unlock();

        const user_base: u64 = @intCast(@intFromPtr(buf.ptr));
        const padding_base = user_base - padding_size;
        const padding: *AllocPadding = @ptrFromInt(padding_base);

        var header_base = user_base - padding.header_offset;
        var header: *AllocHeader = @ptrFromInt(header_base);
        std.debug.assert(!header.is_free);
        header.is_free = true;

        const block_end = header_base + prefix_size + header.bucket_size;

        const next_header: *AllocHeader = @ptrFromInt(block_end);
        @prefetch(next_header, .{});

        const block_footer: *AllocFooter = @ptrFromInt(block_end - footer_size);
        @prefetch(block_footer, .{});

        // Prefetch prev footer for merge_prev path
        const prev_footer_ptr: *AllocFooter = @ptrFromInt(header_base - footer_size);
        @prefetch(prev_footer_ptr, .{});

        merge_prev: {
            const prev_footer_base = header_base - footer_size;
            std.debug.assert(std.mem.isAligned(
                prev_footer_base,
                footer_align,
            ));
            const prev_footer_within_bounds = prev_footer_base > self.reserve_start;
            if (!prev_footer_within_bounds) break :merge_prev;
            const prev_footer: *AllocFooter = @ptrFromInt(prev_footer_base);

            const prev_header_within_bounds = self.reserve_start <= prev_footer.header;
            std.debug.assert(prev_header_within_bounds);
            const prev_header: *AllocHeader = @ptrFromInt(prev_footer.header);
            if (!prev_header.is_free) break :merge_prev;

            const prev_entry_base: u64 = prev_footer.header + prefix_size;
            const prev_node: *Freelist.FreeNode = @ptrFromInt(prev_entry_base);
            const prev_list: *Freelist = prev_node.base;

            _ = prev_list.popSpecific(@ptrCast(prev_node)).?;
            const prev_list_is_now_empty = prev_list.head == null;
            if (prev_list_is_now_empty) {
                const prev_entry_ptr: *TreeEntry = @fieldParentPtr("freelist", prev_list);
                const prev_node_ptr: *RedBlackTree.Node = @fieldParentPtr("data", prev_entry_ptr);
                _ = self.free_tree.removeFromPtr(prev_node_ptr);
            }

            header.is_free = false;
            header = prev_header;

            header_base = prev_footer.header;
            prev_footer.header = 0;

            header.bucket_size = @intCast(block_end - prev_entry_base);
        }

        merge_next: {
            std.debug.assert(std.mem.isAligned(
                block_end,
                header_align,
            ));
            const next_header_within_bounds = block_end <= self.reserve_end;
            if (!next_header_within_bounds) break :merge_next;
            if (!next_header.is_free) break :merge_next;

            const next_end: u64 = block_end + prefix_size + next_header.bucket_size;
            std.debug.assert(std.mem.isAligned(
                next_end,
                header_align,
            ));

            const footer_base = next_end - footer_size;
            const footer_ptr: *AllocFooter = @ptrFromInt(footer_base);
            @prefetch(footer_ptr, .{});

            const next_entry_base: u64 = block_end + prefix_size;
            const next_node: *Freelist.FreeNode = @ptrFromInt(next_entry_base);
            const next_list: *Freelist = next_node.base;

            _ = next_list.popSpecific(@ptrCast(next_node)).?;
            const next_list_is_now_empty = next_list.head == null;
            if (next_list_is_now_empty) {
                const next_entry_ptr: *TreeEntry = @fieldParentPtr("freelist", next_list);
                const next_node_ptr: *RedBlackTree.Node = @fieldParentPtr("data", next_entry_ptr);
                _ = self.free_tree.removeFromPtr(next_node_ptr);
            }

            next_header.is_free = false;
            const absorbed_footer_base = block_end - footer_size;
            const absorbed_footer: *AllocFooter = @ptrFromInt(absorbed_footer_base);
            absorbed_footer.header = 0;

            header.bucket_size = @intCast(next_end - (header_base + prefix_size));
        }

        const coalesced_prefix_end = header_base + prefix_size;
        const coalesced_block_end = coalesced_prefix_end + header.bucket_size;

        const footer_base = coalesced_block_end - footer_size;
        const footer: *AllocFooter = @ptrFromInt(footer_base);
        footer.header = header_base;

        const freelist_entry_base = header_base + prefix_size;
        const freelist_entry: *FreelistEntry = @ptrFromInt(freelist_entry_base);

        self.treeInsert(header.bucket_size, freelist_entry);
    }

    fn treeInsert(
        self: *HeapAllocator,
        bucket_size: u64,
        freelist_entry: *FreelistEntry,
    ) void {
        var current: ?*RedBlackTree.Node = self.free_tree.root;
        var parent: ?*RedBlackTree.Node = null;
        var direction: RedBlackTree.Direction = .left;

        const key: TreeEntry = .{ .bucket_size = bucket_size, .freelist = .{} };

        while (current) |c| {
            parent = c;
            switch (TreeEntry.cmpFn(key, c.data)) {
                .lt => {
                    direction = .left;
                    current = c.getChild(.left);
                },
                .gt => {
                    direction = .right;
                    current = c.getChild(.right);
                },
                .eq => {
                    c.data.freelist.push(freelist_entry);
                    return;
                },
            }
        }

        const new_node = self.free_tree.insertAtPtr(
            parent,
            direction,
            .{ .bucket_size = bucket_size, .freelist = .{} },
        ) catch unreachable;

        new_node.data.freelist.push(freelist_entry);
    }

    pub fn validateState(self: *HeapAllocator, tmp_alloc: std.mem.Allocator) bool {
        const tree_result = RedBlackTree.validateRedBlackTree(
            self.free_tree.root,
            null,
            null,
        );
        if (!tree_result.valid) return false;
        const BlockInfo = struct {
            header_addr: u64,
            entry_addr: u64,
            end_addr: u64,
            bucket_size: u64,
            is_free: bool,
            found_in_tree: bool,
        };

        const BlockMap = std.HashMap(
            usize,
            BlockInfo,
            std.hash_map.AutoContext(usize),
            std.hash_map.default_max_load_percentage,
        );

        var blocks = BlockMap.init(tmp_alloc);
        defer blocks.deinit();

        const Helper = struct {
            fn fail(
                reason: []const u8,
                ctx: struct {
                    reserve_start: u64 = 0,
                    commit_end: u64 = 0,
                    header_addr: u64 = 0,
                    entry_addr: u64 = 0,
                    end_addr: u64 = 0,
                    bucket_size: u64 = 0,
                    is_free: ?bool = null,
                    extra_a: usize = 0,
                    extra_b: usize = 0,
                },
            ) bool {
                std.debug.print(
                    "\n[Heap Validate Failed]\nreason={s}\nreserve_start={x} commit_end={x}\nheader={x} entry={x} end={x} len={d} is_free={any}\nextra_a={x} extra_b={x}\n",
                    .{
                        reason,
                        ctx.reserve_start,
                        ctx.commit_end,
                        ctx.header_addr,
                        ctx.entry_addr,
                        ctx.end_addr,
                        ctx.bucket_size,
                        ctx.is_free,
                        ctx.extra_a,
                        ctx.extra_b,
                    },
                );
                return false;
            }

            fn hdr(addr: u64) *AllocHeader {
                return @ptrFromInt(addr);
            }
            fn ftr(addr: u64) *AllocFooter {
                return @ptrFromInt(addr);
            }
        };

        var cur: u64 = std.mem.alignForward(u64, self.reserve_start, header_align);

        var prev_was_free = false;
        while (cur < self.commit_end) {
            if (cur + header_size > self.commit_end)
                return Helper.fail("header beyond commit_end", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                });

            const h = Helper.hdr(cur).*;

            if (h.bucket_size < (min_user_size + footer_size))
                return Helper.fail("bucket_size < MIN_LEN", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_size = h.bucket_size,
                    .is_free = h.is_free,
                });

            const block_end: u64 = cur + prefix_size + h.bucket_size;
            if (block_end > self.commit_end)
                return Helper.fail("block end > commit_end", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .end_addr = block_end,
                    .bucket_size = h.bucket_size,
                    .is_free = h.is_free,
                });

            const footer_addr: u64 = block_end - footer_size;
            if (h.is_free) {
                const ft = Helper.ftr(footer_addr).*;
                if (ft.header != cur) {
                    std.debug.print("[Heap Validate] extra footer mismatch context: header={x} footer_addr={x} ft.header={x} offset_from_header=+{x}\n", .{
                        cur,
                        footer_addr,
                        ft.header,
                        ft.header - cur,
                    });
                    return Helper.fail("free block footer does not backlink to header", .{
                        .reserve_start = self.reserve_start,
                        .commit_end = self.commit_end,
                        .header_addr = cur,
                        .end_addr = block_end,
                        .bucket_size = h.bucket_size,
                        .is_free = h.is_free,
                        .extra_a = @intCast(ft.header),
                    });
                }
            }

            if (prev_was_free and h.is_free)
                return Helper.fail("adjacent free blocks (coalescing invariant violated)", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_size = h.bucket_size,
                    .is_free = h.is_free,
                });

            const entry_addr: u64 = cur + prefix_size;
            const info = BlockInfo{
                .header_addr = cur,
                .entry_addr = entry_addr,
                .end_addr = block_end,
                .bucket_size = h.bucket_size,
                .is_free = h.is_free,
                .found_in_tree = false,
            };

            const prev = blocks.fetchPut(@intCast(cur), info) catch {
                return Helper.fail("out of memory inserting into block map", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_size = h.bucket_size,
                    .is_free = h.is_free,
                });
            };
            if (prev != null)
                return Helper.fail("duplicate header encountered in map", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_size = h.bucket_size,
                    .is_free = h.is_free,
                });

            prev_was_free = h.is_free;

            const next = std.mem.alignForward(u64, block_end, header_align);
            if (next <= cur)
                return Helper.fail("non-progressing linear walk", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .end_addr = block_end,
                    .bucket_size = h.bucket_size,
                    .is_free = h.is_free,
                    .extra_a = next,
                });
            cur = next;
        }

        if (cur != self.commit_end)
            return Helper.fail("walk did not end exactly at commit_end", .{
                .reserve_start = self.reserve_start,
                .commit_end = self.commit_end,
                .extra_a = cur,
            });

        var stack: [64]?*RedBlackTree.Node = undefined;
        var sp: usize = 0;

        if (self.free_tree.root) |root| {
            stack[sp] = root;
            sp += 1;

            while (sp > 0) {
                sp -= 1;
                const node = stack[sp].?;
                const entry_ptr: *TreeEntry = &node.data;

                var freenode = entry_ptr.freelist.head;
                while (freenode) |fnode| {
                    if (fnode.base != &entry_ptr.freelist)
                        return Helper.fail("freelist entry .base mismatch", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .entry_addr = @intCast(@intFromPtr(fnode)),
                            .extra_a = @intFromPtr(fnode.base),
                            .extra_b = @intFromPtr(&entry_ptr.freelist),
                        });

                    const list_ptr: *Freelist = fnode.base;
                    const parent_entry: *TreeEntry = @fieldParentPtr("freelist", list_ptr);
                    if (parent_entry != entry_ptr)
                        return Helper.fail("freelist back-pointer does not map to current TreeEntry", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .entry_addr = @intCast(@intFromPtr(fnode)),
                            .extra_a = @intFromPtr(parent_entry),
                            .extra_b = @intFromPtr(entry_ptr),
                        });

                    const entry_addr_u64: u64 = @intCast(@intFromPtr(fnode));
                    const header_addr: u64 = entry_addr_u64 - prefix_size;

                    if (header_addr < self.reserve_start or header_addr + header_size > self.commit_end)
                        return Helper.fail("freelist-derived header out of bounds", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u64,
                        });

                    const hptr = Helper.hdr(header_addr);
                    if (!hptr.is_free)
                        return Helper.fail("freelist points to non-free header", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u64,
                            .bucket_size = hptr.bucket_size,
                            .is_free = hptr.is_free,
                        });

                    if (hptr.bucket_size != entry_ptr.bucket_size)
                        return Helper.fail("tree node bucket_size != header bucket_size", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u64,
                            .bucket_size = hptr.bucket_size,
                            .extra_a = entry_ptr.bucket_size,
                        });

                    const bend: u64 = header_addr + prefix_size + hptr.bucket_size;
                    if (bend > self.commit_end)
                        return Helper.fail("block end (from freelist) > commit_end", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .end_addr = bend,
                            .bucket_size = hptr.bucket_size,
                            .is_free = hptr.is_free,
                        });

                    const ft = Helper.ftr(bend - footer_size).*;
                    if (ft.header != header_addr)
                        return Helper.fail("footer backlink mismatch (from freelist)", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .end_addr = bend,
                            .bucket_size = hptr.bucket_size,
                            .extra_a = @intCast(ft.header),
                        });

                    if (blocks.getPtr(@intCast(header_addr))) |bi| {
                        if (!bi.is_free)
                            return Helper.fail("map says allocated but listed in freelist", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .entry_addr = entry_addr_u64,
                                .bucket_size = bi.bucket_size,
                                .is_free = bi.is_free,
                            });
                        if (bi.entry_addr != entry_addr_u64)
                            return Helper.fail("map entry_addr != freelist entry addr", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .entry_addr = entry_addr_u64,
                                .extra_a = @intCast(bi.entry_addr),
                            });
                        if (bi.bucket_size != hptr.bucket_size)
                            return Helper.fail("map bucket_size != header bucket_size", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .bucket_size = hptr.bucket_size,
                                .extra_a = bi.bucket_size,
                            });
                        if (bi.end_addr != bend)
                            return Helper.fail("map end_addr != computed end_addr", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .end_addr = bend,
                                .extra_a = @intCast(bi.end_addr),
                            });
                        bi.found_in_tree = true;
                    } else {
                        return Helper.fail("free block in tree not found in map", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u64,
                            .bucket_size = hptr.bucket_size,
                            .is_free = hptr.is_free,
                        });
                    }

                    freenode = fnode.next;
                }

                if (node.getChild(.left)) |l| {
                    std.debug.assert(sp < stack.len);
                    stack[sp] = l;
                    sp += 1;
                }
                if (node.getChild(.right)) |r| {
                    std.debug.assert(sp < stack.len);
                    stack[sp] = r;
                    sp += 1;
                }
            }
        }

        var it = blocks.iterator();
        while (it.next()) |kv| {
            const bi = kv.value_ptr.*;
            if (bi.is_free and !bi.found_in_tree) {
                std.debug.print(
                    "\n[Heap Validate] Orphan free block\nheader={x} entry={x} end={x} len={d}\n",
                    .{ bi.header_addr, bi.entry_addr, bi.end_addr, bi.bucket_size },
                );
                return false;
            }
        }

        return true;
    }
};

pub const TreeEntry = struct {
    bucket_size: usize,
    freelist: Freelist,

    pub fn cmpFn(first: TreeEntry, second: TreeEntry) std.math.Order {
        return std.math.order(first.bucket_size, second.bucket_size);
    }
};

const FreelistEntry = struct {
    bytes: [freelist_entry_size]u8 align(freelist_entry_align),
};

const using_popSpecific = true;
const link_to_list = true;
pub const Freelist = intrusive_freelist.IntrusiveFreeList(
    *FreelistEntry,
    using_popSpecific,
    link_to_list,
);

const duplicate_is_error = false;
pub const RedBlackTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.cmpFn,
    duplicate_is_error,
);

const stack_bootstrap = false;
const stack_size = 0;
const allocation_chunk_size = 64;
pub const TreeAllocator = slab_alloc.SlabAllocator(
    RedBlackTree.Node,
    stack_bootstrap,
    stack_size,
    allocation_chunk_size,
    true,
);

const dbg = builtin.mode == .Debug;

const header_size = @sizeOf(AllocHeader);
const header_align = @alignOf(AllocHeader);

const padding_size = @sizeOf(AllocPadding);
const padding_align = @alignOf(AllocPadding);

const prefix_size = header_size + padding_size;

const footer_size = @sizeOf(AllocFooter);
const footer_align = @alignOf(AllocFooter);

const freelist_entry_align = @alignOf(u64);
const freelist_entry_size = @sizeOf(usize) * 4;

const min_user_size = freelist_entry_size;
const min_user_align = freelist_entry_align;

const min_block_size = prefix_size + min_user_size + footer_size;

test "tree contains after free, then removed after re-alloc (exact fit)" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u64 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u64 = reserve_start + @as(u64, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const N: usize = 128;

    var buf = try alloc.alloc(u8, N);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(buf);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const key_free: TreeEntry = .{ .bucket_size = N + 8, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_free));

    buf = try alloc.alloc(u8, N);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));
    defer {
        alloc.free(buf);
        _ = heap_allocator.validateState(std.testing.allocator);
    }

    try std.testing.expect(!heap_allocator.free_tree.contains(key_free));
}

test "no-split re-alloc consumes the exact-size free block (tail too small to split)" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u64 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u64 = reserve_start + @as(u64, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const L1: usize = 256;
    const big = try alloc.alloc(u8, L1);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(big);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const key_free: TreeEntry = .{ .bucket_size = L1 + 8, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_free));

    const S: usize = 208;
    const small_nosplit = try alloc.alloc(u8, S);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));
    defer {
        alloc.free(small_nosplit);
        _ = heap_allocator.validateState(std.testing.allocator);
    }

    try std.testing.expect(!heap_allocator.free_tree.contains(key_free));
}

test "split path: re-alloc creates a tail block, tree contains tail bucket_size" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u64 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u64 = reserve_start + @as(u64, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const L1: usize = 256;
    const big = try alloc.alloc(u8, L1);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(big);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const key_free: TreeEntry = .{ .bucket_size = L1 + 8, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_free));

    const S: usize = 64;
    const small_split = try alloc.alloc(u8, S);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));
    defer {
        alloc.free(small_split);
        _ = heap_allocator.validateState(std.testing.allocator);
    }

    const tail_bucket_size: usize = 176;

    const key_tail: TreeEntry = .{ .bucket_size = tail_bucket_size, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_tail));
    try std.testing.expect(!heap_allocator.free_tree.contains(key_free));
}

test "triple coalesce: free A, free C, then free B -> one big block" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u64 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u64 = reserve_start + @as(u64, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const A: usize = 128;
    const B: usize = 160;
    const C: usize = 96;

    const a = try alloc.alloc(u8, A);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const b = try alloc.alloc(u8, B);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const c = try alloc.alloc(u8, C);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(a);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(c);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(b);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const coalesced_len: usize = A + B + C + 56;

    const key_coalesced: TreeEntry = .{ .bucket_size = coalesced_len, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_coalesced));

    const key_A: TreeEntry = .{ .bucket_size = A + 8, .freelist = undefined };
    const key_B: TreeEntry = .{ .bucket_size = B + 8, .freelist = undefined };
    const key_C: TreeEntry = .{ .bucket_size = C + 8, .freelist = undefined };
    try std.testing.expect(!heap_allocator.free_tree.contains(key_A));
    try std.testing.expect(!heap_allocator.free_tree.contains(key_B));
    try std.testing.expect(!heap_allocator.free_tree.contains(key_C));
}
