const std = @import("std");
const builtin = @import("builtin");

const DBG = builtin.mode == .Debug;
const DBG_MAGIC = 0x0DEAD2A6DEAD2A60;

pub fn IntrusiveFreeList(
    comptime T: type,
    comptime using_popSpecific: bool,
    comptime link_to_base: bool,
) type {
    std.debug.assert(@typeInfo(T) == .pointer);
    const ValType = std.meta.Child(T);

    return struct {
        const Self = @This();

        head: ?*FreeNode = null,

        pub const FreeNode = struct {
            dbg_magic: if (DBG) u64 else void,
            next: ?*FreeNode = null,
            prev: if (using_popSpecific) ?*FreeNode else void = if (using_popSpecific) null,
            base: if (link_to_base) *Self else void,
        };

        comptime {
            std.debug.assert(@sizeOf(ValType) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(ValType) >= @alignOf(FreeNode));
        }

        pub fn push(self: *Self, addr: T) void {
            zeroItem(@ptrCast(addr));
            const node: *FreeNode = @ptrCast(@alignCast(addr));

            if (DBG) node.dbg_magic = DBG_MAGIC;
            if (using_popSpecific) {
                if (self.head) |head| {
                    head.prev = node;
                }
                node.prev = null;
            }
            if (link_to_base) {
                node.base = self;
            }

            node.next = self.head;
            self.head = node;
        }

        pub fn pop(self: *Self) ?T {
            const addr = self.head orelse {
                return null;
            };

            if (DBG) std.debug.assert(addr.dbg_magic == DBG_MAGIC);

            self.head = addr.next;

            if (using_popSpecific) {
                if (self.head) |h| {
                    h.prev = null;
                }
            }

            zeroItem(@ptrCast(addr));
            return @ptrCast(@alignCast(addr));
        }

        pub fn popSpecific(self: *Self, addr: T) ?T {
            if (!using_popSpecific) @compileError("must set using_popSpecific flag on the IntrusiveFreelist type to call popSpecific()");

            const node: *FreeNode = @ptrCast(@alignCast(addr));
            if (link_to_base) {
                _ = node.base;
            }

            if (DBG) std.debug.assert(node.dbg_magic == DBG_MAGIC);

            const at_middle = node.prev != null and node.next != null;
            const at_start = node.prev == null and node.next != null;
            const at_end = node.prev != null and node.next == null;
            const only_one = node.prev == null and node.next == null;

            if (at_middle) {
                const prev = node.prev.?;
                const next = node.next.?;
                prev.next = next;
                next.prev = prev;
            } else if (at_start) {
                return self.pop();
            } else if (at_end) {
                const prev = node.prev.?;
                prev.next = null;
            } else if (only_one) {
                std.debug.assert(self.head == node);
                self.head = null;
            }

            zeroItem(@ptrCast(node));
            return @ptrCast(@alignCast(node));
        }

        fn zeroItem(item: [*]u8) void {
            const len = @sizeOf(FreeNode);
            @memset(item[0..len], 0);
        }
    };
}

const TestType = struct {
    pad1: usize,
    pad2: usize,
    pad3: usize,
};

test "mixed push pop operations with prev validation" {
    const using_popSpecific = false;
    const link_to_base = false;
    const FreeList = IntrusiveFreeList(
        *TestType,
        using_popSpecific,
        link_to_base,
    );
    var freelist = FreeList{};
    var values: [5]TestType = .{
        .{ .pad1 = 10, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 20, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 30, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 40, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 50, .pad2 = 0, .pad3 = 0 },
    };

    freelist.push(&values[0]);
    freelist.push(&values[1]);
    freelist.push(&values[2]);

    try std.testing.expect(freelist.pop().? == &values[2]);
    try std.testing.expect(freelist.pop().? == &values[1]);

    freelist.push(&values[3]);
    freelist.push(&values[4]);

    try std.testing.expect(freelist.pop().? == &values[4]);
    try std.testing.expect(freelist.pop().? == &values[3]);
    try std.testing.expect(freelist.pop().? == &values[0]);
    try std.testing.expect(freelist.pop() == null);
}

test "popSpecific() works for start, middle, and end" {
    const using_popSpecific = true;
    const link_to_base = false;
    const FreeList = IntrusiveFreeList(
        *TestType,
        using_popSpecific,
        link_to_base,
    );
    const FreeNode = FreeList.FreeNode;
    var freelist = FreeList{};

    var a = TestType{ .pad1 = 1, .pad2 = 0, .pad3 = 0 };
    var b = TestType{ .pad1 = 2, .pad2 = 0, .pad3 = 0 };
    var c = TestType{ .pad1 = 3, .pad2 = 0, .pad3 = 0 };

    freelist.push(&a);
    freelist.push(&b);
    freelist.push(&c);

    try std.testing.expect(freelist.popSpecific(&b).? == &b);

    const node_c: *FreeNode = @ptrCast(@alignCast(&c));
    const node_a: *FreeNode = @ptrCast(@alignCast(&a));
    try std.testing.expect(node_c.next == node_a);
    try std.testing.expect(node_c.next.?.prev == node_c);

    try std.testing.expect(freelist.popSpecific(&a).? == &a);
    try std.testing.expect(node_c.next == null);

    try std.testing.expect(freelist.popSpecific(&c).? == &c);
}
