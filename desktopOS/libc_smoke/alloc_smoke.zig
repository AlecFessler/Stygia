// alloc_smoke — same build profile as the compiler. Do one c_allocator
// allocation and write the result to confirm the path works.

const std = @import("std");

extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn exit(status: c_int) callconv(.c) noreturn;

pub fn main() void {
    _ = printf("[alloc_smoke] alive\n");

    // Try c_allocator (what the compiler picks via link_libc)
    const allocator = std.heap.c_allocator;
    _ = printf("[alloc_smoke] before alloc\n");
    const buf = allocator.alloc(u8, 64) catch {
        _ = printf("[alloc_smoke] alloc failed\n");
        exit(1);
    };
    _ = printf("[alloc_smoke] alloc returned %p\n", buf.ptr);
    @memset(buf, 0xab);
    _ = printf("[alloc_smoke] memset ok\n");
    allocator.free(buf);
    _ = printf("[alloc_smoke] free ok\n");

    // Try array_list path
    // Test what `&[_]u8{}` evaluates to — it's the sentinel for empty slice.
    const empty: []const u8 = &[_]u8{};
    const empty_ptr_int = @intFromPtr(empty.ptr);
    {
        var hex: [20]u8 = undefined;
        const hexchars = "0123456789abcdef";
        const n: u64 = empty_ptr_int;
        var i: usize = 0;
        while (i < 16) : (i += 1) hex[15 - i] = hexchars[(n >> @intCast(i * 4)) & 0xF];
        hex[16] = '\n';
        _ = printf("[alloc_smoke] empty slice ptr=0x");
        _ = std.os.zag.write(2, &hex, 17);
    }
    var list = std.array_list.Managed(u8).init(allocator);
    defer list.deinit();
    {
        var hex: [20]u8 = undefined;
        const hexchars = "0123456789abcdef";
        const n: u64 = @intFromPtr(list.items.ptr);
        var i: usize = 0;
        while (i < 16) : (i += 1) hex[15 - i] = hexchars[(n >> @intCast(i * 4)) & 0xF];
        hex[16] = '\n';
        _ = printf("[alloc_smoke] list items.ptr=0x");
        _ = std.os.zag.write(2, &hex, 17);
    }
    _ = printf("[alloc_smoke] before ensureUnusedCapacity capacity=%zu\n", list.capacity);
    list.ensureUnusedCapacity(5) catch {
        _ = printf("[alloc_smoke] ensureUnusedCapacity failed\n");
        exit(20);
    };
    _ = printf("[alloc_smoke] after ensureUnusedCapacity capacity=%zu\n", list.capacity);
    _ = printf("[alloc_smoke] before appendSliceAssumeCapacity\n");
    {
        var hex: [20]u8 = undefined;
        const hexchars = "0123456789abcdef";
        const n: u64 = @intFromPtr(list.items.ptr);
        var i: usize = 0;
        while (i < 16) : (i += 1) hex[15 - i] = hexchars[(n >> @intCast(i * 4)) & 0xF];
        hex[16] = '\n';
        _ = printf("[alloc_smoke] post-resize items.ptr=0x");
        _ = std.os.zag.write(2, &hex, 17);
    }
    list.appendSliceAssumeCapacity("hello");
    _ = printf("[alloc_smoke] after appendSliceAssumeCapacity len=%zu\n", list.items.len);

    _ = printf("[alloc_smoke] done\n");
    exit(0);
}
