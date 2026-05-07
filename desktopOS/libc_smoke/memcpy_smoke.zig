// memcpy_smoke — isolate Zig @memcpy on Zag for the no-LLVM backend.
const std = @import("std");

extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn exit(status: c_int) callconv(.c) noreturn;
extern fn malloc(n: usize) callconv(.c) ?[*]u8;

pub fn main() void {
    _ = printf("[memcpy] alive\n");

    const buf_opt = malloc(16);
    if (buf_opt == null) {
        _ = printf("[memcpy] malloc failed\n");
        exit(1);
    }
    const buf = buf_opt.?;
    _ = printf("[memcpy] malloc ok\n");

    const src = "abcde";
    _ = printf("[memcpy] before @memcpy\n");
    @memcpy(buf[0..5], src);
    _ = printf("[memcpy] after @memcpy\n");

    buf[5] = 0;
    _ = printf("[memcpy] result=%s\n", @as([*:0]const u8, @ptrCast(buf)));
    exit(0);
}
