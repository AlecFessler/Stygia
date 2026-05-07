// printf_smoke — even simpler than fs_smoke: just printf + exit.
// Tests that the libc.a → runtime.o → COM1 chain works under the new
// `pub fn main` + start.zig zag_start path, without any fs IPC.

extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn exit(status: c_int) callconv(.c) noreturn;

pub fn main() void {
    _ = printf("[printf_smoke] hello via libc.a + runtime.o\n");
    _ = printf("[printf_smoke] number=%d str=%s\n", @as(c_int, 42), @as([*:0]const u8, "world"));
    _ = printf("[printf_smoke] done\n");
    exit(0);
}
