// mt_smoke — same build profile as the cross-compiled zig compiler
// (multi-threaded, PIE, ReleaseSmall, links libc.a + runtime.o), but
// just calls printf and exits. Diagnostic for the WAKE-loop hang.

extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn exit(status: c_int) callconv(.c) noreturn;

pub fn main() void {
    _ = printf("[mt_smoke] alive\n");
    _ = printf("[mt_smoke] done\n");
    exit(0);
}
