// fs_smoke — exercise the libc → runtime fs IPC chain.
//
// `pub fn main` makes start.zig auto-export `_start = zag_start`, which
// calls our runtime's zag_init() (cap-table walk + COM1 + fs_scratch
// mapping) before main runs.
//
// Test plan:
//   1. printf banner to confirm console works.
//   2. fopen("/fs_smoke.txt", "w"), fwrite(content), fclose.
//   3. fopen("/fs_smoke.txt", "r"), fread, fclose; printf the content.
//   4. unlink("/fs_smoke.txt") and stat to confirm it's gone.
//
// All routes through libc.a → runtime.o → fs_port IPC.

extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn fopen(path: [*:0]const u8, mode: [*:0]const u8) callconv(.c) ?*anyopaque;
extern fn fclose(stream: ?*anyopaque) callconv(.c) c_int;
extern fn fwrite(ptr: [*]const u8, size: usize, n: usize, stream: ?*anyopaque) callconv(.c) usize;
extern fn fread(ptr: [*]u8, size: usize, n: usize, stream: ?*anyopaque) callconv(.c) usize;
extern fn unlink(path: [*:0]const u8) callconv(.c) c_int;
extern fn stat(path: [*:0]const u8, st: *anyopaque) callconv(.c) c_int;
extern fn exit(status: c_int) callconv(.c) noreturn;

const Stat = extern struct { _padding: [144]u8 = @splat(0) };

pub fn main() void {
    _ = printf("[fs_smoke] alive\n");

    // 1. write
    {
        const f = fopen("/fs_smoke.txt", "w") orelse {
            _ = printf("[fs_smoke] fopen(w) failed\n");
            exit(1);
        };
        const content = "hello from fs_smoke via libc + runtime IPC\n";
        const n = fwrite(content.ptr, 1, content.len, f);
        _ = printf("[fs_smoke] fwrite returned %zu (expected %zu)\n", n, content.len);
        _ = fclose(f);
    }

    // 2. read back
    {
        const f = fopen("/fs_smoke.txt", "r") orelse {
            _ = printf("[fs_smoke] fopen(r) failed\n");
            exit(2);
        };
        var buf: [128]u8 = undefined;
        const n = fread(&buf, 1, buf.len - 1, f);
        buf[n] = 0;
        _ = printf("[fs_smoke] fread %zu bytes: %s", n, @as([*:0]const u8, @ptrCast(&buf)));
        _ = fclose(f);
    }

    // 3. unlink
    {
        const rc = unlink("/fs_smoke.txt");
        _ = printf("[fs_smoke] unlink returned %d\n", rc);
    }

    // 4. confirm stat now fails
    {
        var st: Stat = .{};
        const rc = stat("/fs_smoke.txt", &st);
        _ = printf("[fs_smoke] stat after unlink returned %d (expected != 0)\n", rc);
    }

    _ = printf("[fs_smoke] ok\n");
    exit(0);
}
