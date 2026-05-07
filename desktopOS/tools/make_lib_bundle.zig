// Build-time tool: pack lib/std + lib/compiler_rt + extras into a flat
// bundle blob the Zag-userspace provisioner walks at boot. The provisioner
// writes each entry to the SQL FS via fs IPC.
//
// Bundle wire format (little-endian throughout):
//
//   per entry:
//     u8  kind          0=file, 1=dir, 0xFF=end-of-bundle
//     u8  reserved      always 0
//     u16 path_len      bytes (no null terminator)
//     u32 content_len   bytes (0 for dirs)
//     [path_len]u8 path (e.g. "/ziglib/std/array_list.zig")
//     [content_len]u8 content (omitted for dirs)
//
// Args (positional):
//   1: ziglib_root (e.g. ~/.local/zag-toolchains/zig-0.15.2-src/lib)
//   2: output bundle path
//   3: hello_zig_path (raw text content)
//   4: runtime_o_path
//   5: libc_a_path
//
// The script emits dirs depth-first parents-before-children so the
// provisioner can mkdir each one in order without recursion logic.

const std = @import("std");

const KIND_FILE: u8 = 0;
const KIND_DIR: u8 = 1;
const KIND_END: u8 = 0xFF;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const argv = try std.process.argsAlloc(a);
    if (argv.len != 6) {
        std.debug.print("usage: make_lib_bundle <ziglib_root> <out_bundle> <hello.zig> <runtime.o> <libc.a>\n", .{});
        std.process.exit(1);
    }
    const ziglib_root = argv[1];
    const out_path = argv[2];
    const hello_path = argv[3];
    const runtime_o_path = argv[4];
    const libc_a_path = argv[5];

    // Build into a memory buffer, then one-shot write to disk.
    var bundle = std.array_list.Managed(u8).init(a);
    defer bundle.deinit();
    const w = bundle.writer();

    // Top-level synthetic dirs we always emit.
    try emitDir(w, "/ziglib");
    try emitDir(w, "/ziglib/std");
    try emitDir(w, "/ziglib/compiler_rt");

    try walkAndEmit(a, w, ziglib_root, "std", "/ziglib/std");
    try walkAndEmit(a, w, ziglib_root, "compiler_rt", "/ziglib/compiler_rt");
    // Top-level lib/*.zig entry points (compiler_rt.zig, c.zig, etc.)
    // for sub-compilations that look beside the lib dir for their root.
    for ([_][]const u8{ "compiler_rt.zig", "c.zig", "fuzzer.zig", "ubsan_rt.zig" }) |basename| {
        const path = try std.fs.path.join(a, &.{ ziglib_root, basename });
        defer a.free(path);
        const dest = try std.fmt.allocPrint(a, "/ziglib/{s}", .{basename});
        defer a.free(dest);
        try emitFileFromPath(a, w, dest, path);
    }

    // Extras: hello.zig + linkable libc/runtime artifacts at root.
    try emitFileFromPath(a, w, "/hello.zig", hello_path);
    try emitFileFromPath(a, w, "/runtime.o", runtime_o_path);
    try emitFileFromPath(a, w, "/libc.a", libc_a_path);

    // Cache + global cache dirs the compiler will need.
    try emitDir(w, "/zigcache");
    try emitDir(w, "/zigglobal");

    // Sentinel.
    try w.writeByte(KIND_END);

    const out_file = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    defer out_file.close();
    try out_file.writeAll(bundle.items);
}

fn emitDir(w: anytype, path: []const u8) !void {
    try w.writeByte(KIND_DIR);
    try w.writeByte(0);
    try w.writeInt(u16, @intCast(path.len), .little);
    try w.writeInt(u32, 0, .little);
    try w.writeAll(path);
}

fn emitFile(w: anytype, path: []const u8, content: []const u8) !void {
    try w.writeByte(KIND_FILE);
    try w.writeByte(0);
    try w.writeInt(u16, @intCast(path.len), .little);
    try w.writeInt(u32, @intCast(content.len), .little);
    try w.writeAll(path);
    try w.writeAll(content);
}

fn emitFileFromPath(a: std.mem.Allocator, w: anytype, dest: []const u8, src_path: []const u8) !void {
    const file = try std.fs.cwd().openFile(src_path, .{});
    defer file.close();
    const stat = try file.stat();
    const buf = try a.alloc(u8, stat.size);
    defer a.free(buf);
    const n = try file.readAll(buf);
    try emitFile(w, dest, buf[0..n]);
}

// Recursively walk lib_root/sub_dir; two-pass — emit ALL dirs first
// (sorted shortest-path-first so parents precede children), then ALL
// files. Guarantees the provisioner sees mkdir before any
// create_file beneath it.
fn walkAndEmit(
    a: std.mem.Allocator,
    w: anytype,
    lib_root: []const u8,
    sub_dir: []const u8,
    dest_prefix: []const u8,
) !void {
    const root_path = try std.fs.path.join(a, &.{ lib_root, sub_dir });
    defer a.free(root_path);

    var dir = try std.fs.cwd().openDir(root_path, .{ .iterate = true });
    defer dir.close();

    var dirs = std.array_list.Managed([]const u8).init(a);
    defer dirs.deinit();
    const FileEntry = struct { dest: []const u8, src: []const u8 };
    var files = std.array_list.Managed(FileEntry).init(a);
    defer files.deinit();

    var walker = try dir.walk(a);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        const dest = try std.fs.path.join(a, &.{ dest_prefix, entry.path });
        for (dest) |*c| if (c.* == '\\') {
            c.* = '/';
        };
        switch (entry.kind) {
            .directory => try dirs.append(dest),
            .file => {
                const src = try std.fs.path.join(a, &.{ root_path, entry.path });
                try files.append(.{ .dest = dest, .src = src });
            },
            else => {}, // skip symlinks etc.
        }
    }

    std.mem.sort([]const u8, dirs.items, {}, lessThanByLen);
    for (dirs.items) |d| try emitDir(w, d);
    for (files.items) |f| {
        const file = try std.fs.cwd().openFile(f.src, .{});
        defer file.close();
        const stat = try file.stat();
        const buf = try a.alloc(u8, stat.size);
        defer a.free(buf);
        const n = try file.readAll(buf);
        try emitFile(w, f.dest, buf[0..n]);
    }
}

fn lessThanByLen(_: void, a: []const u8, b: []const u8) bool {
    return a.len < b.len;
}
