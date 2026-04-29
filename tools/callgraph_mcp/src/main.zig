//! Callgraph MCP daemon entry point.
//!
//! CLI:
//!   --db <path>        open a single callgraph DB file
//!   --db-dir <dir>     pick the newest *.db in <dir> (by mtime)
//!   --git-root <dir>   repo root for git-plumbing tools
//!                      (`callgraph_commits`); defaults to CWD
//!
//! At least one of --db / --db-dir is required. The daemon refuses to open
//! a DB that doesn't have `meta('schema_complete','true')` — the indexer
//! writes that row last so partially-built artifacts can't be queried.

const std = @import("std");

const mcp = @import("mcp.zig");
const tools = @import("tools.zig");

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var args_it = try std.process.argsWithAllocator(gpa);
    defer args_it.deinit();
    _ = args_it.next();

    var registry = tools.Registry.init(gpa);
    defer registry.deinit();

    var db_paths = std.ArrayList([]const u8){};
    defer {
        for (db_paths.items) |p| gpa.free(p);
        db_paths.deinit(gpa);
    }
    var db_dir: ?[]const u8 = null;
    defer if (db_dir) |d| gpa.free(d);
    var git_root: []const u8 = ".";
    var git_root_owned: ?[]const u8 = null;
    defer if (git_root_owned) |g| gpa.free(g);

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--db")) {
            const v = args_it.next() orelse return error.MissingArg;
            try db_paths.append(gpa, try gpa.dupe(u8, v));
        } else if (std.mem.eql(u8, arg, "--db-dir")) {
            const v = args_it.next() orelse return error.MissingArg;
            db_dir = try gpa.dupe(u8, v);
        } else if (std.mem.eql(u8, arg, "--git-root")) {
            const v = args_it.next() orelse return error.MissingArg;
            const dup = try gpa.dupe(u8, v);
            git_root_owned = dup;
            git_root = dup;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("callgraph_mcp --db <path> | --db-dir <dir> [--git-root <dir>]\n", .{});
            return;
        } else {
            std.debug.print("unknown arg: {s}\n", .{arg});
            return error.BadArgs;
        }
    }
    registry.git_root = git_root;

    if (db_dir) |dir| {
        const newest = try newestDbInDir(gpa, dir);
        if (newest) |p| {
            try db_paths.append(gpa, p);
        } else {
            std.debug.print("no *.db files in {s}\n", .{dir});
        }
    }

    for (db_paths.items) |p| {
        registry.addDb(p) catch |err| {
            std.debug.print("failed to open {s}: {s}\n", .{ p, @errorName(err) });
            // Continue: a broken DB shouldn't kill the whole daemon if
            // others succeeded.
            continue;
        };
    }

    try mcp.run(gpa, &registry);
}

fn newestDbInDir(gpa: std.mem.Allocator, dir_path: []const u8) !?[]const u8 {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    var best: ?[]u8 = null;
    var best_mtime: i128 = std.math.minInt(i128);
    errdefer if (best) |b| gpa.free(b);
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".db")) continue;
        const stat = try dir.statFile(entry.name);
        if (stat.mtime > best_mtime) {
            if (best) |b| gpa.free(b);
            best_mtime = stat.mtime;
            best = try std.fs.path.join(gpa, &.{ dir_path, entry.name });
        }
    }
    return best;
}
