//! Git plumbing helpers shared across the callgraph daemons. These run
//! `git -C <git_root> ...` shellouts; they do NOT touch any DB. The new
//! callgraph pipeline produces `.db` files offline, so commit-loading is a
//! presence check rather than a build orchestration step.
//!
//! Duplicated under both `tools/callgraph_http/src/` and
//! `tools/callgraph_mcp/src/` because the daemons are separate executables
//! and we want each to compile without reaching out of its own directory.

const std = @import("std");

const GIT_FIELD_SEP = "\x1f";

/// Inclusive cap on `?limit=` for /api/commits.
pub const MAX_LIMIT: u32 = 500;
/// Default `?limit=` for /api/commits when none is specified.
pub const DEFAULT_LIMIT: u32 = 30;

/// Run `git log -<limit>` with a `\x1f`-separated record per commit and
/// return stdout (caller owns the slice). The record format is the same
/// one the old callgraph daemon used:
///   `%H \x1f %h \x1f %an \x1f %aI \x1f %s`
/// On any nonzero exit / spawn failure, returns an error and prints the
/// stderr to the daemon log.
pub fn gitLog(
    allocator: std.mem.Allocator,
    git_root: []const u8,
    limit: u32,
) ![]u8 {
    const limit_arg = try std.fmt.allocPrint(allocator, "-{d}", .{limit});
    defer allocator.free(limit_arg);

    const fmt_arg = "--pretty=format:%H" ++ GIT_FIELD_SEP ++ "%h" ++ GIT_FIELD_SEP ++ "%an" ++ GIT_FIELD_SEP ++ "%aI" ++ GIT_FIELD_SEP ++ "%s";
    const argv = [_][]const u8{ "git", "log", limit_arg, fmt_arg };

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 4 * 1024 * 1024,
    });
    errdefer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.debug.print("git log exit {d}: {s}\n", .{ code, result.stderr });
            allocator.free(result.stdout);
            return error.GitLogFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.GitLogFailed;
        },
    }
    return result.stdout;
}

/// Build a set of full SHAs whose tree contains the `-Demit_ir` build
/// option. Strategy: find the oldest commit that touched "emit_ir" in
/// build.zig, then `git rev-list <introducing>~..HEAD` enumerates the
/// introducing commit + all descendants reachable from HEAD.
///
/// On any error returns an empty set; callers then mark every commit
/// stale (which is wrong but safe — the stale marker just decorates the
/// output, no behavior depends on it).
///
/// Caller owns the keys (allocated via `allocator`); use `freeShaSet` to
/// release them.
pub fn buildEmitIrSet(
    allocator: std.mem.Allocator,
    git_root: []const u8,
) std.StringHashMap(void) {
    var set = std.StringHashMap(void).init(allocator);

    const find_argv = [_][]const u8{
        "git",          "log",         "-G",
        "emit_ir",      "--format=%H", "--",
        "build.zig",
    };
    const find_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &find_argv,
        .cwd = git_root,
        .max_output_bytes = 1024 * 1024,
    }) catch return set;
    defer allocator.free(find_result.stdout);
    defer allocator.free(find_result.stderr);

    var oldest: []const u8 = "";
    var line_it = std.mem.splitScalar(u8, find_result.stdout, '\n');
    while (line_it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) oldest = trimmed;
    }
    if (oldest.len == 0) return set;

    const range = std.fmt.allocPrint(allocator, "{s}~..HEAD", .{oldest}) catch return set;
    defer allocator.free(range);
    const list_argv = [_][]const u8{ "git", "rev-list", range };
    const list_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &list_argv,
        .cwd = git_root,
        .max_output_bytes = 16 * 1024 * 1024,
    }) catch return set;
    defer allocator.free(list_result.stdout);
    defer allocator.free(list_result.stderr);

    var sha_it = std.mem.splitScalar(u8, list_result.stdout, '\n');
    while (sha_it.next()) |raw| {
        const sha = std.mem.trim(u8, raw, " \t\r");
        if (sha.len == 0) continue;
        const owned = allocator.dupe(u8, sha) catch continue;
        set.put(owned, {}) catch {
            allocator.free(owned);
            continue;
        };
    }
    return set;
}

pub fn freeShaSet(allocator: std.mem.Allocator, set: *std.StringHashMap(void)) void {
    var it = set.keyIterator();
    while (it.next()) |k| allocator.free(k.*);
    set.deinit();
}

/// Render git-log output into the legacy text format:
///   `<short>  <iso_date>  <subject>[  [stale]]\n`
/// with the `[stale]` marker appended for commits not in `compat_set`.
/// Output is appended to `out`.
pub fn renderCommitsText(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    git_log_stdout: []const u8,
    compat_set: *const std.StringHashMap(void),
) !void {
    var line_it = std.mem.splitScalar(u8, git_log_stdout, '\n');
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        var fields_it = std.mem.splitSequence(u8, line, GIT_FIELD_SEP);
        const sha = fields_it.next() orelse continue;
        const short = fields_it.next() orelse continue;
        _ = fields_it.next() orelse continue; // author
        const date = fields_it.next() orelse continue;
        const subject = fields_it.next() orelse continue;
        try out.writer(allocator).print("{s}  {s}  {s}", .{ short, date, subject });
        if (!compat_set.contains(sha)) try out.appendSlice(allocator, "  [stale]");
        try out.append(allocator, '\n');
    }
}

/// Render git-log output as the same JSON shape the old daemon emitted
/// for the web UI: `{"commits":[{sha,short,author,date,subject,
/// cg_compatible,reviewed_by:[]},...]}`. `reviewed_by` is always empty
/// in the new daemon — the review-tracker endpoints aren't ported.
pub fn renderCommitsJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    git_log_stdout: []const u8,
    compat_set: *const std.StringHashMap(void),
) !void {
    try out.appendSlice(allocator, "{\"commits\":[");
    var first = true;
    var line_it = std.mem.splitScalar(u8, git_log_stdout, '\n');
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        var fields_it = std.mem.splitSequence(u8, line, GIT_FIELD_SEP);
        const sha = fields_it.next() orelse continue;
        const short = fields_it.next() orelse continue;
        const author = fields_it.next() orelse continue;
        const date = fields_it.next() orelse continue;
        const subject = fields_it.next() orelse continue;

        if (!first) try out.append(allocator, ',');
        first = false;
        try out.append(allocator, '{');
        try out.appendSlice(allocator, "\"sha\":");
        try writeJsonString(allocator, out, sha);
        try out.appendSlice(allocator, ",\"short\":");
        try writeJsonString(allocator, out, short);
        try out.appendSlice(allocator, ",\"author\":");
        try writeJsonString(allocator, out, author);
        try out.appendSlice(allocator, ",\"date\":");
        try writeJsonString(allocator, out, date);
        try out.appendSlice(allocator, ",\"subject\":");
        try writeJsonString(allocator, out, subject);
        try out.appendSlice(allocator, ",\"cg_compatible\":");
        try out.appendSlice(allocator, if (compat_set.contains(sha)) "true" else "false");
        try out.appendSlice(allocator, ",\"reviewed_by\":[]}");
    }
    try out.appendSlice(allocator, "]}");
}

fn writeJsonString(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    s: []const u8,
) !void {
    try out.append(allocator, '"');
    for (s) |b| {
        switch (b) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x0c => try out.appendSlice(allocator, "\\f"),
            0...0x07, 0x0b, 0x0e...0x1f => {
                var buf: [8]u8 = undefined;
                const w = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{b});
                try out.appendSlice(allocator, w);
            },
            else => try out.append(allocator, b),
        }
    }
    try out.append(allocator, '"');
}

/// True iff `s` looks like a hex SHA (4..64 hex chars). Used to gate
/// query parameters before shelling out to git.
pub fn isValidSha(s: []const u8) bool {
    if (s.len < 4 or s.len > 64) return false;
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

/// `git show --stat --no-color <sha>` — the summary view used for
/// /api/diff. Returns stdout (caller-owned). Errors propagate so the
/// handler can map them to a 500.
pub fn gitShowStat(
    allocator: std.mem.Allocator,
    git_root: []const u8,
    sha: []const u8,
) ![]u8 {
    const argv = [_][]const u8{ "git", "show", "--stat", "--no-color", sha };
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 8 * 1024 * 1024,
    });
    errdefer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.debug.print("git show exit {d}: {s}\n", .{ code, result.stderr });
            allocator.free(result.stdout);
            return error.GitShowFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.GitShowFailed;
        },
    }
    return result.stdout;
}

/// `git show --name-only --pretty=format: <sha>` — list of files changed
/// in <sha>. Returns stdout (caller-owned). Each line is a path; blank
/// lines (notably the leading newline from the empty pretty format) are
/// the caller's problem to skip.
pub fn gitShowNames(
    allocator: std.mem.Allocator,
    git_root: []const u8,
    sha: []const u8,
) ![]u8 {
    const argv = [_][]const u8{ "git", "show", "--name-only", "--pretty=format:", sha };
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 4 * 1024 * 1024,
    });
    errdefer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.debug.print("git show --name-only exit {d}: {s}\n", .{ code, result.stderr });
            allocator.free(result.stdout);
            return error.GitShowFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.GitShowFailed;
        },
    }
    return result.stdout;
}

/// `git show <sha> -- <path>` — unified-diff hunks for one file in one
/// commit. Returns stdout (caller-owned). Includes the `diff --git`
/// header and all hunks; the caller can strip headers if needed.
pub fn gitShowFileDiff(
    allocator: std.mem.Allocator,
    git_root: []const u8,
    sha: []const u8,
    path: []const u8,
) ![]u8 {
    const argv = [_][]const u8{ "git", "show", "--no-color", sha, "--", path };
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 16 * 1024 * 1024,
    });
    errdefer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.debug.print("git show <sha> -- <path> exit {d}: {s}\n", .{ code, result.stderr });
            allocator.free(result.stdout);
            return error.GitShowFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.GitShowFailed;
        },
    }
    return result.stdout;
}
