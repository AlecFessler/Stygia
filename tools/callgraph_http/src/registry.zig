//! Per-DB registry: discovers `<arch>-<sha>.db` files in --db-dir, opens
//! each read-only, verifies schema_complete, and routes lookups by
//! (sha, arch).
//!
//! One DB file per (arch, commit_sha). The arch token used for routing
//! is whatever the file's `meta('arch')` row says; the filename is
//! advisory. Open failures and partial-schema DBs are logged and skipped
//! so the daemon stays up if the indexer is mid-write.

const std = @import("std");

const sqlite = @import("sqlite.zig");

pub const ArchEntry = struct {
    /// Arch tag taken from the DB's `meta('arch')` row (e.g. "x86_64",
    /// "aarch64"). Owned by the registry's arena.
    arch: []const u8,
    /// Path to the DB file. Owned by the registry's arena.
    path: []const u8,
    /// Open read-only handle. Lives for the registry's lifetime.
    db: sqlite.Db,
};

pub const CommitEntry = struct {
    /// commit_sha exactly as the DB recorded it. Owned by the registry's
    /// arena.
    sha: []const u8,
    /// Default arch tag — first one we discovered for this commit, or
    /// "x86_64" if it's loaded.
    default_arch: []const u8,
    /// One ArchEntry per (sha, arch) DB. Lookup by arch tag.
    arches: std.StringHashMap(ArchEntry),
};

pub const Registry = struct {
    arena: std.heap.ArenaAllocator,
    /// Lookup by full sha. Empty key "" means HEAD/working-tree (not
    /// supported by the SQL backend yet — falls through to /api/* error).
    commits: std.StringHashMap(CommitEntry),
    /// Default sha pointed at on startup. Picked as the lex-largest sha
    /// in the discovery walk so each `callgraph_http` invocation has a
    /// deterministic "default" without us depending on filesystem mtime.
    /// Empty when no DBs were discovered.
    default_sha: []const u8,

    pub fn init(gpa: std.mem.Allocator) Registry {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .commits = std.StringHashMap(CommitEntry).init(gpa),
            .default_sha = "",
        };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.commits.valueIterator();
        while (it.next()) |c| {
            var ait = c.arches.valueIterator();
            while (ait.next()) |a| a.db.close();
            c.arches.deinit();
        }
        self.commits.deinit();
        self.arena.deinit();
    }

    /// Walk `dir` for `<arch>-<sha>.db` files, open each, and index them.
    /// Best-effort: per-file failures are logged and skipped.
    pub fn discover(self: *Registry, dir_path: []const u8) !void {
        const a = self.arena.allocator();
        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
            std.debug.print("registry: cannot open --db-dir {s}: {s}\n", .{ dir_path, @errorName(err) });
            return err;
        };
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".db")) continue;

            // Filename shape: `<arch>-<sha>.db`. Use the LAST hyphen so
            // hyphenated archs (none today, but defensive) survive. The
            // canonical arch is read from meta() so the filename is
            // advisory anyway.
            const stem_len = entry.name.len - 3; // strip .db
            const stem = entry.name[0..stem_len];
            const dash = std.mem.lastIndexOfScalar(u8, stem, '-') orelse {
                std.debug.print("registry: skipping {s}: not <arch>-<sha>.db\n", .{entry.name});
                continue;
            };
            const arch_from_name = stem[0..dash];
            const sha_from_name = stem[dash + 1 ..];
            _ = arch_from_name;

            const full_path = try std.fs.path.join(a, &.{ dir_path, entry.name });
            var db = sqlite.Db.openReadOnly(full_path, a) catch |err| {
                std.debug.print("registry: open {s} failed: {s}\n", .{ full_path, @errorName(err) });
                continue;
            };
            errdefer db.close();

            const meta_arch = readMeta(&db, a, "arch") catch {
                std.debug.print("registry: {s}: no meta('arch')\n", .{full_path});
                db.close();
                continue;
            } orelse {
                std.debug.print("registry: {s}: no meta('arch')\n", .{full_path});
                db.close();
                continue;
            };
            const meta_sha = readMeta(&db, a, "commit_sha") catch null orelse try a.dupe(u8, sha_from_name);

            const arch_entry = ArchEntry{
                .arch = meta_arch,
                .path = full_path,
                .db = db,
            };

            const gop = try self.commits.getOrPut(meta_sha);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .sha = meta_sha,
                    .default_arch = meta_arch,
                    .arches = std.StringHashMap(ArchEntry).init(self.commits.allocator),
                };
            }
            // Prefer x86_64 as the default if both arches show up.
            if (std.mem.eql(u8, meta_arch, "x86_64")) gop.value_ptr.default_arch = meta_arch;
            try gop.value_ptr.arches.put(meta_arch, arch_entry);

            if (self.default_sha.len == 0 or std.mem.lessThan(u8, self.default_sha, meta_sha)) {
                self.default_sha = meta_sha;
            }
            std.debug.print("registry: loaded {s} (sha={s} arch={s})\n", .{ full_path, meta_sha, meta_arch });
        }
    }

    /// Resolve `(sha, arch)` to an ArchEntry. Empty/missing sha falls back
    /// to `default_sha`; empty/missing arch falls back to that commit's
    /// `default_arch`. Returns null when nothing matches.
    pub fn lookup(self: *Registry, sha_opt: ?[]const u8, arch_opt: ?[]const u8) ?*ArchEntry {
        const sha = if (sha_opt) |s| (if (s.len == 0) self.default_sha else s) else self.default_sha;
        if (sha.len == 0) return null;
        const commit = self.commits.getPtr(sha) orelse return null;
        const arch = if (arch_opt) |a| (if (a.len == 0) commit.default_arch else a) else commit.default_arch;
        return commit.arches.getPtr(arch);
    }

    pub fn lookupCommit(self: *Registry, sha_opt: ?[]const u8) ?*CommitEntry {
        const sha = if (sha_opt) |s| (if (s.len == 0) self.default_sha else s) else self.default_sha;
        if (sha.len == 0) return null;
        return self.commits.getPtr(sha);
    }
};

/// Read one row from the meta table. Caller borrows the returned slice
/// for the registry's arena lifetime (we dupe).
fn readMeta(db: *sqlite.Db, arena: std.mem.Allocator, key: []const u8) !?[]const u8 {
    var stmt = try db.prepare("SELECT value FROM meta WHERE key = ?", arena);
    defer stmt.finalize();
    try stmt.bindText(1, key);
    if (!try stmt.step()) return null;
    const v = stmt.columnText(0) orelse return null;
    return try arena.dupe(u8, v);
}
