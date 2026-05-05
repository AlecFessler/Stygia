// Stateless filesystem implementation on top of SQLite.
//
// Schema:
//
//   inodes(inode PK, kind, mode, size, mtime, ctime, atime,
//          link_count, data BLOB)
//   dentries(parent, name, inode)  PK(parent, name)
//
// Inode 1 is the root directory and is seeded by migrate(). Path
// resolution walks dentries from inode 1 with one SELECT per
// component. Slow but simple — the cache layer SQLite provides
// keeps the dentries table hot in RAM after the first walk.
//
// Pread/pwrite materialize the whole blob this revision; phase 3
// switches them to sqlite3_blob_open + incremental I/O so partial
// reads don't quadratic-scale with file size.

const lib = @import("lib");
const log = @import("log");
const sqlite = @import("sqlite");

const c = sqlite.c;
const syscall = lib.syscall;

pub const Error = error{
    NotFound,
    NotADirectory,
    IsADirectory,
    NameTooLong,
    PathTooLong,
    NoSpace,
    Exists,
    NotEmpty,
    Invalid,
    BadPath,
    SqliteError,
    Truncated,
};

pub const NAME_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;

pub const Kind = enum(u8) {
    file = 0,
    dir = 1,
    symlink = 2,
};

pub const ROOT_INODE: i64 = 1;

const SCHEMA =
    "CREATE TABLE IF NOT EXISTS inodes(" ++
    "  inode INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "  kind INTEGER NOT NULL," ++
    "  mode INTEGER NOT NULL," ++
    "  size INTEGER NOT NULL," ++
    "  mtime INTEGER NOT NULL," ++
    "  ctime INTEGER NOT NULL," ++
    "  atime INTEGER NOT NULL," ++
    "  link_count INTEGER NOT NULL DEFAULT 1," ++
    "  data BLOB" ++
    ");" ++
    "CREATE TABLE IF NOT EXISTS dentries(" ++
    "  parent INTEGER NOT NULL," ++
    "  name TEXT NOT NULL," ++
    "  inode INTEGER NOT NULL," ++
    "  PRIMARY KEY(parent, name)" ++
    ");" ++
    "CREATE INDEX IF NOT EXISTS dentry_inode ON dentries(inode);";

/// Run schema CREATE statements and seed inode 1 (root /) if missing.
pub fn migrate(db: *c.sqlite3) !void {
    if (sqlite.exec(db, SCHEMA) != c.SQLITE_OK) return Error.SqliteError;

    // Seed root if absent.
    var sel = sqlite.prepare(db, "SELECT inode FROM inodes WHERE inode = 1;") catch
        return Error.SqliteError;
    defer sel.finalize();
    if (sel.step()) return; // already seeded

    var ins = sqlite.prepare(
        db,
        "INSERT INTO inodes(inode, kind, mode, size, mtime, ctime, atime, link_count, data)" ++
            " VALUES (1, 1, 493, 0, ?, ?, ?, 2, NULL);", // mode 0o755
    ) catch return Error.SqliteError;
    defer ins.finalize();
    const now = nowSeconds();
    sqlite.bindInt64(&ins, 1, now) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 2, now) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 3, now) catch return Error.SqliteError;
    _ = ins.step();
}

pub const StatInfo = struct {
    inode: i64,
    kind: Kind,
    mode: i64,
    size: i64,
    mtime: i64,
    ctime: i64,
    atime: i64,
    link_count: i64,
};

pub fn stat(db: *c.sqlite3, path: []const u8) !StatInfo {
    const inode = try resolve(db, path);
    return statByInode(db, inode);
}

pub fn statByInode(db: *c.sqlite3, inode: i64) !StatInfo {
    var s = sqlite.prepare(
        db,
        "SELECT kind, mode, size, mtime, ctime, atime, link_count" ++
            " FROM inodes WHERE inode = ?;",
    ) catch return Error.SqliteError;
    defer s.finalize();
    sqlite.bindInt64(&s, 1, inode) catch return Error.SqliteError;
    if (!s.step()) return Error.NotFound;
    return .{
        .inode = inode,
        .kind = @enumFromInt(@as(u8, @intCast(s.columnInt64(0)))),
        .mode = s.columnInt64(1),
        .size = s.columnInt64(2),
        .mtime = s.columnInt64(3),
        .ctime = s.columnInt64(4),
        .atime = s.columnInt64(5),
        .link_count = s.columnInt64(6),
    };
}

pub fn pread(db: *c.sqlite3, path: []const u8, offset: u64, dst: []u8) !usize {
    const inode = try resolve(db, path);
    const info = try statByInode(db, inode);
    if (info.kind == .dir) return Error.IsADirectory;
    if (offset >= @as(u64, @intCast(info.size))) return 0;

    var s = sqlite.prepare(db, "SELECT data FROM inodes WHERE inode = ?;") catch
        return Error.SqliteError;
    defer s.finalize();
    sqlite.bindInt64(&s, 1, inode) catch return Error.SqliteError;
    if (!s.step()) return Error.NotFound;

    const blob = s.columnBlob(0);
    if (offset >= blob.len) return 0;
    const avail = blob.len - @as(usize, @intCast(offset));
    const n = @min(dst.len, avail);
    @memcpy(dst[0..n], blob[@intCast(offset) .. @as(usize, @intCast(offset)) + n]);
    return n;
}

pub const PwriteResult = struct {
    written: usize,
    new_size: u64,
};

pub fn pwrite(
    db: *c.sqlite3,
    path: []const u8,
    offset: u64,
    src: []const u8,
    scratch: []u8,
) !PwriteResult {
    const inode = try resolve(db, path);
    const info = try statByInode(db, inode);
    if (info.kind == .dir) return Error.IsADirectory;

    const new_end: u64 = offset + src.len;
    const new_size: u64 = @max(@as(u64, @intCast(info.size)), new_end);
    if (new_size > scratch.len) return Error.NoSpace;

    // Read-modify-write the whole blob through scratch. Phase 3 swaps
    // this for sqlite3_blob_open / sqlite3_blob_write.
    var rd = sqlite.prepare(db, "SELECT data FROM inodes WHERE inode = ?;") catch
        return Error.SqliteError;
    sqlite.bindInt64(&rd, 1, inode) catch {
        rd.finalize();
        return Error.SqliteError;
    };
    var have: usize = 0;
    if (rd.step()) {
        const blob = rd.columnBlob(0);
        @memcpy(scratch[0..blob.len], blob);
        have = blob.len;
    }
    rd.finalize();

    // Zero-fill any gap between EOF and offset.
    if (offset > have) {
        @memset(scratch[have..@intCast(offset)], 0);
    }
    @memcpy(scratch[@intCast(offset) .. @as(usize, @intCast(offset)) + src.len], src);

    var up = sqlite.prepare(
        db,
        "UPDATE inodes SET data = ?, size = ?, mtime = ? WHERE inode = ?;",
    ) catch return Error.SqliteError;
    defer up.finalize();
    sqlite.bindBlob(&up, 1, scratch[0..@intCast(new_size)]) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 2, @intCast(new_size)) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 3, nowSeconds()) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 4, inode) catch return Error.SqliteError;
    _ = up.step();

    return .{ .written = src.len, .new_size = new_size };
}

pub fn truncate(db: *c.sqlite3, path: []const u8, new_size: u64, scratch: []u8) !void {
    const inode = try resolve(db, path);
    const info = try statByInode(db, inode);
    if (info.kind == .dir) return Error.IsADirectory;
    if (new_size > scratch.len) return Error.NoSpace;

    if (@as(i64, @intCast(new_size)) == info.size) return;

    if (new_size > @as(u64, @intCast(info.size))) {
        // Grow with zeros: pull old blob, pad, write back.
        var rd = sqlite.prepare(db, "SELECT data FROM inodes WHERE inode = ?;") catch
            return Error.SqliteError;
        sqlite.bindInt64(&rd, 1, inode) catch {
            rd.finalize();
            return Error.SqliteError;
        };
        var have: usize = 0;
        if (rd.step()) {
            const blob = rd.columnBlob(0);
            @memcpy(scratch[0..blob.len], blob);
            have = blob.len;
        }
        rd.finalize();
        @memset(scratch[have..@intCast(new_size)], 0);
    } else {
        // Shrink: pull blob and crop. (For new_size==0 the SELECT can be skipped.)
        if (new_size > 0) {
            var rd = sqlite.prepare(db, "SELECT data FROM inodes WHERE inode = ?;") catch
                return Error.SqliteError;
            sqlite.bindInt64(&rd, 1, inode) catch {
                rd.finalize();
                return Error.SqliteError;
            };
            if (rd.step()) {
                const blob = rd.columnBlob(0);
                @memcpy(scratch[0..@intCast(new_size)], blob[0..@intCast(new_size)]);
            }
            rd.finalize();
        }
    }

    var up = sqlite.prepare(
        db,
        "UPDATE inodes SET data = ?, size = ?, mtime = ? WHERE inode = ?;",
    ) catch return Error.SqliteError;
    defer up.finalize();
    sqlite.bindBlob(&up, 1, scratch[0..@intCast(new_size)]) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 2, @intCast(new_size)) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 3, nowSeconds()) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 4, inode) catch return Error.SqliteError;
    _ = up.step();
}

pub fn createFile(db: *c.sqlite3, path: []const u8, mode: i64) !i64 {
    return createInode(db, path, .file, mode, null);
}

pub fn mkdir(db: *c.sqlite3, path: []const u8, mode: i64) !i64 {
    return createInode(db, path, .dir, mode, null);
}

pub fn symlink(db: *c.sqlite3, path: []const u8, target: []const u8) !i64 {
    return createInode(db, path, .symlink, 0o777, target);
}

pub fn readlink(db: *c.sqlite3, path: []const u8, dst: []u8) !usize {
    const inode = try resolve(db, path);
    const info = try statByInode(db, inode);
    if (info.kind != .symlink) return Error.Invalid;

    var s = sqlite.prepare(db, "SELECT data FROM inodes WHERE inode = ?;") catch
        return Error.SqliteError;
    defer s.finalize();
    sqlite.bindInt64(&s, 1, inode) catch return Error.SqliteError;
    if (!s.step()) return Error.NotFound;
    const blob = s.columnBlob(0);
    if (blob.len > dst.len) return Error.Truncated;
    @memcpy(dst[0..blob.len], blob);
    return blob.len;
}

pub fn unlink(db: *c.sqlite3, path: []const u8) !void {
    const split = try splitParent(path);
    const parent_inode = try resolve(db, split.dir);
    const inode = try lookupInDir(db, parent_inode, split.name);
    const info = try statByInode(db, inode);
    if (info.kind == .dir) return Error.IsADirectory;

    var d = sqlite.prepare(db, "DELETE FROM dentries WHERE parent = ? AND name = ?;") catch
        return Error.SqliteError;
    defer d.finalize();
    sqlite.bindInt64(&d, 1, parent_inode) catch return Error.SqliteError;
    sqlite.bindText(&d, 2, split.name) catch return Error.SqliteError;
    _ = d.step();

    // For now, dentry removal also drops the inode (no hardlinks).
    var di = sqlite.prepare(db, "DELETE FROM inodes WHERE inode = ?;") catch
        return Error.SqliteError;
    defer di.finalize();
    sqlite.bindInt64(&di, 1, inode) catch return Error.SqliteError;
    _ = di.step();
}

pub fn rmdir(db: *c.sqlite3, path: []const u8) !void {
    const split = try splitParent(path);
    if (split.dir.len == 0 and split.name.len == 0) return Error.Invalid; // / is unremovable
    const parent_inode = try resolve(db, split.dir);
    const inode = try lookupInDir(db, parent_inode, split.name);
    const info = try statByInode(db, inode);
    if (info.kind != .dir) return Error.NotADirectory;

    // Refuse if the dir has any children.
    var ck = sqlite.prepare(db, "SELECT 1 FROM dentries WHERE parent = ? LIMIT 1;") catch
        return Error.SqliteError;
    sqlite.bindInt64(&ck, 1, inode) catch {
        ck.finalize();
        return Error.SqliteError;
    };
    const has_child = ck.step();
    ck.finalize();
    if (has_child) return Error.NotEmpty;

    var d = sqlite.prepare(db, "DELETE FROM dentries WHERE parent = ? AND name = ?;") catch
        return Error.SqliteError;
    defer d.finalize();
    sqlite.bindInt64(&d, 1, parent_inode) catch return Error.SqliteError;
    sqlite.bindText(&d, 2, split.name) catch return Error.SqliteError;
    _ = d.step();

    var di = sqlite.prepare(db, "DELETE FROM inodes WHERE inode = ?;") catch
        return Error.SqliteError;
    defer di.finalize();
    sqlite.bindInt64(&di, 1, inode) catch return Error.SqliteError;
    _ = di.step();
}

pub fn rename(db: *c.sqlite3, old: []const u8, new: []const u8) !void {
    const old_split = try splitParent(old);
    const new_split = try splitParent(new);

    const old_parent = try resolve(db, old_split.dir);
    const old_inode = try lookupInDir(db, old_parent, old_split.name);
    const old_info = try statByInode(db, old_inode);

    const new_parent = try resolve(db, new_split.dir);

    // If `new` already exists, POSIX rename allows file→file replace
    // and dir→empty-dir replace; reject all other combinations.
    if (lookupInDir(db, new_parent, new_split.name)) |existing| {
        const ex_info = try statByInode(db, existing);
        if (ex_info.kind != old_info.kind) {
            if (old_info.kind == .dir) return Error.NotADirectory;
            return Error.IsADirectory;
        }
        if (ex_info.kind == .dir) {
            var ck = sqlite.prepare(db, "SELECT 1 FROM dentries WHERE parent = ? LIMIT 1;") catch
                return Error.SqliteError;
            sqlite.bindInt64(&ck, 1, existing) catch {
                ck.finalize();
                return Error.SqliteError;
            };
            const has_child = ck.step();
            ck.finalize();
            if (has_child) return Error.NotEmpty;
        }
        // Drop the existing dentry and inode.
        var dd = sqlite.prepare(db, "DELETE FROM dentries WHERE parent = ? AND name = ?;") catch
            return Error.SqliteError;
        sqlite.bindInt64(&dd, 1, new_parent) catch {
            dd.finalize();
            return Error.SqliteError;
        };
        sqlite.bindText(&dd, 2, new_split.name) catch {
            dd.finalize();
            return Error.SqliteError;
        };
        _ = dd.step();
        dd.finalize();

        var di = sqlite.prepare(db, "DELETE FROM inodes WHERE inode = ?;") catch
            return Error.SqliteError;
        sqlite.bindInt64(&di, 1, existing) catch {
            di.finalize();
            return Error.SqliteError;
        };
        _ = di.step();
        di.finalize();
    } else |_| {}

    // Move the dentry.
    var up = sqlite.prepare(
        db,
        "UPDATE dentries SET parent = ?, name = ? WHERE parent = ? AND name = ?;",
    ) catch return Error.SqliteError;
    defer up.finalize();
    sqlite.bindInt64(&up, 1, new_parent) catch return Error.SqliteError;
    sqlite.bindText(&up, 2, new_split.name) catch return Error.SqliteError;
    sqlite.bindInt64(&up, 3, old_parent) catch return Error.SqliteError;
    sqlite.bindText(&up, 4, old_split.name) catch return Error.SqliteError;
    _ = up.step();
}

pub const ReaddirEntry = struct {
    inode: i64,
    kind: Kind,
    name: []const u8, // points into a writer-owned buffer
};

pub const ReaddirResult = struct {
    entries_written: usize,
    bytes_used: usize,
    next_cookie: []const u8, // points into the user-supplied cookie_buf; len 0 = end
};

/// Walk `path`'s directory entries with `cookie` as a resume point
/// (last name returned). Writes packed records into `out` and the
/// new cookie name into `cookie_buf`.
pub fn readdir(
    db: *c.sqlite3,
    path: []const u8,
    cookie: []const u8,
    max_entries: usize,
    out: []u8,
    cookie_buf: []u8,
) !ReaddirResult {
    const dir_inode = try resolve(db, path);
    const info = try statByInode(db, dir_inode);
    if (info.kind != .dir) return Error.NotADirectory;

    const sql =
        "SELECT name, inode FROM dentries" ++
        " WHERE parent = ? AND name > ?" ++
        " ORDER BY name LIMIT ?;";
    var s = sqlite.prepare(db, sql) catch return Error.SqliteError;
    defer s.finalize();
    sqlite.bindInt64(&s, 1, dir_inode) catch return Error.SqliteError;
    sqlite.bindText(&s, 2, cookie) catch return Error.SqliteError;
    sqlite.bindInt64(&s, 3, @intCast(max_entries)) catch return Error.SqliteError;

    var written: usize = 0;
    var bytes_used: usize = 0;
    var last_name_len: usize = 0;
    while (s.step()) {
        const name = s.columnText(0);
        const inode = s.columnInt64(1);

        // Inode kind for the record. SQLite SELECT join would be
        // cleaner but adds a planner roundtrip per child; fetch
        // separately. Cache could go in front of this later.
        const child_info = try statByInode(db, inode);

        const rec_hdr_bytes = @sizeOf(extern struct {
            inode: u64,
            kind: u8,
            name_len: u8,
            _pad: [6]u8,
        });
        const rec_total = alignUp8(rec_hdr_bytes + name.len);
        if (bytes_used + rec_total > out.len) break;

        // Header
        const inode_u64: u64 = @intCast(inode);
        std_writeU64Le(out[bytes_used..], inode_u64);
        out[bytes_used + 8] = @intFromEnum(child_info.kind);
        out[bytes_used + 9] = @intCast(name.len);
        @memset(out[bytes_used + 10 .. bytes_used + 16], 0);
        // Name
        @memcpy(out[bytes_used + 16 .. bytes_used + 16 + name.len], name);
        // Pad
        @memset(out[bytes_used + 16 + name.len .. bytes_used + rec_total], 0);

        bytes_used += rec_total;
        written += 1;
        last_name_len = name.len;
        if (last_name_len > cookie_buf.len) return Error.NameTooLong;
        @memcpy(cookie_buf[0..name.len], name);
    }

    const next_cookie: []const u8 = if (written < max_entries)
        cookie_buf[0..0]
    else
        cookie_buf[0..last_name_len];

    return .{
        .entries_written = written,
        .bytes_used = bytes_used,
        .next_cookie = next_cookie,
    };
}

// ── Internals ────────────────────────────────────────────────────

fn createInode(
    db: *c.sqlite3,
    path: []const u8,
    kind: Kind,
    mode: i64,
    initial_data: ?[]const u8,
) !i64 {
    const split = try splitParent(path);
    if (split.name.len == 0) return Error.Invalid;
    if (split.name.len > NAME_MAX) return Error.NameTooLong;

    const parent_inode = try resolve(db, split.dir);
    const parent_info = try statByInode(db, parent_inode);
    if (parent_info.kind != .dir) return Error.NotADirectory;

    if (lookupInDir(db, parent_inode, split.name)) |_| {
        return Error.Exists;
    } else |e| {
        if (e != Error.NotFound) return e;
    }

    // Insert inode.
    var ins = sqlite.prepare(
        db,
        "INSERT INTO inodes(kind, mode, size, mtime, ctime, atime, link_count, data)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    ) catch return Error.SqliteError;
    defer ins.finalize();
    const now = nowSeconds();
    sqlite.bindInt64(&ins, 1, @intFromEnum(kind)) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 2, mode) catch return Error.SqliteError;
    const init_size: i64 = if (initial_data) |d| @intCast(d.len) else 0;
    sqlite.bindInt64(&ins, 3, init_size) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 4, now) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 5, now) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 6, now) catch return Error.SqliteError;
    sqlite.bindInt64(&ins, 7, 1) catch return Error.SqliteError;
    if (initial_data) |d| {
        sqlite.bindBlob(&ins, 8, d) catch return Error.SqliteError;
    } else {
        // Bind NULL for dirs, empty blob for files.
        if (kind == .dir) {
            const rc = c.sqlite3_bind_null(ins.raw, 8);
            if (rc != c.SQLITE_OK) return Error.SqliteError;
        } else {
            sqlite.bindBlob(&ins, 8, "") catch return Error.SqliteError;
        }
    }
    _ = ins.step();

    const new_inode: i64 = c.sqlite3_last_insert_rowid(db);

    // Insert dentry.
    var de = sqlite.prepare(
        db,
        "INSERT INTO dentries(parent, name, inode) VALUES (?, ?, ?);",
    ) catch return Error.SqliteError;
    defer de.finalize();
    sqlite.bindInt64(&de, 1, parent_inode) catch return Error.SqliteError;
    sqlite.bindText(&de, 2, split.name) catch return Error.SqliteError;
    sqlite.bindInt64(&de, 3, new_inode) catch return Error.SqliteError;
    _ = de.step();

    return new_inode;
}

fn lookupInDir(db: *c.sqlite3, parent: i64, name: []const u8) !i64 {
    var s = sqlite.prepare(
        db,
        "SELECT inode FROM dentries WHERE parent = ? AND name = ?;",
    ) catch return Error.SqliteError;
    defer s.finalize();
    sqlite.bindInt64(&s, 1, parent) catch return Error.SqliteError;
    sqlite.bindText(&s, 2, name) catch return Error.SqliteError;
    if (!s.step()) return Error.NotFound;
    return s.columnInt64(0);
}

/// Resolve a slash-path to its inode id. "/" → 1. Empty path is invalid.
pub fn resolve(db: *c.sqlite3, path: []const u8) !i64 {
    if (path.len == 0) return Error.BadPath;
    if (path.len > PATH_MAX) return Error.PathTooLong;
    if (path[0] != '/') return Error.BadPath;

    var cur: i64 = ROOT_INODE;
    var i: usize = 1;
    while (i < path.len) {
        // Skip duplicate slashes.
        while (i < path.len and path[i] == '/') i += 1;
        if (i >= path.len) break;
        const start = i;
        while (i < path.len and path[i] != '/') i += 1;
        const comp = path[start..i];
        if (comp.len > NAME_MAX) return Error.NameTooLong;
        if (comp.len == 1 and comp[0] == '.') continue;
        if (comp.len == 2 and comp[0] == '.' and comp[1] == '.') {
            // Walk up via reverse dentry lookup.
            cur = try parentOf(db, cur);
            continue;
        }
        // The current inode must be a directory.
        const cur_info = try statByInode(db, cur);
        if (cur_info.kind != .dir) return Error.NotADirectory;
        cur = try lookupInDir(db, cur, comp);
    }
    return cur;
}

fn parentOf(db: *c.sqlite3, inode: i64) !i64 {
    if (inode == ROOT_INODE) return ROOT_INODE; // /.. = /
    var s = sqlite.prepare(db, "SELECT parent FROM dentries WHERE inode = ? LIMIT 1;") catch
        return Error.SqliteError;
    defer s.finalize();
    sqlite.bindInt64(&s, 1, inode) catch return Error.SqliteError;
    if (!s.step()) return Error.NotFound;
    return s.columnInt64(0);
}

const SplitPath = struct {
    dir: []const u8, // canonical path of parent ("/" for root children)
    name: []const u8, // basename
};

fn splitParent(path: []const u8) !SplitPath {
    if (path.len == 0 or path[0] != '/') return Error.BadPath;
    if (path.len == 1) return .{ .dir = "/", .name = "" }; // root itself
    // Trim trailing slashes.
    var end: usize = path.len;
    while (end > 1 and path[end - 1] == '/') end -= 1;
    var i = end;
    while (i > 0 and path[i - 1] != '/') i -= 1;
    const name = path[i..end];
    if (name.len > NAME_MAX) return Error.NameTooLong;
    if (i <= 1) return .{ .dir = "/", .name = name };
    // Strip the trailing '/' from the dir slice.
    return .{ .dir = path[0 .. i - 1], .name = name };
}

fn nowSeconds() i64 {
    return @intCast(syscall.timeGetwall().v1 / 1_000_000_000);
}

fn alignUp8(x: usize) usize {
    return (x + 7) & ~@as(usize, 7);
}

fn std_writeU64Le(dst: []u8, v: u64) void {
    var i: usize = 0;
    while (i < 8) : (i += 1) dst[i] = @truncate((v >> @intCast(i * 8)) & 0xFF);
}
