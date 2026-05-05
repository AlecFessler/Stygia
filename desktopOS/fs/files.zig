// File-API wrapper on top of the SQLite-backed filesystem.
//
// Schema: `files(path TEXT PRIMARY KEY, data BLOB, mtime INTEGER)`.
// Each file is a single blob row. Writes overwrite the row. Reads
// return the blob. stat returns size + mtime.
//
// The intent is the smallest-possible POSIX-ish surface — open() is
// implicit, open/close don't carry state, read/write replace whole
// blobs. Random-access reads or partial writes would route through
// SQLite's `incremental I/O` API on the BLOB column; that's a phase-3
// extension when we want to host actual application files.

const lib = @import("lib");
const log = @import("log");
const sqlite = @import("sqlite");

const c = sqlite.c;
const syscall = lib.syscall;

pub const Error = error{
    NotFound,
    SqliteError,
    Truncated,
};

const SCHEMA =
    "CREATE TABLE IF NOT EXISTS files(" ++
    "  path TEXT PRIMARY KEY," ++
    "  data BLOB NOT NULL," ++
    "  mtime INTEGER NOT NULL DEFAULT 0" ++
    ");";

pub fn init(db: *c.sqlite3) !void {
    if (sqlite.exec(db, SCHEMA) != c.SQLITE_OK) return Error.SqliteError;
}

pub fn write(db: *c.sqlite3, path: []const u8, data: []const u8) !void {
    var stmt = sqlite.prepare(
        db,
        "INSERT OR REPLACE INTO files(path, data, mtime) VALUES (?, ?, ?);",
    ) catch return Error.SqliteError;
    defer stmt.finalize();
    try sqlite.bindText(&stmt, 1, path);
    try sqlite.bindBlob(&stmt, 2, data);
    const now: i64 = @intCast(syscall.timeGetwall().v1 / 1_000_000_000);
    try sqlite.bindInt64(&stmt, 3, now);
    _ = stmt.step(); // INSERT returns SQLITE_DONE → step() returns false; no error path needed here
}

/// Read up to dst.len bytes of `path`. Returns the actual byte count.
/// Error.Truncated when the file is larger than dst (still writes
/// dst.len bytes).
pub fn read(db: *c.sqlite3, path: []const u8, dst: []u8) !usize {
    var stmt = sqlite.prepare(db, "SELECT data FROM files WHERE path = ?;") catch
        return Error.SqliteError;
    defer stmt.finalize();
    try sqlite.bindText(&stmt, 1, path);
    if (!stmt.step()) return Error.NotFound;
    const blob = stmt.columnBlob(0);
    const n = @min(dst.len, blob.len);
    @memcpy(dst[0..n], blob[0..n]);
    if (blob.len > dst.len) return Error.Truncated;
    return n;
}

pub const StatInfo = struct {
    size: u64,
    mtime: i64,
};

pub fn stat(db: *c.sqlite3, path: []const u8) !StatInfo {
    var stmt = sqlite.prepare(
        db,
        "SELECT length(data), mtime FROM files WHERE path = ?;",
    ) catch return Error.SqliteError;
    defer stmt.finalize();
    try sqlite.bindText(&stmt, 1, path);
    if (!stmt.step()) return Error.NotFound;
    return .{
        .size = @intCast(stmt.columnInt64(0)),
        .mtime = stmt.columnInt64(1),
    };
}

pub fn unlink(db: *c.sqlite3, path: []const u8) !void {
    var stmt = sqlite.prepare(db, "DELETE FROM files WHERE path = ?;") catch
        return Error.SqliteError;
    defer stmt.finalize();
    try sqlite.bindText(&stmt, 1, path);
    _ = stmt.step();
}
