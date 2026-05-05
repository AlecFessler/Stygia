// Zig glue around the SQLite C API. Mirrors the surface
// `tools/callgraph_mcp/src/sqlite.zig` exposes for the host tools,
// but adapted for our embedded freestanding world: we install our
// own VFS + memsys5 heap before sqlite3_initialize. No dynamic
// allocation outside SQLite's own pool; no panics on errors —
// callers check return codes.

const lib = @import("lib");
const log = @import("log");
const blockdev = @import("blockdev");

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const vfs = @import("vfs.zig");

pub const Error = error{
    SqliteError,
    SqliteOpen,
    SqlitePrepare,
    SqliteBind,
    SqliteStep,
    SqliteFinalize,
};

pub const HEAP_BYTES: usize = 4 * 1024 * 1024; // 4 MiB heap for SQLite
pub const PAGE_BYTES: usize = 1 * 1024 * 1024; // 1 MiB page cache
const MIN_ALLOC: c_int = 64;

var heap_buf: [HEAP_BYTES]u8 align(8) = undefined;
var page_buf: [PAGE_BYTES]u8 align(8) = undefined;
const PAGE_SIZE: c_int = 4096;

pub fn configureHeap() c_int {
    var rc = c.sqlite3_config(
        c.SQLITE_CONFIG_HEAP,
        @as(*anyopaque, @ptrCast(&heap_buf)),
        @as(c_int, @intCast(HEAP_BYTES)),
        MIN_ALLOC,
    );
    if (rc != c.SQLITE_OK) return rc;
    rc = c.sqlite3_config(
        c.SQLITE_CONFIG_PAGECACHE,
        @as(*anyopaque, @ptrCast(&page_buf)),
        PAGE_SIZE,
        @as(c_int, @intCast(PAGE_BYTES / @as(usize, @intCast(PAGE_SIZE)))),
    );
    return rc;
}

pub fn open(name: [*:0]const u8) Error!*c.sqlite3 {
    var db: ?*c.sqlite3 = null;
    const rc = c.sqlite3_open_v2(
        name,
        &db,
        c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE,
        null,
    );
    if (rc != c.SQLITE_OK) {
        log.print("sqlite3_open_v2 rc=");
        log.dec(@intCast(rc));
        log.print("\n");
        if (db) |h| _ = c.sqlite3_close(h);
        return Error.SqliteOpen;
    }
    return db.?;
}

pub fn close(db: *c.sqlite3) void {
    _ = c.sqlite3_close(db);
}

pub fn exec(db: *c.sqlite3, sql: [*:0]const u8) c_int {
    return c.sqlite3_exec(db, sql, null, null, null);
}

pub const Stmt = struct {
    raw: ?*c.sqlite3_stmt,

    pub fn finalize(self: *Stmt) void {
        if (self.raw) |s| _ = c.sqlite3_finalize(s);
        self.raw = null;
    }

    pub fn step(self: *Stmt) bool {
        const rc = c.sqlite3_step(self.raw);
        return rc == c.SQLITE_ROW;
    }

    pub fn columnInt64(self: *Stmt, idx: c_int) i64 {
        return c.sqlite3_column_int64(self.raw, idx);
    }

    pub fn columnBlob(self: *Stmt, idx: c_int) []const u8 {
        const ptr = c.sqlite3_column_blob(self.raw, idx);
        const n = c.sqlite3_column_bytes(self.raw, idx);
        if (ptr == null or n == 0) return &.{};
        const u8p: [*]const u8 = @ptrCast(ptr);
        return u8p[0..@intCast(n)];
    }

    pub fn columnText(self: *Stmt, idx: c_int) []const u8 {
        const ptr = c.sqlite3_column_text(self.raw, idx);
        const n = c.sqlite3_column_bytes(self.raw, idx);
        if (ptr == null or n == 0) return &.{};
        return ptr[0..@intCast(n)];
    }
};

pub fn prepare(db: *c.sqlite3, sql: [*:0]const u8) Error!Stmt {
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) {
        log.print("sqlite3_prepare_v2 rc=");
        log.dec(@intCast(rc));
        log.print(": ");
        if (c.sqlite3_errmsg(db)) |msg| {
            var i: usize = 0;
            while (msg[i] != 0) : (i += 1) log.putc(msg[i]);
        }
        log.print("\n");
        return Error.SqlitePrepare;
    }
    return .{ .raw = stmt };
}

pub fn bindBlob(stmt: *Stmt, idx: c_int, data: []const u8) Error!void {
    const rc = c.sqlite3_bind_blob(
        stmt.raw,
        idx,
        data.ptr,
        @intCast(data.len),
        c.SQLITE_STATIC,
    );
    if (rc != c.SQLITE_OK) return Error.SqliteBind;
}

pub fn bindText(stmt: *Stmt, idx: c_int, data: []const u8) Error!void {
    const rc = c.sqlite3_bind_text(
        stmt.raw,
        idx,
        data.ptr,
        @intCast(data.len),
        c.SQLITE_STATIC,
    );
    if (rc != c.SQLITE_OK) return Error.SqliteBind;
}

pub fn bindInt64(stmt: *Stmt, idx: c_int, v: i64) Error!void {
    const rc = c.sqlite3_bind_int64(stmt.raw, idx, v);
    if (rc != c.SQLITE_OK) return Error.SqliteBind;
}

// ── Incremental BLOB I/O ─────────────────────────────────────────
//
// For files that don't change size, sqlite3_blob_open + _read/_write
// avoids ever materializing the whole row: SQLite walks the b-tree
// to the BLOB's storage and copies just the requested byte range.
// Used by files.pread / files.pwrite-within for O(len) transfers
// instead of O(file_size).

pub const Blob = struct {
    raw: ?*c.sqlite3_blob,

    pub fn close(self: *Blob) void {
        if (self.raw) |b| _ = c.sqlite3_blob_close(b);
        self.raw = null;
    }

    pub fn bytes(self: *Blob) usize {
        return @intCast(c.sqlite3_blob_bytes(self.raw));
    }

    pub fn read(self: *Blob, dst: []u8, offset: u64) Error!void {
        const rc = c.sqlite3_blob_read(
            self.raw,
            dst.ptr,
            @intCast(dst.len),
            @intCast(offset),
        );
        if (rc != c.SQLITE_OK) return Error.SqliteError;
    }

    pub fn write(self: *Blob, src: []const u8, offset: u64) Error!void {
        const rc = c.sqlite3_blob_write(
            self.raw,
            src.ptr,
            @intCast(src.len),
            @intCast(offset),
        );
        if (rc != c.SQLITE_OK) return Error.SqliteError;
    }
};

pub fn blobOpen(
    db: *c.sqlite3,
    table: [*:0]const u8,
    column: [*:0]const u8,
    rowid: i64,
    rw: bool,
) Error!Blob {
    var raw: ?*c.sqlite3_blob = null;
    const flags: c_int = if (rw) 1 else 0;
    const rc = c.sqlite3_blob_open(db, "main", table, column, rowid, flags, &raw);
    if (rc != c.SQLITE_OK) return Error.SqliteError;
    return .{ .raw = raw };
}
