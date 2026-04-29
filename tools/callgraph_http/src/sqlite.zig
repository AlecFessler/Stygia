//! Minimal SQLite C-API wrapper.
//!
//! We use the system libsqlite3 directly rather than depending on a
//! third-party Zig binding so the project has zero non-system dependencies
//! and tracks Zig 0.15 cleanly. Surfaces only the calls the callgraph frontend
//! needs: open, prepare, bind, step, column readers, exec, finalize, close.

const std = @import("std");

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const Error = error{
    SqliteOpenFailed,
    SqlitePrepareFailed,
    SqliteBindFailed,
    SqliteStepFailed,
    SqliteExecFailed,
    SchemaIncomplete,
};

pub const Db = struct {
    handle: ?*c.sqlite3 = null,

    /// Open a DB read-only with mmap + query_only pragmas suitable for
    /// frontends. Returns an error if the file is missing OR if the
    /// `meta('schema_complete','true')` sentinel isn't present — we refuse
    /// to read partially-built indices.
    pub fn openReadOnly(path: []const u8, gpa: std.mem.Allocator) !Db {
        var db: Db = .{};
        const cpath = try gpa.dupeZ(u8, path);
        defer gpa.free(cpath);
        const flags: c_int = c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX;
        const rc = c.sqlite3_open_v2(cpath.ptr, &db.handle, flags, null);
        if (rc != c.SQLITE_OK) {
            if (db.handle) |h| _ = c.sqlite3_close(h);
            return Error.SqliteOpenFailed;
        }
        // Read-side pragmas; failures here are non-fatal but we still try.
        _ = c.sqlite3_exec(db.handle, "PRAGMA query_only=ON;", null, null, null);
        _ = c.sqlite3_exec(db.handle, "PRAGMA mmap_size=268435456;", null, null, null);
        _ = c.sqlite3_exec(db.handle, "PRAGMA temp_store=MEMORY;", null, null, null);
        // Schema-complete sentinel.
        if (!try db.schemaComplete(gpa)) {
            db.close();
            return Error.SchemaIncomplete;
        }
        return db;
    }

    pub fn close(self: *Db) void {
        if (self.handle) |h| _ = c.sqlite3_close(h);
        self.handle = null;
    }

    fn schemaComplete(self: *Db, gpa: std.mem.Allocator) !bool {
        var stmt = self.prepare(
            "SELECT value FROM meta WHERE key='schema_complete'",
            gpa,
        ) catch return false;
        defer stmt.finalize();
        if (!try stmt.step()) return false;
        const v = stmt.columnText(0) orelse return false;
        return std.mem.eql(u8, v, "true");
    }

    pub fn prepare(self: *Db, sql: []const u8, gpa: std.mem.Allocator) !Stmt {
        const csql = try gpa.dupeZ(u8, sql);
        defer gpa.free(csql);
        var raw: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.handle, csql.ptr, @intCast(csql.len), &raw, null);
        if (rc != c.SQLITE_OK) {
            std.debug.print("sqlite prepare failed: {s}\nSQL: {s}\n", .{
                std.mem.span(c.sqlite3_errmsg(self.handle)),
                sql,
            });
            return Error.SqlitePrepareFailed;
        }
        return .{ .raw = raw, .db = self.handle };
    }

    pub fn exec(self: *Db, sql: [:0]const u8) !void {
        var errmsg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.handle, sql.ptr, null, null, &errmsg);
        if (rc != c.SQLITE_OK) {
            if (errmsg != null) {
                std.debug.print("sqlite exec failed: {s}\n", .{std.mem.span(errmsg)});
                c.sqlite3_free(errmsg);
            }
            return Error.SqliteExecFailed;
        }
    }
};

pub const Stmt = struct {
    raw: ?*c.sqlite3_stmt,
    db: ?*c.sqlite3,

    pub fn finalize(self: *Stmt) void {
        if (self.raw) |r| _ = c.sqlite3_finalize(r);
        self.raw = null;
    }

    pub fn bindText(self: *Stmt, idx: c_int, text: []const u8) !void {
        // SQLITE_TRANSIENT (-1) — sqlite copies the buffer, so we don't need
        // to keep `text` alive past this call.
        const rc = c.sqlite3_bind_text(
            self.raw,
            idx,
            text.ptr,
            @intCast(text.len),
            @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))),
        );
        if (rc != c.SQLITE_OK) return Error.SqliteBindFailed;
    }

    pub fn bindInt(self: *Stmt, idx: c_int, v: i64) !void {
        const rc = c.sqlite3_bind_int64(self.raw, idx, v);
        if (rc != c.SQLITE_OK) return Error.SqliteBindFailed;
    }

    /// Returns `true` if a row is available, `false` on done.
    pub fn step(self: *Stmt) !bool {
        const rc = c.sqlite3_step(self.raw);
        if (rc == c.SQLITE_ROW) return true;
        if (rc == c.SQLITE_DONE) return false;
        std.debug.print("sqlite step failed: {s}\n", .{std.mem.span(c.sqlite3_errmsg(self.db))});
        return Error.SqliteStepFailed;
    }

    pub fn columnInt(self: *Stmt, idx: c_int) i64 {
        return c.sqlite3_column_int64(self.raw, idx);
    }

    /// Returns null when the column is NULL. The slice borrows sqlite's
    /// internal buffer and is valid only until the next `step()` /
    /// `finalize()`. Callers that need to keep it must copy.
    pub fn columnText(self: *Stmt, idx: c_int) ?[]const u8 {
        const t = c.sqlite3_column_type(self.raw, idx);
        if (t == c.SQLITE_NULL) return null;
        const ptr = c.sqlite3_column_text(self.raw, idx);
        if (ptr == null) return null;
        const len = c.sqlite3_column_bytes(self.raw, idx);
        return ptr[0..@intCast(len)];
    }
};
