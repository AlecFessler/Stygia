//! Minimal SQLite C-API wrapper for the dead-code analyzer.
//! Read-only access to the per-(arch, commit_sha) callgraph DB.

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

    pub fn openReadOnly(path: []const u8, gpa: std.mem.Allocator) !Db {
        var db: Db = .{};
        const cpath = try gpa.dupeZ(u8, path);
        defer gpa.free(cpath);
        const flags: c_int = c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX;
        const rc = c.sqlite3_open_v2(cpath.ptr, &db.handle, flags, null);
        if (rc != c.SQLITE_OK) {
            if (db.handle) |h| _ = c.sqlite3_close(h);
            std.debug.print("dead_code: failed to open DB at {s}: rc={d}\n", .{ path, rc });
            return Error.SqliteOpenFailed;
        }
        // Don't set query_only — we need to create TEMP tables (which live
        // in a separate database file, so the on-disk DB is still untouched).
        _ = c.sqlite3_exec(db.handle, "PRAGMA mmap_size=268435456;", null, null, null);
        _ = c.sqlite3_exec(db.handle, "PRAGMA temp_store=MEMORY;", null, null, null);
        if (!try db.schemaComplete(gpa)) {
            db.close();
            return Error.SchemaIncomplete;
        }
        return db;
    }

    pub fn openReadWrite(path: []const u8, gpa: std.mem.Allocator) !Db {
        var db: Db = .{};
        const cpath = try gpa.dupeZ(u8, path);
        defer gpa.free(cpath);
        const flags: c_int = c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_NOMUTEX;
        const rc = c.sqlite3_open_v2(cpath.ptr, &db.handle, flags, null);
        if (rc != c.SQLITE_OK) {
            if (db.handle) |h| _ = c.sqlite3_close(h);
            return Error.SqliteOpenFailed;
        }
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

    pub fn columnText(self: *Stmt, idx: c_int) ?[]const u8 {
        const t = c.sqlite3_column_type(self.raw, idx);
        if (t == c.SQLITE_NULL) return null;
        const ptr = c.sqlite3_column_text(self.raw, idx);
        if (ptr == null) return null;
        const len = c.sqlite3_column_bytes(self.raw, idx);
        return ptr[0..@intCast(len)];
    }

    pub fn columnBlob(self: *Stmt, idx: c_int) ?[]const u8 {
        const t = c.sqlite3_column_type(self.raw, idx);
        if (t == c.SQLITE_NULL) return null;
        const ptr = c.sqlite3_column_blob(self.raw, idx);
        if (ptr == null) return null;
        const len = c.sqlite3_column_bytes(self.raw, idx);
        const bytes: [*]const u8 = @ptrCast(ptr.?);
        return bytes[0..@intCast(len)];
    }
};
