//! Minimal SQLite C-API wrapper for the arch-layering analyzer. Mirrors the
//! shape used by tools/check_gen_lock/src/sqlite.zig and
//! tools/dead_code_zig/src/sqlite.zig — kept local so the analyzer is a
//! self-contained binary with no module deps beyond the system libsqlite3.

const std = @import("std");

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const Error = error{
    SqliteOpen,
    SqlitePrepare,
    SqliteBind,
    SqliteStep,
    SqliteExec,
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
            std.debug.print("sqlite open failed for {s}\n", .{path});
            return Error.SqliteOpen;
        }
        _ = c.sqlite3_exec(db.handle, "PRAGMA query_only=ON;", null, null, null);
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
            return Error.SqliteOpen;
        }
        _ = c.sqlite3_exec(db.handle, "PRAGMA temp_store=MEMORY;", null, null, null);
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
            return Error.SqlitePrepare;
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
            return Error.SqliteExec;
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

    pub fn reset(self: *Stmt) void {
        if (self.raw) |r| {
            _ = c.sqlite3_reset(r);
            _ = c.sqlite3_clear_bindings(r);
        }
    }

    pub fn bindText(self: *Stmt, idx: c_int, text: []const u8) !void {
        const rc = c.sqlite3_bind_text(
            self.raw,
            idx,
            text.ptr,
            @intCast(text.len),
            @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))),
        );
        if (rc != c.SQLITE_OK) return Error.SqliteBind;
    }

    pub fn bindInt(self: *Stmt, idx: c_int, v: i64) !void {
        const rc = c.sqlite3_bind_int64(self.raw, idx, v);
        if (rc != c.SQLITE_OK) return Error.SqliteBind;
    }

    pub fn step(self: *Stmt) !bool {
        const rc = c.sqlite3_step(self.raw);
        if (rc == c.SQLITE_ROW) return true;
        if (rc == c.SQLITE_DONE) return false;
        std.debug.print("sqlite step failed: {s}\n", .{std.mem.span(c.sqlite3_errmsg(self.db))});
        return Error.SqliteStep;
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
};
