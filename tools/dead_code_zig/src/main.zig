//! Dead-code analyzer over the per-(arch, commit_sha) callgraph DB.
//!
//! Replaces the prior token-walking analyzer with a thin SQL client. The
//! indexer already encodes every piece of structural information the prior
//! tool reconstructed by hand:
//!   * `entity` — every fn / type / const / var / field decl.
//!   * `entry_reaches` — IR-edge-filtered forward closure from each entry.
//!   * `const_alias` — `pub const X = a.b.C;` alias re-export edges.
//!   * `entity_type_ref` — chain-shaped type uses (field/param/return).
//!   * `token` — for the residual field-name `.<ident>` heuristic.
//!   * `file.source` — full file bytes for skip-range hashing.
//!
//! Behavior matches the previous binary on `kernel/`, `routerOS/`,
//! `hyprvOS/`, `bootloader/`. CLI is now `--db <path> --target <name>`;
//! the positional form is removed (DB-only mode is a hard break).
//!
//! Skip-file workflow ports verbatim from the old tool. Hash bytes come
//! from `file.source` so the analyzer is reproducible against an archived
//! DB without needing the matching git checkout.

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const sqlite = @import("sqlite.zig");

// -----------------------------------------------------------------
// Skip-file types and globals
// -----------------------------------------------------------------

const Sha256 = std.crypto.hash.sha2.Sha256;

const SkipStatus = enum {
    /// Hash matches stored value — findings inside this range are silently dropped.
    hit,
    /// Hash mismatch — the range has drifted since last review.
    invalidated,
    /// Range refers to a file that no longer exists (in the DB).
    missing,
    /// Range bounds are out of order, zero, or extend past EOF when end is numeric.
    bad_range,
};

const SkipEntry = struct {
    rel_path: []const u8,
    start_line: u32,
    end_line: u32,
    end_is_eof: bool,
    stored_hash: []const u8,
    current_hash: []const u8 = "",
    status: SkipStatus = .hit,
};

var g_arena_state: std.heap.ArenaAllocator = undefined;
var g_arena: Allocator = undefined;
var g_skip_entries: ArrayList(SkipEntry) = .{};
var g_skip_file_path: []const u8 = "";

/// Target dir relative to repo root (e.g. "kernel"). Skip-entry paths are
/// resolved against `<target>/<rel_path>` in the DB.
var g_target_rel: []const u8 = "";

// -----------------------------------------------------------------
// Path helpers (kept for skip-file IO; everything else goes through SQL)
// -----------------------------------------------------------------

fn joinPath(a: Allocator, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts, 0..) |p, i| {
        total += p.len;
        if (i + 1 < parts.len) total += 1;
    }
    const out = try a.alloc(u8, total);
    var idx: usize = 0;
    for (parts, 0..) |p, i| {
        @memcpy(out[idx .. idx + p.len], p);
        idx += p.len;
        if (i + 1 < parts.len) {
            out[idx] = '/';
            idx += 1;
        }
    }
    return out;
}

// -----------------------------------------------------------------
// Skip-file: hashing, parsing, IO
// -----------------------------------------------------------------

fn hexEncode(digest: [Sha256.digest_length]u8, out: *[Sha256.digest_length * 2]u8) void {
    const tab = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = tab[b >> 4];
        out[i * 2 + 1] = tab[b & 0x0f];
    }
}

/// Hash the line range `[start..end]` (1-indexed, inclusive). End-of-line
/// conventions are normalized to `\n` before hashing and the buffer always
/// terminates with one trailing `\n`. Returns null on invalid range.
fn hashLineRange(
    a: Allocator,
    file_text: []const u8,
    start_line: u32,
    end_line: u32,
    end_is_eof: bool,
) !?[Sha256.digest_length * 2]u8 {
    if (start_line == 0) return null;

    var buf: ArrayList(u8) = .{};
    defer buf.deinit(a);

    var line_no: u32 = 1;
    var i: usize = 0;
    var collected: u32 = 0;
    while (i < file_text.len) {
        var line_end = i;
        while (line_end < file_text.len and file_text[line_end] != '\n' and file_text[line_end] != '\r') {
            line_end += 1;
        }
        const content = file_text[i..line_end];

        var next = line_end;
        if (next < file_text.len) {
            if (file_text[next] == '\r') {
                next += 1;
                if (next < file_text.len and file_text[next] == '\n') next += 1;
            } else if (file_text[next] == '\n') {
                next += 1;
            }
        }

        const in_range = line_no >= start_line and (end_is_eof or line_no <= end_line);
        if (in_range) {
            try buf.appendSlice(a, content);
            try buf.append(a, '\n');
            collected += 1;
        }

        if (!end_is_eof and line_no >= end_line) break;
        line_no += 1;
        i = next;
    }

    if (end_is_eof) {
        if (collected == 0) return null;
    } else {
        if (start_line > line_no or end_line < start_line) return null;
        if (end_line > line_no) return null;
    }

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(buf.items, &digest, .{});
    var hex: [Sha256.digest_length * 2]u8 = undefined;
    hexEncode(digest, &hex);
    return hex;
}

fn parseSkipLine(a: Allocator, raw: []const u8) !?SkipEntry {
    var line = raw;
    while (line.len > 0 and (line[line.len - 1] == ' ' or line[line.len - 1] == '\t' or line[line.len - 1] == '\r')) {
        line = line[0 .. line.len - 1];
    }
    while (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) line = line[1..];
    if (line.len == 0) return null;
    if (line[0] == '#') return null;

    var split: usize = 0;
    while (split < line.len and line[split] != ' ' and line[split] != '\t') split += 1;
    if (split == line.len) return error.SkipEntryMalformed;
    const left = line[0..split];
    var right = line[split..];
    while (right.len > 0 and (right[0] == ' ' or right[0] == '\t')) right = right[1..];

    const colon = mem.lastIndexOfScalar(u8, left, ':') orelse return error.SkipEntryMalformed;
    const rel_path = try a.dupe(u8, left[0..colon]);
    const range = left[colon + 1 ..];
    const dash = mem.indexOfScalar(u8, range, '-') orelse return error.SkipEntryMalformed;
    const start_str = range[0..dash];
    const end_str = range[dash + 1 ..];
    if (start_str.len == 0 or end_str.len == 0) return error.SkipEntryMalformed;

    const start_line = std.fmt.parseInt(u32, start_str, 10) catch return error.SkipEntryMalformed;
    var end_line: u32 = 0;
    var end_is_eof = false;
    if (mem.eql(u8, end_str, "end")) {
        end_is_eof = true;
    } else {
        end_line = std.fmt.parseInt(u32, end_str, 10) catch return error.SkipEntryMalformed;
    }

    const prefix = "sha256:";
    if (!mem.startsWith(u8, right, prefix)) return error.SkipEntryMalformed;
    const hex = right[prefix.len..];
    if (hex.len != Sha256.digest_length * 2) return error.SkipEntryMalformed;
    for (hex) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return error.SkipEntryMalformed;
    }
    const stored = try a.dupe(u8, hex);

    return SkipEntry{
        .rel_path = rel_path,
        .start_line = start_line,
        .end_line = end_line,
        .end_is_eof = end_is_eof,
        .stored_hash = stored,
    };
}

/// Resolve a skip entry's relative path to the target-prefixed form used in
/// the file table. Skip-entry paths are written relative to the target dir
/// (e.g. `arch/x64/apic.zig`) but the DB stores paths relative to its
/// `--kernel-root` (e.g. `arch/x64/apic.zig` when indexer was rooted at
/// `kernel/`). For DBs rooted at the repo (containing `kernel/`,
/// `routerOS/`, ...) we may need to prepend the target.
fn resolveSkipDbPaths(a: Allocator, rel: []const u8) ![][]const u8 {
    var paths: ArrayList([]const u8) = .{};
    // Without the target prefix (DB rooted at the target dir).
    try paths.append(a, try a.dupe(u8, rel));
    // With the target prefix (DB rooted at the repo).
    if (g_target_rel.len > 0) {
        try paths.append(a, try joinPath(a, &.{ g_target_rel, rel }));
    }
    return paths.toOwnedSlice(a);
}

fn loadSkipFile(a: Allocator, path: []const u8, db: *sqlite.Db) !void {
    const stderr = std.fs.File.stderr();
    const f = fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer f.close();
    const stat = try f.stat();
    const text = try a.alloc(u8, stat.size);
    _ = try f.readAll(text);

    g_skip_file_path = try a.dupe(u8, path);

    var line_no: u32 = 0;
    var it = mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        line_no += 1;
        var entry = parseSkipLine(a, raw) catch {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "skip: {s}:{d}: malformed entry, skipping\n", .{ path, line_no }) catch continue;
            _ = stderr.write(msg) catch {};
            continue;
        } orelse continue;

        try validateSkipEntry(a, &entry, db);
        try g_skip_entries.append(a, entry);
    }
}

/// Compute current_hash for an entry from `file.source` in the DB.
fn validateSkipEntry(a: Allocator, entry: *SkipEntry, db: *sqlite.Db) !void {
    const candidates = try resolveSkipDbPaths(a, entry.rel_path);
    for (candidates) |cand| {
        const src = try fetchFileSource(a, db, cand);
        if (src) |bytes| {
            const hex_opt = try hashLineRange(a, bytes, entry.start_line, entry.end_line, entry.end_is_eof);
            if (hex_opt) |hex_buf| {
                const hex = try a.dupe(u8, &hex_buf);
                entry.current_hash = hex;
                entry.status = if (mem.eql(u8, hex, entry.stored_hash)) .hit else .invalidated;
            } else {
                entry.current_hash = "";
                entry.status = .bad_range;
            }
            return;
        }
    }
    entry.current_hash = "";
    entry.status = .missing;
}

fn fetchFileSource(a: Allocator, db: *sqlite.Db, path: []const u8) !?[]u8 {
    var stmt = try db.prepare("SELECT source FROM file WHERE path = ?", a);
    defer stmt.finalize();
    try stmt.bindText(1, path);
    if (try stmt.step()) {
        const blob = stmt.columnBlob(0) orelse return null;
        return try a.dupe(u8, blob);
    }
    return null;
}

/// True iff a `hit` skip entry covers `(rel_path, line)`.
fn skipCovers(rel_path: []const u8, line: u32) bool {
    var rel = rel_path;
    if (g_target_rel.len > 0 and mem.startsWith(u8, rel, g_target_rel) and
        rel.len > g_target_rel.len and rel[g_target_rel.len] == '/')
    {
        rel = rel[g_target_rel.len + 1 ..];
    }
    for (g_skip_entries.items) |e| {
        if (e.status != .hit) continue;
        if (!mem.eql(u8, e.rel_path, rel)) continue;
        if (line < e.start_line) continue;
        if (!e.end_is_eof and line > e.end_line) continue;
        return true;
    }
    return false;
}

fn reportSkipDiagnostics() !bool {
    const stderr = std.fs.File.stderr();
    var any = false;
    var buf: [1024]u8 = undefined;
    for (g_skip_entries.items) |e| {
        switch (e.status) {
            .hit => continue,
            .invalidated => {
                any = true;
                const end_str: ?[]const u8 = if (e.end_is_eof) "end" else null;
                const msg1 = if (end_str) |es|
                    try std.fmt.bufPrint(&buf, "INVALIDATED: {s}:{d}-{s}\n", .{ e.rel_path, e.start_line, es })
                else
                    try std.fmt.bufPrint(&buf, "INVALIDATED: {s}:{d}-{d}\n", .{ e.rel_path, e.start_line, e.end_line });
                _ = stderr.write(msg1) catch {};
                const msg2 = try std.fmt.bufPrint(&buf, "  stored:  sha256:{s}\n", .{e.stored_hash});
                _ = stderr.write(msg2) catch {};
                const msg3 = try std.fmt.bufPrint(&buf, "  current: sha256:{s}\n", .{e.current_hash});
                _ = stderr.write(msg3) catch {};
                const msg4 = if (end_str) |es|
                    try std.fmt.bufPrint(&buf, "  The whitelisted range has changed since last review. Re-review and run\n  `dead_code_zig --update-skip {s}:{d}-{s}` to refresh.\n", .{ e.rel_path, e.start_line, es })
                else
                    try std.fmt.bufPrint(&buf, "  The whitelisted range has changed since last review. Re-review and run\n  `dead_code_zig --update-skip {s}:{d}-{d}` to refresh.\n", .{ e.rel_path, e.start_line, e.end_line });
                _ = stderr.write(msg4) catch {};
            },
            .missing => {
                any = true;
                const msg = if (e.end_is_eof)
                    try std.fmt.bufPrint(&buf, "MISSING: {s}:{d}-end\n  File not found under {s}/. Remove the entry or restore the file.\n", .{ e.rel_path, e.start_line, g_target_rel })
                else
                    try std.fmt.bufPrint(&buf, "MISSING: {s}:{d}-{d}\n  File not found under {s}/. Remove the entry or restore the file.\n", .{ e.rel_path, e.start_line, e.end_line, g_target_rel });
                _ = stderr.write(msg) catch {};
            },
            .bad_range => {
                any = true;
                const msg = if (e.end_is_eof)
                    try std.fmt.bufPrint(&buf, "BAD-RANGE: {s}:{d}-end\n  Range invalid (file empty or start past EOF).\n", .{ e.rel_path, e.start_line })
                else
                    try std.fmt.bufPrint(&buf, "BAD-RANGE: {s}:{d}-{d}\n  Range invalid (start > end, start == 0, or end past EOF).\n", .{ e.rel_path, e.start_line, e.end_line });
                _ = stderr.write(msg) catch {};
            },
        }
    }
    return any;
}

/// Implement `--update-skip <rel-path>:<start>-<end>`. Reads the source from
/// the DB, computes a fresh hash, and writes/updates the entry in the
/// on-disk skip file.
fn updateSkipEntry(a: Allocator, raw_arg: []const u8, skip_file: []const u8, db: *sqlite.Db) !u8 {
    const stderr = std.fs.File.stderr();

    const colon = mem.lastIndexOfScalar(u8, raw_arg, ':') orelse {
        _ = stderr.write("--update-skip: expected <rel-path>:<start>-<end>\n") catch {};
        return 2;
    };
    const rel_path = raw_arg[0..colon];
    const range = raw_arg[colon + 1 ..];
    const dash = mem.indexOfScalar(u8, range, '-') orelse {
        _ = stderr.write("--update-skip: expected <start>-<end>\n") catch {};
        return 2;
    };
    const start_str = range[0..dash];
    const end_str = range[dash + 1 ..];
    const start_line = std.fmt.parseInt(u32, start_str, 10) catch {
        _ = stderr.write("--update-skip: bad start line\n") catch {};
        return 2;
    };
    var end_line: u32 = 0;
    var end_is_eof = false;
    if (mem.eql(u8, end_str, "end")) {
        end_is_eof = true;
    } else {
        end_line = std.fmt.parseInt(u32, end_str, 10) catch {
            _ = stderr.write("--update-skip: bad end line (expected number or 'end')\n") catch {};
            return 2;
        };
    }

    // Hash the current file content from the DB.
    const candidates = try resolveSkipDbPaths(a, rel_path);
    var src_opt: ?[]u8 = null;
    for (candidates) |cand| {
        if (try fetchFileSource(a, db, cand)) |bytes| {
            src_opt = bytes;
            break;
        }
    }
    const text = src_opt orelse {
        var buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "--update-skip: file not found in DB: {s}\n", .{rel_path}) catch return 2;
        _ = stderr.write(msg) catch {};
        return 2;
    };

    const hex_opt = try hashLineRange(a, text, start_line, end_line, end_is_eof);
    const hex_buf = hex_opt orelse {
        _ = stderr.write("--update-skip: invalid range for that file\n") catch {};
        return 2;
    };
    const new_hex = &hex_buf;

    // Read existing skip-file content (or empty if absent).
    var existing: []u8 = "";
    if (fs.openFileAbsolute(skip_file, .{})) |sf| {
        defer sf.close();
        const sst = try sf.stat();
        existing = try a.alloc(u8, sst.size);
        _ = try sf.readAll(existing);
    } else |err| switch (err) {
        error.FileNotFound => existing = "",
        else => return err,
    }

    var left_buf: [512]u8 = undefined;
    const left = if (end_is_eof)
        try std.fmt.bufPrint(&left_buf, "{s}:{d}-end", .{ rel_path, start_line })
    else
        try std.fmt.bufPrint(&left_buf, "{s}:{d}-{d}", .{ rel_path, start_line, end_line });

    var out: ArrayList(u8) = .{};
    var replaced = false;
    var it = mem.splitScalar(u8, existing, '\n');
    var first = true;
    while (it.next()) |line| {
        if (!first) try out.append(a, '\n');
        first = false;
        var trimmed = line;
        while (trimmed.len > 0 and (trimmed[0] == ' ' or trimmed[0] == '\t')) trimmed = trimmed[1..];
        const matches = mem.startsWith(u8, trimmed, left) and
            (trimmed.len == left.len or trimmed[left.len] == ' ' or trimmed[left.len] == '\t');
        if (matches and !replaced) {
            var rep_buf: [256]u8 = undefined;
            const rep = try std.fmt.bufPrint(&rep_buf, "{s}    sha256:{s}", .{ left, new_hex });
            try out.appendSlice(a, rep);
            replaced = true;
        } else {
            try out.appendSlice(a, line);
        }
    }
    if (!replaced) {
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') {
            try out.append(a, '\n');
        }
        var rep_buf: [256]u8 = undefined;
        const rep = try std.fmt.bufPrint(&rep_buf, "{s}    sha256:{s}\n", .{ left, new_hex });
        try out.appendSlice(a, rep);
    } else {
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') {
            try out.append(a, '\n');
        }
    }

    const tmp_path = try std.fmt.allocPrint(a, "{s}.tmp", .{skip_file});
    {
        const wf = try fs.createFileAbsolute(tmp_path, .{ .truncate = true });
        defer wf.close();
        try wf.writeAll(out.items);
    }
    try fs.renameAbsolute(tmp_path, skip_file);

    var msg_buf: [512]u8 = undefined;
    const action = if (replaced) "updated" else "added";
    const msg = std.fmt.bufPrint(&msg_buf, "{s}: {s} (sha256:{s})\n", .{ action, left, new_hex }) catch return 0;
    const stdout = std.fs.File.stdout();
    _ = stdout.write(msg) catch {};
    return 0;
}

fn defaultSkipPath(a: Allocator, repo_root: []const u8, target_rel: []const u8) ![]u8 {
    return joinPath(a, &.{ repo_root, target_rel, ".dead-code-skip.txt" });
}

// -----------------------------------------------------------------
// Analysis: alive-set CTE + dead-set query
// -----------------------------------------------------------------

const Finding = struct {
    file_path: []const u8,
    name: []const u8,
    parent: ?[]const u8,
    line: u32,
    kind_label: []const u8,
    byte_start: u32,
    byte_end: u32,
    entity_id: i64,
    file_id: i64,
};

fn kindLabel(kind: []const u8) []const u8 {
    if (mem.eql(u8, kind, "fn")) return "FUNCTION";
    if (mem.eql(u8, kind, "type")) return "STRUCT";
    if (mem.eql(u8, kind, "const")) return "CONST";
    if (mem.eql(u8, kind, "var")) return "VAR";
    if (mem.eql(u8, kind, "field")) return "FIELD";
    if (mem.eql(u8, kind, "variant")) return "VARIANT";
    if (mem.eql(u8, kind, "namespace")) return "CONST";
    return "UNKNOWN";
}

fn collectFindings(
    a: Allocator,
    db: *sqlite.Db,
    target: []const u8,
) ![]Finding {
    // Precompute entity simple-names into a temp table so the alive-set
    // query can join against them without resorting to non-portable string
    // ops (SQLite has no `reverse` / "find-last-of" builtin).
    try db.exec("CREATE TEMP TABLE entity_simple_name (entity_id INTEGER PRIMARY KEY, name TEXT NOT NULL)");
    {
        var s = try db.prepare("SELECT id, qualified_name FROM entity", a);
        defer s.finalize();
        var ins = try db.prepare("INSERT INTO entity_simple_name (entity_id, name) VALUES (?, ?)", a);
        defer ins.finalize();
        while (try s.step()) {
            const id = s.columnInt(0);
            const qname = s.columnText(1) orelse continue;
            const simple = if (mem.lastIndexOfScalar(u8, qname, '.')) |i| qname[i + 1 ..] else qname;
            try ins.bindInt(1, id);
            try ins.bindText(2, simple);
            _ = try ins.step();
            _ = sqlite.c.sqlite3_reset(ins.raw);
            _ = sqlite.c.sqlite3_clear_bindings(ins.raw);
        }
    }
    try db.exec("CREATE INDEX entity_simple_name_idx ON entity_simple_name(name)");

    // Materialize the per-target file scope into a temp table. The path
    // scheme is asymmetric: the kernel walker is rooted at `--kernel-root
    // kernel` so kernel paths have NO `kernel/` prefix; non-kernel
    // `--extra-source-root` walks prefix paths with the tree's basename
    // (e.g. `routerOS/foo.zig`). So:
    //   * --target kernel       → exclude every known non-kernel prefix.
    //   * --target routerOS     → require the `routerOS/` prefix.
    //   * --target hyprvOS      → require the `hyprvOS/` prefix.
    //   * --target bootloader   → require the `bootloader/` prefix.
    // tests/ and redteam/ are excluded for every target (the alive-set
    // CTE pulls them in as references via the source-set seed below).
    try db.exec("CREATE TEMP TABLE target_files_tmp (id INTEGER PRIMARY KEY)");
    {
        const filter_sql: []const u8 = if (mem.eql(u8, target, "kernel"))
            "INSERT INTO target_files_tmp SELECT id FROM file" ++
                " WHERE path NOT GLOB '*/tests/*'" ++
                "   AND path NOT GLOB '*/redteam/*'" ++
                "   AND path NOT GLOB 'routerOS/*'" ++
                "   AND path NOT GLOB 'hyprvOS/*'" ++
                "   AND path NOT GLOB 'bootloader/*'" ++
                "   AND path NOT GLOB 'tools/*'" ++
                "   AND path NOT GLOB 'tests/*'"
        else if (mem.eql(u8, target, "routerOS"))
            "INSERT INTO target_files_tmp SELECT id FROM file" ++
                " WHERE path GLOB 'routerOS/*'" ++
                "   AND path NOT GLOB '*/tests/*'" ++
                "   AND path NOT GLOB '*/redteam/*'"
        else if (mem.eql(u8, target, "hyprvOS"))
            "INSERT INTO target_files_tmp SELECT id FROM file" ++
                " WHERE path GLOB 'hyprvOS/*'" ++
                "   AND path NOT GLOB '*/tests/*'" ++
                "   AND path NOT GLOB '*/redteam/*'"
        else if (mem.eql(u8, target, "bootloader"))
            "INSERT INTO target_files_tmp SELECT id FROM file" ++
                " WHERE path GLOB 'bootloader/*'" ++
                "   AND path NOT GLOB '*/tests/*'" ++
                "   AND path NOT GLOB '*/redteam/*'"
        else {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "unsupported --target: {s}\n", .{target}) catch "unsupported --target\n";
            _ = std.fs.File.stderr().write(msg) catch {};
            std.process.exit(2);
        };
        const sentinel = try a.dupeZ(u8, filter_sql);
        try db.exec(sentinel);
    }

    const sql =
        \\WITH RECURSIVE
        \\  target_files(id) AS (
        \\    SELECT id FROM target_files_tmp
        \\  ),
        \\  field_names(name) AS (
        \\    SELECT DISTINCT t2.text
        \\      FROM token t1
        \\      JOIN token t2 ON t2.file_id = t1.file_id AND t2.idx = t1.idx + 1
        \\     WHERE t1.kind = 'period' AND t2.kind = 'identifier'
        \\  ),
        \\  ident_mentions(text) AS (
        \\    SELECT DISTINCT text FROM token WHERE kind = 'identifier'
        \\  ),
        \\  alive(id) AS (
        \\      -- Seed: entry-point closure (kernel-only, IR-derived).
        \\      SELECT entity_id FROM entry_reaches
        \\    UNION
        \\      -- Seed: panic, main, every export fn, anything in tests/redteam.
        \\      SELECT e.id FROM entity e
        \\        LEFT JOIN file f ON f.id = e.def_file_id
        \\       WHERE e.kind = 'fn'
        \\         AND (e.qualified_name = 'panic'
        \\              OR e.qualified_name LIKE '%.panic'
        \\              OR e.qualified_name = 'main'
        \\              OR e.qualified_name LIKE '%.main')
        \\    UNION
        \\      -- Seed: anything defined in a tests/ or redteam/ file is alive.
        \\      SELECT e.id FROM entity e
        \\        JOIN file f ON f.id = e.def_file_id
        \\       WHERE f.path GLOB '*/tests/*' OR f.path GLOB '*/redteam/*'
        \\    UNION
        \\      -- Seed: any const whose definition contains `@import(` —
        \\      -- import aliases are always alive (the prior tool tracked
        \\      -- them as a distinct kind that was promoted to alive
        \\      -- whenever ANY use of the alias name resolved through it).
        \\      SELECT e.id FROM entity e
        \\        JOIN file f ON f.id = e.def_file_id
        \\       WHERE e.kind IN ('const','var')
        \\         AND INSTR(SUBSTR(f.source, e.def_byte_start + 1, e.def_byte_end - e.def_byte_start), '@import(') > 0
        \\    UNION
        \\      -- Seed: `export` decls (linker / asm consumers).
        \\      SELECT e.id FROM entity e
        \\        JOIN file f ON f.id = e.def_file_id
        \\       WHERE INSTR(SUBSTR(f.source, e.def_byte_start + 1, e.def_byte_end - e.def_byte_start), 'export ') > 0
        \\    UNION
        \\      -- Closure: alias targets. Forward-only — `pub const X = a.b.C;`
        \\      -- means using X also uses C, but using C doesn't pull in
        \\      -- every alias of C (the legacy tool only marks the chain
        \\      -- HEAD via an explicit `markLive` per use, not the inverse).
        \\      SELECT a.target_entity_id FROM const_alias a JOIN alive ON a.entity_id = alive.id
        \\    UNION
        \\      -- Closure: type references (struct field types, fn params, returns).
        \\      SELECT etr.referred_entity_id FROM entity_type_ref etr JOIN alive ON etr.referrer_entity_id = alive.id
        \\    UNION
        \\      -- Closure: ir_call edges out of any alive fn (catches
        \\      -- non-entry-rooted cross-target paths via direct calls).
        \\      SELECT c.callee_entity_id FROM ir_call c JOIN alive ON c.caller_entity_id = alive.id
        \\        WHERE c.callee_entity_id IS NOT NULL
        \\          AND c.call_kind IN ('direct','dispatch_x64','dispatch_aarch64')
        \\  ),
        \\  alive_named(id) AS (
        \\      SELECT id FROM alive
        \\    UNION
        \\      -- Field-name heuristic: `.<ident>` mention anywhere keeps
        \\      -- struct fields, variants, and methods alive.
        \\      SELECT esn.entity_id FROM entity_simple_name esn
        \\        JOIN entity e ON e.id = esn.entity_id
        \\        JOIN field_names fn ON fn.name = esn.name
        \\       WHERE e.kind IN ('field','variant','fn')
        \\    UNION
        \\      -- Bare-identifier mention heuristic for `pub` top-level
        \\      -- decls and types/fns/namespaces. The prior tool resolved
        \\      -- chains semantically per-file via @import edges; we
        \\      -- approximate with bare-name token presence anywhere
        \\      -- outside the def itself. Causes some false-negative
        \\      -- divergence vs legacy on routerOS/hyprvOS where two
        \\      -- different `pub fn foo` decls share the same simple
        \\      -- name (one in tree, one in tests/libz).
        \\      SELECT esn.entity_id FROM entity_simple_name esn
        \\        JOIN entity e ON e.id = esn.entity_id
        \\       WHERE (e.kind IN ('type','fn','namespace')
        \\              OR (e.kind IN ('const','var') AND e.is_pub = 1))
        \\         AND EXISTS (
        \\           SELECT 1 FROM token t
        \\            WHERE t.kind = 'identifier'
        \\              AND t.text = esn.name
        \\              AND (t.file_id <> e.def_file_id
        \\                   OR t.byte_start < e.def_byte_start
        \\                   OR t.byte_start >= e.def_byte_end)
        \\              -- Exclude tokens that fall inside ANY OTHER entity's
        \\              -- def span with the same simple name. Without this,
        \\              -- two trees that each define `pub const Foo` keep
        \\              -- each other's def-site token alive as a "use" —
        \\              -- a homonym false-negative the legacy tool didn't
        \\              -- have because it tracked decls per-file.
        \\              AND NOT EXISTS (
        \\                SELECT 1 FROM entity e2
        \\                  JOIN entity_simple_name esn2 ON esn2.entity_id = e2.id
        \\                 WHERE esn2.name = esn.name
        \\                   AND e2.def_file_id = t.file_id
        \\                   AND t.byte_start >= e2.def_byte_start
        \\                   AND t.byte_start < e2.def_byte_end
        \\              )
        \\         )
        \\    UNION
        \\      SELECT esn.entity_id FROM entity_simple_name esn
        \\        JOIN entity e ON e.id = esn.entity_id
        \\       WHERE e.kind IN ('const','var')
        \\         AND e.is_pub = 0
        \\         AND EXISTS (
        \\           SELECT 1 FROM token t
        \\            WHERE t.kind = 'identifier'
        \\              AND t.text = esn.name
        \\              AND t.file_id = e.def_file_id
        \\              AND (t.byte_start < e.def_byte_start
        \\                   OR t.byte_start >= e.def_byte_end)
        \\         )
        \\  )
        \\SELECT e.id, e.kind, e.qualified_name, e.def_line, e.def_byte_start, f.path,
        \\       e.def_byte_end, f.id
        \\FROM entity e
        \\JOIN file f ON f.id = e.def_file_id
        \\WHERE e.def_file_id IN target_files
        \\  AND e.id NOT IN alive_named
        \\ORDER BY f.path, e.def_byte_start
    ;

    var stmt = try db.prepare(sql, a);
    defer stmt.finalize();

    var findings: ArrayList(Finding) = .{};
    while (try stmt.step()) {
        const entity_id = stmt.columnInt(0);
        const kind = stmt.columnText(1) orelse continue;
        const qname = stmt.columnText(2) orelse continue;
        const line: u32 = @intCast(stmt.columnInt(3));
        const byte_start: u32 = @intCast(stmt.columnInt(4));
        const path = stmt.columnText(5) orelse continue;
        const byte_end: u32 = @intCast(stmt.columnInt(6));
        const file_id = stmt.columnInt(7);

        // Split qname into parent + name on the LAST '.' for fields, on the
        // last simple-segment for methods (kind=fn with parent qname).
        const last_dot = mem.lastIndexOfScalar(u8, qname, '.');
        const name = if (last_dot) |d| qname[d + 1 ..] else qname;
        const parent: ?[]const u8 = if (last_dot) |d| qname[0..d] else null;

        // Show parent on FIELD and VARIANT output (matches old tool).
        const show_parent = mem.eql(u8, kind, "field") or mem.eql(u8, kind, "variant");
        const display_parent: ?[]const u8 = if (show_parent and parent != null) blk: {
            // Old tool shows just the immediate container's name, not the
            // full qname. Strip everything before the final segment.
            const p = parent.?;
            if (mem.lastIndexOfScalar(u8, p, '.')) |i| break :blk p[i + 1 ..];
            break :blk p;
        } else null;

        try findings.append(a, .{
            .file_path = try a.dupe(u8, path),
            .name = try a.dupe(u8, name),
            .parent = if (display_parent) |p| try a.dupe(u8, p) else null,
            .line = line,
            .kind_label = kindLabel(kind),
            .byte_start = byte_start,
            .byte_end = byte_end,
            .entity_id = entity_id,
            .file_id = file_id,
        });
    }
    return findings.toOwnedSlice(a);
}

// -----------------------------------------------------------------
// Main
// -----------------------------------------------------------------

pub fn main() !void {
    g_arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer g_arena_state.deinit();
    g_arena = g_arena_state.allocator();

    var args_it = std.process.args();
    _ = args_it.next();

    var db_path: ?[]const u8 = null;
    var target_name: []const u8 = "kernel";
    var skip_override: ?[]const u8 = null;
    var update_arg: ?[]const u8 = null;

    while (args_it.next()) |a| {
        if (mem.eql(u8, a, "--db")) {
            const v = args_it.next() orelse {
                _ = std.fs.File.stderr().write("--db requires a path\n") catch {};
                std.process.exit(2);
            };
            db_path = try g_arena.dupe(u8, v);
        } else if (mem.eql(u8, a, "--target")) {
            const v = args_it.next() orelse {
                _ = std.fs.File.stderr().write("--target requires a name\n") catch {};
                std.process.exit(2);
            };
            target_name = try g_arena.dupe(u8, v);
        } else if (mem.eql(u8, a, "--skip")) {
            const v = args_it.next() orelse {
                _ = std.fs.File.stderr().write("--skip requires a path\n") catch {};
                std.process.exit(2);
            };
            skip_override = try g_arena.dupe(u8, v);
        } else if (mem.eql(u8, a, "--update-skip")) {
            const v = args_it.next() orelse {
                _ = std.fs.File.stderr().write("--update-skip requires <rel-path>:<start>-<end>\n") catch {};
                std.process.exit(2);
            };
            update_arg = try g_arena.dupe(u8, v);
        } else if (mem.eql(u8, a, "--help") or mem.eql(u8, a, "-h")) {
            const stdout = std.fs.File.stdout();
            _ = stdout.write(
                \\usage: dead_code_zig --db <path> [--target <name>] [--skip <path>] [--update-skip <rel>:<start>-<end>]
                \\
                \\Reads the per-(arch, commit_sha) callgraph DB and reports unused decls in the target dir.
                \\
            ) catch {};
            std.process.exit(0);
        } else {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "unknown flag: {s}\n", .{a}) catch "unknown flag\n";
            _ = std.fs.File.stderr().write(msg) catch {};
            std.process.exit(2);
        }
    }

    if (db_path == null) {
        _ = std.fs.File.stderr().write("--db is required\n") catch {};
        std.process.exit(2);
    }

    // Only `kernel` is supported. The non-kernel trees (routerOS,
    // hyprvOS, bootloader) compile separately, so the indexer doesn't
    // emit IR / entry_reaches data for them. Without per-tree IR the
    // alive-set falls back to bare-token heuristics that get tricked by
    // cross-tree homonyms (e.g. hyprvOS/libz/syscall.zig:acquireEcs
    // looks "alive" because the kernel's acquireEcs is referenced from
    // syscall/dispatch.zig). The verdict on those trees would be too
    // unreliable to gate on, so reject them outright.
    if (!std.mem.eql(u8, target_name, "kernel")) {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf,
            "unsupported --target: {s} (only `kernel` is supported — non-kernel trees lack per-tree IR/entry_reaches)\n",
            .{target_name},
        ) catch "unsupported --target\n";
        _ = std.fs.File.stderr().write(msg) catch {};
        std.process.exit(2);
    }

    g_target_rel = target_name;

    // Open DB.
    var db = sqlite.Db.openReadOnly(db_path.?, g_arena) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "failed to open DB: {s}\n", .{@errorName(err)}) catch "DB open error\n";
        _ = std.fs.File.stderr().write(msg) catch {};
        std.process.exit(2);
    };
    defer db.close();

    // Resolve skip file path.
    var cwd_buf: [4096]u8 = undefined;
    const cwd = try std.fs.cwd().realpath(".", &cwd_buf);
    const repo_root = try g_arena.dupe(u8, cwd);

    const skip_path = if (skip_override) |p|
        if (std.fs.path.isAbsolute(p)) try g_arena.dupe(u8, p) else try joinPath(g_arena, &.{ repo_root, p })
    else
        try defaultSkipPath(g_arena, repo_root, target_name);

    if (update_arg) |arg| {
        const rc = try updateSkipEntry(g_arena, arg, skip_path, &db);
        std.process.exit(rc);
    }

    try loadSkipFile(g_arena, skip_path, &db);

    // Scan summary stderr line (mirrors old tool's "Scanning N source files...").
    {
        const summary_sql = "SELECT COUNT(*), (SELECT COUNT(*) FROM file) FROM file WHERE path NOT GLOB '*/tests/*' AND path NOT GLOB '*/redteam/*'";
        var s = try db.prepare(summary_sql, g_arena);
        defer s.finalize();
        if (try s.step()) {
            const src_count = s.columnInt(0);
            const total_files = s.columnInt(1);
            var nbuf: [256]u8 = undefined;
            const summary = try std.fmt.bufPrint(&nbuf, "Scanning {d} source files in {s}/ (with {d} repo files for refs)...\n", .{ src_count, target_name, total_files });
            _ = std.fs.File.stderr().write(summary) catch {};
        }
    }

    const findings = try collectFindings(g_arena, &db, target_name);

    // Render: group by file, drop skip-covered, match old format.
    const stdout = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout.writer(&stdout_buf);
    const w = &stdout_writer.interface;

    var unused_total: u32 = 0;
    var current_file: []const u8 = "";
    var current_file_open = false;
    for (findings) |f| {
        if (skipCovers(f.file_path, f.line)) continue;
        // Display paths with the target prefix (matches the old tool's
        // repo-relative output format) when the DB stores target-rooted
        // paths. If the DB already has the prefix, don't double it.
        const display_path = blk: {
            if (g_target_rel.len == 0) break :blk f.file_path;
            if (mem.startsWith(u8, f.file_path, g_target_rel) and
                f.file_path.len > g_target_rel.len and
                f.file_path[g_target_rel.len] == '/')
                break :blk f.file_path;
            break :blk try joinPath(g_arena, &.{ g_target_rel, f.file_path });
        };
        if (!mem.eql(u8, current_file, display_path)) {
            if (current_file_open) try w.writeAll("\n");
            try w.print("=== {s} ===\n", .{display_path});
            current_file = display_path;
            current_file_open = true;
        }
        if (f.parent) |p| {
            try w.print("  UNUSED {s}: {s}.{s} (line {d})\n", .{ f.kind_label, p, f.name, f.line });
        } else {
            try w.print("  UNUSED {s}: {s} (line {d})\n", .{ f.kind_label, f.name, f.line });
        }
        unused_total += 1;
    }
    if (current_file_open) try w.writeAll("\n");

    if (unused_total == 0) {
        try w.writeAll("No unused code detected!\n");
    } else {
        try w.print("Total: {d} potentially unused items found.\n", .{unused_total});
        try w.writeAll("Review each item manually before removing \xE2\x80\x94 check for @field, @typeInfo, asm, and linker references.\n");
    }
    try w.flush();

    const skip_errors = try reportSkipDiagnostics();

    // Persist findings into lint_finding so downstream tooling (callgraph_http
    // /api/findings, callgraph_mcp callgraph_findings, CI dashboards) can
    // query them by SQL. We close the read-only handle and re-open R/W to
    // write the rows; SQLite WAL mode allows concurrent readers.
    db.close();
    writeFindingsToDb(g_arena, db_path.?, findings, target_name) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "warning: failed to write lint_finding rows: {s}\n", .{@errorName(err)}) catch "warning: lint_finding write failed\n";
        _ = std.fs.File.stderr().write(msg) catch {};
    };

    if (unused_total > 0 or skip_errors) std.process.exit(1);
}

fn writeFindingsToDb(
    a: Allocator,
    db_path: []const u8,
    findings: []const Finding,
    target: []const u8,
) !void {
    var rwdb = try sqlite.Db.openReadWrite(db_path, a);
    defer rwdb.close();

    try rwdb.exec("BEGIN IMMEDIATE");
    errdefer rwdb.exec("ROLLBACK") catch {};

    // Wipe prior dead_code findings for this target only — other targets'
    // rows are owned by separate analyzer runs and stay live.
    {
        var del = try rwdb.prepare(
            "DELETE FROM lint_finding WHERE analyzer = 'dead_code' AND extra_json LIKE ?",
            a,
        );
        defer del.finalize();
        const pat = try std.fmt.allocPrint(a, "%\"target\":\"{s}\"%", .{target});
        try del.bindText(1, pat);
        _ = try del.step();
    }

    var ins = try rwdb.prepare(
        \\INSERT INTO lint_finding
        \\  (analyzer, severity, rule, entity_id, file_id, byte_start, byte_end, line, message, extra_json)
        \\VALUES ('dead_code', 'warn', ?, ?, ?, ?, ?, ?, ?, ?)
    , a);
    defer ins.finalize();

    for (findings) |f| {
        if (skipCovers(f.file_path, f.line)) continue;

        const rule = if (mem.eql(u8, f.kind_label, "FIELD"))
            "unused_field"
        else if (mem.eql(u8, f.kind_label, "VARIANT"))
            "unused_variant"
        else
            "unused_pub";

        const message = if (f.parent) |p|
            try std.fmt.allocPrint(a, "UNUSED {s}: {s}.{s}", .{ f.kind_label, p, f.name })
        else
            try std.fmt.allocPrint(a, "UNUSED {s}: {s}", .{ f.kind_label, f.name });

        const extra = try std.fmt.allocPrint(a, "{{\"target\":\"{s}\"}}", .{target});

        _ = sqlite.c.sqlite3_reset(ins.raw);
        _ = sqlite.c.sqlite3_clear_bindings(ins.raw);
        try ins.bindText(1, rule);
        try ins.bindInt(2, f.entity_id);
        try ins.bindInt(3, f.file_id);
        try ins.bindInt(4, @intCast(f.byte_start));
        try ins.bindInt(5, @intCast(f.byte_end));
        try ins.bindInt(6, @intCast(f.line));
        try ins.bindText(7, message);
        try ins.bindText(8, extra);
        _ = try ins.step();
    }

    try rwdb.exec("COMMIT");
}

