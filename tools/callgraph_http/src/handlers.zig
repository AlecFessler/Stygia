//! HTTP handlers, all SQL-backed against a per-request DB connection
//! resolved through the shared registry. Endpoint shape mirrors
//! tools/callgraph/src/server.zig — request paths, query keys, response
//! content-type — so the existing web UI and MCP shim swap over with no
//! changes. Handler bodies are rewritten to query SQLite instead of
//! walking in-memory Function/Atom trees.

const std = @import("std");

const git = @import("git.zig");
const registry_mod = @import("registry.zig");
const sqlite = @import("sqlite.zig");
const trace_mod = @import("trace.zig");
const util = @import("util.zig");

const ArchEntry = registry_mod.ArchEntry;
const Registry = registry_mod.Registry;
const respondBytes = util.respondBytes;
const percentDecodeAlloc = util.percentDecodeAlloc;
const getQueryValue = util.getQueryValue;
const jsonStr = util.jsonStr;
const jsonEscape = util.jsonEscape;
const isTruthy = util.isTruthy;
const parseHexU64 = util.parseHexU64;

pub fn respondJson(request: *std.http.Server.Request, body: []const u8) !void {
    return respondBytes(request, .ok, "application/json; charset=utf-8", body);
}
pub fn respondText(request: *std.http.Server.Request, body: []const u8) !void {
    return respondBytes(request, .ok, "text/plain; charset=utf-8", body);
}
pub fn respondNotFound(request: *std.http.Server.Request, body: []const u8) !void {
    return respondBytes(request, .not_found, "text/plain; charset=utf-8", body);
}
pub fn respondBadRequest(request: *std.http.Server.Request, body: []const u8) !void {
    return respondBytes(request, .bad_request, "text/plain; charset=utf-8", body);
}

/// Resolve `(sha, arch)` from query into an open DB. Emits a 404 with a
/// friendly message and returns null on any miss so callers can early-out.
pub fn resolveArch(
    request: *std.http.Server.Request,
    registry: *Registry,
    sha_opt: ?[]const u8,
    arch_opt: ?[]const u8,
) !?*ArchEntry {
    const entry = registry.lookup(sha_opt, arch_opt) orelse {
        try respondNotFound(request, "no DB loaded for that (sha,arch); check /api/arches\n");
        return null;
    };
    return entry;
}

// ── /api/arches ───────────────────────────────────────────────────────────

pub fn handleArches(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const sha_param = getQueryValue(query, "sha") orelse "";
    const sha = if (sha_param.len == 0) registry.default_sha else sha_param;

    const commit = registry.lookupCommit(sha) orelse {
        return respondNotFound(request, "no commit DB matching sha\n");
    };

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"arches\":[");
    var first = true;
    var it = commit.arches.keyIterator();
    while (it.next()) |k| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        try jsonStr(&buf, allocator, k.*);
    }
    try buf.appendSlice(allocator, "],\"default\":");
    try jsonStr(&buf, allocator, commit.default_arch);
    try buf.append(allocator, '}');
    return respondJson(request, buf.items);
}

// ── /api/graph ─────────────────────────────────────────────────────────────
//
// The web UI expects a {functions: [...], entry_points: [...], definitions: [...]}
// payload matching tools/callgraph/src/types.zig::Graph. We assemble it
// per-request from the structural tables: entity (kind='fn') is each
// Function; entry_point joined to entity gives entry_points; entity
// (kind in struct/union/enum/const) gives definitions. Edges (callees)
// come from ir_call grouped by caller.
//
// This is the heaviest endpoint. A pre-materialized blob row is the
// future optimization; today, generate per request and let the kernel
// cache the SQLite pages.

pub fn handleGraph(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"functions\":[");

    // 1) functions: every entity with kind='fn'. We need entity columns
    //    + def_file path + entry kind (LEFT JOIN entry_point).
    {
        var stmt = try entry.db.prepare(
            \\SELECT e.id, e.qualified_name, file.path, e.def_line, e.def_col,
            \\       e.is_ast_only, ep.kind
            \\FROM entity e
            \\JOIN file ON file.id = e.def_file_id
            \\LEFT JOIN entry_point ep ON ep.entity_id = e.id
            \\WHERE e.kind = 'fn'
            \\ORDER BY e.id
        , a);
        defer stmt.finalize();

        var first = true;
        while (try stmt.step()) {
            if (!first) try buf.append(allocator, ',');
            first = false;
            const id: u32 = @intCast(stmt.columnInt(0));
            const qname = stmt.columnText(1) orelse "";
            const file = stmt.columnText(2) orelse "";
            const def_line: u32 = @intCast(stmt.columnInt(3));
            const def_col: u32 = @intCast(stmt.columnInt(4));
            const is_ast_only = stmt.columnInt(5) != 0;
            const entry_kind = stmt.columnText(6);

            try buf.writer(allocator).print("{{\"id\":{d},\"name\":", .{id});
            try jsonStr(&buf, allocator, qname);
            try buf.appendSlice(allocator, ",\"mangled\":");
            try jsonStr(&buf, allocator, qname);
            try buf.appendSlice(allocator, ",\"def_loc\":{\"file\":");
            try jsonStr(&buf, allocator, file);
            try buf.writer(allocator).print(",\"line\":{d},\"col\":{d}}}", .{ def_line, def_col });
            try buf.writer(allocator).print(",\"is_ast_only\":{s}", .{if (is_ast_only) "true" else "false"});
            try buf.writer(allocator).print(",\"is_entry\":{s}", .{if (entry_kind != null) "true" else "false"});
            if (entry_kind) |k| {
                try buf.appendSlice(allocator, ",\"entry_kind\":");
                try jsonStr(&buf, allocator, k);
            } else {
                try buf.appendSlice(allocator, ",\"entry_kind\":null");
            }

            // callees for this function — emit inline
            try buf.appendSlice(allocator, ",\"callees\":[");
            var ci = try entry.db.prepare(
                \\SELECT ic.callee_entity_id, e2.qualified_name, ic.call_kind, f.path, ic.site_line
                \\FROM ir_call ic
                \\LEFT JOIN entity e2 ON e2.id = ic.callee_entity_id
                \\LEFT JOIN ast_node an ON an.id = ic.ast_node_id
                \\LEFT JOIN file f ON f.id = an.file_id
                \\WHERE ic.caller_entity_id = ?
                \\ORDER BY ic.id
            , a);
            defer ci.finalize();
            try ci.bindInt(1, @intCast(id));
            var firstc = true;
            while (try ci.step()) {
                if (!firstc) try buf.append(allocator, ',');
                firstc = false;
                const cto_text = ci.columnText(0);
                const cto_id: ?i64 = if (cto_text == null) null else ci.columnInt(0);
                const cname = ci.columnText(1) orelse "";
                const ckind = ci.columnText(2) orelse "direct";
                const cfile = ci.columnText(3) orelse file;
                const cline: u32 = @intCast(ci.columnInt(4));
                try buf.appendSlice(allocator, "{\"to\":");
                if (cto_id) |t| try buf.writer(allocator).print("{d}", .{t}) else try buf.appendSlice(allocator, "null");
                try buf.appendSlice(allocator, ",\"target_name\":");
                try jsonStr(&buf, allocator, cname);
                try buf.appendSlice(allocator, ",\"kind\":");
                try jsonStr(&buf, allocator, ckind);
                try buf.appendSlice(allocator, ",\"site\":{\"file\":");
                try jsonStr(&buf, allocator, cfile);
                try buf.writer(allocator).print(",\"line\":{d},\"col\":0}}}}", .{cline});
            }
            try buf.appendSlice(allocator, "]");
            // intra is rendered server-side now; ship empty for the JSON
            // graph dump (the trace endpoint handles control-flow).
            try buf.appendSlice(allocator, ",\"intra\":[]}");
        }
    }

    try buf.appendSlice(allocator, "],\"entry_points\":[");
    {
        var stmt = try entry.db.prepare(
            \\SELECT entity_id, kind, label FROM entry_point ORDER BY kind, label
        , a);
        defer stmt.finalize();
        var first = true;
        while (try stmt.step()) {
            if (!first) try buf.append(allocator, ',');
            first = false;
            const fid: u32 = @intCast(stmt.columnInt(0));
            const k = stmt.columnText(1) orelse "manual";
            const label = stmt.columnText(2) orelse "";
            try buf.writer(allocator).print("{{\"fn_id\":{d},\"kind\":", .{fid});
            try jsonStr(&buf, allocator, k);
            try buf.appendSlice(allocator, ",\"label\":");
            try jsonStr(&buf, allocator, label);
            try buf.append(allocator, '}');
        }
    }
    try buf.appendSlice(allocator, "],\"definitions\":[");
    {
        var stmt = try entry.db.prepare(
            \\SELECT e.id, e.qualified_name, e.kind, file.path,
            \\       e.def_line, e.def_line
            \\FROM entity e
            \\JOIN file ON file.id = e.def_file_id
            \\WHERE e.kind IN ('type','const','var','namespace')
            \\ORDER BY e.id
        , a);
        defer stmt.finalize();
        var first = true;
        while (try stmt.step()) {
            if (!first) try buf.append(allocator, ',');
            first = false;
            const id: u32 = @intCast(stmt.columnInt(0));
            const qname = stmt.columnText(1) orelse "";
            const kind = stmt.columnText(2) orelse "constant";
            const file = stmt.columnText(3) orelse "";
            const ls: u32 = @intCast(stmt.columnInt(4));
            const le: u32 = @intCast(stmt.columnInt(5));
            const tail = std.mem.lastIndexOfScalar(u8, qname, '.');
            const short = if (tail) |t| qname[t + 1 ..] else qname;
            try buf.writer(allocator).print("{{\"id\":{d},\"name\":", .{id});
            try jsonStr(&buf, allocator, short);
            try buf.appendSlice(allocator, ",\"qualified_name\":");
            try jsonStr(&buf, allocator, qname);
            try buf.appendSlice(allocator, ",\"file\":");
            try jsonStr(&buf, allocator, file);
            try buf.writer(allocator).print(",\"line_start\":{d},\"line_end\":{d},\"kind\":", .{ ls, le });
            // Map schema entity-kind → DefKind tag.
            const def_kind: []const u8 = if (std.mem.eql(u8, kind, "type"))
                "struct_"
            else if (std.mem.eql(u8, kind, "const"))
                "constant"
            else if (std.mem.eql(u8, kind, "var"))
                "global_var"
            else
                "constant";
            try jsonStr(&buf, allocator, def_kind);
            try buf.appendSlice(allocator, ",\"is_pub\":true}");
        }
    }
    try buf.appendSlice(allocator, "]}");
    return respondJson(request, buf.items);
}

// ── /api/source ───────────────────────────────────────────────────────────
// Pull file source from the `file` table directly. The schema stores the
// full file inline so we slice by line.

pub fn handleSource(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const path_raw = getQueryValue(query, "path") orelse return respondBadRequest(request, "missing ?path=\n");
    const start_raw = getQueryValue(query, "start") orelse return respondBadRequest(request, "missing ?start=\n");
    const end_raw = getQueryValue(query, "end") orelse return respondBadRequest(request, "missing ?end=\n");
    const start = std.fmt.parseInt(u32, start_raw, 10) catch return respondBadRequest(request, "bad ?start=\n");
    const end = std.fmt.parseInt(u32, end_raw, 10) catch return respondBadRequest(request, "bad ?end=\n");
    if (end < start) return respondBadRequest(request, "end < start\n");

    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    const path = try percentDecodeAlloc(allocator, path_raw);
    defer allocator.free(path);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var stmt = try entry.db.prepare(
        \\SELECT id, source FROM file WHERE path = ?
    , a);
    defer stmt.finalize();
    try stmt.bindText(1, path);
    if (!try stmt.step()) return respondNotFound(request, "source file not found in DB\n");
    const file_id: i64 = stmt.columnInt(0);
    const source = stmt.columnText(1) orelse "";

    // Find byte range for [start, end] inclusive. line_starts in O(n).
    const range = computeLineRange(source, start, end);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"lines\":[");
    {
        var line_start: usize = range.begin;
        var first = true;
        var i: usize = range.begin;
        while (i < range.end) : (i += 1) {
            if (source[i] == '\n') {
                var line_end = i;
                if (line_end > line_start and source[line_end - 1] == '\r') line_end -= 1;
                if (!first) try buf.append(allocator, ',');
                first = false;
                try jsonStr(&buf, allocator, source[line_start..line_end]);
                line_start = i + 1;
            }
        }
        if (line_start < range.end) {
            var tail_end = range.end;
            if (tail_end > line_start and source[tail_end - 1] == '\r') tail_end -= 1;
            if (!first) try buf.append(allocator, ',');
            try jsonStr(&buf, allocator, source[line_start..tail_end]);
        }
    }
    try buf.appendSlice(allocator, "],\"tokens\":[");

    // Tokens, scoped to this file & byte range.
    var tstmt = try entry.db.prepare(
        \\SELECT byte_start, byte_len, kind FROM token
        \\WHERE file_id = ? AND byte_start >= ? AND byte_start < ?
        \\ORDER BY idx
    , a);
    defer tstmt.finalize();
    try tstmt.bindInt(1, file_id);
    try tstmt.bindInt(2, @intCast(range.begin));
    try tstmt.bindInt(3, @intCast(range.end));
    var first = true;
    while (try tstmt.step()) {
        const bs: usize = @intCast(tstmt.columnInt(0));
        const bl: usize = @intCast(tstmt.columnInt(1));
        const kind = tstmt.columnText(2) orelse "identifier";
        const lc = byteToLineCol(source, bs);
        if (!first) try buf.append(allocator, ',');
        first = false;
        try buf.writer(allocator).print(
            "{{\"line\":{d},\"col\":{d},\"len\":{d},\"kind\":",
            .{ lc.line, lc.col, bl },
        );
        try jsonStr(&buf, allocator, kind);
        try buf.append(allocator, '}');
    }
    try buf.appendSlice(allocator, "]}");
    return respondJson(request, buf.items);
}

const RangeBounds = struct { begin: usize, end: usize };
fn computeLineRange(contents: []const u8, start: u32, end: u32) RangeBounds {
    if (start == 0) return .{ .begin = 0, .end = 0 };
    var line: u32 = 1;
    var i: usize = 0;
    var range_begin: ?usize = null;
    var range_end: usize = contents.len;
    while (i <= contents.len) {
        if (line == start and range_begin == null) range_begin = i;
        if (line == end + 1) {
            range_end = i;
            break;
        }
        if (i == contents.len) break;
        if (contents[i] == '\n') line += 1;
        i += 1;
    }
    if (range_begin) |begin| return .{ .begin = begin, .end = range_end };
    return .{ .begin = 0, .end = 0 };
}

const LineCol = struct { line: u32, col: u32 };
fn byteToLineCol(contents: []const u8, byte: usize) LineCol {
    var line: u32 = 1;
    var line_start: usize = 0;
    var i: usize = 0;
    while (i < byte and i < contents.len) : (i += 1) {
        if (contents[i] == '\n') {
            line += 1;
            line_start = i + 1;
        }
    }
    return .{ .line = line, .col = @intCast(byte - line_start + 1) };
}

// ── /api/find ─────────────────────────────────────────────────────────────
// FTS5 over qualified names + entry-reach annotation.

pub fn handleFind(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const q_raw = getQueryValue(query, "q") orelse getQueryValue(query, "query") orelse
        return respondBadRequest(request, "missing ?q=<substr>\n");
    const limit_raw = getQueryValue(query, "limit") orelse "200";
    var limit: u32 = std.fmt.parseInt(u32, limit_raw, 10) catch 200;
    if (limit == 0) limit = 200;
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    const needle = try percentDecodeAlloc(allocator, q_raw);
    defer allocator.free(needle);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // FTS5 takes a MATCH expression; we feed a prefix-glob form. For
    // bare substrings without spaces this works; richer patterns
    // pass through. Fall back to plain LIKE on prepare failure.
    var found = std.ArrayList(u8){};
    defer found.deinit(allocator);

    var matches: u32 = 0;

    // Try LIKE — FTS5 needs token-shaped patterns the user may not
    // provide; LIKE is forgiving and the dataset is small enough that
    // the perf delta is negligible until the indexer ships large
    // graphs. (A future pass switches to FTS5 with MATCH '<word>*'.)
    var stmt = try entry.db.prepare(
        \\SELECT e.id, e.qualified_name, file.path, e.def_line, e.is_ast_only,
        \\       ep.kind,
        \\       (SELECT COUNT(*) FROM entry_reaches er WHERE er.entity_id = e.id) AS reach_count
        \\FROM entity e
        \\JOIN file ON file.id = e.def_file_id
        \\LEFT JOIN entry_point ep ON ep.entity_id = e.id
        \\WHERE e.qualified_name LIKE ?
        \\ORDER BY e.qualified_name
        \\LIMIT ?
    , a);
    defer stmt.finalize();
    const like_pat = try std.fmt.allocPrint(a, "%{s}%", .{needle});
    try stmt.bindText(1, like_pat);
    try stmt.bindInt(2, @intCast(limit));

    while (try stmt.step()) {
        const qname = stmt.columnText(1) orelse "";
        const path = stmt.columnText(2) orelse "";
        const line: u32 = @intCast(stmt.columnInt(3));
        const is_ast_only = stmt.columnInt(4) != 0;
        const ek = stmt.columnText(5);
        const reach: u32 = @intCast(stmt.columnInt(6));

        try found.writer(allocator).print("{s}", .{qname});
        // Pad to align on column 64
        const padding: usize = if (qname.len < 64) 64 - qname.len else 2;
        var p: usize = 0;
        while (p < padding) : (p += 1) try found.append(allocator, ' ');
        if (ek) |k| try found.writer(allocator).print("({s})  ", .{k});
        if (reach > 0) try found.writer(allocator).print("(reached by {d})  ", .{reach});
        try found.writer(allocator).print("{s}:{d}", .{ shortFile(path), line });
        if (is_ast_only) try found.appendSlice(allocator, "  inlined");
        try found.append(allocator, '\n');
        matches += 1;
    }
    if (matches == 0) try found.appendSlice(allocator, "(no matches)\n");
    return respondText(request, found.items);
}

fn shortFile(p: []const u8) []const u8 {
    if (std.mem.indexOf(u8, p, "/kernel/")) |i| return p[i + 1 ..];
    return p;
}

// ── /api/loc ──────────────────────────────────────────────────────────────

pub fn handleLoc(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const name_raw = getQueryValue(query, "name") orelse getQueryValue(query, "fn") orelse
        return respondBadRequest(request, "missing ?name=<fn>\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var stmt = try entry.db.prepare(
        \\SELECT e.qualified_name, file.path, e.def_line, e.def_col,
        \\       e.is_ast_only, ep.kind
        \\FROM entity e
        \\JOIN file ON file.id = e.def_file_id
        \\LEFT JOIN entry_point ep ON ep.entity_id = e.id
        \\WHERE e.qualified_name = ?
        \\LIMIT 1
    , a);
    defer stmt.finalize();
    try stmt.bindText(1, name);
    if (!try stmt.step()) return respondNotFound(request, "function not found\n");

    const qname = stmt.columnText(0) orelse name;
    const file = stmt.columnText(1) orelse "";
    const line: u32 = @intCast(stmt.columnInt(2));
    const is_ast_only = stmt.columnInt(4) != 0;
    const ek = stmt.columnText(5);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.writer(allocator).print("{s}  {s}:{d}", .{ qname, shortFile(file), line });
    if (ek) |k| try buf.writer(allocator).print("  ({s})", .{k});
    if (is_ast_only) try buf.appendSlice(allocator, "  inlined");
    try buf.append(allocator, '\n');
    return respondText(request, buf.items);
}

// ── /api/fn_source ────────────────────────────────────────────────────────

pub fn handleFnSource(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const name_raw = getQueryValue(query, "name") orelse getQueryValue(query, "fn") orelse
        return respondBadRequest(request, "missing ?name=<fn>\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var stmt = try entry.db.prepare(
        \\SELECT file.path, file.source, e.def_byte_start, e.def_byte_end, e.def_line
        \\FROM entity e JOIN file ON file.id = e.def_file_id
        \\WHERE e.qualified_name = ? AND e.kind = 'fn'
        \\LIMIT 1
    , a);
    defer stmt.finalize();
    try stmt.bindText(1, name);
    if (!try stmt.step()) return respondNotFound(request, "function not found\n");

    const path = stmt.columnText(0) orelse "";
    const source = stmt.columnText(1) orelse "";
    const bs: usize = @intCast(stmt.columnInt(2));
    const be: usize = @intCast(stmt.columnInt(3));
    const line: u32 = @intCast(stmt.columnInt(4));

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.writer(allocator).print("--- {s}:{d}\n", .{ path, line });
    if (bs <= be and be <= source.len) try buf.appendSlice(allocator, source[bs..be]);
    if (buf.items.len == 0 or buf.items[buf.items.len - 1] != '\n') try buf.append(allocator, '\n');
    try buf.appendSlice(allocator, "---\n");
    return respondText(request, buf.items);
}

// ── /api/callers ──────────────────────────────────────────────────────────

pub fn handleCallers(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const name_raw = getQueryValue(query, "name") orelse getQueryValue(query, "fn") orelse
        return respondBadRequest(request, "missing ?name=<fn>\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Aggregate across generic-monomorphization siblings: pick every
    // entity sharing this qualified_name OR whose generic_parent
    // resolves up the chain to one of those entities. Two-step join:
    // first the canonical id set, then the ir_call lookup.
    var stmt = try entry.db.prepare(
        \\SELECT e_caller.qualified_name, file.path, ic.site_line, ic.call_kind
        \\FROM ir_call ic
        \\JOIN entity e_callee ON e_callee.id = ic.callee_entity_id
        \\JOIN entity e_caller ON e_caller.id = ic.caller_entity_id
        \\JOIN file ON file.id = e_caller.def_file_id
        \\WHERE e_callee.qualified_name = ?
        \\   OR e_callee.generic_parent_id IN (
        \\       SELECT id FROM entity WHERE qualified_name = ?
        \\   )
        \\ORDER BY e_caller.qualified_name, ic.site_line
    , a);
    defer stmt.finalize();
    try stmt.bindText(1, name);
    try stmt.bindText(2, name);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    var n: u32 = 0;
    var prev: []const u8 = "";
    while (try stmt.step()) {
        const caller = stmt.columnText(0) orelse "";
        const file = stmt.columnText(1) orelse "";
        const site_line: u32 = @intCast(stmt.columnInt(2));
        const ckind = stmt.columnText(3) orelse "direct";

        const display: []const u8 = if (std.mem.eql(u8, caller, prev)) "  ↳" else caller;
        try buf.writer(allocator).print("  {s}", .{display});
        // pad to col 64
        const used: usize = 2 + display.len;
        const pad: usize = if (used < 64) 64 - used else 2;
        var p: usize = 0;
        while (p < pad) : (p += 1) try buf.append(allocator, ' ');
        try buf.writer(allocator).print("({s})  @ {s}:{d}\n", .{ ckind, shortFile(file), site_line });
        n += 1;
        prev = caller;
    }
    if (n == 0) {
        try buf.appendSlice(allocator, "(no callers found in graph — may be unreachable, indirect-only, or an entry point)\n");
    } else {
        var head = std.ArrayList(u8){};
        defer head.deinit(allocator);
        try head.writer(allocator).print("{d} call sites for {s}:\n", .{ n, name });
        try head.appendSlice(allocator, buf.items);
        return respondText(request, head.items);
    }
    return respondText(request, buf.items);
}

// ── /api/entries ──────────────────────────────────────────────────────────

pub fn handleEntries(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const kind_raw = getQueryValue(query, "kind") orelse getQueryValue(query, "kinds") orelse "";

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kind_decoded = try percentDecodeAlloc(a, kind_raw);

    // Build the optional kind filter clause.
    const sql_base =
        \\SELECT ep.kind, ep.label, ep.vector, e.qualified_name, file.path, e.def_line
        \\FROM entry_point ep
        \\JOIN entity e ON e.id = ep.entity_id
        \\JOIN file ON file.id = e.def_file_id
    ;
    const order_by = " ORDER BY ep.kind, ep.label";

    var stmt = if (kind_decoded.len == 0) blk: {
        const full = try std.fmt.allocPrint(a, "{s}{s}", .{ sql_base, order_by });
        break :blk try entry.db.prepare(full, a);
    } else blk: {
        // Build a `WHERE ep.kind IN (?,?,...)` clause. We allow a small
        // hand-set of kinds (< 8 in practice), so we can splice text and
        // bind text params without going through more tooling.
        var qs = std.ArrayList(u8){};
        defer qs.deinit(a);
        try qs.appendSlice(a, sql_base);
        try qs.appendSlice(a, " WHERE ep.kind IN (");
        var it = std.mem.splitScalar(u8, kind_decoded, ',');
        var idx: u32 = 0;
        while (it.next()) |raw| {
            const k = std.mem.trim(u8, raw, " \t");
            if (k.len == 0) continue;
            if (idx > 0) try qs.append(a, ',');
            try qs.append(a, '?');
            idx += 1;
        }
        try qs.appendSlice(a, ")");
        try qs.appendSlice(a, order_by);
        var s = try entry.db.prepare(qs.items, a);
        // Re-iterate for binding.
        var it2 = std.mem.splitScalar(u8, kind_decoded, ',');
        var bidx: c_int = 1;
        while (it2.next()) |raw| {
            const k = std.mem.trim(u8, raw, " \t");
            if (k.len == 0) continue;
            try s.bindText(bidx, k);
            bidx += 1;
        }
        break :blk s;
    };
    defer stmt.finalize();

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    var prev_kind: []const u8 = "";
    while (try stmt.step()) {
        // dupe `k` before stash; SQLite reuses the column buffer each step,
        // so the next iteration's `eql(prev_kind, k)` would otherwise read
        // either freed memory or the new row's bytes.
        const k = try a.dupe(u8, stmt.columnText(0) orelse "manual");
        const label = stmt.columnText(1) orelse "";
        const qname = stmt.columnText(3) orelse "";
        const path = stmt.columnText(4) orelse "";
        const line: u32 = @intCast(stmt.columnInt(5));

        if (prev_kind.len > 0 and !std.mem.eql(u8, prev_kind, k)) try buf.append(allocator, '\n');
        prev_kind = k;
        try buf.writer(allocator).print("{s} -> {s}", .{ label, qname });
        const used = label.len + 4 + qname.len;
        const pad: usize = if (used < 64) 64 - used else 2;
        var p: usize = 0;
        while (p < pad) : (p += 1) try buf.append(allocator, ' ');
        try buf.writer(allocator).print("({s})  {s}:{d}\n", .{ k, shortFile(path), line });
    }
    return respondText(request, buf.items);
}

// ── /api/reaches ──────────────────────────────────────────────────────────

pub fn handleReaches(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const from_raw = getQueryValue(query, "from") orelse return respondBadRequest(request, "missing ?from=\n");
    const to_raw = getQueryValue(query, "to") orelse return respondBadRequest(request, "missing ?to=\n");
    const max_raw = getQueryValue(query, "max") orelse "24";
    const max_hops: u32 = std.fmt.parseInt(u32, max_raw, 10) catch 24;
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    const from = try percentDecodeAlloc(allocator, from_raw);
    defer allocator.free(from);
    const to = try percentDecodeAlloc(allocator, to_raw);
    defer allocator.free(to);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Recursive CTE walking ir_call edges filtered to direct/dispatch.
    // Track the path by accumulating ids in a string. Stop at max_hops.
    const sql =
        \\WITH RECURSIVE
        \\  src(id, qname) AS (SELECT id, qualified_name FROM entity WHERE qualified_name = ?1),
        \\  dst(id, qname) AS (SELECT id, qualified_name FROM entity WHERE qualified_name = ?2),
        \\  walk(cur, depth, path) AS (
        \\    SELECT id, 0, CAST(id AS TEXT) FROM src
        \\    UNION ALL
        \\    SELECT ic.callee_entity_id, walk.depth + 1,
        \\           walk.path || ',' || CAST(ic.callee_entity_id AS TEXT)
        \\    FROM walk
        \\    JOIN ir_call ic ON ic.caller_entity_id = walk.cur
        \\    WHERE ic.call_kind IN ('direct','dispatch_x64','dispatch_aarch64')
        \\      AND ic.callee_entity_id IS NOT NULL
        \\      AND walk.depth < ?3
        \\      AND instr(',' || walk.path || ',', ',' || CAST(ic.callee_entity_id AS TEXT) || ',') = 0
        \\  )
        \\  SELECT walk.depth, walk.path
        \\  FROM walk JOIN dst ON dst.id = walk.cur
        \\  ORDER BY walk.depth ASC LIMIT 1
    ;
    var stmt = try entry.db.prepare(sql, a);
    defer stmt.finalize();
    try stmt.bindText(1, from);
    try stmt.bindText(2, to);
    try stmt.bindInt(3, @intCast(max_hops));

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);

    if (!try stmt.step()) {
        try buf.writer(allocator).print(
            "no path from {s} to {s} within {d} hops (search exhausted or depth-limited)\n",
            .{ from, to, max_hops },
        );
        return respondText(request, buf.items);
    }
    const depth: u32 = @intCast(stmt.columnInt(0));
    const path_csv = stmt.columnText(1) orelse "";

    try buf.writer(allocator).print("path ({d} hops):\n", .{depth});

    // path_csv is "id,id,id,..." — resolve each to qname.
    var idx: u32 = 0;
    var iter = std.mem.splitScalar(u8, path_csv, ',');
    while (iter.next()) |id_str| {
        const id = std.fmt.parseInt(i64, id_str, 10) catch continue;
        var qstmt = try entry.db.prepare("SELECT qualified_name FROM entity WHERE id = ?", a);
        defer qstmt.finalize();
        try qstmt.bindInt(1, id);
        if (try qstmt.step()) {
            const qn = qstmt.columnText(0) orelse "";
            try buf.writer(allocator).print("{d} {s}\n", .{ idx, qn });
        }
        idx += 1;
    }
    return respondText(request, buf.items);
}

// ── /api/modules ──────────────────────────────────────────────────────────

pub fn handleModules(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const min_edges_raw = getQueryValue(query, "min_edges") orelse "1";
    const min_edges: u32 = @max(@as(u32, 1), std.fmt.parseInt(u32, min_edges_raw, 10) catch 1);
    const direction = getQueryValue(query, "direction") orelse "out";

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Aggregate ir_call → (src_module, dst_module, count) using
    // module.qualified_name on both ends.
    var stmt = try entry.db.prepare(
        \\SELECT m_src.qualified_name, m_dst.qualified_name, COUNT(*)
        \\FROM ir_call ic
        \\JOIN entity e_caller ON e_caller.id = ic.caller_entity_id
        \\JOIN entity e_callee ON e_callee.id = ic.callee_entity_id
        \\JOIN module m_src ON m_src.id = e_caller.module_id
        \\JOIN module m_dst ON m_dst.id = e_callee.module_id
        \\WHERE m_src.id != m_dst.id
        \\GROUP BY m_src.qualified_name, m_dst.qualified_name
        \\HAVING COUNT(*) >= ?
        \\ORDER BY m_src.qualified_name, m_dst.qualified_name
    , a);
    defer stmt.finalize();
    try stmt.bindInt(1, @intCast(min_edges));

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.writer(allocator).print("module graph (direction={s}; min_edges={d}):\n\n", .{ direction, min_edges });
    var prev_src: []const u8 = "";
    while (try stmt.step()) {
        // dupe `src` before stash; SQLite's column buffer is reused on the
        // next step(), so the next iteration's eql(prev_src, src) would be
        // reading freed/overwritten memory.
        const src = try a.dupe(u8, stmt.columnText(0) orelse "");
        const dst = stmt.columnText(1) orelse "";
        const count: u32 = @intCast(stmt.columnInt(2));
        if (!std.mem.eql(u8, src, prev_src)) {
            if (prev_src.len > 0) try buf.append(allocator, '\n');
            try buf.writer(allocator).print("{s}\n", .{src});
            prev_src = src;
        }
        try buf.writer(allocator).print("  -> {s} ({d})\n", .{ dst, count });
    }
    return respondText(request, buf.items);
}

// ── /api/type ─────────────────────────────────────────────────────────────

pub fn handleType(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const name_raw = getQueryValue(query, "name") orelse return respondBadRequest(request, "missing ?name=\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Walk const_alias chain via CTE. We resolve `name` to an entity id,
    // then follow `const_alias` until we land on a non-const target or
    // hit a 4-hop cap.
    const sql =
        \\WITH RECURSIVE
        \\  start(id, qname) AS (SELECT id, qualified_name FROM entity WHERE qualified_name = ?1 LIMIT 1),
        \\  chain(id, qname, depth) AS (
        \\    SELECT id, qname, 0 FROM start
        \\    UNION ALL
        \\    SELECT e.id, e.qualified_name, chain.depth + 1
        \\    FROM chain
        \\    JOIN const_alias ca ON ca.entity_id = chain.id
        \\    JOIN entity e ON e.id = ca.target_entity_id
        \\    WHERE chain.depth < 4
        \\  )
        \\  SELECT chain.id, chain.qname, e.kind, file.path, e.def_line, e.def_byte_start, e.def_byte_end,
        \\         file.source
        \\  FROM chain
        \\  JOIN entity e ON e.id = chain.id
        \\  JOIN file ON file.id = e.def_file_id
        \\  ORDER BY chain.depth ASC
    ;
    var stmt = try entry.db.prepare(sql, a);
    defer stmt.finalize();
    try stmt.bindText(1, name);

    var path_chain = std.ArrayList([]const u8){};
    defer path_chain.deinit(a);

    var final_kind: []const u8 = "";
    var final_qname: []const u8 = "";
    var final_path: []const u8 = "";
    var final_line: u32 = 0;
    var final_bs: usize = 0;
    var final_be: usize = 0;
    var final_source: []const u8 = "";
    var found = false;

    while (try stmt.step()) {
        // SQLite invalidates columnText pointers when step() advances or
        // returns done; dupe every string we want past the loop.
        const qname = try a.dupe(u8, stmt.columnText(1) orelse "");
        try path_chain.append(a, qname);
        final_qname = qname;
        final_kind = try a.dupe(u8, stmt.columnText(2) orelse "");
        final_path = try a.dupe(u8, stmt.columnText(3) orelse "");
        final_line = @intCast(stmt.columnInt(4));
        final_bs = @intCast(stmt.columnInt(5));
        final_be = @intCast(stmt.columnInt(6));
        final_source = try a.dupe(u8, stmt.columnText(7) orelse "");
        found = true;
        // const_alias only chains from `const`-kind entities; the moment
        // we see a non-const we have the underlying type and stop.
        if (!std.mem.eql(u8, final_kind, "const")) break;
    }
    if (!found) return respondNotFound(request, "type not found\n");

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    if (path_chain.items.len > 1) {
        try buf.appendSlice(allocator, "(followed alias: ");
        for (path_chain.items, 0..) |q, i| {
            if (i > 0) try buf.appendSlice(allocator, " → ");
            try buf.appendSlice(allocator, q);
        }
        try buf.appendSlice(allocator, ")\n");
    }
    try buf.writer(allocator).print(
        "{s} ({s}) — {s}:{d}\n---\n",
        .{ final_qname, final_kind, shortFile(final_path), final_line },
    );
    if (final_be <= final_source.len and final_bs <= final_be) {
        try buf.appendSlice(allocator, final_source[final_bs..final_be]);
    }
    if (buf.items.len == 0 or buf.items[buf.items.len - 1] != '\n') try buf.append(allocator, '\n');
    try buf.appendSlice(allocator, "---\n");
    return respondText(request, buf.items);
}

// ── /api/src_bin, /api/src_bin_at, /api/bin_addr2line ─────────────────────

pub fn handleSrcBin(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const name_raw = getQueryValue(query, "name") orelse getQueryValue(query, "fn") orelse
        return respondBadRequest(request, "missing ?name=\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Resolve symbol range first.
    var sstmt = try entry.db.prepare(
        \\SELECT bs.addr, bs.size FROM bin_symbol bs
        \\JOIN entity e ON e.id = bs.entity_id
        \\WHERE e.qualified_name = ?
        \\LIMIT 1
    , a);
    defer sstmt.finalize();
    try sstmt.bindText(1, name);
    if (!try sstmt.step()) return respondNotFound(request, "no symbol for that name\n");

    const addr_lo: u64 = @bitCast(sstmt.columnInt(0));
    const sym_size: u64 = @bitCast(sstmt.columnInt(1));
    const addr_hi: u64 = addr_lo + sym_size;

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.writer(allocator).print(
        "── {s} ── {s} (size {d} bytes, addr 0x{x})\n",
        .{ name, entry.arch, sym_size, addr_lo },
    );

    // Disasm with interleaved source-line markers via dwarf_line floor join.
    var istmt = try entry.db.prepare(
        \\SELECT bi.addr, bi.mnemonic, bi.operands,
        \\       file.path,
        \\       (SELECT dl.line FROM dwarf_line dl
        \\        WHERE bi.addr BETWEEN dl.addr_lo AND dl.addr_hi
        \\        ORDER BY dl.addr_lo DESC LIMIT 1) AS src_line,
        \\       (SELECT dl.file_id FROM dwarf_line dl
        \\        WHERE bi.addr BETWEEN dl.addr_lo AND dl.addr_hi
        \\        ORDER BY dl.addr_lo DESC LIMIT 1) AS src_file_id
        \\FROM bin_inst bi
        \\LEFT JOIN file ON file.id = NULL
        \\WHERE bi.addr >= ? AND bi.addr < ?
        \\ORDER BY bi.addr
    , a);
    defer istmt.finalize();
    try istmt.bindInt(1, @bitCast(addr_lo));
    try istmt.bindInt(2, @bitCast(addr_hi));

    var last_line: i64 = -1;
    while (try istmt.step()) {
        const addr: u64 = @bitCast(istmt.columnInt(0));
        const mnem = istmt.columnText(1) orelse "";
        const ops = istmt.columnText(2) orelse "";
        const src_line = istmt.columnInt(4);
        const src_file_id = istmt.columnInt(5);
        if (src_line != 0 and src_line != last_line) {
            // resolve file path
            var fstmt = try entry.db.prepare("SELECT path FROM file WHERE id = ?", a);
            defer fstmt.finalize();
            try fstmt.bindInt(1, src_file_id);
            const fp: []const u8 = if (try fstmt.step()) (fstmt.columnText(0) orelse "") else "";
            try buf.writer(allocator).print("  ; {s}:{d}\n", .{ shortFile(fp), src_line });
            last_line = src_line;
        }
        try buf.writer(allocator).print("  {x:0>16}: {s} {s}\n", .{ addr, mnem, ops });
    }
    return respondText(request, buf.items);
}

pub fn handleSrcBinAt(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const at_raw = getQueryValue(query, "at") orelse return respondBadRequest(request, "missing ?at=file:line\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const at = try percentDecodeAlloc(allocator, at_raw);
    defer allocator.free(at);

    const colon = std.mem.lastIndexOfScalar(u8, at, ':') orelse return respondBadRequest(request, "?at must be file:line\n");
    const file_part = at[0..colon];
    const line = std.fmt.parseInt(u32, at[colon + 1 ..], 10) catch return respondBadRequest(request, "line is not an integer\n");
    const basename = std.fs.path.basename(file_part);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Find dwarf_line ranges matching the basename + line.
    var dstmt = try entry.db.prepare(
        \\SELECT dl.addr_lo, dl.addr_hi, file.path
        \\FROM dwarf_line dl JOIN file ON file.id = dl.file_id
        \\WHERE dl.line = ? AND file.path LIKE ?
        \\ORDER BY dl.addr_lo
    , a);
    defer dstmt.finalize();
    try dstmt.bindInt(1, @intCast(line));
    const like_pat = try std.fmt.allocPrint(a, "%/{s}", .{basename});
    try dstmt.bindText(2, like_pat);

    var ranges = std.ArrayList(struct { lo: u64, hi: u64 }){};
    defer ranges.deinit(a);
    while (try dstmt.step()) {
        const lo: u64 = @bitCast(dstmt.columnInt(0));
        const hi: u64 = @bitCast(dstmt.columnInt(1));
        try ranges.append(a, .{ .lo = lo, .hi = hi });
    }

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    if (ranges.items.len == 0) {
        try buf.writer(allocator).print(
            "no instructions emitted for {s}:{d} in {s}\n",
            .{ file_part, line, entry.arch },
        );
        return respondText(request, buf.items);
    }

    try buf.writer(allocator).print(
        "── {s}:{d} → {d} range(s) in {s} ──\n",
        .{ file_part, line, ranges.items.len, entry.arch },
    );
    for (ranges.items) |r| {
        var istmt = try entry.db.prepare(
            \\SELECT addr, mnemonic, operands FROM bin_inst
            \\WHERE addr BETWEEN ? AND ? ORDER BY addr
        , a);
        defer istmt.finalize();
        try istmt.bindInt(1, @bitCast(r.lo));
        try istmt.bindInt(2, @bitCast(r.hi));
        while (try istmt.step()) {
            const addr: u64 = @bitCast(istmt.columnInt(0));
            const mnem = istmt.columnText(1) orelse "";
            const ops = istmt.columnText(2) orelse "";
            try buf.writer(allocator).print("  {x:0>16}: {s} {s}\n", .{ addr, mnem, ops });
        }
    }
    return respondText(request, buf.items);
}

pub fn handleBinAddr2Line(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const addr_raw = getQueryValue(query, "addr") orelse return respondBadRequest(request, "missing ?addr=<hex>\n");
    const addr = parseHexU64(addr_raw) orelse return respondBadRequest(request, "bad addr\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch_q = getQueryValue(query, "arch");
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);

    // Enumerate either the requested arch or every arch this commit has.
    const commit = registry.lookupCommit(sha) orelse {
        return respondNotFound(request, "no commit DB matching sha\n");
    };
    var matched: bool = false;
    var ait = commit.arches.valueIterator();
    while (ait.next()) |entry| {
        if (arch_q) |aq| {
            if (aq.len > 0 and !std.mem.eql(u8, aq, entry.arch)) continue;
        }
        var stmt = try entry.db.prepare(
            \\SELECT dl.line, file.path,
            \\       (SELECT bs.addr FROM bin_symbol bs
            \\        WHERE ? BETWEEN bs.addr AND bs.addr + bs.size - 1
            \\        LIMIT 1) AS sym_addr,
            \\       (SELECT e.qualified_name FROM bin_symbol bs
            \\        JOIN entity e ON e.id = bs.entity_id
            \\        WHERE ? BETWEEN bs.addr AND bs.addr + bs.size - 1
            \\        LIMIT 1) AS sym_name
            \\FROM dwarf_line dl JOIN file ON file.id = dl.file_id
            \\WHERE ? BETWEEN dl.addr_lo AND dl.addr_hi
            \\ORDER BY dl.addr_lo DESC LIMIT 1
        , a);
        defer stmt.finalize();
        try stmt.bindInt(1, @bitCast(addr));
        try stmt.bindInt(2, @bitCast(addr));
        try stmt.bindInt(3, @bitCast(addr));
        if (!try stmt.step()) continue;
        const line: u32 = @intCast(stmt.columnInt(0));
        const path = stmt.columnText(1) orelse "";
        const sym_addr_text = stmt.columnText(2);
        const sym_name = stmt.columnText(3);
        if (sym_addr_text != null and sym_name != null) {
            const sa: u64 = @bitCast(stmt.columnInt(2));
            try buf.writer(allocator).print(
                "{s}: {s}:{d}  in {s}+0x{x}\n",
                .{ entry.arch, shortFile(path), line, sym_name.?, addr - sa },
            );
        } else {
            try buf.writer(allocator).print("{s}: {s}:{d}\n", .{ entry.arch, shortFile(path), line });
        }
        matched = true;
    }
    if (!matched) try buf.writer(allocator).print("0x{x}: no DWARF entry in any loaded arch\n", .{addr});
    return respondText(request, buf.items);
}

// ── /api/bin_dataflow_reg ─────────────────────────────────────────────────
// Linear scan of bin_inst in fn range, emit lines whose operands mention
// the register. Heuristic: register-as-first-operand is dst, otherwise src.

pub fn handleBinDataflowReg(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const reg_raw = getQueryValue(query, "reg") orelse return respondBadRequest(request, "missing ?reg=\n");
    const name_raw = getQueryValue(query, "name");
    const stop_at_call_raw = getQueryValue(query, "stop_at_call") orelse "1";
    const stop_at_call = isTruthy(stop_at_call_raw);
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const reg = try percentDecodeAlloc(allocator, reg_raw);
    defer allocator.free(reg);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Resolve fn range.
    if (name_raw == null) return respondBadRequest(request, "missing ?name=<fn> (?from/?to not yet supported)\n");
    const name = try percentDecodeAlloc(allocator, name_raw.?);
    defer allocator.free(name);

    var sstmt = try entry.db.prepare(
        \\SELECT bs.addr, bs.size FROM bin_symbol bs
        \\JOIN entity e ON e.id = bs.entity_id
        \\WHERE e.qualified_name = ? LIMIT 1
    , a);
    defer sstmt.finalize();
    try sstmt.bindText(1, name);
    if (!try sstmt.step()) return respondNotFound(request, "symbol not found\n");
    const lo: u64 = @bitCast(sstmt.columnInt(0));
    const sz: u64 = @bitCast(sstmt.columnInt(1));
    const hi = lo + sz;

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.writer(allocator).print(
        "── reg `{s}` in {s} (0x{x}..0x{x}) ── (stop_at_call={s})\n",
        .{ reg, name, lo, hi, if (stop_at_call) "true" else "false" },
    );

    var istmt = try entry.db.prepare(
        \\SELECT addr, mnemonic, operands FROM bin_inst
        \\WHERE addr >= ? AND addr < ? ORDER BY addr
    , a);
    defer istmt.finalize();
    try istmt.bindInt(1, @bitCast(lo));
    try istmt.bindInt(2, @bitCast(hi));

    var hits: u32 = 0;
    while (try istmt.step()) {
        const addr: u64 = @bitCast(istmt.columnInt(0));
        const mnem = istmt.columnText(1) orelse "";
        const ops = istmt.columnText(2) orelse "";
        if (stop_at_call and isCallMnem(mnem)) {
            try buf.writer(allocator).print(
                "  {x:0>16}: {s} {s}\n  ; reached call boundary; reg may be clobbered (caller-saved)\n",
                .{ addr, mnem, ops },
            );
            break;
        }
        const role = registerRole(ops, reg) orelse continue;
        try buf.writer(allocator).print("  {x:0>16}: [{s}] {s} {s}\n", .{ addr, role, mnem, ops });
        hits += 1;
    }
    if (hits == 0) try buf.writer(allocator).print("\n  (no occurrences of `{s}`)\n", .{reg});
    return respondText(request, buf.items);
}

fn isCallMnem(s: []const u8) bool {
    const t = std.mem.trim(u8, s, " \t");
    return std.mem.eql(u8, t, "call");
}

/// Coarse register-role heuristic. First operand owning a bare register
/// token (no [ ]) is the dst; everything else is a src. Doesn't try to
/// alias-walk widths (rax/eax/ax/al) — the indexer's analyzer pass should
/// own that logic when it's ported over.
fn registerRole(operands: []const u8, reg: []const u8) ?[]const u8 {
    const comma = std.mem.indexOfScalar(u8, operands, ',') orelse {
        if (std.mem.indexOf(u8, operands, reg) != null) return "src";
        return null;
    };
    const first = std.mem.trim(u8, operands[0..comma], " \t");
    const rest = operands[comma + 1 ..];
    if (std.mem.indexOf(u8, first, reg) != null and std.mem.indexOfScalar(u8, first, '[') == null) return "dst";
    if (std.mem.indexOf(u8, rest, reg) != null) return "src";
    return null;
}

// ── /api/trace ────────────────────────────────────────────────────────────
// Delegates to trace.zig.

pub fn handleTrace(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const entry_raw = getQueryValue(query, "entry") orelse getQueryValue(query, "name") orelse getQueryValue(query, "fn") orelse
        return respondBadRequest(request, "missing ?entry=\n");
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;
    const depth_raw = getQueryValue(query, "depth") orelse "6";
    const depth: u32 = std.fmt.parseInt(u32, depth_raw, 10) catch 6;
    const fmt = getQueryValue(query, "format") orelse "text";

    const fn_name = try percentDecodeAlloc(allocator, entry_raw);
    defer allocator.free(fn_name);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    trace_mod.render(allocator, &entry.db, fn_name, depth, fmt, &buf) catch |err| switch (err) {
        error.NotFound => return respondNotFound(request, "function not found\n"),
        else => |e| return e,
    };
    return respondText(request, buf.items);
}

// ── /api/commits ──────────────────────────────────────────────────────────
// Output formats (text + JSON) match the legacy callgraph daemon byte for
// byte so any shell scripts the user wrote against /api/commits keep
// working when they switch to callgraph_http.

pub fn handleCommits(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    git_root: []const u8,
) !void {
    var limit: u32 = git.DEFAULT_LIMIT;
    var fmt: enum { json, text } = .json;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "limit")) {
            limit = std.fmt.parseInt(u32, val, 10) catch limit;
        } else if (std.mem.eql(u8, key, "format")) {
            if (std.mem.eql(u8, val, "text")) fmt = .text;
            if (std.mem.eql(u8, val, "json")) fmt = .json;
        }
    }
    if (limit == 0) limit = git.DEFAULT_LIMIT;
    if (limit > git.MAX_LIMIT) limit = git.MAX_LIMIT;

    const log_stdout = git.gitLog(allocator, git_root, limit) catch {
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git log failed\n");
    };
    defer allocator.free(log_stdout);

    var compat_set = git.buildEmitIrSet(allocator, git_root);
    defer git.freeShaSet(allocator, &compat_set);

    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);

    if (fmt == .text) {
        try git.renderCommitsText(allocator, &out, log_stdout, &compat_set);
        return respondText(request, out.items);
    }
    try git.renderCommitsJson(allocator, &out, log_stdout, &compat_set);
    return respondJson(request, out.items);
}

// ── /api/load_commit{,/status} ────────────────────────────────────────────
// In the new architecture the indexer runs offline and produces a
// `<arch>-<sha>.db` file per commit; the daemon is a read-only consumer.
// load_commit therefore CANNOT spawn a build — it just reports whether a
// matching DB already exists in --db-dir. Response shape is intentionally
// kept compatible with the legacy daemon (same JSON keys) so existing
// clients don't crash, but `status` is one of:
//   ready       — at least one <arch>-<sha>.db exists for this sha
//   not_loaded  — no DB for this sha is present
//   errored     — only on bad input
// The legacy `building` state is unreachable here.

pub fn handleLoadCommit(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    return loadCommitStatus(allocator, request, query, registry);
}

pub fn handleLoadCommitStatus(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    return loadCommitStatus(allocator, request, query, registry);
}

fn loadCommitStatus(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const sha = util.getQueryValue(query, "sha") orelse "";
    if (!git.isValidSha(sha)) return respondBadRequest(request, "missing or invalid ?sha=\n");

    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);

    const commit_opt = registry.lookupCommit(sha);
    const status: []const u8 = if (commit_opt != null) "ready" else "not_loaded";
    const short = sha[0..@min(sha.len, 12)];

    try out.appendSlice(allocator, "{\"sha\":");
    try jsonStr(&out, allocator, sha);
    try out.appendSlice(allocator, ",\"short\":");
    try jsonStr(&out, allocator, short);
    try out.appendSlice(allocator, ",\"status\":");
    try jsonStr(&out, allocator, status);
    try out.appendSlice(allocator, ",\"arches\":[");
    if (commit_opt) |commit| {
        var first = true;
        var ait = commit.arches.keyIterator();
        while (ait.next()) |k| {
            if (!first) try out.append(allocator, ',');
            first = false;
            try jsonStr(&out, allocator, k.*);
        }
    }
    try out.appendSlice(allocator, "],\"default_arch\":");
    if (commit_opt) |commit| {
        try jsonStr(&out, allocator, commit.default_arch);
    } else {
        try out.appendSlice(allocator, "\"\"");
    }
    try out.appendSlice(allocator, ",\"error\":null}");

    return respondJson(request, out.items);
}

// ── /api/diff{,_files,_hunks} ─────────────────────────────────────────────
// Simpler input shape than the legacy daemon (single ?sha=) because the
// new clients only ever ask "what changed in commit X". Output is raw
// `git show ...` for the text endpoints and a JSON `{files:[...]}` shape
// for /api/diff_files.

pub fn handleDiff(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    git_root: []const u8,
) !void {
    const sha = util.getQueryValue(query, "sha") orelse "";
    if (!git.isValidSha(sha)) return respondBadRequest(request, "missing or invalid ?sha=\n");

    const stdout = git.gitShowStat(allocator, git_root, sha) catch {
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git show failed\n");
    };
    defer allocator.free(stdout);
    return respondText(request, stdout);
}

pub fn handleDiffFiles(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    git_root: []const u8,
) !void {
    const sha = util.getQueryValue(query, "sha") orelse "";
    if (!git.isValidSha(sha)) return respondBadRequest(request, "missing or invalid ?sha=\n");

    const stdout = git.gitShowNames(allocator, git_root, sha) catch {
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git show --name-only failed\n");
    };
    defer allocator.free(stdout);

    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"files\":[");
    var first = true;
    var line_it = std.mem.splitScalar(u8, stdout, '\n');
    while (line_it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!first) try out.append(allocator, ',');
        first = false;
        try jsonStr(&out, allocator, line);
    }
    try out.appendSlice(allocator, "]}");
    return respondJson(request, out.items);
}

pub fn handleDiffHunks(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    git_root: []const u8,
) !void {
    const sha = util.getQueryValue(query, "sha") orelse "";
    const path_param = util.getQueryValue(query, "path") orelse "";
    if (!git.isValidSha(sha)) return respondBadRequest(request, "missing or invalid ?sha=\n");
    if (path_param.len == 0) return respondBadRequest(request, "missing ?path=\n");

    const decoded = try percentDecodeAlloc(allocator, path_param);
    defer allocator.free(decoded);

    const stdout = git.gitShowFileDiff(allocator, git_root, sha, decoded) catch {
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git show <sha> -- <path> failed\n");
    };
    defer allocator.free(stdout);
    return respondText(request, stdout);
}

// ── /api/findings ─────────────────────────────────────────────────────────
// Query the lint_finding table populated by the analyzer pass(es). Filter
// by analyzer / rule / severity / file (path GLOB) / limit. Results are
// "<analyzer>  <severity>  <rule>  <file>:<line>  <message>" one per line.
pub fn handleFindings(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    registry: *Registry,
) !void {
    const sha = getQueryValue(query, "sha") orelse "";
    const arch = getQueryValue(query, "arch") orelse "";
    const entry = (try resolveArch(request, registry, sha, arch)) orelse return;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const analyzer = getQueryValue(query, "analyzer") orelse "";
    const rule = getQueryValue(query, "rule") orelse "";
    const severity = getQueryValue(query, "severity") orelse "";
    const file_glob = getQueryValue(query, "file") orelse "";
    const limit_raw = getQueryValue(query, "limit") orelse "500";
    const limit = std.fmt.parseInt(u32, limit_raw, 10) catch 500;

    var stmt = try entry.db.prepare(
        \\SELECT lf.analyzer, lf.severity, lf.rule, f.path, lf.line, lf.message
        \\  FROM lint_finding lf
        \\  JOIN file f ON f.id = lf.file_id
        \\ WHERE (?1 = '' OR lf.analyzer = ?1)
        \\   AND (?2 = '' OR lf.rule = ?2)
        \\   AND (?3 = '' OR lf.severity = ?3)
        \\   AND (?4 = '' OR f.path GLOB ?4)
        \\ ORDER BY f.path, lf.line, lf.id
        \\ LIMIT ?5
    , a);
    defer stmt.finalize();
    try stmt.bindText(1, analyzer);
    try stmt.bindText(2, rule);
    try stmt.bindText(3, severity);
    try stmt.bindText(4, file_glob);
    try stmt.bindInt(5, @intCast(limit));

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    var matches: u32 = 0;
    while (try stmt.step()) {
        const an = stmt.columnText(0) orelse "";
        const sv = stmt.columnText(1) orelse "";
        const ru = stmt.columnText(2) orelse "";
        const fp = stmt.columnText(3) orelse "";
        const line: u32 = @intCast(stmt.columnInt(4));
        const msg = stmt.columnText(5) orelse "";
        try buf.writer(allocator).print(
            "{s}  [{s}]  {s}  {s}:{d}  {s}\n",
            .{ an, sv, ru, fp, line, msg },
        );
        matches += 1;
    }
    if (matches == 0) try buf.appendSlice(allocator, "(no findings — analyzers may not have populated lint_finding yet)\n");
    return respondText(request, buf.items);
}
