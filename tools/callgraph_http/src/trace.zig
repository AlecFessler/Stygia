//! Trace renderer for the SQL backend.
//!
//! Walks the call hierarchy rooted at one fn, emitting an indented tree
//! (text format) or the compact base-36 line format (compact format) the
//! existing /api/trace agent surface uses.
//!
//! ## Status: minimal SQL-backed port
//!
//! The ORIGINAL render.zig consumes pre-built `Atom` trees that capture
//! AST control-flow structure (if_else / switch / loop) for each fn body,
//! interleaved with call atoms. The schema stores the raw AST (ast_node +
//! ast_edge) but the indexer hasn't yet produced the simplified Atom-tree
//! materialization the renderer expects.
//!
//! For now we walk `ir_call` only — every line is a function call. The
//! fold-tag set (^@~&!%=?>*-) is preserved so the LLM-targeted UX stays
//! consistent; the `?` (branch) and `*` (loop) tags simply never appear
//! in this version. Once the indexer materializes Atom trees (either as
//! a structural layer in the DB or as a `blob(kind='atom_tree')` row per
//! fn), this file gets replaced with the verbatim port the spec calls for.
//!
//! Fold tags emitted:
//!   `^` depth cap, body has callees
//!   `@` fn with no callees in its body (typically AST-only inlines)
//!   `~` body shown elsewhere (recursion / sibling repeat)
//!   `%` debug.* call
//!   `=` std./builtin./compiler_rt. call
//!   `&` indirect (call_kind='indirect')
//!   `!` unresolved direct (callee_entity_id IS NULL, not indirect)

const std = @import("std");

const sqlite = @import("sqlite.zig");

pub const Error = error{NotFound} || std.mem.Allocator.Error || sqlite.Error;

pub fn render(
    gpa: std.mem.Allocator,
    db: *sqlite.Db,
    root_qname: []const u8,
    max_depth: u32,
    format: []const u8,
    out: *std.ArrayList(u8),
) Error!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Resolve root fn id.
    const root_id = (try resolveFnId(db, a, root_qname)) orelse return error.NotFound;

    var visited = std.AutoHashMap(i64, u32).init(a); // ancestor stack
    var rendered = std.AutoHashMap(i64, u32).init(a); // any-prior renders
    var stats: Stats = .{};

    // Pre-walk for stats (fns_visited, at_cap, top fanout).
    try statsWalk(db, a, root_id, 0, max_depth, &visited, &rendered, &stats);

    visited.clearRetainingCapacity();
    rendered.clearRetainingCapacity();

    if (std.mem.eql(u8, format, "compact")) {
        try out.writer(gpa).print("T fns={d} cap={d} d={d}", .{ stats.fns_visited, stats.at_cap, max_depth });
        if (stats.top_fanout > 0) try out.writer(gpa).print(" top={s}/{d}", .{ stats.top_name, stats.top_fanout });
        try out.appendSlice(gpa, "\n");
        try compactFn(gpa, db, a, root_id, root_qname, 0, max_depth, &visited, &rendered, out);
        return;
    }

    if (stats.top_fanout > 0) {
        try out.writer(gpa).print(
            "trace: {d} fns, {d} at depth cap (depth={d}), top fanout {s} ({d} calls)\n\n",
            .{ stats.fns_visited, stats.at_cap, max_depth, stats.top_name, stats.top_fanout },
        );
    } else {
        try out.writer(gpa).print(
            "trace: {d} fns, {d} at depth cap (depth={d})\n\n",
            .{ stats.fns_visited, stats.at_cap, max_depth },
        );
    }
    try renderFnText(gpa, db, a, root_id, root_qname, 0, max_depth, &visited, &rendered, out);
}

const Stats = struct {
    fns_visited: u32 = 0,
    at_cap: u32 = 0,
    top_name: []const u8 = "",
    top_fanout: u32 = 0,
};

fn statsWalk(
    db: *sqlite.Db,
    a: std.mem.Allocator,
    fn_id: i64,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(i64, u32),
    rendered: *std.AutoHashMap(i64, u32),
    stats: *Stats,
) Error!void {
    stats.fns_visited += 1;
    try rendered.put(fn_id, depth);

    const callees = try fetchCallees(db, a, fn_id);
    if (callees.len > stats.top_fanout) {
        stats.top_fanout = @intCast(callees.len);
        // Look up the qname for this fn for the header.
        const qn = (try qnameFor(db, a, fn_id)) orelse "";
        stats.top_name = qn;
    }
    for (callees) |c| {
        if (c.callee_id == null) continue;
        const cid = c.callee_id.?;
        if (visited.contains(cid)) continue;
        if (rendered.contains(cid)) continue;
        if (c.has_no_body) continue;
        if (depth + 1 >= max_depth) {
            stats.at_cap += 1;
            continue;
        }
        try visited.put(cid, depth);
        defer _ = visited.remove(cid);
        try statsWalk(db, a, cid, depth + 1, max_depth, visited, rendered, stats);
    }
}

fn renderFnText(
    gpa: std.mem.Allocator,
    db: *sqlite.Db,
    a: std.mem.Allocator,
    fn_id: i64,
    qname: []const u8,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(i64, u32),
    rendered: *std.AutoHashMap(i64, u32),
    out: *std.ArrayList(u8),
) Error!void {
    const indent = depth * 2;
    var i: usize = 0;
    while (i < indent) : (i += 1) try out.append(gpa, ' ');
    try out.appendSlice(gpa, qname);
    try out.append(gpa, '\n');
    try rendered.put(fn_id, depth);

    const callees = try fetchCallees(db, a, fn_id);
    if (callees.len == 0) {
        var k: usize = 0;
        while (k < indent + 2) : (k += 1) try out.append(gpa, ' ');
        try out.appendSlice(gpa, "(no calls)\n");
        return;
    }

    var prev_block: i64 = -1;
    for (callees) |c| {
        if (c.ast_node_id) |aid| {
            var marker_buf = std.ArrayList(u8){};
            var owning_block: i64 = -1;
            try collectControlMarkers(db, a, aid, &marker_buf, &owning_block);
            if (owning_block != prev_block and marker_buf.items.len > 0) {
                var pad: usize = 0;
                while (pad < indent + 2) : (pad += 1) try out.append(gpa, ' ');
                try out.appendSlice(gpa, marker_buf.items);
                try out.append(gpa, '\n');
                prev_block = owning_block;
            }
        }
        try renderCallText(gpa, db, a, c, depth + 1, max_depth, visited, rendered, out);
    }
}

fn renderCallText(
    gpa: std.mem.Allocator,
    db: *sqlite.Db,
    a: std.mem.Allocator,
    c: Callee,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(i64, u32),
    rendered: *std.AutoHashMap(i64, u32),
    out: *std.ArrayList(u8),
) Error!void {
    const indent = depth * 2;
    var i: usize = 0;
    while (i < indent) : (i += 1) try out.append(gpa, ' ');

    if (isDebugName(c.target_name)) {
        try out.writer(gpa).print("↓ debug  {s}\n", .{c.target_name});
        return;
    }
    if (isLibraryName(c.target_name)) {
        try out.writer(gpa).print("→ stdlib  {s}\n", .{c.target_name});
        return;
    }
    if (c.callee_id == null) {
        if (std.mem.eql(u8, c.kind, "indirect")) {
            try out.writer(gpa).print("? indirect  {s}\n", .{c.target_name});
        } else {
            try out.writer(gpa).print("{s}  (no body)\n", .{c.target_name});
        }
        return;
    }
    const cid = c.callee_id.?;
    if (visited.contains(cid)) {
        try out.writer(gpa).print("↻ recursive  {s}\n", .{c.target_name});
        return;
    }
    if (rendered.contains(cid)) {
        try out.writer(gpa).print("~ already-shown  {s}\n", .{c.target_name});
        return;
    }
    if (c.has_no_body) {
        try out.writer(gpa).print("@ {s}  (no body, ast-only or empty)\n", .{c.target_name});
        return;
    }
    if (depth + 1 >= max_depth) {
        try out.writer(gpa).print("▸ {s}\n", .{c.target_name});
        return;
    }
    try visited.put(cid, depth);
    defer _ = visited.remove(cid);
    try renderFnText(gpa, db, a, cid, c.target_name, depth, max_depth, visited, rendered, out);
}

fn compactFn(
    gpa: std.mem.Allocator,
    db: *sqlite.Db,
    a: std.mem.Allocator,
    fn_id: i64,
    qname: []const u8,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(i64, u32),
    rendered: *std.AutoHashMap(i64, u32),
    out: *std.ArrayList(u8),
) Error!void {
    try writeDepth(gpa, out, depth);
    try out.appendSlice(gpa, qname);
    try out.append(gpa, '\n');
    try rendered.put(fn_id, depth);

    const callees = try fetchCallees(db, a, fn_id);
    var prev_block: i64 = -1;
    for (callees) |c| {
        if (c.ast_node_id) |aid| {
            var marker_buf = std.ArrayList(u8){};
            var owning_block: i64 = -1;
            try collectControlMarkers(db, a, aid, &marker_buf, &owning_block);
            if (owning_block != prev_block and marker_buf.items.len > 0) {
                try writeDepth(gpa, out, depth + 1);
                try out.appendSlice(gpa, marker_buf.items);
                try out.append(gpa, '\n');
                prev_block = owning_block;
            }
        }
        try compactCall(gpa, db, a, c, depth + 1, max_depth, visited, rendered, out);
    }
}

fn compactCall(
    gpa: std.mem.Allocator,
    db: *sqlite.Db,
    a: std.mem.Allocator,
    c: Callee,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(i64, u32),
    rendered: *std.AutoHashMap(i64, u32),
    out: *std.ArrayList(u8),
) Error!void {
    if (isAssertionName(c.target_name)) return;
    if (isDebugName(c.target_name)) {
        try writeTagLine(gpa, out, depth, '%', c.target_name);
        return;
    }
    if (isLibraryName(c.target_name)) {
        try writeTagLine(gpa, out, depth, '=', c.target_name);
        return;
    }
    if (c.callee_id == null) {
        const tag: u8 = if (std.mem.eql(u8, c.kind, "indirect")) '&' else '!';
        try writeTagLine(gpa, out, depth, tag, c.target_name);
        return;
    }
    const cid = c.callee_id.?;
    if (visited.get(cid)) |bd| {
        try writeBodyRef(gpa, out, depth, bd, c.target_name);
        return;
    }
    if (rendered.get(cid)) |bd| {
        try writeBodyRef(gpa, out, depth, bd, c.target_name);
        return;
    }
    if (c.has_no_body) {
        try writeTagLine(gpa, out, depth, '@', c.target_name);
        return;
    }
    if (depth + 1 >= max_depth) {
        try writeTagLine(gpa, out, depth, '^', c.target_name);
        return;
    }
    try visited.put(cid, depth);
    defer _ = visited.remove(cid);
    try compactFn(gpa, db, a, cid, c.target_name, depth, max_depth, visited, rendered, out);
}

fn writeDepth(gpa: std.mem.Allocator, out: *std.ArrayList(u8), depth: u32) !void {
    const d = if (depth > 35) 35 else depth;
    const c: u8 = if (d < 10) '0' + @as(u8, @intCast(d)) else 'a' + @as(u8, @intCast(d - 10));
    try out.append(gpa, c);
}

fn writeTagLine(gpa: std.mem.Allocator, out: *std.ArrayList(u8), depth: u32, tag: u8, payload: []const u8) !void {
    try writeDepth(gpa, out, depth);
    try out.append(gpa, tag);
    try out.appendSlice(gpa, payload);
    try out.append(gpa, '\n');
}

fn writeBodyRef(gpa: std.mem.Allocator, out: *std.ArrayList(u8), depth: u32, body_depth: u32, name: []const u8) !void {
    try writeDepth(gpa, out, depth);
    try out.append(gpa, '~');
    try writeDepth(gpa, out, body_depth);
    try out.appendSlice(gpa, name);
    try out.append(gpa, '\n');
}

const Callee = struct {
    callee_id: ?i64,
    target_name: []const u8,
    kind: []const u8,
    ast_node_id: ?i64,
    /// True when the callee resolves to an entity that has 0 outgoing
    /// ir_calls AND is_ast_only — typical of compiler-inlined helpers.
    /// Drives the `@` fold tag.
    has_no_body: bool,
};

fn fetchCallees(db: *sqlite.Db, a: std.mem.Allocator, caller_id: i64) ![]Callee {
    var out = std.ArrayList(Callee){};
    var stmt = try db.prepare(
        \\SELECT ic.callee_entity_id, ic.call_kind,
        \\       COALESCE(e.qualified_name, '<unresolved>') AS qname,
        \\       COALESCE(e.is_ast_only, 0) AS is_ast_only,
        \\       (SELECT COUNT(*) FROM ir_call ic2 WHERE ic2.caller_entity_id = ic.callee_entity_id) AS out_count,
        \\       ic.ast_node_id
        \\FROM ir_call ic
        \\LEFT JOIN entity e ON e.id = ic.callee_entity_id
        \\WHERE ic.caller_entity_id = ?
        \\ORDER BY ic.id
    , a);
    defer stmt.finalize();
    try stmt.bindInt(1, caller_id);
    while (try stmt.step()) {
        const cid_text = stmt.columnText(0);
        const cid: ?i64 = if (cid_text == null) null else stmt.columnInt(0);
        const kind = try a.dupe(u8, stmt.columnText(1) orelse "direct");
        const qname = try a.dupe(u8, stmt.columnText(2) orelse "<unresolved>");
        const is_ast_only = stmt.columnInt(3) != 0;
        const out_count = stmt.columnInt(4);
        const an_text = stmt.columnText(5);
        const an_id: ?i64 = if (an_text == null) null else stmt.columnInt(5);
        try out.append(a, .{
            .callee_id = cid,
            .target_name = qname,
            .kind = kind,
            .ast_node_id = an_id,
            .has_no_body = is_ast_only and out_count == 0,
        });
    }
    return out.toOwnedSlice(a);
}

/// Walk parent_id from `start_node` upward up to 8 levels, emit `?if`,
/// `?else`, `*while`, `*for`, `>prong:<role>` markers for each enclosing
/// control-flow ancestor. `owning_block` is set to the innermost ancestor
/// node id so callers can tell when the structural context changed
/// between consecutive callees. Marker text is appended to `buf`.
fn collectControlMarkers(
    db: *sqlite.Db,
    a: std.mem.Allocator,
    start_node: i64,
    buf: *std.ArrayList(u8),
    owning_block: *i64,
) Error!void {
    var cur: i64 = start_node;
    var depth: u32 = 0;
    while (depth < 8) : (depth += 1) {
        var stmt = try db.prepare(
            \\SELECT a.id, a.kind, a.parent_id, ae.role
            \\  FROM ast_node a
            \\  LEFT JOIN ast_edge ae ON ae.child_id = a.id
            \\ WHERE a.id = ? LIMIT 1
        , a);
        defer stmt.finalize();
        try stmt.bindInt(1, cur);
        if (!try stmt.step()) return;
        const kind = try a.dupe(u8, stmt.columnText(1) orelse "");
        const parent_t = sqlite.c.sqlite3_column_type(stmt.raw, 2);
        const parent_id: ?i64 = if (parent_t == sqlite.c.SQLITE_NULL) null else stmt.columnInt(2);
        const role = if (stmt.columnText(3)) |r| try a.dupe(u8, r) else null;

        if (std.mem.eql(u8, kind, "if")) {
            if (buf.items.len > 0) try buf.append(a, ' ');
            try buf.appendSlice(a, "?if");
            owning_block.* = cur;
        } else if (std.mem.eql(u8, kind, "else")) {
            if (buf.items.len > 0) try buf.append(a, ' ');
            try buf.appendSlice(a, "?else");
            owning_block.* = cur;
        } else if (std.mem.eql(u8, kind, "while") or std.mem.eql(u8, kind, "for")) {
            if (buf.items.len > 0) try buf.append(a, ' ');
            try buf.append(a, '*');
            try buf.appendSlice(a, kind);
            owning_block.* = cur;
        } else if (std.mem.eql(u8, kind, "switch_prong")) {
            if (buf.items.len > 0) try buf.append(a, ' ');
            try buf.appendSlice(a, ">prong");
            if (role) |r| if (r.len > 0) {
                try buf.append(a, ':');
                try buf.appendSlice(a, r);
            };
            owning_block.* = cur;
        }
        if (parent_id == null) break;
        cur = parent_id.?;
    }
}

fn resolveFnId(db: *sqlite.Db, a: std.mem.Allocator, qname: []const u8) !?i64 {
    var stmt = try db.prepare(
        "SELECT id FROM entity WHERE qualified_name = ? AND kind = 'fn' LIMIT 1",
        a,
    );
    defer stmt.finalize();
    try stmt.bindText(1, qname);
    if (!try stmt.step()) return null;
    return stmt.columnInt(0);
}

fn qnameFor(db: *sqlite.Db, a: std.mem.Allocator, id: i64) !?[]const u8 {
    var stmt = try db.prepare("SELECT qualified_name FROM entity WHERE id = ? LIMIT 1", a);
    defer stmt.finalize();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return null;
    return try a.dupe(u8, stmt.columnText(0) orelse "");
}

fn isDebugName(n: []const u8) bool {
    return std.mem.startsWith(u8, n, "debug.") or std.mem.indexOf(u8, n, ".debug.") != null;
}
fn isLibraryName(n: []const u8) bool {
    return std.mem.startsWith(u8, n, "std.") or
        std.mem.startsWith(u8, n, "builtin.") or
        std.mem.startsWith(u8, n, "compiler_rt.");
}
fn isAssertionName(n: []const u8) bool {
    if (std.mem.eql(u8, n, "debug.assert")) return true;
    if (std.mem.endsWith(u8, n, ".debug.assert")) return true;
    if (std.mem.startsWith(u8, n, "debug.FullPanic.")) return true;
    if (std.mem.indexOf(u8, n, ".debug.FullPanic.") != null) return true;
    if (std.mem.eql(u8, n, "builtin.returnError")) return true;
    return false;
}
