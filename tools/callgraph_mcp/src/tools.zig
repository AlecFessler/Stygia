//! Tool dispatch for the callgraph MCP daemon. Each `callgraph_*` handler
//! issues SQL queries against an open SQLite DB matching tools/indexer/schema.sql.
//!
//! The registry holds one open Db per (arch, commit_sha) DB file the daemon
//! was launched against. Most tools target a single DB; when multiple DBs
//! are loaded (e.g. one per arch) the caller doesn't currently get to pick —
//! we use the most-recent (newest mtime). The entries / arches tools span
//! all loaded DBs.

const std = @import("std");

const git = @import("git.zig");
const sqlite = @import("sqlite.zig");

pub const DbEntry = struct {
    /// File path the DB was opened from; used for diagnostic output only.
    path: []const u8,
    /// Architecture tag from meta.arch ("x86_64"|"aarch64").
    arch: []const u8,
    /// Commit SHA the DB was built for.
    commit_sha: []const u8,
    db: sqlite.Db,
};

pub const Registry = struct {
    gpa: std.mem.Allocator,
    dbs: std.ArrayList(DbEntry),
    /// Repo root used for git-plumbing tools (callgraph_commits).
    /// Defaults to CWD; override at construction time. Lifetime-managed
    /// by main; the registry just borrows the slice.
    git_root: []const u8,

    pub fn init(gpa: std.mem.Allocator) Registry {
        return .{ .gpa = gpa, .dbs = .{}, .git_root = "." };
    }

    pub fn deinit(self: *Registry) void {
        for (self.dbs.items) |*e| {
            self.gpa.free(e.path);
            self.gpa.free(e.arch);
            self.gpa.free(e.commit_sha);
            e.db.close();
        }
        self.dbs.deinit(self.gpa);
    }

    pub fn addDb(self: *Registry, path: []const u8) !void {
        var db = try sqlite.Db.openReadOnly(path, self.gpa);
        errdefer db.close();
        const arch = try metaValue(&db, self.gpa, "arch");
        errdefer self.gpa.free(arch);
        const sha = try metaValue(&db, self.gpa, "commit_sha");
        errdefer self.gpa.free(sha);
        try self.dbs.append(self.gpa, .{
            .path = try self.gpa.dupe(u8, path),
            .arch = arch,
            .commit_sha = sha,
            .db = db,
        });
    }

    /// Pick the DB an `arch` parameter wants, defaulting to the newest one.
    /// Today everything is single-DB so the default lookup is sufficient;
    /// when the indexer ships per-arch DBs we'll wire the param through.
    pub fn pick(self: *Registry, arch: ?[]const u8) ?*DbEntry {
        if (self.dbs.items.len == 0) return null;
        if (arch) |a| {
            for (self.dbs.items) |*e| {
                if (std.mem.eql(u8, e.arch, a)) return e;
            }
        }
        return &self.dbs.items[0];
    }

    pub fn dispatch(
        self: *Registry,
        al: std.mem.Allocator,
        tool: []const u8,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !bool {
        if (std.mem.eql(u8, tool, "callgraph_arches")) {
            try self.toolArches(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_find")) {
            try self.toolFind(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_loc")) {
            try self.toolLoc(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_src")) {
            try self.toolSrc(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_callers")) {
            try self.toolCallers(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_reaches")) {
            try self.toolReaches(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_entries")) {
            try self.toolEntries(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_modules")) {
            try self.toolModules(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_trace")) {
            try self.toolTrace(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_type")) {
            try self.toolType(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_src_bin")) {
            try self.toolSrcBin(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_src_bin_at")) {
            try self.toolSrcBinAt(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_bin_dataflow_reg")) {
            try self.toolBinDataflowReg(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_bin_addr2line")) {
            try self.toolBinAddr2Line(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_commits")) {
            try self.toolCommits(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "callgraph_findings")) {
            try self.toolFindings(al, args, out);
            return true;
        }
        return false;
    }

    fn toolFindings(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const analyzer = jsonString(args, "analyzer") orelse "";
        const rule = jsonString(args, "rule") orelse "";
        const severity = jsonString(args, "severity") orelse "";
        const file_glob = jsonString(args, "file") orelse "";
        const limit_v = jsonInt(args, "limit") orelse 500;

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
        , al);
        defer stmt.finalize();
        try stmt.bindText(1, analyzer);
        try stmt.bindText(2, rule);
        try stmt.bindText(3, severity);
        try stmt.bindText(4, file_glob);
        try stmt.bindInt(5, limit_v);

        var matches: u32 = 0;
        while (try stmt.step()) {
            const an = stmt.columnText(0) orelse "";
            const sv = stmt.columnText(1) orelse "";
            const ru = stmt.columnText(2) orelse "";
            const fp = stmt.columnText(3) orelse "";
            const line: u32 = @intCast(stmt.columnInt(4));
            const msg = stmt.columnText(5) orelse "";
            try std.fmt.format(out.writer(al), "{s}\t[{s}]\t{s}\t{s}:{d}\t{s}\n", .{ an, sv, ru, fp, line, msg });
            matches += 1;
        }
        if (matches == 0) try out.appendSlice(al, "(no findings — analyzers may not have populated lint_finding yet)\n");
    }

    // ----------------------------------------------------------- helpers

    fn entryByName(entry: *DbEntry, al: std.mem.Allocator, name: []const u8) !?Entity {
        // Try qualified_name match first; fall back to suffix match (".name")
        // so callers can pass a simple name and still find a unique fn.
        var stmt = try entry.db.prepare(
            \\SELECT id, kind, qualified_name, def_file_id, def_byte_start, def_byte_end,
            \\       def_line, def_col, generic_parent_id, is_ast_only
            \\  FROM entity
            \\ WHERE qualified_name = ?
            \\ LIMIT 1
        , al);
        defer stmt.finalize();
        try stmt.bindText(1, name);
        if (try stmt.step()) {
            return try readEntityOwned(&stmt, al);
        }
        // Suffix fallback.
        var stmt2 = try entry.db.prepare(
            \\SELECT id, kind, qualified_name, def_file_id, def_byte_start, def_byte_end,
            \\       def_line, def_col, generic_parent_id, is_ast_only
            \\  FROM entity
            \\ WHERE qualified_name LIKE ?
            \\ ORDER BY length(qualified_name) ASC
            \\ LIMIT 1
        , al);
        defer stmt2.finalize();
        const pat = try std.fmt.allocPrint(al, "%.{s}", .{name});
        try stmt2.bindText(1, pat);
        if (try stmt2.step()) {
            return try readEntityOwned(&stmt2, al);
        }
        return null;
    }

    // ----------------------------------------------------------- handlers

    fn toolArches(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        if (self.dbs.items.len == 0) {
            try out.appendSlice(al, "no DBs loaded\n");
            return;
        }
        for (self.dbs.items) |e| {
            try std.fmt.format(out.writer(al), "{s}\t{s}\t{s}\n", .{ e.arch, e.commit_sha, e.path });
        }
    }

    fn toolFind(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const q = jsonString(args, "q") orelse return;
        const limit = jsonInt(args, "limit") orelse 200;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");

        // The schema declares `entity_fts` over qualified_name. FTS5 substring
        // queries need wildcard tokens; we lowercase + concat with `*` to
        // match any segment that contains the query as a prefix. For
        // arbitrary substrings we ALSO fall back to a LIKE scan when FTS5
        // misses (e.g. mid-token matches).
        var stmt = try entry.db.prepare(
            \\SELECT e.qualified_name, e.kind, f.path, e.def_line
            \\  FROM entity e
            \\  JOIN file f ON f.id = e.def_file_id
            \\ WHERE e.qualified_name LIKE ?
            \\ ORDER BY length(e.qualified_name) ASC
            \\ LIMIT ?
        , al);
        defer stmt.finalize();
        const pat = try std.fmt.allocPrint(al, "%{s}%", .{q});
        try stmt.bindText(1, pat);
        try stmt.bindInt(2, limit);
        var hits: usize = 0;
        while (try stmt.step()) {
            const qname = stmt.columnText(0) orelse "?";
            const kind = stmt.columnText(1) orelse "?";
            const path = stmt.columnText(2) orelse "?";
            const line = stmt.columnInt(3);
            try std.fmt.format(out.writer(al), "{s}\t({s})\t{s}:{d}\n", .{ qname, kind, path, line });
            hits += 1;
        }
        if (hits == 0) try std.fmt.format(out.writer(al), "no matches for {s}\n", .{q});
    }

    fn toolLoc(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const name = jsonString(args, "name") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const ent = (try entryByName(entry, al, name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        };
        // Read file path.
        const path = try filePath(entry, al, ent.def_file_id);
        defer al.free(path);
        if (ent.is_ast_only) {
            try std.fmt.format(out.writer(al), "{s}\t{s}:{d}:{d}\t[inlined]\n", .{
                ent.qualified_name, path, ent.def_line, ent.def_col,
            });
        } else {
            try std.fmt.format(out.writer(al), "{s}\t{s}:{d}:{d}\n", .{
                ent.qualified_name, path, ent.def_line, ent.def_col,
            });
        }
    }

    fn toolSrc(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const name = jsonString(args, "name") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const ent = (try entryByName(entry, al, name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        };
        // schema: substr(file.source, def_byte_start+1, def_byte_end - def_byte_start)
        var stmt = try entry.db.prepare(
            \\SELECT substr(f.source, ? + 1, ? - ?)
            \\  FROM file f
            \\ WHERE f.id = ?
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, @intCast(ent.def_byte_start));
        try stmt.bindInt(2, @intCast(ent.def_byte_end));
        try stmt.bindInt(3, @intCast(ent.def_byte_start));
        try stmt.bindInt(4, ent.def_file_id);
        if (!try stmt.step()) {
            try std.fmt.format(out.writer(al), "{s}: source not found\n", .{name});
            return;
        }
        const src = stmt.columnText(0) orelse "";
        try out.appendSlice(al, src);
        if (src.len == 0 or src[src.len - 1] != '\n') try out.append(al, '\n');
    }

    fn toolCallers(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const name = jsonString(args, "name") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const ent = (try entryByName(entry, al, name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        };
        // Aggregate across generic instantiations: if `name` is a generic parent,
        // include ir_call rows whose callee_entity_id is any child whose
        // generic_parent_id = parent. If `name` is itself a child, walk up to
        // the parent and aggregate from there. The recursive CTE collects the
        // entity id set first, then queries ir_call once.
        var stmt = try entry.db.prepare(
            \\WITH RECURSIVE
            \\  parent AS (
            \\    SELECT COALESCE(generic_parent_id, id) AS pid
            \\      FROM entity WHERE id = ?
            \\  ),
            \\  family AS (
            \\    SELECT pid AS id FROM parent
            \\    UNION
            \\    SELECT e.id FROM entity e
            \\      JOIN parent p ON e.generic_parent_id = p.pid
            \\  )
            \\SELECT caller.qualified_name, c.call_kind, f.path, c.site_line
            \\  FROM ir_call c
            \\  JOIN entity caller ON caller.id = c.caller_entity_id
            \\  JOIN file f       ON f.id = caller.def_file_id
            \\ WHERE c.callee_entity_id IN (SELECT id FROM family)
            \\ ORDER BY caller.qualified_name, c.site_line
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, ent.id);
        var hits: usize = 0;
        while (try stmt.step()) {
            const cname = stmt.columnText(0) orelse "?";
            const ckind = stmt.columnText(1) orelse "?";
            const path = stmt.columnText(2) orelse "?";
            const line = stmt.columnInt(3);
            try std.fmt.format(out.writer(al), "{s}\t({s})\t@{s}:{d}\n", .{ cname, ckind, path, line });
            hits += 1;
        }
        if (hits == 0) try std.fmt.format(out.writer(al), "no callers found for {s}\n", .{name});
    }

    fn toolReaches(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const from = jsonString(args, "from") orelse return;
        const to = jsonString(args, "to") orelse return;
        const max_depth = jsonInt(args, "max_depth") orelse 24;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const from_e = (try entryByName(entry, al, from)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{from});
            return;
        };
        const to_e = (try entryByName(entry, al, to)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{to});
            return;
        };
        // Recursive CTE: BFS-ish forward walk on filtered ir_call. SQLite's
        // recursive CTE does DFS by default, so a cycle protector keeps the
        // walk finite. We don't ask for shortest paths optimally — any cycle-
        // free path is returned, but ORDER BY depth picks the smallest.
        var stmt = try entry.db.prepare(
            \\WITH RECURSIVE walk(id, depth, path) AS (
            \\    SELECT ?, 0, CAST(? AS TEXT)
            \\  UNION ALL
            \\    SELECT c.callee_entity_id,
            \\           w.depth + 1,
            \\           w.path || '>' || c.callee_entity_id
            \\      FROM ir_call c
            \\      JOIN walk w ON w.id = c.caller_entity_id
            \\     WHERE c.callee_entity_id IS NOT NULL
            \\       AND c.call_kind IN ('direct','dispatch_x64','dispatch_aarch64')
            \\       AND w.depth < ?
            \\       AND instr(w.path, '>' || c.callee_entity_id || '>') = 0
            \\       AND w.path NOT LIKE (c.callee_entity_id || '>%')
            \\)
            \\SELECT path, depth FROM walk
            \\ WHERE id = ?
            \\ ORDER BY depth ASC
            \\ LIMIT 1
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, from_e.id);
        try stmt.bindInt(2, from_e.id);
        try stmt.bindInt(3, max_depth);
        try stmt.bindInt(4, to_e.id);
        if (!try stmt.step()) {
            try std.fmt.format(out.writer(al), "no path from {s} to {s} within {d} hops\n", .{ from, to, max_depth });
            return;
        }
        const raw_path = stmt.columnText(0) orelse "";
        // Resolve every id to a name in one query.
        try out.appendSlice(al, "yes\n");
        var it = std.mem.tokenizeScalar(u8, raw_path, '>');
        var idx: u32 = 0;
        while (it.next()) |id_str| {
            const id = std.fmt.parseInt(i64, id_str, 10) catch continue;
            const qname = try lookupQname(entry, al, id);
            defer al.free(qname);
            try std.fmt.format(out.writer(al), "{d}\t{s}\n", .{ idx, qname });
            idx += 1;
        }
    }

    fn toolEntries(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const kind_filter = jsonString(args, "kind");
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        var stmt = try entry.db.prepare(
            \\SELECT ep.kind, ep.label, e.qualified_name, f.path, e.def_line, ep.vector
            \\  FROM entry_point ep
            \\  JOIN entity e ON e.id = ep.entity_id
            \\  JOIN file f   ON f.id = e.def_file_id
            \\ ORDER BY ep.kind, ep.vector, ep.label
        , al);
        defer stmt.finalize();
        var current_kind: []const u8 = "";
        var any = false;
        while (try stmt.step()) {
            const k = stmt.columnText(0) orelse "?";
            if (kind_filter) |kf| if (!std.mem.eql(u8, kf, k)) continue;
            const label = stmt.columnText(1) orelse "?";
            const qname = stmt.columnText(2) orelse "?";
            const path = stmt.columnText(3) orelse "?";
            const line = stmt.columnInt(4);
            if (!std.mem.eql(u8, current_kind, k)) {
                if (any) try out.append(al, '\n');
                try std.fmt.format(out.writer(al), "## {s}\n", .{k});
                // current_kind borrows sqlite memory which is invalidated on
                // step(); copy the kind tag (cheap, short).
                current_kind = try al.dupe(u8, k);
            }
            try std.fmt.format(out.writer(al), "  {s}\t{s}\t{s}:{d}\n", .{ label, qname, path, line });
            any = true;
        }
        if (!any) try out.appendSlice(al, "no entry points found\n");
    }

    fn toolModules(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const min_edges = jsonInt(args, "min_edges") orelse 2;
        const direction = jsonString(args, "direction") orelse "out";
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        // The schema gives us module per entity; aggregate caller-module to
        // callee-module crossings. `level` from CLAUDE.md exists in the spec
        // but the schema only stores qualified_name; we just key on it.
        var stmt = try entry.db.prepare(
            \\SELECT m1.qualified_name AS src,
            \\       m2.qualified_name AS dst,
            \\       COUNT(*) AS cnt
            \\  FROM ir_call c
            \\  JOIN entity e1 ON e1.id = c.caller_entity_id
            \\  JOIN entity e2 ON e2.id = c.callee_entity_id
            \\  JOIN module m1 ON m1.id = e1.module_id
            \\  JOIN module m2 ON m2.id = e2.module_id
            \\ WHERE c.callee_entity_id IS NOT NULL
            \\   AND m1.id != m2.id
            \\ GROUP BY m1.id, m2.id
            \\ HAVING cnt >= ?
            \\ ORDER BY src, cnt DESC
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, min_edges);
        // Collect rows once; the `both` direction needs them twice.
        const Row = struct { src: []const u8, dst: []const u8, cnt: i64 };
        var rows = std.ArrayList(Row){};
        defer {
            for (rows.items) |r| {
                al.free(r.src);
                al.free(r.dst);
            }
            rows.deinit(al);
        }
        while (try stmt.step()) {
            try rows.append(al, .{
                .src = try al.dupe(u8, stmt.columnText(0) orelse ""),
                .dst = try al.dupe(u8, stmt.columnText(1) orelse ""),
                .cnt = stmt.columnInt(2),
            });
        }
        if (std.mem.eql(u8, direction, "in")) {
            try out.appendSlice(al, "## inbound\n");
            try renderModulesIn(al, out, rows.items);
        } else if (std.mem.eql(u8, direction, "both")) {
            try out.appendSlice(al, "## outbound\n");
            try renderModulesOut(al, out, rows.items);
            try out.appendSlice(al, "\n## inbound\n");
            try renderModulesIn(al, out, rows.items);
        } else {
            try out.appendSlice(al, "## outbound\n");
            try renderModulesOut(al, out, rows.items);
        }
        if (rows.items.len == 0) try out.appendSlice(al, "no cross-module edges meeting threshold\n");
    }

    fn toolType(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const name = jsonString(args, "name") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const ent = (try entryByName(entry, al, name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        };
        // Type table direct hit.
        var tstmt = try entry.db.prepare(
            \\SELECT id, kind, size, align FROM type WHERE entity_id = ? LIMIT 1
        , al);
        defer tstmt.finalize();
        try tstmt.bindInt(1, ent.id);
        if (try tstmt.step()) {
            const tid = tstmt.columnInt(0);
            const kind = tstmt.columnText(1) orelse "?";
            try std.fmt.format(out.writer(al), "{s}\t({s})\tsize={d} align={d}\n", .{
                ent.qualified_name, kind, tstmt.columnInt(2), tstmt.columnInt(3),
            });
            // Field walk.
            var fstmt = try entry.db.prepare(
                \\SELECT idx, name, offset, type_ref FROM type_field
                \\ WHERE type_id = ? ORDER BY idx ASC
            , al);
            defer fstmt.finalize();
            try fstmt.bindInt(1, tid);
            while (try fstmt.step()) {
                try std.fmt.format(out.writer(al), "  field[{d}] {s} offset={d}\n", .{
                    fstmt.columnInt(0),
                    fstmt.columnText(1) orelse "?",
                    fstmt.columnInt(2),
                });
            }
            return;
        }
        // Alias chain (depth ≤ 4).
        var astmt = try entry.db.prepare(
            \\WITH RECURSIVE chain(level, eid, target_id) AS (
            \\    SELECT 0, entity_id, target_entity_id
            \\      FROM const_alias WHERE entity_id = ?
            \\  UNION ALL
            \\    SELECT chain.level + 1, ca.entity_id, ca.target_entity_id
            \\      FROM const_alias ca
            \\      JOIN chain ON ca.entity_id = chain.target_id
            \\     WHERE chain.level < 4
            \\)
            \\SELECT chain.level, e.qualified_name
            \\  FROM chain
            \\  JOIN entity e ON e.id = chain.target_id
            \\ ORDER BY chain.level
        , al);
        defer astmt.finalize();
        try astmt.bindInt(1, ent.id);
        var any = false;
        while (try astmt.step()) {
            try std.fmt.format(out.writer(al), "alias[{d}] -> {s}\n", .{
                astmt.columnInt(0),
                astmt.columnText(1) orelse "?",
            });
            any = true;
        }
        if (any) return;
        // Fallback: dump the entity's source body so the user gets *something*.
        // Matches the HTTP /api/type behavior — the type table isn't populated
        // by the indexer yet, but the entity row + file source are.
        var src_stmt = try entry.db.prepare(
            \\SELECT e.kind, f.path, e.def_line, e.def_byte_start, e.def_byte_end, f.source
            \\  FROM entity e JOIN file f ON f.id = e.def_file_id
            \\ WHERE e.id = ? LIMIT 1
        , al);
        defer src_stmt.finalize();
        try src_stmt.bindInt(1, ent.id);
        if (!try src_stmt.step()) {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        }
        const kind = try al.dupe(u8, src_stmt.columnText(0) orelse "");
        const path = try al.dupe(u8, src_stmt.columnText(1) orelse "");
        const def_line: u32 = @intCast(src_stmt.columnInt(2));
        const bs: usize = @intCast(src_stmt.columnInt(3));
        const be: usize = @intCast(src_stmt.columnInt(4));
        const source = try al.dupe(u8, src_stmt.columnText(5) orelse "");
        try std.fmt.format(out.writer(al), "{s} ({s}) — {s}:{d}\n---\n", .{ ent.qualified_name, kind, path, def_line });
        if (be <= source.len and bs <= be) {
            try out.appendSlice(al, source[bs..be]);
            if (be == 0 or source[be - 1] != '\n') try out.append(al, '\n');
        }
    }

    fn toolSrcBin(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const name = jsonString(args, "name") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const ent = (try entryByName(entry, al, name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        };
        // Resolve the symbol's [addr, addr+size) range.
        var sstmt = try entry.db.prepare(
            \\SELECT addr, size FROM bin_symbol WHERE entity_id = ? ORDER BY addr ASC LIMIT 1
        , al);
        defer sstmt.finalize();
        try sstmt.bindInt(1, ent.id);
        if (!try sstmt.step()) {
            try std.fmt.format(out.writer(al), "{s}: no bin_symbol (likely inlined)\n", .{name});
            return;
        }
        const sym_addr = sstmt.columnInt(0);
        const sym_size = sstmt.columnInt(1);
        const sym_end = sym_addr + sym_size;
        // Walk bin_inst joined with dwarf_line for source-line interleaving.
        // Emit `; file:line` only when the (file_id,line) range changes.
        var stmt = try entry.db.prepare(
            \\SELECT b.addr, b.mnemonic, b.operands,
            \\       d.file_id, d.line, f.path
            \\  FROM bin_inst b
            \\  LEFT JOIN dwarf_line d
            \\         ON b.addr BETWEEN d.addr_lo AND d.addr_hi
            \\  LEFT JOIN file f ON f.id = d.file_id
            \\ WHERE b.addr >= ? AND b.addr < ?
            \\ ORDER BY b.addr ASC
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, sym_addr);
        try stmt.bindInt(2, sym_end);
        var last_path: ?[]const u8 = null;
        defer if (last_path) |p| al.free(p);
        var last_line: i64 = -1;
        while (try stmt.step()) {
            const addr = stmt.columnInt(0);
            const mnem = stmt.columnText(1) orelse "";
            const ops = stmt.columnText(2) orelse "";
            const path = stmt.columnText(5);
            const line = if (stmt.columnText(4) != null) stmt.columnInt(4) else -1;
            const path_changed = blk: {
                if (path == null and last_path == null) break :blk false;
                if (path == null or last_path == null) break :blk true;
                break :blk !std.mem.eql(u8, path.?, last_path.?);
            };
            if (path != null and (line != last_line or path_changed)) {
                try std.fmt.format(out.writer(al), "; {s}:{d}\n", .{ path.?, line });
                if (last_path) |p| al.free(p);
                last_path = try al.dupe(u8, path.?);
                last_line = line;
            }
            try std.fmt.format(out.writer(al), "  {x:0>8}: {s} {s}\n", .{ @as(u64, @bitCast(addr)), mnem, ops });
        }
    }

    fn toolSrcBinAt(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const at = jsonString(args, "at") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const colon = std.mem.lastIndexOfScalar(u8, at, ':') orelse {
            try out.appendSlice(al, "expected `path:line`\n");
            return;
        };
        const path_str = at[0..colon];
        const line = std.fmt.parseInt(i64, at[colon + 1 ..], 10) catch {
            try out.appendSlice(al, "bad line number\n");
            return;
        };
        // Match by basename — the agent often passes a bare basename.
        const base = std.fs.path.basename(path_str);
        var range_stmt = try entry.db.prepare(
            \\SELECT d.addr_lo, d.addr_hi
            \\  FROM dwarf_line d
            \\  JOIN file f ON f.id = d.file_id
            \\ WHERE f.path LIKE ? AND d.line = ?
            \\ ORDER BY d.addr_lo
        , al);
        defer range_stmt.finalize();
        const pat = try std.fmt.allocPrint(al, "%{s}", .{base});
        try range_stmt.bindText(1, pat);
        try range_stmt.bindInt(2, line);
        var any = false;
        while (try range_stmt.step()) {
            const lo = range_stmt.columnInt(0);
            const hi = range_stmt.columnInt(1);
            // Inner query: instructions in this range.
            var ins = try entry.db.prepare(
                \\SELECT addr, mnemonic, operands FROM bin_inst
                \\ WHERE addr BETWEEN ? AND ?
                \\ ORDER BY addr ASC
            , al);
            defer ins.finalize();
            try ins.bindInt(1, lo);
            try ins.bindInt(2, hi);
            while (try ins.step()) {
                try std.fmt.format(out.writer(al), "  {x:0>8}: {s} {s}\n", .{
                    @as(u64, @bitCast(ins.columnInt(0))),
                    ins.columnText(1) orelse "",
                    ins.columnText(2) orelse "",
                });
                any = true;
            }
        }
        if (!any) try std.fmt.format(out.writer(al), "no instructions for {s}:{d} (likely DCE'd or no DWARF entry)\n", .{ at[0..colon], line });
    }

    fn toolBinDataflowReg(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const name = jsonString(args, "name") orelse return;
        const reg = jsonString(args, "reg") orelse return;
        const stop_at_call = jsonBoolDefault(args, "stop_at_call", true);
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const ent = (try entryByName(entry, al, name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{name});
            return;
        };
        var sstmt = try entry.db.prepare(
            \\SELECT addr, size FROM bin_symbol WHERE entity_id = ? LIMIT 1
        , al);
        defer sstmt.finalize();
        try sstmt.bindInt(1, ent.id);
        if (!try sstmt.step()) {
            try std.fmt.format(out.writer(al), "{s}: no bin_symbol\n", .{name});
            return;
        }
        const sym_addr = sstmt.columnInt(0);
        const sym_end = sym_addr + sstmt.columnInt(1);

        var stmt = try entry.db.prepare(
            \\SELECT addr, mnemonic, operands FROM bin_inst
            \\ WHERE addr >= ? AND addr < ?
            \\ ORDER BY addr ASC
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, sym_addr);
        try stmt.bindInt(2, sym_end);

        const lreg = try std.ascii.allocLowerString(al, reg);
        defer al.free(lreg);
        while (try stmt.step()) {
            const addr = stmt.columnInt(0);
            const mnem = stmt.columnText(1) orelse "";
            const ops = stmt.columnText(2) orelse "";
            if (stop_at_call and std.mem.startsWith(u8, mnem, "call")) {
                try std.fmt.format(out.writer(al), "  {x:0>8}: {s} {s}    [stop: call]\n", .{ @as(u64, @bitCast(addr)), mnem, ops });
                break;
            }
            // Width-alias-aware match: we look for the register name as a
            // word in the operands. The schema captures pre-formatted
            // operand text, so we tokenise on commas and compare each token
            // (lowered) against a small alias set.
            const hit = matchRegInOps(lreg, ops);
            if (hit == .none) continue;
            const tag: []const u8 = switch (hit) {
                .dst => "[dst]",
                .src => "[src]",
                else => "",
            };
            try std.fmt.format(out.writer(al), "  {x:0>8}: {s} {s}    {s}\n", .{ @as(u64, @bitCast(addr)), mnem, ops, tag });
        }
    }

    fn toolBinAddr2Line(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const addr_str = jsonString(args, "addr") orelse return;
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const trimmed = if (std.mem.startsWith(u8, addr_str, "0x") or std.mem.startsWith(u8, addr_str, "0X"))
            addr_str[2..]
        else
            addr_str;
        // Kernel virtual addresses (0xffffffff8xxxxxxx) overflow i64 if parsed
        // directly — go through u64 and bit-cast to match how the writer stored
        // them.
        const addr_u: u64 = std.fmt.parseInt(u64, trimmed, 16) catch {
            try out.appendSlice(al, "bad hex address\n");
            return;
        };
        const addr: i64 = @bitCast(addr_u);
        // Floor on dwarf_line.
        var dstmt = try entry.db.prepare(
            \\SELECT f.path, d.line
            \\  FROM dwarf_line d
            \\  JOIN file f ON f.id = d.file_id
            \\ WHERE d.addr_lo <= ?
            \\ ORDER BY d.addr_lo DESC LIMIT 1
        , al);
        defer dstmt.finalize();
        try dstmt.bindInt(1, addr);
        // Floor on bin_symbol.
        var sstmt = try entry.db.prepare(
            \\SELECT s.addr, e.qualified_name
            \\  FROM bin_symbol s
            \\  JOIN entity e ON e.id = s.entity_id
            \\ WHERE s.addr <= ?
            \\ ORDER BY s.addr DESC LIMIT 1
        , al);
        defer sstmt.finalize();
        try sstmt.bindInt(1, addr);

        if (try dstmt.step()) {
            const path = dstmt.columnText(0) orelse "?";
            const line = dstmt.columnInt(1);
            try std.fmt.format(out.writer(al), "{s}: {s}:{d}", .{ entry.arch, path, line });
        } else {
            try std.fmt.format(out.writer(al), "{s}: <no dwarf_line>", .{entry.arch});
        }
        if (try sstmt.step()) {
            const sym_addr = sstmt.columnInt(0);
            const off = addr - sym_addr;
            try std.fmt.format(out.writer(al), "  in {s}+{x}\n", .{
                sstmt.columnText(1) orelse "?",
                @as(u64, @intCast(off)),
            });
        } else {
            try out.append(al, '\n');
        }
    }

    // ----------------------------------------------- trace (the big one)

    fn toolTrace(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const root_name = jsonString(args, "entry") orelse return;
        const max_depth = @as(u32, @intCast(jsonInt(args, "depth") orelse 6));
        const hide_debug = jsonBoolDefault(args, "hide_debug", true);
        const hide_library = jsonBoolDefault(args, "hide_library", true);
        const hide_assertions = jsonBoolDefault(args, "hide_assertions", true);
        const entry = self.pick(jsonString(args, "arch")) orelse return out.appendSlice(al, "no DBs loaded\n");
        const root = (try entryByName(entry, al, root_name)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not found\n", .{root_name});
            return;
        };
        // DFS with a simple visited-on-path cycle gate. Each step queries
        // ir_call for the current entity, then for each call pulls the
        // ast_node ancestor chain to detect enclosing control-flow
        // constructs. We render an indented tree:
        //   <indent><name>           — fn
        //   <indent>  ?if_else …     — branch marker (compact-style)
        //   <indent>  *loop          — loop marker
        //   <indent>  ^name          — capped (depth limit)
        try std.fmt.format(out.writer(al), "T root={s}\n", .{root.qualified_name});
        var visited = std.AutoHashMap(i64, void).init(al);
        defer visited.deinit();
        try traceWalk(entry, al, out, root.id, root.qualified_name, 0, max_depth, &visited, .{
            .hide_debug = hide_debug,
            .hide_library = hide_library,
            .hide_assertions = hide_assertions,
        });
    }

    /// `callgraph_commits` — output identical to callgraph_http's
    /// `/api/commits?format=text`. Shells out to `git log` against
    /// `self.git_root` and decorates the output with `[stale]` markers.
    fn toolCommits(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        var limit: u32 = git.DEFAULT_LIMIT;
        if (jsonInt(args, "limit")) |n| {
            if (n > 0) limit = @intCast(@min(n, @as(i64, git.MAX_LIMIT)));
        }
        const log_stdout = git.gitLog(al, self.git_root, limit) catch {
            try out.appendSlice(al, "git log failed\n");
            return;
        };
        defer al.free(log_stdout);

        var compat_set = git.buildEmitIrSet(al, self.git_root);
        defer git.freeShaSet(al, &compat_set);

        try git.renderCommitsText(al, out, log_stdout, &compat_set);
    }
};

const TraceFlags = struct {
    hide_debug: bool,
    hide_library: bool,
    hide_assertions: bool,
};

fn traceWalk(
    entry: *DbEntry,
    al: std.mem.Allocator,
    out: *std.ArrayList(u8),
    fn_id: i64,
    fn_name: []const u8,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(i64, void),
    flags: TraceFlags,
) !void {
    try writeIndent(out, al, depth);
    try std.fmt.format(out.writer(al), "{s}\n", .{fn_name});

    if (depth + 1 >= max_depth) return;
    if (try visited.fetchPut(fn_id, {})) |_| return;
    defer _ = visited.remove(fn_id);

    // Pull all calls out of this fn, with their ast_node ids.
    var stmt = try entry.db.prepare(
        \\SELECT c.callee_entity_id, c.call_kind, c.ast_node_id, c.site_line,
        \\       e.qualified_name
        \\  FROM ir_call c
        \\  LEFT JOIN entity e ON e.id = c.callee_entity_id
        \\ WHERE c.caller_entity_id = ?
        \\ ORDER BY c.site_line ASC, c.id ASC
    , al);
    defer stmt.finalize();
    try stmt.bindInt(1, fn_id);

    // Collect rows so we can do a separate ancestor query without nesting
    // active statement scans.
    const Row = struct {
        callee_id: ?i64,
        call_kind: []const u8,
        ast_node_id: ?i64,
        site_line: i64,
        callee_name: ?[]const u8,
    };
    var rows = std.ArrayList(Row){};
    defer {
        for (rows.items) |r| {
            al.free(r.call_kind);
            if (r.callee_name) |n| al.free(n);
        }
        rows.deinit(al);
    }
    while (try stmt.step()) {
        const callee_id_raw = stmt.columnInt(0);
        const has_callee = (sqlite.c.sqlite3_column_type(stmt.raw, 0) != sqlite.c.SQLITE_NULL);
        const call_kind = stmt.columnText(1) orelse "?";
        const has_ast = (sqlite.c.sqlite3_column_type(stmt.raw, 2) != sqlite.c.SQLITE_NULL);
        const ast_node_id = stmt.columnInt(2);
        const site_line = stmt.columnInt(3);
        const callee_name = stmt.columnText(4);
        try rows.append(al, .{
            .callee_id = if (has_callee) callee_id_raw else null,
            .call_kind = try al.dupe(u8, call_kind),
            .ast_node_id = if (has_ast) ast_node_id else null,
            .site_line = site_line,
            .callee_name = if (callee_name) |n| try al.dupe(u8, n) else null,
        });
    }

    // Track the most recent ancestor "block group" so we don't print the
    // same control-flow header twice in a row. The schema's ast_edge.role
    // gives us "then"/"else"/"condition"/"body" tags that distinguish
    // arms; we use them to emit branch markers.
    var prev_block: i64 = -1;
    for (rows.items) |r| {
        // Ancestor walk: collect nearest enclosing if/else/while/for/
        // switch_prong/block. We walk via ast_edge upward, capping at 8.
        var marker_buf = std.ArrayList(u8){};
        defer marker_buf.deinit(al);
        var owning_block: i64 = -1;
        if (r.ast_node_id) |aid| {
            try collectControlMarkers(entry, al, aid, &marker_buf, &owning_block);
        }
        if (owning_block != prev_block and marker_buf.items.len > 0) {
            try writeIndent(out, al, depth + 1);
            try out.appendSlice(al, marker_buf.items);
            try out.append(al, '\n');
            prev_block = owning_block;
        }

        // Filter rules.
        if (r.callee_name) |cn| {
            if (flags.hide_assertions and isAssertion(cn)) continue;
            if (flags.hide_debug and isDebug(cn)) {
                try writeIndent(out, al, depth + 1);
                try std.fmt.format(out.writer(al), "%{s}\n", .{cn});
                continue;
            }
            if (flags.hide_library and isLibrary(cn)) {
                try writeIndent(out, al, depth + 1);
                try std.fmt.format(out.writer(al), "={s}\n", .{cn});
                continue;
            }
        }

        // Indirect / unresolved.
        if (r.callee_id == null) {
            try writeIndent(out, al, depth + 1);
            const tag: u8 = if (std.mem.eql(u8, r.call_kind, "indirect") or
                std.mem.eql(u8, r.call_kind, "vtable")) '&' else '!';
            const nm = r.callee_name orelse "<unresolved>";
            try std.fmt.format(out.writer(al), "{c}{s}\n", .{ tag, nm });
            continue;
        }

        // Recurse.
        const cname = r.callee_name orelse "<anon>";
        if (depth + 2 >= max_depth) {
            // Capped marker.
            try writeIndent(out, al, depth + 1);
            try std.fmt.format(out.writer(al), "^{s}\n", .{cname});
            continue;
        }
        try traceWalk(entry, al, out, r.callee_id.?, cname, depth + 1, max_depth, visited, flags);
    }
}

fn collectControlMarkers(
    entry: *DbEntry,
    al: std.mem.Allocator,
    ast_node_id: i64,
    buf: *std.ArrayList(u8),
    owning_block: *i64,
) !void {
    // Walk parent chain. We climb at most 8 levels — any deeper and the
    // markers become noise.
    var cur: i64 = ast_node_id;
    var i: u32 = 0;
    while (i < 8) {
        var stmt = try entry.db.prepare(
            \\SELECT a.id, a.kind, a.parent_id, ae.role
            \\  FROM ast_node a
            \\  LEFT JOIN ast_edge ae ON ae.child_id = a.id
            \\ WHERE a.id = ?
            \\ LIMIT 1
        , al);
        defer stmt.finalize();
        try stmt.bindInt(1, cur);
        if (!try stmt.step()) return;
        const kind = stmt.columnText(1) orelse return;
        const parent_t = sqlite.c.sqlite3_column_type(stmt.raw, 2);
        const parent_id: ?i64 = if (parent_t == sqlite.c.SQLITE_NULL) null else stmt.columnInt(2);
        const role = stmt.columnText(3);

        if (std.mem.eql(u8, kind, "if")) {
            if (buf.items.len > 0) try buf.append(al, ' ');
            try buf.appendSlice(al, "?if");
            owning_block.* = cur;
        } else if (std.mem.eql(u8, kind, "else")) {
            if (buf.items.len > 0) try buf.append(al, ' ');
            try buf.appendSlice(al, "?else");
            owning_block.* = cur;
        } else if (std.mem.eql(u8, kind, "while") or std.mem.eql(u8, kind, "for")) {
            if (buf.items.len > 0) try buf.append(al, ' ');
            try buf.append(al, '*');
            try buf.appendSlice(al, kind);
            owning_block.* = cur;
        } else if (std.mem.eql(u8, kind, "switch_prong")) {
            if (buf.items.len > 0) try buf.append(al, ' ');
            try buf.appendSlice(al, ">prong");
            if (role) |r| if (r.len > 0) {
                try buf.append(al, ':');
                try buf.appendSlice(al, r);
            };
            owning_block.* = cur;
        }
        if (parent_id == null) break;
        cur = parent_id.?;
        i += 1;
    }
}

fn writeIndent(out: *std.ArrayList(u8), al: std.mem.Allocator, depth: u32) !void {
    var n: u32 = 0;
    while (n < depth) {
        try out.appendSlice(al, "  ");
        n += 1;
    }
}

fn isDebug(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "debug.") or
        std.mem.indexOf(u8, name, ".debug.") != null;
}

fn isLibrary(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "std.") or
        std.mem.startsWith(u8, name, "builtin.");
}

fn isAssertion(name: []const u8) bool {
    return std.mem.eql(u8, name, "debug.assert") or
        std.mem.startsWith(u8, name, "debug.FullPanic.") or
        std.mem.eql(u8, name, "builtin.returnError");
}

const RegHit = enum { none, src, dst };

fn matchRegInOps(reg: []const u8, ops: []const u8) RegHit {
    // Operands look like `rax, [rbx+8]` — first operand = dst (intel syntax).
    var first = true;
    var it = std.mem.tokenizeAny(u8, ops, ",[] +*-");
    var saw_match = false;
    while (it.next()) |tok| {
        var lower_buf: [16]u8 = undefined;
        if (tok.len >= lower_buf.len) {
            first = false;
            continue;
        }
        const lower = std.ascii.lowerString(&lower_buf, tok);
        if (regAliasMatch(reg, lower)) {
            if (first) return .dst;
            saw_match = true;
        }
        first = false;
    }
    return if (saw_match) .src else .none;
}

fn regAliasMatch(canonical: []const u8, candidate: []const u8) bool {
    // The query register normalised to lowercase. Common width aliases:
    //   rax|eax|ax|ah|al
    //   xmm0|ymm0|zmm0   (and the rest of 0..15)
    //   r10|r10d|r10w|r10b  (and 8..15)
    if (std.mem.eql(u8, canonical, candidate)) return true;
    // GP family.
    const Group = struct { a: []const u8, b: []const u8, c: []const u8, d: []const u8, e: []const u8 };
    const gps = [_]Group{
        .{ .a = "rax", .b = "eax", .c = "ax", .d = "ah", .e = "al" },
        .{ .a = "rbx", .b = "ebx", .c = "bx", .d = "bh", .e = "bl" },
        .{ .a = "rcx", .b = "ecx", .c = "cx", .d = "ch", .e = "cl" },
        .{ .a = "rdx", .b = "edx", .c = "dx", .d = "dh", .e = "dl" },
    };
    for (gps) |g| {
        const fields = [_][]const u8{ g.a, g.b, g.c, g.d, g.e };
        var canon_in = false;
        var cand_in = false;
        for (fields) |f| {
            if (std.mem.eql(u8, canonical, f)) canon_in = true;
            if (std.mem.eql(u8, candidate, f)) cand_in = true;
        }
        if (canon_in and cand_in) return true;
    }
    // SIMD family — same numeric suffix counts as alias.
    const simd_prefixes = [_][]const u8{ "xmm", "ymm", "zmm" };
    for (simd_prefixes) |sp| {
        if (std.mem.startsWith(u8, canonical, sp)) {
            const num = canonical[sp.len..];
            for (simd_prefixes) |op| {
                if (std.mem.startsWith(u8, candidate, op) and std.mem.eql(u8, candidate[op.len..], num))
                    return true;
            }
        }
    }
    // r8..r15 family.
    if (std.mem.startsWith(u8, canonical, "r") and canonical.len >= 2 and
        std.ascii.isDigit(canonical[1]))
    {
        const stripped = stripRsuffix(canonical);
        const cand_stripped = stripRsuffix(candidate);
        if (std.mem.eql(u8, stripped, cand_stripped)) return true;
    }
    return false;
}

fn stripRsuffix(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    const last = s[s.len - 1];
    if (last == 'd' or last == 'w' or last == 'b') return s[0 .. s.len - 1];
    return s;
}

const Entity = struct {
    id: i64,
    kind: []const u8,
    qualified_name: []const u8,
    def_file_id: i64,
    def_byte_start: i64,
    def_byte_end: i64,
    def_line: i64,
    def_col: i64,
    generic_parent_id: ?i64,
    is_ast_only: bool,
};

fn readEntityOwned(stmt: *sqlite.Stmt, al: std.mem.Allocator) !Entity {
    // Dupe sqlite-borrowed strings — `Entity` outlives the `Stmt` it came
    // from (the caller's `defer stmt.finalize()` invalidates these slices).
    const kind_raw = stmt.columnText(1) orelse "";
    const qname_raw = stmt.columnText(2) orelse "";
    return .{
        .id = stmt.columnInt(0),
        .kind = try al.dupe(u8, kind_raw),
        .qualified_name = try al.dupe(u8, qname_raw),
        .def_file_id = stmt.columnInt(3),
        .def_byte_start = stmt.columnInt(4),
        .def_byte_end = stmt.columnInt(5),
        .def_line = stmt.columnInt(6),
        .def_col = stmt.columnInt(7),
        .generic_parent_id = if (sqlite.c.sqlite3_column_type(stmt.raw, 8) == sqlite.c.SQLITE_NULL)
            null
        else
            stmt.columnInt(8),
        .is_ast_only = stmt.columnInt(9) != 0,
    };
}

fn metaValue(db: *sqlite.Db, gpa: std.mem.Allocator, key: []const u8) ![]u8 {
    var stmt = try db.prepare("SELECT value FROM meta WHERE key = ?", gpa);
    defer stmt.finalize();
    try stmt.bindText(1, key);
    if (!try stmt.step()) return try gpa.dupe(u8, "?");
    const v = stmt.columnText(0) orelse "";
    return gpa.dupe(u8, v);
}

fn filePath(entry: *DbEntry, al: std.mem.Allocator, file_id: i64) ![]u8 {
    var stmt = try entry.db.prepare("SELECT path FROM file WHERE id = ?", al);
    defer stmt.finalize();
    try stmt.bindInt(1, file_id);
    if (!try stmt.step()) return al.dupe(u8, "?");
    return al.dupe(u8, stmt.columnText(0) orelse "?");
}

fn lookupQname(entry: *DbEntry, al: std.mem.Allocator, id: i64) ![]u8 {
    var stmt = try entry.db.prepare("SELECT qualified_name FROM entity WHERE id = ?", al);
    defer stmt.finalize();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return al.dupe(u8, "?");
    return al.dupe(u8, stmt.columnText(0) orelse "?");
}

fn renderModulesOut(al: std.mem.Allocator, out: *std.ArrayList(u8), rows: anytype) !void {
    var current_src: []const u8 = "";
    for (rows) |r| {
        if (!std.mem.eql(u8, current_src, r.src)) {
            try std.fmt.format(out.writer(al), "{s}\n", .{r.src});
            current_src = r.src;
        }
        try std.fmt.format(out.writer(al), "  -> {s} ({d})\n", .{ r.dst, r.cnt });
    }
}

fn renderModulesIn(al: std.mem.Allocator, out: *std.ArrayList(u8), rows: anytype) !void {
    // Group by dst — re-sort the array logically by collecting per dst.
    const Row = @TypeOf(rows[0]);
    var sorted = std.ArrayList(Row){};
    defer sorted.deinit(al);
    try sorted.appendSlice(al, rows);
    std.mem.sort(Row, sorted.items, {}, struct {
        fn lt(_: void, a: Row, b: Row) bool {
            const c = std.mem.order(u8, a.dst, b.dst);
            if (c != .eq) return c == .lt;
            return a.cnt > b.cnt;
        }
    }.lt);
    var current_dst: []const u8 = "";
    for (sorted.items) |r| {
        if (!std.mem.eql(u8, current_dst, r.dst)) {
            try std.fmt.format(out.writer(al), "{s}\n", .{r.dst});
            current_dst = r.dst;
        }
        try std.fmt.format(out.writer(al), "  <- {s} ({d})\n", .{ r.src, r.cnt });
    }
}

// ----------------------------------------------------------- json helpers

fn jsonString(v: std.json.Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const got = v.object.get(key) orelse return null;
    if (got != .string) return null;
    return got.string;
}

fn jsonInt(v: std.json.Value, key: []const u8) ?i64 {
    if (v != .object) return null;
    const got = v.object.get(key) orelse return null;
    return switch (got) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

fn jsonBoolDefault(v: std.json.Value, key: []const u8, default: bool) bool {
    if (v != .object) return default;
    const got = v.object.get(key) orelse return default;
    return switch (got) {
        .bool => |b| b,
        else => default,
    };
}
