//! Arch-layering analyzer over the per-(arch, commit_sha) callgraph DB.
//!
//! Replaces the grep-based `stage_arch_layering_lint` in tests/precommit.sh
//! with a token-aware analyzer. The Zag kernel has a strict three-tier
//! dispatch architecture documented in CLAUDE.md:
//!
//!     generic kernel code  ↔  zag.arch.dispatch  ↔  zag.arch.{x64,aarch64}
//!         (kernel/**)         (kernel/arch/dispatch/)   (kernel/arch/x64/, kernel/arch/aarch64/)
//!
//! Two violations:
//!
//!   1. Up-leak — code under kernel/arch/x64/ or kernel/arch/aarch64/
//!      reaches into `zag.arch.dispatch.*`. Arch implementations live
//!      *underneath* the dispatch boundary, so a backend reaching upward
//!      means the boundary is being inverted.
//!
//!   2. Down-leak — code outside kernel/arch/ reaches into
//!      `zag.arch.x64.*` or `zag.arch.aarch64.*`. Generic code must
//!      traverse `zag.arch.dispatch.*` to reach the per-arch backend.
//!
//! ─── What this analyzer catches ────────────────────────────────────────
//!
//!   • Direct chain references in any context (file-level decls, function
//!     bodies, struct-field initializers, anywhere else).
//!     e.g. `const t = zag.arch.dispatch.time;` from arch/x64/.
//!     e.g. `lapic: zag.arch.x64.kvm.lapic.Lapic = .{},` from kernel/capdom/.
//!
//!   • Single-step alias expansion. Given a file-local
//!     `const NAME = zag.arch[.<seg>...]` decl, any later chain rooted at
//!     NAME is re-expanded and checked against the rules.
//!     e.g.
//!         const arch = zag.arch;
//!         const dispatch = arch.dispatch.cpu;   ← still flagged under x64/
//!
//! ─── What this analyzer punts on ───────────────────────────────────────
//!
//!   • Multi-hop alias chains across files (`pub const X = a.b.C;`
//!     re-export through index files into another file's import). The
//!     `const_alias` table in the DB resolves such chains entity-wise,
//!     but for the layering rule we'd need to know the *path through
//!     namespaces* not the terminal entity, and the indexer doesn't
//!     materialize that. Reaching the deeper transitive case requires
//!     either a per-file qname-prefix table or an AST walk that resolves
//!     each member-access through the import graph; both are
//!     follow-up work.
//!
//!   • Index files that re-export `pub const dispatch = @import(...);` —
//!     since `kernel/arch/arch.zig` itself sits under `arch/`, its
//!     re-exports are unconstrained. A generic-side use of
//!     `zag.arch.x64.foo` is still caught at the use-site (the chain
//!     starts at `zag.arch`).
//!
//!   • `@import("zag")` rebound to a non-`zag` name. The chain detector
//!     keys on the literal identifier `zag`; a file that does
//!     `const z = @import("zag"); const t = z.arch.x64.foo;` would slip
//!     through. The Zag style mandates `const zag = @import("zag");` so
//!     this is acceptable in practice; future hardening could record any
//!     `const X = @import("zag")` and treat X as a synonym.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const sqlite = @import("sqlite.zig");

// ─── Per-file classification ──────────────────────────────────────────

const FileClass = enum {
    /// `kernel/arch/dispatch/*` — the boundary itself; may reach into
    /// either backend, may reach generic. No layering check applies.
    dispatch,
    /// `kernel/arch/x64/**` — must not reach `zag.arch.dispatch.*`.
    arch_x64,
    /// `kernel/arch/aarch64/**` — same constraint as `arch_x64`.
    arch_aarch64,
    /// `kernel/**` (excluding `kernel/arch/**`) and `bootloader/**` —
    /// must not reach `zag.arch.x64.*` or `zag.arch.aarch64.*`.
    generic,
    /// Tests, redteam, tools, and sub-projects (routerOS/hyprvOS) — not
    /// subject to the kernel's three-tier rule. Skipped entirely.
    out_of_scope,
};

fn classifyFile(path: []const u8) FileClass {
    // tests/, redteam/, tools/ are out-of-scope wherever they live.
    if (mem.indexOf(u8, path, "/tests/") != null) return .out_of_scope;
    if (mem.indexOf(u8, path, "/redteam/") != null) return .out_of_scope;
    if (mem.startsWith(u8, path, "tests/")) return .out_of_scope;
    if (mem.startsWith(u8, path, "redteam/")) return .out_of_scope;
    if (mem.startsWith(u8, path, "tools/")) return .out_of_scope;
    // Sub-projects — separate libz, separate three-tier rules don't apply.
    if (mem.startsWith(u8, path, "routerOS/")) return .out_of_scope;
    if (mem.startsWith(u8, path, "hyprvOS/")) return .out_of_scope;
    if (mem.startsWith(u8, path, "desktopOS/")) return .out_of_scope;

    // Bootloader is `bootloader/`-prefixed in the DB and is generic-
    // tier from the layering POV.
    if (mem.startsWith(u8, path, "bootloader/")) return .generic;

    // The DB stores kernel paths without a `kernel/` prefix.
    if (mem.startsWith(u8, path, "arch/dispatch/") or
        mem.eql(u8, path, "arch/dispatch.zig"))
    {
        return .dispatch;
    }
    if (mem.startsWith(u8, path, "arch/x64/")) return .arch_x64;
    if (mem.startsWith(u8, path, "arch/aarch64/")) return .arch_aarch64;
    // The arch index file itself (`arch/arch.zig`) is under arch/ but
    // not under any backend; treat as dispatch-tier (it re-exports
    // both backends + dispatch).
    if (mem.startsWith(u8, path, "arch/")) return .dispatch;

    return .generic;
}

// ─── Token model ──────────────────────────────────────────────────────

const Token = struct {
    idx: u32,
    kind: []const u8,
    byte_start: u32,
    text: []const u8,
};

const FileRow = struct {
    id: i64,
    path: []const u8,
};

// Maps a file-local alias name to the prefix-path it expands to,
// where the prefix is rooted at `zag`. Only aliases whose RHS chain
// starts at `zag` and never breaks out of the chain are recorded; this
// keeps the reasoning sound (every use of NAME re-expands to the same
// dotted path).
const Alias = struct {
    /// Local identifier (LHS of the `const NAME = ...` decl).
    name: []const u8,
    /// Dotted segments after `zag.`. e.g. `["arch","dispatch"]` for
    /// `const arch_disp = zag.arch.dispatch;`. May be empty for
    /// `const z = zag;` (records that `z.arch.dispatch.*` is also a
    /// chain we have to check).
    segments: []const []const u8,
};

// ─── Findings ─────────────────────────────────────────────────────────

const Severity = enum { up_leak, down_leak };

const Finding = struct {
    file_id: i64,
    file_path: []const u8,
    line: u32,
    byte_start: u32,
    severity: Severity,
    /// The fully-expanded chain we found, joined with `.`. Always
    /// starts with `zag.arch.<dispatch|x64|aarch64>...`.
    chain: []const u8,
    /// "direct" (user wrote the literal `zag.arch.<...>` chain) or
    /// "alias:<name>" (the chain came from expanding a file-local
    /// alias).
    via: []const u8,
};

fn ruleFor(sev: Severity) []const u8 {
    return switch (sev) {
        .up_leak => "up_leak_arch_to_dispatch",
        .down_leak => "down_leak_generic_to_arch",
    };
}

fn severityLabel(sev: Severity) []const u8 {
    return switch (sev) {
        .up_leak => "UP-LEAK",
        .down_leak => "DOWN-LEAK",
    };
}

// ─── Token loading ────────────────────────────────────────────────────

fn loadFiles(a: Allocator, db: *sqlite.Db) ![]FileRow {
    var stmt = try db.prepare(
        "SELECT id, path FROM file ORDER BY path",
        a,
    );
    defer stmt.finalize();
    var out: ArrayList(FileRow) = .{};
    while (try stmt.step()) {
        const id = stmt.columnInt(0);
        const path = stmt.columnText(1) orelse continue;
        try out.append(a, .{
            .id = id,
            .path = try a.dupe(u8, path),
        });
    }
    return out.toOwnedSlice(a);
}

fn loadFileTokens(a: Allocator, db: *sqlite.Db, file_id: i64) ![]Token {
    var stmt = try db.prepare(
        "SELECT idx, kind, byte_start, text FROM token WHERE file_id = ? ORDER BY idx",
        a,
    );
    defer stmt.finalize();
    try stmt.bindInt(1, file_id);
    var out: ArrayList(Token) = .{};
    while (try stmt.step()) {
        const idx: u32 = @intCast(stmt.columnInt(0));
        const kind = stmt.columnText(1) orelse continue;
        const byte_start: u32 = @intCast(stmt.columnInt(2));
        const text = stmt.columnText(3) orelse "";
        try out.append(a, .{
            .idx = idx,
            .kind = try a.dupe(u8, kind),
            .byte_start = byte_start,
            .text = try a.dupe(u8, text),
        });
    }
    return out.toOwnedSlice(a);
}

// Map (file_id, byte_start) → 1-indexed line via file_line_index.
fn lineForByte(a: Allocator, db: *sqlite.Db, file_id: i64, byte_start: u32) !u32 {
    var stmt = try db.prepare(
        "SELECT line FROM file_line_index WHERE file_id = ? AND byte_start <= ? ORDER BY byte_start DESC LIMIT 1",
        a,
    );
    defer stmt.finalize();
    try stmt.bindInt(1, file_id);
    try stmt.bindInt(2, @intCast(byte_start));
    if (try stmt.step()) {
        return @intCast(stmt.columnInt(0));
    }
    return 1;
}

// ─── Chain extraction ─────────────────────────────────────────────────

/// A `(identifier, period, identifier, period, ...)` chain anchored at
/// the first identifier token. `start_idx` is the index of the anchor
/// identifier in the file's token stream, `segments` are the identifier
/// texts in order (the anchor itself is segments[0]).
const Chain = struct {
    start_idx: u32,
    byte_start: u32,
    segments: []const []const u8,
};

fn extractChain(a: Allocator, toks: []const Token, anchor_i: usize) !Chain {
    var segs: ArrayList([]const u8) = .{};
    try segs.append(a, toks[anchor_i].text);
    var i = anchor_i + 1;
    while (i + 1 < toks.len) {
        if (!mem.eql(u8, toks[i].kind, "period")) break;
        if (!mem.eql(u8, toks[i + 1].kind, "identifier")) break;
        try segs.append(a, toks[i + 1].text);
        i += 2;
    }
    return .{
        .start_idx = toks[anchor_i].idx,
        .byte_start = toks[anchor_i].byte_start,
        .segments = try segs.toOwnedSlice(a),
    };
}

// ─── Alias collection (single-step) ───────────────────────────────────

/// Recognize  `const NAME = <chain>;`  where <chain> is anchored at the
/// identifier `zag` and consists of `identifier ('.' identifier)*`. Any
/// non-`zag`-anchored RHS, any `@import(...)` call, and any chain that
/// breaks the `period identifier` pattern is rejected (returns null).
///
/// Returned alias.segments holds the dotted suffix after `zag` (so
/// `const a = zag;` yields `[]`, `const a = zag.arch;` yields `["arch"]`,
/// `const a = zag.arch.dispatch;` yields `["arch","dispatch"]`).
fn parseAliasDecl(a: Allocator, toks: []const Token, decl_i: usize) !?Alias {
    // Expected token shape:
    //   keyword_const  identifier  equal  identifier("zag")  (period identifier)*  semicolon
    if (decl_i + 4 >= toks.len) return null;
    if (!mem.eql(u8, toks[decl_i].kind, "keyword_const")) return null;
    if (!mem.eql(u8, toks[decl_i + 1].kind, "identifier")) return null;
    if (!mem.eql(u8, toks[decl_i + 2].kind, "equal")) return null;
    if (!mem.eql(u8, toks[decl_i + 3].kind, "identifier")) return null;
    if (!mem.eql(u8, toks[decl_i + 3].text, "zag")) return null;

    const name = toks[decl_i + 1].text;

    var segs: ArrayList([]const u8) = .{};
    var i = decl_i + 4;
    while (i + 1 < toks.len) {
        if (mem.eql(u8, toks[i].kind, "semicolon")) {
            return .{ .name = name, .segments = try segs.toOwnedSlice(a) };
        }
        if (!mem.eql(u8, toks[i].kind, "period")) {
            // Anything else after the chain (e.g. a call, a type
            // ascription) means this isn't a clean alias decl.
            return null;
        }
        if (!mem.eql(u8, toks[i + 1].kind, "identifier")) return null;
        try segs.append(a, toks[i + 1].text);
        i += 2;
    }
    return null;
}

// ─── Main scan ────────────────────────────────────────────────────────

const Policy = struct {
    cls: FileClass,

    /// Apply layering rules to a fully-expanded chain rooted at `zag`.
    /// `zag_segments` is the path *after* the leading `zag` — e.g.
    /// `["arch","dispatch","time"]` for `zag.arch.dispatch.time`.
    /// Returns the violation kind (or null if clean).
    fn check(self: Policy, zag_segments: []const []const u8) ?Severity {
        // Need at least `arch.<something>` to matter.
        if (zag_segments.len < 2) return null;
        if (!mem.eql(u8, zag_segments[0], "arch")) return null;
        const second = zag_segments[1];

        switch (self.cls) {
            .arch_x64, .arch_aarch64 => {
                if (mem.eql(u8, second, "dispatch")) return .up_leak;
                return null;
            },
            .generic => {
                if (mem.eql(u8, second, "x64") or mem.eql(u8, second, "aarch64")) {
                    return .down_leak;
                }
                return null;
            },
            .dispatch, .out_of_scope => return null,
        }
    }
};

fn scanFile(
    a: Allocator,
    db: *sqlite.Db,
    file: FileRow,
    out: *ArrayList(Finding),
) !void {
    const cls = classifyFile(file.path);
    if (cls == .out_of_scope) return;
    // dispatch-tier files aren't subject to the rule — but we still
    // need to walk them? No: nothing here fires for .dispatch, skip.
    if (cls == .dispatch) return;

    const policy = Policy{ .cls = cls };
    const toks = try loadFileTokens(a, db, file.id);
    if (toks.len == 0) return;

    // Pass 1: collect file-local aliases that root at `zag`.
    var aliases: std.StringHashMap(Alias) = .init(a);
    {
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            // Only treat `const` decls at brace_depth==0 as alias decls?
            // The DB token table doesn't expose brace_depth on every row
            // here (we didn't fetch it), and Zag style mandates all
            // `const` imports/aliases sit at file scope anyway. Treating
            // every `const NAME = zag…;` as an alias is safe — a
            // function-local rebinding of `zag` is rare and would
            // simply mean we expand more chains, which never produces
            // a *false* positive (the expanded chain still has to
            // start with `zag`).
            if (!mem.eql(u8, toks[i].kind, "keyword_const")) continue;
            const alias = try parseAliasDecl(a, toks, i) orelse continue;
            // Don't re-record `zag` itself.
            if (mem.eql(u8, alias.name, "zag")) continue;
            try aliases.put(alias.name, alias);
        }
    }

    // Pass 2: walk every identifier-anchored chain. Skip anchors that
    // sit immediately after a `period` (those are interior segments of
    // a chain we already started earlier). Also skip anchors that are
    // the LHS of a `const NAME = ...` decl — those are *defining* the
    // name, not *using* it, and the RHS will be scanned on its own
    // anchor (`zag`) so the chain still gets flagged.
    var i: usize = 0;
    while (i < toks.len) : (i += 1) {
        if (!mem.eql(u8, toks[i].kind, "identifier")) continue;
        if (i > 0 and mem.eql(u8, toks[i - 1].kind, "period")) continue;
        if (i >= 1 and i + 1 < toks.len and
            mem.eql(u8, toks[i - 1].kind, "keyword_const") and
            mem.eql(u8, toks[i + 1].kind, "equal"))
        {
            continue;
        }

        const anchor_text = toks[i].text;

        // Direct chain rooted at `zag`.
        var zag_suffix: ?[]const []const u8 = null;
        var via_label: []const u8 = "direct";

        if (mem.eql(u8, anchor_text, "zag")) {
            const chain = try extractChain(a, toks, i);
            zag_suffix = chain.segments[1..]; // drop leading `zag`
        } else if (aliases.get(anchor_text)) |alias| {
            // Aliased chain. Expand: alias.segments ++ remainder.
            const chain = try extractChain(a, toks, i);
            // alias.segments is the suffix-after-zag the alias represents.
            // chain.segments[0] is the anchor (== alias.name); discard.
            const remainder = chain.segments[1..];
            var combined: ArrayList([]const u8) = .{};
            try combined.appendSlice(a, alias.segments);
            try combined.appendSlice(a, remainder);
            zag_suffix = try combined.toOwnedSlice(a);
            via_label = try std.fmt.allocPrint(a, "alias:{s}", .{anchor_text});
        } else {
            continue;
        }

        const segs = zag_suffix.?;
        const sev_opt = policy.check(segs);
        if (sev_opt == null) continue;
        const sev = sev_opt.?;

        // Build display chain: `zag.<seg1>.<seg2>...` (no trailing dot).
        var chain_buf: ArrayList(u8) = .{};
        try chain_buf.appendSlice(a, "zag");
        for (segs) |s| {
            try chain_buf.append(a, '.');
            try chain_buf.appendSlice(a, s);
        }

        const line = try lineForByte(a, db, file.id, toks[i].byte_start);
        try out.append(a, .{
            .file_id = file.id,
            .file_path = file.path,
            .line = line,
            .byte_start = toks[i].byte_start,
            .severity = sev,
            .chain = try chain_buf.toOwnedSlice(a),
            .via = via_label,
        });
    }
}

// ─── Output + finding persistence ─────────────────────────────────────

fn lessFinding(_: void, a: Finding, b: Finding) bool {
    const c = mem.order(u8, a.file_path, b.file_path);
    if (c == .lt) return true;
    if (c == .gt) return false;
    if (a.line != b.line) return a.line < b.line;
    return a.byte_start < b.byte_start;
}

fn renderFindings(findings: []const Finding) !void {
    const stdout = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout.writer(&stdout_buf);
    const w = &stdout_writer.interface;

    var up: u32 = 0;
    var down: u32 = 0;
    for (findings) |f| {
        // Display path: prepend `kernel/` for kernel-relative paths so
        // the report matches the grep output's absolute-from-repo form.
        const display_path: []const u8 = if (mem.startsWith(u8, f.file_path, "bootloader/") or
            mem.startsWith(u8, f.file_path, "kernel/"))
            f.file_path
        else
            f.file_path; // we'll prefix manually below for clarity

        const needs_kernel_prefix = !mem.startsWith(u8, f.file_path, "bootloader/") and
            !mem.startsWith(u8, f.file_path, "kernel/");

        if (needs_kernel_prefix) {
            try w.print("kernel/{s}:{d}: {s} {s} (via {s})\n", .{
                display_path, f.line, severityLabel(f.severity), f.chain, f.via,
            });
        } else {
            try w.print("{s}:{d}: {s} {s} (via {s})\n", .{
                display_path, f.line, severityLabel(f.severity), f.chain, f.via,
            });
        }

        switch (f.severity) {
            .up_leak => up += 1,
            .down_leak => down += 1,
        }
    }
    try w.print("\nTotal: {d} up-leaks (arch → dispatch), {d} down-leaks (generic → arch).\n", .{ up, down });
    try w.flush();
}

fn writeFindingsToDb(
    a: Allocator,
    db_path: []const u8,
    findings: []const Finding,
) !void {
    var rwdb = try sqlite.Db.openReadWrite(db_path, a);
    defer rwdb.close();

    try rwdb.exec("BEGIN IMMEDIATE");
    errdefer rwdb.exec("ROLLBACK") catch {};

    {
        var del = try rwdb.prepare(
            "DELETE FROM lint_finding WHERE analyzer = 'arch_layering'",
            a,
        );
        defer del.finalize();
        _ = try del.step();
    }

    var ins = try rwdb.prepare(
        \\INSERT INTO lint_finding
        \\  (analyzer, severity, rule, entity_id, file_id, byte_start, byte_end, line, message, extra_json)
        \\VALUES ('arch_layering', 'err', ?1, NULL, ?2, ?3, ?3, ?4, ?5, ?6)
    , a);
    defer ins.finalize();

    for (findings) |f| {
        const message = try std.fmt.allocPrint(a, "{s} {s}", .{ severityLabel(f.severity), f.chain });
        defer a.free(message);
        const extra = try std.fmt.allocPrint(a, "{{\"via\":\"{s}\"}}", .{f.via});
        defer a.free(extra);

        ins.reset();
        try ins.bindText(1, ruleFor(f.severity));
        try ins.bindInt(2, f.file_id);
        try ins.bindInt(3, @intCast(f.byte_start));
        try ins.bindInt(4, @intCast(f.line));
        try ins.bindText(5, message);
        try ins.bindText(6, extra);
        _ = try ins.step();
    }

    try rwdb.exec("COMMIT");
}

// ─── Entry point ──────────────────────────────────────────────────────

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var args_it = std.process.args();
    _ = args_it.next();

    var db_path: ?[]const u8 = null;
    while (args_it.next()) |arg| {
        if (mem.eql(u8, arg, "--db")) {
            const v = args_it.next() orelse {
                _ = std.fs.File.stderr().write("--db requires a path\n") catch {};
                std.process.exit(2);
            };
            db_path = try a.dupe(u8, v);
        } else if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            const stdout = std.fs.File.stdout();
            _ = stdout.write(
                \\usage: check_arch_layering --db <path>
                \\
                \\Reads the per-(arch, commit_sha) callgraph DB and reports any
                \\violation of the kernel's three-tier dispatch rule:
                \\  - arch-specific code (kernel/arch/{x64,aarch64}/) reaching
                \\    into zag.arch.dispatch.* (UP-LEAK).
                \\  - generic code (kernel/**, bootloader/**) reaching into
                \\    zag.arch.{x64,aarch64}.* (DOWN-LEAK).
                \\
                \\Findings are also written to lint_finding (analyzer='arch_layering').
                \\Exits 1 when any violation is found, 0 otherwise.
                \\
            ) catch {};
            std.process.exit(0);
        } else {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "unknown flag: {s}\n", .{arg}) catch "unknown flag\n";
            _ = std.fs.File.stderr().write(msg) catch {};
            std.process.exit(2);
        }
    }

    if (db_path == null) {
        _ = std.fs.File.stderr().write("--db is required\n") catch {};
        std.process.exit(2);
    }

    var db = sqlite.Db.openReadOnly(db_path.?, a) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "failed to open DB: {s}\n", .{@errorName(err)}) catch "DB open error\n";
        _ = std.fs.File.stderr().write(msg) catch {};
        std.process.exit(2);
    };
    defer db.close();

    const files = try loadFiles(a, &db);

    var findings: ArrayList(Finding) = .{};
    for (files) |f| {
        try scanFile(a, &db, f, &findings);
    }

    std.mem.sort(Finding, findings.items, {}, lessFinding);
    try renderFindings(findings.items);

    // Persist findings to lint_finding so callgraph_findings/MCP queries
    // can serve them. Re-open R/W (current handle is read-only).
    db.close();
    writeFindingsToDb(a, db_path.?, findings.items) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "warning: failed to write lint_finding rows: {s}\n", .{@errorName(err)}) catch "warning: lint_finding write failed\n";
        _ = std.fs.File.stderr().write(msg) catch {};
    };

    if (findings.items.len > 0) std.process.exit(1);
}
