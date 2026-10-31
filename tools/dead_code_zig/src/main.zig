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
//! `hyprvOS/`, `bootloader/`. CLI is `--db <path> --target <name>`;
//! the positional form is removed (DB-only mode is a hard break).
//!
//! `--db` is repeatable. The first is the **primary**: skip-file
//! resolution, target-file scoping, and `lint_finding` writeback all
//! happen against it. Each additional `--db` is treated as an
//! **alt** DB whose alive-set augments the primary's. A finding is
//! emitted only when the entity is dead under EVERY DB's alive-set
//! (matched by `qualified_name`). This closes the cross-arch precision
//! gap: the per-pre-commit `x86_64-<sha>.db` cannot see aarch64 IR /
//! entry_reaches, so aarch64-only-reachable code falsely scored "dead"
//! under the lone x86_64 alive-set; passing the matching aarch64 DB as
//! a second `--db` lets its `ir_call` closure cover those entities.
//! All alt DBs must share the primary's `meta.commit_sha` (the
//! qualified-name match presumes one source-tree snapshot).
//!
//! Skip-file workflow ports verbatim from the old tool. Hash bytes come
//! from `file.source` so the analyzer is reproducible against an archived
//! DB without needing the matching git checkout.
//!
//! Skip-file format
//! ----------------
//!
//! Two anchor forms are supported. The symbol form is canonical; the
//! line-range form is preserved for legacy entries during migration but
//! is structurally fragile (see bd-Zag-Subsystems-Agents-na6c).
//!
//!   1. Symbol-anchored (preferred):
//!        entity:<file_path>::<qualified_name>    sha256:<hex>
//!
//!      `<file_path>` is the DB-canonical path (matches `file.path`,
//!      e.g. `arch/x64/apic.zig` or `libz/caps.zig`). `<qualified_name>`
//!      is the entity's `entity.qualified_name` column value (dotted
//!      module path, e.g. `sched.execution_context.State.dead`). The hash is
//!      over the entity's normalized source span (see Normalization
//!      below). Survives edits that shift the entity's line position;
//!      invalidates only on rename or content-mutation.
//!
//!   2. Line-range (legacy):
//!        <relpath>:<start>-<end>    sha256:<hex>
//!
//!      `<end>` may be the literal `end` for "to EOF". Hash is over the
//!      raw line bytes (joined by `\n`, terminating `\n`). Brittle in
//!      both directions: any upstream edit that shifts subsequent line
//!      numbers invalidates the SHA pin even when the anchored content
//!      is byte-identical, and any whitespace tweak on an anchored line
//!      invalidates it even when the entity is unchanged. Use SAS for
//!      new entries.
//!
//! Entity-content normalization (symbol form only)
//! -----------------------------------------------
//!
//! The hash bytes for a symbol-anchored entry are derived from
//! `file.source[def_byte_start..def_byte_end]` after the following
//! transformations, applied in order:
//!
//!   1. End-of-line normalization: `\r\n` and bare `\r` → `\n`.
//!   2. End-of-line `//` comments stripped (with `"…"` string-literal
//!      awareness; `\\` escape inside strings respected). Doc comments
//!      (`///`, `//!`) are stripped along with regular `//` comments —
//!      the principle is that comment churn must not invalidate the
//!      anchor.
//!   3. Trailing whitespace per line stripped (including the strip
//!      introduced by step 2).
//!   4. Empty lines dropped EVERYWHERE (not just trailing). Without
//!      this, adding a comment-only line inside a multi-line entity
//!      body would leave a residual empty line and change the hash —
//!      which would defeat the "comment churn must not invalidate"
//!      rule. With it, both the comment and the now-empty line drop out
//!      together.
//!   5. Lines joined with single `\n`. No terminating newline.
//!
//! The hash is then `sha256(normalized_bytes)`. This makes the anchor
//! invariant to: comment additions/removals, trailing-whitespace edits,
//! CRLF/LF flips, and trailing-blank-line nudges. It still detects:
//! renames, value changes, signature changes, body refactors.
//!
//! Lookup matching: a symbol-anchored entry suppresses any finding whose
//! `(file_path, qualified_name)` matches the entry. No line arithmetic
//! involved, so upstream comment / declaration / blank-line shifts do
//! not invalidate the suppression.

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
    /// Hash matches stored value — findings covered by this entry are silently dropped.
    hit,
    /// Hash mismatch — the entity's normalized content (or the line range
    /// for legacy entries) has drifted since last review.
    invalidated,
    /// Anchor target no longer resolves: file absent from the DB
    /// (line_range form) or no entity matches `(file_path, qualified_name)`
    /// (symbol form).
    missing,
    /// Range bounds are out of order, zero, or extend past EOF when end is numeric.
    /// (line_range form only.)
    bad_range,
};

const SkipKind = enum {
    /// Legacy `<file>:<start>-<end>` anchor. Brittle to upstream line
    /// shifts AND to whitespace edits on the anchored lines themselves.
    /// Preserved for migration; new entries should use `.symbol`.
    line_range,
    /// `entity:<file>::<qname>` anchor. Survives any edit that doesn't
    /// rename the entity or alter its normalized content.
    symbol,
};

const SkipEntry = struct {
    kind: SkipKind,
    /// .line_range: target-relative or DB-canonical path (resolved at
    ///              validation time via resolveSkipDbPaths).
    /// .symbol:     DB-canonical path (matches `file.path`).
    file_path: []const u8,
    /// .line_range only.
    start_line: u32 = 0,
    end_line: u32 = 0,
    end_is_eof: bool = false,
    /// .symbol only — `entity.qualified_name`.
    qualified_name: []const u8 = "",
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

/// Normalize an entity's def-span content per the rules in the top-of-file
/// doc comment, then return its sha256 as 64-char lowercase hex. Used by
/// symbol-anchored skip entries; keeps the hash invariant to comment churn,
/// trailing-whitespace edits, CRLF/LF flips, and trailing-blank-line nudges.
///
/// `body` is the raw bytes of `file.source[def_byte_start..def_byte_end]`.
fn hashEntityContent(a: Allocator, body: []const u8) ![Sha256.digest_length * 2]u8 {
    var buf: ArrayList(u8) = .{};
    defer buf.deinit(a);

    // Collect normalized lines into `lines`, then drop trailing blanks
    // and join with `\n` (no terminating newline).
    var lines: ArrayList([]u8) = .{};
    defer {
        for (lines.items) |s| a.free(s);
        lines.deinit(a);
    }

    var i: usize = 0;
    while (i <= body.len) {
        // Slice one logical line, advancing past the EOL.
        var line_end = i;
        while (line_end < body.len and body[line_end] != '\n' and body[line_end] != '\r') {
            line_end += 1;
        }
        const raw_line = body[i..line_end];

        var next = line_end;
        if (next < body.len) {
            if (body[next] == '\r') {
                next += 1;
                if (next < body.len and body[next] == '\n') next += 1;
            } else if (body[next] == '\n') {
                next += 1;
            }
        }

        // Strip end-of-line `//` comment (string-aware).
        var code_end: usize = raw_line.len;
        var in_string = false;
        var in_char = false;
        var k: usize = 0;
        while (k < raw_line.len) : (k += 1) {
            const ch = raw_line[k];
            if (!in_string and !in_char and ch == '/' and k + 1 < raw_line.len and raw_line[k + 1] == '/') {
                code_end = k;
                break;
            }
            if (!in_char and ch == '"') {
                in_string = !in_string;
            } else if (!in_string and ch == '\'') {
                in_char = !in_char;
            } else if ((in_string or in_char) and ch == '\\' and k + 1 < raw_line.len) {
                k += 1; // skip escaped char
            }
        }

        var trimmed = raw_line[0..code_end];
        // Strip trailing whitespace (introduced by code or unmasked by
        // comment strip).
        while (trimmed.len > 0 and (trimmed[trimmed.len - 1] == ' ' or trimmed[trimmed.len - 1] == '\t')) {
            trimmed = trimmed[0 .. trimmed.len - 1];
        }

        if (trimmed.len > 0) {
            const owned = try a.dupe(u8, trimmed);
            try lines.append(a, owned);
        }

        if (next == i and i >= body.len) break;
        i = next;
        if (i == body.len) {
            // Trailing newline at EOF — exit; an empty final line wouldn't
            // contribute under the drop-empty rule above anyway.
            break;
        }
    }

    // Join with `\n`.
    for (lines.items, 0..) |s, idx| {
        if (idx > 0) try buf.append(a, '\n');
        try buf.appendSlice(a, s);
    }

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(buf.items, &digest, .{});
    var hex: [Sha256.digest_length * 2]u8 = undefined;
    hexEncode(digest, &hex);
    return hex;
}

/// Resolve `(file_path, qualified_name)` to a unique entity row. Returns
/// the entity's def-span byte content (newly allocated) on hit; null on
/// miss. The DB's UNIQUE constraint is `(module_id, kind, qualified_name)`,
/// so two entities can share a `(file_path, qualified_name)` only across
/// `kind` (rare; e.g. a const struct + a field with the same name as the
/// struct on the same line). When that happens we pick the first row, which
/// is sufficient for the skip-list's "is this entity unchanged?" question
/// since renaming or mutating either entity will move def_byte_{start,end}.
fn fetchEntityBody(a: Allocator, db: *sqlite.Db, file_path: []const u8, qname: []const u8) !?[]u8 {
    var stmt = try db.prepare(
        \\SELECT substr(f.source, e.def_byte_start + 1, e.def_byte_end - e.def_byte_start)
        \\FROM entity e
        \\JOIN file f ON f.id = e.def_file_id
        \\WHERE f.path = ? AND e.qualified_name = ?
        \\ORDER BY e.id LIMIT 1
    , a);
    defer stmt.finalize();
    try stmt.bindText(1, file_path);
    try stmt.bindText(2, qname);
    if (try stmt.step()) {
        const blob = stmt.columnBlob(0) orelse return null;
        return try a.dupe(u8, blob);
    }
    return null;
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

    const sha_prefix = "sha256:";
    if (!mem.startsWith(u8, right, sha_prefix)) return error.SkipEntryMalformed;
    const hex = right[sha_prefix.len..];
    if (hex.len != Sha256.digest_length * 2) return error.SkipEntryMalformed;
    for (hex) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return error.SkipEntryMalformed;
    }
    const stored = try a.dupe(u8, hex);

    const sym_prefix = "entity:";
    if (mem.startsWith(u8, left, sym_prefix)) {
        // entity:<file>::<qname>
        const body = left[sym_prefix.len..];
        const sep = mem.indexOf(u8, body, "::") orelse return error.SkipEntryMalformed;
        const file_path = body[0..sep];
        const qname = body[sep + 2 ..];
        if (file_path.len == 0 or qname.len == 0) return error.SkipEntryMalformed;
        return SkipEntry{
            .kind = .symbol,
            .file_path = try a.dupe(u8, file_path),
            .qualified_name = try a.dupe(u8, qname),
            .stored_hash = stored,
        };
    }

    // Legacy line-range form.
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

    return SkipEntry{
        .kind = .line_range,
        .file_path = rel_path,
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

/// Compute current_hash for an entry against the DB's file/entity tables
/// and set `entry.status` accordingly.
fn validateSkipEntry(a: Allocator, entry: *SkipEntry, db: *sqlite.Db) !void {
    switch (entry.kind) {
        .line_range => {
            const candidates = try resolveSkipDbPaths(a, entry.file_path);
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
        },
        .symbol => {
            const body = try fetchEntityBody(a, db, entry.file_path, entry.qualified_name);
            if (body) |bytes| {
                const hex_buf = try hashEntityContent(a, bytes);
                const hex = try a.dupe(u8, &hex_buf);
                entry.current_hash = hex;
                entry.status = if (mem.eql(u8, hex, entry.stored_hash)) .hit else .invalidated;
            } else {
                entry.current_hash = "";
                entry.status = .missing;
            }
        },
    }
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

/// True iff a `hit` skip entry covers the given finding. `file_path` is
/// the DB-canonical path (as stored in `Finding.file_path`); `qname` is
/// the entity's qualified_name.
fn skipCovers(file_path: []const u8, line: u32, qname: []const u8) bool {
    // Normalize the line-range comparison path to drop a leading
    // `<g_target_rel>/` prefix when present (legacy entries are written
    // target-relative).
    var rel = file_path;
    if (g_target_rel.len > 0 and mem.startsWith(u8, rel, g_target_rel) and
        rel.len > g_target_rel.len and rel[g_target_rel.len] == '/')
    {
        rel = rel[g_target_rel.len + 1 ..];
    }
    for (g_skip_entries.items) |e| {
        if (e.status != .hit) continue;
        switch (e.kind) {
            .line_range => {
                if (!mem.eql(u8, e.file_path, rel)) continue;
                if (line < e.start_line) continue;
                if (!e.end_is_eof and line > e.end_line) continue;
                return true;
            },
            .symbol => {
                if (!mem.eql(u8, e.file_path, file_path)) continue;
                if (!mem.eql(u8, e.qualified_name, qname)) continue;
                return true;
            },
        }
    }
    return false;
}

fn reportSkipDiagnostics() !bool {
    const stderr = std.fs.File.stderr();
    var any = false;
    var buf: [1024]u8 = undefined;
    for (g_skip_entries.items) |e| {
        if (e.status == .hit) continue;
        any = true;
        const anchor = try formatSkipAnchor(&buf, e);
        switch (e.status) {
            .hit => unreachable,
            .invalidated => {
                var b2: [1024]u8 = undefined;
                const msg1 = try std.fmt.bufPrint(&b2, "INVALIDATED: {s}\n", .{anchor});
                _ = stderr.write(msg1) catch {};
                var b3: [256]u8 = undefined;
                const msg2 = try std.fmt.bufPrint(&b3, "  stored:  sha256:{s}\n", .{e.stored_hash});
                _ = stderr.write(msg2) catch {};
                var b4: [256]u8 = undefined;
                const msg3 = try std.fmt.bufPrint(&b4, "  current: sha256:{s}\n", .{e.current_hash});
                _ = stderr.write(msg3) catch {};
                var b5: [1024]u8 = undefined;
                const msg4 = switch (e.kind) {
                    .line_range => try std.fmt.bufPrint(&b5, "  The whitelisted range has changed since last review. Re-review and run\n  `dead_code_zig --update-skip {s}` to refresh.\n", .{anchor}),
                    .symbol => try std.fmt.bufPrint(&b5, "  The entity's normalized content has changed since last review. Re-review and run\n  `dead_code_zig --update-skip {s}` to refresh.\n", .{anchor}),
                };
                _ = stderr.write(msg4) catch {};
            },
            .missing => {
                var b2: [1024]u8 = undefined;
                const msg = switch (e.kind) {
                    .line_range => try std.fmt.bufPrint(&b2, "MISSING: {s}\n  File not found under {s}/. Remove the entry or restore the file.\n", .{ anchor, g_target_rel }),
                    .symbol => try std.fmt.bufPrint(&b2, "MISSING: {s}\n  No entity matches that (file, qualified_name) in the DB. Remove the entry or update its qname.\n", .{anchor}),
                };
                _ = stderr.write(msg) catch {};
            },
            .bad_range => {
                var b2: [1024]u8 = undefined;
                const msg = try std.fmt.bufPrint(&b2, "BAD-RANGE: {s}\n  Range invalid (start > end, start == 0, or end past EOF).\n", .{anchor});
                _ = stderr.write(msg) catch {};
            },
        }
    }
    return any;
}

/// Format an entry's anchor (the part before `sha256:`) into `buf`, returning
/// the slice. Used for diagnostic messages and `--update-skip` echo.
fn formatSkipAnchor(buf: []u8, e: SkipEntry) ![]u8 {
    return switch (e.kind) {
        .line_range => if (e.end_is_eof)
            try std.fmt.bufPrint(buf, "{s}:{d}-end", .{ e.file_path, e.start_line })
        else
            try std.fmt.bufPrint(buf, "{s}:{d}-{d}", .{ e.file_path, e.start_line, e.end_line }),
        .symbol => try std.fmt.bufPrint(buf, "entity:{s}::{s}", .{ e.file_path, e.qualified_name }),
    };
}

/// Implement `--update-skip <anchor>`. The anchor may be either a legacy
/// line-range form (`<rel-path>:<start>-<end>`) or a symbol-anchored form
/// (`entity:<file>::<qname>`). Reads the source/entity content from the DB,
/// computes a fresh normalized hash, and writes/updates the entry in the
/// on-disk skip file.
fn updateSkipEntry(a: Allocator, raw_arg: []const u8, skip_file: []const u8, db: *sqlite.Db) !u8 {
    const stderr = std.fs.File.stderr();

    var left_buf: [1024]u8 = undefined;
    var hex_holder: [Sha256.digest_length * 2]u8 = undefined;

    const left = blk: {
        const sym_prefix = "entity:";
        if (mem.startsWith(u8, raw_arg, sym_prefix)) {
            // Symbol-anchored form.
            const body = raw_arg[sym_prefix.len..];
            const sep = mem.indexOf(u8, body, "::") orelse {
                _ = stderr.write("--update-skip: expected entity:<file>::<qname>\n") catch {};
                return 2;
            };
            const file_path = body[0..sep];
            const qname = body[sep + 2 ..];
            if (file_path.len == 0 or qname.len == 0) {
                _ = stderr.write("--update-skip: empty file or qname in entity:<file>::<qname>\n") catch {};
                return 2;
            }
            const ent_body = (try fetchEntityBody(a, db, file_path, qname)) orelse {
                var b: [512]u8 = undefined;
                const msg = std.fmt.bufPrint(&b, "--update-skip: no entity found in DB for {s}::{s}\n", .{ file_path, qname }) catch return 2;
                _ = stderr.write(msg) catch {};
                return 2;
            };
            hex_holder = try hashEntityContent(a, ent_body);
            break :blk try std.fmt.bufPrint(&left_buf, "entity:{s}::{s}", .{ file_path, qname });
        }

        // Legacy line-range form.
        const colon = mem.lastIndexOfScalar(u8, raw_arg, ':') orelse {
            _ = stderr.write("--update-skip: expected <rel-path>:<start>-<end> or entity:<file>::<qname>\n") catch {};
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

        const candidates = try resolveSkipDbPaths(a, rel_path);
        var src_opt: ?[]u8 = null;
        for (candidates) |cand| {
            if (try fetchFileSource(a, db, cand)) |bytes| {
                src_opt = bytes;
                break;
            }
        }
        const text = src_opt orelse {
            var b: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&b, "--update-skip: file not found in DB: {s}\n", .{rel_path}) catch return 2;
            _ = stderr.write(msg) catch {};
            return 2;
        };

        const hex_opt = try hashLineRange(a, text, start_line, end_line, end_is_eof);
        hex_holder = hex_opt orelse {
            _ = stderr.write("--update-skip: invalid range for that file\n") catch {};
            return 2;
        };
        break :blk if (end_is_eof)
            try std.fmt.bufPrint(&left_buf, "{s}:{d}-end", .{ rel_path, start_line })
        else
            try std.fmt.bufPrint(&left_buf, "{s}:{d}-{d}", .{ rel_path, start_line, end_line });
    };

    const new_hex = &hex_holder;

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

/// Implement `--rewrite-skip`. Reads every line of the on-disk skip file,
/// transforms each legacy `<file>:<start>-<end>` entry into one or more
/// `entity:<file>::<qname>` entries (one per matching DB entity), preserves
/// comments and blank lines, and rewrites the file in place.
///
/// Already-symbol entries pass through with their stored hash recomputed
/// against the current DB content (so the rewrite also serves as a "rehash
/// every entry" pass for the post-edit DB).
///
/// Legacy entries with NO matching entity in the line range are dropped
/// with a stderr warning. These were already silent no-ops at the analyzer
/// level (the line referred to nothing the analyzer would emit a finding
/// for), so dropping them is safe; if the worker had intended to suppress
/// a real entity, the analyzer will surface it on the next run and a
/// fresh symbol-anchored entry can be added.
fn rewriteSkipFile(a: Allocator, skip_file: []const u8, db: *sqlite.Db) !u8 {
    const stderr = std.fs.File.stderr();

    // Read existing content (or fail loudly — there's no useful "rewrite"
    // to perform when the file is absent).
    const sf = fs.openFileAbsolute(skip_file, .{}) catch |err| {
        var b: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&b, "--rewrite-skip: failed to open {s}: {s}\n", .{ skip_file, @errorName(err) }) catch return 2;
        _ = stderr.write(msg) catch {};
        return 2;
    };
    defer sf.close();
    const sst = try sf.stat();
    const existing = try a.alloc(u8, sst.size);
    _ = try sf.readAll(existing);

    var out: ArrayList(u8) = .{};
    var line_no: u32 = 0;
    var rewrote: u32 = 0;
    var rehashed: u32 = 0;
    var dropped: u32 = 0;

    var it = mem.splitScalar(u8, existing, '\n');
    var first_line = true;
    var produced_anchors: std.StringHashMapUnmanaged(void) = .empty;

    while (it.next()) |raw| {
        line_no += 1;
        const line = raw;

        // Preserve comments and blank lines verbatim. Detect by parsing:
        // anything that doesn't yield a SkipEntry (and isn't malformed)
        // is a comment/blank — emit verbatim. Malformed entries we also
        // pass through (with a stderr warning) to keep the rewrite
        // non-destructive.
        const parsed = parseSkipLine(a, line) catch |err| {
            var b: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&b, "--rewrite-skip: {s}:{d}: malformed (kept verbatim): {s}\n", .{ skip_file, line_no, @errorName(err) }) catch null;
            if (msg) |m| _ = stderr.write(m) catch {};
            try emitLineVerbatim(a, &out, line, &first_line);
            continue;
        };

        if (parsed == null) {
            try emitLineVerbatim(a, &out, line, &first_line);
            continue;
        }
        const entry = parsed.?;

        switch (entry.kind) {
            .symbol => {
                // Recompute the hash against the current DB; if the entity
                // is gone, drop with warning.
                const body = try fetchEntityBody(a, db, entry.file_path, entry.qualified_name);
                if (body == null) {
                    var b: [512]u8 = undefined;
                    const msg = std.fmt.bufPrint(&b, "--rewrite-skip: dropping entry for missing entity: {s}::{s}\n", .{ entry.file_path, entry.qualified_name }) catch null;
                    if (msg) |m| _ = stderr.write(m) catch {};
                    dropped += 1;
                    continue;
                }
                const hex_buf = try hashEntityContent(a, body.?);
                try emitSymbolEntry(a, &out, entry.file_path, entry.qualified_name, &hex_buf, &first_line, &produced_anchors);
                rehashed += 1;
            },
            .line_range => {
                // Find every entity whose def_line falls in the range AND
                // whose def_byte_end stays within the file. Emit one symbol
                // entry per matched entity.
                const candidates = try resolveSkipDbPaths(a, entry.file_path);
                var resolved_path: ?[]const u8 = null;
                for (candidates) |cand| {
                    var s = try db.prepare("SELECT 1 FROM file WHERE path = ? LIMIT 1", a);
                    defer s.finalize();
                    try s.bindText(1, cand);
                    if (try s.step()) {
                        resolved_path = cand;
                        break;
                    }
                }
                if (resolved_path == null) {
                    var b: [512]u8 = undefined;
                    const msg = std.fmt.bufPrint(&b, "--rewrite-skip: dropping entry for missing file: {s}\n", .{entry.file_path}) catch null;
                    if (msg) |m| _ = stderr.write(m) catch {};
                    dropped += 1;
                    continue;
                }

                const end_line: u32 = if (entry.end_is_eof) std.math.maxInt(u32) else entry.end_line;
                var ent_stmt = try db.prepare(
                    \\SELECT e.qualified_name,
                    \\       substr(f.source, e.def_byte_start + 1, e.def_byte_end - e.def_byte_start),
                    \\       f.path
                    \\FROM entity e
                    \\JOIN file f ON f.id = e.def_file_id
                    \\WHERE f.path = ? AND e.def_line BETWEEN ? AND ?
                    \\ORDER BY e.def_byte_start, e.id
                , a);
                defer ent_stmt.finalize();
                try ent_stmt.bindText(1, resolved_path.?);
                try ent_stmt.bindInt(2, @intCast(entry.start_line));
                try ent_stmt.bindInt(3, @intCast(end_line));

                var matched: u32 = 0;
                while (try ent_stmt.step()) {
                    const qname = ent_stmt.columnText(0) orelse continue;
                    const body = ent_stmt.columnBlob(1) orelse continue;
                    const file_path = ent_stmt.columnText(2) orelse continue;
                    const hex_buf = try hashEntityContent(a, body);
                    try emitSymbolEntry(a, &out, file_path, qname, &hex_buf, &first_line, &produced_anchors);
                    matched += 1;
                }

                if (matched == 0) {
                    var b: [512]u8 = undefined;
                    const msg = std.fmt.bufPrint(&b, "--rewrite-skip: dropping line-range entry with no matching entity: {s}:{d}-{d}\n", .{ entry.file_path, entry.start_line, entry.end_line }) catch null;
                    if (msg) |m| _ = stderr.write(m) catch {};
                    dropped += 1;
                } else {
                    rewrote += 1;
                }
            },
        }
    }

    // Trailing newline parity with the reader: write back exactly what we
    // accumulated. parseSkipLine + the verbatim path keep the file's
    // newline-terminated convention intact.
    const tmp_path = try std.fmt.allocPrint(a, "{s}.tmp", .{skip_file});
    {
        const wf = try fs.createFileAbsolute(tmp_path, .{ .truncate = true });
        defer wf.close();
        try wf.writeAll(out.items);
    }
    try fs.renameAbsolute(tmp_path, skip_file);

    var sb: [256]u8 = undefined;
    const summary = std.fmt.bufPrint(&sb, "rewrite-skip: rewrote {d} legacy entries, rehashed {d} symbol entries, dropped {d} unmatched\n", .{ rewrote, rehashed, dropped }) catch return 0;
    const stdout = std.fs.File.stdout();
    _ = stdout.write(summary) catch {};
    return 0;
}

fn emitLineVerbatim(a: Allocator, out: *ArrayList(u8), line: []const u8, first_line: *bool) !void {
    if (!first_line.*) try out.append(a, '\n');
    first_line.* = false;
    try out.appendSlice(a, line);
}

fn emitSymbolEntry(
    a: Allocator,
    out: *ArrayList(u8),
    file_path: []const u8,
    qname: []const u8,
    hex: *const [Sha256.digest_length * 2]u8,
    first_line: *bool,
    seen: *std.StringHashMapUnmanaged(void),
) !void {
    var key_buf: [1024]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}::{s}", .{ file_path, qname }) catch return;
    if (seen.contains(key)) return; // dedupe across multiple line-range matches
    const owned_key = try a.dupe(u8, key);
    try seen.put(a, owned_key, {});

    if (!first_line.*) try out.append(a, '\n');
    first_line.* = false;
    var line_buf: [1024]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&line_buf, "entity:{s}::{s}    sha256:{s}", .{ file_path, qname, hex });
    try out.appendSlice(a, formatted);
}

fn defaultSkipPath(a: Allocator, repo_root: []const u8) ![]u8 {
    return joinPath(a, &.{ repo_root, "tools", "dead_code_zig", "skip.txt" });
}

// -----------------------------------------------------------------
// Analysis: alive-set CTE + dead-set query
// -----------------------------------------------------------------

const Finding = struct {
    file_path: []const u8,
    name: []const u8,
    parent: ?[]const u8,
    /// Full `entity.qualified_name`. Used as the cross-DB matching key
    /// when alt DBs augment the primary's alive-set — qnames are stable
    /// across the per-(arch, sha) DBs since the AST/walk passes are
    /// arch-agnostic.
    qname: []const u8,
    line: u32,
    kind_label: []const u8,
    byte_start: u32,
    byte_end: u32,
    entity_id: i64,
    file_id: i64,
};

/// Body of the alive-named CTE chain — shared between the findings query
/// (which prepends `target_files` and selects entities NOT in alive_named)
/// and `loadAliveQnames` (which selects DISTINCT qualified_names of every
/// alive entity for cross-DB augmentation). Callers prepare an
/// `entity_simple_name` temp table before referencing this; both
/// `field_names` and `alive_named` join against it.
const ALIVE_NAMED_CTES =
    \\  field_names(name) AS (
    \\    SELECT DISTINCT t2.text
    \\      FROM token t1
    \\      JOIN token t2 ON t2.file_id = t1.file_id AND t2.idx = t1.idx + 1
    \\     WHERE t1.kind = 'period' AND t2.kind = 'identifier'
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
;

/// Populate the `entity_simple_name` temp table both query paths use
/// (alive_named's heuristics join through it). Idempotent across calls
/// in case a caller invokes both `collectFindings` and
/// `loadAliveQnames` on the same connection.
fn setupEntitySimpleName(a: Allocator, db: *sqlite.Db) !void {
    try db.exec("CREATE TEMP TABLE IF NOT EXISTS entity_simple_name (entity_id INTEGER PRIMARY KEY, name TEXT NOT NULL)");
    // If the table already has rows we're done — second invocation on
    // the same connection (e.g. `--update-skip` then findings) skips the
    // expensive re-scan.
    {
        var s = try db.prepare("SELECT 1 FROM entity_simple_name LIMIT 1", a);
        defer s.finalize();
        if (try s.step()) return;
    }
    var sel = try db.prepare("SELECT id, qualified_name FROM entity", a);
    defer sel.finalize();
    var ins = try db.prepare("INSERT INTO entity_simple_name (entity_id, name) VALUES (?, ?)", a);
    defer ins.finalize();
    while (try sel.step()) {
        const id = sel.columnInt(0);
        const qname = sel.columnText(1) orelse continue;
        const simple = if (mem.lastIndexOfScalar(u8, qname, '.')) |i| qname[i + 1 ..] else qname;
        try ins.bindInt(1, id);
        try ins.bindText(2, simple);
        _ = try ins.step();
        _ = sqlite.c.sqlite3_reset(ins.raw);
        _ = sqlite.c.sqlite3_clear_bindings(ins.raw);
    }
    try db.exec("CREATE INDEX IF NOT EXISTS entity_simple_name_idx ON entity_simple_name(name)");
}

/// Run the alive-named CTE on `db` and insert every alive entity's
/// qualified_name into `out`. Used to merge alt-arch DBs' alive-sets
/// into the primary analyzer's "is this entity actually used anywhere"
/// decision, by qname (since entity IDs are not stable across DBs but
/// qnames are).
fn loadAliveQnames(
    a: Allocator,
    db: *sqlite.Db,
    out: *std.StringHashMapUnmanaged(void),
) !void {
    try setupEntitySimpleName(a, db);
    const sql = "WITH RECURSIVE\n" ++ ALIVE_NAMED_CTES ++
        "\nSELECT DISTINCT e.qualified_name FROM alive_named JOIN entity e ON e.id = alive_named.id";
    var stmt = try db.prepare(sql, a);
    defer stmt.finalize();
    while (try stmt.step()) {
        const qname = stmt.columnText(0) orelse continue;
        if (out.contains(qname)) continue;
        const dup = try a.dupe(u8, qname);
        try out.put(a, dup, {});
    }
}

/// Read a single `meta` row's value, NULL when absent.
fn fetchMeta(a: Allocator, db: *sqlite.Db, key: []const u8) !?[]u8 {
    var stmt = try db.prepare("SELECT value FROM meta WHERE key = ?", a);
    defer stmt.finalize();
    try stmt.bindText(1, key);
    if (try stmt.step()) {
        const v = stmt.columnText(0) orelse return null;
        return try a.dupe(u8, v);
    }
    return null;
}

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
    try setupEntitySimpleName(a, db);

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

    const sql = "WITH RECURSIVE\n" ++
        \\  target_files(id) AS (
        \\    SELECT id FROM target_files_tmp
        \\  ),
        \\
    ++ ALIVE_NAMED_CTES ++
        \\
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
            .qname = try a.dupe(u8, qname),
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

    var db_paths: std.ArrayList([]const u8) = .empty;
    var target_name: []const u8 = "kernel";
    var skip_override: ?[]const u8 = null;
    var update_arg: ?[]const u8 = null;
    var rewrite_skip = false;

    while (args_it.next()) |a| {
        if (mem.eql(u8, a, "--db")) {
            const v = args_it.next() orelse {
                _ = std.fs.File.stderr().write("--db requires a path\n") catch {};
                std.process.exit(2);
            };
            try db_paths.append(g_arena, try g_arena.dupe(u8, v));
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
                _ = std.fs.File.stderr().write("--update-skip requires <rel-path>:<start>-<end> or entity:<file>::<qname>\n") catch {};
                std.process.exit(2);
            };
            update_arg = try g_arena.dupe(u8, v);
        } else if (mem.eql(u8, a, "--rewrite-skip")) {
            rewrite_skip = true;
        } else if (mem.eql(u8, a, "--help") or mem.eql(u8, a, "-h")) {
            const stdout = std.fs.File.stdout();
            _ = stdout.write(
                \\usage: dead_code_zig --db <path> [--db <path>...] [--target <name>] [--skip <path>]
                \\                     [--update-skip <anchor>] [--rewrite-skip]
                \\
                \\Reads the per-(arch, commit_sha) callgraph DB and reports unused decls in the target dir.
                \\
                \\`--db` is repeatable. The first is the primary; additional DBs
                \\augment the alive-set by qualified_name (used to cover the
                \\cross-arch precision gap when the primary is x86_64-only).
                \\All DBs must share the same meta.commit_sha.
                \\
                \\Skip-file anchor forms (see top of src/main.zig for spec):
                \\  symbol:  entity:<file>::<qualified_name>    sha256:<hex>
                \\  legacy:  <relpath>:<start>-<end>            sha256:<hex>
                \\
                \\`--update-skip <anchor>` recomputes the SHA for one entry
                \\(adding it if missing); `<anchor>` accepts either form.
                \\
                \\`--rewrite-skip` migrates every legacy line-range entry in
                \\the skip file to symbol form, emitting one `entity:` line
                \\per matched DB entity. Entries without a matching entity
                \\are dropped (with a stderr warning) since they had become
                \\silent no-ops anyway. Run once after a kernel structural
                \\change resettles the layout.
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

    if (db_paths.items.len == 0) {
        _ = std.fs.File.stderr().write("--db is required\n") catch {};
        std.process.exit(2);
    }
    const primary_db_path = db_paths.items[0];
    const alt_db_paths = db_paths.items[1..];

    // Only `kernel` is supported. The non-kernel trees (routerOS,
    // hyprvOS, bootloader) compile separately, so the indexer doesn't
    // emit IR / entry_reaches data for them. Without per-tree IR the
    // alive-set falls back to bare-token heuristics that get tricked by
    // cross-tree homonyms. The verdict on those trees would be too
    // unreliable to gate on, so reject them outright.
    if (!std.mem.eql(u8, target_name, "kernel")) {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &buf,
            "unsupported --target: {s} (only `kernel` is supported — non-kernel trees lack per-tree IR/entry_reaches)\n",
            .{target_name},
        ) catch "unsupported --target\n";
        _ = std.fs.File.stderr().write(msg) catch {};
        std.process.exit(2);
    }

    g_target_rel = target_name;

    // Open primary DB. The primary determines target_files scope, owns
    // the skip-file resolution, and is the writeback target for
    // lint_finding rows. Alt DBs (if any) are opened separately below
    // for their alive-set qnames only.
    var db = sqlite.Db.openReadOnly(primary_db_path, g_arena) catch |err| {
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
        try defaultSkipPath(g_arena, repo_root);

    if (update_arg) |arg| {
        const rc = try updateSkipEntry(g_arena, arg, skip_path, &db);
        std.process.exit(rc);
    }

    if (rewrite_skip) {
        const rc = try rewriteSkipFile(g_arena, skip_path, &db);
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

    // Augment with alt-DB alive qnames. A finding is suppressed if the
    // entity's qualified_name is alive in ANY of the supplied DBs —
    // the primary alone underestimates aliveness when it's an x86_64
    // DB and an aarch64-only path keeps the entity reachable.
    var alt_alive: std.StringHashMapUnmanaged(void) = .empty;
    if (alt_db_paths.len > 0) {
        const primary_sha = (try fetchMeta(g_arena, &db, "commit_sha")) orelse "";
        for (alt_db_paths) |alt_path| {
            var alt_db = sqlite.Db.openReadOnly(alt_path, g_arena) catch |err| {
                var buf: [512]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "failed to open alt DB {s}: {s}\n", .{ alt_path, @errorName(err) }) catch "alt DB open error\n";
                _ = std.fs.File.stderr().write(msg) catch {};
                std.process.exit(2);
            };
            defer alt_db.close();
            const alt_sha = (try fetchMeta(g_arena, &alt_db, "commit_sha")) orelse "";
            if (!mem.eql(u8, primary_sha, alt_sha)) {
                var buf: [512]u8 = undefined;
                const msg = std.fmt.bufPrint(
                    &buf,
                    "alt DB commit_sha mismatch: primary={s} alt={s} (path: {s})\n",
                    .{ primary_sha, alt_sha, alt_path },
                ) catch "alt DB commit_sha mismatch\n";
                _ = std.fs.File.stderr().write(msg) catch {};
                std.process.exit(2);
            }
            try loadAliveQnames(g_arena, &alt_db, &alt_alive);
        }
        var nbuf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&nbuf, "  augmenting alive-set with {d} alt DB(s); {d} cross-arch alive qnames\n", .{ alt_db_paths.len, alt_alive.count() });
        _ = std.fs.File.stderr().write(msg) catch {};
    }

    const findings = try collectFindings(g_arena, &db, target_name);

    // Render: group by file, drop skip-covered, match old format.
    const stdout = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    // writerStreaming, NOT writer: std.fs.File.writer() defaults to
    // POSITIONAL writes (pwrite at the Writer's own `pos`, starting at 0).
    // Against a terminal that is invisible, but the gauntlet is normally
    // captured with `./tests/precommit.sh > log`, and there stdout is a
    // seekable file — so every analyzer stage restarted at offset 0 and
    // overwrote the stages before it. Captured logs silently lost their
    // earlier stages; verified by feeding this binary a redirected stdout
    // with known preceding lines and watching them disappear.
    // Streaming mode uses ordinary write(2) and appends. See bd stygia-8qz
    // (found while wiring stage [0d]).
    var stdout_writer = stdout.writerStreaming(&stdout_buf);
    const w = &stdout_writer.interface;

    var unused_total: u32 = 0;
    var current_file: []const u8 = "";
    var current_file_open = false;
    for (findings) |f| {
        if (skipCovers(f.file_path, f.line, f.qname)) continue;
        if (alt_alive.contains(f.qname)) continue;
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
    // write the rows; SQLite WAL mode allows concurrent readers. Writeback
    // applies the same alt-alive filter as the stdout render, so the DB
    // and the CLI agree on what's actually dead.
    db.close();
    writeFindingsToDb(g_arena, primary_db_path, findings, target_name, &alt_alive) catch |err| {
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
    alt_alive: *const std.StringHashMapUnmanaged(void),
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
        if (skipCovers(f.file_path, f.line, f.qname)) continue;
        if (alt_alive.contains(f.qname)) continue;

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
