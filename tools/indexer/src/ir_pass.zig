const std = @import("std");
const types = @import("types.zig");

const IrFnRow = types.IrFnRow;
const IrCallRow = types.IrCallRow;

pub const PassResult = struct {
    ir_fns: []IrFnRow,
    ir_calls: []IrCallRow,
    /// Entity IDs that have at least one ir_fn define. Used to set is_ast_only
    /// on the complement.
    has_ir_define: std.AutoHashMapUnmanaged(u32, void),
    /// Diagnostics for the stage-3 log line.
    stats: Stats,
};

pub const Stats = struct {
    /// `define` lines whose LLVM name was quoted (`@"..."`).
    quoted_defines: usize = 0,
    /// callee `@"..."` operands seen.
    quoted_calls: usize = 0,
    /// ir_fn rows resolved through generic-instantiation erasure.
    demangled_fns: usize = 0,
    /// ir_call rows resolved through mono-suffix stripping.
    calls_via_mono_suffix: usize = 0,
    /// ir_call rows resolved through generic-instantiation erasure.
    calls_via_generic: usize = 0,
};

/// `resolved_via` provenance tags written on demangled edges, so consumers
/// can tell an exact LLVM-name→entity hit from a reconstructed one.
pub const VIA_MONO_SUFFIX = "ir_mono_suffix";
pub const VIA_GENERIC = "ir_generic_erased";

/// Outcome of resolving one LLVM symbol name against the entity table.
const Resolved = struct {
    entity_id: u32,
    /// NULL for an exact qualified-name hit; a `VIA_*` tag otherwise.
    via: ?[]const u8,
};

/// Parse a `kernel.<arch>.ll` file and emit ir_fn + ir_call rows.
///
/// Resolution against entities goes through `entity_by_qname`, which the
/// orchestrator builds from the final entity table after stage 2.5. Three
/// things stand between an LLVM symbol name and that table:
///
///  1. LLVM *quotes* any global whose name contains a character outside
///     `[A-Za-z0-9._$-]`, escaping inner bytes as `\XX`. Every monomorphized
///     Zig generic is quoted, because its name embeds the instantiation
///     argument list: `@"a.b.SecureSlab(caps.CapabilityDomain,256).create"`.
///  2. Zig appends a `__anon_NNNNN` discriminator to functions that take an
///     anonymous comptime parameter (callbacks, tuples).
///  3. The instantiation argument list itself has no counterpart in the AST:
///     `ast_pass` flattens the members of a `return struct { … }` generic
///     body into the enclosing module namespace, so the entity for
///     `SecureSlab(T,N).create` is plain `a.b.create`.
///
/// `resolveName` walks all three, most-specific first, and tags the
/// reconstructed hits in `ir_call.resolved_via`.
pub fn pass(
    palloc: std.mem.Allocator,
    ir_path: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) !PassResult {
    const f = try std.fs.cwd().openFile(ir_path, .{});
    defer f.close();
    const stat = try f.stat();
    const bytes = try palloc.alloc(u8, @intCast(stat.size));
    const n = try f.readAll(bytes);
    if (n != bytes.len) return error.ShortRead;
    const text: []const u8 = bytes[0..n];

    // Pre-pass: build dbg metadata id → source line table.
    // DILocation entries live in the metadata section at the bottom of the IR
    // file (after all function bodies), so we have to scan for them up front.
    var dbg_lines: std.AutoHashMapUnmanaged(u32, u32) = .empty;
    {
        var meta_iter = std.mem.splitScalar(u8, text, '\n');
        while (meta_iter.next()) |raw_line| {
            // Format: `!NNNN = !DILocation(line: M, column: K, scope: !P)`
            if (raw_line.len < 8 or raw_line[0] != '!') continue;
            const eq_idx = std.mem.indexOf(u8, raw_line, " = !DILocation(") orelse continue;
            const id_str = raw_line[1..eq_idx];
            const id = std.fmt.parseInt(u32, id_str, 10) catch continue;
            const after_paren = raw_line[eq_idx + " = !DILocation(".len ..];
            const line_kw = "line: ";
            const ln_idx = std.mem.indexOf(u8, after_paren, line_kw) orelse continue;
            const after_kw = after_paren[ln_idx + line_kw.len ..];
            // Line number ends at next `,` or `)`.
            var end: usize = 0;
            while (end < after_kw.len and after_kw[end] >= '0' and after_kw[end] <= '9') end += 1;
            if (end == 0) continue;
            const line_no = std.fmt.parseInt(u32, after_kw[0..end], 10) catch continue;
            try dbg_lines.put(palloc, id, line_no);
        }
    }

    var ir_fns: std.ArrayList(IrFnRow) = .empty;
    var ir_calls: std.ArrayList(IrCallRow) = .empty;
    var has_ir: std.AutoHashMapUnmanaged(u32, void) = .empty;
    var stats: Stats = .{};

    var current_caller_id: ?u32 = null;
    var line_iter = std.mem.splitScalar(u8, text, '\n');

    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        if (current_caller_id == null) {
            // Looking for `define ... @name(...) ... {`
            if (std.mem.startsWith(u8, line, "define ")) {
                const at_idx = std.mem.indexOfScalar(u8, line, '@') orelse continue;
                const parsed = parseAtName(palloc, line, at_idx) catch null;
                // A `define` whose name we cannot lex at all: treat as an
                // unknown function so we still skip over its body rather
                // than scanning it at top level (which is how quoted
                // generics used to leak their bodies out of the graph).
                const ir_name = if (parsed) |p| p.name else "";
                if (parsed) |p| {
                    if (p.quoted) stats.quoted_defines += 1;
                }
                if (ir_name.len == 0) {
                    current_caller_id = 0;
                    continue;
                }

                // Skip LLVM-internal builtins.
                if (std.mem.startsWith(u8, ir_name, "llvm.")) continue;

                if (try resolveName(palloc, ir_name, entity_by_qname)) |r| {
                    if (r.via != null and std.mem.eql(u8, r.via.?, VIA_GENERIC)) {
                        stats.demangled_fns += 1;
                    }
                    try ir_fns.append(palloc, .{
                        .entity_id = r.entity_id,
                        .ir_name = ir_name,
                        .attrs = extractAttrs(palloc, line) catch null,
                    });
                    try has_ir.put(palloc, r.entity_id, {});
                    current_caller_id = r.entity_id;
                } else {
                    // No entity match — could be __ubsan_*, llvm.*, etc. Track
                    // as "we entered a function" so we still skip over its body.
                    current_caller_id = 0; // sentinel: in-fn, no caller_entity
                }
            }
        } else {
            // Inside a function body.
            if (std.mem.eql(u8, line, "}")) {
                current_caller_id = null;
                continue;
            }
            const caller = current_caller_id.?;
            if (caller == 0) continue; // unknown caller; skip
            try parseCallLine(palloc, line, caller, entity_by_qname, &dbg_lines, &ir_calls, &stats);
        }
    }

    return .{
        .ir_fns = try ir_fns.toOwnedSlice(palloc),
        .ir_calls = try ir_calls.toOwnedSlice(palloc),
        .has_ir_define = has_ir,
        .stats = stats,
    };
}

fn parseCallLine(
    palloc: std.mem.Allocator,
    line: []const u8,
    caller: u32,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
    dbg_lines: *const std.AutoHashMapUnmanaged(u32, u32),
    out: *std.ArrayList(IrCallRow),
    stats: *Stats,
) !void {
    // Resolve `!dbg !N` (if present) to a source line via the metadata table.
    const site_line: u32 = blk: {
        const tag = ", !dbg !";
        const idx = std.mem.lastIndexOf(u8, line, tag) orelse break :blk 0;
        const after = line[idx + tag.len ..];
        var end: usize = 0;
        while (end < after.len and after[end] >= '0' and after[end] <= '9') end += 1;
        if (end == 0) break :blk 0;
        const id = std.fmt.parseInt(u32, after[0..end], 10) catch break :blk 0;
        break :blk dbg_lines.get(id) orelse 0;
    };
    // Look for `  call ` or `  invoke ` (with leading whitespace).
    const trimmed = std.mem.trimLeft(u8, line, " \t");
    const after_call: []const u8 = blk: {
        // `call`, `invoke`, `tail call`, `musttail call`, `notail call`
        if (std.mem.startsWith(u8, trimmed, "call ")) break :blk trimmed["call ".len..];
        if (std.mem.startsWith(u8, trimmed, "invoke ")) break :blk trimmed["invoke ".len..];
        if (std.mem.startsWith(u8, trimmed, "tail call ")) break :blk trimmed["tail call ".len..];
        if (std.mem.startsWith(u8, trimmed, "musttail call ")) break :blk trimmed["musttail call ".len..];
        if (std.mem.startsWith(u8, trimmed, "notail call ")) break :blk trimmed["notail call ".len..];
        // Could also start with `%X = call ...`
        if (std.mem.indexOf(u8, trimmed, "= call ")) |eq_pos| {
            break :blk trimmed[eq_pos + "= call ".len ..];
        }
        if (std.mem.indexOf(u8, trimmed, "= invoke ")) |eq_pos| {
            break :blk trimmed[eq_pos + "= invoke ".len ..];
        }
        if (std.mem.indexOf(u8, trimmed, "= tail call ")) |eq_pos| {
            break :blk trimmed[eq_pos + "= tail call ".len ..];
        }
        return;
    };

    // Find the callee target. Look for the first `@` or `%` that introduces
    // the callee. Skip past type tokens up to the first `@`/`%` followed by
    // an identifier.
    var i: usize = 0;
    while (i < after_call.len) {
        const ch = after_call[i];
        if (ch == '@') {
            const parsed = (parseAtName(palloc, after_call, i) catch null) orelse return;
            const name = parsed.name;

            // Skip inline assembly, asm sideeffect, etc. — those have no @name.
            if (name.len == 0) return;
            if (parsed.quoted) stats.quoted_calls += 1;

            if (std.mem.startsWith(u8, name, "llvm.")) {
                try out.append(palloc, .{
                    .caller_entity_id = caller,
                    .callee_entity_id = null,
                    .call_kind = "intrinsic",
                    .resolved_via = null,
                    .confidence = null,
                    .ast_node_id = null,
                    .site_line = site_line,
                });
                return;
            }

            const r = try resolveName(palloc, name, entity_by_qname);
            if (r) |rr| {
                if (rr.via) |v| {
                    if (std.mem.eql(u8, v, VIA_MONO_SUFFIX)) stats.calls_via_mono_suffix += 1;
                    if (std.mem.eql(u8, v, VIA_GENERIC)) stats.calls_via_generic += 1;
                }
            }
            try out.append(palloc, .{
                .caller_entity_id = caller,
                .callee_entity_id = if (r) |rr| rr.entity_id else null,
                .call_kind = "direct",
                .resolved_via = if (r) |rr| rr.via else null,
                .confidence = null,
                .ast_node_id = null,
                .site_line = site_line,
            });
            return;
        } else if (ch == '%') {
            // Indirect call through a register/SSA value.
            try out.append(palloc, .{
                .caller_entity_id = caller,
                .callee_entity_id = null,
                .call_kind = "indirect",
                .resolved_via = null,
                .confidence = null,
                .ast_node_id = null,
                .site_line = site_line,
            });
            return;
        } else if (ch == '"') {
            // Skip quoted asm template, e.g. `call void asm sideeffect "stac"`.
            // Just bail — these are inline asm, not function calls.
            return;
        }
        i += 1;
    }
}

// ── LLVM symbol-name lexing ────────────────────────────────────────────

pub const AtName = struct {
    /// Unescaped name text. Owned by the caller's allocator when `quoted`.
    name: []const u8,
    /// Index just past the name in the input slice.
    end: usize,
    quoted: bool,
};

/// Lex the LLVM global name that starts at `s[at] == '@'`.
///
/// LLVM has two spellings: a bare identifier over `[A-Za-z0-9._$-]`, and a
/// double-quoted form for everything else, in which bytes outside the plain
/// set are written `\XX` (two uppercase hex digits) — notably `\22` for the
/// quote itself, which is why scanning to the next literal `"` terminates
/// correctly. Zig emits the quoted form for every monomorphized generic,
/// because the instantiation argument list contains `(`, `,` and `)`.
///
/// Returns null when `s[at]` does not introduce a name at all (inline asm,
/// an unterminated quote).
pub fn parseAtName(palloc: std.mem.Allocator, s: []const u8, at: usize) !?AtName {
    std.debug.assert(s[at] == '@');
    var i = at + 1;
    if (i < s.len and s[i] == '"') {
        i += 1;
        const start = i;
        while (i < s.len and s[i] != '"') : (i += 1) {}
        if (i >= s.len) return null; // unterminated
        const raw = s[start..i];
        return .{ .name = try unescape(palloc, raw), .end = i + 1, .quoted = true };
    }
    const start = i;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '$' or c == '-')) break;
    }
    if (i == start) return null;
    return .{ .name = s[start..i], .end = i, .quoted = false };
}

/// Expand LLVM's `\XX` byte escapes (and `\\`) inside a quoted identifier.
fn unescape(palloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, raw, '\\') == null) return try palloc.dupe(u8, raw);
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(palloc, raw.len);
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '\\' and i + 1 < raw.len) {
            if (raw[i + 1] == '\\') {
                try out.append(palloc, '\\');
                i += 2;
                continue;
            }
            if (i + 2 < raw.len) {
                const hi = std.fmt.charToDigit(raw[i + 1], 16) catch null;
                const lo = std.fmt.charToDigit(raw[i + 2], 16) catch null;
                if (hi != null and lo != null) {
                    try out.append(palloc, @as(u8, hi.?) * 16 + lo.?);
                    i += 3;
                    continue;
                }
            }
        }
        try out.append(palloc, raw[i]);
        i += 1;
    }
    return try out.toOwnedSlice(palloc);
}

// ── LLVM symbol name → entity resolution ───────────────────────────────

/// Resolve one LLVM function name to an entity, most-specific first:
///
///   1. exact qualified-name hit                         → via = null
///   2. after stripping a `__anon_NNNNN` discriminator    → via = ir_mono_suffix
///   3. after erasing generic instantiation arguments     → via = ir_generic_erased
///
/// Step 3 tries both shapes a Zig generic can take in the entity table: the
/// flattened one `ast_pass` actually emits (`a.b.member`, because members of
/// a `return struct { … }` body are hoisted into the enclosing module) and
/// the nested one (`a.b.Generic.member`), so the resolution survives a
/// future ast_pass that stops flattening.
fn resolveName(
    palloc: std.mem.Allocator,
    name: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) !?Resolved {
    if (entity_by_qname.get(name)) |id| return .{ .entity_id = id, .via = null };

    const stripped = stripMonoSuffix(name);
    if (stripped.len != name.len) {
        if (entity_by_qname.get(stripped)) |id| {
            return .{ .entity_id = id, .via = VIA_MONO_SUFFIX };
        }
    }

    // Only names carrying an instantiation argument list can be erased.
    if (std.mem.indexOfScalar(u8, stripped, '(') == null) return null;

    const cands = try genericCandidates(palloc, stripped, entity_by_qname);
    for (cands) |c| {
        if (entity_by_qname.get(c)) |id| return .{ .entity_id = id, .via = VIA_GENERIC };
    }
    return null;
}

/// Build the erased-qname candidates for a monomorphized name.
///
/// `a.b.Foo(X,Y).bar` yields `a.b.bar` (flattened) and `a.b.Foo.bar`
/// (nested), in that order. A segment is only treated as an instantiation
/// when its head is itself a known entity in the same namespace — that
/// rejects std-library names such as `array_list.Aligned(T,null).append`,
/// which would otherwise collide with an unrelated kernel `array_list.append`
/// if one ever existed.
fn genericCandidates(
    palloc: std.mem.Allocator,
    name: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) ![]const []const u8 {
    var flat: std.ArrayList(u8) = .empty;
    var nested: std.ArrayList(u8) = .empty;
    var saw_instantiation = false;

    var it = SegmentIter{ .s = name };
    while (it.next()) |seg| {
        const head_len = std.mem.indexOfScalar(u8, seg, '(') orelse {
            // Plain segment.
            if (flat.items.len > 0) try flat.append(palloc, '.');
            try flat.appendSlice(palloc, seg);
            if (nested.items.len > 0) try nested.append(palloc, '.');
            try nested.appendSlice(palloc, seg);
            continue;
        };
        const head = seg[0..head_len];
        if (head.len == 0) return &.{};

        // Gate: `<prefix>.<head>` must name a real entity under either the
        // nested or the flattened prefix accumulated so far.
        if (!try headIsKnown(palloc, nested.items, head, entity_by_qname) and
            !try headIsKnown(palloc, flat.items, head, entity_by_qname))
        {
            return &.{};
        }

        saw_instantiation = true;
        // Flattened form drops the instantiation segment entirely.
        // Nested form keeps its head.
        if (nested.items.len > 0) try nested.append(palloc, '.');
        try nested.appendSlice(palloc, head);
    }
    if (!saw_instantiation) return &.{};

    var out: std.ArrayList([]const u8) = .empty;
    if (flat.items.len > 0) try out.append(palloc, flat.items);
    if (nested.items.len > 0) try out.append(palloc, nested.items);
    return try out.toOwnedSlice(palloc);
}

fn headIsKnown(
    palloc: std.mem.Allocator,
    prefix: []const u8,
    head: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) !bool {
    if (prefix.len == 0) return entity_by_qname.get(head) != null;
    const probe = try std.fmt.allocPrint(palloc, "{s}.{s}", .{ prefix, head });
    return entity_by_qname.get(probe) != null;
}

/// Split a decorated name on `.` at nesting depth zero, so the dots inside
/// an instantiation argument list (`SecureSlab(caps.domain.CapabilityDomain,
/// 256)`) do not split the segment.
const SegmentIter = struct {
    s: []const u8,
    i: usize = 0,

    fn next(self: *SegmentIter) ?[]const u8 {
        if (self.i >= self.s.len) return null;
        const start = self.i;
        var depth: i32 = 0;
        while (self.i < self.s.len) : (self.i += 1) {
            switch (self.s[self.i]) {
                '(', '[', '{' => depth += 1,
                ')', ']', '}' => depth -= 1,
                '.' => if (depth == 0) {
                    const seg = self.s[start..self.i];
                    self.i += 1;
                    return seg;
                },
                else => {},
            }
        }
        return self.s[start..self.i];
    }
};

/// Strip Zig's monomorphization suffix `__anon_NNNN` (and related variants
/// like `__struct_NNNN`) so generics map back to the AST-level qualified name.
fn stripMonoSuffix(name: []const u8) []const u8 {
    // Find the last `__` that precedes a known suffix prefix.
    const SUFFIX_PREFIXES = [_][]const u8{ "__anon_", "__struct_", "__enum_", "__union_" };
    var best: ?usize = null;
    for (SUFFIX_PREFIXES) |pref| {
        if (std.mem.lastIndexOf(u8, name, pref)) |pos| {
            if (best == null or pos > best.?) best = pos;
        }
    }
    if (best) |pos| return name[0..pos];
    return name;
}

fn extractAttrs(palloc: std.mem.Allocator, line: []const u8) !?[]const u8 {
    // Extract the comma-separated attribute words between `define` and `@`,
    // plus trailing `unnamed_addr`, `#N`, etc. For slice C just record the
    // linkage-prefix portion so we can distinguish weak/internal/etc. later.
    const at_idx = std.mem.indexOfScalar(u8, line, '@') orelse return null;
    const head = std.mem.trim(u8, line[0..at_idx], " \t");
    if (head.len == 0) return null;
    return try palloc.dupe(u8, head);
}

// ── Unit tests ─────────────────────────────────────────────────────────

test "parseAtName: bare identifier" {
    const s = "define void @sched.timer.onFire(ptr %0) {";
    const at = std.mem.indexOfScalar(u8, s, '@').?;
    const p = (try parseAtName(std.testing.allocator, s, at)).?;
    try std.testing.expectEqualStrings("sched.timer.onFire", p.name);
    try std.testing.expect(!p.quoted);
}

test "parseAtName: quoted identifier with escapes" {
    const s = "define void @\"sched.priority_queue.PriorityQueue(T,\\22next\\22[0..4],4).enqueue\"(ptr %0) {";
    const at = std.mem.indexOfScalar(u8, s, '@').?;
    const p = (try parseAtName(std.testing.allocator, s, at)).?;
    defer std.testing.allocator.free(p.name);
    try std.testing.expect(p.quoted);
    try std.testing.expectEqualStrings(
        "sched.priority_queue.PriorityQueue(T,\"next\"[0..4],4).enqueue",
        p.name,
    );
}

test "SegmentIter: dots inside instantiation args do not split" {
    var it = SegmentIter{ .s = "a.b.Foo(x.y.Z,256).bar" };
    try std.testing.expectEqualStrings("a", it.next().?);
    try std.testing.expectEqualStrings("b", it.next().?);
    try std.testing.expectEqualStrings("Foo(x.y.Z,256)", it.next().?);
    try std.testing.expectEqualStrings("bar", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "stripMonoSuffix takes the last discriminator" {
    try std.testing.expectEqualStrings("a.b.forEachAlive", stripMonoSuffix("a.b.forEachAlive__anon_94571"));
    try std.testing.expectEqualStrings("a.b.plain", stripMonoSuffix("a.b.plain"));
}

test "resolveName: exact, mono-suffix, generic-erased" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var m: std.StringHashMapUnmanaged(u32) = .empty;
    try m.put(al, "sched.timer.onFire", 1);
    try m.put(al, "a.b.SecureSlab", 2);
    try m.put(al, "a.b.forEachAlive", 3);
    try m.put(al, "a.b.helper", 4);

    const exact = (try resolveName(al, "sched.timer.onFire", &m)).?;
    try std.testing.expectEqual(@as(u32, 1), exact.entity_id);
    try std.testing.expect(exact.via == null);

    const mono = (try resolveName(al, "a.b.helper__anon_7", &m)).?;
    try std.testing.expectEqual(@as(u32, 4), mono.entity_id);
    try std.testing.expectEqualStrings(VIA_MONO_SUFFIX, mono.via.?);

    const gen = (try resolveName(al, "a.b.SecureSlab(c.d.T,256).forEachAlive__anon_94571", &m)).?;
    try std.testing.expectEqual(@as(u32, 3), gen.entity_id);
    try std.testing.expectEqualStrings(VIA_GENERIC, gen.via.?);

    // Unknown generic head → no erasure, no phantom edge.
    try std.testing.expect((try resolveName(al, "array_list.Aligned(x,null).append", &m)) == null);
}
