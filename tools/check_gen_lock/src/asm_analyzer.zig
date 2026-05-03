//! Inline-asm gen-lock analyzer.
//!
//! Special-cased extension to the main analyzer: the AST/source-byte
//! pipeline is blind to inline assembly, so the L4 IPC fast path's
//! cmpxchg-based gen-lock acquire/release sequences slip past every
//! regular check. This module steps in for ONE NARROW CASE — a function
//! whose entire body is a single `asm volatile (...)` expression with
//! NO interleaved Zig statements. Mixed-asm-and-Zig functions are out of
//! scope (would need real CFG analysis over both languages); only x86_64
//! is recognized for now (asm mnemonic patterns differ on other arches).
//!
//! The contract the analyzer enforces inside such a function:
//!
//!   - Every memory operand of the form `<offset>(%base)` whose offset
//!     comes from a `@offsetOf(T, "field")` substitution through a
//!     `std.fmt.comptimePrint(fmt, args)` call is treated as an access
//!     to T's field via %base.
//!
//!   - When the field is `_gen_lock` and the instruction is
//!     `lock cmpxchgq %src, <offset>(%base)` immediately followed by a
//!     conditional jump (`je .L<name>`), the analyzer treats this as
//!     a CONDITIONAL acquire of T at %base. The lock is recorded as
//!     held only on the .L<name> jump-target path (fall-through is the
//!     CAS-failed path; lock not held).
//!
//!   - When the field is `_gen_lock` and the instruction is
//!     `andq $-2, <offset>(%base)`, the analyzer treats this as a
//!     RELEASE of T at %base.
//!
//!   - For any OTHER field of a slab-backed T accessed via
//!     `<offset>(%base)`, the analyzer requires that lock(T at %base) be
//!     currently held.
//!
//!   - Raw numeric offsets `<num>(%base)` (no symbolic resolution) are
//!     REJECTED if %base is currently typed as a slab pointer (we infer
//!     this from prior symbolic accesses through the same register).
//!     Hardcoded offsets in this codebase have all been bug sources, so
//!     they're forbidden in fully-naked-asm functions — use
//!     `@offsetOf(T, "field")` through `comptimePrint` args instead.
//!
//! Control flow is handled by linear walk with per-label state
//! snapshots: on first reach of a label (declaration or jump target),
//! we snapshot the current active-lock set; subsequent visits must
//! match, otherwise we report a join-point inconsistency.
//!
//! Out of scope (deliberately):
//!   - aarch64
//!   - Composite offsets like `@offsetOf(T1, "f1") + @offsetOf(T2, "f2")`:
//!     these compute byte offsets through non-slab navigation structs
//!     (e.g., `KernelHandle.ref.ptr`), not slab field accesses; we record
//!     them as opaque markers. (KernelHandle isn't slab-backed, so its
//!     fields don't carry a lock obligation.)
//!   - Functions with ANY non-asm Zig statements
//!   - Architectures other than x86_64

const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

// ── Public types ──────────────────────────────────────────────────────

pub const Finding = struct {
    file_path: []const u8,    // arena-owned
    line: u32,
    fn_qname: []const u8,     // arena-owned
    rule: []const u8,
    message: []const u8,      // arena-owned
};

pub const Input = struct {
    qname: []const u8,
    file_path: []const u8,
    file_source: []const u8,
    fn_text: []const u8,        // bytes of the entire fn (signature + body)
    fn_byte_start: u32,         // byte offset of fn_text within file_source
};

// ── Public entry ──────────────────────────────────────────────────────

pub fn scanAll(
    gpa: Allocator,
    arena: Allocator,
    fns: []const Input,
    slab_types: *const StringHashMap(void),
    out: *ArrayList(Finding),
) !void {
    for (fns) |f| try scanFn(gpa, arena, f, slab_types, out);
}

fn scanFn(
    gpa: Allocator,
    arena: Allocator,
    f: Input,
    slab_types: *const StringHashMap(void),
    out: *ArrayList(Finding),
) !void {
    // Gate 1: callconv(.naked).
    if (mem.indexOf(u8, f.fn_text, "callconv(.naked)") == null) return;
    // Gate 2: per-fn opt-out marker. Use this on functions where the
    // analyzer's per-register lock-bracket model is too coarse — e.g.,
    // L4-style hand-off where one lock provides exclusive access to a
    // hand-off target without acquiring the target's own lock.
    if (mem.indexOf(u8, f.fn_text, "// asm-genlock: skip") != null) return;
    // Gate 3: body is a single asm volatile(...) statement.
    const block = findFnBlock(f.fn_text) orelse return;
    const body = f.fn_text[block.start..block.end];
    const asm_span = findSingleAsmStatement(body) orelse return;
    const asm_expr = body[asm_span.start..asm_span.end];
    const asm_expr_byte = f.fn_byte_start + @as(u32, @intCast(block.start)) + @as(u32, @intCast(asm_span.start));
    const asm_base_line = byteToLine(f.file_source, asm_expr_byte);

    var lines = try expandAsmExpression(gpa, arena, asm_expr, asm_base_line);
    defer lines.deinit(gpa);

    try analyzeLines(
        gpa,
        arena,
        lines.items,
        f.qname,
        f.file_path,
        slab_types,
        out,
    );
}

// ── Source-text helpers ───────────────────────────────────────────────

const Span = struct { start: usize, end: usize };

/// Naive paren-aware scanner that finds the outermost `{...}` block in
/// `text`. Skips chars inside `\\` continuation lines, `"..."` strings,
/// and `// ...` comments.
fn findFnBlock(text: []const u8) ?Span {
    var i: usize = 0;
    // Find first top-level `{`.
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '/' and i + 1 < text.len and text[i + 1] == '/') {
            while (i < text.len and text[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '\\' and i + 1 < text.len and text[i + 1] == '\\') {
            while (i < text.len and text[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '"') {
            i = scanRegularStringEnd(text, i) orelse return null;
            continue;
        }
        if (c == '{') break;
    }
    if (i >= text.len) return null;
    const start = i + 1;
    var depth: i32 = 1;
    i = start;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '/' and i + 1 < text.len and text[i + 1] == '/') {
            while (i < text.len and text[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '\\' and i + 1 < text.len and text[i + 1] == '\\') {
            while (i < text.len and text[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '"') {
            i = scanRegularStringEnd(text, i) orelse return null;
            continue;
        }
        if (c == '{') depth += 1;
        if (c == '}') {
            depth -= 1;
            if (depth == 0) return .{ .start = start, .end = i };
        }
    }
    return null;
}

/// Find a single `asm volatile (...)` statement inside `body`, returning
/// the span between the opening and closing parens (exclusive). Returns
/// null if `body` has anything other than this single statement (after
/// stripping comments and whitespace).
fn findSingleAsmStatement(body: []const u8) ?Span {
    var i = skipWsAndComments(body, 0);
    const NEEDLE = "asm volatile";
    if (i + NEEDLE.len > body.len) return null;
    if (!mem.eql(u8, body[i .. i + NEEDLE.len], NEEDLE)) return null;
    i += NEEDLE.len;
    i = skipWsAndComments(body, i);
    if (i >= body.len or body[i] != '(') return null;
    const open = i;
    i += 1;
    var depth: i32 = 1;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (c == '/' and i + 1 < body.len and body[i + 1] == '/') {
            while (i < body.len and body[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '\\' and i + 1 < body.len and body[i + 1] == '\\') {
            while (i < body.len and body[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '"') {
            i = scanRegularStringEnd(body, i) orelse return null;
            i -= 1; // for-loop will i += 1
            continue;
        }
        if (c == '(') depth += 1;
        if (c == ')') {
            depth -= 1;
            if (depth == 0) {
                const close = i;
                var j = skipWsAndComments(body, close + 1);
                if (j >= body.len or body[j] != ';') return null;
                j = skipWsAndComments(body, j + 1);
                if (j != body.len) return null;
                return .{ .start = open + 1, .end = close };
            }
        }
    }
    return null;
}

fn skipWsAndComments(s: []const u8, start: usize) usize {
    var i = start;
    while (i < s.len) {
        if (ascii.isWhitespace(s[i])) {
            i += 1;
            continue;
        }
        if (i + 1 < s.len and s[i] == '/' and s[i + 1] == '/') {
            while (i < s.len and s[i] != '\n') : (i += 1) {}
            continue;
        }
        break;
    }
    return i;
}

/// Returns index of the byte AFTER the closing `"` of a `"..."` string
/// starting at `i` (where `s[i] == '"'`). Handles `\"` escapes.
fn scanRegularStringEnd(s: []const u8, start: usize) ?usize {
    var i = start + 1;
    while (i < s.len) : (i += 1) {
        if (s[i] == '\\' and i + 1 < s.len) {
            i += 1;
            continue;
        }
        if (s[i] == '"') return i + 1;
    }
    return null;
}

fn byteToLine(src: []const u8, byte: u32) u32 {
    var line: u32 = 1;
    var i: usize = 0;
    while (i < byte and i < src.len) : (i += 1) {
        if (src[i] == '\n') line += 1;
    }
    return line;
}

fn offsetToLine(s: []const u8, off: usize) u32 {
    var line: u32 = 0;
    var i: usize = 0;
    while (i < off and i < s.len) : (i += 1) {
        if (s[i] == '\n') line += 1;
    }
    return line;
}

// ── Expansion ─────────────────────────────────────────────────────────

const SymRef = struct {
    placeholder: []const u8,    // "port_lock_off"
    is_simple: bool,            // single @offsetOf(T, "field")
    struct_name: []const u8,    // "Port"   (only valid when is_simple)
    field_name: []const u8,     // "_gen_lock"  (only valid when is_simple)
};

const AsmLine = struct {
    text: []const u8,         // arena-owned, post-substitution
    source_line: u32,
    refs: []const SymRef,     // arena-owned
};

const ExpansionList = ArrayList(AsmLine);

/// Walk the asm expression source. Recognized tokens:
///   - `\\<line>` continuation strings (multi-line raw asm)
///   - `"..."` regular string literals
///   - `std.fmt.comptimePrint(fmt, .{...})` calls (resolve)
///   - `(if (X) <a> else <b>)` ternary — take the THEN branch
///   - `++` operator — treat as join (no-op for our flat output)
/// Anything else is skipped silently.
fn expandAsmExpression(
    gpa: Allocator,
    arena: Allocator,
    asm_expr: []const u8,
    base_line: u32,
) !ExpansionList {
    var out = ExpansionList.empty;
    errdefer out.deinit(gpa);

    var p: usize = 0;
    while (p < asm_expr.len) {
        // Whitespace + `++`.
        if (ascii.isWhitespace(asm_expr[p]) or asm_expr[p] == '+') {
            p += 1;
            continue;
        }
        // Line comment.
        if (p + 1 < asm_expr.len and asm_expr[p] == '/' and asm_expr[p + 1] == '/') {
            while (p < asm_expr.len and asm_expr[p] != '\n') p += 1;
            continue;
        }
        // `(if (build_options.X) THEN else ELSE)` form.
        if (asm_expr[p] == '(') {
            const save = p;
            const inner_start = p + 1;
            const k = skipWsAndComments(asm_expr, inner_start);
            if (matchKeyword(asm_expr, k, "if") and (k + 2 >= asm_expr.len or !isIdentChar(asm_expr[k + 2]))) {
                if (parseIfThenElse(asm_expr, save)) |span| {
                    var sub = try expandAsmExpression(
                        gpa,
                        arena,
                        asm_expr[span.then_start..span.then_end],
                        base_line + offsetToLine(asm_expr, span.then_start),
                    );
                    defer sub.deinit(gpa);
                    try out.appendSlice(gpa, sub.items);
                    p = span.expr_end;
                    continue;
                }
            }
            // Unrecognized (...) — skip past it.
            p = skipBalanced(asm_expr, save, '(', ')') orelse return out;
            continue;
        }
        // `"..."` literal.
        if (asm_expr[p] == '"') {
            const end = scanRegularStringEnd(asm_expr, p) orelse return out;
            const content = asm_expr[p + 1 .. end - 1];
            try emitTextLines(gpa, arena, content, base_line + offsetToLine(asm_expr, p), &out);
            p = end;
            continue;
        }
        // `\\<line>` continuation string: collect contiguous prefix.
        if (p + 1 < asm_expr.len and asm_expr[p] == '\\' and asm_expr[p + 1] == '\\') {
            const start_off = p;
            const collected = try collectMultilineString(arena, asm_expr, &p);
            try emitTextLines(gpa, arena, collected, base_line + offsetToLine(asm_expr, start_off), &out);
            continue;
        }
        // `std.fmt.comptimePrint(...)` call.
        if (matchIdentRun(asm_expr, p, "std.fmt.comptimePrint") or
            matchIdentRun(asm_expr, p, "comptimePrint"))
        {
            const cp = parseComptimePrint(asm_expr, p) orelse {
                // Skip past `comptimePrint(...)` if we can.
                p = skipPastIdentAndBalanced(asm_expr, p) orelse return out;
                continue;
            };
            const resolved = try resolveComptimePrint(arena, cp.fmt_text, cp.args_text);
            const before = out.items.len;
            try emitTextLines(gpa, arena, resolved.text, base_line + offsetToLine(asm_expr, p), &out);
            try attachRefs(&out, before, resolved.refs);
            p = cp.end;
            continue;
        }
        // Unknown construct — advance one char.
        p += 1;
    }
    return out;
}

fn matchKeyword(s: []const u8, start: usize, kw: []const u8) bool {
    if (start + kw.len > s.len) return false;
    return mem.eql(u8, s[start .. start + kw.len], kw);
}

fn isIdentChar(c: u8) bool {
    return ascii.isAlphanumeric(c) or c == '_' or c == '.';
}

/// Match an exact identifier-run that exactly equals `name`. The byte
/// AFTER the match must be a non-ident char (or end-of-string).
fn matchIdentRun(s: []const u8, start: usize, name: []const u8) bool {
    if (start + name.len > s.len) return false;
    if (!mem.eql(u8, s[start .. start + name.len], name)) return false;
    const after = start + name.len;
    if (after < s.len and isIdentChar(s[after])) return false;
    return true;
}

/// `(<open>...<close>)` matched-pair scan starting at `start` (where
/// `s[start] == open`). Returns index AFTER the matched close, or null
/// if unbalanced. Skips strings + comments + `\\` continuation lines.
fn skipBalanced(s: []const u8, start: usize, open: u8, close: u8) ?usize {
    if (s[start] != open) return null;
    var depth: i32 = 1;
    var i = start + 1;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '/' and i + 1 < s.len and s[i + 1] == '/') {
            while (i < s.len and s[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '\\' and i + 1 < s.len and s[i + 1] == '\\') {
            while (i < s.len and s[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '"') {
            i = scanRegularStringEnd(s, i) orelse return null;
            i -= 1; // for-loop increments
            continue;
        }
        if (c == open) depth += 1;
        if (c == close) {
            depth -= 1;
            if (depth == 0) return i + 1;
        }
    }
    return null;
}

fn skipPastIdentAndBalanced(s: []const u8, start: usize) ?usize {
    var i = start;
    while (i < s.len and isIdentChar(s[i])) i += 1;
    while (i < s.len and ascii.isWhitespace(s[i])) i += 1;
    if (i >= s.len or s[i] != '(') return null;
    return skipBalanced(s, i, '(', ')');
}

const IfSpan = struct {
    then_start: usize,
    then_end: usize,
    expr_end: usize, // byte AFTER the closing `)` of the surrounding `(if ...)`
};

/// Parse `(if (<cond>) <then> else <else>)`, returning the span of the
/// THEN branch and the byte after the outer `)`. The `<then>` and
/// `<else>` arms are each a single expression — we look for `else` at
/// expression-paren depth zero of the outer parens.
fn parseIfThenElse(s: []const u8, start: usize) ?IfSpan {
    if (s[start] != '(') return null;
    const outer_end = skipBalanced(s, start, '(', ')') orelse return null;
    var i = start + 1;
    i = skipWsAndComments(s, i);
    if (!matchKeyword(s, i, "if")) return null;
    i += 2;
    i = skipWsAndComments(s, i);
    if (i >= s.len or s[i] != '(') return null;
    const cond_end = skipBalanced(s, i, '(', ')') orelse return null;
    i = cond_end;
    i = skipWsAndComments(s, i);
    const then_start = i;
    // Find " else " at outer depth.
    var depth: i32 = 0;
    while (i < outer_end - 1) : (i += 1) {
        const c = s[i];
        if (c == '/' and i + 1 < s.len and s[i + 1] == '/') {
            while (i < outer_end - 1 and s[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '\\' and i + 1 < s.len and s[i + 1] == '\\') {
            while (i < outer_end - 1 and s[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '"') {
            i = scanRegularStringEnd(s, i) orelse return null;
            i -= 1;
            continue;
        }
        if (c == '(' or c == '{' or c == '[') depth += 1;
        if (c == ')' or c == '}' or c == ']') depth -= 1;
        if (depth == 0 and c == 'e' and matchIdentRun(s, i, "else")) {
            const then_end = i;
            return .{ .then_start = then_start, .then_end = then_end, .expr_end = outer_end };
        }
    }
    return null;
}

/// Collect a chain of `\\<line>` continuation strings starting at `*p`.
/// Advances `*p` past the chain. Returns the concatenated content with
/// each line terminated by `\n`. (Discards the `\\` prefix on each line.)
fn collectMultilineString(arena: Allocator, s: []const u8, p: *usize) ![]const u8 {
    var buf = ArrayList(u8).empty;
    defer buf.deinit(arena);
    while (true) {
        var i = p.*;
        // Skip leading whitespace on the line up to the `\\`.
        var j = i;
        while (j < s.len and (s[j] == ' ' or s[j] == '\t')) j += 1;
        if (j + 1 < s.len and s[j] == '\\' and s[j + 1] == '\\') {
            // Append from after `\\` to end of line.
            var k = j + 2;
            while (k < s.len and s[k] != '\n') k += 1;
            try buf.appendSlice(arena, s[j + 2 .. k]);
            try buf.append(arena, '\n');
            // Advance past the newline.
            p.* = if (k < s.len) k + 1 else k;
            i = p.*;
            // Skip blank lines or whitespace until next `\\` or end.
            var look = i;
            while (look < s.len and (s[look] == ' ' or s[look] == '\t' or s[look] == '\n' or s[look] == '\r')) look += 1;
            if (look + 1 < s.len and s[look] == '\\' and s[look + 1] == '\\') {
                p.* = look;
                continue;
            }
            return try arena.dupe(u8, buf.items);
        }
        // No `\\` found — break.
        return try arena.dupe(u8, buf.items);
    }
}

fn emitTextLines(
    gpa: Allocator,
    arena: Allocator,
    text: []const u8,
    base_line: u32,
    out: *ExpansionList,
) !void {
    var i: usize = 0;
    var line_no: u32 = base_line;
    while (i < text.len) {
        var j = i;
        while (j < text.len and text[j] != '\n') j += 1;
        const ln = text[i..j];
        // Strip asm-style line comments (`//` or `#`) — these get carried
        // along inside `\\`-continuation strings and confuse pattern
        // matching otherwise.
        const without_comment = stripAsmLineComment(ln);
        const trimmed = trimAscii(without_comment);
        if (trimmed.len > 0) {
            try out.append(gpa, .{
                .text = try arena.dupe(u8, trimmed),
                .source_line = line_no,
                .refs = &.{},
            });
        }
        line_no += 1;
        if (j >= text.len) break;
        i = j + 1;
    }
}

fn stripAsmLineComment(line: []const u8) []const u8 {
    var i: usize = 0;
    while (i + 1 < line.len) : (i += 1) {
        if (line[i] == '/' and line[i + 1] == '/') return line[0..i];
        if (line[i] == '#') return line[0..i];
    }
    return line;
}

fn trimAscii(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, &std.ascii.whitespace);
}

// ── comptimePrint resolution ──────────────────────────────────────────

const ComptimePrintCall = struct {
    fmt_text: []const u8,    // raw (un-decoded) format string content
    args_text: []const u8,   // raw struct-literal args
    end: usize,              // byte AFTER the closing `)` of the call
};

const ResolvedPrint = struct {
    text: []const u8,        // arena-owned, with refs substituted
    refs: []const SymRef,    // arena-owned
};

/// Parse `<head>(fmt, args)` where `<head>` is the comptimePrint identifier.
fn parseComptimePrint(s: []const u8, start: usize) ?ComptimePrintCall {
    var i = start;
    // Skip the identifier head.
    while (i < s.len and isIdentChar(s[i])) i += 1;
    while (i < s.len and ascii.isWhitespace(s[i])) i += 1;
    if (i >= s.len or s[i] != '(') return null;
    const open = i;
    const close = skipBalanced(s, open, '(', ')') orelse return null;
    // Inner content is open+1 .. close-1
    const inner_start = open + 1;
    const inner_end = close - 1;
    // Find the comma separating fmt from args at depth 0.
    var p: usize = inner_start;
    p = skipWsAndComments(s, p);
    // First arg should be a string literal (either "..." or `\\` chain).
    var fmt_start: usize = 0;
    var fmt_end: usize = 0;
    if (p < inner_end and s[p] == '"') {
        const e = scanRegularStringEnd(s, p) orelse return null;
        fmt_start = p + 1;
        fmt_end = e - 1;
        p = e;
    } else if (p + 1 < inner_end and s[p] == '\\' and s[p + 1] == '\\') {
        // Multi-line. Walk past contiguous `\\`-prefixed lines.
        var q = p;
        while (true) {
            // Skip leading ws on each line until either `\\` or non-`\\`.
            var k = q;
            while (k < inner_end and (s[k] == ' ' or s[k] == '\t')) k += 1;
            if (k + 1 < inner_end and s[k] == '\\' and s[k + 1] == '\\') {
                // Advance past this line.
                q = k;
                while (q < inner_end and s[q] != '\n') q += 1;
                if (q < inner_end) q += 1;
                continue;
            }
            break;
        }
        fmt_start = p;
        fmt_end = q;
        p = q;
    } else {
        return null;
    }
    p = skipWsAndComments(s, p);
    if (p >= inner_end or s[p] != ',') return null;
    p += 1;
    p = skipWsAndComments(s, p);
    const args_start = p;
    return .{
        .fmt_text = s[fmt_start..fmt_end],
        .args_text = s[args_start..inner_end],
        .end = close,
    };
}

/// Decode a fmt string (either "..." escape form or `\\` continuation
/// form) into a flat byte buffer. Owned by `arena`.
fn decodeFmt(arena: Allocator, fmt_text: []const u8) ![]const u8 {
    if (fmt_text.len == 0) return "";
    if (fmt_text[0] == '\\') {
        // Multi-line continuation. Each line: skip ws, expect `\\`,
        // append rest, append '\n'.
        var buf = ArrayList(u8).empty;
        defer buf.deinit(arena);
        var i: usize = 0;
        while (i < fmt_text.len) {
            // Skip leading ws.
            while (i < fmt_text.len and (fmt_text[i] == ' ' or fmt_text[i] == '\t')) i += 1;
            if (i + 1 < fmt_text.len and fmt_text[i] == '\\' and fmt_text[i + 1] == '\\') {
                var k = i + 2;
                while (k < fmt_text.len and fmt_text[k] != '\n') k += 1;
                try buf.appendSlice(arena, fmt_text[i + 2 .. k]);
                try buf.append(arena, '\n');
                i = if (k < fmt_text.len) k + 1 else k;
                continue;
            }
            // Non-`\\` content — skip the rest of the line.
            while (i < fmt_text.len and fmt_text[i] != '\n') i += 1;
            if (i < fmt_text.len) i += 1;
        }
        return try arena.dupe(u8, buf.items);
    }
    // Regular "..." string content. Decode common escapes (\\n, \\t, \\\\, \\")
    var buf = ArrayList(u8).empty;
    defer buf.deinit(arena);
    var i: usize = 0;
    while (i < fmt_text.len) : (i += 1) {
        if (fmt_text[i] == '\\' and i + 1 < fmt_text.len) {
            const nx = fmt_text[i + 1];
            switch (nx) {
                'n' => try buf.append(arena, '\n'),
                't' => try buf.append(arena, '\t'),
                'r' => try buf.append(arena, '\r'),
                '\\' => try buf.append(arena, '\\'),
                '"' => try buf.append(arena, '"'),
                else => {
                    try buf.append(arena, '\\');
                    try buf.append(arena, nx);
                },
            }
            i += 1;
            continue;
        }
        try buf.append(arena, fmt_text[i]);
    }
    return try arena.dupe(u8, buf.items);
}

const ArgEntry = struct {
    name: []const u8,
    expr_text: []const u8,
};

/// Parse `.{ .name = expr, .name = expr, ... }` into a list of name/expr
/// pairs. The outer `.{` / `}` is required.
fn parseArgsLiteral(arena: Allocator, args_text: []const u8) !ArrayList(ArgEntry) {
    var out = ArrayList(ArgEntry).empty;
    errdefer out.deinit(arena);
    var i: usize = 0;
    i = skipWsAndComments(args_text, i);
    if (i + 1 >= args_text.len) return out;
    if (args_text[i] != '.' or args_text[i + 1] != '{') return out;
    i += 2;
    while (true) {
        i = skipWsAndComments(args_text, i);
        if (i >= args_text.len) break;
        if (args_text[i] == '}') break;
        if (args_text[i] != '.') break;
        i += 1; // skip `.`
        // Parse name.
        var n_end = i;
        while (n_end < args_text.len and isIdentChar(args_text[n_end])) n_end += 1;
        const name = args_text[i..n_end];
        if (name.len == 0) break;
        i = n_end;
        i = skipWsAndComments(args_text, i);
        if (i >= args_text.len or args_text[i] != '=') break;
        i += 1;
        i = skipWsAndComments(args_text, i);
        // Parse expression up to next top-level `,` or `}`.
        const expr_start = i;
        var depth: i32 = 0;
        while (i < args_text.len) : (i += 1) {
            const c = args_text[i];
            if (c == '"') {
                i = (scanRegularStringEnd(args_text, i) orelse return out) - 1;
                continue;
            }
            if (c == '(' or c == '{' or c == '[') depth += 1;
            if (c == ')' or c == '}' or c == ']') {
                if (depth == 0) break;
                depth -= 1;
                continue;
            }
            if (c == ',' and depth == 0) break;
        }
        const expr = trimAscii(args_text[expr_start..i]);
        try out.append(arena, .{ .name = name, .expr_text = expr });
        if (i < args_text.len and args_text[i] == ',') {
            i += 1;
            continue;
        }
        break;
    }
    return out;
}

const SimpleOffset = struct {
    struct_name: []const u8,    // arena-owned
    field_name: []const u8,     // arena-owned
};

/// Recognize `@offsetOf(<TypeExpr>, "<field>")` as a single simple ref.
/// `<TypeExpr>` is the textual type expression (we keep the trailing
/// short identifier as struct_name for slab-type matching). Multi-arg
/// composites like `@offsetOf(...) + @offsetOf(...)` return null.
fn parseSimpleOffsetOf(arena: Allocator, expr: []const u8) !?SimpleOffset {
    const t = trimAscii(expr);
    if (!mem.startsWith(u8, t, "@offsetOf(")) return null;
    const inner_start: usize = "@offsetOf(".len;
    const close = skipBalanced(t, inner_start - 1, '(', ')') orelse return null;
    // Verify nothing follows the closing `)` (no `+`, no second @offsetOf).
    var p = close;
    while (p < t.len and ascii.isWhitespace(t[p])) p += 1;
    if (p != t.len) return null;
    const inner = t[inner_start .. close - 1];
    // Find the comma at depth 0.
    var i: usize = 0;
    var depth: i32 = 0;
    while (i < inner.len) : (i += 1) {
        const c = inner[i];
        if (c == '"') {
            i = (scanRegularStringEnd(inner, i) orelse return null) - 1;
            continue;
        }
        if (c == '(' or c == '{' or c == '[') depth += 1;
        if (c == ')' or c == '}' or c == ']') depth -= 1;
        if (c == ',' and depth == 0) break;
    }
    if (i >= inner.len) return null;
    const type_text = trimAscii(inner[0..i]);
    var rest = trimAscii(inner[i + 1 ..]);
    // Strip optional trailing comma.
    if (rest.len > 0 and rest[rest.len - 1] == ',') rest = trimAscii(rest[0 .. rest.len - 1]);
    if (rest.len < 2 or rest[0] != '"' or rest[rest.len - 1] != '"') return null;
    const field = rest[1 .. rest.len - 1];
    // Pull short name from type_text (final ident segment after `.`).
    const dot = mem.lastIndexOfScalar(u8, type_text, '.');
    const short = if (dot) |d| type_text[d + 1 ..] else type_text;
    return .{
        .struct_name = try arena.dupe(u8, short),
        .field_name = try arena.dupe(u8, field),
    };
}

/// Substitute `{[<name>]<formatchar>}` placeholders in `fmt` with
/// either:
///   - `<<sym:<i>>>`  for a recognized `@offsetOf(T, "field")` arg
///                    (i = index into the returned refs slice)
///   - `<<opaque>>`   for any other expression
fn resolveComptimePrint(arena: Allocator, fmt_text: []const u8, args_text: []const u8) !ResolvedPrint {
    var args = try parseArgsLiteral(arena, args_text);
    defer args.deinit(arena);

    var refs = ArrayList(SymRef).empty;
    errdefer refs.deinit(arena);
    // Parse each arg as either a simple offsetOf or opaque.
    // index parallel to args.
    var resolved_kinds = try arena.alloc(?SimpleOffset, args.items.len);
    for (args.items, 0..) |a, i| {
        resolved_kinds[i] = try parseSimpleOffsetOf(arena, a.expr_text);
    }

    const decoded = try decodeFmt(arena, fmt_text);
    var buf = ArrayList(u8).empty;
    defer buf.deinit(arena);

    var i: usize = 0;
    while (i < decoded.len) {
        // Look for `{[<name>]<spec>}`.
        if (decoded[i] == '{' and i + 1 < decoded.len and decoded[i + 1] == '[') {
            // Parse name.
            const name_start = i + 2;
            var k = name_start;
            while (k < decoded.len and decoded[k] != ']') k += 1;
            if (k >= decoded.len) {
                try buf.append(arena, decoded[i]);
                i += 1;
                continue;
            }
            const name = decoded[name_start..k];
            // Skip past `]<spec>}`.
            var brace = k + 1;
            while (brace < decoded.len and decoded[brace] != '}') brace += 1;
            if (brace >= decoded.len) {
                try buf.append(arena, decoded[i]);
                i += 1;
                continue;
            }
            // Find matching arg.
            var arg_idx: ?usize = null;
            for (args.items, 0..) |a, ai| {
                if (mem.eql(u8, a.name, name)) {
                    arg_idx = ai;
                    break;
                }
            }
            if (arg_idx) |ai| {
                if (resolved_kinds[ai]) |so| {
                    const ref_idx = refs.items.len;
                    try refs.append(arena, .{
                        .placeholder = try arena.dupe(u8, name),
                        .is_simple = true,
                        .struct_name = so.struct_name,
                        .field_name = so.field_name,
                    });
                    var marker_buf: [64]u8 = undefined;
                    const marker = try std.fmt.bufPrint(&marker_buf, "<<sym:{d}>>", .{ref_idx});
                    try buf.appendSlice(arena, marker);
                } else {
                    // Opaque numeric.
                    try buf.appendSlice(arena, "<<opaque>>");
                }
            } else {
                // Unknown placeholder — pass through.
                try buf.appendSlice(arena, decoded[i .. brace + 1]);
            }
            i = brace + 1;
            continue;
        }
        try buf.append(arena, decoded[i]);
        i += 1;
    }
    return .{
        .text = try arena.dupe(u8, buf.items),
        .refs = try refs.toOwnedSlice(arena),
    };
}

/// Attach refs to lines emitted from ONE comptimePrint resolution. The
/// refs slice's indices `0..refs.len` correspond to `<<sym:N>>` markers
/// in the lines' text. We attach the FULL refs slice to every line in
/// this batch — the markers index into `line.refs[N]` directly, so the
/// slice must preserve the comptimePrint's own indexing. Different
/// comptimePrint calls produce different `line.refs` slices, so there's
/// no cross-call collision even though indices restart at 0 per call.
fn attachRefs(
    out: *ExpansionList,
    start_idx: usize,
    refs: []const SymRef,
) !void {
    if (refs.len == 0) return;
    var i = start_idx;
    while (i < out.items.len) : (i += 1) {
        out.items[i].refs = refs;
    }
}

// ── Pattern matching + analysis ───────────────────────────────────────

/// Per-line classification.
const LineClass = union(enum) {
    label: []const u8,                                  // ".Lname"
    jmp_uncond: []const u8,                              // jmp .Lname
    jmp_cond: struct { cc: []const u8, target: []const u8 }, // jcc .Lname
    cmpxchg_acquire: AccessSite,                         // lock cmpxchgq ..., <T._gen_lock>(%base)
    release: AccessSite,                                 // andq $-2, <T._gen_lock>(%base)
    field_access: AccessSite,                            // <op> ... <T.<field>>(%base)
    raw_access: struct { base_reg: []const u8, offset: i64 }, // <op> ... <num>(%base)
    other,
};

const AccessSite = struct {
    struct_name: []const u8,
    field_name: []const u8,
    base_reg: []const u8,
};

const Operand = struct {
    /// Symbolic ref index (if any); -1 if numeric/none.
    ref_idx: i32,
    /// Numeric offset (if any).
    num_offset: ?i64,
    /// True iff the offset came from a comptimePrint placeholder
    /// substitution where the arg expression wasn't a recognizable
    /// `@offsetOf(T, "field")`. The user is still using comptimePrint
    /// (so we trust them) but we can't pin a struct field. Treated as
    /// a field-access of `base_reg`'s currently-typed struct.
    is_opaque_sub: bool = false,
    /// Base register name (e.g. "rcx"); empty if not a memory operand.
    base_reg: []const u8,
};

fn classifyLine(line: AsmLine, slab_types: *const StringHashMap(void)) LineClass {
    const text = line.text;
    // Label: `.L<name>:`
    if (text.len > 0 and text[text.len - 1] == ':') {
        return .{ .label = trimAscii(text[0 .. text.len - 1]) };
    }
    // Skip blank.
    if (text.len == 0) return .other;

    // First token = mnemonic.
    var i: usize = 0;
    while (i < text.len and !ascii.isWhitespace(text[i])) i += 1;
    const mnem = text[0..i];

    // Unconditional jump.
    if (mem.eql(u8, mnem, "jmp")) {
        const target = trimAscii(text[i..]);
        return .{ .jmp_uncond = target };
    }
    // Conditional jumps (single instruction set).
    if (mem.startsWith(u8, mnem, "j") and mnem.len <= 4 and !mem.eql(u8, mnem, "jmp")) {
        const target = trimAscii(text[i..]);
        return .{ .jmp_cond = .{ .cc = mnem, .target = target } };
    }

    // `lock cmpxchgq %src, <op>` — acquire pattern.
    if (mem.eql(u8, mnem, "lock")) {
        // Skip `lock` and find next mnemonic.
        const j = skipWsAsm(text, i);
        var k = j;
        while (k < text.len and !ascii.isWhitespace(text[k])) k += 1;
        const m2 = text[j..k];
        if (mem.eql(u8, m2, "cmpxchgq") or mem.eql(u8, m2, "cmpxchg")) {
            // Second operand is the destination memory operand.
            const op = parseLastMemOperand(text[k..], line.refs) orelse return .other;
            if (op.ref_idx >= 0) {
                const r = line.refs[@intCast(op.ref_idx)];
                if (mem.eql(u8, r.field_name, "_gen_lock")) {
                    return .{ .cmpxchg_acquire = .{
                        .struct_name = r.struct_name,
                        .field_name = r.field_name,
                        .base_reg = op.base_reg,
                    } };
                }
            }
            // cmpxchg on non-`_gen_lock` is unusual; treat as raw access.
            if (op.num_offset) |_| {
                return .{ .raw_access = .{ .base_reg = op.base_reg, .offset = op.num_offset.? } };
            }
            return .other;
        }
        return .other;
    }

    // `andq $-2, <op>` — release pattern.
    if (mem.eql(u8, mnem, "andq")) {
        // Check immediate is `$-2`.
        const rest = trimAscii(text[i..]);
        if (mem.startsWith(u8, rest, "$-2,") or mem.startsWith(u8, rest, "$-2 ,")) {
            const op_start = mem.indexOfScalar(u8, rest, ',').? + 1;
            const op = parseLastMemOperand(rest[op_start..], line.refs) orelse return .other;
            if (op.ref_idx >= 0) {
                const r = line.refs[@intCast(op.ref_idx)];
                if (mem.eql(u8, r.field_name, "_gen_lock")) {
                    return .{ .release = .{
                        .struct_name = r.struct_name,
                        .field_name = r.field_name,
                        .base_reg = op.base_reg,
                    } };
                }
            }
        }
        // fall through to generic memory-operand classification below
    }

    // Generic: any memory operand `<offset>(%base)` in the line.
    const op = parseLastMemOperand(text[i..], line.refs) orelse return .other;
    if (op.ref_idx >= 0) {
        const r = line.refs[@intCast(op.ref_idx)];
        if (slab_types.contains(r.struct_name) and !mem.eql(u8, r.field_name, "_gen_lock")) {
            return .{ .field_access = .{
                .struct_name = r.struct_name,
                .field_name = r.field_name,
                .base_reg = op.base_reg,
            } };
        }
        return .other;
    }
    // Opaque substitution: trust the user used @offsetOf-derived math
    // through comptimePrint, but we can't pin the field. Treat as a
    // field access of whatever base_reg is currently typed as.
    if (op.is_opaque_sub) {
        return .{ .field_access = .{
            .struct_name = "<opaque>",
            .field_name = "<unknown>",
            .base_reg = op.base_reg,
        } };
    }
    if (op.num_offset) |off| {
        return .{ .raw_access = .{ .base_reg = op.base_reg, .offset = off } };
    }
    return .other;
}

/// Find the destination register (AT&T: rightmost operand) for a write
/// instruction. Returns null when the destination isn't a single register
/// (memory, no operands, control flow, etc.). Used to invalidate
/// register-to-slab-type bindings after a register gets overwritten.
fn instructionDestReg(text: []const u8) ?[]const u8 {
    // Find first whitespace to separate mnemonic from operands.
    var i: usize = 0;
    while (i < text.len and !ascii.isWhitespace(text[i])) i += 1;
    if (i == text.len) return null; // no operands
    const mnem = text[0..i];

    // Skip control-flow / no-write mnemonics.
    if (mem.eql(u8, mnem, "jmp")) return null;
    if (mem.startsWith(u8, mnem, "j") and mnem.len <= 4) return null; // jcc
    if (mem.eql(u8, mnem, "ret") or mem.eql(u8, mnem, "iretq")) return null;
    if (mem.eql(u8, mnem, "call")) return null;
    if (mem.eql(u8, mnem, "push") or mem.eql(u8, mnem, "pushq")) return null;
    if (mem.eql(u8, mnem, "test") or mem.eql(u8, mnem, "testq") or
        mem.eql(u8, mnem, "testl") or mem.eql(u8, mnem, "testb"))
        return null;
    if (mem.eql(u8, mnem, "cmp") or mem.eql(u8, mnem, "cmpq") or
        mem.eql(u8, mnem, "cmpl") or mem.eql(u8, mnem, "cmpb"))
        return null;
    if (mem.eql(u8, mnem, "swapgs") or mem.eql(u8, mnem, "stac") or
        mem.eql(u8, mnem, "clac") or mem.eql(u8, mnem, "pause") or
        mem.eql(u8, mnem, "ud2") or mem.eql(u8, mnem, "lfence") or
        mem.eql(u8, mnem, "mfence") or mem.eql(u8, mnem, "sfence"))
        return null;
    // `lock` prefix instructions: the destination is memory (the
    // cmpxchg's second operand). We classify those separately, and
    // those don't overwrite the base reg.
    if (mem.eql(u8, mnem, "lock")) return null;

    // Find the rightmost operand. Strip trailing whitespace, then walk
    // back to a top-level comma (depth 0).
    var end = text.len;
    while (end > 0 and ascii.isWhitespace(text[end - 1])) end -= 1;
    if (end <= i) return null;
    var p = end;
    var depth: i32 = 0;
    while (p > i) {
        p -= 1;
        const c = text[p];
        if (c == ')' or c == ']') depth += 1;
        if (c == '(' or c == '[') depth -= 1;
        if (c == ',' and depth == 0) {
            const rhs_start = p + 1;
            const rhs = trimAscii(text[rhs_start..end]);
            // If RHS is `%<reg>`, return the reg name.
            if (rhs.len < 2 or rhs[0] != '%') return null;
            var s = rhs[1..];
            if (s.len > 0 and s[0] == '%') s = s[1..]; // double-`%` from Zig asm
            // Reject memory operand `(%base)` etc.
            for (s) |ch| if (!ascii.isAlphanumeric(ch) and ch != '_') return null;
            return s;
        }
    }
    return null;
}

fn skipWsAsm(s: []const u8, start: usize) usize {
    var i = start;
    while (i < s.len and ascii.isWhitespace(s[i])) i += 1;
    return i;
}

/// Find a `<offset>(%base)` memory operand anywhere in the operands
/// portion of an asm line. AT&T syntax puts memory on either side of
/// the comma depending on instruction (src,dst order with src or dst
/// possibly being memory). Most instructions have at most one memory
/// operand, so we just find the first `(` that closes properly with a
/// `%reg` inside.
///
/// Supported offset forms:
///   - `<<sym:N>>`   (substituted symbolic ref)
///   - `<<opaque>>`  (substituted but expr wasn't @offsetOf)
///   - `<integer>`   (raw numeric, decimal or 0x-hex)
///   - empty         (shorthand for `0(%base)`)
fn parseLastMemOperand(operands: []const u8, refs: []const SymRef) ?Operand {
    // Scan for `(` that opens a memory operand: the first reg inside
    // is `%<name>`. Walk left-to-right so we find the first such operand
    // (matches the typical case of one mem operand per instruction).
    var i: usize = 0;
    while (i < operands.len) : (i += 1) {
        if (operands[i] != '(') continue;
        // Find matching ')'.
        var depth: i32 = 1;
        var j: usize = i + 1;
        while (j < operands.len) : (j += 1) {
            if (operands[j] == '(') depth += 1;
            if (operands[j] == ')') {
                depth -= 1;
                if (depth == 0) break;
            }
        }
        if (depth != 0) return null;
        const inner = operands[i + 1 .. j];
        const base_reg = parseRegName(inner) orelse {
            // Not a memory operand; keep scanning.
            i = j;
            continue;
        };

        // Offset = text immediately preceding `(`.
        var off_end = i;
        while (off_end > 0 and ascii.isWhitespace(operands[off_end - 1])) off_end -= 1;
        var off_start = off_end;
        while (off_start > 0) {
            const c = operands[off_start - 1];
            if (ascii.isWhitespace(c) or c == ',') break;
            off_start -= 1;
        }
        const off_text = operands[off_start..off_end];

        if (mem.startsWith(u8, off_text, "<<sym:") and mem.endsWith(u8, off_text, ">>")) {
            const num_text = off_text["<<sym:".len .. off_text.len - 2];
            const idx = std.fmt.parseInt(usize, num_text, 10) catch return .{
                .ref_idx = -1, .num_offset = null, .base_reg = base_reg,
            };
            if (idx >= refs.len) return .{
                .ref_idx = -1, .num_offset = null, .base_reg = base_reg,
            };
            return .{ .ref_idx = @intCast(idx), .num_offset = null, .base_reg = base_reg };
        }
        if (mem.eql(u8, off_text, "<<opaque>>")) {
            return .{ .ref_idx = -1, .num_offset = 0, .is_opaque_sub = true, .base_reg = base_reg };
        }
        if (off_text.len == 0) {
            return .{ .ref_idx = -1, .num_offset = 0, .base_reg = base_reg };
        }
        const n = std.fmt.parseInt(i64, off_text, 0) catch return null;
        return .{ .ref_idx = -1, .num_offset = n, .base_reg = base_reg };
    }
    return null;
}

/// Parse the first `%<reg>` in `s`; returns the register name (e.g. "rcx").
fn parseRegName(s: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < s.len and (ascii.isWhitespace(s[i]) or s[i] == ',')) i += 1;
    if (i + 1 >= s.len or s[i] != '%') return null;
    var j = i + 1;
    // GAS AT&T uses `%%reg` inside Zig's asm macro, where the second `%`
    // belongs to the register name? No — it's escape-doubled by Zig's
    // string interp. We may see one or two `%`s depending on how we
    // captured the text.
    if (j < s.len and s[j] == '%') j += 1;
    const name_start = j;
    while (j < s.len and (ascii.isAlphanumeric(s[j]) or s[j] == '_')) j += 1;
    return s[name_start..j];
}

// ── Linear walker with label snapshots ────────────────────────────────

const ActiveLock = struct {
    struct_name: []const u8,
    base_reg: []const u8,
};

const State = struct {
    locks: ArrayList(ActiveLock),
    /// Registers known to be slab pointers (any prior symbolic access
    /// through this register evidences a slab type). We track the most
    /// recent type per register; subsequent raw numeric accesses through
    /// the same register are flagged.
    typed_regs: StringHashMapUnmanaged([]const u8), // base_reg → struct_name
    /// False when fall-through reached us via dead-code (after an
    /// unconditional jmp). The next label must adopt its snapshot
    /// rather than compare to ours.
    alive: bool,

    fn init() State {
        return .{
            .locks = .empty,
            .typed_regs = .empty,
            .alive = true,
        };
    }

    fn deinit(self: *State, arena: Allocator) void {
        self.locks.deinit(arena);
        self.typed_regs.deinit(arena);
    }

    fn clone(self: *const State, arena: Allocator) !State {
        var copy = State.init();
        copy.alive = self.alive;
        try copy.locks.appendSlice(arena, self.locks.items);
        var it = self.typed_regs.iterator();
        while (it.next()) |kv| try copy.typed_regs.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        return copy;
    }

    fn adopt(self: *State, arena: Allocator, src: *const State) !void {
        self.locks.clearRetainingCapacity();
        try self.locks.appendSlice(arena, src.locks.items);
        self.typed_regs.clearRetainingCapacity();
        var it = src.typed_regs.iterator();
        while (it.next()) |kv| try self.typed_regs.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        self.alive = true;
    }

    fn holdsLock(self: *const State, struct_name: []const u8, base_reg: []const u8) bool {
        for (self.locks.items) |l| {
            if (mem.eql(u8, l.struct_name, struct_name) and mem.eql(u8, l.base_reg, base_reg))
                return true;
        }
        return false;
    }

    fn addLock(self: *State, arena: Allocator, struct_name: []const u8, base_reg: []const u8) !void {
        if (self.holdsLock(struct_name, base_reg)) return;
        try self.locks.append(arena, .{ .struct_name = struct_name, .base_reg = base_reg });
    }

    fn dropLock(self: *State, struct_name: []const u8, base_reg: []const u8) bool {
        var i: usize = 0;
        while (i < self.locks.items.len) : (i += 1) {
            const l = self.locks.items[i];
            if (mem.eql(u8, l.struct_name, struct_name) and mem.eql(u8, l.base_reg, base_reg)) {
                _ = self.locks.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    fn equals(self: *const State, other: *const State) bool {
        if (self.locks.items.len != other.locks.items.len) return false;
        for (self.locks.items) |a| {
            if (!other.holdsLock(a.struct_name, a.base_reg)) return false;
        }
        return true;
    }
};

const LabelSnapshot = struct {
    name: []const u8,
    state: State,
    first_line: u32,
};

fn analyzeLines(
    gpa: Allocator,
    arena: Allocator,
    lines: []AsmLine,
    fn_qname: []const u8,
    file_path: []const u8,
    slab_types: *const StringHashMap(void),
    out: *ArrayList(Finding),
) !void {
    var state = State.init();
    defer state.deinit(arena);

    // `name → snapshot`
    var snaps = StringHashMapUnmanaged(*State).empty;
    defer snaps.deinit(arena);
    var snap_storage = ArrayList(*State).empty;
    defer {
        for (snap_storage.items) |s| {
            s.deinit(arena);
        }
        snap_storage.deinit(arena);
    }

    var i: usize = 0;
    while (i < lines.len) : (i += 1) {
        const ln = lines[i];
        const class = classifyLine(ln, slab_types);
        // Type-tracking invalidation: when a tracked register becomes
        // the destination of a write, it no longer points to the same
        // slab. Subsequent symbolic accesses re-type it. We do this
        // BEFORE classifying acquire/release/etc. — those operate on
        // memory operands, not register destinations, so they don't
        // overwrite the base reg.
        if (class == .other or class == .field_access or class == .raw_access) {
            if (instructionDestReg(ln.text)) |dest| {
                _ = state.typed_regs.remove(dest);
            }
        }
        switch (class) {
            .label => |name| {
                if (snaps.get(name)) |snap_ptr| {
                    if (state.alive) {
                        if (!state.equals(snap_ptr)) {
                            try emit(gpa, arena, out, .{
                                .file_path = file_path,
                                .line = ln.source_line,
                                .fn_qname = fn_qname,
                                .rule = "asm_label_state_mismatch",
                                .message = try std.fmt.allocPrint(
                                    arena,
                                    "label {s}: lock state at fall-through differs from prior jump-target state",
                                    .{name},
                                ),
                            });
                        }
                        // Adopt to ensure consistency.
                        try state.adopt(arena, snap_ptr);
                    } else {
                        // Reached only via prior jump(s). Adopt the snapshot.
                        try state.adopt(arena, snap_ptr);
                    }
                } else {
                    if (state.alive) {
                        // First reach via fall-through. Snapshot now.
                        const sp = try arena.create(State);
                        sp.* = try state.clone(arena);
                        try snap_storage.append(arena, sp);
                        try snaps.put(arena, try arena.dupe(u8, name), sp);
                    } else {
                        // Dead-code label with no incoming jumps. Treat
                        // as a fresh reachable point with empty state.
                        state.locks.clearRetainingCapacity();
                        state.typed_regs.clearRetainingCapacity();
                        state.alive = true;
                    }
                }
            },
            .cmpxchg_acquire => |acq| {
                // Look ahead for the immediately-following `je .L<label>`.
                // If found, that label's snapshot acquires lock(T at base).
                // The fall-through path does not.
                if (i + 1 < lines.len) {
                    const nxt = lines[i + 1];
                    const nxt_class = classifyLine(nxt, slab_types);
                    if (nxt_class == .jmp_cond and mem.eql(u8, nxt_class.jmp_cond.cc, "je")) {
                        const target = nxt_class.jmp_cond.target;
                        // Compute the would-be acquired state.
                        var acquired = try state.clone(arena);
                        try acquired.addLock(arena, acq.struct_name, acq.base_reg);
                        try acquired.typed_regs.put(arena, acq.base_reg, acq.struct_name);
                        try recordOrCheckSnap(gpa, arena, &snaps, &snap_storage, target, &acquired, fn_qname, file_path, nxt.source_line, out);
                        // Fall-through path also evidences %base is *T,
                        // even though the lock isn't held.
                        try state.typed_regs.put(arena, acq.base_reg, acq.struct_name);
                        // Fall-through: state unchanged.
                        i += 1; // skip the je we already consumed
                        continue;
                    }
                }
                // No `je` follows — accept it as an unconditional acquire.
                try state.addLock(arena, acq.struct_name, acq.base_reg);
                try state.typed_regs.put(arena, acq.base_reg, acq.struct_name);
            },
            .release => |rel| {
                if (!state.dropLock(rel.struct_name, rel.base_reg)) {
                    try emit(gpa, arena, out, .{
                        .file_path = file_path,
                        .line = ln.source_line,
                        .fn_qname = fn_qname,
                        .rule = "asm_release_without_acquire",
                        .message = try std.fmt.allocPrint(
                            arena,
                            "release of {s}._gen_lock via %{s}: not currently held",
                            .{ rel.struct_name, rel.base_reg },
                        ),
                    });
                }
            },
            .field_access => |acc| {
                // For opaque substitutions, infer the struct from the
                // currently-typed base reg. Otherwise the access itself
                // evidences the type, so register it.
                const struct_name = if (mem.eql(u8, acc.struct_name, "<opaque>"))
                    state.typed_regs.get(acc.base_reg) orelse continue
                else blk: {
                    try state.typed_regs.put(arena, acc.base_reg, acc.struct_name);
                    break :blk acc.struct_name;
                };
                if (!state.holdsLock(struct_name, acc.base_reg)) {
                    try emit(gpa, arena, out, .{
                        .file_path = file_path,
                        .line = ln.source_line,
                        .fn_qname = fn_qname,
                        .rule = "asm_unlocked_field_access",
                        .message = try std.fmt.allocPrint(
                            arena,
                            "access {s}.{s} via %{s}: lock not held",
                            .{ struct_name, acc.field_name, acc.base_reg },
                        ),
                    });
                }
            },
            .raw_access => |raw| {
                if (state.typed_regs.get(raw.base_reg)) |t| {
                    try emit(gpa, arena, out, .{
                        .file_path = file_path,
                        .line = ln.source_line,
                        .fn_qname = fn_qname,
                        .rule = "asm_raw_offset_on_slab",
                        .message = try std.fmt.allocPrint(
                            arena,
                            "raw numeric offset {d}(%{s}) where %{s} is typed *{s}: use @offsetOf via comptimePrint",
                            .{ raw.offset, raw.base_reg, raw.base_reg, t },
                        ),
                    });
                }
            },
            .jmp_uncond => |target| {
                try recordOrCheckSnap(gpa, arena, &snaps, &snap_storage, target, &state, fn_qname, file_path, ln.source_line, out);
                // Mark as dead-code; next label adopts its snapshot.
                state.locks.clearRetainingCapacity();
                state.typed_regs.clearRetainingCapacity();
                state.alive = false;
            },
            .jmp_cond => |jc| {
                try recordOrCheckSnap(gpa, arena, &snaps, &snap_storage, jc.target, &state, fn_qname, file_path, ln.source_line, out);
            },
            .other => {},
        }
    }
}

fn recordOrCheckSnap(
    gpa: Allocator,
    arena: Allocator,
    snaps: *StringHashMapUnmanaged(*State),
    snap_storage: *ArrayList(*State),
    name: []const u8,
    cur: *State,
    fn_qname: []const u8,
    file_path: []const u8,
    line: u32,
    out: *ArrayList(Finding),
) !void {
    if (snaps.get(name)) |snap_ptr| {
        if (!cur.equals(snap_ptr)) {
            try emit(gpa, arena, out, .{
                .file_path = file_path,
                .line = line,
                .fn_qname = fn_qname,
                .rule = "asm_jump_state_mismatch",
                .message = try std.fmt.allocPrint(
                    arena,
                    "jump to {s}: lock state at this site differs from prior visit",
                    .{name},
                ),
            });
        }
        return;
    }
    const sp = try arena.create(State);
    sp.* = try cur.clone(arena);
    try snap_storage.append(arena, sp);
    try snaps.put(arena, try arena.dupe(u8, name), sp);
}

fn emit(gpa: Allocator, _: Allocator, out: *ArrayList(Finding), f: Finding) !void {
    try out.append(gpa, f);
}
