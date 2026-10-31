//! Stage 5a — mechanical interrupt/exception entry-point discovery.
//!
//! The original entry_point population was a hand-maintained name list in a
//! SQL `LIKE` chain (see `main.zig`'s `entry_sql`). A name list can only ever
//! be as complete as the last person who edited it: on x86_64 it knew
//! `exceptionHandler`, `pageFaultHandler` and `schedTimerHandler` and missed
//! the other seven live IDT handlers — `deviceIrqHandler`, `spuriousHandler`,
//! the TLB-shootdown / FPU-flush IPI vectors — because they are neither
//! in the list nor in `arch/*/exceptions.zig`.
//!
//! This pass derives the set from the two places the kernel actually binds a
//! vector to a Zig function, so a new handler is discovered the moment it is
//! wired up:
//!
//!   R1  `interrupts.registerVector(<vec>, <handler>, .<VectorKind>)` — the
//!       x86-64 IDT. The dispatch itself is an indirect call through
//!       `vector_table[]`, so the registration call is the only static
//!       vector→handler link that exists. The third argument is the
//!       `VectorKind` literal: `.external` → `irq`, `.exception` →
//!       `exception`.
//!
//!   R2  `&handler` bound as an inline-asm operand inside a
//!       `callconv(.naked)` function — the aarch64 exception vector table,
//!       whose sixteen entries `adrp` each handler's address out of the
//!       operand list.
//!
//! Handler arguments are written in Stygia's file-local-alias style
//! (`paging_mod.tlbShootdownHandler`), so resolution expands a file's
//! `const NAME = a.b.c;` decls before matching against qualified names.
//!
//! Emitted rows are merged with `INSERT OR IGNORE` *after* the legacy
//! name-based inserts, so an entity already rooted keeps its existing kind
//! and label and only genuinely new entries are added.

const std = @import("std");
const types = @import("types.zig");
const writer = @import("writer.zig");
const tokens_mod = @import("tokens.zig");

const FinalEntity = writer.FinalEntity;

pub const EntryRow = struct {
    entity_id: u32,
    /// `irq` | `exception`
    kind: []const u8,
    label: []const u8,
    /// How it was found — for the stage log, not persisted.
    source: []const u8,
};

pub const Result = struct {
    rows: []EntryRow,
    /// Registration sites whose handler argument did not resolve to a
    /// function entity. Logged so a rename cannot silently shrink the set.
    unresolved: []const []const u8,
};

const Tok = struct {
    kind: []const u8,
    byte_start: u32,
    text: []const u8,
};

const FnRange = struct { start: u32, end: u32, ent: u32 };

const VECTOR_REGISTRARS = [_][]const u8{"registerVector"};

pub fn pass(
    a: std.mem.Allocator,
    files: []const types.FileRecord,
    entities: []const FinalEntity,
) !Result {
    // ── Index entities ────────────────────────────────────────────────
    var by_short: std.StringHashMapUnmanaged(std.ArrayList(u32)) = .empty;
    var fn_ranges_by_file: std.AutoHashMapUnmanaged(u32, std.ArrayList(FnRange)) = .empty;
    for (entities, 0..) |e, i| {
        if (!std.mem.eql(u8, e.kind, "fn")) continue;
        const short = shortName(e.qualified_name);
        const gop = try by_short.getOrPut(a, short);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, @intCast(i));

        const rg = try fn_ranges_by_file.getOrPut(a, e.def_file_id);
        if (!rg.found_existing) rg.value_ptr.* = .empty;
        try rg.value_ptr.append(a, .{
            .start = e.def_byte_start,
            .end = e.def_byte_end,
            .ent = @intCast(i),
        });
    }

    var out: std.ArrayList(EntryRow) = .empty;
    var unresolved: std.ArrayList([]const u8) = .empty;
    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;

    for (files) |file| {
        const toks = try tokenizeFile(a, file.source);
        if (toks.len == 0) continue;
        const ranges: []const FnRange = if (fn_ranges_by_file.get(file.id)) |l| l.items else &.{};
        var aliases = try buildAliases(a, toks);
        defer aliases.deinit(a);

        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (!std.mem.eql(u8, toks[i].kind, "identifier")) continue;

            // ── R1: registerVector(vec, HANDLER, .kind) ───────────────
            if (isRegistrar(toks[i].text) and
                i + 1 < toks.len and std.mem.eql(u8, toks[i + 1].kind, "l_paren"))
            {
                if (try nthArgChain(a, toks, i + 1, 1)) |segs| {
                    const vk = enumLiteralArg(toks, i + 1, 2);
                    const kind: []const u8 = if (vk) |v|
                        (if (std.mem.eql(u8, v, "exception")) "exception" else "irq")
                    else
                        "irq";
                    if (resolveFn(a, entities, &by_short, &aliases, segs, file.id)) |ei| {
                        try emit(a, &out, &seen, entities, ei, kind, "vector_table");
                    } else {
                        try unresolved.append(a, try std.fmt.allocPrint(
                            a,
                            "{s}: registerVector handler `{s}` did not resolve",
                            .{ file.path, try joinChain(a, segs) },
                        ));
                    }
                }
            }

            // ── R2: `&handler` inside a callconv(.naked) fn ───────────
            if (i > 0 and std.mem.eql(u8, toks[i - 1].kind, "ampersand")) {
                if (enclosingFn(ranges, toks[i].byte_start)) |host| {
                    if (isNaked(toks, entities[host])) {
                        const ch = readChain(a, toks, i) catch continue;
                        if (resolveFn(a, entities, &by_short, &aliases, ch.segs, file.id)) |ei| {
                            const nm = shortName(entities[ei].qualified_name);
                            const kind: []const u8 = if (containsIgnoreCase(nm, "irq")) "irq" else "exception";
                            try emit(a, &out, &seen, entities, ei, kind, "naked_asm");
                        }
                    }
                }
            }
        }
    }

    return .{
        .rows = try out.toOwnedSlice(a),
        .unresolved = try unresolved.toOwnedSlice(a),
    };
}

fn emit(
    a: std.mem.Allocator,
    out: *std.ArrayList(EntryRow),
    seen: *std.AutoHashMapUnmanaged(u32, void),
    entities: []const FinalEntity,
    ent_idx: u32,
    kind: []const u8,
    source: []const u8,
) !void {
    const e = entities[ent_idx];
    if (seen.contains(e.id)) return;
    try seen.put(a, e.id, {});
    try out.append(a, .{
        .entity_id = e.id,
        .kind = kind,
        .label = e.qualified_name,
        .source = source,
    });
}

// ── Tokens ─────────────────────────────────────────────────────────────

fn tokenizeFile(a: std.mem.Allocator, source: [:0]const u8) ![]Tok {
    const rows = try tokens_mod.tokenize(a, source);
    const out = try a.alloc(Tok, rows.len);
    for (rows, 0..) |r, i| {
        out[i] = .{ .kind = r.kind, .byte_start = r.byte_start, .text = r.text };
    }
    return out;
}

fn isRegistrar(name: []const u8) bool {
    for (VECTOR_REGISTRARS) |r| if (std.mem.eql(u8, name, r)) return true;
    return false;
}

const Chain = struct { segs: []const []const u8, next: usize };

/// `a.b.c` starting at token `i` (which must be an identifier).
fn readChain(a: std.mem.Allocator, toks: []const Tok, i: usize) !Chain {
    var segs: std.ArrayList([]const u8) = .empty;
    try segs.append(a, toks[i].text);
    var j = i + 1;
    while (j + 1 < toks.len and
        std.mem.eql(u8, toks[j].kind, "period") and
        std.mem.eql(u8, toks[j + 1].kind, "identifier"))
    {
        try segs.append(a, toks[j + 1].text);
        j += 2;
    }
    return .{ .segs = try segs.toOwnedSlice(a), .next = j };
}

fn isOpen(k: []const u8) bool {
    return std.mem.eql(u8, k, "l_paren") or std.mem.eql(u8, k, "l_bracket") or std.mem.eql(u8, k, "l_brace");
}
fn isClose(k: []const u8) bool {
    return std.mem.eql(u8, k, "r_paren") or std.mem.eql(u8, k, "r_bracket") or std.mem.eql(u8, k, "r_brace");
}

/// Chain of the `n`-th (0-based) argument of the call whose `l_paren` is at
/// `lparen_i`. Null when that argument is not a bare (optionally
/// address-of'd) identifier chain — an expression argument names no single
/// function, and guessing one would invent an entry point.
fn nthArgChain(a: std.mem.Allocator, toks: []const Tok, lparen_i: usize, n: usize) !?[]const []const u8 {
    var depth: i32 = 0;
    var arg: usize = 0;
    var arg_start: usize = lparen_i + 1;
    var i = lparen_i;
    while (i < toks.len) : (i += 1) {
        const k = toks[i].kind;
        if (isOpen(k)) {
            depth += 1;
        } else if (isClose(k)) {
            depth -= 1;
            if (depth == 0) {
                if (arg == n) return try argChain(a, toks, arg_start, i);
                return null;
            }
        } else if (std.mem.eql(u8, k, "comma") and depth == 1) {
            if (arg == n) return try argChain(a, toks, arg_start, i);
            arg += 1;
            arg_start = i + 1;
        }
    }
    return null;
}

fn argChain(a: std.mem.Allocator, toks: []const Tok, from: usize, to: usize) !?[]const []const u8 {
    var i = from;
    while (i < to and std.mem.eql(u8, toks[i].kind, "ampersand")) i += 1;
    if (i >= to or !std.mem.eql(u8, toks[i].kind, "identifier")) return null;
    const ch = try readChain(a, toks, i);
    if (ch.next != to) return null; // expression, not a bare chain
    return ch.segs;
}

/// The `.<ident>` enum literal in argument `n`, if that argument is exactly
/// one.
fn enumLiteralArg(toks: []const Tok, lparen_i: usize, n: usize) ?[]const u8 {
    var depth: i32 = 0;
    var arg: usize = 0;
    var start: usize = lparen_i + 1;
    var i = lparen_i;
    while (i < toks.len) : (i += 1) {
        const k = toks[i].kind;
        var at_boundary = false;
        if (isOpen(k)) {
            depth += 1;
        } else if (isClose(k)) {
            depth -= 1;
            at_boundary = depth == 0;
        } else if (std.mem.eql(u8, k, "comma") and depth == 1) {
            at_boundary = true;
        }
        if (!at_boundary) continue;
        if (arg == n) {
            if (start + 1 < i and
                std.mem.eql(u8, toks[start].kind, "period") and
                std.mem.eql(u8, toks[start + 1].kind, "identifier")) return toks[start + 1].text;
            return null;
        }
        if (std.mem.eql(u8, k, "comma")) {
            arg += 1;
            start = i + 1;
        } else return null;
    }
    return null;
}

// ── File-local `const NAME = a.b.c;` aliases ───────────────────────────

fn buildAliases(a: std.mem.Allocator, toks: []const Tok) !std.StringHashMapUnmanaged([]const []const u8) {
    var m: std.StringHashMapUnmanaged([]const []const u8) = .empty;
    var i: usize = 0;
    while (i + 4 < toks.len) : (i += 1) {
        if (!std.mem.eql(u8, toks[i].kind, "keyword_const")) continue;
        if (!std.mem.eql(u8, toks[i + 1].kind, "identifier")) continue;
        if (!std.mem.eql(u8, toks[i + 2].kind, "equal")) continue;
        if (!std.mem.eql(u8, toks[i + 3].kind, "identifier")) continue;
        const ch = try readChain(a, toks, i + 3);
        // Only a bare `const NAME = chain;` is a pure namespace rename;
        // anything else (a call, an index) would be a guess to expand.
        if (ch.next >= toks.len or !std.mem.eql(u8, toks[ch.next].kind, "semicolon")) continue;
        if (ch.segs.len < 2) continue;
        try m.put(a, toks[i + 1].text, ch.segs);
    }
    return m;
}

// ── Resolution ─────────────────────────────────────────────────────────

/// Resolve an identifier chain to a unique function entity index.
///
///   1. whole chain is a qualified-name suffix, uniquely;
///   2. …the same, restricted to functions defined in `pref_file`;
///   3. single-segment chain, unique within `pref_file`;
///   4. single-segment chain, globally unique.
///
/// Ambiguity that survives all four resolves to "no entry": a guess would
/// invent an interrupt entry point, and a phantom entry is worse than a
/// missing one the `unresolved` log names.
fn resolveFn(
    a: std.mem.Allocator,
    entities: []const FinalEntity,
    by_short: *const std.StringHashMapUnmanaged(std.ArrayList(u32)),
    aliases: *const std.StringHashMapUnmanaged([]const []const u8),
    segs_in: []const []const u8,
    pref_file: u32,
) ?u32 {
    if (segs_in.len == 0) return null;
    const cands = by_short.get(segs_in[segs_in.len - 1]) orelse return null;
    if (cands.items.len == 0) return null;

    var segs = segs_in;
    if (segs.len > 1) {
        if (aliases.get(segs[0])) |exp| {
            var joined: std.ArrayList([]const u8) = .empty;
            joined.appendSlice(a, exp) catch return null;
            joined.appendSlice(a, segs[1..]) catch return null;
            segs = joined.items;
        }
    }
    // The root module is not part of any qualified name in the entity table.
    if (segs.len > 1 and std.mem.eql(u8, segs[0], "stygia")) segs = segs[1..];

    const chain = joinChain(a, segs) catch return null;

    // `full` = the chain IS the whole qualified name; `exact` = the chain is
    // a dot-aligned SUFFIX of it. Full equality is strictly the stronger
    // evidence and is tried first.
    //
    // Why this ordering is load-bearing: the indexer's source roots include
    // `tools/`, which contains this pass's OWN fixtures. So the tree holds
    // both
    //     arch.x64.paging.tlbShootdownHandler                       (kernel)
    //     tools.indexer.tests.fixtures.03_entry_points_register_vector
    //         .kernel.arch.x64.paging.tlbShootdownHandler           (fixture)
    // and the second one ends with `.arch.x64.paging.tlbShootdownHandler`.
    // Ranking suffix hits equally therefore produced exact_n == 2 for the
    // real IDT registration in kernel/arch/x64/irq.zig, which fell through
    // to `if (exact_n > 1) return null` and dropped the W9 TLB-shootdown IPI
    // handler from `entry_point` entirely — logged only as a one-line
    // "did not resolve" warning. Both check_gen_lock and check_thread_closure
    // seed from `entry_point`, so the shootdown path was a seed in NEITHER,
    // and any lock class reachable only from it was invisible to both. A
    // false NEGATIVE, unlike the rest of those tools' imprecision.
    //
    // A fixture can never win a full-equality match against a kernel entity
    // (its qualified name is prefixed by its path), so preferring full
    // equality resolves the collision in the kernel's favour without any
    // path-based special-casing. See bd stygia-ywh.
    var full: ?u32 = null;
    var full_n: usize = 0;
    var full_local: ?u32 = null;
    var full_local_n: usize = 0;
    var exact: ?u32 = null;
    var exact_n: usize = 0;
    var exact_local: ?u32 = null;
    var exact_local_n: usize = 0;
    var local: ?u32 = null;
    var local_n: usize = 0;
    for (cands.items) |ci| {
        const e = entities[ci];
        const is_local = e.def_file_id == pref_file;
        if (is_local) {
            local = ci;
            local_n += 1;
        }
        const qn = e.qualified_name;
        if (std.mem.eql(u8, qn, chain)) {
            full = ci;
            full_n += 1;
            if (is_local) {
                full_local = ci;
                full_local_n += 1;
            }
        }
        if (std.mem.eql(u8, qn, chain) or
            (qn.len > chain.len and std.mem.endsWith(u8, qn, chain) and qn[qn.len - chain.len - 1] == '.'))
        {
            exact = ci;
            exact_n += 1;
            if (is_local) {
                exact_local = ci;
                exact_local_n += 1;
            }
        }
    }
    if (full_n == 1) return full;
    if (full_local_n == 1) return full_local;
    if (exact_n == 1) return exact;
    if (exact_local_n == 1) return exact_local;
    if (exact_n > 1) return null;

    // A dotted chain names its callee; falling back to "the same-named fn
    // in this file" would be a different function. A single-segment chain
    // is the opposite case: a handler passed to `registerVector` has no
    // qualifier, and file scope is how Zig resolves it.
    if (segs.len == 1) {
        if (local_n == 1) return local;
        if (cands.items.len == 1) return cands.items[0];
    }
    return null;
}

fn enclosingFn(ranges: []const FnRange, byte: u32) ?u32 {
    var best: ?FnRange = null;
    for (ranges) |r| {
        if (r.start > byte or byte >= r.end) continue;
        if (best == null or r.start >= best.?.start) best = r;
    }
    return if (best) |b| b.ent else null;
}

/// `callconv(.naked)` appears in the signature, before the body's `{`.
fn isNaked(toks: []const Tok, e: FinalEntity) bool {
    for (toks) |t| {
        if (t.byte_start < e.def_byte_start) continue;
        if (t.byte_start >= e.def_byte_end) return false;
        if (std.mem.eql(u8, t.kind, "identifier") and std.mem.eql(u8, t.text, "naked")) return true;
        if (std.mem.eql(u8, t.kind, "l_brace")) return false; // past the signature
    }
    return false;
}

fn joinChain(a: std.mem.Allocator, segs: []const []const u8) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (segs, 0..) |s, i| {
        if (i != 0) try buf.append(a, '.');
        try buf.appendSlice(a, s);
    }
    return buf.items;
}

fn shortName(q: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, q, '.')) |p| return q[p + 1 ..];
    return q;
}

fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        var ok = true;
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(hay[i + j]) != std.ascii.toLower(c)) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}
