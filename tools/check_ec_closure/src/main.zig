//! EC-lifecycle closure analyzer over the per-(arch, commit_sha) callgraph DB.
//!
//! Mechanizes two enumerations that `docs/kernel/systems.md` currently
//! maintains by hand. The motivating observation: of the three tables in
//! that doc, the one derived from the callgraph DB survived a hostile
//! independent re-derivation with zero rows missing; the two closed from
//! human recall held every critical finding of the last review round.
//! Same author, same day — the only variable was whether a tool did the
//! enumeration.
//!
//! ─── Rule A — interrupt-context wake-source closure ────────────────────
//!
//! Reports every function reachable from an interrupt/exception entry
//! point that can wake or claim an execution context. Adding a new ISR
//! path that wakes an EC becomes a visible diff instead of a silent one.
//!
//!   seeds       union of three mechanical sources (see `collectIrqSeeds`)
//!   primitives  the EC claim / run-queue-insertion funnels (`WAKE_PRIMITIVES`)
//!   closure     fwd(seeds) ∩ bwd(primitives) over the call graph
//!   report      claim sites, grouped by their *wake source* — the first
//!               non-`arch/` function on the witness path from an ISR
//!
//! ─── Rule B — lock-class IRQ-masking closure ───────────────────────────
//!
//! Every `SpinLock` instance in this kernel is declared with an explicit
//! `.class = "…"` label (that is what the lockdep / stuck-lock wait table
//! in `utils/sync/debug.zig` keys on), which gives each lock a stable
//! static identity. For each class we classify every acquire site as
//! MASKED (`lockIrqSave` / `lockIrqSaveOrdered`) or PLAIN (`lock` /
//! `lockOrdered` / `tryLock`), and cross it with whether the acquiring
//! function is reachable from a syscall/boot entry (EC context) or only
//! from an interrupt entry (already IRQs-off by hardware).
//!
//! A class with PLAIN acquires on EC-context paths can be preempted while
//! held. That is the property the EC-lifecycle design needs to know about.
//!
//! ─── Why the call graph is repaired before either rule runs ────────────
//!
//! `ir_call` alone is NOT a sound base for a closure claim. The indexer
//! maps LLVM IR callee names back to entities by exact name, and Zig's
//! monomorphized generics carry decorated IR names
//! (`…SecureSlab(caps.capability_domain.CapabilityDomain,256).forEachAlive__anon_94571`)
//! that never match an entity row — so every call *through* a generic is
//! silently absent from `ir_call`. This is not hypothetical: on today's
//! tree the timer-wheel wake source
//!
//!     wheelExpireDue → onFire → propagateAndWake
//!                    → [SecureSlab(CapabilityDomain,256).forEachAlive]   ← IR edge missing
//!                    → propagateField0Visitor → propagateVisit → futex.wake
//!
//! is completely invisible in the raw `ir_call` graph. A tool built on
//! `ir_call` alone would have reported four wake sources and looked
//! authoritative doing it.
//!
//! So we overlay a *syntactic* call graph derived from the token stream
//! (`addSyntacticEdges`): every identifier chain inside a function body
//! that resolves unambiguously to a function entity becomes an edge,
//! whether it is syntactically a call or a bare function reference (an
//! address-taken callback — which is exactly what jumps the `forEachAlive`
//! gap). This over-approximates, which is the correct bias for a
//! "did we miss a wake path" tool, and every reported edge carries its
//! provenance (`ir` / `syn-call` / `syn-ref`) so a human can audit it.
//!
//! The overlay has a second benefit: both rules work on DBs built without
//! `--ir` at all, which is what the fixture harness produces.
//!
//! ─── Scope limits, stated up front ─────────────────────────────────────
//!
//!   • Rule B covers `SpinLock` classes only. Per-object `GenLock` /
//!     `SlabRef` acquires have no static class identity (one lock per slab
//!     slot) and are already the subject of `tools/check_gen_lock`. Every
//!     acquire receiver that fails to resolve to a declared SpinLock class
//!     is counted and listed under UNRESOLVED, so the gap stays visible
//!     rather than assumed empty.
//!
//!   • Reachability is over the *static* call graph. A function reachable
//!     from an ISR seed is not necessarily reachable on every dynamic
//!     path; runtime guards (`if (is_vcpu)`, mode checks) are not modelled.
//!     The tool answers "can this ISR reach a wake", not "does it always".
//!
//!   • Each DB carries IR for one arch only. Seeds under the *other*
//!     arch's directory are dropped (`archOf`), so per-DB output is a
//!     per-arch answer; run both DBs to get the union.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const sqlite = @import("sqlite.zig");

// ─── Seed / primitive configuration ───────────────────────────────────
//
// The two places where the analyzer carries kernel-specific knowledge.
// Both are validated against the DB at startup: a name that resolves to
// zero function entities is an `analyzer_error` and exits 2 rather than
// silently shrinking the closure. That is the point — a rename must break
// the tool loudly, not quietly weaken every finding it produces.

const PrimTier = enum {
    /// `tryClaimWake` — the single cmpxchg that transfers ownership of a
    /// waiting EC to the waker. Every genuine wake routes through it (see
    /// the doc comment on `scheduler.markReady`).
    claim,
    /// Run-queue insertion. Strictly broader than `claim`: also covers
    /// re-enqueue of an already-owned EC, which is a run-queue mutation
    /// from interrupt context but not a wake.
    enqueue,

    fn label(self: PrimTier) []const u8 {
        return switch (self) {
            .claim => "claim",
            .enqueue => "enqueue",
        };
    }
};

const PrimSpec = struct { qname: []const u8, tier: PrimTier };

const WAKE_PRIMITIVES = [_]PrimSpec{
    .{ .qname = "sched.execution_context.tryClaimWake", .tier = .claim },
    .{ .qname = "sched.scheduler.enqueue", .tier = .enqueue },
    .{ .qname = "sched.scheduler.enqueueOnCore", .tier = .enqueue },
};

/// Functions whose second argument is an interrupt handler. Seed source
/// S2 — this is how the x86-64 IDT is populated, and the only mechanical
/// link between a vector and its handler (the dispatch itself is an
/// indirect call through `vector_table[]`, which no callgraph resolves).
const VECTOR_REGISTRARS = [_][]const u8{"registerVector"};

/// Acquire methods on `SpinLock` and on `GenLock`/`SlabRef`. `masked` =
/// the variant disables IRQs for the duration of the hold.
///
/// The `lockWithGen*` family is GenLock's verify-and-acquire path and
/// `lockOrderedIrqSave` is SlabRef's; both were absent while GenLock was
/// out of scope. They matter now that `_gen_lock` resolves to a class:
/// omitting the two PLAIN ones (`lockWithGen`, `lockWithGenOrdered`)
/// would let the class's verdict be computed from a strict subset of its
/// acquires and report "IRQ-MASKED at every acquire" for a class that has
/// plain acquires the scan never looked at.
const AcquireMethod = struct { name: []const u8, masked: bool };
const ACQUIRE_METHODS = [_]AcquireMethod{
    .{ .name = "lock", .masked = false },
    .{ .name = "lockOrdered", .masked = false },
    .{ .name = "tryLock", .masked = false },
    .{ .name = "lockIrqSave", .masked = true },
    .{ .name = "lockIrqSaveOrdered", .masked = true },
    // GenLock verify-and-acquire / SlabRef.
    .{ .name = "lockWithGen", .masked = false },
    .{ .name = "lockWithGenOrdered", .masked = false },
    .{ .name = "lockWithGenIrqSave", .masked = true },
    .{ .name = "lockWithGenIrqSaveOrdered", .masked = true },
    .{ .name = "lockOrderedIrqSave", .masked = true },
};

/// Types whose declarations carry a lockdep `.class` label. `GenLock` is
/// the per-object gen+lock word every slab-backed type embeds as
/// `_gen_lock`; it labels its class at RUNTIME from the slab constructor
/// (see `runtimeClassAssignments`), not in the field default.
const LOCK_TYPES = [_][]const u8{ "SpinLock", "GenLock" };

/// The `SpinLock` implementation acquires through `self`, which is not a
/// lock class. Skip the file rather than report bogus UNRESOLVED rows.
const LOCK_IMPL_FILE = "utils/sync/spin_lock.zig";

/// Rule B is a statement about the *kernel's* lock discipline. The
/// indexer's extra source roots pull in userspace and tooling trees that
/// have their own, unrelated `SpinLock` types — `libz/libc/src/heap/`
/// ships a no-op stub whose `lock()` body is empty. Including them would
/// report userspace locks as kernel preemption hazards.
fn inKernelScope(path: []const u8) bool {
    if (mem.startsWith(u8, path, "libz/")) return false;
    if (mem.startsWith(u8, path, "tools/")) return false;
    if (mem.startsWith(u8, path, "tests/")) return false;
    if (mem.startsWith(u8, path, "redteam/")) return false;
    if (mem.startsWith(u8, path, "routerOS/")) return false;
    if (mem.startsWith(u8, path, "hyprvOS/")) return false;
    return true;
}

// ─── Token model ──────────────────────────────────────────────────────

const TokKind = enum {
    identifier,
    period,
    l_paren,
    r_paren,
    l_bracket,
    r_bracket,
    l_brace,
    r_brace,
    equal,
    colon,
    semicolon,
    comma,
    ampersand,
    asterisk,
    pipe,
    keyword_const,
    keyword_for,
    string_literal,
    other,

    fn parse(s: []const u8) TokKind {
        const table = [_]struct { []const u8, TokKind }{
            .{ "identifier", .identifier },
            .{ "period", .period },
            .{ "l_paren", .l_paren },
            .{ "r_paren", .r_paren },
            .{ "l_bracket", .l_bracket },
            .{ "r_bracket", .r_bracket },
            .{ "l_brace", .l_brace },
            .{ "r_brace", .r_brace },
            .{ "equal", .equal },
            .{ "colon", .colon },
            .{ "semicolon", .semicolon },
            .{ "comma", .comma },
            .{ "ampersand", .ampersand },
            .{ "asterisk", .asterisk },
            .{ "pipe", .pipe },
            .{ "keyword_const", .keyword_const },
            .{ "keyword_for", .keyword_for },
            .{ "string_literal", .string_literal },
        };
        for (table) |t| if (mem.eql(u8, s, t[0])) return t[1];
        return .other;
    }
};

const Tok = struct {
    kind: TokKind,
    byte_start: u32,
    /// Only populated for `identifier` and `string_literal`; "" otherwise.
    text: []const u8,
};

// ─── Entity / graph model ─────────────────────────────────────────────

const Ent = struct {
    id: i64,
    is_fn: bool,
    qname: []const u8,
    short: []const u8,
    file_id: i64,
    byte_start: u32,
    byte_end: u32,
    line: u32,
};

const EdgeProv = enum {
    ir,
    syn_call,
    syn_ref,

    fn label(self: EdgeProv) []const u8 {
        return switch (self) {
            .ir => "ir",
            .syn_call => "syn-call",
            .syn_ref => "syn-ref",
        };
    }
};

const Edge = struct {
    from: u32,
    to: u32,
    line: u32,
    prov: EdgeProv,
};

const FileRow = struct { id: i64, path: []const u8 };
const FnRange = struct { byte_start: u32, byte_end: u32, ent: u32 };

// ─── Lock model (Rule B) ──────────────────────────────────────────────

const LockDecl = struct {
    decl_name: []const u8,
    /// The `.class = "…"` label. Literals joined by `++` are rendered with
    /// `…` between them (e.g. `SecureSlab(…).lock`).
    class: []const u8,
    file_id: i64,
    line: u32,
};

/// One lockdep class — the kernel's `.class` string — and every
/// declaration that carries it.
const ClassGroup = struct {
    class: []const u8,
    decls: []u32,
};

const AcquireSite = struct {
    /// Index into `Ctx.classes`, NOT into `Ctx.locks`: identity is the
    /// declared lockdep class, not the declaration site.
    class_idx: u32,
    file_id: i64,
    line: u32,
    method: []const u8,
    masked: bool,
    host: ?u32,
    receiver: []const u8,
};

const UnresolvedAcq = struct {
    file_id: i64,
    line: u32,
    receiver: []const u8,
    method: []const u8,
};

// ─── Analysis context ─────────────────────────────────────────────────

const Ctx = struct {
    a: Allocator,
    db: *sqlite.Db,
    db_path: []const u8,
    arch: []const u8,

    files: []FileRow,
    file_by_id: std.AutoHashMap(i64, u32),
    /// Per-file sorted `byte_start` of each 1-indexed line.
    line_starts: [][]u32,

    ents: []Ent,
    idx_by_id: std.AutoHashMap(i64, u32),
    by_short: std.StringHashMap(std.ArrayListUnmanaged(u32)),

    toks: [][]Tok,
    fn_ranges: [][]FnRange,
    /// Per-file `const NAME = a.b.c;` import aliases, used to expand a
    /// chain head before qualified-name matching.
    file_aliases: []std.StringHashMap([][]const u8),

    edges: []Edge,
    out_adj: [][]u32,
    in_adj: [][]u32,

    locks: []LockDecl,
    /// Lock classes, keyed on the kernel's declared `.class` string.
    classes: []ClassGroup,
    /// `locks[i]` belongs to `classes[class_of_decl[i]]`.
    class_of_decl: []u32,
    acquires: []AcquireSite,
    unresolved: []UnresolvedAcq,

    fn path(self: *const Ctx, file_id: i64) []const u8 {
        const i = self.file_by_id.get(file_id) orelse return "<unknown>";
        return self.files[i].path;
    }

    /// Display path — the DB stores kernel files without the `kernel/`
    /// prefix; report lines should be copy-pasteable from the repo root.
    fn dpath(self: *const Ctx, file_id: i64) []const u8 {
        const p = self.path(file_id);
        const already = mem.startsWith(u8, p, "bootloader/") or
            mem.startsWith(u8, p, "kernel/") or mem.startsWith(u8, p, "tools/") or
            mem.startsWith(u8, p, "tests/") or mem.startsWith(u8, p, "libz/") or
            mem.startsWith(u8, p, "redteam/");
        if (already) return p;
        return std.fmt.allocPrint(self.a, "kernel/{s}", .{p}) catch p;
    }

    fn isArchFile(self: *const Ctx, file_id: i64) bool {
        return mem.startsWith(u8, self.path(file_id), "arch/");
    }

    /// `x86_64` / `aarch64` / null for arch-neutral files.
    fn archOf(self: *const Ctx, file_id: i64) ?[]const u8 {
        const p = self.path(file_id);
        if (mem.startsWith(u8, p, "arch/x64/")) return "x86_64";
        if (mem.startsWith(u8, p, "arch/aarch64/")) return "aarch64";
        return null;
    }

    fn lineForByte(self: *const Ctx, file_id: i64, byte: u32) u32 {
        const fi = self.file_by_id.get(file_id) orelse return 0;
        const starts = self.line_starts[fi];
        if (starts.len == 0) return 0;
        var lo: usize = 0;
        var hi: usize = starts.len; // find last index with starts[i] <= byte
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (starts[mid] <= byte) lo = mid + 1 else hi = mid;
        }
        return if (lo == 0) 1 else @intCast(lo);
    }

    fn dloc(self: *const Ctx, file_id: i64, line: u32) []const u8 {
        return std.fmt.allocPrint(self.a, "{s}:{d}", .{ self.dpath(file_id), line }) catch "?";
    }

    fn entLoc(self: *const Ctx, ent: u32) []const u8 {
        return self.dloc(self.ents[ent].file_id, self.ents[ent].line);
    }
};

// ─── DB loading ───────────────────────────────────────────────────────

fn loadMeta(a: Allocator, db: *sqlite.Db, key: []const u8) ![]const u8 {
    var stmt = try db.prepare("SELECT value FROM meta WHERE key = ?", a);
    defer stmt.finalize();
    try stmt.bindText(1, key);
    if (try stmt.step()) {
        if (stmt.columnText(0)) |v| return try a.dupe(u8, v);
    }
    return "unknown";
}

fn loadFiles(a: Allocator, db: *sqlite.Db) ![]FileRow {
    var stmt = try db.prepare("SELECT id, path FROM file ORDER BY id", a);
    defer stmt.finalize();
    var out: ArrayList(FileRow) = .{};
    while (try stmt.step()) {
        try out.append(a, .{
            .id = stmt.columnInt(0),
            .path = try a.dupe(u8, stmt.columnText(1) orelse ""),
        });
    }
    return out.toOwnedSlice(a);
}

fn loadLineIndex(ctx: *Ctx) !void {
    const a = ctx.a;
    var lists = try a.alloc(ArrayList(u32), ctx.files.len);
    for (lists) |*l| l.* = .{};
    var stmt = try ctx.db.prepare(
        "SELECT file_id, byte_start FROM file_line_index ORDER BY file_id, line",
        a,
    );
    defer stmt.finalize();
    while (try stmt.step()) {
        const fi = ctx.file_by_id.get(stmt.columnInt(0)) orelse continue;
        try lists[fi].append(a, @intCast(stmt.columnInt(1)));
    }
    ctx.line_starts = try a.alloc([]u32, ctx.files.len);
    for (lists, 0..) |*l, i| ctx.line_starts[i] = try l.toOwnedSlice(a);
}

fn loadEntities(a: Allocator, db: *sqlite.Db) ![]Ent {
    var stmt = try db.prepare(
        \\SELECT id, kind, qualified_name, def_file_id, def_byte_start, def_byte_end, def_line
        \\FROM entity ORDER BY id
    , a);
    defer stmt.finalize();
    var out: ArrayList(Ent) = .{};
    while (try stmt.step()) {
        const kind = stmt.columnText(1) orelse "";
        const qn = try a.dupe(u8, stmt.columnText(2) orelse "");
        const dot = mem.lastIndexOfScalar(u8, qn, '.');
        try out.append(a, .{
            .id = stmt.columnInt(0),
            .is_fn = mem.eql(u8, kind, "fn"),
            .qname = qn,
            .short = if (dot) |d| qn[d + 1 ..] else qn,
            .file_id = stmt.columnInt(3),
            .byte_start = @intCast(stmt.columnInt(4)),
            .byte_end = @intCast(stmt.columnInt(5)),
            .line = @intCast(stmt.columnInt(6)),
        });
    }
    return out.toOwnedSlice(a);
}

fn loadTokens(ctx: *Ctx) !void {
    const a = ctx.a;
    var lists = try a.alloc(ArrayList(Tok), ctx.files.len);
    for (lists) |*l| l.* = .{};
    var stmt = try ctx.db.prepare(
        "SELECT file_id, kind, byte_start, text FROM token ORDER BY file_id, idx",
        a,
    );
    defer stmt.finalize();
    while (try stmt.step()) {
        const fi = ctx.file_by_id.get(stmt.columnInt(0)) orelse continue;
        const kind = TokKind.parse(stmt.columnText(1) orelse "");
        const text: []const u8 = switch (kind) {
            .identifier, .string_literal => try a.dupe(u8, stmt.columnText(3) orelse ""),
            else => "",
        };
        try lists[fi].append(a, .{
            .kind = kind,
            .byte_start = @intCast(stmt.columnInt(2)),
            .text = text,
        });
    }
    ctx.toks = try a.alloc([]Tok, ctx.files.len);
    for (lists, 0..) |*l, i| ctx.toks[i] = try l.toOwnedSlice(a);
}

fn lessFnRange(_: void, x: FnRange, y: FnRange) bool {
    if (x.byte_start != y.byte_start) return x.byte_start < y.byte_start;
    return x.byte_end > y.byte_end;
}

fn buildFnRanges(ctx: *Ctx) !void {
    const a = ctx.a;
    var lists = try a.alloc(ArrayList(FnRange), ctx.files.len);
    for (lists) |*l| l.* = .{};
    for (ctx.ents, 0..) |e, i| {
        if (!e.is_fn) continue;
        const fi = ctx.file_by_id.get(e.file_id) orelse continue;
        try lists[fi].append(a, .{ .byte_start = e.byte_start, .byte_end = e.byte_end, .ent = @intCast(i) });
    }
    ctx.fn_ranges = try a.alloc([]FnRange, ctx.files.len);
    for (lists, 0..) |*l, i| {
        const s = try l.toOwnedSlice(a);
        std.mem.sort(FnRange, s, {}, lessFnRange);
        ctx.fn_ranges[i] = s;
    }
}

/// Collect `const NAME = a.b.c;` chains per file.
///
/// Stygia style binds every cross-module reference to a file-local alias
/// (`const paging_mod = stygia.arch.x64.paging;`), so without expansion a
/// call written `paging_mod.tlbShootdownHandler` matches no qualified name
/// and the edge — or, as happened here, the IDT seed — is simply lost.
fn buildFileAliases(ctx: *Ctx) !void {
    const a = ctx.a;
    ctx.file_aliases = try a.alloc(std.StringHashMap([][]const u8), ctx.files.len);
    for (ctx.files, 0..) |_, fi| {
        var m = std.StringHashMap([][]const u8).init(a);
        const toks = ctx.toks[fi];
        var i: usize = 0;
        while (i + 4 < toks.len) : (i += 1) {
            if (toks[i].kind != .keyword_const) continue;
            if (toks[i + 1].kind != .identifier or toks[i + 2].kind != .equal) continue;
            if (toks[i + 3].kind != .identifier) continue;
            const ch = try readChain(a, toks, i + 3);
            // Only a bare `const NAME = chain;` counts. A call, an index, a
            // type ascription — anything else and the alias is not a pure
            // namespace rename, so expanding through it would be a guess.
            if (ch.next >= toks.len or toks[ch.next].kind != .semicolon) continue;
            if (ch.segs.len < 2) continue;
            try m.put(toks[i + 1].text, ch.segs);
        }
        ctx.file_aliases[fi] = m;
    }
}

/// Innermost function whose byte range contains `byte`.
fn enclosingFn(ctx: *const Ctx, file_i: u32, byte: u32) ?u32 {
    const ranges = ctx.fn_ranges[file_i];
    var best: ?FnRange = null;
    for (ranges) |r| {
        if (r.byte_start > byte) break;
        if (byte < r.byte_end) {
            if (best == null or r.byte_start >= best.?.byte_start) best = r;
        }
    }
    return if (best) |b| b.ent else null;
}

// ─── Call graph construction ──────────────────────────────────────────

fn loadIrEdges(ctx: *Ctx, out: *ArrayList(Edge), seen: *std.AutoHashMap(u64, void)) !void {
    var stmt = try ctx.db.prepare(
        \\SELECT caller_entity_id, callee_entity_id, site_line
        \\FROM ir_call
        \\WHERE callee_entity_id IS NOT NULL
        \\  AND call_kind IN ('direct','dispatch_x64','dispatch_aarch64')
    , ctx.a);
    defer stmt.finalize();
    while (try stmt.step()) {
        const from = ctx.idx_by_id.get(stmt.columnInt(0)) orelse continue;
        const to = ctx.idx_by_id.get(stmt.columnInt(1)) orelse continue;
        const key = (@as(u64, from) << 32) | @as(u64, to);
        if (seen.contains(key)) continue;
        try seen.put(key, {});
        try out.append(ctx.a, .{
            .from = from,
            .to = to,
            .line = @intCast(stmt.columnInt(2)),
            .prov = .ir,
        });
    }
}

/// Resolve an identifier chain to a unique function entity.
///
/// Resolution order, most specific first:
///   1. the whole chain is a qualified-name suffix, uniquely;
///   2. …the same, restricted to functions defined in `pref_file`;
///   3. the terminal segment alone, restricted to `pref_file`, uniquely;
///   4. the terminal segment alone, globally unique.
///
/// Step 2/3 are what make `registerVector(PMI_VECTOR, pmiHandler, …)`
/// resolve: there are three `pmiHandler`s in the tree (intel, amd,
/// aarch64) and only file scope tells them apart.
///
/// Ambiguity that survives all four steps resolves to "no edge": a guess
/// would produce phantom wake paths, which is worse than a missing one we
/// can name.
fn resolveFn(ctx: *const Ctx, segs_in: []const []const u8, pref_file: ?i64) ?u32 {
    if (segs_in.len == 0) return null;
    const cands = ctx.by_short.get(segs_in[segs_in.len - 1]) orelse return null;
    if (cands.items.len == 0) return null;

    // Expand a file-local import alias on the chain head, then drop a
    // leading `stygia` (the root module is not part of any qualified name
    // in the entity table).
    var segs = segs_in;
    if (segs.len > 1 and pref_file != null) {
        if (ctx.file_by_id.get(pref_file.?)) |fi| {
            if (ctx.file_aliases[fi].get(segs[0])) |exp| {
                var joined: ArrayList([]const u8) = .{};
                joined.appendSlice(ctx.a, exp) catch return null;
                joined.appendSlice(ctx.a, segs[1..]) catch return null;
                segs = joined.items;
            }
        }
    }
    if (segs.len > 1 and mem.eql(u8, segs[0], "stygia")) segs = segs[1..];

    var buf: ArrayList(u8) = .{};
    for (segs, 0..) |s, i| {
        if (i != 0) buf.append(ctx.a, '.') catch return null;
        buf.appendSlice(ctx.a, s) catch return null;
    }
    const chain = buf.items;

    // Full qualified-name equality outranks a dot-aligned suffix match.
    //
    // The DB indexes `tools/`, which holds this analyzer's own fixtures and
    // the indexer's, so a kernel name can be shadowed by a fixture copy
    // whose qualified name merely ENDS with it — e.g.
    // `tools.indexer.tests.fixtures.03_….kernel.arch.x64.paging
    //  .tlbShootdownHandler` vs the real `arch.x64.paging
    //  .tlbShootdownHandler`. Counting both as "exact" made the IDT
    // registration for the W9 TLB-shootdown IPI ambiguous, so it resolved
    // to nothing and never became a Rule A/B seed. Mirrors the identical
    // fix in tools/indexer/src/entry_pass.zig. See bd stygia-ywh.
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
        const e = ctx.ents[ci];
        const is_local = pref_file != null and e.file_id == pref_file.?;
        if (is_local) {
            local = ci;
            local_n += 1;
        }
        const qn = e.qname;
        if (mem.eql(u8, qn, chain)) {
            full = ci;
            full_n += 1;
            if (is_local) {
                full_local = ci;
                full_local_n += 1;
            }
        }
        if (mem.eql(u8, qn, chain) or
            (qn.len > chain.len and mem.endsWith(u8, qn, chain) and qn[qn.len - chain.len - 1] == '.'))
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

    // Terminal-only fallback is restricted to *single-segment* chains.
    //
    // A dotted chain names its callee: `state.run_queue.enqueue(cur)` is
    // `priority_queue.enqueue`, and if no qualified name ends in
    // `state.run_queue.enqueue` the honest answer is "unknown", not "the
    // `enqueue` that happens to live in this file". Without this guard the
    // same-file tiebreak resolved that call to `sched.scheduler.enqueue`
    // and invented a run-queue-insertion claim site inside `yieldTo`.
    //
    // Single-segment chains are the opposite case: `pmiHandler` passed to
    // `registerVector` has no qualifier to match against, and file scope is
    // exactly how Zig resolves it.
    // `self.method()` inside a generic container is the other legitimate
    // case: the receiver is a value, not a namespace, and the method is
    // defined in the same file. Same-file uniqueness is then the right
    // answer, and it is what keeps `SecureSlab`'s internal
    // `self.destroyLocked(…)` chain connected.
    if (segs.len == 1 or (segs.len == 2 and mem.eql(u8, segs[0], "self"))) {
        if (local_n == 1) return local;
        if (cands.items.len == 1) return cands.items[0];
    }
    return null;
}

const Chain = struct { segs: [][]const u8, next: usize };

fn readChain(a: Allocator, toks: []const Tok, i: usize) !Chain {
    var segs: ArrayList([]const u8) = .{};
    try segs.append(a, toks[i].text);
    var j = i + 1;
    while (j + 1 < toks.len and toks[j].kind == .period and toks[j + 1].kind == .identifier) {
        try segs.append(a, toks[j + 1].text);
        j += 2;
    }
    return .{ .segs = try segs.toOwnedSlice(a), .next = j };
}

/// See the module doc comment: overlays token-derived edges so calls
/// through monomorphized generics and address-taken callbacks are not
/// silently absent from the graph.
fn addSyntacticEdges(ctx: *Ctx, out: *ArrayList(Edge), seen: *std.AutoHashMap(u64, void)) !void {
    const a = ctx.a;
    for (ctx.files, 0..) |f, fi| {
        const toks = ctx.toks[fi];
        if (toks.len == 0 or ctx.fn_ranges[fi].len == 0) continue;
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].kind != .identifier) continue;
            if (i > 0 and toks[i - 1].kind == .period) continue; // interior segment
            const ch = try readChain(a, toks, i);
            i = ch.next - 1;
            const host = enclosingFn(ctx, @intCast(fi), toks[ch.next - ch.segs.len].byte_start) orelse continue;
            const tgt = resolveFn(ctx, ch.segs, f.id) orelse continue;
            if (tgt == host) continue;
            const key = (@as(u64, host) << 32) | @as(u64, tgt);
            if (seen.contains(key)) continue;
            try seen.put(key, {});
            const is_call = ch.next < toks.len and toks[ch.next].kind == .l_paren;
            try out.append(a, .{
                .from = host,
                .to = tgt,
                .line = ctx.lineForByte(f.id, toks[ch.next - ch.segs.len].byte_start),
                .prov = if (is_call) .syn_call else .syn_ref,
            });
        }
    }
}

fn buildAdjacency(ctx: *Ctx) !void {
    const a = ctx.a;
    var outs = try a.alloc(ArrayList(u32), ctx.ents.len);
    var ins = try a.alloc(ArrayList(u32), ctx.ents.len);
    for (outs) |*l| l.* = .{};
    for (ins) |*l| l.* = .{};
    for (ctx.edges) |e| {
        try outs[e.from].append(a, e.to);
        try ins[e.to].append(a, e.from);
    }
    ctx.out_adj = try a.alloc([]u32, ctx.ents.len);
    ctx.in_adj = try a.alloc([]u32, ctx.ents.len);
    for (outs, 0..) |*l, i| ctx.out_adj[i] = try l.toOwnedSlice(a);
    for (ins, 0..) |*l, i| ctx.in_adj[i] = try l.toOwnedSlice(a);
}

fn reach(a: Allocator, adj: [][]u32, seeds: []const u32, n: usize) ![]bool {
    const seen = try a.alloc(bool, n);
    @memset(seen, false);
    var stack: ArrayList(u32) = .{};
    for (seeds) |s| {
        if (!seen[s]) {
            seen[s] = true;
            try stack.append(a, s);
        }
    }
    while (stack.pop()) |x| {
        for (adj[x]) |y| {
            if (!seen[y]) {
                seen[y] = true;
                try stack.append(a, y);
            }
        }
    }
    return seen;
}

/// Shortest path from any seed to `target`, as entity indices.
fn witnessPath(ctx: *Ctx, seeds: []const u32, target: u32) !?[]u32 {
    const a = ctx.a;
    const prev = try a.alloc(i64, ctx.ents.len);
    @memset(prev, -2); // -2 unvisited, -1 seed
    var q: ArrayList(u32) = .{};
    for (seeds) |s| {
        if (prev[s] == -2) {
            prev[s] = -1;
            try q.append(a, s);
        }
    }
    var head: usize = 0;
    while (head < q.items.len) : (head += 1) {
        const x = q.items[head];
        if (x == target) break;
        for (ctx.out_adj[x]) |y| {
            if (prev[y] == -2) {
                prev[y] = @intCast(x);
                try q.append(a, y);
            }
        }
    }
    if (prev[target] == -2) return null;
    var rev: ArrayList(u32) = .{};
    var cur: i64 = @intCast(target);
    while (cur >= 0) {
        try rev.append(a, @intCast(cur));
        cur = prev[@intCast(cur)];
    }
    const out = try a.alloc(u32, rev.items.len);
    for (rev.items, 0..) |v, i| out[out.len - 1 - i] = v;
    return out;
}

// ─── Rule A: interrupt-entry seed discovery ───────────────────────────

const SeedSource = enum {
    /// `entry_point` rows the indexer curates by name.
    db_entry_point,
    /// 2nd argument to a `registerVector(…)` call — the x86-64 IDT.
    vector_table,
    /// `&handler` bound as an inline-asm operand inside a `callconv(.naked)`
    /// function — the aarch64 exception vector table.
    naked_asm_operand,

    fn label(self: SeedSource) []const u8 {
        return switch (self) {
            .db_entry_point => "entry_point",
            .vector_table => "vector_table",
            .naked_asm_operand => "naked_asm",
        };
    }
};

/// Asynchronous (device / IPI / timer) vs synchronous (fault / trap).
///
/// The kernel itself draws exactly this line — `dispatchInterrupt` only
/// calls `sync_debug.enterIrqContext()` for `.external` vectors, because a
/// synchronous exception "executes on top of whatever IRQ-mode discipline
/// the interrupted code already chose". The distinction matters for the
/// report: on aarch64 the SVC syscall arrives through `handleSyncLowerEl`,
/// so a closure that does not separate the two hands you the entire
/// syscall surface as an "interrupt-context wake source".
const EntryKind = enum {
    async_irq,
    sync_exception,

    fn label(self: EntryKind) []const u8 {
        return switch (self) {
            .async_irq => "async",
            .sync_exception => "sync",
        };
    }
};

const Seed = struct { ent: u32, src: SeedSource, kind: EntryKind, note: []const u8 };

fn collectIrqSeeds(ctx: *Ctx) ![]Seed {
    const a = ctx.a;
    var seen = std.AutoHashMap(u32, void).init(a);
    var out: ArrayList(Seed) = .{};

    // S1 — the DB's curated entry points.
    {
        var stmt = try ctx.db.prepare(
            \\SELECT entity_id, label, kind FROM entry_point
            \\WHERE kind IN ('exception','irq','trap','ipi','timer')
        , a);
        defer stmt.finalize();
        while (try stmt.step()) {
            const ei = ctx.idx_by_id.get(stmt.columnInt(0)) orelse continue;
            if (seen.contains(ei)) continue;
            try seen.put(ei, {});
            const ep_kind = stmt.columnText(2) orelse "";
            const async_by_kind = mem.eql(u8, ep_kind, "irq") or
                mem.eql(u8, ep_kind, "ipi") or mem.eql(u8, ep_kind, "timer");
            try out.append(a, .{
                .ent = ei,
                .src = .db_entry_point,
                .kind = if (async_by_kind or nameLooksAsync(ctx.ents[ei].qname))
                    .async_irq
                else
                    .sync_exception,
                .note = try a.dupe(u8, stmt.columnText(1) orelse ""),
            });
        }
    }

    // S2 / S3 — token-derived.
    //
    // Scope-filtered exactly like Rule B's lock discovery, and for the same
    // reason. The indexer's extra source roots pull in `tools/`, which
    // contains THIS analyzer's fixture kernels — every one of which calls
    // `registerVector(…)` because that is how a fixture declares an ISR.
    // Unfiltered, a real-tree run took 48 of its 70 "interrupt entry
    // points" from tools/check_ec_closure/tests/fixtures/*, inflating the
    // entry count, the closure, and the wake-source table with functions
    // that are not in the kernel at all. The fixture harness itself is
    // unaffected: it writes each fixture to `kernel/arch/x64/irq.zig` in a
    // temp tree, so fixture DB paths are `arch/x64/…` and stay in scope.
    for (ctx.files, 0..) |f, fi| {
        if (!inKernelScope(f.path)) continue;
        const toks = ctx.toks[fi];
        if (toks.len == 0) continue;
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].kind != .identifier) continue;

            // S2: `<chain>.registerVector( vec , HANDLER , kind )`
            var is_registrar = false;
            for (VECTOR_REGISTRARS) |r| {
                if (mem.eql(u8, toks[i].text, r)) is_registrar = true;
            }
            if (is_registrar and i + 1 < toks.len and toks[i + 1].kind == .l_paren) {
                if (try nthCallArgChain(ctx, toks, i + 1, 1)) |segs| {
                    if (resolveFn(ctx, segs, f.id)) |ei| {
                        if (!seen.contains(ei)) {
                            try seen.put(ei, {});
                            // 3rd argument is the `VectorKind` enum literal:
                            // `.external` (async device/IPI/timer) or
                            // `.exception` (synchronous fault).
                            const vk = enumLiteralArg(toks, i + 1, 2);
                            const is_async = if (vk) |v| mem.eql(u8, v, "external") else nameLooksAsync(ctx.ents[ei].qname);
                            try out.append(a, .{
                                .ent = ei,
                                .src = .vector_table,
                                .kind = if (is_async) .async_irq else .sync_exception,
                                .note = ctx.dloc(f.id, ctx.lineForByte(f.id, toks[i].byte_start)),
                            });
                        }
                    }
                }
            }

            // S3: `&handler` inside a `callconv(.naked)` function.
            if (i > 0 and toks[i - 1].kind == .ampersand) {
                const host = enclosingFn(ctx, @intCast(fi), toks[i].byte_start);
                if (host != null and isNakedFn(ctx, host.?)) {
                    const ch = try readChain(a, toks, i);
                    if (resolveFn(ctx, ch.segs, f.id)) |ei| {
                        if (!seen.contains(ei)) {
                            try seen.put(ei, {});
                            try out.append(a, .{
                                .ent = ei,
                                .src = .naked_asm_operand,
                                .kind = if (nameLooksAsync(ctx.ents[ei].qname)) .async_irq else .sync_exception,
                                .note = try std.fmt.allocPrint(a, "{s} in {s}", .{
                                    ctx.dloc(f.id, ctx.lineForByte(f.id, toks[i].byte_start)),
                                    ctx.ents[host.?].qname,
                                }),
                            });
                        }
                    }
                }
            }
        }
    }
    return out.toOwnedSlice(a);
}

/// Fallback async classification when no `VectorKind` / `entry_point.kind`
/// is available — the aarch64 vector-table operands are distinguished only
/// by handler name (`handleIrqCurrentEl` vs `handleSyncCurrentEl`).
///
/// Matched against the *short* name only. Matching the whole qualified name
/// meant every handler defined in a module whose path contains `irq` —
/// i.e. all of `kernel/arch/x64/irq.zig` — was forced async regardless of
/// the `VectorKind` it was registered with. That was invisible while the
/// indexer's `entry_point` table omitted those handlers (they arrived
/// through the `vector_table` source, which reads the literal
/// `.exception` / `.external` and never consults the name); once the
/// indexer learned to discover them, the `entry_point` source won the
/// dedup and the fallback started firing on `.exception` handlers.
fn nameLooksAsync(qname: []const u8) bool {
    const short = if (mem.lastIndexOfScalar(u8, qname, '.')) |p| qname[p + 1 ..] else qname;
    return mem.indexOf(u8, short, "Irq") != null or
        mem.indexOf(u8, short, "irq") != null or
        mem.indexOf(u8, short, "Timer") != null;
}

/// Text of an enum-literal argument (`.external` → "external"). Null when
/// the argument at `n` is not a bare `.identifier`.
fn enumLiteralArg(toks: []const Tok, lparen_i: usize, n: usize) ?[]const u8 {
    var depth: i32 = 0;
    var arg: usize = 0;
    var start: usize = lparen_i + 1;
    var i = lparen_i;
    while (i < toks.len) : (i += 1) {
        const close = switch (toks[i].kind) {
            .l_paren, .l_bracket, .l_brace => blk: {
                depth += 1;
                break :blk false;
            },
            .r_paren, .r_bracket, .r_brace => blk: {
                depth -= 1;
                break :blk depth == 0;
            },
            .comma => depth == 1,
            else => false,
        };
        if (!close) continue;
        if (arg == n) {
            if (start + 1 < i and toks[start].kind == .period and toks[start + 1].kind == .identifier) {
                return toks[start + 1].text;
            }
            return null;
        }
        if (toks[i].kind == .comma) {
            arg += 1;
            start = i + 1;
        } else return null;
    }
    return null;
}

/// True when the function signature carries `callconv(.naked)`.
fn isNakedFn(ctx: *const Ctx, ent: u32) bool {
    const e = ctx.ents[ent];
    const fi = ctx.file_by_id.get(e.file_id) orelse return false;
    const toks = ctx.toks[fi];
    for (toks) |t| {
        if (t.byte_start < e.byte_start) continue;
        if (t.byte_start >= e.byte_end) return false;
        if (t.kind == .identifier and mem.eql(u8, t.text, "naked")) return true;
        if (t.kind == .l_brace) return false; // past the signature
    }
    return false;
}

/// Chain of the `n`-th (0-based) argument of the call whose `l_paren` sits
/// at `lparen_i`. Null when that argument isn't a bare identifier chain.
fn nthCallArgChain(ctx: *Ctx, toks: []const Tok, lparen_i: usize, n: usize) !?[][]const u8 {
    var depth: i32 = 0;
    var arg: usize = 0;
    var arg_start: usize = lparen_i + 1;
    var i = lparen_i;
    while (i < toks.len) : (i += 1) {
        switch (toks[i].kind) {
            .l_paren, .l_bracket, .l_brace => depth += 1,
            .r_paren, .r_bracket, .r_brace => {
                depth -= 1;
                if (depth == 0) {
                    if (arg == n) return try argChain(ctx, toks, arg_start, i);
                    return null;
                }
            },
            .comma => {
                if (depth == 1) {
                    if (arg == n) return try argChain(ctx, toks, arg_start, i);
                    arg += 1;
                    arg_start = i + 1;
                }
            },
            else => {},
        }
    }
    return null;
}

fn argChain(ctx: *Ctx, toks: []const Tok, from: usize, to: usize) !?[][]const u8 {
    var i = from;
    while (i < to and toks[i].kind == .ampersand) i += 1;
    if (i >= to or toks[i].kind != .identifier) return null;
    const ch = try readChain(ctx.a, toks, i);
    if (ch.next != to) return null; // argument is an expression, not a bare chain
    return ch.segs;
}

// ─── Rule B: lock-class discovery ─────────────────────────────────────

/// Lockdep classes assigned at RUNTIME rather than in a field default:
/// `<chain>.class = "lit"[ ++ … ];`. Keyed by the last field name of the
/// assigned chain.
///
/// This exists for one construct, but it is the construct that covers most
/// of the kernel's locks. A slab-backed type embeds `_gen_lock: GenLock =
/// .{}` with no class, and `SecureSlab(T).publish` labels the slot as it
/// hands it out:
///
///     slot_ptr._gen_lock.class = "SecureSlab(" ++ @typeName(T) ++ ")._gen_lock";
///
/// Every `_gen_lock` field in the tree therefore belongs to that class
/// family, which is what lets an acquire written `cd._gen_lock…` in
/// syscall/ resolve against a decl in caps/ — see `resolveLockClass`.
///
/// `++`-joined literals are rendered with `…` for the non-literal parts,
/// the same convention `collectLockDecls` uses for `SecureSlab(" ++
/// @typeName(T) ++ ").lock`. That collapses every instantiation of a
/// generic into one class. It is an OVER-approximation — distinct `T`s get
/// distinct strings at runtime — and so costs false positives, not false
/// negatives, which is the correct bias here.
///
/// Assignments whose right-hand side is not a string literal (e.g.
/// `e.class = class;` in utils/sync/debug_core.zig, which is plumbing that
/// copies a class rather than declaring one) yield no literal and are
/// skipped.
fn runtimeClassAssignments(ctx: *Ctx) !std.StringHashMap([]const u8) {
    const a = ctx.a;
    var m = std.StringHashMap([]const u8).init(a);
    for (ctx.files, 0..) |f, fi| {
        if (!inKernelScope(f.path)) continue;
        const toks = ctx.toks[fi];
        var i: usize = 0;
        while (i + 2 < toks.len) : (i += 1) {
            // `… . class = <string literal chain> ;`
            if (toks[i].kind != .identifier or !mem.eql(u8, toks[i].text, "class")) continue;
            if (i == 0 or toks[i - 1].kind != .period) continue;
            if (toks[i + 1].kind != .equal) continue;
            // Field the class is being attached to: the chain segment
            // immediately before `.class`.
            if (i < 2 or toks[i - 2].kind != .identifier) continue;
            const field = toks[i - 2].text;

            var buf: ArrayList(u8) = .{};
            var first = true;
            var k = i + 2;
            while (k < toks.len and toks[k].kind != .semicolon and
                toks[k].kind != .comma and toks[k].kind != .r_brace) : (k += 1)
            {
                if (toks[k].kind != .string_literal) continue;
                if (!first) try buf.appendSlice(a, "\u{2026}");
                try buf.appendSlice(a, stripQuotes(toks[k].text));
                first = false;
            }
            if (buf.items.len == 0) continue;
            // First assignment wins; a second one for the same field name
            // would be a genuine ambiguity we do not try to resolve.
            if (m.contains(field)) continue;
            try m.put(field, buf.items);
        }
    }
    return m;
}

fn collectLockDecls(ctx: *Ctx) ![]LockDecl {
    const a = ctx.a;
    var out: ArrayList(LockDecl) = .{};
    var seen = std.StringHashMap(void).init(a);
    var rt_classes = try runtimeClassAssignments(ctx);
    defer rt_classes.deinit();

    for (ctx.files, 0..) |f, fi| {
        if (!inKernelScope(f.path)) continue;
        const toks = ctx.toks[fi];
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].kind != .identifier) continue;
            var is_lock_type = false;
            for (LOCK_TYPES) |lt| {
                if (mem.eql(u8, toks[i].text, lt)) is_lock_type = true;
            }
            if (!is_lock_type) continue;

            // Backward: find the declared name. Two accepted shapes:
            //     NAME : [ …len… ] [chain.] SpinLock …
            //     NAME =           [chain.] SpinLock { … }
            var p: isize = @as(isize, @intCast(i)) - 1;
            while (p >= 1 and toks[@intCast(p)].kind == .period and
                toks[@intCast(p - 1)].kind == .identifier) : (p -= 2)
            {}
            if (p >= 0 and toks[@intCast(p)].kind == .r_bracket) {
                var d: i32 = 0;
                while (p >= 0) : (p -= 1) {
                    if (toks[@intCast(p)].kind == .r_bracket) d += 1;
                    if (toks[@intCast(p)].kind == .l_bracket) {
                        d -= 1;
                        if (d == 0) {
                            p -= 1;
                            break;
                        }
                    }
                }
            }
            if (p < 1) continue;
            const anchor = toks[@intCast(p)].kind;
            if (anchor != .colon and anchor != .equal) continue;
            const nametok = toks[@intCast(p - 1)];
            if (nametok.kind != .identifier) continue;
            // `= [_]SpinLock{…}` re-mentions the type; the real decl was
            // already picked up from the type-annotation occurrence.
            if (mem.eql(u8, nametok.text, "SpinLock")) continue;

            // Forward: collect `.class = "…"` up to the decl terminator.
            var class_buf: ArrayList(u8) = .{};
            var depth: i32 = 0;
            var j = i + 1;
            while (j < toks.len) : (j += 1) {
                switch (toks[j].kind) {
                    .l_paren, .l_bracket, .l_brace => depth += 1,
                    .r_paren, .r_bracket, .r_brace => depth -= 1,
                    .semicolon => if (depth <= 0) break,
                    .comma => if (depth <= 0) break,
                    .identifier => {
                        if (mem.eql(u8, toks[j].text, "class") and
                            j > 0 and toks[j - 1].kind == .period and
                            j + 2 < toks.len and toks[j + 1].kind == .equal)
                        {
                            var k = j + 2;
                            var first = true;
                            while (k < toks.len and toks[k].kind != .comma and
                                toks[k].kind != .semicolon and toks[k].kind != .r_brace) : (k += 1)
                            {
                                if (toks[k].kind == .string_literal) {
                                    if (!first) try class_buf.appendSlice(a, "\u{2026}");
                                    try class_buf.appendSlice(a, stripQuotes(toks[k].text));
                                    first = false;
                                }
                            }
                        }
                    },
                    else => {},
                }
            }

            // A declaration with no inline `.class` may still have a class:
            // `GenLock` is labelled at runtime by the slab that owns the
            // slot (`slot_ptr._gen_lock.class = "SecureSlab(" ++
            // @typeName(T) ++ ")._gen_lock"` in secure_slab.zig). Consult
            // the runtime-assignment map by field name before giving up.
            const class: []const u8 = if (class_buf.items.len > 0)
                class_buf.items
            else if (rt_classes.get(nametok.text)) |c|
                c
            else
                try std.fmt.allocPrint(a, "@unclassified:{s}", .{nametok.text});

            const key = try std.fmt.allocPrint(a, "{d}\x00{s}", .{ f.id, nametok.text });
            if (seen.contains(key)) continue;
            try seen.put(key, {});

            try out.append(a, .{
                .decl_name = nametok.text,
                .class = class,
                .file_id = f.id,
                .line = ctx.lineForByte(f.id, nametok.byte_start),
            });
        }
    }
    return out.toOwnedSlice(a);
}

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') return s[1 .. s.len - 1];
    return s;
}

/// Local `const X = &chain[…];` aliases inside one function body. The
/// per-core lock arrays (`core_locks`, `wheel_locks`) are always reached
/// this way, so without alias expansion every one of their acquires
/// resolves to the bare name `lock` and lands in UNRESOLVED.
const Alias = struct { name: []const u8, segs: [][]const u8 };

fn collectAliases(ctx: *Ctx, file_i: u32, host: u32) ![]Alias {
    const a = ctx.a;
    const e = ctx.ents[host];
    const toks = ctx.toks[file_i];
    var out: ArrayList(Alias) = .{};
    var i: usize = 0;
    while (i + 4 < toks.len) : (i += 1) {
        if (toks[i].byte_start < e.byte_start) continue;
        if (toks[i].byte_start >= e.byte_end) break;
        // `const NAME = [&]chain…;`
        if (toks[i].kind == .keyword_const and
            toks[i + 1].kind == .identifier and toks[i + 2].kind == .equal)
        {
            var j = i + 3;
            if (toks[j].kind == .ampersand) j += 1;
            if (j >= toks.len or toks[j].kind != .identifier) continue;
            const ch = try readChain(a, toks, j);
            try out.append(a, .{ .name = toks[i + 1].text, .segs = ch.segs });
            continue;
        }
        // `for (&chain[, …]) |[*]NAME[, …]|` — the per-core lock arrays
        // are swept this way (`for (&core_locks) |*lock|` in
        // `scheduler.awaitDomainQuiesced`), and without this the capture
        // name shadows nothing resolvable and the acquire is lost.
        if (toks[i].kind == .keyword_for and toks[i + 1].kind == .l_paren) {
            var operands: ArrayList([][]const u8) = .{};
            var j = i + 2;
            var depth: i32 = 1;
            var start = j;
            while (j < toks.len and depth > 0) : (j += 1) {
                switch (toks[j].kind) {
                    .l_paren, .l_bracket, .l_brace => depth += 1,
                    .r_paren, .r_bracket, .r_brace => {
                        depth -= 1;
                        if (depth == 0) {
                            if (try argChain(ctx, toks, start, j)) |c| {
                                try operands.append(a, c);
                            } else try operands.append(a, &.{});
                        }
                    },
                    .comma => if (depth == 1) {
                        if (try argChain(ctx, toks, start, j)) |c| {
                            try operands.append(a, c);
                        } else try operands.append(a, &.{});
                        start = j + 1;
                    },
                    else => {},
                }
            }
            if (j >= toks.len or toks[j].kind != .pipe) continue;
            var cap: usize = 0;
            var k = j + 1;
            while (k < toks.len and toks[k].kind != .pipe) : (k += 1) {
                if (toks[k].kind == .asterisk) continue;
                if (toks[k].kind == .comma) {
                    cap += 1;
                    continue;
                }
                if (toks[k].kind != .identifier) continue;
                if (cap < operands.items.len and operands.items[cap].len > 0) {
                    try out.append(a, .{ .name = toks[k].text, .segs = operands.items[cap] });
                }
            }
        }
    }
    return out.toOwnedSlice(a);
}

/// Group the declarations into lock CLASSES, keyed on the kernel's own
/// lockdep `.class` string.
///
/// Identity used to be one-row-per-declaration, which was wrong in both
/// directions:
///
///   • UNDER-grouping. `serial.print_lock` is declared once in
///     arch/x64/serial.zig and once in arch/aarch64/serial.zig. Two decls,
///     one class — but Rule B printed two CLASS blocks and computed two
///     independent verdicts, so a class could be reported "IRQ-MASKED at
///     every acquire" on the strength of half its acquire sites.
///
///   • Unresolvable cross-file receivers. Every slab-backed type declares
///     `_gen_lock`, so a decl-keyed lookup for `cd._gen_lock…` found ~12
///     candidates, none in the acquiring file, and gave up — 33 acquires
///     into UNRESOLVED. All 12 decls carry the SAME class, so the
///     ambiguity was never real: the answer does not depend on which decl
///     you pick.
///
/// Keying on the class string makes both cases fall out: candidates that
/// disagree on class are still a genuine ambiguity and stay unresolved.
fn buildClassGroups(ctx: *Ctx) !void {
    const a = ctx.a;
    var groups: ArrayList(ClassGroup) = .{};
    var by_class = std.StringHashMap(u32).init(a);
    const of_decl = try a.alloc(u32, ctx.locks.len);
    for (ctx.locks, 0..) |l, li| {
        const g = try by_class.getOrPut(l.class);
        if (!g.found_existing) {
            g.value_ptr.* = @intCast(groups.items.len);
            try groups.append(a, .{ .class = l.class, .decls = &.{} });
        }
        of_decl[li] = g.value_ptr.*;
    }
    // Second pass: attach the decl list to each group, in decl order.
    var lists = try a.alloc(ArrayList(u32), groups.items.len);
    for (lists) |*x| x.* = .{};
    for (ctx.locks, 0..) |_, li| try lists[of_decl[li]].append(a, @intCast(li));
    for (lists, 0..) |*x, gi| groups.items[gi].decls = try x.toOwnedSlice(a);

    ctx.classes = try groups.toOwnedSlice(a);
    ctx.class_of_decl = of_decl;
}

/// Resolve an acquire receiver to a lock CLASS index.
///
/// Same-file decl wins outright. Otherwise every declaration sharing the
/// receiver's terminal field name must agree on its class; if they do, the
/// class is determined even though the declaration is not.
fn resolveLockClass(ctx: *Ctx, file_id: i64, aliases: []const Alias, segs_in: []const []const u8) ?u32 {
    var segs = segs_in;
    if (segs.len == 1) {
        for (aliases) |al| {
            if (mem.eql(u8, al.name, segs[0])) {
                segs = al.segs;
                break;
            }
        }
    }
    const term = segs[segs.len - 1];

    var same_file: ?u32 = null;
    var same_n: usize = 0;
    var any_class: ?u32 = null;
    var n_named: usize = 0;
    var all_agree = true;
    for (ctx.locks, 0..) |l, li| {
        if (!mem.eql(u8, l.decl_name, term)) continue;
        n_named += 1;
        const gi = ctx.class_of_decl[li];
        if (any_class) |prev| {
            if (prev != gi) all_agree = false;
        } else any_class = gi;
        if (l.file_id == file_id) {
            same_file = ctx.class_of_decl[li];
            same_n += 1;
        }
    }
    if (same_n == 1) return same_file;
    if (n_named > 0 and all_agree) return any_class;
    return null;
}

fn collectAcquires(ctx: *Ctx) !void {
    const a = ctx.a;
    var sites: ArrayList(AcquireSite) = .{};
    var unres: ArrayList(UnresolvedAcq) = .{};

    for (ctx.files, 0..) |f, fi| {
        if (mem.eql(u8, f.path, LOCK_IMPL_FILE)) continue;
        if (!inKernelScope(f.path)) continue;
        const toks = ctx.toks[fi];
        if (toks.len == 0) continue;

        var cached_host: ?u32 = null;
        var cached_aliases: []Alias = &.{};

        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].kind != .identifier) continue;
            if (i > 0 and toks[i - 1].kind == .period) continue;
            const anchor = i;
            const ch = try readChain(a, toks, i);
            i = ch.next - 1;
            if (ch.segs.len < 2) continue;
            if (ch.next >= toks.len or toks[ch.next].kind != .l_paren) continue;

            const method = ch.segs[ch.segs.len - 1];
            var masked: bool = false;
            var is_acq = false;
            for (ACQUIRE_METHODS) |m| {
                if (mem.eql(u8, m.name, method)) {
                    is_acq = true;
                    masked = m.masked;
                }
            }
            if (!is_acq) continue;

            const recv = ch.segs[0 .. ch.segs.len - 1];
            const host = enclosingFn(ctx, @intCast(fi), toks[anchor].byte_start);
            if (host) |h| {
                if (cached_host == null or cached_host.? != h) {
                    cached_aliases = try collectAliases(ctx, @intCast(fi), h);
                    cached_host = h;
                }
            }
            const recv_text = try mem.join(a, ".", recv);
            const line = ctx.lineForByte(f.id, toks[anchor].byte_start);

            if (resolveLockClass(ctx, f.id, cached_aliases, recv)) |li| {
                try sites.append(a, .{
                    .class_idx = li,
                    .file_id = f.id,
                    .line = line,
                    .method = method,
                    .masked = masked,
                    .host = host,
                    .receiver = recv_text,
                });
            } else {
                try unres.append(a, .{
                    .file_id = f.id,
                    .line = line,
                    .receiver = recv_text,
                    .method = method,
                });
            }
        }
    }
    ctx.acquires = try sites.toOwnedSlice(a);
    ctx.unresolved = try unres.toOwnedSlice(a);
}

// ─── Reporting ────────────────────────────────────────────────────────

const Opts = struct {
    db_paths: [][]const u8,
    summary: bool,
    rule_a: bool,
    rule_b: bool,
    show_paths: bool,
    strict: bool,
    write_findings: bool,
    unresolved_detail: bool,
};

const Counts = struct {
    entries: usize = 0,
    sources: usize = 0,
    claim_sites: usize = 0,
    classes: usize = 0,
    plain_ec_classes: usize = 0,
    plain_ec_sites: usize = 0,
    mixed_classes: usize = 0,
    async_sources: usize = 0,
    unresolved: usize = 0,
};

const ClaimSite = struct {
    host: u32,
    prim: u32,
    tier: PrimTier,
    file_id: i64,
    line: u32,
    prov: EdgeProv,
    /// Wake-source group: first non-`arch/` entity on the witness path.
    source: u32,
};

fn lessClaim(ctx: *const Ctx, x: ClaimSite, y: ClaimSite) bool {
    const c = mem.order(u8, ctx.ents[x.source].qname, ctx.ents[y.source].qname);
    if (c != .eq) return c == .lt;
    if (x.line != y.line) return x.line < y.line;
    return x.tier == .claim and y.tier != .claim;
}

const W = *std.Io.Writer;

fn ruleA(ctx: *Ctx, o: Opts, w: W, counts: *Counts) ![]ClaimSite {
    const a = ctx.a;

    // ── Seeds, filtered to this DB's arch ────────────────────────────
    const all_seeds = try collectIrqSeeds(ctx);
    var seeds: ArrayList(Seed) = .{};
    var seed_ids: ArrayList(u32) = .{};
    for (all_seeds) |s| {
        if (ctx.archOf(ctx.ents[s.ent].file_id)) |ar| {
            if (!mem.eql(u8, ar, ctx.arch)) continue; // other arch: no IR in this DB
        }
        try seeds.append(a, s);
        try seed_ids.append(a, s.ent);
    }
    counts.entries = seeds.items.len;

    // ── Primitives ───────────────────────────────────────────────────
    var prims: ArrayList(u32) = .{};
    var prim_tier = std.AutoHashMap(u32, PrimTier).init(a);
    for (WAKE_PRIMITIVES) |p| {
        var segs: ArrayList([]const u8) = .{};
        var it = mem.splitScalar(u8, p.qname, '.');
        while (it.next()) |s| try segs.append(a, s);
        const ei = resolveFn(ctx, segs.items, null) orelse {
            try w.print("analyzer_error: wake primitive '{s}' does not resolve to a function entity in {s}\n", .{ p.qname, ctx.db_path });
            try w.flush();
            std.process.exit(2);
        };
        try prims.append(a, ei);
        try prim_tier.put(ei, p.tier);
    }

    const fwd = try reach(a, ctx.out_adj, seed_ids.items, ctx.ents.len);
    const bwd = try reach(a, ctx.in_adj, prims.items, ctx.ents.len);

    // Same closure restricted to *asynchronous* entries. A source reachable
    // only from a synchronous exception entry runs in the faulting EC's own
    // context; on aarch64 that set includes the entire SVC syscall surface,
    // which is not what "interrupt-context wake" means.
    var async_ids: ArrayList(u32) = .{};
    for (seeds.items) |s| {
        if (s.kind == .async_irq) try async_ids.append(a, s.ent);
    }
    const fwd_async = try reach(a, ctx.out_adj, async_ids.items, ctx.ents.len);

    // ── Claim sites: call edges into a primitive, from IRQ-reachable code
    var sites: ArrayList(ClaimSite) = .{};
    for (ctx.edges) |e| {
        const tier = prim_tier.get(e.to) orelse continue;
        if (!fwd[e.from]) continue;
        if (prim_tier.contains(e.from)) continue; // primitive → primitive plumbing
        try sites.append(a, .{
            .host = e.from,
            .prim = e.to,
            .tier = tier,
            .file_id = ctx.ents[e.from].file_id,
            .line = e.line,
            .prov = e.prov,
            .source = e.from, // filled in below
        });
    }
    const site_slice = try sites.toOwnedSlice(a);
    counts.claim_sites = site_slice.len;

    // ── Wake sources = the arch → generic frontier of the closure.
    //
    // A wake source is a function that (a) can reach an EC claim, (b) is
    // itself reachable from an interrupt entry, (c) lives outside
    // `kernel/arch/` and (d) is called directly by arch code that is also
    // inside the closure. That is precisely "the first thing the ISR
    // plumbing hands control to that can wake an EC" — the granularity a
    // hand-written enumeration table uses.
    //
    // Deliberately NOT "the first non-arch node on a shortest witness
    // path": a claim site reachable from several ISRs would then be
    // attributed to whichever path happened to be shortest, and the other
    // sources would silently vanish from the table. (That bug hid the
    // timer-wheel source behind the device-IRQ source on the first run of
    // this analyzer.)
    var sources: ArrayList(u32) = .{};
    for (0..ctx.ents.len) |ni| {
        const n: u32 = @intCast(ni);
        if (!fwd[n] or !bwd[n]) continue;
        if (!ctx.ents[n].is_fn) continue;
        if (ctx.isArchFile(ctx.ents[n].file_id)) continue;
        var from_arch = false;
        for (ctx.in_adj[n]) |c| {
            if (fwd[c] and bwd[c] and ctx.isArchFile(ctx.ents[c].file_id)) from_arch = true;
        }
        if (from_arch) try sources.append(a, n);
    }
    std.mem.sort(u32, sources.items, @as(*const Ctx, ctx), struct {
        fn less(c: *const Ctx, x: u32, y: u32) bool {
            return mem.order(u8, c.ents[x].qname, c.ents[y].qname) == .lt;
        }
    }.less);
    counts.sources = sources.items.len;
    for (sources.items) |sx| {
        if (fwd_async[sx]) counts.async_sources += 1;
    }

    if (o.summary) return site_slice;

    // ── Render ───────────────────────────────────────────────────────
    try w.print("\n══ RULE A — interrupt-context EC wake closure ({s}) ══\n\n", .{ctx.arch});
    try w.print("Interrupt entry points ({d}):\n", .{seeds.items.len});
    for (seeds.items) |s| {
        try w.print("  [{s:<5}][{s:<12}] {s:<48} {s}\n", .{
            s.kind.label(), s.src.label(), ctx.ents[s.ent].qname, ctx.entLoc(s.ent),
        });
    }
    var n_bwd: usize = 0;
    var n_fwd: usize = 0;
    var n_int: usize = 0;
    for (0..ctx.ents.len) |i| {
        if (fwd[i]) n_fwd += 1;
        if (bwd[i]) n_bwd += 1;
        if (fwd[i] and bwd[i]) n_int += 1;
    }
    try w.print("\nWake primitives:\n", .{});
    for (prims.items) |p| {
        try w.print("  [{s:<7}] {s:<48} {s}\n", .{
            (prim_tier.get(p).?).label(), ctx.ents[p].qname, ctx.entLoc(p),
        });
    }
    try w.print("\nClosure: |IRQ-reachable|={d}  |wake-reaching|={d}  |intersection|={d}\n", .{ n_fwd, n_bwd, n_int });

    var n_async_src: usize = 0;
    for (sources.items) |sx| {
        if (fwd_async[sx]) n_async_src += 1;
    }
    try w.print("\nWAKE SOURCES ({d} total, {d} reachable from an asynchronous IRQ entry)\n", .{ sources.items.len, n_async_src });
    try w.print("— the arch → generic frontier of the closure:\n", .{});
    for (sources.items, 0..) |src, si| {
        const one = [_]u32{src};
        const from_src = try reach(a, ctx.out_adj, &one, ctx.ents.len);
        try w.print("\n  {d}. {s}   [{s}]\n     defined  {s}\n", .{
            si + 1,
            ctx.ents[src].qname,
            if (fwd_async[src]) "async-IRQ reachable" else "SYNC-EXCEPTION ONLY",
            ctx.entLoc(src),
        });
        // Which ISR entries actually reach this source?
        var first = true;
        for (seeds.items) |sd| {
            const os = [_]u32{sd.ent};
            const r = try reach(a, ctx.out_adj, &os, ctx.ents.len);
            if (!r[src]) continue;
            try w.print("{s}{s}", .{ if (first) "     entered from  " else ", ", ctx.ents[sd.ent].qname });
            first = false;
        }
        if (!first) try w.print("\n", .{});
        if (o.show_paths) {
            if (try witnessPath(ctx, seed_ids.items, src)) |pth| {
                try w.print("     witness  ", .{});
                for (pth, 0..) |n, k| {
                    if (k != 0) try w.print(" → ", .{});
                    try w.print("{s}", .{ctx.ents[n].qname});
                }
                try w.print("\n", .{});
            }
        }
        var printed = std.AutoHashMap(u64, void).init(a);
        for (site_slice) |s| {
            if (!from_src[s.host]) continue;
            const k = (@as(u64, s.host) << 32) | @as(u64, s.prim);
            if (printed.contains(k)) continue;
            try printed.put(k, {});
            try w.print("     {s:<8} {s}:{d}  {s} → {s}   [{s}]\n", .{
                s.tier.label(),
                ctx.dpath(s.file_id),
                s.line,
                ctx.ents[s.host].qname,
                ctx.ents[s.prim].qname,
                s.prov.label(),
            });
        }
    }

    // The negative half of the answer, and the half a hand derivation is
    // most likely to get wrong: entries that reach no EC claim at all.
    try w.print("\nWAKE-FREE interrupt entries (reach no `claim`-tier primitive):\n", .{});
    var any_free = false;
    for (seeds.items) |s| {
        const one = [_]u32{s.ent};
        const r = try reach(a, ctx.out_adj, &one, ctx.ents.len);
        var has = false;
        for (site_slice) |cs| {
            if (cs.tier == .claim and r[cs.host]) {
                has = true;
                break;
            }
        }
        if (!has) {
            any_free = true;
            try w.print("  {s:<48} {s}\n", .{ ctx.ents[s.ent].qname, ctx.entLoc(s.ent) });
        }
    }
    if (!any_free) try w.print("  (none)\n", .{});

    return site_slice;
}


const ClassVerdict = enum { masked_all, plain_ec, no_sites, irq_only_plain, plain_unreachable };

fn ruleB(ctx: *Ctx, o: Opts, w: W, counts: *Counts) !void {
    const a = ctx.a;

    // EC context = reachable from a syscall or boot entry.
    var ec_seeds: ArrayList(u32) = .{};
    {
        var stmt = try ctx.db.prepare(
            "SELECT entity_id FROM entry_point WHERE kind IN ('syscall','boot')",
            a,
        );
        defer stmt.finalize();
        while (try stmt.step()) {
            if (ctx.idx_by_id.get(stmt.columnInt(0))) |ei| try ec_seeds.append(a, ei);
        }
    }
    const ec_reach = try reach(a, ctx.out_adj, ec_seeds.items, ctx.ents.len);

    // Asynchronous-IRQ context and synchronous-exception context are kept
    // apart, because they answer different questions. A plain acquire of a
    // lock that an *asynchronous* handler also takes on the same core is a
    // self-deadlock: the IRQ lands mid-critical-section and spins on a lock
    // the interrupted code holds. A synchronous exception cannot do that —
    // it only fires because the running code faulted, and the fault handler
    // is a continuation of that same EC.
    var async_seeds: ArrayList(u32) = .{};
    var sync_seeds: ArrayList(u32) = .{};
    for (try collectIrqSeeds(ctx)) |s| {
        if (ctx.archOf(ctx.ents[s.ent].file_id)) |ar| {
            if (!mem.eql(u8, ar, ctx.arch)) continue;
        }
        switch (s.kind) {
            .async_irq => try async_seeds.append(a, s.ent),
            .sync_exception => try sync_seeds.append(a, s.ent),
        }
    }
    const async_reach = try reach(a, ctx.out_adj, async_seeds.items, ctx.ents.len);
    const sync_reach = try reach(a, ctx.out_adj, sync_seeds.items, ctx.ents.len);

    counts.classes = ctx.classes.len;
    counts.unresolved = ctx.unresolved.len;

    if (!o.summary) {
        try w.print("\n══ RULE B — lock-class IRQ-masking closure ({s}) ══\n", .{ctx.arch});
    }

    // Order classes: plain-EC first (the interesting ones), then by name.
    const order = try a.alloc(u32, ctx.classes.len);
    for (order, 0..) |*x, i| x.* = @intCast(i);

    const verdicts = try a.alloc(ClassVerdict, ctx.classes.len);
    for (verdicts, 0..) |*v, li| {
        var n_sites: usize = 0;
        var n_plain_ec: usize = 0;
        var n_plain_irq: usize = 0;
        var n_plain_any: usize = 0;
        var n_masked: usize = 0;
        for (ctx.acquires) |s| {
            if (s.class_idx != li) continue;
            n_sites += 1;
            const ec = if (s.host) |h| ec_reach[h] else false;
            const ir = if (s.host) |h| async_reach[h] else false;
            if (s.masked) n_masked += 1 else {
                n_plain_any += 1;
                if (ec) n_plain_ec += 1 else if (ir) n_plain_irq += 1;
            }
        }
        v.* = if (n_sites == 0)
            .no_sites
        else if (n_plain_ec > 0)
            .plain_ec
        else if (n_plain_irq > 0)
            .irq_only_plain
        else if (n_plain_any > 0)
            .plain_unreachable
        else
            .masked_all;
        if (v.* == .plain_ec) {
            counts.plain_ec_classes += 1;
            counts.plain_ec_sites += n_plain_ec;
        }
        if (n_plain_any > 0 and n_masked > 0) counts.mixed_classes += 1;
    }

    if (o.summary) return;

    const Sorter = struct {
        ctx: *const Ctx,
        v: []ClassVerdict,
        fn less(self: @This(), x: u32, y: u32) bool {
            const rank = struct {
                fn f(vv: ClassVerdict) u8 {
                    return switch (vv) {
                        .plain_ec => 0,
                        .irq_only_plain => 1,
                        .plain_unreachable => 2,
                        .masked_all => 3,
                        .no_sites => 4,
                    };
                }
            }.f;
            const rx = rank(self.v[x]);
            const ry = rank(self.v[y]);
            if (rx != ry) return rx < ry;
            return mem.order(u8, self.ctx.classes[x].class, self.ctx.classes[y].class) == .lt;
        }
    };
    std.mem.sort(u32, order, Sorter{ .ctx = ctx, .v = verdicts }, Sorter.less);

    for (order) |li| {
        const g = ctx.classes[li];
        const verdict: []const u8 = switch (verdicts[li]) {
            .masked_all => "IRQ-MASKED at every acquire",
            .plain_ec => "PLAIN acquires on EC-context paths  ← preemptible while held",
            .irq_only_plain => "PLAIN acquires, but only on IRQ-context paths (IRQs already off)",
            .plain_unreachable => "PLAIN acquires whose callers the static graph cannot reach - context UNPROVEN",
            .no_sites => "no acquire sites found",
        };
        try w.print("\nCLASS {s}\n      {s}\n", .{ g.class, verdict });
        // Every declaration carrying this class. More than one is normal:
        // per-arch twins (`serial.print_lock`) and the `_gen_lock` field of
        // every slab-backed type all share a single class.
        for (g.decls) |di| {
            const l = ctx.locks[di];
            try w.print("      decl {s}  (`{s}`)\n", .{ ctx.dloc(l.file_id, l.line), l.decl_name });
        }
        for (ctx.acquires) |s| {
            if (s.class_idx != li) continue;
            const ec = if (s.host) |h| ec_reach[h] else false;
            const ai = if (s.host) |h| async_reach[h] else false;
            const sx = if (s.host) |h| sync_reach[h] else false;
            var ctxbuf: ArrayList(u8) = .{};
            if (ec) try ctxbuf.appendSlice(a, "ec");
            if (ai) {
                if (ctxbuf.items.len != 0) try ctxbuf.append(a, '+');
                try ctxbuf.appendSlice(a, "async-irq");
            }
            if (sx) {
                if (ctxbuf.items.len != 0) try ctxbuf.append(a, '+');
                try ctxbuf.appendSlice(a, "sync-exc");
            }
            if (ctxbuf.items.len == 0) try ctxbuf.appendSlice(a, "unreachable");
            try w.print("        {s:<6} {s}:{d}  {s}.{s}()  in {s}  [{s}]{s}\n", .{
                if (s.masked) "MASKED" else "PLAIN",
                ctx.dpath(s.file_id),
                s.line,
                s.receiver,
                s.method,
                if (s.host) |h| ctx.ents[h].qname else "<file scope>",
                ctxbuf.items,
                if (!s.masked and ec and ai) "   <<< SELF-DEADLOCK RISK: plain acquire of a class an async IRQ also takes" else "",
            });
        }
    }

    if (ctx.unresolved.len > 0) {
        try w.print("\nUNRESOLVED acquire receivers ({d}) — receivers whose terminal field\n", .{ctx.unresolved.len});
        try w.print("name does not determine a declared lockdep class.\n", .{});
        try w.print("\n", .{});
        try w.print("Direct `SpinLock` and `<x>._gen_lock` acquires ARE resolved (the\n", .{});
        try w.print("latter via the runtime class assignment in secure_slab.zig). What\n", .{});
        try w.print("remains is dominated by SlabRef receivers — `cd_ref.lockIrqSave(…)`\n", .{});
        try w.print("— where the receiver is a local whose type decides the class. The\n", .{});
        try w.print("kernel proves every SlabRef acquire bottoms out in the target's\n", .{});
        try w.print("`self.ptr._gen_lock`, so these ARE that class; the analyzer cannot\n", .{});
        try w.print("say so, because the DB carries no local-variable types (`dwarf_local`\n", .{});
        try w.print("is empty) and attributing them by elimination would silently\n", .{});
        try w.print("misfile any genuinely unresolved SpinLock landing here.\n", .{});
        try w.print("tools/check_gen_lock check 6 covers this population directly.\n", .{});
        // Group by receiver terminal for a readable summary.
        var grouped = std.StringHashMap(u32).init(a);
        for (ctx.unresolved) |u| {
            const term = if (mem.lastIndexOfScalar(u8, u.receiver, '.')) |d| u.receiver[d + 1 ..] else u.receiver;
            const e = try grouped.getOrPut(term);
            if (!e.found_existing) e.value_ptr.* = 0;
            e.value_ptr.* += 1;
        }
        if (o.unresolved_detail) {
            for (ctx.unresolved) |u| {
                try w.print("      {s}:{d}  {s}.{s}()" ++ "\n", .{
                    ctx.dpath(u.file_id), u.line, u.receiver, u.method,
                });
            }
        }
        var it = grouped.iterator();
        while (it.next()) |e| {
            try w.print("    {d:>3}×  {s}\n", .{ e.value_ptr.*, e.key_ptr.* });
        }
    }
}

// ─── lint_finding write-back ──────────────────────────────────────────

fn writeFindings(a: Allocator, db_path: []const u8, ctx: *Ctx, sites: []const ClaimSite) !void {
    var rw = try sqlite.Db.openReadWrite(db_path, a);
    defer rw.close();
    try rw.exec("BEGIN IMMEDIATE");
    errdefer rw.exec("ROLLBACK") catch {};
    {
        var del = try rw.prepare("DELETE FROM lint_finding WHERE analyzer = 'ec_closure'", a);
        defer del.finalize();
        _ = try del.step();
    }
    var ins = try rw.prepare(
        \\INSERT INTO lint_finding
        \\  (analyzer, severity, rule, entity_id, file_id, byte_start, byte_end, line, message, extra_json)
        \\VALUES ('ec_closure', ?1, ?2, ?3, ?4, 0, 0, ?5, ?6, ?7)
    , a);
    defer ins.finalize();

    for (sites) |s| {
        if (s.tier != .claim) continue;
        const msg = try std.fmt.allocPrint(a, "irq-context wake: {s} → {s} (source {s})", .{
            ctx.ents[s.host].qname, ctx.ents[s.prim].qname, ctx.ents[s.source].qname,
        });
        const extra = try std.fmt.allocPrint(a, "{{\"prov\":\"{s}\",\"arch\":\"{s}\"}}", .{ s.prov.label(), ctx.arch });
        ins.reset();
        try ins.bindText(1, "info");
        try ins.bindText(2, "irq_wake_source");
        try ins.bindInt(3, ctx.ents[s.host].id);
        try ins.bindInt(4, s.file_id);
        try ins.bindInt(5, @intCast(s.line));
        try ins.bindText(6, msg);
        try ins.bindText(7, extra);
        _ = try ins.step();
    }
    for (ctx.acquires) |s| {
        if (s.masked) continue;
        const msg = try std.fmt.allocPrint(a, "plain (non-IRQ-masked) acquire of lock class {s} via {s}.{s}()", .{
            ctx.classes[s.class_idx].class, s.receiver, s.method,
        });
        ins.reset();
        try ins.bindText(1, "warn");
        try ins.bindText(2, "plain_lock_acquire");
        if (s.host) |h| try ins.bindInt(3, ctx.ents[h].id);
        try ins.bindInt(4, s.file_id);
        try ins.bindInt(5, @intCast(s.line));
        try ins.bindText(6, msg);
        try ins.bindText(7, "{}");
        _ = try ins.step();
    }
    try rw.exec("COMMIT");
}

// ─── Entry point ──────────────────────────────────────────────────────

const USAGE =
    \\usage: check_ec_closure --db <path> [--db <path> …] [options]
    \\
    \\Computes two closures over the callgraph DB that docs/kernel/systems.md
    \\maintains by hand:
    \\
    \\  Rule A  interrupt-context EC wake sources — every function reachable
    \\          from an interrupt/exception entry that can wake or claim an
    \\          execution context.
    \\  Rule B  lock-class IRQ-masking — for every declared SpinLock class,
    \\          whether all EC-context acquires mask IRQs.
    \\
    \\options:
    \\  --db <path>     callgraph DB (repeatable; one per arch)
    \\  --rule a|b      run only one rule (default: both)
    \\  --summary       one machine-readable line per DB, no detail
    \\  --paths         print a witness call path for each wake source
    \\  --strict        exit 1 when any class has plain EC-context acquires
    \\  --unresolved-detail
    \\                  list every acquire receiver Rule B could not attribute
    \\  --write        persist findings into lint_finding (analyzer='ec_closure')
    \\  -h, --help      this text
    \\
    \\Exit: 0 on success, 1 under --strict with plain EC-context acquires,
    \\      2 on analyzer error (unresolvable seed/primitive, DB failure).
    \\
;

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var dbs: ArrayList([]const u8) = .{};
    var o = Opts{
        .db_paths = &.{},
        .summary = false,
        .rule_a = true,
        .rule_b = true,
        .show_paths = false,
        .strict = false,
        .write_findings = false,
        .unresolved_detail = false,
    };

    var args_it = std.process.args();
    _ = args_it.next();
    while (args_it.next()) |arg| {
        if (mem.eql(u8, arg, "--db")) {
            const v = args_it.next() orelse die("--db requires a path\n");
            try dbs.append(a, try a.dupe(u8, v));
        } else if (mem.eql(u8, arg, "--rule")) {
            const v = args_it.next() orelse die("--rule requires a|b\n");
            o.rule_a = mem.eql(u8, v, "a");
            o.rule_b = mem.eql(u8, v, "b");
            if (!o.rule_a and !o.rule_b) die("--rule takes 'a' or 'b'\n");
        } else if (mem.eql(u8, arg, "--summary")) {
            o.summary = true;
        } else if (mem.eql(u8, arg, "--paths")) {
            o.show_paths = true;
        } else if (mem.eql(u8, arg, "--strict")) {
            o.strict = true;
        } else if (mem.eql(u8, arg, "--unresolved-detail")) {
            o.unresolved_detail = true;
        } else if (mem.eql(u8, arg, "--write")) {
            o.write_findings = true;
        } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            _ = std.fs.File.stdout().write(USAGE) catch {};
            std.process.exit(0);
        } else {
            die("unknown flag\n");
        }
    }
    if (dbs.items.len == 0) die("--db is required (see --help)\n");
    o.db_paths = dbs.items;

    const stdout = std.fs.File.stdout();
    var buf: [1 << 16]u8 = undefined;
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
    var fw = stdout.writerStreaming(&buf);
    const w = &fw.interface;

    var exit_code: u8 = 0;
    for (o.db_paths) |p| {
        var db = sqlite.Db.openReadOnly(p, a) catch |err| {
            try w.print("analyzer_error: cannot open {s}: {s}\n", .{ p, @errorName(err) });
            try w.flush();
            std.process.exit(2);
        };

        var ctx = Ctx{
            .a = a,
            .db = &db,
            .db_path = p,
            .arch = try loadMeta(a, &db, "arch"),
            .files = undefined,
            .file_by_id = std.AutoHashMap(i64, u32).init(a),
            .line_starts = undefined,
            .ents = undefined,
            .idx_by_id = std.AutoHashMap(i64, u32).init(a),
            .by_short = std.StringHashMap(std.ArrayListUnmanaged(u32)).init(a),
            .toks = undefined,
            .fn_ranges = undefined,
            .file_aliases = undefined,
            .edges = undefined,
            .out_adj = undefined,
            .in_adj = undefined,
            .locks = undefined,
            .classes = undefined,
            .class_of_decl = undefined,
            .acquires = undefined,
            .unresolved = undefined,
        };

        ctx.files = try loadFiles(a, &db);
        for (ctx.files, 0..) |f, i| try ctx.file_by_id.put(f.id, @intCast(i));
        try loadLineIndex(&ctx);
        ctx.ents = try loadEntities(a, &db);
        for (ctx.ents, 0..) |e, i| {
            try ctx.idx_by_id.put(e.id, @intCast(i));
            if (!e.is_fn) continue;
            const g = try ctx.by_short.getOrPut(e.short);
            if (!g.found_existing) g.value_ptr.* = .{};
            try g.value_ptr.append(a, @intCast(i));
        }
        try loadTokens(&ctx);
        try buildFnRanges(&ctx);
        try buildFileAliases(&ctx);

        var edges: ArrayList(Edge) = .{};
        var seen = std.AutoHashMap(u64, void).init(a);
        try loadIrEdges(&ctx, &edges, &seen);
        const n_ir = edges.items.len;
        try addSyntacticEdges(&ctx, &edges, &seen);
        ctx.edges = try edges.toOwnedSlice(a);
        try buildAdjacency(&ctx);

        ctx.locks = try collectLockDecls(&ctx);
        try buildClassGroups(&ctx);
        try collectAcquires(&ctx);

        var counts: Counts = .{};
        if (!o.summary) {
            try w.print("\n╔══════════════════════════════════════════════════════════════════╗\n", .{});
            try w.print("  db   {s}\n  arch {s}\n  graph {d} ir edges + {d} syntactic-overlay edges over {d} entities\n", .{
                p, ctx.arch, n_ir, ctx.edges.len - n_ir, ctx.ents.len,
            });
            try w.print("╚══════════════════════════════════════════════════════════════════╝\n", .{});
        }

        var sites: []ClaimSite = &.{};
        if (o.rule_a) sites = try ruleA(&ctx, o, w, &counts);
        if (o.rule_b) try ruleB(&ctx, o, w, &counts);

        try w.print("\nSummary[{s}]: entries={d} sources={d} async_sources={d} claim_sites={d} classes={d} plain_ec_classes={d} plain_ec_sites={d} mixed_classes={d} unresolved={d}\n", .{
            ctx.arch,
            counts.entries,
            counts.sources,
            counts.async_sources,
            counts.claim_sites,
            counts.classes,
            counts.plain_ec_classes,
            counts.plain_ec_sites,
            counts.mixed_classes,
            counts.unresolved,
        });
        try w.flush();

        if (o.write_findings) {
            db.close();
            writeFindings(a, p, &ctx, sites) catch |err| {
                try w.print("warning: lint_finding write failed: {s}\n", .{@errorName(err)});
            };
        } else {
            db.close();
        }

        if (o.strict and counts.plain_ec_classes > 0) exit_code = 1;
    }
    try w.flush();
    std.process.exit(exit_code);
}

fn die(msg: []const u8) noreturn {
    _ = std.fs.File.stderr().write(msg) catch {};
    std.process.exit(2);
}
