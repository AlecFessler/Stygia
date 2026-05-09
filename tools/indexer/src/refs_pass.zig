//! Stage 2.5 follow-up: resolve provisional alias and type-ref chains
//! against the final entity table and emit `const_alias` / `entity_type_ref`
//! rows. Drops chains that don't resolve.

const std = @import("std");
const types = @import("types.zig");
const writer = @import("writer.zig");

const FinalEntity = writer.FinalEntity;
const ConstAliasRow = writer.ConstAliasRow;
const TypeRefRow = writer.TypeRefRow;

pub const PassResult = struct {
    const_aliases: []ConstAliasRow,
    type_refs: []TypeRefRow,
};

/// Per-module resolution context: maps the simple name of every entity
/// (the part after the last `.`) to a list of fully-qualified entity ids
/// in that module. Used as the first hop when resolving a chain whose head
/// segment is a local decl name (e.g. `sync` in
/// `pub const lockPair = sync.lockPair;` where `sync` is the file's import).
const ModuleNameTable = std.StringHashMapUnmanaged(std.ArrayListUnmanaged(u32));

pub fn pass(
    allocator: std.mem.Allocator,
    entities: []const FinalEntity,
    modules: []const types.ModuleRecord,
    aliases: []const types.ProvisionalAlias,
    type_refs_in: []const types.ProvisionalTypeRef,
) !PassResult {
    // Build qname → entity_id map (one entity per qname after dedup).
    var qname_to_id: std.StringHashMapUnmanaged(u32) = .empty;
    try qname_to_id.ensureTotalCapacity(allocator, @intCast(entities.len));
    for (entities) |e| {
        try qname_to_id.put(allocator, e.qualified_name, e.id);
    }

    // Build module_id → module_qname lookup.
    var module_qnames: std.AutoHashMapUnmanaged(u32, []const u8) = .empty;
    try module_qnames.ensureTotalCapacity(allocator, @intCast(modules.len));
    for (modules) |m| {
        try module_qnames.put(allocator, m.id, m.qualified_name);
    }

    // Build per-module simple-name → entity_id list. Used as fallback when
    // the chain's first segment is a local import alias.
    var per_module: std.AutoHashMapUnmanaged(u32, ModuleNameTable) = .empty;
    for (entities) |e| {
        const tail = simpleName(e.qualified_name);
        const gop_mod = try per_module.getOrPut(allocator, e.module_id);
        if (!gop_mod.found_existing) gop_mod.value_ptr.* = .{};
        const gop_name = try gop_mod.value_ptr.getOrPut(allocator, tail);
        if (!gop_name.found_existing) gop_name.value_ptr.* = .{};
        try gop_name.value_ptr.append(allocator, e.id);
    }

    // Build alias_qname → resolved target chain by recursively following
    // const_alias edges (which we're computing now). To keep things simple,
    // resolve aliases on-the-fly as a single pass without recursion: a
    // chain like `[sync, lockPair]` first attempts a direct qname match of
    // the full chain, then a per-module-prefix match.

    var const_aliases_out: std.ArrayListUnmanaged(ConstAliasRow) = .empty;
    try const_aliases_out.ensureTotalCapacity(allocator, aliases.len);

    for (aliases) |a| {
        const alias_id = qname_to_id.get(a.alias_qname) orelse continue;
        if (resolveChain(allocator, a.target_chain, a.alias_module_id, &qname_to_id, &module_qnames, &per_module, entities)) |target_id| {
            if (target_id != alias_id) {
                try const_aliases_out.append(allocator, .{ .entity_id = alias_id, .target_entity_id = target_id });
            }
        }
    }

    var type_refs_out: std.ArrayListUnmanaged(TypeRefRow) = .empty;
    try type_refs_out.ensureTotalCapacity(allocator, type_refs_in.len);

    for (type_refs_in) |tr| {
        const referrer_id = qname_to_id.get(tr.referrer_qname) orelse continue;
        if (resolveChain(allocator, tr.target_chain, tr.referrer_module_id, &qname_to_id, &module_qnames, &per_module, entities)) |target_id| {
            if (target_id != referrer_id) {
                try type_refs_out.append(allocator, .{
                    .referrer_entity_id = referrer_id,
                    .referred_entity_id = target_id,
                    .role = tr.role,
                });
            }
        }
    }

    return .{
        .const_aliases = try const_aliases_out.toOwnedSlice(allocator),
        .type_refs = try type_refs_out.toOwnedSlice(allocator),
    };
}

fn simpleName(qname: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, qname, '.')) |i| return qname[i + 1 ..];
    return qname;
}

/// Resolve a chain to an entity_id, or return null if it doesn't resolve.
/// Strategy (in order):
///   1. Direct match: chain joined by '.' equals some entity.qualified_name.
///   2. Module-prefixed: prepend module_qname (looked up via referrer module).
///   3. Suffix match: any entity whose qname ends with ".chain[0].chain[1]..".
///   4. Single-segment: if chain.len == 1, pick the unique entity in
///      `referrer_module_id` whose simple-name equals chain[0].
fn resolveChain(
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    referrer_module_id: u32,
    qname_to_id: *const std.StringHashMapUnmanaged(u32),
    module_qnames: *const std.AutoHashMapUnmanaged(u32, []const u8),
    per_module: *const std.AutoHashMapUnmanaged(u32, ModuleNameTable),
    entities: []const FinalEntity,
) ?u32 {
    if (chain.len == 0) return null;

    // 1. Direct.
    {
        const joined = joinDot(allocator, chain) catch return null;
        defer allocator.free(joined);
        if (qname_to_id.get(joined)) |id| return id;
    }

    // 2. Module-prefixed: prepend the referrer module's qname.
    if (module_qnames.get(referrer_module_id)) |mq| {
        if (mq.len > 0) {
            const joined = joinDotWithPrefix(allocator, mq, chain) catch return null;
            defer allocator.free(joined);
            if (qname_to_id.get(joined)) |id| return id;
        }
    }

    // 3. Single-segment local: if chain has 1 segment, look up in referrer
    //    module's name table.
    if (chain.len == 1) {
        if (per_module.get(referrer_module_id)) |table| {
            if (table.get(chain[0])) |list| {
                if (list.items.len >= 1) return list.items[0];
            }
        }
    }

    // 4. Suffix match: last resort, any qname ending with ".chain.joined".
    //    Used to catch chains like `[sync, lockPair]` where `sync` is a
    //    file's `@import("sync.zig")` alias and the canonical qname for
    //    `lockPair` is `<dir>.<dir>.sync.lockPair`. We accept the first
    //    suffix match; ambiguous chains pick deterministic-by-id.
    {
        const suffix = joinDot(allocator, chain) catch return null;
        defer allocator.free(suffix);
        for (entities) |e| {
            if (e.qualified_name.len < suffix.len + 1) continue;
            const tail_off = e.qualified_name.len - suffix.len;
            if (e.qualified_name[tail_off - 1] != '.') continue;
            if (std.mem.eql(u8, e.qualified_name[tail_off..], suffix)) return e.id;
        }
    }

    // 5. Fuzzy chain-segments-in-order match: `[proc, Process]` matches
    //    `proc.process.Process` because all chain segments appear as
    //    path components in order. Used when `chain[0]` is a file's
    //    `@import("…")` alias the indexer didn't resolve. Prefer the
    //    entity whose qname has the fewest "extra" segments. Retry
    //    by trimming a leading segment so chains like
    //    `[stygia, arch, aarch64, paging]` resolve to `arch.aarch64.paging`
    //    (where `stygia` is a build.zig module pointing at the kernel root).
    var trim: usize = 0;
    while (trim + 1 < chain.len) : (trim += 1) {
        const sub = chain[trim..];
        if (sub.len < 1) break;
        var best: ?u32 = null;
        var best_extra: usize = std.math.maxInt(usize);
        for (entities) |e| {
            const tail = simpleName(e.qualified_name);
            if (!std.mem.eql(u8, tail, sub[sub.len - 1])) continue;

            var seg_iter = std.mem.splitScalar(u8, e.qualified_name, '.');
            var matched: usize = 0;
            var total_segs: usize = 0;
            while (seg_iter.next()) |seg| {
                total_segs += 1;
                if (matched < sub.len - 1 and std.mem.eql(u8, seg, sub[matched])) {
                    matched += 1;
                }
            }
            if (matched != sub.len - 1) continue;

            const extra = total_segs - sub.len;
            if (extra < best_extra) {
                best = e.id;
                best_extra = extra;
            }
        }
        if (best) |id| return id;
    }

    return null;
}

fn joinDot(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts, 0..) |p, i| {
        total += p.len;
        if (i + 1 < parts.len) total += 1;
    }
    const out = try allocator.alloc(u8, total);
    var idx: usize = 0;
    for (parts, 0..) |p, i| {
        @memcpy(out[idx .. idx + p.len], p);
        idx += p.len;
        if (i + 1 < parts.len) {
            out[idx] = '.';
            idx += 1;
        }
    }
    return out;
}

fn joinDotWithPrefix(allocator: std.mem.Allocator, prefix: []const u8, parts: []const []const u8) ![]u8 {
    var total: usize = prefix.len;
    if (parts.len > 0) total += 1; // dot after prefix
    for (parts, 0..) |p, i| {
        total += p.len;
        if (i + 1 < parts.len) total += 1;
    }
    const out = try allocator.alloc(u8, total);
    var idx: usize = 0;
    @memcpy(out[idx .. idx + prefix.len], prefix);
    idx += prefix.len;
    if (parts.len > 0) {
        out[idx] = '.';
        idx += 1;
    }
    for (parts, 0..) |p, i| {
        @memcpy(out[idx .. idx + p.len], p);
        idx += p.len;
        if (i + 1 < parts.len) {
            out[idx] = '.';
            idx += 1;
        }
    }
    return out;
}
