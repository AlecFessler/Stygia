-- Seed test data for callgraph_http. Builds a tiny but plausibly-shaped
-- callgraph DB so every endpoint can return non-empty results
-- before the real indexer is wired up.
--
-- Apply against an empty schema:
--   sqlite3 x86_64-DEADBEEF.db < ../indexer/schema.sql
--   sqlite3 x86_64-DEADBEEF.db < seed.sql
--
-- The `meta('schema_complete','true')` row goes LAST — the server refuses
-- to open a DB without it.

BEGIN;

-- ── files ─────────────────────────────────────────────────────────────────
INSERT INTO file (id, path, sha256, size, source) VALUES
 (1, '/home/alec/Stygia/kernel/syscall/dispatch.zig',
    x'00000000000000000000000000000000000000000000000000000000000000aa',
    280,
    'const std = @import("std");
const stygia = @import("stygia");

const vmm = stygia.memory.vmm;

pub fn sysOpen(path: []const u8) !u32 {
    // dispatch into the VMM
    const page = try vmm.alloc(4096);
    return @intCast(@intFromPtr(page));
}

pub fn boot() void {
    while (true) {
        sysOpen("/init") catch {};
    }
}
'),
 (2, '/home/alec/Stygia/kernel/memory/vmm.zig',
    x'00000000000000000000000000000000000000000000000000000000000000bb',
    180,
    'const std = @import("std");

pub const Page = struct {
    addr: u64,
    size: u32,
};

pub fn alloc(size: u32) ![]u8 {
    if (size == 0) return error.InvalidSize;
    // call into the PMM
    return allocPage(size);
}

fn allocPage(size: u32) ![]u8 {
    _ = size;
    return &.{};
}
');

-- ── modules ───────────────────────────────────────────────────────────────
INSERT INTO module (id, qualified_name, root_file_id) VALUES
 (1, 'syscall.dispatch', 1),
 (2, 'memory.vmm', 2);

-- ── file line index (entry per line start) ────────────────────────────────
-- Computed by hand for the seed; real indexer fills this from \n positions.
INSERT INTO file_line_index (file_id, line, byte_start) VALUES
 (1, 1, 0),
 (1, 2, 23),
 (1, 3, 46),
 (1, 4, 47),
 (1, 5, 73),
 (1, 6, 74),
 (1, 7, 113),
 (1, 8, 144),
 (1, 9, 184),
 (1, 10, 185),
 (1, 11, 186),
 (1, 12, 209),
 (1, 13, 230),
 (1, 14, 263),
 (1, 15, 268),
 (2, 1, 0),
 (2, 2, 23),
 (2, 3, 24),
 (2, 4, 43),
 (2, 5, 58),
 (2, 6, 71),
 (2, 7, 75),
 (2, 8, 76),
 (2, 9, 113),
 (2, 10, 152),
 (2, 11, 178),
 (2, 12, 197),
 (2, 13, 198),
 (2, 14, 226),
 (2, 15, 244);

-- ── entities ──────────────────────────────────────────────────────────────
INSERT INTO entity
 (id, kind, qualified_name, module_id, def_file_id, def_byte_start, def_byte_end,
  def_line, def_col, generic_parent_id, is_ast_only, is_slab_backed)
VALUES
 -- syscall.dispatch.sysOpen — direct caller of vmm.alloc
 (1, 'fn',  'syscall.dispatch.sysOpen', 1, 1, 75, 207, 6, 1, NULL, 0, 0),
 -- syscall.dispatch.boot — boot entry
 (2, 'fn',  'syscall.dispatch.boot',    1, 1, 209, 268, 12, 1, NULL, 0, 0),
 -- memory.vmm.alloc — public allocator
 (3, 'fn',  'memory.vmm.alloc',         2, 2, 76, 196, 8, 1, NULL, 0, 0),
 -- memory.vmm.allocPage — internal helper, ast-only (compiler inlines)
 (4, 'fn',  'memory.vmm.allocPage',     2, 2, 197, 280, 14, 1, NULL, 1, 0),
 -- memory.vmm.Page — type
 (5, 'type','memory.vmm.Page',          2, 2, 24, 75, 3, 1, NULL, 0, 0),
 -- memory.vmm.Frame — alias of Page (for const_alias chain test)
 (6, 'const','memory.vmm.Frame',        2, 2, 73, 74, 5, 1, NULL, 0, 0);

INSERT INTO entity_fts (rowid, qualified_name) VALUES
 (1, 'syscall.dispatch.sysOpen'),
 (2, 'syscall.dispatch.boot'),
 (3, 'memory.vmm.alloc'),
 (4, 'memory.vmm.allocPage'),
 (5, 'memory.vmm.Page'),
 (6, 'memory.vmm.Frame');

-- ── tokens (a handful per file, just enough for source highlights) ────────
INSERT INTO token (file_id, idx, kind, byte_start, byte_len, text, paren_depth, brace_depth) VALUES
 (1, 0, 'keyword',    0, 5, 'const',     0, 0),
 (1, 1, 'keyword',    47, 6, 'pub fn',   0, 0),
 (1, 2, 'identifier', 57, 7, 'sysOpen',  0, 0),
 (1, 3, 'comment',    79, 28, '// dispatch into the VMM', 0, 1),
 (1, 4, 'keyword',    186, 6, 'pub fn',  0, 0),
 (1, 5, 'identifier', 196, 4, 'boot',    0, 0),
 (2, 0, 'keyword',    0, 5, 'const',     0, 0),
 (2, 1, 'keyword',    24, 9, 'pub const',0, 0),
 (2, 2, 'identifier', 34, 4, 'Page',     0, 0),
 (2, 3, 'keyword',    76, 6, 'pub fn',   0, 0),
 (2, 4, 'identifier', 86, 5, 'alloc',    0, 0),
 (2, 5, 'comment',    122, 25, '// call into the PMM', 0, 1);

-- ── AST nodes (one per fn def + one call_expr per ir_call) ─────────────────
INSERT INTO ast_node (id, file_id, parent_id, kind, byte_start, byte_end, entity_id) VALUES
 (10, 1, NULL, 'fn_decl',   75, 207, 1),  -- sysOpen body
 (11, 1, 10,   'block',     115, 207, NULL),
 (12, 1, 11,   'call_expr', 145, 165, NULL),  -- vmm.alloc call site
 (13, 1, NULL, 'fn_decl',   209, 268, 2),  -- boot body
 (14, 1, 13,   'block',     223, 268, NULL),
 (15, 1, 14,   'while',     230, 266, NULL),
 (16, 1, 15,   'call_expr', 245, 261, NULL),  -- sysOpen call site under loop
 (20, 2, NULL, 'fn_decl',   76, 196, 3),  -- alloc body
 (21, 2, 20,   'block',     105, 196, NULL),
 (22, 2, 21,   'if',        110, 152, NULL),
 (23, 2, 21,   'call_expr', 178, 192, NULL), -- allocPage call site
 (24, 2, NULL, 'fn_decl',   197, 280, 4); -- allocPage body

INSERT INTO ast_edge (parent_id, child_id, role) VALUES
 (10, 11, 'body'),
 (11, 12, NULL),
 (13, 14, 'body'),
 (14, 15, NULL),
 (15, 16, 'body'),
 (20, 21, 'body'),
 (21, 22, NULL),
 (21, 23, NULL);

-- ── IR calls (the actual call edges) ──────────────────────────────────────
INSERT INTO ir_call
 (id, caller_entity_id, callee_entity_id, call_kind, resolved_via, confidence,
  ast_node_id, site_line)
VALUES
 (1, 1, 3, 'direct', NULL, NULL, 12, 8),   -- sysOpen → vmm.alloc
 (2, 2, 1, 'direct', NULL, NULL, 16, 14),  -- boot → sysOpen
 (3, 3, 4, 'direct', NULL, NULL, 23, 11);  -- alloc → allocPage

-- ── entry points (one per kind for /api/entries variety) ──────────────────
INSERT INTO entry_point (entity_id, kind, vector, syscall_nr, label) VALUES
 (2, 'boot',    NULL, NULL, 'kernel_main'),
 (1, 'syscall', NULL, 0,    'sys_open');

-- ── precomputed reachability (entry → reachable entity, min_depth) ────────
INSERT INTO entry_reaches (entry_id, entity_id, min_depth) VALUES
 (1, 1, 0),
 (1, 2, 1),
 (1, 3, 2),
 (1, 4, 3),
 (2, 1, 0),
 (2, 3, 1),
 (2, 4, 2);

-- ── types ─────────────────────────────────────────────────────────────────
INSERT INTO type (id, entity_id, kind, size, align) VALUES
 (1, 5, 'struct', 16, 8);

INSERT INTO type_field (type_id, idx, name, offset, type_ref) VALUES
 (1, 0, 'addr', 0, NULL),
 (1, 1, 'size', 8, NULL);

-- ── const alias chain: Frame → Page ───────────────────────────────────────
INSERT INTO const_alias (entity_id, target_entity_id) VALUES
 (6, 5);

-- ── binary (DWARF) layer ──────────────────────────────────────────────────
INSERT INTO bin_symbol (addr, entity_id, size, section) VALUES
 (0xffffffff80100000, 1, 64, '.text'),  -- sysOpen
 (0xffffffff80100040, 2, 32, '.text'),  -- boot
 (0xffffffff80100060, 3, 48, '.text'),  -- alloc
 (0xffffffff80100090, 4, 16, '.text');  -- allocPage

INSERT INTO bin_inst (addr, bytes, mnemonic, operands) VALUES
 (0xffffffff80100000, x'4889e5',     'mov',  'rbp, rsp'),
 (0xffffffff80100003, x'4883ec10',   'sub',  'rsp, 0x10'),
 (0xffffffff80100007, x'be00100000', 'mov',  'esi, 0x1000'),
 (0xffffffff8010000c, x'e84f000000', 'call', '0xffffffff80100060'),  -- call alloc
 (0xffffffff80100011, x'4889ec',     'mov',  'rsp, rbp'),
 (0xffffffff80100014, x'c3',         'ret',  ''),
 (0xffffffff80100040, x'eb00',       'jmp',  '0xffffffff80100042'),
 (0xffffffff80100042, x'e8b9ffffff', 'call', '0xffffffff80100000'),  -- call sysOpen
 (0xffffffff80100047, x'ebf9',       'jmp',  '0xffffffff80100042'),
 (0xffffffff80100060, x'4885f6',     'test', 'esi, esi'),
 (0xffffffff80100063, x'7405',       'je',   '0xffffffff8010006a'),
 (0xffffffff80100065, x'e826000000', 'call', '0xffffffff80100090'),  -- call allocPage
 (0xffffffff8010006a, x'c3',         'ret',  ''),
 (0xffffffff80100090, x'31c0',       'xor',  'eax, eax'),
 (0xffffffff80100092, x'c3',         'ret',  '');

-- DWARF line ranges. addr_lo→addr_hi inclusive, mapped to file:line.
INSERT INTO dwarf_line (addr_lo, addr_hi, file_id, line, col) VALUES
 (0xffffffff80100000, 0xffffffff80100006, 1, 6, 1),
 (0xffffffff80100007, 0xffffffff80100010, 1, 8, 5),
 (0xffffffff80100011, 0xffffffff80100014, 1, 9, 5),
 (0xffffffff80100040, 0xffffffff80100041, 1, 12, 1),
 (0xffffffff80100042, 0xffffffff80100046, 1, 14, 9),
 (0xffffffff80100047, 0xffffffff80100048, 1, 13, 5),
 (0xffffffff80100060, 0xffffffff80100064, 2, 9, 5),
 (0xffffffff80100065, 0xffffffff80100069, 2, 11, 5),
 (0xffffffff8010006a, 0xffffffff8010006a, 2, 12, 1),
 (0xffffffff80100090, 0xffffffff80100092, 2, 16, 5);

-- ── meta (schema_complete LAST so partial DBs are unreadable) ─────────────
INSERT INTO meta (key, value) VALUES
 ('arch',              'x86_64'),
 ('commit_sha',        'deadbeefcafebabe1234567890abcdef00112233'),
 ('built_at',          '2026-04-28T00:00:00Z'),
 ('schema_version',    '1'),
 ('ingest_duration_ms','42'),
 ('total_entities',    '6'),
 ('total_edges',       '3'),
 ('schema_complete',   'true');

COMMIT;
