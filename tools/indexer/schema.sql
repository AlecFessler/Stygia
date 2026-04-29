-- ============================================================================
-- callgraph DB schema
-- One file per (arch, commit_sha). Immutable build artifact, no migrations.
-- Built by the kernel build pipeline; consumed by HTTP/MCP frontends and
-- analyzer tools (genlock, dead_code, ...) that write findings into
-- lint_finding.
-- ============================================================================

-- Pragmas: pick a balance of write throughput and on-disk durability.
-- Frontends should set their own read-side pragmas.
PRAGMA journal_mode  = WAL;
PRAGMA synchronous   = NORMAL;
PRAGMA temp_store    = MEMORY;
PRAGMA page_size     = 8192;
PRAGMA cache_size    = -262144;  -- 256MB

-- ── BUILD METADATA ─────────────────────────────────────────────────────────
-- expected keys: arch, commit_sha, built_at, schema_version,
-- ingest_duration_ms, total_entities, total_edges, schema_complete
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ── IDENTITY LAYER ─────────────────────────────────────────────────────────
CREATE TABLE file (
    id     INTEGER PRIMARY KEY,
    path   TEXT NOT NULL UNIQUE,
    sha256 BLOB NOT NULL,
    size   INTEGER NOT NULL,
    source BLOB NOT NULL              -- full file bytes inline; BLOB so substr/length operate on bytes (TEXT would treat as UTF-8 chars)
);

CREATE TABLE file_line_index (
    file_id    INTEGER NOT NULL REFERENCES file(id),
    line       INTEGER NOT NULL,      -- 1-indexed
    byte_start INTEGER NOT NULL,
    PRIMARY KEY (file_id, line)
);
-- byte→line lookup:
--   SELECT line FROM file_line_index
--   WHERE file_id = ? AND byte_start <= ?
--   ORDER BY byte_start DESC LIMIT 1;

CREATE TABLE module (
    id             INTEGER PRIMARY KEY,
    qualified_name TEXT NOT NULL UNIQUE,
    root_file_id   INTEGER NOT NULL REFERENCES file(id)
);

CREATE TABLE entity (
    id                INTEGER PRIMARY KEY,
    kind              TEXT NOT NULL,           -- fn | type | const | var | field | namespace
    qualified_name    TEXT NOT NULL,
    module_id         INTEGER NOT NULL REFERENCES module(id),
    def_file_id       INTEGER NOT NULL REFERENCES file(id),
    def_byte_start    INTEGER NOT NULL,
    def_byte_end      INTEGER NOT NULL,
    def_line          INTEGER NOT NULL,        -- materialized at index time
    def_col           INTEGER NOT NULL,
    generic_parent_id INTEGER REFERENCES entity(id),       -- NULL for non-monomorphized
    is_ast_only       INTEGER NOT NULL DEFAULT 0,          -- LLVM/front-end inlined every callsite
    is_slab_backed    INTEGER NOT NULL DEFAULT 0,          -- struct contains _gen_lock: GenLock
    is_pub            INTEGER NOT NULL DEFAULT 0,          -- top-level `pub` visibility
    UNIQUE (module_id, kind, qualified_name)
);
CREATE INDEX entity_qname_idx          ON entity(qualified_name);
CREATE INDEX entity_module_idx         ON entity(module_id);
CREATE INDEX entity_generic_parent_idx ON entity(generic_parent_id) WHERE generic_parent_id IS NOT NULL;

-- FTS5 over qualified names for `find` tool.
CREATE VIRTUAL TABLE entity_fts USING fts5(
    qualified_name,
    content='entity', content_rowid='id'
);

-- ── STAGE 1: TOKENS ────────────────────────────────────────────────────────
CREATE TABLE token (
    file_id     INTEGER NOT NULL REFERENCES file(id),
    idx         INTEGER NOT NULL,
    kind        TEXT NOT NULL,                  -- keyword | identifier | string | comment | ...
    byte_start  INTEGER NOT NULL,
    byte_len    INTEGER NOT NULL,
    text        TEXT NOT NULL,
    paren_depth INTEGER NOT NULL,               -- precomputed for analyzers
    brace_depth INTEGER NOT NULL,
    PRIMARY KEY (file_id, idx)
);
CREATE INDEX token_byte_idx ON token(file_id, byte_start);

CREATE VIRTUAL TABLE token_fts USING fts5(
    text, kind UNINDEXED,
    content='token'
);

-- ── STAGE 2: AST ───────────────────────────────────────────────────────────
CREATE TABLE ast_node (
    id         INTEGER PRIMARY KEY,
    file_id    INTEGER NOT NULL REFERENCES file(id),
    parent_id  INTEGER REFERENCES ast_node(id),
    kind       TEXT NOT NULL,                   -- fn_decl | call_expr | if | else | while
                                                -- | for | switch_prong | block | ...
    byte_start INTEGER NOT NULL,
    byte_end   INTEGER NOT NULL,
    entity_id  INTEGER REFERENCES entity(id)    -- non-NULL on definition nodes
);
CREATE INDEX ast_node_entity_idx ON ast_node(entity_id) WHERE entity_id IS NOT NULL;
CREATE INDEX ast_node_parent_idx ON ast_node(parent_id);
CREATE INDEX ast_node_byte_idx   ON ast_node(file_id, byte_start);

CREATE TABLE ast_edge (
    parent_id INTEGER NOT NULL REFERENCES ast_node(id),
    child_id  INTEGER NOT NULL REFERENCES ast_node(id),
    role      TEXT,                              -- "condition" | "then" | "else" | "body" | NULL
    PRIMARY KEY (parent_id, child_id)
);

-- ── STAGE 3: LLVM IR / CALLGRAPH (pre-optimization capture) ────────────────
CREATE TABLE ir_fn (
    entity_id INTEGER PRIMARY KEY REFERENCES entity(id),
    ir_name   TEXT NOT NULL,
    attrs     TEXT,
    blob_id   INTEGER REFERENCES blob(id)
);

CREATE TABLE ir_call (
    id               INTEGER PRIMARY KEY,
    caller_entity_id INTEGER NOT NULL REFERENCES entity(id),
    callee_entity_id INTEGER REFERENCES entity(id),  -- NULL for unresolved indirect
    call_kind        TEXT NOT NULL,                  -- direct | dispatch_x64 | dispatch_aarch64
                                                     -- | vtable | indirect | intrinsic | inline
                                                     -- | leaf_userspace
    resolved_via     TEXT,                           -- "dispatch_table:syscall_table"
                                                     -- | "ast_fnptr" | "all_callers_agree"
                                                     -- | "receiver_chain" | NULL for direct
    confidence       INTEGER,                        -- 0-100 for resolved indirects; NULL otherwise
    ast_node_id      INTEGER REFERENCES ast_node(id),
    site_line        INTEGER NOT NULL                -- materialized for fast `callers` rendering
);
CREATE INDEX ir_call_callee_idx ON ir_call(callee_entity_id) WHERE callee_entity_id IS NOT NULL;
CREATE INDEX ir_call_caller_idx ON ir_call(caller_entity_id);
CREATE INDEX ir_call_site_idx   ON ir_call(ast_node_id);

-- ── STAGE 4: DWARF + BINARY ────────────────────────────────────────────────
CREATE TABLE bin_symbol (
    addr      INTEGER PRIMARY KEY,
    entity_id INTEGER NOT NULL REFERENCES entity(id),
    size      INTEGER NOT NULL,
    section   TEXT NOT NULL
);
CREATE INDEX bin_symbol_entity_idx ON bin_symbol(entity_id);

CREATE TABLE bin_inst (
    addr     INTEGER PRIMARY KEY,
    bytes    BLOB NOT NULL,
    mnemonic TEXT NOT NULL,
    operands TEXT NOT NULL
);

-- COALESCED RANGES, not per-PC entries.
CREATE TABLE dwarf_line (
    addr_lo INTEGER PRIMARY KEY,
    addr_hi INTEGER NOT NULL,                     -- inclusive
    file_id INTEGER NOT NULL REFERENCES file(id),
    line    INTEGER NOT NULL,
    col     INTEGER
);
CREATE INDEX dwarf_line_file_idx ON dwarf_line(file_id, line);

CREATE TABLE dwarf_die (
    offset        INTEGER PRIMARY KEY,
    entity_id     INTEGER NOT NULL REFERENCES entity(id),
    tag           TEXT NOT NULL,
    parent_offset INTEGER
);

CREATE TABLE dwarf_local (
    entity_id     INTEGER NOT NULL REFERENCES entity(id),
    name          TEXT NOT NULL,
    type_ref      INTEGER REFERENCES type(id),
    location_expr BLOB
);

-- ── KERNEL-SHAPE AXIS ──────────────────────────────────────────────────────
CREATE TABLE entry_point (
    entity_id  INTEGER PRIMARY KEY REFERENCES entity(id),
    kind       TEXT NOT NULL,                     -- boot | syscall | trap | exception | irq | timer | ipi
    vector     INTEGER,                           -- IDT vector
    syscall_nr INTEGER,
    label      TEXT NOT NULL                      -- "page_fault", "sys_send"
);
CREATE INDEX entry_point_kind_idx ON entry_point(kind);

CREATE TABLE exit_sink (
    entity_id INTEGER PRIMARY KEY REFERENCES entity(id),
    kind      TEXT NOT NULL                       -- iret | sysret | hlt | panic | reschedule | vmlaunch | vmresume
);

-- Precomputed forward reachability from each entry, edge-kind-filtered to
-- {direct, dispatch_x64, dispatch_aarch64} only — same filter the live tool uses.
CREATE TABLE entry_reaches (
    entry_id  INTEGER NOT NULL REFERENCES entity(id),
    entity_id INTEGER NOT NULL REFERENCES entity(id),
    min_depth INTEGER NOT NULL,
    PRIMARY KEY (entry_id, entity_id)
);
CREATE INDEX entry_reaches_entity_idx ON entry_reaches(entity_id);

CREATE TABLE entry_sink_path (
    entry_id  INTEGER NOT NULL REFERENCES entity(id),
    sink_id   INTEGER NOT NULL REFERENCES entity(id),
    path_blob BLOB,                               -- representative entity_id chain (varint-packed)
    PRIMARY KEY (entry_id, sink_id)
);

-- ── TYPE SYSTEM ────────────────────────────────────────────────────────────
CREATE TABLE type (
    id        INTEGER PRIMARY KEY,
    entity_id INTEGER REFERENCES entity(id),     -- NULL for anonymous types
    kind      TEXT NOT NULL,                      -- struct | union | enum | array | pointer | primitive | ...
    size      INTEGER,
    align     INTEGER
);

CREATE TABLE type_field (
    type_id  INTEGER NOT NULL REFERENCES type(id),
    idx      INTEGER NOT NULL,
    name     TEXT NOT NULL,
    offset   INTEGER,
    type_ref INTEGER REFERENCES type(id),
    PRIMARY KEY (type_id, idx)
);

-- `pub const X = a.b.C;` resolved at index time; recursive CTE for `type` tool's alias chain.
CREATE TABLE const_alias (
    entity_id        INTEGER PRIMARY KEY REFERENCES entity(id),
    target_entity_id INTEGER NOT NULL REFERENCES entity(id)
);

-- Resolved type-expression references: `struct { x: Bar }`, `fn f(p: Foo) Baz`, etc.
-- Populated for chain-shaped type expressions whose terminal qname resolves to a known entity.
-- Used by the dead-code analyzer to track type uses without leaning on the loose name-heuristic.
CREATE TABLE entity_type_ref (
    referrer_entity_id INTEGER NOT NULL REFERENCES entity(id),
    referred_entity_id INTEGER NOT NULL REFERENCES entity(id),
    role TEXT NOT NULL,  -- 'field_type' | 'param_type' | 'return_type'
    PRIMARY KEY (referrer_entity_id, referred_entity_id, role)
);
CREATE INDEX entity_type_ref_referred_idx ON entity_type_ref(referred_entity_id);

-- ── ANALYZER FINDINGS (write-back surface for genlock, dead_code, redteam, …) ──
CREATE TABLE lint_finding (
    id         INTEGER PRIMARY KEY,
    analyzer   TEXT NOT NULL,                     -- "genlock" | "dead_code" | ...
    severity   TEXT NOT NULL,                     -- "err" | "warn" | "info" | "analyzer_error"
    rule       TEXT NOT NULL,                     -- "bare_pointer_field" | "ptr_bypass" | ...
    entity_id  INTEGER REFERENCES entity(id),    -- NULL for file-level findings
    file_id    INTEGER NOT NULL REFERENCES file(id),
    byte_start INTEGER NOT NULL,
    byte_end   INTEGER NOT NULL,
    line       INTEGER NOT NULL,
    message    TEXT NOT NULL,
    extra_json TEXT
);
CREATE INDEX lint_finding_entity_idx   ON lint_finding(entity_id);
CREATE INDEX lint_finding_file_idx     ON lint_finding(file_id);
CREATE INDEX lint_finding_analyzer_idx ON lint_finding(analyzer);

-- ── BLOB STORE ─────────────────────────────────────────────────────────────
CREATE TABLE blob (
    id    INTEGER PRIMARY KEY,
    kind  TEXT NOT NULL,                          -- "ir_fn_body" | "ast_subtree" | "graph_json" | ...
    bytes BLOB NOT NULL
);
