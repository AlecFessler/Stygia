# callgraph indexer

Builds a SQLite database that captures the full structural state of a kernel
build — tokens, AST, pre-optimization LLVM IR + callgraph, DWARF, disassembly,
kernel-shape axis (entry points, sinks, reachability) — for consumption by
HTTP and MCP frontends and analyzer tools (genlock, dead_code, ...).

One DB file per `(arch, commit_sha)`. Immutable build artifact. Frontends are
thin SQL query translators over a directory of these files.

## Schema

`schema.sql` is the locked source of truth. All consumers (this indexer, the
HTTP server, the MCP server, every analyzer) honor it verbatim.

## Pipeline

```
Stage 0  walk source tree                  → file, file_line_index, module
Stage 1  tokenize per file (parallel)      → token, token_fts                     ╮
Stage 2  parse AST per file (parallel)     → ast_node, ast_edge, entity           ├ parallel
                                             (provisional ids), entity_fts,       │
                                             is_slab_backed, const_alias          ╯
Stage 2.5  single-threaded sync            → resolves entity.id globally; writes
                                             entity rows to DB
Stage 3  LLVM IR + callgraph (pre-opt)     → ir_fn, ir_call (pre-inline edges),   ╮
         + indirect-call resolution           is_ast_only flag                    ├ parallel
Stage 4  DWARF + objdump on final ELF      → bin_symbol, bin_inst,                │
                                             dwarf_line (coalesced),              │
                                             dwarf_die, dwarf_local,              │
                                             type, type_field                     ╯
Stage 5  kernel-shape pass (after 3)       → entry_point, exit_sink,
                                             entry_reaches, entry_sink_path
Stage 5.5  index build                     → CREATE INDEX, populate FTS5
Stage 6  analyzer wave (separate procs)    → lint_finding rows
Stage 7  finalize                          → meta('schema_complete','true')
```

Stages 1+2 parallelize per file via a bounded thread pool.
Stages 3+4 parallelize after 2.5 completes.
Single writer thread holds the SQLite connection; producers ship batched
`WriteJob` records over a bounded channel.

Output is written to `<out>.tmp` and atomically renamed to `<out>` on
successful completion of stage 7. Frontends refuse to open a DB without
`meta('schema_complete','true')`.

## Verification: IR is pre-optimization

Confirmed: `kernel.getEmittedLlvmIr()` emits IR before LLVM's optimizer runs.
- `ModuleID = 'BitcodeBuffer'` header
- ~1900 `define` rows (LLVM's inliner would have eliminated trivial wrappers)
- `pub inline fn` correctly absent (Zig front-end inlines them)
- Callgraph topology preserved through LLVM-eligible inline candidates
