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
Stage 5a mechanical interrupt-entry pass     entry_reaches, entry_sink_path
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

## Stage 3: LLVM name → entity resolution

LLVM quotes any global whose name leaves `[A-Za-z0-9._$-]`, escaping inner
bytes as `\XX`. Every monomorphized Zig generic is quoted, because its name
embeds the instantiation argument list:

```
@"memory.allocators.secure_slab.SecureSlab(caps.capability_domain.CapabilityDomain,256).forEachAlive__anon_94571"
```

Resolution walks three steps, most specific first, and records which one hit
in `ir_call.resolved_via`:

| step | `resolved_via` |
|---|---|
| exact qualified-name hit | `NULL` |
| after stripping a `__anon_NNNNN` discriminator | `ir_mono_suffix` |
| after erasing generic instantiation arguments | `ir_generic_erased` |

Erasure maps the monomorphization back to its *declaration* entity — `ast_pass`
flattens the members of a `return struct { … }` generic body into the
enclosing module, so the entity above is `memory.allocators.secure_slab.forEachAlive`.
Every instantiation of a generic therefore collapses onto one entity, which is
what makes a reachability query walk *through* a generic instead of stopping at
it. A segment is only treated as an instantiation when its head (`SecureSlab`)
is itself a known entity in that namespace, so std-library names such as
`array_list.Aligned(T,null).append` cannot mint a phantom edge.

Collapsing every instantiation onto one entity is a deliberate
over-approximation: `SecureSlab(ExecutionContext,256).forEachAlive` and
`SecureSlab(CapabilityDomain,256).forEachAlive` share the single AST entity
`memory.allocators.secure_slab.forEachAlive`, so that entity's callee set is
the union over all instantiations. Reachability answers are therefore sound
(no real path is missing) but not exact. Consumers that need per-
instantiation precision can exclude `resolved_via = 'ir_generic_erased'`;
`ir_fn.ir_name` retains the full decorated name for every monomorphization.

## Stage 5a: interrupt-entry discovery

`entry_point` used to be populated purely from a name list in a SQL `LIKE`
chain, which knew 3 of the 10 live x86-64 interrupt entries. Discovery is now
derived from the two places the kernel actually binds a vector to a Zig
function:

* `interrupts.registerVector(vec, handler, .external | .exception)` — the
  x86-64 IDT. Dispatch itself is an indirect call through `vector_table[]`,
  so the registration call is the only static vector→handler link.
* `&handler` bound as an inline-asm operand inside a `callconv(.naked)`
  function — the aarch64 exception vector table.

Handler arguments are resolved through Stygia's file-local alias style
(`const paging_mod = stygia.arch.x64.paging;`). A handler argument that does
not resolve to a unique function entity is logged as a warning rather than
guessed — a phantom entry point is worse than a named gap. The rows merge with
`INSERT OR IGNORE` after the legacy name-based inserts, so an entity found by
both keeps its existing kind and label.

Known limitation: an alias bound through `@import("rel/path.zig")` rather than
through the root-module chain is not expanded.

## Tests

`bash tests/run_tests.sh` runs the fixture suite (`tests/fixtures/<NN_name>/`:
a `kernel/` tree, an optional `ir.ll`, a `checks.sql` and its `expected.txt`).
`BLESS=1` regenerates expectations after an intentional change.

## Verification: IR is pre-optimization

Confirmed: `kernel.getEmittedLlvmIr()` emits IR before LLVM's optimizer runs.
- `ModuleID = 'BitcodeBuffer'` header
- ~1900 `define` rows (LLVM's inliner would have eliminated trivial wrappers)
- `pub inline fn` correctly absent (Zig front-end inlines them)
- Callgraph topology preserved through LLVM-eligible inline candidates
