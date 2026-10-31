# check_gen_lock (Zig)

Static analyzer for SecureSlab gen-lock coverage on the Stygia microkernel
tree. Consumes the per-(arch, commit, working-tree) callgraph DB built by
`tools/indexer`, so it sees real entities, AST nodes, tokens, entry
points and IR call edges instead of raw source text.

(The `tools/check_gen_lock.py` this was originally ported from is long
gone from the tree; so is the `./test.sh` driver older revisions of this
file pointed at. See "CI integration" below for the live gate.)

## Build

From this directory:

```
zig build
```

Produces the binary at `tools/check_gen_lock/zig-out/bin/check_gen_lock`.

## Usage

Run from the repo root (or any subdirectory — the tool walks up to the
kernel/ directory automatically):

```
tools/check_gen_lock/zig-out/bin/check_gen_lock           # full report
tools/check_gen_lock/zig-out/bin/check_gen_lock --summary # one line per entry
tools/check_gen_lock/zig-out/bin/check_gen_lock --entry createThread
tools/check_gen_lock/zig-out/bin/check_gen_lock --list-slab-types
tools/check_gen_lock/zig-out/bin/check_gen_lock --list-methods
tools/check_gen_lock/zig-out/bin/check_gen_lock --help
```

Exit status is nonzero if any err-severity findings are emitted.

## Checks performed

1. **Slab-backed type discovery.** Struct definitions that contain
   `_gen_lock: GenLock = .{}` are marked as slab-backed by the indexer
   (`entity.is_slab_backed`); this tool just reads that column. Fully
   dynamic — the count is whatever the tree currently defines, so it is
   deliberately not enumerated here.

2. **Bare-pointer invariant.** Struct fields whose type matches `*T`,
   `?*T`, `[N]*T`, `[]*T` for slab-backed T are violations — slab
   pointers must be `SlabRef(T)`. Exempted: the slab allocator itself
   (`kernel/memory/allocators/{secure_slab,allocators}.zig`).

3. **`.ptr` bypass detection.** `<chain>.<slabref_field>.ptr` extracts
   the raw pointer and skips the gen check. Flagged as an error unless:
   - The access is an identity compare (`ref.ptr == other` / `!=`).
   - The pointer is used only as an address (`@intFromPtr(ref.ptr)`).
   - A `// caller-pinned` annotation applies (see "Annotation
     adjacency" below). The annotation the code actually looks for is
     `caller-pinned`; earlier revisions of this file documented
     `self-alive`, which appears nowhere in the analyzer.

4. **Per-entry gen-lock bracketing — folded into check 5.** There is no
   separate bracketing pass, and the numbered slot survives only so
   finding names and cross-references keep lining up.

   For the record, because previous revisions of this file described it
   in detail as though it shipped: the legacy analyzer's memoized
   per-param callee **summary** — folding each callee's (access / lock /
   unlock / defer_unlock) events on its slab-typed params into the
   caller's per-ident timeline — is **not implemented**. Neither is
   tight-precede / tight-follow bracketing, nor the "self-alive" ident
   exemption and its derivation rules (`scheduler.currentThread()`,
   refcount pins, `// self-alive` comments, the syscall caller-cast
   pattern). No part of the analyzer matches the string `self-alive`.
   What actually runs is check 5's release-coverage walk, below.

   Entry points come from the DB's `entry_point` table, not from a
   path convention in this tool. The indexer derives `syscall` entries
   from the arms of `syscall.dispatch.dispatch` via IR (the exact
   handler set), falling back to "every fn under `syscall/*.zig`" only
   when built without `--ir`, as the fixture harness is.

   The `catch` / `orelse` branch attached *directly* to an acquire is
   the acquire-FAILED path, so that acquire is not live inside it:
   `GenLock.lockWithGenIrqSaveOrdered` restores interrupts and returns
   `error.StaleHandle` **without** holding the lock, and releasing on
   that path would be an unlock of a lock never taken. The walker
   therefore walks the branch with that one acquire dropped
   (`failureBranchOf` in `src/main.zig`). Scoped deliberately narrowly:
   any *other* lock live across the branch is still reported, and the
   acquire stays live for everything after the branch falls through, so
   `catch {}` followed by an unreleased exit is still a finding.
   Fixtures `13_lock_catch_failure_branch_clean` /
   `14_lock_catch_still_flags_leaks` pin both directions. Without this,
   multi-line `catch { … return; }` acquires read as leaks.

5. **Per-path release coverage.** For every lock acquired in an entry
   body, every reachable control-flow exit (return / `try` error
   propagation / break / continue) between the lock and its release must
   be covered by an explicit unlock, a `defer ref.unlock(...)`, or — for
   error-flavor exits — an `errdefer ref.unlock(...)`. `@panic` and
   `unreachable` impose no obligation.

6. **IRQ-acquired lock-class discipline.** A lock class L is
   "IRQ-acquired" iff some **asynchronous, masked-on-entry** interrupt
   entry transitively reaches an acquire of L. Every acquire of such a
   class must satisfy one of:

   - (a) it is reachable **only** from a masked-on-entry interrupt, so
     the CPU has already masked and there is nothing to save;
   - (b) it uses an IRQ-saving acquire variant (`lockIrqSave`,
     `lockIrqSaveOrdered`, `lockOrderedIrqSave`, `lockWithGenIrqSave`,
     `lockWithGenIrqSaveOrdered`, `lockWithGenOrderedIrqSave`);
   - (c) the enclosing function body brackets it with
     `arch.cpu.saveAndDisableInterrupts()` / `restoreInterrupts()`.

   Acquire sites inside the lock API's own forwarders (an enclosing fn
   whose name is itself an acquire/release method, e.g. `SpinLock.lock`
   delegating to `self.lockOrdered`) are exempt: they are the primitive,
   not a user of it.

   A pairing checker separately flags acquire-vs-release flavor
   mismatches per receiver chain (plain `lock()` ↔ `unlock()`;
   `lockIrqSave*` ↔ `unlockIrqRestore`).

   **Rule (a) is the whole check.** Until this pass it read "reachable
   from an IRQ entry" rather than "only reachable", which made check 6
   very nearly vacuous: a class becomes IRQ-acquired precisely *because*
   some acquire of it is IRQ-reachable, so the test exempted exactly the
   sites that put the class in scope. The live `stack.freelist_lock`
   self-deadlock (timer IRQ → `preempt` → `yieldTo` →
   `finalizeDestroyMarkedDead` → `destroyKernel` → `quarantineSlot`) sat
   inside that hole and the check reported zero violations. Fixtures 15
   and 16 pin both directions.

   **Why asynchronous only.** The remedy this check prescribes is "use
   an IRQ-saving variant", which answers only the asynchronous hazard.
   A synchronous trap (page fault, `#GP`, sync abort) is raised by the
   critical section's own instructions and is not maskable, so demanding
   `lockIrqSave` for a trap-reachable class is advice that cannot fix
   the reported hazard. `trap_sync` reachability is still collected and
   printed in the class listing as context; it just does not on its own
   demand IrqSave.

### Entry seeds and reachability

Entry seeds come from the DB's `entry_point` table — the indexer derives
handlers from `interrupts.registerVector(...)` sites and from `&handler`
operands in `callconv(.naked)` vector tables, so a handler is rooted the
moment it is wired to a vector. The former hardcoded nine-name
`IRQ_ENTRY_DECLS` table is gone.

`entry_point.kind` is coarser than the check needs (`exception` covers
both real sync traps and the aarch64 async IRQ arms), so the *set* comes
from the DB and only the async/sync *classification* uses the handler
name, defaulting to `trap_sync` — which grants no exemption — when
unrecognized.

Reachability is the **union** of `ir_call` edges and source-text call
edges. Each loses calls the other keeps: the IR is emitted after
inlining, and text matching is short-name only. Unioning is conservative
for both questions the check asks ("can an IRQ reach this acquire?" and
"can process context also reach it?"), where a missed edge is a false
negative either way.

Every *resolved* edge is traversed regardless of `resolved_via`;
dropping `ir_generic_erased` or `ir_mono_suffix` edges would be the
analyzer deciding a call it can see does not exist. Instead the weakest
provenance along the path is recorded and printed
(`[IRQ reachability via ir_generic_erased]`) so a human can weigh it.

### Known imprecision (read before triaging a finding)

- **Class identity is the literal receiver text.** `self.lock` conflates
  `PhysicalMemoryManager.lock` with `SecureSlab(T).lock`, and a local
  named `vm_ref` groups with every other `vm_ref`. The kernel already
  declares real lockdep class strings
  (`SpinLock = .{ .class = "stack.freelist_lock" }`, 20 of them); wiring
  those in is the single highest-value follow-up for this check.
- **Generic instantiations are merged by the indexer.**
  `secure_slab.forEachAlive` is one entity carrying the union of every
  visitor's callees, so a path can enter through one instantiation and
  leave through another (`hang_detector.dump → forEachAlive →
  destroyThreadsInProcess` is such a phantom).

Both are over-approximations: they cost false positives, not false
negatives. The next one does not.

- **A registered vector is missing from the seed set.** The indexer
  logs `stage 5a: arch/x64/irq.zig: registerVector handler
  `paging_mod.tlbShootdownHandler` did not resolve` on every build.
  `entry_pass.resolveFn` refuses to guess when a chain is ambiguous —
  correct in itself, a phantom entry point is worse than a missing one —
  but the consequence is that the TLB-shootdown IPI is **not** an IRQ
  seed here. Any lock class reachable only through that handler will not
  be classified IRQ-acquired, which is a false NEGATIVE: silence where a
  deadlock could live. Fixing it belongs in `tools/indexer`'s alias
  expansion, not here. Until then, treat "no finding" on shootdown-only
  paths as "not checked".

### Deferred sites and the both-arches requirement

Check 6 defers any acquire site under `kernel/arch/<other-arch>/` to the
run for the arch that compiles it, and prints the deferred count on the
summary line. That deferral is only sound if BOTH arch DBs are analyzed;
`tests/precommit.sh` stage [0c] therefore invokes the analyzer twice,
once per DB. `--db` is single-valued, so a second `--db` flag would
silently overwrite the first rather than union — do not "simplify" the
stage into one invocation.

## Annotation adjacency (`// caller-pinned`)

Checks 2 and 3 share one walker. An annotation applies when it is on the
site's own line, or in the comment window above it, where the walk:

- searches `//` comment lines for the annotation;
- **steps over blank lines** rather than stopping at them;
- **stops at the first line of real code**, which is what prevents an
  annotation from covering anything but the statement directly beneath
  its block;
- gives up after `ANNOTATION_LOOKBACK_LINES` (32) lines.

The blank-line tolerance is deliberate: the previous walker stopped dead
at the first blank line, so inserting one — or leaving one behind after
deleting a temporary probe line — silently revoked the exemption and
turned the site into an error with no edit to the annotation itself.

32 is calibrated, not guessed: the 93 `caller-pinned` comment
annotations under `kernel/` sit at most 14 lines above the code they
justify. Fixtures 17 and 18 pin the tolerant and the still-rejected
cases.

## Inline-assembly checker (x86_64, fully-naked-asm fns only)

For functions whose entire body is a single `asm volatile (...)`
expression — currently only `syscallEntry` — the regular AST/source
checker can't see what the asm is doing with `cmpxchg` and `andq`
against `_gen_lock`. The asm checker (`src/asm_analyzer.zig`) steps
in for that one case:

- Resolves `std.fmt.comptimePrint("...{[name]d}...", .{ .name = expr })`
  blocks. When `expr` is `@offsetOf(T, "field")`, the placeholder is
  bound to a symbolic reference `T.field`. Composite expressions like
  `@offsetOf(KernelHandle, "ref") + @offsetOf(ErasedSlabRef, "ptr")`
  remain opaque (we trust them but can't pin a field).
- Recognizes `lock cmpxchgq %src, <T._gen_lock>(%base)` followed by
  `je .L<name>` as a CONDITIONAL acquire — the lock is held only on
  the `.L<name>` branch.
- Recognizes `andq $-2, <T._gen_lock>(%base)` as a release.
- For any other access `<T.field>(%base)` against a slab-backed `T`,
  requires that `lock(T at %base)` be currently held.
- Rejects raw numeric offsets `<num>(%base)` when `%base` is currently
  typed as a slab pointer (use `@offsetOf` via `comptimePrint`).
- Walks the asm linearly with per-label state snapshots; jumps to a
  label snapshot the lock state at the jump site, and revisits must
  match.

Findings emitted under rule names `asm_unlocked_field_access`,
`asm_release_without_acquire`, `asm_raw_offset_on_slab`, and
`asm_label_state_mismatch` / `asm_jump_state_mismatch`.

A function can opt out by adding `// asm-genlock: skip` anywhere in
its source (typically a doc comment over the fn). Reach for this only
when there's a documented reason the per-register lock-bracket model
is genuinely too coarse for this fn — NOT as a way to silence findings
that look inconvenient. A flagged unlocked field access on a slab
pointer is almost always a real race against syscalls that other
handles to the same object can make through their own holding processes.

Out of scope (deliberately): aarch64 (different mnemonics), functions
with mixed Zig and asm, composite-offset field-pinning.

## Spec-v3 conventions baked into the analyzer

- Entry points are read from the DB's `entry_point` table, not from a
  path convention here. See check 4 above for how the indexer builds it.
- `DEFAULT_FIELD_CHAINS` maps (owner type, field) pairs that yield a
  slab-typed value. When the schema changes, re-scan with
  `grep -n 'SlabRef(' kernel/.../<owner>.zig` and update it. (There is
  no `FAT_YIELDING_FIELDS` table; earlier revisions of this file named
  one.)
- `lock()` matchers accept the spec-v3 `lock(@src())` form (any
  balanced argument list), not just the spec-v2 `lock()` shape.

## Directory layout

```
tools/check_gen_lock/
├── README.md              (this file)
├── build.zig
├── src/
│   ├── main.zig           checks 1-6 + CLI
│   ├── asm_analyzer.zig   the inline-asm checker
│   └── sqlite.zig         minimal SQLite binding
└── tests/
    ├── run_tests.sh       fixture harness
    └── fixtures/          NN_name.zig (+ optional NN_name.aux.zig)
```

Each fixture declares its expectation on line 1 (`// EXPECT: clean` or
`// EXPECT: errors=N`). The harness materializes it as
`kernel/syscall/<name>.zig`, runs the indexer over a temp tree, and runs
the analyzer against the resulting DB.

A fixture that needs to own an interrupt entry point must put the
handler in a `<name>.aux.zig` sidecar, which the harness materializes
under `kernel/arch/x64/`. Without `--ir` the indexer's syscall-entry
fallback claims every fn under `syscall/*.zig`, and since
`entry_point.entity_id` is the primary key, a `registerVector`-bound
handler in that directory is silently dropped by `INSERT OR IGNORE`.

## CI integration

- `tests/precommit.sh` stage **[0c]** runs this tool as a gating stage:
  it builds the analyzer, runs `tests/run_tests.sh`, then runs the
  full rule set against both x86_64 and aarch64 callgraph DBs. Any
  err-severity finding fails the commit gate.
- Runs in ~1.4s against a prebuilt DB.
- Current finding totals are deliberately not pinned here — they moved
  every time the tree did, and the numbers in this section were stale by
  a wide margin (67 entries / 82 idents / 13 slab types vs. an actual
  75 / 60 / 16). Run the tool.
