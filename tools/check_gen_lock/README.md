# check_gen_lock (Zig)

Static analyzer for SecureSlab gen-lock coverage on the Stygia microkernel
tree. Port of `tools/check_gen_lock.py` to Zig, backed by
`std.zig.Tokenizer` so the analyzer sees real tokens (strings, comments,
paren depth, brace depth) instead of raw source text.

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
tools/check_gen_lock/zig-out/bin/check_gen_lock --entry createExecutionContext
tools/check_gen_lock/zig-out/bin/check_gen_lock --list-slab-types
tools/check_gen_lock/zig-out/bin/check_gen_lock --list-methods
tools/check_gen_lock/zig-out/bin/check_gen_lock --help
```

Exit status is nonzero if any err-severity findings are emitted.

## Checks performed

1. **Slab-backed type discovery.** Struct definitions that contain
   `_gen_lock: GenLock = .{}` are marked as slab-backed. Discovered
   dynamically; the current spec-v3 tree has 13 slab-backed types
   (CapabilityDomain, ExecutionContext, VAR, Port, PageFrame, Timer,
   DeviceRegion, VirtualMachine, VmNode, PerfmonState, Vm, VCpu,
   PmuState).

5. **IRQ-acquired lock-class discipline.** A separate analyzer pass
   builds a kernel-wide direct call graph, classifies every lock class
   reachable from any IRQ / NMI / async-trap entry as "IRQ-acquired",
   and demands that every acquire site of an IRQ-acquired class either
   (a) lives on a path that's only reachable from a hardware-IRQ entry
   (CPU has masked already), (b) uses an IRQ-saving acquire variant
   (`lockIrqSave`, `lockIrqSaveOrdered`, `lockOrderedIrqSave`,
   `lockWithGenIrqSave`, `lockWithGenIrqSaveOrdered`,
   `lockWithGenOrderedIrqSave`), or (c) is bracketed by a
   `arch.cpu.saveAndDisableInterrupts()` / `restoreInterrupts()` pair
   in the enclosing function body. A pairing checker also flags
   acquire-vs-release flavor mismatches per receiver chain (plain
   `lock()` ↔ `unlock()`; IRQ-saving `lockIrqSave*` ↔
   `unlockIrqRestore`).

2. **Bare-pointer invariant.** Struct fields whose type matches `*T`,
   `?*T`, `[N]*T`, `[]*T` for slab-backed T are violations — slab
   pointers must be `SlabRef(T)`. Exempted: the slab allocator itself
   (`kernel/memory/allocators/{secure_slab,allocators}.zig`).

3. **`.ptr` bypass detection.** `<chain>.<slabref_field>.ptr` extracts
   the raw pointer and skips the gen check. Flagged as an error unless:
   - The access is an identity compare (`ref.ptr == other` / `!=`).
   - A `// self-alive` comment appears on the same line or anywhere in
     the contiguous `//` comment block immediately above.

4. **Per-entry gen-lock bracketing.** For every kernel entry point —
   every `pub fn` in `kernel/syscall/<file>.zig` (excluding the
   dispatch / errors / pmu / syscall re-export files), the
   exception/IRQ handlers in `kernel/arch/{x64,aarch64}/exceptions.zig`,
   and the scheduler tick — the analyzer walks the function body ONCE
   with a fresh ident env. At each call site, it looks up the callee's
   memoized per-param **summary** — the list of (access / lock /
   unlock / defer_unlock) events the callee performs on each of its
   slab-typed params — and folds those events into the caller's
   per-ident event timeline at the real source line of the call.
   Callee-internal locals never enter the caller env; only param-keyed
   effects are visible across the call boundary.

   Each access to a slab-typed local must be:
   - tight-preceded by a `lock(@src())` / `lockWithGen()` on the same
     ident,
   - tight-followed by an `unlock()`, OR a `defer <ident>.unlock()`
     covering the scope exit.
   - Self-alive idents are exempt. A local is self-alive when it
     derives from any of:
     - `scheduler.currentThread()` / `scheduler.currentProc()`
     - a refcount pin (`defer x.releaseRef()` / `.decRef()`)
     - an explicit `// self-alive` comment
     - the spec-v3 syscall caller-cast pattern
       `const ec: *T = @ptrCast(@alignCast(caller))`, where `caller`
       is the entry's first parameter of type `*anyopaque` — the
       kernel ABI hands the syscall handler a pointer to the running
       ExecutionContext, which cannot be reaped during the syscall.

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
handles to the same object can make through their own holding domains.

Out of scope (deliberately): aarch64 (different mnemonics), functions
with mixed Zig and asm, composite-offset field-pinning.

## Spec-v3 conventions baked into the analyzer

- Entry-point discovery treats every `pub fn` in
  `kernel/syscall/<file>.zig` as a syscall handler (with
  `dispatch.zig`, `errors.zig`, `pmu.zig`, and `syscall.zig` excluded
  as non-handler re-exports). Spec-v3 dropped the `sys*` prefix the
  spec-v2 tool relied on.
- The static `FAT_YIELDING_FIELDS` and `DEFAULT_FIELD_CHAINS` tables
  enumerate every `SlabRef(T)` field on a slab-backed struct. When the
  schema changes, re-scan with
  `grep -n 'SlabRef(' kernel/.../<owner>.zig` and update both tables.
- `lock()` matchers accept the spec-v3 `lock(@src())` form (any
  balanced argument list), not just the spec-v2 `lock()` shape.

## Current finding totals

On the current kernel tree the analyzer reports:

- 67 entry points analyzed, 82 tracked slab-typed idents.
- 0 err / 0 info bracketing findings.
- 13 slab-backed types, 0 bare-pointer violations, 0 `.ptr` bypass
  sites.

## Directory layout

```
tools/check_gen_lock/
├── README.md       (this file)
├── build.zig
└── src/
    └── main.zig
```

## CI integration

- `./test.sh pre-commit` runs this tool as a **gating stage**: any
  err-severity finding fails the commit gate. Standalone target:
  `./test.sh genlock`.
- Runs in ~1.7s on the current tree; 0 err / 0 info.
