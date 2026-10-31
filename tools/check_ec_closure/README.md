# check_ec_closure

Static analyzer over the per-(arch, commit_sha) callgraph DB that mechanically
computes two closures `docs/kernel/systems.md` has been maintaining by hand.

```
zig build                       # needs Zig 0.15.2 + system libsqlite3
zig-out/bin/check_ec_closure \
    --db tools/callgraph_http/test/dbs/x86_64-<sha>.db \
    --db tools/callgraph_http/test/dbs/aarch64-<sha>.db
bash tests/run_tests.sh         # fixture suite
```

## Why it exists

The EC-lifecycle design doc went through four adversarial review rounds and
contains three enumeration tables. The one derived from the callgraph DB
survived a hostile independent re-derivation with zero rows missing. The two
closed from human recall held every critical finding of the final round —
same author, same care, same day. The only variable was whether a tool did
the enumeration. This makes that tool-closure permanent.

## Rule A — interrupt-context wake-source closure

Every function reachable from an interrupt/exception entry point that can
wake or claim an execution context.

**Seeds** (interrupt entry points) come from the union of three mechanical
sources, so that no single one silently going stale shrinks the answer:

| source | what it is |
|---|---|
| `entry_point` | the indexer's curated `kind IN (exception, irq, trap, ipi, timer)` rows |
| `vector_table` | the 2nd argument of every `interrupts.registerVector(vec, handler, kind)` call — the x86-64 IDT. The dispatch itself is an indirect call through `vector_table[]`, which no callgraph can resolve, so this is the only mechanical vector→handler link |
| `naked_asm` | `&handler` bound as an inline-asm operand inside a `callconv(.naked)` function — the aarch64 exception vector table |

The DB's own `entry_point` table is **not** sufficient on its own: it misses
`deviceIrqHandler`, the TLB-shootdown / FPU-flush
IPI vectors and `spuriousHandler`, because it discovers handlers by name from
a fixed list.

Each seed is tagged `async` (device / IPI / timer — the CPU masked IRQs on
entry) or `sync` (fault / trap — runs on top of whatever IRQ discipline the
interrupted code chose). This is the same line `dispatchInterrupt` draws when
it decides whether to call `sync_debug.enterIrqContext()`. It matters: on
aarch64 the SVC syscall arrives through `handleSyncLowerEl`, so a closure
that does not separate the two hands you the whole syscall surface as an
"interrupt-context wake source".

**Primitives** are the EC claim funnels, in two tiers:

* `claim` — `sched.execution_context.tryClaimWake`, the single cmpxchg that
  transfers ownership of a waiting EC to the waker. Every genuine wake routes
  through it.
* `enqueue` — `sched.scheduler.enqueue` / `enqueueOnCore`. Strictly broader:
  also covers re-enqueue of an already-owned EC, which is a run-queue
  mutation from interrupt context but not a wake.

A primitive name that fails to resolve to a function entity is an
`analyzer_error` and exits 2. A rename must break the tool loudly.

**Wake sources** are the arch → generic frontier of `fwd(seeds) ∩
bwd(primitives)`: functions in the closure that live outside `kernel/arch/`
and are called directly by arch code that is also in the closure. That is
"the first thing the ISR plumbing hands control to that can wake an EC" —
the granularity a hand-written table uses.

Deliberately *not* "the first non-arch node on a shortest witness path": a
claim site reachable from several ISRs would then be attributed to whichever
path happened to be shortest and the other sources would silently vanish.
That bug hid the timer-wheel source behind the device-IRQ source on the first
run of this analyzer.

The report also lists **wake-free** entries — the negative half of the answer,
and the half a hand derivation is most likely to get wrong.

## Rule B — lock-class IRQ-masking closure

Every `SpinLock` instance in this kernel is declared with an explicit
`.class = "…"` label (what the lockdep / stuck-lock wait table in
`utils/sync/debug.zig` keys on), which gives each lock a stable static
identity. For each class, every acquire site is classified

* MASKED — `lockIrqSave` / `lockIrqSaveOrdered`
* PLAIN — `lock` / `lockOrdered` / `tryLock`

and crossed with the contexts the acquiring function is reachable from:
`ec` (syscall/boot), `async-irq` (device / IPI / timer) and `sync-exc`
(fault / trap). A class with PLAIN acquires on EC-context paths can be
preempted while held.

The `ec` × `async-irq` intersection is called out separately as
`SELF-DEADLOCK RISK`: a plain acquire means IRQs stay enabled for the hold,
and if an asynchronous handler on the same core also takes that class, the
interrupt lands mid-critical-section and spins on a lock the interrupted code
is holding. A *synchronous* exception cannot do that — it only fires because
the running code faulted, and the handler is a continuation of that same EC —
which is why the two are not merged.

The tool does **not** model IRQ state flowing across call boundaries, so
`SELF-DEADLOCK RISK` marks a hazard *shape*, not a proof. A plain acquire is
still safe if every caller happens to have masked IRQs already (the
`ec_create` path does exactly that: `allocSlot`'s plain `freelist_lock.lock()`
runs under the caller's `cd_ref.lockIrqSave`). Turning the shape into a
verdict needs an IRQ-state flow analysis — a natural Rule C, not attempted
here.

Receiver attribution handles the three forms the kernel actually uses: a bare
or dotted name (`tree_mutex`, `stygia.caps.derivation.tree_mutex`), a field
(`self.lock`, `bucket.lock`), and the two per-core-array alias forms
(`const lock = &core_locks[core];` and `for (&core_locks) |*lock|`). Anything
that does not resolve to a declared class is counted and listed under
UNRESOLVED, so the blind spot is visible rather than assumed empty; on the
current tree that list is entirely `GenLock`/`SlabRef` acquires, which have
no static class identity and are `tools/check_gen_lock`'s subject.

Scope is `kernel/` + `bootloader/`. The indexer's extra source roots pull in
userspace trees with their own unrelated `SpinLock` types —
`libz/libc/src/heap/spin_lock.zig` ships a stub whose `lock()` body is empty
— and reporting those as kernel preemption hazards would be noise.

## The call graph is repaired before either rule runs

`ir_call` alone is **not** a sound base for a closure claim. The indexer maps
LLVM IR callee names back to entities by exact name, and Zig's monomorphized
generics carry decorated IR names —
`…SecureSlab(caps.capability_domain.CapabilityDomain,256).forEachAlive__anon_94571`
— that never match an entity row. Every call *through* a generic is silently
absent. On today's tree the timer-wheel wake source

```
wheelExpireDue → onFire → propagateAndWake
               → [SecureSlab(CapabilityDomain,256).forEachAlive]   ← IR edge missing
               → propagateField0Visitor → propagateVisit → futex.wake
```

is completely invisible in the raw `ir_call` graph. A tool built on `ir_call`
alone reports four wake sources and looks authoritative doing it.

So the analyzer overlays a *syntactic* call graph derived from the token
stream: every identifier chain inside a function body that resolves
unambiguously to a function entity becomes an edge, whether it is
syntactically a call (`syn-call`) or a bare function reference (`syn-ref`, an
address-taken callback — exactly what jumps the `forEachAlive` gap).
Ambiguity always resolves to *no* edge; a guess would produce phantom wake
paths, which is worse than a missing one you can name. Every reported edge
carries its provenance so a human can audit it.

The overlay also lets both rules work on DBs built without `--ir` at all,
which is what the fixture harness produces — and what makes fixture 03 a real
test of the callback repair rather than a tautology.

## Known limits

* Reachability is over the *static* call graph. A function reachable from an
  ISR seed is not necessarily reachable on every dynamic path; runtime guards
  (`if (is_vcpu)`, mode checks) are not modelled. The tool answers "can this
  ISR reach a wake", not "does it always".
* Each DB carries IR for one arch. Seeds under the other arch's directory are
  dropped, so per-DB output is a per-arch answer; pass both DBs for the union.
* Rule B's `[unreachable]` context tag means the static graph reaches the
  acquiring function from no entry point — usually because its only call
  sites are inside monomorphized generics. Context is then *unproven*, not
  proven-safe, and the verdict says so.

## Exit codes

| code | meaning |
|---|---|
| 0 | ran successfully (report mode) |
| 1 | `--strict` and at least one class has plain EC-context acquires |
| 2 | analyzer error — unresolvable primitive, DB open/schema failure |

`--write` persists findings to `lint_finding` under `analyzer='ec_closure'`
(`rule='irq_wake_source'` / `rule='plain_lock_acquire'`) so the callgraph MCP
`findings` tool can serve them.

This tool is **not** wired into `tests/precommit.sh`. See the report that
accompanied its introduction for the suggested gating shape.
