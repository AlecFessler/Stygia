# Open design questions

Three items surfaced by the July 2026 stability campaign that are **not**
straightforward bugs. Each one is either spec-conformant behaviour with a bad
shape, or a fix whose correct form is a policy choice. They are parked here
rather than patched, because guessing at the answer would bake a decision into
the kernel or the test suite without anyone having made it.

None of these block the suite today. All three were found while chasing
`stygia-ojs`, and the first is its actual root cause.

---

## 1. `stygia-zzy` (P1) — priority is unreachable from the userspace cap struct

`create_execution_context` reads the new EC's scheduling priority from `[1]`
bits 32-33 (`CREATE_EC_PRIORITY_SHIFT = 32`, `kernel/syscall/execution_context.zig`).
But `libz/caps.zig`'s `EcCap` is a `packed struct(u16)`. `EcCap.toU16()` cannot
physically reach bits 32-33, so the natural call

```zig
const w = caps.EcCap{ .term = true, .susp = true, .bind = true };
syscall.createExecutionContext(@as(u64, w.toU16()), entry, 1, 0, 0)
```

silently requests priority `0` = `Priority.idle`, the **lowest** of four bands.
No diagnostic, and on an idle machine the EC runs immediately — so the mistake
is invisible under light load and only bites under contention.

The kernel is conformant: spec §[create_execution_context] test 13 says "on
success, the EC's priority is set to `[1].priority`", and priority 0 is a legal
request. This is an API-shape problem: the dangerous default is the easy one.

**It was the root cause of `stygia-ojs`.** `map_pf_12`'s worker EC was created
at `idle` while the test EC waiting on it runs at `.normal`. Combined with
strict-priority dispatch (no aging) and item 2 below, the worker never executed
a single instruction inside a 30 s window — ~82% of reps at `-Dbatch=16`, and
100% pass in isolation.

### Decision needed

Pick a remedy:

1. **Typed libz helper** — e.g. `createExecutionContextAt(caps, priority, ...)`,
   or an `EcCreateArgs` struct, so priority cannot be omitted by accident.
   Most explicit; touches every call site.
2. **Widen the userspace cap word** to a struct that carries the priority field,
   so `EcCap.toU16()` stops being the natural thing to pass where a `u64` is
   expected.
3. **Document only** — note at the syscall wrapper that a bare `EcCap` requests
   `Priority.idle`. Cheapest, leaves the footgun armed.

### Knock-on: 13 latently starvable tests

98 test cases call `createExecutionContext`. 17 use an `atomicLoad` spin
handshake, i.e. the worker **must** actually run for the test to progress. 13 of
those pass no explicit priority:

```
recv_05  recv_10  recv_16  suspend_08  suspend_10  suspend_11  reply_07
clear_event_route_06  handle_attachments_10  futex_wake_04
futex_wait_val_08  terminate_04  yield_03
```

These are very likely the shared root cause of the residual intermittent MISS
family, which has historically been chased as several separate scheduler bugs.

They were **deliberately left untouched**. Most reference priority semantically
(`futex_wake_04` and `futex_wait_val_08` test priority-ordered wake; `suspend_11`
mentions priority four times), so a blanket "OR in `1 << 32`" sweep could change
what they assert. Whether to fix these per-test or at the API level is the same
question as the choice above — resolve it there first.

`map_pf_12` **was** fixed, because it had a measured failure and its worker is
pure scaffolding with no priority semantics under test.

---

## 2. `stygia-yxj` (P2) — `affinity = 0` pins an EC to the creating core for life

Spec §[affinity]: "`[2] new_affinity`: 64-bit core mask. **0 = kernel picks any
core**", and §[create_capability_domain] test 31: "affinity equal to `[5]`
(any-core when 0)". So `affinity = 0` means the EC is *eligible for every core*.

What the kernel does:

```zig
fn pickCoreForAffinity(affinity: u64) u8 {
    if (affinity == 0) return @truncate(arch.smp.coreID());
    return @truncate(@as(u64, @ctz(affinity)));
}
```

"Any core" resolves to "whichever core happens to be running the creator". That
is defensible as an *initial* placement, but:

1. There is no work stealing anywhere in `kernel/sched/scheduler.zig`.
2. The preemption re-enqueue (`scheduler.zig:673`) re-picks with
   `pickCoreForAffinity(cur.affinity)` — for `affinity = 0`, the current core
   again.

So the arbitrary initial choice is **permanent**. An `affinity = 0` EC is pinned
for life to whichever core created it, despite being eligible for all of them.

Combined with strict priority and no aging, a low-priority `affinity = 0` EC on
a busy core never runs *even when three of four cores are idle*. That is the
amplifier that made `stygia-ojs` fatal rather than merely slow.

Not filed as a spec violation — the kernel did "pick a core".

### Decision needed

Which shape:

1. Resolve `affinity = 0` to the **least-loaded** core at enqueue.
2. **Re-evaluate placement on re-enqueue** rather than only at creation.
3. Add **work stealing** for ECs whose affinity mask permits more than one core.

(1) is the smallest change and fixes the common case. (3) is the general fix and
the largest. (2) interacts with cache locality and with the `last_dispatched_core`
/ `on_cpu` invariants that `stygia-3ys` and item 3 depend on — treat it as the
risky one.

### Blast radius: the entire test suite runs on one core

This is bigger than "an unlucky EC can starve". Following the affinity-0 path all
the way through shows the whole 485-test suite executes its test ECs on a single
core, for the entire run.

The chain, all four links verified in source:

1. **The runner spawns every test with `initial_ec_affinity = 0`** —
   `tests/suite/runner/primary.zig:618-625`. Per-core ECs with pinned affinity
   are explicitly *deferred future work* in that file's own header
   (`primary.zig:19-26`).
2. **`affinity = 0` enqueues the child on the calling core** —
   `kernel/caps/capability_domain.zig:531-539`:
   `if (initial_ec_affinity == 0) break :blk calling_core;`
   The runner is a single EC, so "the calling core" is always the same core.
3. **Re-enqueue on preemption picks the current core again** —
   `scheduler.zig:617-620` computes `local_allowed = cur.affinity == 0 or ...`,
   which is unconditionally true for `affinity == 0`, so the EC goes back on the
   core it just ran on.
4. **Nothing else ever moves it.** The scheduler says so directly at
   `scheduler.zig:612`: *"there is no other migration trigger — `setAffinity`
   writes the mask without repositioning, and `preempt` re-enters this same
   path"*. There is no work stealing and no pull path; the only
   `migrate`-shaped function in the file, `migrateFlush`, is an FPU-state
   helper.

Tests create their worker ECs from the test EC, also with affinity 0, so those
land on the same core too. Net effect: on a 4-core target, test workloads use one
core and three sit idle.

Two consequences worth separating:

- **Correctness/robustness.** This is the amplifier behind the whole starvation
  family (`stygia-zzy`, `stygia-ojs`, `stygia-yj0`) and the leading mechanism for
  `stygia-9tt`, where all 16 ECs of one batch went MISS together. Sixteen ECs
  starving *simultaneously* is a single-core queueing phenomenon, not sixteen
  independent accidents.
- **Coverage.** The primary validation loop structurally cannot exercise
  cross-core scheduling of test ECs. Any bug that needs two test ECs on two
  different cores is invisible to it. That is a blind spot in the main gate, and
  it is worth knowing before reading "485/485" as broad multi-core assurance.

It also explains the latency numbers measured for `stygia-dk6`: 16-29 ms for an
always-runnable EC and up to ~70 ms for a freshly-woken one are what
single-core queueing with ~16 resident ECs looks like, not what a 4-core box
should produce.

One stale comment was corrected while establishing this:
`capability_domain.zig` claimed "The scheduler's pull path can still migrate it
later" next to the affinity-0 enqueue. There is no pull path; the comment
described a mechanism that does not exist and made the pinning look temporary.

Note this cuts both ways for remedy (3) above: adding work stealing would change
the suite from single-core to genuinely concurrent, which is the point — but it
would also expose the suite to cross-core races it has never run against, so
expect new failures that are pre-existing bugs rather than regressions.

---

## 3. `stygia-5pw` (P2) — self-park clears `on_cpu` while still on the EC's kstack

**Found by inspection. No failure evidence yet** — recorded so it is not lost.

The self-park paths clear `ec.on_cpu = false` while the core is still executing
on that EC's kernel stack, then run a long path on it.

aarch64 `wf_trapped` arm (`arch/aarch64/exceptions.zig` ~689):

```zig
ctx.elr_el1 += 4;
parkIdleWait(ec_ptr);      // .idle_wait, on_cpu = false, clears current_ec
cpu.enableInterrupts();
scheduler.run();           // <-- still on ec's kstack
```

`execution_context.parkIdleWait` clears `on_cpu` at ~691; `port.zig`
`suspendOnPort` does the same at ~589 and returns into the syscall path, which
likewise reaches `scheduler.run()` on the caller's kstack.

`on_cpu = false` is precisely the signal `finalizeDestroyMarkedDead` uses to
decide a zombie's kernel stack is no longer in use — the `stygia-3ys` gate,
which only began working on aarch64 once `loadEcContextAndReturn` started
raising `on_cpu`. If a peer core dead-marks this EC's domain and reaps in the
window between the clear and actually leaving the kstack, it unmaps a stack this
core is still running on.

Contrast the deliberate park path: `parkAndAwaitIRQ` calls
`parkPerCoreCaches(core, park_top)` *before* the park primitive, and the
primitive's stack swap moves off the EC kstack, so the matching clear in
`scheduler_run_after_park` (via `consumePostParkClear`) is genuinely safe. The
self-park paths have no such stack switch.

Exposure is narrow — it needs a concurrent domain teardown of the very EC that
is self-parking — but not exotic: that is exactly the
`create_execution_context_15` shape, where a dummy EC spins `wfi` (trapping into
this arm on every dispatch) while its owning domain is torn down. The code
comment in the `wf_trapped` arm already records that an earlier attempt
(`SCTLR.nTWI = 1`, native EL0 `wfi`) produced "the destroy walk's UAF race
against an actively-executing EC" and hung around test ~144.

### Decision needed

The obvious fix — publish the clear into the per-core `post_park_clear_on_cpu`
slot instead of storing `false` inline — **does not fully close the window**:
`switchTo` consumes that slot *before* `loadEcContextAndReturn`, so the clear
still lands while we are on the doomed stack. The truly safe point is after
`SP_EL1` has been retargeted at the incoming EC's kstack.

x86 does its `on_cpu` writes inside the asm return paths
(`arch/x64/interrupts.zig` 2216 / 2386 / 2404) for exactly this reason. aarch64
has no equivalent and relies on Zig-level stores at imprecise points. So the
question is whether to give aarch64 the same asm-precise treatment, which is
real work in the dispatch epilogue.

Do **not** fix this speculatively alongside unrelated work: it needs its own
A/B, and the baseline to beat is the `stygia-3ys` 200-rep arm (193 clean / 7 bad,
zero panics, zero wedges).
