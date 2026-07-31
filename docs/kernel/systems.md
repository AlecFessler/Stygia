# Stygia systems: the execution-context lifecycle machine

> **REVIEW STATUS: UNSOUND AS WRITTEN — DO NOT IMPLEMENT YET.**
> An adversarial review (`systems-review.md`, 2026-07-31) found three critical
> defects: an unprotected pre-publish window in the two-phase park that admits
> lost wakes (failure class 7), a retire path that can finalize a kernel stack
> while an in-flight wake winner is still writing into it (class 8), and
> cross-EC `suspend` unmodelled in all three of its legal target states.
> Classes 1, 3, 4, 5 and 6 ARE foreclosed, and the structural deletions
> (`committed_ec`, `post_park_clear_on_cpu`, `pending_cross_enqueue`,
> `pending_kstack_release`, `pending_zombie[64]`) survived attack — the
> skeleton is sound; two novel mechanisms are under-specified at the hard
> points. Read the review alongside this document. Do not build a formal
> proof over this model until the critical findings are closed: proving it as
> written would machine-check a design containing a lost wake and a UAF.

Status: **design target**, not a description of the current tree. This is the
machine the code should converge on. Where today's code is referenced
(`kernel/sched/scheduler.zig`, `kernel/sched/execution_context.zig`,
`kernel/sched/port.zig`, `kernel/sched/futex.zig`,
`kernel/caps/capability_domain.zig`, `kernel/arch/{x64,aarch64}/`), it is as
evidence of a constraint or as the mechanism a design step deletes. Normative
words (MUST/NEVER/only) describe the target design.

---

## 1. The problem being designed away

Today "the state of an EC" is the product of at least eight overlapping
signals, each answering some version of *is this EC still in use*:

```
State enum | on_cpu | slab-gen parity | current_queue_core | last_dispatched_core
  | referenced-by { PerCore.current_ec, .committed_ec, .pending_zombie[64],
                    .post_park_clear_on_cpu, .pending_kstack_release,
                    .pending_cross_enqueue }
  | suspend_port | pending_reply_holder
```

No single writer owns the product, no single predicate reads it, and the
composite has produced a systematic bug family (§7 lists the eight classes
this design forecloses). The root causes are three:

1. **State is scattered.** The `State` enum is not the state; queue
   membership, kstack liveness, and reclaim eligibility are separate facts
   with separate writers that can disagree.
2. **Transitions are not atomic with respect to preemption.** An EC leaves
   `running` in several steps spread across a syscall path, the scheduler,
   and an arch hop, and a preempt landing mid-sequence can abandon the
   sequence (and the kernel frame executing it) forever.
3. **Obligations are unassigned.** "This EC must eventually be reaped" and
   "this kstack must eventually be freed" are discharged by whichever path
   happens to notice, via hand-copied predicates that have already diverged.

The design below is organized around three principles:

- **One fact, one word, one writer.** Every cross-core-readable fact is a
  single machine word with exactly one writer context. Facts that need
  multi-party arbitration are arbitrated by CAS on exactly one word.
- **State implies containment.** The lifecycle state *is* the answer to
  "which container holds this EC". There is no state in which an EC is
  runnable but unreachable, or reachable but unrunnable.
- **Transitions complete at the hop.** No EC is ever observable as claimable
  while any core's stack pointer is on its kernel stack. The park-kstack hop
  (which the current tree already has, and which this design leans into
  harder) is the single instruction at which a core provably leaves an EC's
  kstack; every exit from `running` is *completed* there, by the owning core.

Prefer deleting state to validating it: §2.5 accounts for every one of
today's signals — kept, narrowed, or deleted.

---

## 2. The state space

### 2.1 The lifecycle word

Each EC carries exactly one authoritative lifecycle field:

```zig
/// u8, CAS-only, written exclusively by kernel/sched/lifecycle.zig
/// (plus the pinned fast-path asm sites listed in §9.4).
pub const State = enum(u8) {
    ready,     // resident in exactly one run queue; claimable by a dispatcher
    running,   // owned by exactly one core (owner_core); current on that core
    parking,   // owner core is completing an exit-from-running; not claimable
    waiting,   // parked in exactly one wait assembly; claimable by wakers
    woken,     // wake claimed while parking; owner core will enqueue at hop
    retired,   // terminal; slab gen already dead; awaiting finalize
};
```

Six states, same count as today's enum — but each is now a single-word fact
with a defined owner, and **every queue/container membership is implied by
the state** rather than tracked beside it.

What each state means, precisely:

| State | Containment (implied, exact) | Kstack | Claimable by |
|---|---|---|---|
| `ready` | exactly one per-core run queue | quiescent | dispatcher (under that core's lock) |
| `running` | `core_states[owner_core].current == ec` | owner core is on it | retire only |
| `parking` | target wait assembly (already linked) or a requeue directive | owner core is on it | wakers (→`woken`), retire |
| `waiting` | exactly one wait assembly (§2.2) | quiescent | wakers (→`ready`), retire |
| `woken` | none (unlinked by the claiming waker) | owner core is on it | retire only |
| `retired` | none | quiescent iff prior state was `ready`/`waiting`; else owner core until its hop | finalize only |

Today's three wait states (`suspended_on_port`, `futex_wait`, `idle_wait`)
collapse into `waiting`: *which* container holds the EC and *what* a wake
means are **data** (the wait descriptor, §2.2), not state. The
port-specific distinction "parked in the wait queue" vs "dequeued by recv,
awaiting reply" is likewise data: both are `waiting`; a recv's dequeue moves
the EC's containment from the port queue to the reply pin under the port
lock without any state transition at all.

`exited` is replaced by `retired`, which is **fused** with the slab-gen
death mark: there is no operation that sets `retired` without flipping the
gen to even, and none that flips an EC's gen without setting `retired`
(§6.1, invariant S5). Today's "`.exited` with an odd gen" — the shape of the
worst leak in the project's history — becomes unrepresentable.

### 2.2 The wait descriptor

A single struct, `ec.wait`, valid **only** in `parking`/`waiting`/`woken`,
written **only** by the EC's own core during `running → parking`, and read
by exactly two parties afterward: the waker that wins the claim CAS, and the
retirer that wins a retire CAS. Ownership transfers with the CAS
(acq_rel), so no field in it is ever concurrently written.

```zig
pub const Wait = struct {
    kind: enum(u8) { none, port_queue, reply_pin, futex, idle, requeue },
    // Containers, so claim/retire can unlink without a global sweep:
    port: ?SlabRef(Port),                 // port_queue / reply_pin
    reply_holder: ?*KernelHandle,         // reply_pin (+ domain, slot)
    futex_nodes: ?[*]WaitNode, futex_count: u8,
    deadline_ns: u64,                     // 0 = untimed; one table (§8.4)
    // Wake payload staging (event fields, pending_event_word, …) lives in
    // the same single-owner regime and is listed in §3.4.
};
```

The current fields `suspend_port`, `pending_reply_holder/domain/slot`,
`futex_wait_nodes/`count, `futex_deadline_ns`, `recv_deadline_ns` all fold
into this descriptor. They survive as data — that part of today's complexity
is essential — but their validity window and writer become checkable.

`kind == .requeue` covers the two non-wait exits from `running`: preemption
(re-enqueue by priority/affinity) and affinity migration. Both are just a
park whose "container" is a directive the owner core consumes at the hop.
This deletes `PerCore.pending_cross_enqueue` as a separate mechanism.

### 2.3 Per-core words

```zig
pub const PerCore = struct {
    run_queue: EcQueue,           // under core_locks[core] as today
    current: ?*ExecutionContext,  // ONE naturally aligned pointer word
    active_root: atomic u64,      // publish-after-load, as today
    idle_parked: bool,            // park decision, under core_locks[core]
    park_stack: Stack,
    idle_ec: ?SlabRef(EC),
};
```

- `current` is written at **exactly two sites**: the dispatch commit (under
  `core_locks[core]`, §5 edge 2) and the hop (§4). It is never nulled
  mid-syscall by suspend paths, never cleared by `parkSelfFaulted`-style
  helpers — those sites no longer exist. The single-pointer-word layout is
  retained from the current tree verbatim; the 24-byte `?SlabRef` tearing
  autopsy on `PerCore.current_ec` (Pi 5, fault at
  `@offsetOf(EC, "domain")`) is the permanent justification.
- `active_root` and the `awaitDomainQuiesced` barrier are retained
  unchanged: translation quiescence is essential complexity (§10).
- `committed_ec` is **deleted**: with the dequeue, the `ready → running`
  CAS, and the `current` write all in one critical section under
  `core_locks[core]` (§5 edge 2), the "committed but not yet current"
  window the field papered over no longer exists. The teardown barrier's
  one-acquire-per-core-lock prologue still publishes any in-flight commit.
- `pending_zombie[64]`, `post_park_clear_on_cpu`, `pending_kstack_release`,
  `pending_cross_enqueue` are **deleted** (§2.5, §8).

### 2.4 `owner_core`

One byte on the EC, valid **only** in `running`/`parking`/`woken`/`retired`-
pre-finalize, written under `core_locks[core]` at dispatch commit. It
answers exactly one question: *which core discharges this EC's hop
obligations* (finalize on retire, enqueue on woken, eviction-barrier
identity spin). It is today's `last_dispatched_core` with its validity
window tightened from "forever, monotone floor" to "while a core owns me".
Outside those states its value is meaningless and MUST NOT be read; a debug
build poisons it on `parking → waiting` and on finalize.

### 2.5 Disposition of today's signals

| Today | Disposition |
|---|---|
| `State` enum (6) | redefined (§2.1); wait flavors → descriptor data |
| `on_cpu` | **deleted.** Kstack liveness becomes structural: claimable states imply quiescence (invariant S3). No flag ⇒ no stranded flag, no missing writer per arch, no deferred-release stash protocol |
| slab gen parity | kept; fused with `retired` (S5) |
| `current_queue_core` | replaced by a queue-core field maintained strictly under `core_locks[core]` at enqueue/dequeue — a locked field, not a racy hint. The IPC fast path must maintain it too (§9.4); the "asm bypasses the hint, fall back to a 64-lock sweep" special case is deleted |
| `last_dispatched_core` | narrowed to `owner_core` (§2.4) |
| `PerCore.current_ec` | kept (single word, two writer sites) |
| `PerCore.committed_ec` | deleted (§2.3) |
| `PerCore.pending_zombie[64]` | deleted; the retire handoff channel is the state word itself (§8.2) |
| `PerCore.post_park_clear_on_cpu` | deleted (no flag to clear) |
| `PerCore.pending_kstack_release` | deleted (the hop's overwrite of `current` *is* the release) |
| `PerCore.pending_cross_enqueue` | deleted (requeue directive, §2.2) |
| `suspend_port`, `pending_reply_*` | kept as descriptor data with a defined ownership handoff |
| `leak_tag`, all `stygia-afo`/`2u0` counters | deleted; the invariants they were instrumenting become assertable (§9.2) |

Net: one authoritative word per EC, one byte of scoped owner, one
descriptor with single-owner discipline, and four fewer per-core mailbox
slots. Everything deleted is state whose only job was to re-derive facts
the state machine now carries directly.

---

## 3. The concurrency substrate

A transition table alone would bless the worst historical bugs as correct.
The machine is therefore explicit about preemption, interrupts, and word
granularity.

### 3.1 Preemption points

Kernel execution is in one of two contexts:

- **EC context**: on some EC's kstack (syscall, exception, or an IRQ that
  interrupted either).
- **Scheduler context**: on the per-core park kstack (dispatch tail,
  `run()`, teardown work, idle).

Rules:

1. **Preemption is claim-gated.** The preempt tick may only dispatch away
   from EC context if it successfully claims
   `running → parking(requeue)` on the current EC. If the CAS fails, the
   current EC is mid-transition (`parking`/`woken`: its own core is
   completing an exit) or `retired` (rule 3); the tick does **not**
   dispatch and returns from the IRQ. The interrupted transition resumes
   and completes at its own hop.

   *Consequence:* a kernel frame in EC context can only be abandoned when
   the preempt path has claimed its EC — and a claimed EC's frame is,
   by definition, the frame being retired or re-queued. There is no
   "callee re-enabled IRQs inside a must-complete sequence" hazard,
   because must-complete sequences are protected by an unclaimable state,
   not by an IRQ mask. The entire discipline of auditing callees for
   `enableInterrupts()` is deleted rather than enforced. (Forecloses
   failure class 2.)

2. **Scheduler context never dispatches from an interrupt.** A tick landing
   while SP is in the park stack returns immediately (one SP range check).
   Work that MUST run to completion — domain teardown phase 2, finalize,
   requeue — runs in scheduler context and is therefore structurally
   un-abandonable, with IRQs *enabled* (so wake IPIs and TLB-shootdown
   acks are always serviceable; no ack-while-spinning heroics needed for
   these paths).

3. **Entry checks.** Syscall entry, exception entry, and the preempt tick
   all begin by reading `current.state`. `retired` ⇒ route to the hop
   (abandon the frame deliberately: nothing will ever resume a retired
   EC, and the hop finalizes it). This replaces the scattered
   "disowned-current escape" logic in today's `yieldTo`.

### 3.2 The two named atomic sequences

Exactly two multi-step sequences must be atomic with respect to concurrent
claimers, and both are protected by the state word rather than by masking:

- **The park sequence** (`running → parking → hop`): performed by the owner
  core. All fallible work (deadline-slot allocation, table checks) happens
  *before* the `parking` publish; after the publish there is no failure
  path and no blocking operation — the sequence runs straight to the hop.
  (Today's futex `E_NOMEM` unwind that flips `.futex_wait` back to
  `.running` becomes impossible: the failure is detected before the state
  ever changes.) IRQs may remain enabled throughout: rule 3.1(1) makes a
  mid-sequence tick harmless.
- **The dispatch sequence** (`ready → running → SP on new kstack`): the
  dequeue, the domain-liveness filter, the `ready → running` CAS, the
  `current`/`owner_core` writes all occur in one `core_locks[core]`
  critical section (IRQ-masked, as all container locks are); the SP/root
  load follows on the park stack. Retire serializes against the commit via
  the same lock (its queue unlink takes it), so the historical
  "dequeue → setCurrentEc window" (the batch-168 iretq-#GP kstack free)
  has no gap to race.

These are the only sequences an analyzer needs to certify (§9.3): each is
one short function in the chokepoint module, not a property smeared across
five files.

### 3.3 Interrupt discipline

- Container locks (run queues, port `_gen_lock`, futex buckets, deadline
  table) are IRQ-masked for the duration of the hold, exactly as
  `tools/check_gen_lock`'s IRQ-class pass already demands. Nothing new.
- No kernel code outside `arch/` enables interrupts. Today's single
  violation (the `postZombie` contended-spin escape in
  `destroyExecutionContextLocked`) is deleted along with the mechanism
  that needed it.
- The park primitive's masked-halt contract (`sti;hlt` shadow / aarch64
  masked-`wfi`) is unchanged.

### 3.4 Atomicity granularity — what a concurrent reader may observe

Every fact readable from another core is a single naturally aligned machine
word, or is reached only after an acq_rel CAS transfers ownership:

| Fact | Width | Writer | Cross-core readers | Discipline |
|---|---|---|---|---|
| `ec.state` | 1 byte | chokepoint CAS only | anyone | CAS/acquire loads; every decision that acts on a read re-validates by CAS |
| `ec.owner_core` | 1 byte | dispatching core under its lock | retirer (after retire CAS), eviction barrier | valid only in owned states |
| `ec.wait.*` | multi-word | EC's own core, pre-`parking` | claim winner, retire winner | ownership transfers with the CAS; never concurrently written |
| `ec.ctx` payload writes (syscall return, event GPRs) | multi-word | claim winner only | the EC itself, after re-dispatch | happens-before via the claim CAS + enqueue lock |
| `PerCore.current` | 8 bytes | owning core (2 sites) | identity compares only (barriers, eviction spin, diagnostics) | never dereferenced cross-core except under the caller-pinned identity rules; slab bytes-intact-until-finalize backs stale pointers (§8.2) |
| `PerCore.active_root` | 8 bytes | owning core, release-after-load | teardown barrier | as today |
| `PerCore.idle_parked` | 1 byte | owning core under its lock | enqueuers under the same lock | as today |
| slab gen word | 8 bytes | slab allocator / retire | handle resolution | as today |

Anything wider than a word (the descriptor, the saved frame) is reached
only through single-owner-then-transfer. There is no field left with the
shape that produced the torn `?SlabRef` read. (Forecloses failure class 3.)

---

## 4. The hop

The hop is the existing `hopToStackAndCall` primitive, promoted from
mechanism to load-bearing contract:

> **Hop contract.** The hop is the only way a core stops executing on an
> EC's kstack. On the park stack, immediately after the swap, the hopping
> core — and only it — completes the outgoing EC's transition:
>
> 1. Read `outgoing.state` (it is unclaimable by preempt, and only wakers/
>    retirers could have changed it — via CAS, which the completion below
>    re-runs):
>    - `parking` → CAS to `waiting`. Success: done (EC is now claimable,
>      and the core is provably off its kstack — publication order is the
>      whole point).
>    - CAS failed, now `woken` → stamp `ready` + enqueue (under the target
>      core's lock, honoring affinity/priority), send wake/preempt IPI per
>      the standard enqueue policy.
>    - CAS failed, now `retired`, or was `retired` at entry → **finalize**
>      (§8.2): free kstack, `destroyAlreadyMarked` the slab slot.
>    - `parking(kind=requeue)` → stamp `ready` + enqueue per directive.
> 2. Overwrite `PerCore.current` (with the incoming EC or null) and repoint
>    TSS.RSP0 / gs:0 / SP_EL1 caches. This overwrite **is** the kstack
>    release — there is no flag to clear.
> 3. Proceed: dispatch tail for an incoming EC, or `run()`.
>
> On x86 the hop must EOI the in-service scheduler vector before parking
> (the current `schedulerEscapeEoi` rule, kept verbatim).

Every scheduler exit path goes through the hop: block, preempt, migrate,
fault-park, self-retire, remote-retire discovery, idle. The boot-time
"no park stack yet" fallback runs the tail in place, exactly as today.

Because `parking → waiting` happens *at* the hop, the invariant

> **claimable ⇒ kstack-quiescent**

holds by construction, and the entire family of mechanisms that
approximated it — `on_cpu` and its deferred-release stash, the wake-side
`on_cpu` spin in `markReady` / futex wake phase 2 / `rendezvousWithReceiver`
/ `expireTimedRecvWaiters`, the reaper's `standing_on_zombie` SP-range
check, the stranded-flag escapes in `takeOwnPendingZombie` /
`claimOwnZombieInline` — is deleted. Wakers never spin on another core's
progress; the worst case for a wake that races a park is that the parking
core itself performs the enqueue a few hundred cycles later at its hop
(which is also the moment the EC first becomes safely dispatchable, so no
latency is actually lost relative to today's spin).

---

## 5. The transition table

All transitions execute in `kernel/sched/lifecycle.zig` (the chokepoint,
§9.1) except the two pinned fast-path asm sites (§9.4). Absent rows are
illegal; the chokepoint CAS makes them unreachable, and a debug build
asserts on any CAS whose (from, to) pair is not in this table.

| # | Edge | Actor | Trigger | Precondition | Postcondition |
|---|---|---|---|---|---|
| 1 | *(slab pending)* → `ready` | creator | `publish` at the end of `create_execution_context` / vCPU / idle-EC creation | EC fully constructed, invisible (slab not yet published); all fallible work done | gen live **and** EC enqueued on a chosen core, both under that core's lock. There is no observable created-but-unowned EC |
| 2 | `ready` → `running` | dispatching core | dequeue | under `core_locks[core]`: popped from this queue, domain-ref live (`domainRefAlive`), CAS wins | `current = ec`, `owner_core = core`, still under the lock; then SP/root load in the dispatch sequence |
| 3 | `running` → `parking` | owner core | blocking syscall (recv, suspend, futex wait), wfi/hlt trap, event-route fault delivery, preempt tick (kind=requeue), affinity migration (kind=requeue) | descriptor written; containers linked under their locks (port queue / futex buckets / deadline slot); no fallible step remains | park sequence runs straight to the hop |
| 4 | `parking` → `waiting` | owner core | the hop | SP off the kstack (structural) | EC claimable; `owner_core` poisoned (debug) |
| 5 | `parking` → `woken` | any waker | wake source found the EC through a container during the park window | CAS wins (at most one) | winner writes payload, unlinks remaining containers under their locks; owner core will enqueue at its hop |
| 6 | `waiting` → `ready` | any waker | futex wake, deadline expiry, reply / reply_transfer, E_CLOSED propagation, sender-rendezvous of a parked receiver, cross-EC suspend of an idle-waiter | CAS wins (at most one per wait episode) | winner writes payload, unlinks remaining containers, enqueues under target core's lock (stamp + link in one section) |
| 7 | `woken` → `ready` | owner core | the hop | — | enqueue per affinity/priority, under target core's lock |
| 8 | `parking(requeue)` → `ready` | owner core | the hop | — | as 7 |
| 9 | `running` → `retired` | self (fault fallback, `delete(SLOT_SELF)`) or a remote retirer (`terminate`, domain teardown, port vCPU cascade) | retire | CAS wins; retire **fuses** the slab-gen death flip in the same operation | containers: none (running has none). Self: proceed to hop, finalize there. Remote: wake IPI to `owner_core`; that core's next entry check (§3.1 rule 3) hops and finalizes. Retirer's eviction barrier spins on `currentEcPtrOn(owner_core) != ec` identity word |
| 10 | `parking`/`woken` → `retired` | retirer | retire | CAS wins | retirer unlinks containers (idempotent, under locks); owner core's hop CAS fails, observes `retired`, finalizes |
| 11 | `ready`/`waiting` → `retired` | retirer | retire | CAS wins | retirer unlinks (run queue / wait assembly / deadline slot, under locks) and — because these states imply kstack quiescence — **finalizes inline** |
| 12 | `retired` → *(freed)* | as assigned by 9–11 | finalize | no core's SP on the kstack (structural: inline case was quiescent; hop case just left it) | kstack unmapped (VA + frames ride the existing invalidation-epoch quarantine), slot zeroed + freelisted (`destroyAlreadyMarked`) |

Notes:

- **There is no `running → ready` edge.** Preemption and migration go
  through `parking(requeue)` (edges 3, 8) so that re-enqueue happens only
  after the hop. This is the single change that makes
  "claimable ⇒ quiescent" total; today's `yieldTo` re-enqueues `cur` while
  still standing on its kstack, and every downstream mechanism exists to
  survive that.
- **Retire is one operation** (`lifecycle.retire(ec)`): CAS loop over
  whatever state the EC is in, gen flip, container unwind, obligation
  routing (inline finalize vs owner IPI). All five current retire-flavored
  paths — `terminate`, `destroyExecutionContextLocked`, `parkSelfFaulted`,
  the vCPU cascade, `releaseSelf` — become callers of it. The prepare-phase
  resource release (event routes, exit_port unlink, perfmon, vCPU arch
  state, FPU-owner clear, pending-reply abandonment) is a straight-line
  body inside retire, after the CAS and before finalize routing.
- **Wake payload writes** (`setSyscallReturn`, event GPR staging,
  `pending_event_word`) are performed only by the claim winner (edges 5, 6)
  — the CAS is what makes them race-free, exactly as today's
  `tryClaimWake` doctrine established. That doctrine is essential
  complexity and is retained as the *only* wake arbitration mechanism.

---

## 6. Invariants

Stated to be mechanically checkable. Each is annotated with the failure
class(es) from the historical record it forecloses (numbered as in §7).

### 6.1 Safety

- **S1 (containment).** `state == ready` ⇔ the EC is linked in exactly one
  run queue; `waiting` ⇔ exactly one wait assembly; `running`/`parking`/
  `woken` ⇒ in no claimable container and `owner_core` valid;
  `retired` ⇒ in no container. Every membership edit occurs under the
  container's lock in the same critical section as (or strictly after, via
  claim ownership) the state fact that implies it. *(Forecloses 6, 7.)*
- **S2 (single writer).** Every field in §3.4's table is written only by
  its named writer context. In particular `ec.state` is written only by
  chokepoint CAS; `PerCore.current` only by its own core at the two named
  sites. *(Forecloses 3, 5.)*
- **S3 (kstack quiescence).** If any core's SP is in `ec.kernel_stack`,
  then that core is `ec.owner_core` and
  `ec.state ∈ {running, parking, woken}` or is `retired` awaiting that
  core's hop-finalize. Contrapositive: `ready`/`waiting`/finalize-eligible
  ⇒ no core is on the kstack. Established by edges 4/7/8 happening *at*
  the hop. *(Forecloses 8, and deletes the machinery whose failure was 4.)*
- **S4 (claim uniqueness).** For each wait episode, at most one
  `waiting → ready` or `parking → woken` CAS succeeds; only the winner may
  write payload or enqueue; losers do nothing. *(Forecloses 7's
  double-enqueue half — the two-cores-one-frame family.)*
- **S5 (retire fusion).** `gen even ⇔ state == retired ∨ freed`. No
  operation produces a dead-marked live state or a live-gen terminal
  state. *(Forecloses 1.)*
- **S6 (word granularity).** No fact readable off-core is wider than one
  machine word unless reached via CAS-transferred ownership. *(Forecloses
  3.)*
- **S7 (dispatch filter).** Edge 2 commits only `ready` ECs whose domain
  ref is gen-live, checked under the same lock as the commit. *(Retains
  today's dying-domain filter; forecloses the CR3=0 dispatch family.)*
- **S8 (enqueue gate).** The only paths that link an EC into a run queue
  are edges 1, 6, 7, 8 — publish, claim winner, owner hop — and all stamp
  `ready` and link under the target core's lock in one section.
  *(Forecloses 6, 7.)*

### 6.2 Liveness

Each obligation names its discharger and its bound.

- **L1 (parks complete).** `parking`/`woken` are transient: the owner core
  reaches its hop without any blocking operation after the state publish
  (park-sequence rule, §3.2). Bound: straight-line local work. Discharger:
  owner core. Checked: analyzer certifies no lock acquire / no spin between
  the `parking` CAS and the hop call (§9.3).
- **L2 (retired ⇒ freed).** Retire from `ready`/`waiting` finalizes inline
  (bound: immediate). Retire from owned states: the retirer sends a wake
  IPI to `owner_core`; that core's next kernel entry — bounded by IPI
  delivery, or by the preempt heartbeat for a core wedged in user mode, or
  by the re-armed park timer for an idle core (today's heartbeat rule,
  kept) — routes to the hop and finalizes. Discharger: named at retire
  time, always exactly one. *(Forecloses 1 and 4: there is no state in
  which no one is responsible for a dead EC.)*
- **L3 (ready ⇒ dispatched).** The enqueue/park race is resolved under
  `core_locks[core]`: the park decision (`idle_parked`) is published under
  the same lock the enqueuer takes, and the wake IPI is sent iff the
  target is idle/parked — today's lost-wake fix, kept verbatim as the
  normative rule. Bound: one wake IPI or one heartbeat tick. *(Forecloses
  7's lost-enqueue half.)*
- **L4 (deadlines fire).** A timed wait registers in the single deadline
  table (§8.4) before the park publish; the per-core tick scans it and
  attempts the claim. Losing the claim to the event waker is a correct
  outcome (S4). Discharger: timer tick core.
- **L5 (terminate is synchronous eviction).** `retire` of a remotely
  `running` EC returns to the terminator only after
  `currentEcPtrOn(owner_core)` stops naming the EC (identity spin on one
  word). Kstack finalize remains asynchronous under L2's bound —
  terminate's spec obligation is "stops executing", not "is freed".
  [MAINTAINER CALL §11.3 if the stronger guarantee is wanted.]

---

## 7. The eight failure classes, and where each dies

1. **Orphaned `.exited` (odd gen, never posted, never reaped).** Dead by
   S5 (cannot exist) + L2 (finalize always has an assigned discharger).
   `parkSelfFaulted` — the writer of 100% of the leaked population — is
   replaced by self-retire (edge 9), whose finalize is the caller core's
   own hop.
2. **Abandoned teardown frame.** Dead by §3.1: preemption is claim-gated
   in EC context, and teardown phase 2 runs in scheduler context where the
   tick never dispatches. The IRQ-mask-as-frame-lifeline pattern (and the
   audit burden of every callee that might unmask) is deleted, not
   defended.
3. **Torn state read.** Dead by S6/§3.4: nothing multi-word is
   cross-core-readable. The `current` single-word layout is retained as
   the exemplar.
4. **Stranded `on_cpu`.** Dead by deletion: there is no flag. Quiescence
   is derived from per-core words that are unconditionally overwritten at
   every hop — a stranded value is unrepresentable.
5. **Duplicated predicate drift / missing per-arch writer.** Dead by §9:
   one chokepoint owns every transition; one `stale(ec)` predicate
   (`state == retired`, gen subsumed by S5) is the only pop-side filter;
   the analyzer pins the writer set and requires paired per-arch sites.
6. **Ownerless EC.** Dead by edge 1: creation is invisible until publish,
   and publish *is* enqueue. S1 makes "runnable but in no queue"
   unrepresentable at every later point too.
7. **Lost wake / lost enqueue / double enqueue.** Dead by S4 (claim), S8
   (enqueue gate), L3 (locked park decision), and the `woken` latch (a
   wake that lands mid-park is never dropped — it is recorded in the state
   word itself and honored at the hop).
8. **Reap while live.** Dead by S3 + edge 12's placement: finalize runs
   either from a state that implies quiescence or at the hop that just
   established it. The kstack VA/frame invalidation-epoch quarantine in
   `stack.destroyKernel` (aliasing closure) is retained beneath this.

---

## 8. Integration and reclamation

### 8.1 Scheduler

- **Dispatch** is edge 2 + the dispatch sequence. The vCPU synthetic-exit
  pre-loop keeps its shape but each vCPU it cycles goes
  `ready → running → parking(exit_port) → waiting` through the standard
  edges — no special-case state writes.
- **Preempt** is edge 3(kind=requeue) + edge 8. `yieldTo(target)`'s
  explicit-target arm is edge 2 with the target pre-selected under the
  lock.
- **Idle** parks the core (scheduler context); `idle_parked` and the
  masked-halt contract are unchanged.
- **markReady / tryClaimWake** are subsumed by `lifecycle.wake(ec, payload)`
  — one function performing the claim (edge 5 or 6), payload write, and
  (edge 6) enqueue.

### 8.2 Retire and finalize (the reclamation path in full)

From "no longer runnable" to "slot and kstack reusable":

1. `lifecycle.retire(ec)`: CAS loop → `retired` + gen flip (S5), container
   unwind (run queue / port queue / reply pin / futex buckets / deadline
   slot — all named by the descriptor, all idempotent, all under their
   locks), resource release (routes, exit_port, perfmon, vCPU arch state,
   FPU-owner slot clear, reply abandonment).
2. Obligation routing: prior state `ready`/`waiting` ⇒ finalize inline
   (quiescent by S3). Prior state owned ⇒ wake IPI to `owner_core`; its
   entry check routes to the hop; the hop finalizes. The handoff channel
   is the state word — no mailbox slots, no post/spin/drain protocol, no
   per-(poster,target) columns.
3. Finalize (edge 12): unmap kstack (epoch-quarantined), zero + freelist
   the slab slot.
4. **Grace rule for stale bare pointers**: slab bytes stay intact from gen
   flip until finalize's zero, and every cross-core bare-`*EC` use is
   identity-compare-only (the caller-pinned doctrine, retained). Claim
   CASes make payload-writing use-after-free impossible without needing
   the bytes; the bytes-intact window is only for identity readers.

Domain teardown (`destroyPhase1/2` today):

- Phase 1 (dead-mark the CD, snapshot the deferred struct) is unchanged in
  substance.
- Phase 2 runs **in scheduler context**: `delete(SLOT_SELF)` retires the
  caller EC (edge 9, self), hops carrying the `DestroyDeferred`, and the
  park-stack code runs the walk: retire every matching EC (inline
  finalize for quiescent victims; IPI for owned ones), then
  `awaitDomainQuiesced` (retained verbatim: lock-sweep prologue,
  `active_root` clause, `current` domain-identity clause), then VMAR
  teardown, handle release walk, `freeUserAddrSpace`, table blocks, ASID,
  `destroyAlreadyMarked`. No IRQ mask is needed for frame survival
  (§3.1 rule 2); no `keep_ref` caller-EC special case (it was retired
  before the walk and its even gen skips it); no same-core zombie-column
  pathology (there are no columns).
- The remote-victim rule is unchanged in spirit: retire only guarantees
  eviction-within-a-tick; the translation barrier is what gates table
  freeing. That barrier is essential complexity — the design keeps it and
  says so.

### 8.3 Ports

- **suspend / fault delivery**: edge 3 with `kind=port_queue`; descriptor
  carries port ref + event payload staging. Rendezvous with a parked
  receiver is `lifecycle.wake(receiver, payload)` after `deliverEvent`
  (edge 6), with the receiver's `on_cpu` spin deleted — if the receiver is
  still `parking` on its old core, the claim lands as edge 5 and its own
  core enqueues it at the hop.
- **recv with queued sender**: pop under port lock skips `stale(ec)`
  entries (the one predicate); the dequeue-for-reply moves containment
  from port queue to reply pin **without a state transition** (both are
  `waiting`).
- **reply / reply_transfer / E_ABANDONED / E_CLOSED**: all are
  `lifecycle.wake` with different payloads. `propagateClosedToSenders`'s
  current write-then-claim ordering (payload written before the claim,
  unlike its receiver twin — live predicate drift today) becomes
  impossible: payload writing is inside the wake function, after the CAS,
  once, for everyone.
- **Port lifetime** (bind/recv refcounts, vCPU cascade) is untouched
  except that the cascade's per-vCPU destroy is a `retire` call.

### 8.4 Futex and timers

- **wait**: edge 3 with `kind=futex`; nodes and vaddrs stay EC-resident
  (essential — the syscall frame dies before the wake; retained).
  Bucket-lock ordering discipline is unchanged.
- **wake**: bucket pop → `lifecycle.wake` (claim, payload = woken vaddr,
  sibling-node unlink, enqueue). The four-phase
  lock/spin/re-lock/enqueue dance collapses to: unlink under bucket lock,
  claim, act.
- **timers**: `timed_waiters[64]` (futex) and `timed_recv_waiters[256]`
  (port) unify into one deadline table keyed by the descriptor's
  `deadline_ns`, scanned by the tick, claim-attempted on expiry. One
  mechanism, one registration/cancel path (cancel is part of container
  unwind in wake/retire), one stale-detection rule (the claim itself; the
  deadline-snapshot recheck survives as the cheap pre-filter). The
  per-core snapshot scratch (IRQ-stack-depth fix) is retained.

### 8.5 Creation

`allocExecutionContext` keeps its structure (kstack map, user stack, first
iret frame) but ends in `lifecycle.publish(ec, core)` — gen-live + enqueue
under one lock (edge 1). Failure before publish unwinds a private object;
there is no partially-created EC visible to any walk. vCPUs publish into
`waiting(exit_port)` instead of a queue when the spec's initial-exit
handshake wants them born suspended — publish must name an owner either
way; "no owner" is not expressible.

---

## 9. Enforcement

### 9.1 The chokepoint

`kernel/sched/lifecycle.zig` exports: `publish`, `dispatchCommit`, `park`,
`hopComplete`, `wake`, `retire`, `finalize` and is the **sole writer** of
`ec.state` (with the pinned exceptions in §9.4). A comptime transition
table constant mirrors §5; every CAS site asserts its (from, to) pair is a
row.

### 9.2 Debug-build assertions

- Transition legality on every CAS (the table constant).
- On enqueue: state stamped `ready` in the same lock section; link count 1.
- At hop: outgoing state ∈ {parking, woken, retired}; poison `owner_core`
  on `parking → waiting`.
- At finalize: 64-way scan asserting no `PerCore.current` names the EC and
  no SP-range overlap (debug only; release relies on S3).
- Pop-side: the single `stale(ec)` predicate is the only skip condition.
- Descriptor poisoning outside its validity states.

### 9.3 Static analysis (the existing grain)

Rules that fit `tools/check_gen_lock` / `tools/dead_code_zig` (SAS
symbol-anchoring) / `tools/check_arch_layering` and the callgraph DB:

1. **Writer-set pinning**: the set of stores to `ExecutionContext.state`
   (and `PerCore.current`) is exactly {lifecycle fns} ∪ {listed asm
   blocks}. Symbol-anchored like dead_code's skip entries so drift is a
   CI failure, not a comment.
2. **Park-sequence certification**: on every path from a `park()` call to
   the corresponding hop call, no lock acquire, no IRQ enable, no
   unbounded loop (callgraph reachability over the same DB
   `check_gen_lock` already builds).
3. **Paired-arch transitions**: every lifecycle call site tagged with an
   arch-neutral transition ID; the analyzer requires each ID to be
   reachable from both arch entry sets. This is the rule that would have
   caught the aarch64 `on_cpu`-writer-missing-for-its-whole-existence bug.
4. **Container-lock coupling**: enqueue/remove callers must hold the
   matching lock class (extends the existing IRQ-class pass; runtime
   lockdep remains the dynamic backstop).
5. **Bare-pointer invariant**: unchanged (`SlabRef` rule), with the §3.4
   caller-pinned identity-compare whitelist made explicit per field.

### 9.4 The IPC fast path

The x86 suspend/reply fast paths (`arch/x64/interrupts.zig` steps 14 /
R-14) write EC state, `current`, and queue links in asm. Under this design
they are **fused park+dispatch implementations of edges 3+4 and 6+2** and
must satisfy the same contract: publish-claimable strictly after SP leaves
the outgoing kstack; maintain the queue-core field; stamp through the same
offsets the chokepoint uses (`@offsetOf` pins + comptime layout asserts,
as today). They are the *only* entries in analyzer rule 9.3(1)'s asm list.
[MAINTAINER CALL §11.1 on whether to keep them asm-fused or route through
callable chokepoint stubs at some cycle cost.]

---

## 10. Essential complexity — kept deliberately

Called out so nobody "simplifies" these away later:

- **The wake-claim CAS** (`tryClaimWake` doctrine). Two independent wakers
  per timed wait is inherent; the EC's own state word is the only common
  serialization point (per-core queue locks provably cannot arbitrate it).
  This design makes the claim the *only* arbitration mechanism, everywhere.
- **Translation quiescence** (`active_root` publish-after-load +
  `awaitDomainQuiesced` + the lock-sweep prologue). Freeing page tables
  needs a barrier no per-EC state can replace.
- **Slab gen parity + bytes-intact-until-finalize.** Structural UAF
  detection for handles and safe identity reads for stale snapshots.
- **EC-resident wait storage** (futex nodes/vaddrs, event staging). The
  syscall frame provably dies before the wake; the EC is the only correct
  home.
- **The park-kstack hop and per-core park stacks.** The design's central
  primitive; already proven in-tree.
- **The locked park decision** (`idle_parked`) and the parked-core timer
  heartbeat. Both close measured lost-wake holes; both are now normative.
- **Ack-while-spinning on the spins that remain** (container locks, the
  eviction barrier, `awaitDomainQuiesced`). Far fewer spins survive, but
  the ones that do keep the TLB-maintenance service rule.

---

## 11. Decisions needing the maintainer's call

1. **Fast-path policy** (§9.4): keep steps 14/R-14 as pinned asm
   implementing fused edges (fastest; needs the paired-site analyzer to be
   trustworthy), or route their state writes through `extern` chokepoint
   stubs (uniform enforcement, measurable syscall-path cost). The design
   works with either; the analyzer rule set differs.
2. **`woken` enqueue placement**: this design has the parking core enqueue
   at its own hop (deletes all cross-core wake spins). Alternative: waker
   spins until `waiting` then claims (closer to today). The spin-free
   version is strictly simpler and no slower end-to-end (the EC cannot be
   safely dispatched before the hop either way), but it does move the
   affinity/priority routing of that enqueue onto the parking core —
   confirm that is acceptable for the futex `pickCoreForEc` semantics.
3. **Terminate strength**: L5 guarantees eviction, not finalize, at
   syscall return (matches today). If the spec's §[terminate] test surface
   is ever read to require the kstack freed synchronously, terminate would
   additionally wait on the finalize (bounded by L2); that is a spec
   interpretation question, not a mechanism question.
4. **`idle_wait` as a state vs a wait kind**: modeled here as
   `waiting(kind=idle)` with no container. If the aarch64 wfi/wfe trap
   path wants a cheaper non-descriptor park, a dedicated kind flag is
   sufficient; do not resurrect a distinct enum state for it.

---

## 12. Migration

Ordered so every step lands green on the existing suite and each step
*deletes* a mechanism (the deletions are the point — a step that only adds
is off-plan):

1. **Chokepoint extraction.** Move every `ec.state` write and
   `tryClaimWake` into `lifecycle.zig`; add the transition-table debug
   assert and analyzer rule 9.3(1). Deletes: nothing yet; makes every
   later step diff-reviewable and drift-proof. (`leak_tag` and the
   stygia-2u0/afo diagnostic counters can be dropped here — their
   questions become assertions.)
2. **Retire fusion.** Implement `retire()` fusing state+gen and fold
   `terminate` / `destroyExecutionContextLocked` / `parkSelfFaulted` /
   `finalizePendingVcpus` into callers. Deletes: the three divergent
   copies of the reap predicate; the `.exited`-odd-gen shape (bug 1) even
   before the hop work lands.
3. **Two-phase park (`parking`/`woken`).** Introduce the claim-gated
   preempt and the hop-completion of `parking → waiting`/`woken → ready`.
   Deletes: the wake-side `on_cpu` spins in `markReady`, futex wake
   phase 2, `rendezvousWithReceiver`, `expireTimedRecvWaiters`.
4. **Hop-completes-everything** (preempt requeue + migration through
   `parking(requeue)`; `current` written only at commit/hop). Deletes:
   `on_cpu` itself, `stashKstackRelease`/`takePendingReleaseByte`,
   `PerCore.pending_kstack_release`, `post_park_clear_on_cpu` +
   `consumePostParkClear`, `pending_cross_enqueue`, `clearCurrentEc`'s
   scattered call sites, the disowned-current escape logic.
5. **State-word retire handoff.** Route remote-retire finalize through the
   owner core's entry-check + hop. Deletes: `pending_zombie[64]`,
   `postZombie`/`takeOwnPendingZombie`/`claimOwnZombieInline`, the
   `ZOMBIE_WAKE_RETRY_SPINS` loops, the kernel's only
   `enableInterrupts()` outside `arch/`, `last_dispatched_core` (narrowed
   to `owner_core`).
6. **Scheduler-context teardown.** Run `destroyPhase2` on the park stack
   behind a self-retire hop. Deletes: the phase-2 IRQ-mask fragility and
   its long defensive comment, the `keep_ref` caller-EC special case, the
   `in_phase2`/abandonment instrumentation.
7. **Commit unification + registry merge.** Fold `committed_ec` into the
   locked commit; unify the two timed-waiter registries; make the
   queue-core field a locked descriptor field maintained by all enqueuers
   including the fast path. Deletes: `committed_ec`, one of the two
   deadline registries, the 64-lock `removeFromQueue` sweep fallback.
8. **Analyzer completion.** Land rules 9.3(2)–(4); wire into the precommit
   CI next to `check_gen_lock`/`dead_code_zig`/`check_arch_layering`.

Steps 3–5 are the risk core and should each ride a full N=100 bare-metal
pass (the existing Pi rig discipline) before the next lands.
