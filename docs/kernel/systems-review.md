# Adversarial review: `systems.md` (round 1)

Date: 2026-07-31. Reviewer brief: find where the design is WRONG or INCOMPLETE;
default to refuting. Read-only review against the real tree.

## Verdict: **UNSOUND** (as written)

The skeleton — one CAS-word lifecycle, hop-completed exits, retire fused with
gen-death, teardown in scheduler context — is genuinely good, and most of the
deletions are honestly earned. But the document's two novel mechanisms (the
two-phase park and fused retire) each have a reachable interleaving that
violates the doc's own safety/liveness claims, and one whole family of real EC
transitions (cross-EC suspend) has no home in the transition table. These are
not polish items; they sit at the exact places the historical bug families
lived.

---

## CRITICAL

### C1 — Park/wake race: the pre-publish window is unprotected, and the doc's own ordering rules force it open
*(Axis: correctness. §3.2 / §5 edges 3,5,6 / §6.2 L4 / §4)*

Edge 3's precondition ("containers linked … no fallible step remains") plus
L1/9.3(2) ("no lock acquire between the `parking` CAS and the hop") force
container linking and all fallible work — including the port rendezvous, which
mints the reply handle (fallible, `E_FULL`) — **before** the `parking` publish.
In that window the EC is findable through containers/pins while
`state == running`, and:

- **Preempt-tick steal.** §3.2 explicitly says "IRQs may remain enabled
  throughout: rule 3.1(1) makes a mid-sequence tick harmless." False. In the
  link-to-publish window the state is still `running`, so the tick's
  `running → parking(requeue)` CAS **succeeds**, clobbers the just-written wait
  descriptor, and requeues an EC still linked in a wait container (S1
  violated). Concrete lost wake: receiver R links into port queue → tick steals
  it into requeue → sender pops R, both claim CASes fail ("losers do nothing")
  → rendezvous dropped; R later resumes its interrupted park sequence, CASes
  `running → parking` with the stale port descriptor, and parks forever on a
  queue it is no longer linked in. This is failure class 7, which §7 claims
  foreclosed.
- **Cross-core waker sees `running`.** A futex waker popping a node, the
  deadline tick scanning the table (L4 registers **before** the publish), or a
  reply arriving through the pin minted during the rendezvous — all find
  `running`; edges 5/6 both fail; no party is designated to retry. For the
  deadline case the two-phase scratch clears the slot in phase 1, so a claim
  that fails against a pre-publish park **loses the deadline permanently** —
  L4's "losing the claim to the event waker is a correct outcome" assumes the
  only loser cause is another winner, which is false. That is precisely the
  "obligation with no bounded discharger" defect class.

The current tree closes the single-container half of this by publishing the
wait state **under all container locks** (futex: `ec.state = .futex_wait` at
`kernel/sched/futex.zig:434` inside the all-buckets critical section, nodes
linked at :436-439 after it; port: state under `port._gen_lock` at
`kernel/sched/execution_context.zig:1645`), and patches the rendezvous/reply
half with exactly the machinery the design deletes: `markReady`'s `.running`
claim arm (`kernel/sched/scheduler.zig:2100-2107` — "resumeFromReply can reach
here with the EC still `.running`") and the rendezvous `on_cpu` spin
(`kernel/sched/port.zig:2111-2116`). The design deletes both and offers nothing
in their place; "wakers never spin on another core's progress" (§4) is
unsatisfiable for the reply-vs-park race without either a bounded claim-retry
(contradicting §4's letter) or publishing before the rendezvous (contradicting
L1).

### C2 — Retire does not arbitrate with an in-flight wake winner; §8.2's UAF-impossibility claim is false
*(Axis: correctness. §5 edges 10/11, §6.1 S4, §8.2)*

Edge 6's winner CASes `waiting → ready`, **then** writes payload through
`ec.ctx` (which points into the kernel stack), **then** enqueues. Between the
claim and the enqueue the EC is `ready`-in-no-queue (blessed by S1's "or
strictly after, via claim ownership"). Edge 11 lets retire CAS
`ready → retired` in that window and **finalize inline** — free the kstack,
zero the slot — while the winner is mid-`setSyscallReturn` into that kstack.

Interleaving: waker wins claim on core A, is host-descheduled (the tree's own
doctrine: "KVM vCPU preemption breaks every 'visible soon' argument",
`scheduler.zig:163-171`); terminate on core B retires+finalizes inline; core A
resumes, writes payload into freed/quarantined kstack pages and enqueues a
freed slot. Same hole on edge 5→10: waker wins `parking → woken`, retire flips
`woken → retired`, owner's hop finalizes while the waker writes payload.

§8.2's grace rule ("Claim CASes make payload-writing use-after-free
impossible") only forecloses claimants *after* retire, not winners *before* it
— and the bytes-intact window is explicitly identity-only, not `ctx`.
Additionally, if the winner's later "stamp `ready` + link" is a plain store
rather than a re-validating CAS (the doc never says), it resurrects a retired
EC — exactly stygia-qbx (`scheduler.zig:1562-1587`). Today's kernel has the
same race *shape* but with far wider deferral (zombie post → target core's next
`switchTo`); the design tightens finalize to inline and declares the race
impossible. Failure class 8 is therefore **not** fully foreclosed.

### C3 — Cross-EC `suspend` is unmodeled in all three of its legal target states
*(Axis: coverage. §5 / §8.3)*

`suspend` accepts targets in `.running`, `.ready`, and `.idle_wait`
(`kernel/sched/port.zig:430`, re-check at :470; `suspendOnPort`'s assert at
`kernel/sched/execution_context.zig:1620`; the `.ready` arm does
`removeFromQueue` at :1622-1624). In the model:

- **Remote `.running` target:** no edge exists — §2.1 says `running` is
  "claimable by retire only", and edge 3's actor is the owner core. Worse, a
  naive remote CAS to `parking` **livelocks the owner's tick**: rule 3.1(1)
  says a failed claim means "the tick does not dispatch," so the owner core
  would run the suspended-but-still-executing EC forever with every tick
  declining to preempt. A remote-suspend protocol (directive + IPI, owner parks
  at entry check) is required and absent. Today's aftermath machinery for this
  exact case — yieldTo's disowned-current escape (`scheduler.zig:994-1019`) —
  is deleted with only `retired`-entry-check routing replacing it (rule 3.1(3)
  covers retire, not suspend).
- **`.ready` target:** no `ready → waiting` edge exists at all.
- **`.idle_wait` target:** edge 6 lists "cross-EC suspend of an idle-waiter" as
  a `waiting → ready` trigger. That is wrong: the target becomes
  `suspended_on_port` (port queue or reply pin), never `ready`. The real
  transition is a wait-kind change `waiting(idle) → waiting(port)` needing
  arbitration against concurrent retire, and a descriptor write by a non-owner
  — inexpressible under §2.2's ownership rules.

---

## MAJOR

### M1 — The vCPU pre-loop is incompatible with hop-only completion; stranded `parking` vCPUs
§8.1 says the pre-loop "keeps its shape but each vCPU it cycles goes
ready → running → parking(exit_port) → waiting through the standard edges."
Edge 4 (`parking → waiting`) triggers **only** at the hop, and "absent rows are
illegal." The pre-loop cycles N vCPUs without a hop per cycle, and its run-dry
arm *returns* with no hop at all (`scheduler.zig:580-664`, and :690 — "the hop
deliberately happens ONLY on the non-vCPU final dispatch"). Result: cycled
vCPUs stuck in `parking` forever; a VMM's reply claims `parking → woken` (edge
5) then waits for an owner-core hop that never comes. The model needs an
explicit "owner may complete `parking → waiting` inline when it never entered
the EC's kstack / is in scheduler context" rule.

### M2 — The dequeue-for-reply containment move is mis-specified; S1/S2 fail on the doc's own showcase case
§2.1: "a recv's dequeue moves the EC's containment from the port queue to the
reply pin **under the port lock** without any state transition." The reply pin
*is* a minted handle in the receiver's domain; minting requires the receiver's
CD lock, and the canonical CD→Port order forces the pop (port lock) and the pin
write (CD lock, port dropped) into two scopes: `recvInner` drops the port lock
at `port.zig:566` before `deliverEvent`; `mintReply` writes
`sender.pending_reply_holder/domain/slot` at `port.zig:2199-2204` under the CD
lock only. Between them the sender is contained **nowhere** — S1's "`waiting` ⇔
exactly one wait assembly" has a hole, and a retire landing mid-move unlinks
nothing and can finalize under the receiver's pending pin-write. Also, the
receiver writing `reply_holder` into the sender's descriptor directly
contradicts §2.2 ("written only by the EC's own core during
`running → parking`") — as do the E_CLOSED/expiry paths that clear descriptor
fields.

### M3 — Scheduler-context teardown only covers self-delete; the create-failure teardown has no home
§8.2's phase-2 story is "delete(SLOT_SELF) retires the caller EC, hops carrying
the DestroyDeferred." Domain teardown is *also* initiated by
`cleanupPartiallyCreatedCd` (`kernel/caps/capability_domain.zig:591-626`,
called from ≥7 `create_capability_domain` failure arms at
:326/:330/:334/:350/:403/:422/:525), where the caller EC is in a **different,
live** domain and must survive to return the error. Retiring the creator is not
an option; running phase 2 on the park stack requires abandoning a frame that
must be resumed. The design needs either a park-and-resume-with-deferred-work
primitive (never introduced) or must concede EC-context teardown for this path
— reopening abandonability (failure class 2) exactly where it claims deletion.
Mechanically, `DestroyDeferred` (~100+ bytes,
`capability_domain.zig:1194-1216`) also cannot ride the hop's single `u64` arg.

### M4 — The fused fast path breaks the `committed_ec`-deletion and barrier arguments
§2.3 deletes `committed_ec` because dequeue + CAS + `current` write happen "in
one critical section under `core_locks[core]`". The fused 6+2 fast path writes
`current`/`current_ec_gen`/`last_dispatched_core` with **no core lock**
(`kernel/arch/x64/interrupts.zig:1449-1459` step 14; :2593-2603 R-14). Either
the fast path must acquire `core_locks[core]` in asm — feasible, R13 already
spins on it (:2272-2280), but a real hot-path cost the doc never mentions — or
§2.4/§3.4's "`owner_core` written under `core_locks` at dispatch commit" and S7
are false at the fast path, and the barrier prologue can miss a fast-path
in-flight commit stalled by host preemption (the exact hazard
`PerCore.committed_ec`'s comment documents, `scheduler.zig:158-171`). §9.4's
edge inventory is also incomplete: reply R13 additionally implements the
**caller's** `running → parking(requeue) → ready` (bare-reply branch,
:2270-2318) and `running → parking → waiting` (atomic-recv park, :2337-2457)
plus a mid-asm Zig fallback (`replyAtomicRecvSendersFallback`, :2406).

### M5 — "Publish-claimable strictly after the SP swap" has no SP swap to anchor on
The fast path never switches `rsp`: it runs on the outgoing sender's kstack
from entry to `sysretq`. Today it publishes the sender claimable (state +
`on_cpu=0`) at step 12 (`interrupts.zig:1292-1298`), ~5 steps before
`sysretq`, and survives only because the remaining release-build steps provably
never touch `rsp` — and in `ctx_trace`/`ec_log` builds they *do* (`subq $192` +
`call` at :1441-1443, :2585-2587, pushing frames onto the already-claimable
kstack). Satisfying the design's contract requires introducing a mid-asm `rsp`
retarget and moving the outgoing publish after it — expressible on x64, but a
structural rewrite the doc presents as an ordering tweak. aarch64 currently has
**no** IPC fast path at all, which the doc should state.

---

## MINOR

- **m1** — Per-core idle EC has no home in S1. Retained in §2.3 but dispatched
  from the slot without being "popped from this queue"
  (`dequeueOrIdleLocked`, `scheduler.zig:1521-1527`), sits `ready`-in-no-queue
  between dispatches, and *is* enqueued when preempted. S1 needs a carve-out.
- **m2** — Analyzer rule 9.3(2) is violated by the design's own preempt path:
  the tick claims `running → parking(requeue)` then must acquire `core_locks`
  before hopping. Needs scoping to wait-parks.
- **m3** — L2's "preempt heartbeat for a core wedged in user mode": user mode
  takes the wake IPI directly; the heartbeat matters for parked cores
  (`scheduler.zig:1295-1304`). Unified deadline-table capacity (64 futex + 256
  recv, `futex.zig:30`, `port.zig:64`) and its full/E_NOMEM behaviour unstated.

---

## Historical failure classes NOT in fact foreclosed

- **Class 7 (lost wake/enqueue)** — not foreclosed; C1 constructs lost
  rendezvous, lost reply, and lost deadline through the pre-publish window, one
  of them *forced* by the design's own ordering rules.
- **Class 8 (reap while live)** — not fully; C2's finalize races an in-flight
  claim winner's `ctx` write. S3's kstack quiescence is necessary but not
  sufficient for finalize.
- **Class 2 (abandoned teardown frame)** — foreclosed for `delete(SLOT_SELF)`
  and the no-route memory-fault teardown, but **not** for
  `cleanupPartiallyCreatedCd` (M3).
- **Classes 1, 3, 4, 5, 6** — genuinely foreclosed.

## What I attacked and could not break

- **Retire-fusion replacing `parkSelfFaulted`.** Tried to show a spec
  regression (today's odd-gen park keeps handles resolvable). The spec says the
  opposite — `specv3.md:3248`: no-route thread_fault ⇒ "the EC is terminated."
  The design is *more* spec-faithful than today's workaround. Attack failed.
- **`committed_ec` deletion (slow path).** The one-critical-section commit plus
  lock-sweep prologue genuinely closes the KVM-preemption window the field
  papers over. Sound — the residue is only the fast path (M4).
- **`post_park_clear_on_cpu` / stygia-7jm deletion.** Rule 3.1(2) (scheduler
  context never dispatches from an interrupt) removes the skipped-landing-pad
  mechanism at its root; with no flag there is nothing to strand. Could not
  construct a strand. (Note: on x86 the wake IPI *is* the sched vector,
  `arch/dispatch/smp.zig:70-75`, so the SP-range check must land in that
  handler on both arches.)
- **`pending_cross_enqueue` → requeue directive; `pending_kstack_release` → hop
  publish-order; `pending_zombie[64]` → state-word handoff.** Each subsumption
  checked against the field docs and their corpses (`scheduler.zig:187-347`,
  `execution_context.zig:2132-2247`); every case discharges to a named party
  with a bounded trigger. The same-core `postZombie` unsatisfiable-spin
  pathology (1176/1176 measured) is structurally gone. Held.
- **Torn-read class (S6/§3.4).** Every cross-core-readable model fact is ≤ 8
  bytes or CAS-transferred. No new aarch64 tearing shape found (modulo M2's
  descriptor-writer carve-outs).
- **Reply pins crossing into dead domains.** Descriptor-as-data plus SlabRef
  gen re-validation carries over; teardown of a holder-domain mid-abandon is
  caught by the gen. Held.
- **Lost-wake/park decision (L3), heartbeat, `active_root` barrier,
  ack-while-spinning set.** Retained verbatim and correctly classified as
  essential. Held.
- **The doc's factual claims about today's code.** Spot-verified and accurate —
  the single `enableInterrupts()` outside `arch/`
  (`execution_context.zig:2226`), `propagateClosedToSenders` write-before-claim
  drift vs. its receiver twin (`port.zig:2296-2319` vs :2277-2292), the two
  timed registries, the eight-signal inventory, the batch-168 and Pi-5 autopsy
  citations. The document knows the tree well; its failures are in the new
  machine, not in its evidence.

---

## Change before anyone implements

1. **Close the pre-publish window explicitly (C1).** Require the `parking`
   publish inside the final container-lock critical section (today's futex
   discipline, generalized); define waker behaviour on encountering a
   linked/pinned but not-yet-claimable EC — a bounded claim-retry justified by
   L1's bound — and weaken §4's "wakers never spin" to "no unbounded spins";
   resolve the rendezvous ordering contradiction (fallible-first forces the
   reply pin to exist pre-publish) by specifying the reply-side retry; make the
   deadline tick re-register (or claim `parking → woken`) instead of dropping
   the slot.
2. **Specify retire's synchronization with in-flight claim winners (C2).**
   Either defer finalize behind a winner's completed enqueue (a wake-commit
   bit, or finalize handed to the winner on its mandatory re-validating
   enqueue-CAS discovering `retired`), and make the enqueue stamp a CAS that
   aborts on `retired` — in the table, not folded into a §3.4 generality.
3. **Add the missing rows and settle the fast/teardown policy (C3/M1/M3/M4).**
   A remote-suspend protocol (directive + IPI, owner-side park at entry check)
   plus `ready → waiting` and the idle-wait kind-change; a scheduler-context
   inline-completion rule for the vCPU pre-loop; a decision on whether the
   fused fast path takes `core_locks[core]` (with the barrier argument
   re-derived if not); and an owner for the `cleanupPartiallyCreatedCd`
   teardown that doesn't retire the creator.
