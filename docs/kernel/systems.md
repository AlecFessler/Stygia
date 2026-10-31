# Stygia systems: the execution-context lifecycle machine

Status: **design target, revision 16** (2026-08-02). **Revision 16's
systems text is DOC-ONLY — the lifecycle transition relation in
`docs/kernel/tla/ECLifecycle.tla` is the module the revision-15 exit-0
battery ran against.** The later TLA recovery pass changes artifact
coverage (`t1d`/`pr4d`) and the scoping of `LiveSuspender`, not the
state-transition graph. It has two halves.
**First**, it states one premise the domain-pause argument had been
asserting (the quiesced-resume rule, §3.3), fixes which leg of the user
boundary the domain-paused arm is checked on (§3.1 rule 3), and records
the tree obligation both create (§11.13) — all three invisible to a model
that has no domains and no user memory, so this is exactly the shape the
README's parity discipline warns about and its ledger entry is **G12**.
**Second**, it closes **§12's first review**, which the plan FAILED with
five blockers: the domain-wide pause is DEFERRED out of the refactor to
bead `stygia-qap`, `restart_at_entry` is downgraded from "IN, deferred"
to not a design obligation, and steps 1, 3, 4, 5, 8 and 9 are corrected
against the tree. §12 now ends with the closure check that catches the
recurring failure — a mechanism written normatively into §§0–9 and
scheduled nowhere — and running that check found two more.
Review history: round 1
(`docs/kernel/systems-review.md`, UNSOUND — mechanisms; closed in rev 2),
round 2 (UNSOUND but converging — protocols; closed in rev 3), round 3
(UNSOUND — quantifier errors; closed in rev 4), round 4 (UNSOUND — one
wrong condition or un-computed enumeration inside each of three correct
mechanisms, F1–F3, plus majors F4–F6; closed in rev 5), round 5 (the TLA+
model round, `docs/kernel/tla/`: one asserted-but-unenforced ordering N4,
two conditionality gaps N1/N3, plus enumeration repairs; closed in
rev 6), round 6 (adversarial review of rev 6: NO CRITICALS — the N4
mechanism, the retired-but-linked licence, W7, the S7 route and finalize
routing all held; majors M1–M6 on unspecified arms, recall-level
universals, tool-reality drift, and API sufficiency; closed in rev 7),
round 10 (adversarial review of rev 10: three criticals — the IRQ rule
had no re-entrancy arm, §12's step-4 ordering, and the `dropped`
deletion's ABA; closed in rev 11), round 9 (adversarial review of rev 9: FIVE CRITICALS, and the first
round in which NONE invalidated a mechanism — all five were text or
apparatus: `dropped` had no clearing rule and made a target permanently
unsuspendable; `run.sh` could not exit 0 and gated none of the new
falsifiers; two concurrent `priority` calls desync the word from the
bucket key; the IRQ state of EC context was never stated while twelve
arguments depend on it; and domain restart was absent from the machine
entirely. Closed here), round 8 (adversarial review of rev 8: THREE CRITICALS — **C-1** mutual
terminate, a hard two-core deadlock that is LIVE IN THE TREE and that
rev 8 made worse by having no self-terminate carve-out at all; **C-2**
the round-7 priority fix re-opened for `parking(wait)`, the one state
that is already linked — **and C-2 is CLOSED as of revision 13**, since
§8.1's repair uses drop-and-retry and was never actually blocked on a
lock order (§3.5); **C-3** §3.5's lock chain refuted by the tree in its
left edge, and the chain PROJECT retracted in revision 13; plus eight
majors), round 7 (adversarial
review of rev 7: TWO CRITICALS — **C1**, an
unspecified instruction ORDER inside a mechanism that was itself correct
(`pin_depth`'s bump against the acquire it protects, re-opening F3 under
the default implementation), and **C2**, a doc statement contradicting
`specv3.md` §[priority] verbatim; plus majors M-1–M-6 and minors; closed
here). §13 maps every finding to its fix. This revision is CO-EVOLVED with the
model: every normative mechanism here is encoded in
`docs/kernel/tla/ECLifecycle.tla` **except those the README's ledger
names as unmodelled — G9 (`priority` re-bucket), G11 (`dir = "dead"`),
G12 (the whole domain pause, including §3.3's quiesced-resume rule),
G13 (`current_queue_core`) and G14 (`idle_parked` + L3's wake-IPI
rule), and G16 (`teardown_pending` / `TeardownRequest`)** — with no model-invented repair
mechanisms, and the falsification gates (X1–X3, F1 both readings, N4,
e4, and rev 8's `pinord`) each fail when the corresponding fix is
dialed out. **Claim discipline
(round 6 M6): "the battery is green" is claimable only for text that a
full `run.sh` exit-0 has actually run against.** Revision 8 carries three
SEMANTIC deltas (M-2's deletion of the staged destination as placement
authority, M-3's `mark_state` word, C1's `pin_depth` ordering rule with
its new falsifier), so every rev-7 verdict went stale on this edit and
the whole battery was re-run against this exact text; the results table
is the README's. Where this document and the model
disagree, one of them has a bug — fix both, and update the model's
parity table (`docs/kernel/tla/README.md`) in the same change.

**And where this document and `specv3.md` disagree, the SPEC wins and
this document is the bug** (round 7 C2, the worked example: rev 7's
§8.1 said a priority edit of a non-`ready` target "takes effect at its
next placement", while §[priority]'s Description says verbatim that for
a target suspended on a port or waiting on a futex "the new priority
takes effect immediately and reorders the target into the appropriate
priority bucket", with [test 06]/[test 07] testing exactly that). A
genuine spec GAP is a different thing and is recorded as a maintainer
call in §11, never resolved by silently narrowing the machine.

The three normative closure tables introduced in rev 4 — the
interrupt-context wake-source table (§5.1), the retire matrix (§5.2), and
the wait-for graph (§3.6) — are the artifact's verification spine.
Round 4's verdict on them is the operative lesson: T1, the one table
closed against the callgraph DB, survived a hostile independent
re-derivation with zero defects; T2 and T3, closed by recall, contained
all three criticals. Revision 5 therefore converted every remaining
by-recall enumeration into a computed one — the pin-lock class (§2.4,
9.3(7)), the spin inventory (W7–W9, 9.3(6)), the T2 justifications.
Revision 6 is the model round's closure and is governed by one
principle: **the machine must be the simplest one that is correct and
sufficient for the syscall API's EC state changes** — where the model
needed a mechanism the prose merely asserted, the prose acquired the
mechanism (N4), and where the model showed a construct was not
load-bearing, it was deleted (retire's separate unwind step; see §13).
Revision 8 holds the same line and applies it to itself: it deletes the
staged destination as placement authority (M-2), deletes one of the two
mechanisms rev 7 offered for a priority edit (C2), and adds exactly one
new word (`mark_state`) — for a fact that was already being relied on
without one.

Round 7's own lesson, worth naming because it is new in kind: **both
criticals were invisible to the machine-checked battery**. C1 is an
instruction ORDER one level below the model's atomicity, and C2 is a
contradiction with a document the model does not read. Six rounds of
findings came from constructing interleavings; this round's came from
asking what the words permit an implementer to write, and from reading
the spec next to the design. Neither question is answered by running
anything.

Upheld across rounds and not disturbed here: the CAS-word lifecycle, the
hop, retire fused with gen-death, all five per-core mailbox deletions, the
slow-path publish-under-lock C1 fix, `claimed`+S8, the directive protocol's
deadlock freedom, the degenerate hop, M2's holder containment, and F1's
in-lock fast-path publish (verified against the real asm in round 3). This
revision has not yet been re-reviewed; treat it as pending-re-review before
implementation or formal proof.

This is NOT a description of the current tree; it is the machine the code
should converge on. Where today's code is referenced
(`kernel/sched/scheduler.zig`, `kernel/sched/execution_context.zig`,
`kernel/sched/port.zig`, `kernel/sched/futex.zig`,
`kernel/caps/capability_domain.zig`, `kernel/devices/device_region.zig`,
`kernel/arch/{x64,aarch64}/`), it is as evidence of a constraint or as the
mechanism a design step deletes. Normative words (MUST/NEVER/only) describe
the target design.

---

## 0. Scope — normative, and read this before anything else

This document exists to solve **one** problem, stated in §1: the kernel
carries eight overlapping signals for where an execution context is, and
roughly 90% of recent bug fixes were EC teardown or lost wakes. The
machine's job is therefore the **EC lifecycle and every state change that
moves an EC on, off, or between CPU cores.** Nothing else.

Six review rounds have confirmed the mechanism and churned the boundary.
This section is normative so the boundary stops moving.

### 0.1 The test

**Does this affect EC lifecycle or scheduler state — where an EC is,
what core it is on, whether it is runnable?** In scope if yes,
**regardless of which subsystem it lives in**.

The boundary is this test, **not an enumeration** (round-12 refinement).
An enumeration is exactly what drifts: revision 13 wrote one and it
immediately contradicted itself, scoping out three syscalls that ARE the
in-scope primitive eight lines below. Lists below are worked examples of
applying the test, not the boundary itself.

**Err toward inclusion.** Over-tightening hides real defects behind a
boundary, which is worse than carrying a little extra. If a strict
reading would exclude something that has caused or could cause an
EC-lifecycle or lost-wake bug, include it.

**IN, by the test:**

- The **lifecycle word** and its seven states (§2.1).
- **Every transition that moves an EC on, off, or between cores** —
  dispatch, park, wake, claim, requeue, migration, retire, finalize
  (§5's edge table).
- The **wait/wake sources that cause those transitions**: timer, futex,
  port (recv / reply / suspend), the suspend directive, rendezvous,
  device IRQ (§5.1's T1).
- **Teardown and reclamation ordering**, including the kstack hop
  (§4, §8.2).
- **The claim protocol** — who owns an EC in transit (§3.5, §5.2's T2).
- **The domain-wide pause AND its resume** (§0.3) — it moves N ECs off
  cores and then back onto them, which is the test's own definition.
  **IN SCOPE, but DEFERRED out of the §12 refactor to bead `stygia-qap`**
  (maintainer decision, revision 16): it is unimplemented at HEAD,
  unmodelled in the battery, and no migration step depends on it. In
  scope means the design is here and normative; it does not mean this
  refactor builds it.
- **The wakes caused by `revoke`/`restrict`** — a port-refcount cascade
  waking suspended senders with `E_CLOSED` is a wake, so it is in, via
  edge 5a's existing close-propagation trigger. No new edge.
- ~~**`restart_at_entry`** — it makes an EC runnable.~~ **NO LONGER AN
  OBLIGATION as of revision 16** (maintainer decision, §0.3). It WOULD
  make an EC runnable, and the machine will route it when restart
  semantics are built — but the tree implements only the policy plumbing,
  so this listed a scope commitment against a feature that does not
  exist. The test is unchanged; what changed is that there is nothing yet
  for the test to apply to.
- **The invariants that give every EC-lifecycle fact ONE WRITER and ONE
  VALIDITY PREDICATE** (§6, §2.6). **This is the deliverable**, and it
  is worth stating precisely rather than as "provably redundant"
  (round-13): the machine **adds** words — `pin_depth`, `mark_state`,
  `payload_done`, `directive_state`, `teardown_pending`, `cd.paused`,
  and the `pended` state. §2.6 calls that "the honest price" and it is.
  Redundancy is met **literally** for the four signals actually deleted
  (`on_cpu`, `committed_ec`, `pending_zombie[64]` and its three
  companions, both timed registries) and **derivationally** for the
  rest — each survivor now has a named writer, a stated width and a
  validity set, so no reader has to reconstruct a fact by correlating
  several. That is §1's real principle, and the doc should not overclaim
  past it.

### 0.2 OUT — and there are TWO different reasons, never conflated

Conflating these is how the boundary drifts, so each exclusion names
which one applies.

**Reason A — SOLVED ELSEWHERE.** Related to EC lifecycle, but a
different instrument already handles it, and duplicating it here is
extra complexity this machine must not carry.

- **Kernel-wide lock ordering.** `ordered_group` tags, address-ordered
  same-class nesting, and lockdep's dynamic pair-registry cycle
  detection already handle it. **A global static lock order is extra
  complexity the model must not carry** — not because lock ordering is
  unrelated to EC lifecycle (it plainly is related), but because
  another instrument solves it. See §3.5, which retracts the chain
  project revisions 10–12 built and blocked work on.
- **Analyzer capability.** Enforcement is separate work with its own
  instrument. This document states what it ASSUMES is enforced; it does
  not specify how, and no mechanism here is gated on tooling that does
  not exist.
- **Migration sequencing.** §12 is a separate plan; nothing in §§2–8
  depends on its ordering.

**Reason B — GENUINELY DOES NOT TOUCH EC LIFECYCLE OR SCHEDULER STATE.**

- **Capability-derivation mechanics** — which handles `revoke`/`restrict`
  kill, and the derivation-tree walk. (Their *wakes* are IN, above.)
- **VMAR contents and handle-table rewriting** — the address-space work
  itself, as distinct from any EC movement it triggers.
- **`power_sleep`.** Judged on the test rather than by category
  (round-12): the spec says it returns on wake, so it is not terminal —
  but it neither moves an EC between cores nor changes its runnability
  from the scheduler's view. The core idles and resumes the same EC.
  **OUT by reason B**, and §3.6's diagnostics carve-out is corrected to
  say so rather than filing it as terminal.

### 0.3 BORDERLINE, each judged on the test and each stated with which way it lands

- **Domain-wide pause — IN, and routed by a GATE rather than by N
  suspensions (round-13 C-1).** `specv3.md` says verbatim at `:722`,
  `:1894` and `:1952` that `acquire_vmars` / `idc_read` / `idc_write`
  each **pause every EC in the target domain**. Two earlier attempts at
  routing it were wrong: revision 13 said "N applications of the
  existing suspend edge" (does not type-check — every suspend route ends
  in `waiting(port_queue)` and §[suspend] requires a port handle), and
  revision 14 said the pauser "arms N directives" (does not type-check
  either — §2.5's directive has exactly ONE consume arm and it parks
  into a port, while a pause has no port). **`running` was left with no
  route at all**, which is the common case: a debugger pausing a live
  domain.

  **The mechanism is a per-domain gate checked at the user boundary, and
  it touches §2.5 not at all.** No directive kind discriminator, no
  second payload, no new lock class in the park sequence, no change to
  the break disambiguator:

  1. The capability domain carries a **`paused` word** (§3.4).
  2. **Pause entry** CASes the target domain's `paused` 0 → 1 under its
     `_gen_lock`.
  3. **§3.1 rule 3 gains a third boundary arm**: an EC arriving at a
     user boundary whose own domain reads `paused` performs a standard
     edge-3 park into `waiting(domain_pause)`. **On BOTH legs of that
     boundary** — the kernel → user return leg is the one that makes the
     pause a pause, and revision 15 left it to the ambiguity of the word
     "boundary" (§3.1 rule 3, revision 16).
  4. **Resume** clears the word, then 5a-claims each gated EC and places
     it (edge 6).

  **Why this needs no per-state routing on 5a/5c, which is the question
  revision 14 left open.** The gate is on the path back to user code, so
  it catches every EC regardless of the state it was in. A
  `waiting(futex)` target is NOT claimed and NOT left to run: an
  unrelated `futex_wake` makes it `ready`, it dispatches, it runs the
  tail of its own futex return in KERNEL code, and it parks at the gate
  before executing a single user instruction in the rewritten address
  space. Claiming it instead would destroy the futex wait; leaving it
  ungated would let it run user code. **The gate does neither, and it
  does the same thing for every state**, which is why this is smaller
  than the per-state table revision 14 would have needed.

  **That argument has a premise, and revisions 14–15 ASSERTED it rather
  than stating it (round-13 follow-up).** The pauser's predicate covers
  the **runnable subset only**, so the moment it is satisfied the pauser
  proceeds and `acquire_vmars` / `idc_read` / `idc_write` begin operating
  on the address space — and a **later** wake can still make an EC of
  that domain `ready` and then `running`, in kernel code, while that work
  is mid-flight. Everything such an EC executes between the wake and the
  gate therefore runs against an address space that is being rewritten
  underneath it. Revision 15 discharged this with a parenthetical citing
  §3.3, and **§3.3 does not cover it**: §3.3's ban is on user-memory
  access **inside container-lock and gen-lock holds**, and a syscall
  return tail is not inside a hold. The premise is now a rule of its
  own — **the quiesced-resume rule (§3.3)** — with a §9.2 assertion and a
  §9.3(2) analyzer clause, on the standing principle that a premise
  nobody can execute is a premise nobody has checked.

  **The rule is not free, and pretending it was is what the parenthetical
  did.** The tree violates it at HEAD on **both** arches: the dispatch
  tail flushes `pending_event_word` into `[user_sp + 0]` and
  `pending_event_rip` into the vreg-14 slot *after* the CR3/TTBR0 swap
  into the resumed EC's address space and *before* the `iretq`/`ERET`
  (`arch/x64/interrupts.zig:3003`, `arch/aarch64/cpu.zig:555`), with
  SMAP/PAN deliberately cleared for the write — a kernel write to the
  woken EC's user stack on the rendezvous-wake resume path, downstream of
  any gate that could park the EC instead. Recorded as §11.13, which is
  where the implementer's choice lives; it is a real obligation on the
  refactor and not a doc-side flourish.

  **What the pauser actually waits for, which fixes W5-N's contradiction
  with T3 rule (b).** It does NOT enumerate N and it does not hold a
  lock while waiting. It waits on a predicate over the **runnable subset
  only** — no EC of the domain is `running`, `ready` or `parking` —
  because those are the only states from which user code is reachable
  without passing the gate; `waiting`, `claimed` and `pended` are safe
  by construction, since every path from them back to user code goes
  through the boundary. The set cannot grow underneath the wait:
  **edge 1's publish already takes the CD `_gen_lock` in its section**
  (§8.5), so a creation into a paused domain publishes into
  `waiting(domain_pause)` rather than `ready`, serialized by a lock the
  publisher already holds and the pauser does not. So the pauser spins
  holding nothing (rule (b) satisfied) over a predicate that only ever
  decreases.

  **Two refusals make the no-cycle argument real** — revision 14 claimed
  §2.5.1 covered this and it did not, because §2.5.1's mechanism is the
  suspender CASing its *own* directive word and nothing said a pauser
  does that. The domain-level analogue, stated directly:
  - **A pause whose target domain contains the calling EC is refused.**
    A pauser inside the paused set would gate itself at its own
    boundary and never reach its resume.
  - **A pause is refused if the CALLER's own domain is already paused.**
    This is §2.5.1's shape lifted to domains — check your own word
    before claiming another's — and it is what makes mutual pause
    unrepresentable: P1 ∈ D2 pauses D1, then P2 ∈ D1 attempting to
    pause D2 finds D1 already paused and is refused. Without it, both
    pausers sit in kernel frames waiting for targets that can never
    reach a boundary, which is round-8 C-1's shape in a third
    mechanism.

  Both refusals return an E_BUSY-class error. **`idc_read`/`idc_write`/
  `acquire_vmars` have no E_BUSY cause in `specv3.md`**, so this is a
  spec addition and it is recorded in §11.8 alongside `suspend`'s —
  not invented here. A caller that retries must back off; a tight retry
  is a new spin and would need a T3 row, which this design does not add.

  **DEFERRED out of the §12 refactor to bead `stygia-qap` (maintainer
  decision, 2026-08-02), the same treatment `restart_at_entry` already
  carries.** Everything above stays normative and the follow-on will use
  it verbatim — only the MIGRATION STATUS changes. **It has no rows in
  §5.2 and no step in §12**, and the three reasons are:
  1. **It is unimplemented at HEAD, so deferring regresses nothing.**
     DERIVED, not recalled: `memory/vmar.zig:1606`/`:1610` are
     `fn quiesceDomain(cd: *CapabilityDomain) void { _ = cd; }` and its
     resume twin — empty stubs — called from `:795` (`idc_read`) and
     `:873` (`idc_write`), and `acquire_vmars`
     (`caps/capability_domain.zig:860`) has no pause call at all. So
     `specv3.md` `:722`/`:1894`/`:1952` is unhonoured on all three
     syscalls today.
  2. **It is UNMODELLED in the battery** (`docs/kernel/tla/README.md`
     ledger **G12**). Building it during the refactor would repeat
     precisely the mistake the refactor exists to undo — implementing
     against a mechanism no battery has exercised.
  3. **Nothing in steps 1–10 depends on it.** Its own step would sit
     after step 6, needing edge 6 from step 3, the boundary gate from
     4c, and the CD-locked publish arm from step 7.

  **And the follow-on is a RESTRUCTURING, not a stub-fill** — recorded
  here because it is the part that makes this more than a one-line
  scheduling note. `vmar.zig:780` takes `v._gen_lock.lockIrqSave` and
  holds it across BOTH the pause point at `:795` AND the SMAP window at
  `:807` (identically at `:848`/`:873`/`:877`). §3.6 W5-N requires the
  pauser to spin **holding no lock** with `pin_depth == 0`; §9.2
  requires every EC-context spin entry to assert **IRQs enabled**; and
  §3.3's in-hold ban makes `:807`/`:877` violations of §9.3(2) in their
  own right (see §12's note on hoisting them). All three fail at the
  call sites as they stand, so the pause cannot be dropped into them.

- **`restart_at_entry` — NOT A DESIGN OBLIGATION OF THIS MACHINE
  (maintainer decision, 2026-08-02; downgraded from revisions 13–15's
  "IN, deferred").** The machine WILL route it when restart semantics are
  built. Until then it is not an obligation here, and revisions 13–15
  promising it an edge was a commitment to route one value of one policy
  in a feature that does not exist and whose semantics will move when it
  is designed.

  **The tree agrees, and this is DERIVED rather than recalled.**
  `specv3.md` §[restart_semantics] is normative, but the kernel
  implements only the POLICY PLUMBING — `restartPolicyMonotone`,
  `restartPolicyMask` and the create/copy ceiling bounding at
  `caps/capability.zig:346`/`:581`/`:591`/`:604` — and all **eight**
  `tests/suite/cases/restart_semantics_*.zig` cases test `E_PERM`
  ceiling bounding, not restart behaviour. `grep -rn restart_at_entry
  kernel` returns only the enum-value name inside comments. **There is
  no domain-restart implementation anywhere in the tree**, so there is
  nothing for this machine to be consistent with yet.

  **The analysis of what the edge would look like is kept, because it is
  the right answer when the feature arrives** — only its status is
  demoted. It moves an EC to runnable, in **one edge**: claim by the
  state's normal route (5a from `waiting`, 5c from `ready`, the directive
  from `running`), **reset the saved frame to the entry point under the
  won claim**, then place via edge 6. The frame reset under a won claim
  is the only new step. It has no rows in §5, §5.2 or §12, and revision
  14's "plus one T2 row" understated what routing it costs — it is a
  transition with an actor and a failure arm and would need the same
  treatment every other edge got.
- **`persist` — OUT, and this is the closest call in the document.** It
  does not move the EC: the EC keeps running on its core throughout.
  What makes it borderline is that it rewrites the address space under a
  live EC, and `active_root`/W6 IS scheduler state. **Landing: OUT by
  reason B for the rewriting itself, with one obligation retained
  in-scope** — a `persist`ing EC is a running EC whose root is being
  republished, which is precisely the configuration
  `awaitDomainQuiesced` (W6) exists to serialize against. So `persist`
  must either take that barrier or state why it is exempt, and **that
  obligation is in scope even though the rewriting is not.** Recorded in
  §11 rather than designed here.

### 0.4 What an implementer codes against

**§2 (state space), §4 (the hop), §5 (the transition table), §6 (the
invariants), §7 (the failure classes), and the EC-lifecycle parts of §8**
are the implementable machine. They are delimited in the text by the
markers `<<< IMPLEMENTABLE SPEC — BEGIN >>>` and `<<< END >>>`.
Everything outside those markers is context, rationale, review history,
enforcement notes and maintainer calls: useful for understanding *why*
the machine is shaped this way, and **not** something to code against.

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
composite has produced a systematic bug family (§7). The root causes are
three: state is scattered; transitions are not atomic with respect to
preemption; obligations are unassigned.

The design is organized around four principles:

- **One fact, one word, one writer.** Every cross-core-readable fact is a
  single machine word with exactly one writer context. Multi-party
  arbitration is CAS on exactly one word; anything wider is written only
  under CAS-won exclusivity and released with a single-word store.
- **State implies containment.** The lifecycle state *is* the answer to
  "which container holds this EC".
- **Every hand-off is a claim, and every obligation has one named
  discharger.** Any party that takes an EC out of a claimable state wins a
  CAS first, owns the EC exclusively while it works, and re-validates with
  a second CAS at placement. A won claim is never orphaned: claim-holding
  frames are pinned against requeue preemption (§3.1 rule 1) and never
  abandoned by entry checks (§3.1 rule 3). The retire matrix (§5.2) names
  the discharger for every (state × continuation) cell.
- **Exits from `running` complete at the hop**, and interrupt-context
  wakes against a mid-park EC hand their placement TO that hop (`pended`)
  instead of waiting on it — interrupt context never waits on scheduler
  progress (§3.6).

Prefer deleting state to validating it: §2.6 accounts for every one of
today's signals.

---

<!-- ============================================================= -->
<!-- <<< IMPLEMENTABLE SPEC — BEGIN >>>                            -->
<!-- ============================================================= -->

> **<<< IMPLEMENTABLE SPEC — BEGIN >>>**
>
> Everything from here to the END marker is what the refactor codes
> against: §2 the state space, §3 the concurrency substrate, §4 the hop,
> §5 the transition table and its three closure tables, §6 the
> invariants, §7 the failure classes, §8 integration and reclamation.
> Normative words (MUST / NEVER / only) inside this range describe the
> machine to be built.
>
> **§3 is included deliberately, and that is a deviation worth naming.**
> The scope instruction listed §2, §4, §5, §6, §7 and the EC-lifecycle
> parts of §8. §3 is in anyway because §5's edge table cites it
> normatively at nearly every row: edge 3 IS §3.2's park sequence, edges
> 5a/5b/5c are gated on §3.5's R-claim, the requeue arms are gated on
> §3.1 rule 1's pin gate, and T2's unreachable cells are discharged by
> §3.1 rule 3. An implementer handed §5 without §3 cannot code a single
> edge correctly. The cost is that this range is ~1,900 lines rather
> than the ~1,060 of the narrower list; the alternative is a spec whose
> normative citations dangle.
>
> Outside it — §0, §1, §9's enforcement notes, §10, §11's maintainer
> calls, §12's migration plan, §13's changelog — is context, rationale
> and review history. Useful for understanding why the machine is shaped
> this way; **not** something to code against (§0.4).

## 2. The state space

### 2.1 The lifecycle word

```zig
/// u8, CAS-only, written exclusively by kernel/sched/lifecycle.zig
/// (plus the pinned fast-path asm sites listed in §9.4).
pub const State = enum(u8) {
    ready,     // linked in exactly one run queue
    running,   // owned by exactly one core (owner_core); current on that core
    parking,   // owner core is completing an exit-from-running
    waiting,   // parked in one wait episode's containers; claimable
    claimed,   // held by one named kernel path; quiescent-origin hand-off
    pended,    // claimed from `parking`; placement/finalize owed to owner core
    retired,   // terminal; slab gen already dead; awaiting finalize
};
```

**Seven states** (one more than rev 3: `pended` splits out of `claimed`).
The split is round 3's X2/X3 closure: a claim whose origin was `parking`
now records, in the state word itself, that its placement is owed to the
owner core's hop — so no claimant ever waits on a hop, and no wake is ever
declined. Each state is a single-word fact with a defined owner, and every
container membership is implied by the state.

| State | Containment (implied, exact) | Kstack | Who may take it |
|---|---|---|---|
| `ready` | exactly one run queue | quiescent | dispatcher (edge 2), suspender (edge 5c), retire — all under that queue's lock |
| `running` | `core_states[owner_core].current == ec` | owner core is on it | retire (CAS); a suspend **directive** (§2.5) — never a direct CAS |
| `parking` | wait episode's containers already linked, or a requeue directive | owner core is on it | claim (edge 5b → `pended`), retire |
| `waiting` | exactly one wait episode's containers (§2.2) | quiescent | claim (edge 5a → `claimed`), retire |
| `claimed` | none claimable; held by exactly one named holder | quiescent (origin was `waiting`/`ready`) | retire (CAS; discharge stays with the holder) |
| `pended` | none claimable; wake recorded, discharge owed to owner core | owner core still on it until its hop | retire (CAS; discharge stays with the owner's hop) |
| `retired` | wait-container links MAY persist until finalize's leading unwind (§8.2, N4); pop-side skips `stale(ec)` (§9.2) | per §5.2 routing | finalize only |

Today's three wait states collapse into `waiting`; wait flavor is data
(§2.2). `claimed` is the quiescent-origin hand-off (recv pop, cross-EC
suspend of ready/idle, wakes of `waiting` ECs); the holder discharges.
`pended` is the parking-origin hand-off; the **owner core** discharges at
its hop — placement, finalize-on-retired, and any deferred marking — after
the claimant's `payload_done` handshake (§2.2). Because the claim CAS
(`parking → pended`) and the hop's commit CAS (`parking → waiting`) target
the same word, exactly one wins and the hop's failed-CAS re-read cannot
miss a pend: there is no flag-set-after-hop-passed window and no fence is
needed beyond the CASes themselves. (This is why the pend fact lives in
the state word rather than in a descriptor flag.)

`retired` is fused with the slab-gen death mark under the EC's `_gen_lock`
(S5): "`.exited` with an odd gen" — the worst leak in the project's
history — is unrepresentable.

**Why `pended` stays despite firing zero times in measurement** (round 6,
the reverted Phase-3 instrumentation: no 5b claim across nine boots on
both arches at 4 cores, all four wake-side spin sites at zero iterations
— while the `parking` window itself was traversed thousands of times per
boot). The zero is workload timing — the owner core always won the race
to its hop — the same timing-zero class as the wake-side barriers that
were REACHED hundreds of times per boot and entered never. The race is
one adverse tick away in a window exercised constantly, and `pended` is
not insurance against a rare race being harmful: it is the sound
replacement for the only known alternatives — the interrupt-context
release-wait and the same-core decline — which the model's falsifiers
PROVE unsound whenever the race does occur (X2 hard deadlock in 7
states; X3 permanently lost one-shot wake in 4; both machine-checked,
`docs/kernel/tla/run.sh`). Under the simplicity criterion the honest
comparison is `pended` versus a wait or a decline, not `pended` versus
nothing; cutting it re-opens X2/X3 by construction. Removal was
considered and rejected in the rev-6 removal sweep (§13).

#### 2.1.1 ~~The per-core idle EC~~ — WITHDRAWN in revision 16

**There is no per-core idle EC, this machine does not introduce one, and
the tree's arrangement is better than the one this section described.**
Revisions up to 15 said: *"the idle EC's permanent containment is its
core's `idle_ec` slot, which counts as its run queue for S1; a preempt
requeues it to the slot. Never retired while the core lives."* That was a
normative containment rule for a construct nothing builds — found by §12's
closure check, not by reading, after sixteen revisions.

**What the tree actually does, and why it is not a gap to be filled.**
DERIVED — `grep -rn idle_ec kernel --include='*.zig'` (quote the glob;
unquoted it is expanded by this project's zsh before `grep` sees it)
returns exactly three
sites and **none of them is an assignment**: the declaration at
`sched/scheduler.zig:184` (`idle_ec: ?SlabRef(ExecutionContext) = null`),
one read at `:1521`, and a comment at `:1098`. `perCoreInit`
(`scheduler.zig:392`) does not allocate one, so the read at `:1521` is
unreachable and the declaration's own comment — *"Allocated at
perCoreInit; runs `hlt`/`wfi` when the run queue is empty"* — describes a
mechanism that does not exist.

The real mechanism is **`parkAndAwaitIRQ`**, and `:1098` states why it
replaced the idle EC: it *"eliminates the cross-core kstack-sharing bug
where multiple idle cores held stale `gs:0` pointing at the same suspended
EC's kstack and concurrently pushed IRQ frames onto it from kernel mode,
silently stomping each other's saved state"*. A core with an empty run
queue swaps `rsp`/`gs:0`/`TSS.RSP0` to its own **dedicated park kstack**
and `sti`+`hlt`s there. **Building an idle EC to satisfy this section
would regress a fixed bug.** So the section is withdrawn rather than
scheduled, and §12 gains no step.

**S1 is untouched, and this is the part to state explicitly rather than
leave to inference.** S1 says every EC in a valid state is in exactly one
container. The withdrawn text made the idle slot a container so that the
idle EC would have one. With no idle EC there is no such EC to contain:

> **A core with an empty run queue holds NO execution context.** It is
> parked on its own park kstack, which is core-owned storage and not an
> EC container. Idleness is therefore a fact about a CORE, recorded in
> `PerCore.idle_parked` (`scheduler.zig:347`), **not a state of any EC** —
> so it raises no containment obligation at all.

The `idle_ec` field, its unreachable read, and its stale declaration
comment are dead code in the tree; retiring them belongs to a cleanup, not
to this machine, and §12 deliberately does not claim it.

**Not to be confused with the `.idle_wait` EC state or `wait.kind ==
.idle`, which are REAL and unaffected** (§2.2; §11.6 "unchanged"). Those
are what a *user* EC parks in when it executes `wfi`/`hlt` and traps — the
aarch64 EL0 `wfi` trap at `arch/aarch64/exceptions.zig:737` and the x86-64
`#GP`-on-`hlt` path at `arch/x64/exceptions.zig:260` — and `suspend`
accepts such a target (`exceptions.zig:741`, `:759`). That is an EC
choosing to idle, which is nothing like a core having no EC to run.

### 2.2 The wait descriptor

A single struct, `ec.wait`, valid only in `parking`/`waiting`/`claimed`/
`pended`.

```zig
pub const Wait = struct {
    kind: enum(u8) { none, port_queue, reply_pin, futex, idle, requeue,
                     domain_pause },   // §0.3 / round-12 C-1
    port: ?SlabRef(Port),                  // port_queue / reply_pin
    reply_holder: ?*KernelHandle,          // reply_pin (+ domain, slot)
    futex_nodes: ?[*]WaitNode, futex_count: u8,
    deadline_node: DeadlineNode,           // intrusive; §8.4
    deadline_ns: u64,                      // 0 = untimed
    payload_done: atomic bool,             // pended handshake; §2.1, §4.
                                           // Set by the 5b claimant's
                                           // release-store; CLEARED BY THE
                                           // DISCHARGER at placement or
                                           // finalize (round 5 G8: a stale
                                           // TRUE surviving into a later
                                           // episode would satisfy W2/W7
                                           // vacuously and reopen F1)
    // Wake payload staging (event fields, pending_event_word, …) follows
    // the single-owner regime (§3.4).
    // NO staged destination core (round-8 simplicity): M-2 removed its
    // only authoritative consumer, and what was left was a
    // cross-core-readable field with no §3.4 row and no writer
    // discipline — i.e. exactly the kind of signal §1 exists to delete.
    // Every placement computes its destination from the fresh
    // descriptor under the destination queue lock (§4).
};
```

Today's `suspend_port`, `pending_reply_holder/domain/slot`, futex node
fields, and both deadline fields fold in. `kind == .requeue` covers
preemption and affinity migration; deletes `pending_cross_enqueue`.

**`kind == .domain_pause`** (round-12 C-1) is the port-less pause
`acquire_vmars` / `idc_read` / `idc_write` perform (§0.3). It carries
**no port, no event and no reply capability** — which is exactly why it
could not be "N applications of the existing suspend edge": every
suspend route terminates in `waiting(port_queue)` and §[suspend]
requires a port handle. **Its container is the paused domain's EC list,
reached under the CD `_gen_lock`** — the same list §8.2's teardown walk
already iterates, so this adds a wait kind and a use of an existing
container rather than a new container. The design decision is recorded
here rather than left implicit: **no kernel-synthesized internal port.**
A synthetic port would have to be minted, refcounted, torn down on
domain death and made invisible to `recv`, which is more machinery than
a wait kind whose container already exists.

**What is NOT in here** (round 7 M-1, stated because the review read
§8.1's "descriptor write" as creating a fourth `ec.wait` writer):
`ec.priority` and `ec.affinity` are **stable per-EC fields, not wait-
descriptor fields**. They are meaningful in every state, they survive
across wait episodes, and a `running` or `ready` EC has both — so they
cannot live in a struct valid only in `parking`/`waiting`/`claimed`/
`pended`. They get their own §3.4 rows, their own named writer (the
`priority`/`affinity` syscall), and their own reach-and-validate
protocol (§8.1). The writer enumeration below is therefore unchanged
and complete for `ec.wait`, and analyzer 9.3(1)/S2 has a writer to pin
for each of the two new words rather than an unattributed store.

**One genuine `ec.wait` writer IS added, and round 9's M-4 is right that
revision 9 hid it.** C-2 routes `parking(wait)` and `waiting` targets to
a re-bucket that edits the **futex `WaitNode`s the descriptor names** —
and those nodes are `ec.wait` storage (`futex_nodes`), not separate
words. So the enumeration below gains a fourth entry rather than staying
at three: **the `priority` syscall, for the wait descriptor's linkage
keys only, under the reaching container lock with the EC re-validated
inside that hold.** It is narrow and it is disciplined — it writes no
payload, no port ref, no deadline, only the bucket key of a node it
found linked — but it is a writer, it belongs in the list, and S2's
"every fact written only by its named writer context" is only true once
it is listed.

**Writers and the two access rules:**

- Descriptor writers — **four**, not three (round-9 M-4): the EC's own
  core during the park sequence; the holder of a `claimed` EC; the
  claimant of a `pended` EC up to its `payload_done` release-store (after
  which the owner core reads it at the hop); and **the `priority`
  syscall, restricted to the linkage keys of the wait nodes the
  descriptor names, under the reaching container lock with the EC
  re-validated inside that hold** (§8.1's re-bucket — it writes no
  payload, no port ref and no deadline, only the bucket key of a node it
  found linked). **Why the fourth writer does not break S2, stated
  because revision 10 added the writer and left the argument out
  (round-10 M-F): the writers are FIELD-DISJOINT.** The
  descriptor-post-publish rule's writer (§2.2's rendezvous pin window)
  touches `port` / `reply_holder`; the `priority` re-bucket touches
  only `futex_nodes[i].key` and the node's queue position. No field has
  two writers, so "one fact, one word, one writer" survives — but it
  survives by a disjointness that has to be checked, not by the writers
  being separated in time, and 9.3(1)'s writer-set pinning must be
  expressed per FIELD here rather than per struct.
- **Saved-frame region ban (absolute).** After the wait-park publish,
  nobody but a claim winner touches the EC's saved frame. The parking
  core's own event staging (the §[event_state] GPR snapshot) completes
  *before* the publish (§3.2 step 1).
- **Descriptor post-publish rule (scoped).** The parking core may access
  its descriptor after the publish, until its hop, **iff** the access
  completes inside the lock section that gates the new reachability route
  it is creating (the receiver-CD hold for the rendezvous pin). This rule
  carries an assumption that must stay explicit (round-3 repair): during
  the pin-write window the sender has **no pre-existing reachability
  route** — in particular no deadline registration. That holds because
  `suspend` is untimed by spec; a future timed suspend would have to
  register its deadline *after* the pin write, or the deadline tick could
  claim the EC while the owner is still writing the descriptor.

A claim winner's payload write into the saved frame is legal while the
parking core still executes lower on the same kstack — the ban is what
makes it so. `payload_done` (release-store by the claimant,
acquire-spin by the owner's hop) is the only claimant→owner handshake;
single-producer/single-consumer, one direction, no SB hazard.

### 2.3 Per-core words

```zig
pub const PerCore = struct {
    run_queue: EcQueue,            // under core_locks[core] as today
    current: ?*ExecutionContext,   // ONE naturally aligned pointer word
    active_root: atomic u64,       // publish-after-load, as today
    idle_parked: bool,             // park decision, under core_locks[core].
                                   // THIS is where idleness lives — it is a
                                   // fact about the CORE, not a state of any
                                   // EC (§2.1.1, revision 16)
    park_stack: Stack,             // the idle core parks HERE, via
                                   // parkAndAwaitIRQ — core-owned storage,
                                   // NOT an EC container (§2.1.1)
    // idle_ec: REMOVED in revision 16 with §2.1.1. There is no per-core idle
    // EC: the field is never assigned at HEAD and its one read is
    // unreachable, and re-introducing one would regress the cross-core
    // kstack-sharing bug `parkAndAwaitIRQ` fixed (scheduler.zig:1098).
    teardown_pending: ?TeardownRequest, // §8.2; self-produced, self-consumed
};

pub const TeardownRequest = struct {
    kind: enum(u8) { self_delete, no_route_fault },
    cd: SlabRef(CapabilityDomain), // held from validation through phase 2
};
```

- `current`: written at exactly two sites (dispatch commit under
  `core_locks[core]`; the hop, §4 step 1). Single-pointer-word layout
  retained; the Pi-5 tearing autopsy is the permanent justification.
- `active_root` + `awaitDomainQuiesced`: retained unchanged.
- `committed_ec`: deleted (slow path: one critical section; fast path
  brought under the core lock, §9.4).
- `teardown_pending`: carries the self-delete teardown request across the
  hop (the payload cannot ride the hop's single `u64`). Revised per M-A:
  it now carries the **CD ref for the whole teardown** — dead-mark
  included — not a post-dead-mark snapshot (§8.2). The producing EC stores
  exactly one `TeardownRequest` before self-retire; the park-stack consumer
  clears it before phase 1 and owns both teardown phases from there.
- `pending_zombie[64]`, `post_park_clear_on_cpu`, `pending_kstack_release`,
  `pending_cross_enqueue`: remain deleted; three reviews attacked these
  deletions and they held.

### 2.4 `owner_core`, `pin_depth`, and `mark_state`

**`owner_core`** (one byte): valid only in `running`/`parking`/`pended`,
plus `retired`-pre-finalize **only when the retire's from-state was one
of those three** (round 6 minor: a claimed-origin retiree has NO valid
`owner_core` — T2's claimed row forbids reading it, and the validity set
as previously written contradicted that); written under
`core_locks[core]` at dispatch commit. The `claimed`/`pended` split makes the validity set exact: a
`claimed` EC (quiescent origin) has NO valid `owner_core` and no rule may
read it (round-3 repair — rev 3's retire routing implicitly read it for
claims from `waiting`); a `pended` EC's `owner_core` is valid by
construction (the state only exists between the claim and that core's
hop). Debug builds poison it outside the validity set.

**`pin_depth`** (one byte — round 3 X1; membership corrected round 4 F3;
**membership RE-DERIVED AGAINST HEAD in revision 12, round-11 C-2**):
a per-EC count of held claims plus held **pin-class locks**, where the
pin class is **computed, not named**: every lock class with at least one
EC-context acquire site **in which a tick can land** is a pin class
(analyzer rule 9.3(7)). **"In which a tick can land" is the
EFFECTIVE-MASK reading and it is normative** — see the blockquote below.
Revision 16 left this sentence in its old SYNTACTIC form ("an acquire
site that is not IRQ-saving", i.e. is the call `lock()` or
`lockIrqSave()`?) while the blockquote declared effective-mask normative,
so an implementer reading top-down built the reading revision 14 got
wrong (round-14 N-5).

> **Re-derivation result — ANSWER FIRST, because this blockquote is what
> step 4's class set is derived from and revisions 14–15 buried the
> conclusion three paragraphs below its own refutation. Under the
> normative EFFECTIVE-MASK reading (stated at the end of this
> blockquote), THE PIN CLASS IS EMPTY AT HEAD.** The two classes this
> document once NAMED are gone from the set; the gen-lock classes look
> like members under the *syntactic* reading and are not members under
> the effective one; revision 14's "tree defect" is withdrawn and there
> is nothing to convert. Everything below is how that answer was reached
> — read it for the method, not for a different verdict.
>
> **Step 1 of that derivation: the two named classes.** §2.4 stated as
> fact that `SlabAllocator.lock` and the kstack
> `freelist_lock` are "plain `lock()`". Verified at HEAD: their acquires
> are `secure_slab.zig:507, :669, :718` and `stack.zig:185, :204, :234`,
> and **every one is `lockIrqSave`**; both carry in-tree comments reading
> *"Always taken with `lockIrqSave`, never plain `lock`"*; they were
> converted in commit `f1215bbf5`, *"memory: mask IRQs at every acquire
> of four IRQ-reachable lock classes"*, after lockdep's IRQ-mode-mix
> check caught the hazard live. **The tree fixed this before the
> document noticed**, and the cited line numbers were stale.
>
> **Step 2: the gen-lock classes, and this is where the reading
> matters.** Under the SYNTACTIC reading the gen-lock classes are
> in the set, via plain `SlabRef.lock()` at genuine EC-context sites —
> `vm_runloop.zig:73` and neighbours, on both arches. The third clause
> (§2.4) forbids pin-counting them, because they are IRQ-reachable. **A
> rule about what the code MUST DO is not a filter that empties the
> computed set**: the set is what the analyzer computes from the tree as
> it is, and the third clause is the obligation that tree then violates.
>
> **Step 3, and the one that settles it: which reading the computed rule
> uses — CALL FORM or EFFECTIVE MASK. This is the durable question and
> revision 14 got it wrong by applying the syntactic one (round-13).** Revision 14 read "non-IRQ-saving
> EC-context acquire site" **syntactically** — is the call `lock()` or
> `lockIrqSave()`? — and concluded that `vm_runloop.zig`'s plain
> `SlabRef.lock()` puts the gen-lock class in the set, making it a tree
> defect. **The analyzer applies the EFFECTIVE reading**: can a tick
> land inside this hold? And it cannot: `enterGuest`'s only caller
> brackets it in `saveAndDisableInterrupts`/`restoreInterrupts`
> (`scheduler.zig:598` / `:618`), and `check_gen_lock` rule (c2)
> already carves the site out — **and by a stronger argument than "by
> name", which is what revision 16 wrote (round-14 N-5).** Rule (c2) is
> an **interprocedural greatest fixpoint** over call sites
> (`tools/check_gen_lock/src/main.zig:2930-2960`): a function is in
> masked context iff it has at least one IR caller and EVERY call site
> either sits inside its caller's bracket or comes from a caller that is
> itself in masked context, computed optimistically and falsified so that
> a call cycle whose every entry is masked stays masked. **The tool is
> stronger than the document said**, and that matters here specifically:
> it is the evidence that effective-mask membership is COMPUTABLE at all
> rather than a reading only a human can apply. A by-name carve-out would
> not generalise past the one site; a fixpoint does.
>
> **Normative: §2.4's computed rule is the EFFECTIVE-MASK reading** — a
> class is a pin class iff a tick can land in one of its EC-context
> holds. That is the reading 9.3(7) implements and the one T2's ready×K
> cell needs, since the cell's question is precisely "can this frame be
> requeue-preempted mid-hold". Under it the vCPU sites are NOT in the
> set, **revision 13's "the class is empty at HEAD" is correct, and
> revision 14's "tree defect" is withdrawn** — there is nothing to
> convert. (Revision 14 also prescribed converting them to
> `lockWithGenIrqSave`, which would not have compiled: that is a method
> of `GenLock`, not of `SlabRef`; the `SlabRef`-level equivalent is
> `lockIrqSave`, with a different return shape.)

**What that does and does not invalidate — this is a finding, not a
failure, and most of the machinery gets STRONGER:**

- **§5.2's `ready × K` justification is discharged, and under the
  effective-mask reading the masking arm alone does it** (round-13
  restores revision 13's position, which round 12 had overturned on the
  syntactic reading). Every class either masks at every EC-context
  acquire or is effectively masked there, so an IRQ-masked section
  cannot span a tick and a requeue-preempted frame holds no lock. The
  two-arm dichotomy remains the normative statement — it is what
  constrains any FUTURE member — but no member exists today for the
  pin-counted arm to carry.
- **`pin_depth` remains fully load-bearing, because it counts CLAIMS.**
  The lock half of the class is empty; the claim half is not, and X1 is
  a claim defect. The requeue gate (§3.1 rule 1), C1's ordering rule,
  `InvNoPreemptedLockHolder` and the `pinord` falsifier all keep their
  content on the claim side.
- **§2.4's third clause and C1's ordering rule are retained as STANDING
  RULES over a currently-empty set.** They constrain any future member,
  and the analyzer computes membership per build — which is exactly why
  membership was made computed rather than named in F3. A rule with no
  current members is not vacuous; it is the thing that stops the next
  `stack.freelist_lock` from being introduced unmasked.
- **The model's `PINLOCK_ON` therefore models a HYPOTHETICAL member**,
  and the README says so. Its value is that it keeps the gate honest if
  the class ever becomes non-empty.
- **§12 step 4's constraint stands**, since it constrains the class
  rather than today's membership.

Incremented at claim-win and pin-class
acquire; decremented at discharge/release. Written only by the EC's own
core in EC context, read only by that core's tick — same-core, no
atomics. The requeue gate (§3.1 rule 1) requires `pin_depth == 0`.
Interrupt-context claim bodies do not touch it. Assert: `pin_depth == 0`
at every hop and at every wait-park publish; debug lockdep bumps and
checks it at pin-class sites.

**Ordering — normative, and the whole point of the counter** (round 7
C1; rev 7 said only "incremented at … acquire; decremented at
discharge/release" and never ordered the bump against the acquire):

> **The increment PRECEDES acquisition of the thing it protects, and the
> decrement FOLLOWS that thing's release or discharge.** Concretely:
> `pin_depth += 1;` then the pin-class `lock()`; and `unlock()` then
> `pin_depth -= 1;`. For a claim, the bump is executed **inside the
> IRQ-masked reaching-lock section that performs the claim CAS**, and
> the decrement follows the placement/discharge.

Why this is not a stylistic preference: **pin-class locks are by
definition not IRQ-masked at their EC-context acquire sites** — that
property is exactly what puts a class in the set. So `lock();
pin_depth += 1;`, which is the default thing an engineer writes, leaves
a live preemption point between the two instructions. A tick landing
there reads `pin_depth == 0`, passes the §3.1 rule-1 gate, wins the
`running → parking(requeue)` CAS, and requeue-preempts a frame that is
**holding the slab-class lock**. Every other allocator then spins
IRQ-masked (W1) on a class whose holder sits `ready`; if that holder is
queued on a core that is itself spinning, it is a hard deadlock. Worse,
T2's ready×K cell would inline-retire that frame on the justification
"a requeue-preempted frame holds no lock at all" — which the window
makes false. The same reasoning gives the two mirror windows: a
decrement before the `unlock()`, and a claim-side bump taken after the
reaching container lock is dropped. All three are closed by the rule
above; §9.2 asserts it.

Model status, stated so nobody over-reads a green run: the pin-class
half of this rule is machine-checked — `PIN_BUMP_FIRST = FALSE`
reproduces `lock(); pin_depth += 1;` and violates
`InvNoPreemptedLockHolder` (T2's ready×K justification as an invariant)
in four states. The **claim-side** half is NOT: a claim CAS happens
inside an IRQ-masked container-lock section, which the model represents
as a single atomic action, so placing the bump inside that section is
true by construction there and the model cannot see an implementation
that puts it outside. That half rests on this sentence and the §9.2
assert.

**`mark_state`** (**one bit**: deferred marking owed / not owed —
collapsed from a tri-state in round 8, because nothing ever needed to
distinguish "never owed" from "owed and discharged"; round 7 M-3). Rev 7
carried the deferred-marking obligation (§5.2's marking column, W4, L5)
as prose only — no descriptor row, no per-core word, no §3.4 row —
despite its being a cross-core, multi-party fact: the **retirer** says
it is owed, a **different core's discharger** says it is done, and a
**third core's terminator** waits on it. "One fact, one word, one
writer" is this document's first principle, so the fact gets a word:

```zig
mark_state: atomic u8,   // ONE BIT: deferred marking owed / not owed
```

- **Retirer** (edge 9, inside the retire CAS's own `_gen_lock`
  exclusivity) leaves the bit CLEAR for the eager rows (`ready`,
  `waiting`, `running`, pin-free `parking`) and SETS it for the deferred rows
  (`claimed`, `pended`, pin-writing `parking`) — one store, under
  exclusivity won by the CAS, exactly as §1's principle licenses.
- **Discharger** — the single party the §5.2 matrix names for that cell
  — CLEARS the bit with a **release-store** at its placement or
  finalize.
- **Terminator** (W4/L5) **acquire-loads** it, and returns only on
  `≠ owed`.

This is the same single-producer/single-consumer, one-direction
hand-off as `payload_done`, and the two writers are disjoint in time by
construction: the discharger's store is enabled only by its own
observation of the bit SET, which only the retirer can have done. W4's
boundedness argument in §3.6 assumed that acquire/release pairing
silently; it is now stated. Finalize asserts the bit is CLEAR
when it completes (§9.2).

### 2.5 The suspend directive

`running` is unclaimable except by retire. Cross-EC `suspend` of a
running target delegates via the CAS-won-exclusivity pattern:

```zig
directive_state: atomic u32,       // packed { state: u8, owner_slot: u24 }
                                   //   state values:
                                   //   none | suspending | claiming |
                                   //   armed | failed | dead
directive_result: atomic i64,      // owner publishes before armed→failed;
                                   //   meaningful only while state is
                                   //   failed; matching waiter reads it
                                   //   before acking failed→none
directive_port: SlabRef(Port),     // written only between claiming and
                                   //   armed; READ ONLY BY THE OWNER at
                                   //   its boundary check. The suspender
                                   //   never reads it back — it holds its
                                   //   own reference to the port it armed
                                   //   with (§3.4, round-10 C-D)
```

- **Suspender**: enters with `pin_depth == 0` — the W5 wait below is a
  spin, and T3 rule (b)'s spin-entry assert applies to it normatively
  (round 5 N1; see the deadlock-freedom paragraph at the end of this
  section). CAS `none → claiming`; write `directive_port`;
  **CAS `claiming → armed`** — a CAS, not a store (round 5 G-D1): if
  finalize set `dead` (or the slot was recycled; gen-stale) between the
  claim and the arm, the arm CAS fails and the suspender returns E_TERM
  without writing a freed slot's word; wake IPI; then run the **terminal
  re-check/disarm loop** (round 3 M-B; loop form per round 4 F5 — rev 4
  ran a single re-check *before* the left-`running` wait and never again,
  so a target still `running` at re-check time could then park into an
  unrelated futex wait, satisfy "left `running`", and leave the armed
  directive pending unboundedly behind that wait — the exact shape the
  re-check was added to remove):
  repeat { if `directive_state == (failed, me)` → read
  `directive_result`, CAS `failed → none`, and return that error; if
  `directive_state != (armed, me)` → break
  (consumed, terminated/reused, or superseded; disambiguated below); if
  the target's state is not `running` → CAS `(armed, me) → none` to
  disarm — on success, re-dispatch by the target's settled state
  (`ready` → 5c; `waiting(idle)` → 5a; `parking`/`pended` → transient,
  re-read, L1-bounded; other waits → a state-gate error whose CODE IS
  UNRESOLVED — specv3 §[suspend] licenses E_INVAL for exactly three
  causes, none of which covers a target blocked in a futex/recv/reply
  wait (round 6 M5, kernel bead `stygia-uyd`; §11.4);
  `retired` → E_TERM); on disarm failure, loop; — else keep
  waiting (lock-free, preemptible, W5) }. **The wait is NOT bounded**
  (round 7 minor; rev 7 still said "bounded" here, contradicting its own
  §3.6): W5 terminates under §3.6's two stated assumptions, and an
  assumption is not a bound. §11.7's alternative — cap the loop at K
  re-checks and disarm unconditionally — is the version that would make
  the word "bounded" true, and it is a spec call because it changes
  §[suspend]'s return semantics.
  **The loop breaks when the word is no longer MY ARM, never on a value
  comparison** (revision 11, round-10 C-D + M-A, **corrected in revision
  12, round-11 M-0** — this bullet bolded an EPOCH through revision 11,
  forty-four lines above the text proving an epoch is itself an ABA, so
  an implementer coding from the bullet wrote the refuted mechanism.
  That is the second revision running in which this bullet, which reads
  like the loop body, prescribed something the section below disproves).

  Why the value-based version is wrong: deleting `dropped` (round-9 C-1)
  made the owner write `armed → none` for BOTH consumption and a
  stale-port drop, and directive exclusivity holds only while the word
  is non-`none`. So the word is an **ABA**. Two concrete failures, both
  in a window a full quantum wide (the W5 spinner is unpinned and
  requeue-preemptible by §3.3):
  1. A arms B with port P; P dies; B drops (`armed → none`); C claims B
     (`none → claiming`); **A reads `claiming` and returns SUCCESS** for
     a suspension that was never delivered. Revision 10 repaired the
     `none` observation and left `claiming` — which §2.5 defines as a
     proxy for *having passed through `none`* — inheriting the exact
     ambiguity that was just repaired.
  2. A arms B; B drops; C arms B afresh; **A's disarm CAS fires on
     `armed` and disarms C's directive.**

  Neither is fixable by enumerating values, because the information the
  suspender needs — *did MY arm end?* — is not in the value. The word
  therefore carries the **identity of the suspender that placed the
  current arm**, packed so the CAS stays single-word:

  ```zig
  directive_state: atomic u32,   // { state: u8, owner_slot: u24 }
  ```

  - `owner_slot` is the claiming suspender's slab index, installed by the
    winning `none → claiming` CAS, retained through `armed`/`failed` so
    only the matching waiter can ack, and zero whenever the state is
    `none` or `dead`.
  - **The suspender's disarm CAS is on `(armed, me)`**, so it can never
    disarm an arm it did not place — closing failure 2 by construction.
  - `dead` is still mapped to E_TERM **when it is observed**, but the
    machine must not DEPEND on observing it: the zero is a race the
    suspender loses whenever it is preempted, which §2.5 measures as
    the common case rather than the rare one.
  - **Its loop breaks iff the word is no longer `(armed, me)`**,
    whatever the state value is — closing failure 1, and closing it for
    `claiming`, `none`, a re-armed `armed`, and any value added later,
    because the test is on *ownership of the current arm* and not on an
    enumeration. The exception is `(failed, me)`: that is an owner-side
    consume-failure terminal for this arm, not success. The waiter reads
    `directive_result` while the word is `(failed, me)`, acks
    `failed → none`, and returns the published error. `directive_result`
    may remain stale outside `failed`; no success path reads it. `dead` is
    still E_TERM.
  - Having broken, the suspender runs a **TWO-PART disambiguator**
    (round-11 C-1; revision 11 had only the first part and that is a
    live defect):
    1. **the gen of the PORT reference it armed with** — its own
       reference, not a read of `directive_port`, which is what lets
       `directive_port` stay owner-read-only (§3.4). Stale ⇒ the
       suspension was dropped, not delivered.
    2. **the gen of the TARGET's `SlabRef`** — stale ⇒ **E_TERM**.

    **Why part 2 is mandatory, and why `dead` cannot carry F6's meaning
    on its own.** §5 edge 10 and §8.2 order the release body to write
    `directive_state → dead` and then, *a few steps later in the same
    routine*, `slot zero + freelist`. And `none` MUST be the all-zeroes
    encoding — otherwise a recycled slot reads non-`none`, its
    `none → claiming` CAS fails forever, and the EC is permanently
    unsuspendable, which is round-9 C-1 exactly. **So the zero converts
    `dead` back to `none`.** Trace: A arms B; A is requeue-preempted
    (§2.5 measures this window as a full quantum); B is terminated,
    finalized and zeroed; A resumes, reads `none`, re-validates the port
    — alive and unchanged — and returns **SUCCESS** where the correct
    return is E_TERM. That is round-4's F6 re-opened by a later step of
    its own edge-10 row, and it makes both this section's *"`dead` is
    still E_TERM"* and §3.4's *"terminal `dead` distinguishes retired
    from consumed"* false in the presence of the zero. The target-gen
    check is what restores F6's guarantee without requiring `dead` to
    survive a routine that zeroes the slot.

  **Identity rather than an epoch, and that is a MODEL RESULT rather
  than a preference.** Revision 11 first specified exactly the obvious
  thing — an epoch bumped on every transition out of `armed`, with the
  suspender snapshotting it at arm. TLC refuted it: **a bounded epoch is
  itself an ABA.** A `drop → claim → arm` cycle bumps it, and the model
  wrapped a 2-bit epoch in four bumps and violated the ownership
  invariant. An 8-bit epoch wraps in 256 — and the W5 spinner has **no
  bound at all** (this section terminates by assumption, not by a
  count), so 256 cycles is reachable rather than theoretical. Identity
  does not wrap: **the suspender is a live EC for exactly as long as it
  is spinning, so its own slab slot cannot be recycled underneath it.**
  The falsifier is `diraba`; `dirabafix` is the same scope with the
  ownership test dialed in.

    (Rev 4 cleared to `none` at finalize, making a dead target
  indistinguishable from a delivered suspension; round 5 G-D3 added the
  `claiming` case; revision 11 subsumes both — arm ownership makes the
  value enumeration irrelevant to the break decision.)
- **Owner core**: consumes at a user-boundary entry check only (§3.1 rule
  3): acquire `(armed, owner_slot)` → gen-validate the port (**stale or
  otherwise unable to consume ⇒ publish `directive_result`, CAS
  `(armed, owner_slot) → (failed, owner_slot)`, and deliver nothing; the
  matching SUSPENDER acks `failed → none` and returns the error**) →
  standard edge-3 park into the port with the snapshot from its fresh
  **user** trap frame → reset `none` **atomically with the edge-3
  publish** (the park's commit point; round 5 G-D2 — a post-hop reset
  would leave a window where a suspender's disarm CAS wins against an
  already-consumed suspension and misreports E_INVAL).
- **The stale-port drop, resolved by DELETION** (round-8 M-3 introduced a
  fourth terminal `dropped`; round-9 C-1 showed it was both incomplete
  and unnecessary, and it is gone). Rev 8 wrote "stale ⇒ drop" and left
  the word's fate unstated, which is genuinely wrong in both readings:
  leaving it `armed` spins the suspender forever, and clearing it to
  `none` — which §2.5 defines as *consumed* — reports SUCCESS for a
  suspension that was never delivered. Rev 9 added a `dropped` terminal
  and **inherited `dead`'s "never cleared" property without `dead`'s
  justification**: `dead` is written by finalize on an EC being freed, so
  never clearing it is correct there; `dropped` sits on a LIVE EC, so a
  single stale-port drop would leave every future suspender's
  `none → claiming` CAS failing forever and the EC **permanently
  unsuspendable** — reachable by ordinary means (arm a directive, destroy
  the port, let the target reach its boundary) and leaving the EC
  undebuggable for the rest of its life.

  The current protocol keeps `dropped` deleted but no longer collapses
  stale/bad-port owner failure into the success-like `armed → none`
  write. The owner publishes `directive_result`, CASes
  `(armed, owner_slot) → (failed, owner_slot)`, and the matching waiter
  reads the result while the word is still `failed`, acks `failed → none`,
  and returns the error. It does **not** clear `directive_result` after the
  ack: clearing the word and result cannot be made one atomic update, so
  the result is authoritative only while `directive_state` is `failed` and
  may be stale otherwise. What the deletion still buys: no stuck stale
  terminal and no E_CLOSED-class invention; what `failed` adds is the
  missing result path that prevents an owner-side consume failure from
  being reported as suspend success. The word's full state set is now
  **six** values: `none | suspending | claiming | armed | failed | dead`.
  Retire supersedes; finalize clears. A racing suspender's failed CAS
  surfaces the spec's E_BUSY-class state-gate error.

#### 2.5.1 Suspend cycles — rejected, not survived (round 7)

**The observation that motivates this.** Both of the model's directive-path
liveness findings are the SAME shape. N1: two suspenders in the W5 wait,
each holding a pin-class lock, each unpreemptible under the pin gate — a
hard cross-core deadlock. N6: two suspenders, one stalled in a kernel
frame at the `claiming → armed` step, phase-locked so neither reaches the
user boundary at which a directive is consumed — a livelock. Self-suspend
is trivial (the caller is at a user boundary by definition). Third-party
suspend is bounded by rule 3 at one unpinned tick. **Symmetric suspension
is the only shape that breaks**, and revision 8 REJECTS it rather than
surviving it by assumption.

**Why the obvious mechanism does not work.** "CAS the target's directive
only if it has not named me" is wrong: the two intents live in **two
different words** — A arms B's directive, B arms A's. A single CAS covers
one location, so A's CAS on B's word and B's CAS on A's word can both
succeed concurrently. The check A needs ("has B armed *me*?") reads **A's
own** word while A's action writes **B's**. Any correct mechanism must
make a two-word check-and-act indivisible.

Two mechanisms do that. Both are encoded and machine-checked
(`CYCLE_REJECT` in `docs/kernel/tla/ECLifecycle.tla`); the model's verdicts
and the reason the second is recommended are in the README.

**(A) Pair-locked rejection** — the round-7 maintainer proposal:

> Acquire **both** EC gen locks, **lowest slot index first**. If the
> target's directive already names the caller, return an E_BUSY-class
> cycle error. Otherwise arm. **Release both locks. THEN enter the W5
> wait.**

The release-before-wait ordering is load-bearing: a suspender that spins
while holding locks is exactly N1, and T3 rule (b) forbids it. Verified:
mutual suspend becomes unreachable at 2×2 with all features, and with the
check dialed out it is reachable in a handful of states.

**(B) Self-mark rejection** — recommended, and strictly stronger:

> The suspender first CASes **its own** directive word `none →
> suspending`; only then does it CAS the target's `none → claiming`. A
> word that reads `suspending` is not claimable. **The self-mark is held
> for the WHOLE syscall** — through the arm and through the W5 wait —
> and is released only as the call returns (on success, on the
> CAS-2-failed E_BUSY arm, and on E_TERM alike).

One extra value in an existing word, two single-word CASes, **no second
lock and therefore no lock ORDER at all**. The correctness argument is
one sentence:

> **A cycle requires every participant to be both suspender and target;
> the self-mark makes those mutually exclusive.**

Where (A) closes 2-cycles, (B) closes the class — for cycles of every
length, without detecting cycles at all.

**Exactly what it rejects — three cases, not one** (stated because only
the first is "symmetric suspend", and a reader should not have to derive
the other two):

1. `A` suspends `B` while `B` is suspending `A` — the symmetric case
   that produced N1 and N6.
2. `A` suspends `B` while `B` is suspending some unrelated **third** EC
   `C` — no cycle exists, and it is still refused.
3. `A` suspends `B` while some third EC `C` is suspending **`A`** —
   `A`'s own word is not `none`, so `A`'s self-mark CAS fails.

**Consequence for the E_BUSY rate, which is userspace-visible and must
not be discovered in production.** Because the mark is held across the
W5 wait rather than only across the two CASes, **any two overlapping
cross-EC suspends of running targets can produce an E_BUSY, whether or
not a cycle exists.** E_BUSY is therefore an EXPECTED outcome of
concurrent suspends, not a pathological one: a debugger or supervisor
that suspends ECs from more than one thread must be written with a retry,
and the retry is a deliberate part of the API contract rather than
something its author discovers under load. §11.8's proposed spec text
says so.

**The narrower alternative, considered and not taken.** Releasing the
mark immediately after the target-claim CAS succeeds would make E_BUSY
vanishingly rare (the window is a few instructions). It also appears to
remain correct, by a longer argument: a claimed EC cannot self-mark
(its word is `claiming`/`armed`), and in any cycle every participant is
claimed, so no participant could have started a suspend. That argument
is sound as far as it has been checked, but it is a multi-step
reachability claim about a state this document has been wrong about
before, whereas the held-for-the-whole-syscall rule is the one-sentence
invariant above and is what the model actually verifies. **If the
E_BUSY rate turns out to matter in practice, the early-release variant
is the optimisation to evaluate — and it needs its own model run
before it is adopted, not a paragraph.**

**Why (B) is recommended over (A) — two findings, both verified:**

1. **(A)'s lock order is an AB-BA against the existing tree.** The x86-64
   fast-suspend asm path already nests two EC gen locks —
   `receiver_ec` (`interrupts.zig`, Step 9.5) then `sender_ec` (Step 9.7),
   held together until Step 12.5 — and it orders them **by role, not by
   index**. Whenever `slot(sender) < slot(receiver)`, a slot-index rule
   takes the same pair in the opposite order. Today the two sites cannot
   contend (the fast path's receiver is `waiting` when its lock is taken,
   while BOTH of (A)'s ECs are `running`), so there is no reachable
   AB-BA — but that is a recall-closed universal over two code paths,
   which is the exact failure mode this document's own history says to
   distrust. Worse, the tree's comment there claims the site is tagged
   `ordered_group=2 (EC_NESTED_GROUP)`, **and that constant does not
   exist anywhere in `kernel/` or `tools/`** — the same
   tool-reality drift round 6's M2 catalogued. (B) takes no second lock,
   so the question does not arise.
2. **(A) does not close 3-cycles; (B) does — measured, not argued.** The
   check in (A) is pairwise, and a 3-cycle (a suspends b, b suspends c,
   c suspends a) passes every pairwise test individually. At 2 cores × 3
   ECs the model reaches one in **14 states** with (A) enabled
   (`InvNoSuspendCycle3` violated: `e1.dsrc = e3, e2.dsrc = e1,
   e3.dsrc = e2`, each suspender requeue-preempted in `dirC` to free its
   core for the next). At the same scope with (B) enabled, both cycle
   invariants hold across **6,179,060** states (`cr3self`, revision 15;
   the 109,626 this line carried was the revision-11 figure). Note the
   shape of the trace:
   it needs no exotic timing, only the ordinary preempt-requeue-dispatch
   cycle this machine performs constantly.

**(B)'s cost, restated in one line:** it rejects strictly more than (A) —
the three cases enumerated above rather than only the first — and it
holds the mark for the whole syscall, so E_BUSY is a normal outcome of
concurrent suspends. That is the price of a mechanism that needs no cycle
detection, no second lock, and no assumption. §11.8 carries the proposed
`specv3.md` text.

**What this replaces.** Under either mechanism the N6 assumptions are no
longer load-bearing for W5: §3.6's assumption (2) (no perpetual
cross-core alignment) exists ONLY to survive the symmetric-suspend
livelock, and a machine in which symmetric suspend is unreachable does not
need it. The normal path is completely unchanged — a non-cycle-forming
suspend keeps rule 3's one-unpinned-tick bound exactly as before. That is
why this is preferred to §11.7's bounded W5 wait (which makes *every*
suspend fallible) and to async completion (which changes every suspend's
shape): **this one charges the pathological caller and nobody else.**

The requester's wait condition — *left `running`*, weaker than *parked* —
is load-bearing for deadlock freedom (mutual remote suspends break via
requeue preemption of the kernel-mode spinners, which hold no claims and
are therefore preemptible under the §3.1 rule-1 gate; round 2 tried and
failed to deadlock this). **That break is CONDITIONAL on T3 rule (b)**
(round 5 N1): it holds only because the spinners are unpinned. A
suspender that entered the W5 wait holding any pin-class lock (§2.4 —
and F3 put the slab and kstack-freelist classes in that set) is
unpreemptible under the same pin gate, and two such suspenders targeting
each other are a hard cross-core deadlock — the model finds it in
seconds without the assert. The spin-entry `pin_depth == 0` assert
(§3.6 rule (b), §9.2) is therefore normative on every suspend path.

**Enforcement, verified against the tree (round 6 M2 — do not re-soften
this into ambiguity):** what exists TODAY is `check_gen_lock` (its IRQ
pass repaired; its check 6 enforces the mask-everywhere ARM of the §2.4
dichotomy) and `check_ec_closure` Rule A / Rule B — and Rule B, which is
what actually computes the pin-class dichotomy's input, is
**report-only: it is not wired into precommit** (stage [0c] gates
`check_gen_lock` alone). Known blind spots of the current tools, named
so nobody mistakes silence for cleanliness: (1) **no spin-inventory
check exists in either tool** — there is no bounded-loop-on-remote-word
detection at all, so 9.3(6b) is FUTURE work in its entirety, including
both the every-spin-matches-a-T3-row check and the spin-entry
pin-freedom check; (2) Rule B counts GenLock/SlabRef acquires as
UNRESOLVED rather than classifying them; (3) acquires in
`[unreachable]`-context are unproven, not proven-safe; (4)
`tlbShootdownHandler` fails entry resolution in both tools, so the W9
IPI path is not a seed anywhere — shootdown-only lock paths are "not
checked", not "clean". Until 9.3(6b) exists, rule (b)'s entire
enforcement is the runtime debug assert (§9.2) plus lockdep's pin-class
bumping at the 9.3(7) sites — both of which are themselves design-target
machinery that lands with `pin_depth`. **Latent tension, and revision 11 RESOLVES IT THE OTHER WAY (round-10
C-A).** Check 6 today flags `stack.freelist_lock`'s plain acquires and
prescribes `IrqSave`, while F3 designates that class pin-counted (plain
acquire + `pin_depth`). Revision 10 proposed that "check 6 must learn
the pin-counted arm". **That proposal is withdrawn.** It amounted to
telling the one analyzer that currently demands a mask to stand down, in
the very revision (§3.3) that created the hazard the mask was
protecting against — the analyzer was right and the design was about to
overrule it.

The correct direction is the inverse: rules (c)/(c2) flip from *finding*
explicit masks to **forbidding unmasked EC-context acquires on any
IRQ-reachable class**, which is §2.4's third clause expressed as a
check. Under that reading `stack.freelist_lock` is pin-counted only if
it has no interrupt-context acquire site, and check 6 keeps its teeth
everywhere else.

**Cost, stated rather than implied, because it is real work**: this
needs (1) `trap_sync` promoted, or masking at fault entry, so the
analyzer can tell an EC-context acquire from an exception-context one;
and (2) an **IF-state model in `asm_analyzer.zig`** — the two hazard
sites above are raw asm, so a Zig-level acquire-site scan cannot see
them at all. Neither exists. Until both do, §2.4's third clause is
enforced by review and by the two named sites being fixed, not by
tooling. **[MAINTAINER CALL §11.11 — round-11 M-7: revision 11 routed
this to §11.4, which is "Remote-suspend semantics" (`stygia-uyd`) and
covers none of it. §11.11 is new and is where the C-A cost lives.]**

### 2.6 Disposition of today's signals

| Today | Disposition |
|---|---|
| `State` enum (6) | seven states (§2.1); wait flavors → descriptor data; `claimed`/`pended` absorb every hand-off |
| `on_cpu` | **deleted.** Quiescence is structural (S3). The wake-side spins it fed are gone entirely: parking-origin claims (`pended`) hand placement to the owner's hop instead of waiting for it; the only claimant→owner coupling is the one-way `payload_done` handshake, waited on by the **owner in scheduler context**, never by interrupt context (§3.6) |
| slab gen parity | kept; fused with `retired` under the EC `_gen_lock` (S5) |
| `current_queue_core` | **KEPT, and now discharged** (round-12 M-4): it had no §3.4 row through revision 13 — no width, no named writer, no validity set — which is verbatim the argument §2.2 used to DELETE the staged destination. It now has one (§3.4): written under the destination queue lock at edges 1/6/6p/8, cleared under the same lock on every exit from `ready`, valid iff `state == ready`, and safe when stale because every reader re-validates under the lock it points at (§3.5's drop-and-retry). **Kept rather than deleted because deleting it reinstates exactly what this row records as removed** — a 64-core search on every reach-and-validate and every `removeFromQueue`. It is derived-by-search only in the sense that the search is the fallback; the field is the index that makes the fallback unnecessary |
| `last_dispatched_core` | narrowed to `owner_core` (§2.4) |
| `PerCore.current_ec` | kept (single word, two writer sites) |
| `PerCore.committed_ec` | deleted (§2.3, §9.4) |
| `PerCore.pending_zombie[64]`, `.post_park_clear_on_cpu`, `.pending_kstack_release`, `.pending_cross_enqueue` | deleted (upheld three times) |
| `suspend_port`, `pending_reply_*` | descriptor data with defined ownership handoff |
| `timed_waiters[64]` + `timed_recv_waiters[256]` | one intrusive per-EC deadline node (§8.4); registration infallible |
| — (new) | `pended` state value, `payload_done` bit, `pin_depth` byte, `mark_state` **bit** (§2.4, round 7 M-3 — the deferred-marking fact was previously wordless; collapsed from a tri-state in round 8), `directive_state`+`directive_port`, `teardown_pending`: the honest price of closed hand-offs, remote suspend, and self-delete teardown |
| `priority`, `affinity` (today: plain fields, edited by a bare store) | kept as stable per-EC words with a named writer and a re-bucket obligation (§3.4, §8.1); the deferred-re-bucket defect (a queued EC keeps its old key until it naturally re-enqueues) is closed |
| `leak_tag`, diagnostic counters | deleted; their questions become assertions (§9.2) |

---

## 3. The concurrency substrate

### 3.1 Preemption points

Kernel execution is in **EC context** (some EC's kstack) or **scheduler
context** (the park kstack).

1. **Preemption is claim-gated AND pin-gated.** The preempt tick
   dispatches away from EC context only if the current EC's
   `pin_depth == 0` (round 3 X1) and its `running → parking(requeue)` CAS
   wins. The pin gate is what makes S4's holder-persistence true: a frame
   holding a claim (or a non-IRQ-masked lock) is never requeue-preempted,
   so it can never become a `ready`/`parking(requeue)` EC whose retire
   would inline-finalize an in-flight claim — the two X1 windows are
   unreachable (§5.2). Wake bodies are L6-bounded, so the deferral costs
   at most one tick. Directive-waiters and eviction spinners hold no
   claims (`pin_depth == 0`) and remain preemptible — the
   mutual-remote-suspend break is untouched. On CAS failure:
   `parking`/`claimed`/`pended` → return from the IRQ (a transition or
   hand-off is in flight; it completes at its own hop or discharge);
   `retired` → rule 3's gate.
2. **Scheduler context never dispatches from an interrupt** (SP-range
   check in the sched-vector handler on both arches). Teardown, finalize,
   requeue, and `pended` discharge run here, un-abandonable, IRQs
   enabled.
3. **Entry checks are user-boundary-gated, and they run FIRST.** The
   `retired` and `directive` arms fire only on entry from user mode; the
   **domain-paused** arm fires on **both legs** of the boundary, and the
   difference is load-bearing (see below). **The domain-paused arm
   (round-13 C-1, §0.3):** an EC
   whose own domain reads `paused` performs a standard edge-3 park into
   `waiting(domain_pause)`, published under the CD `_gen_lock`. Its
   precedence sits **below `retired` and below the directive**: a dying
   EC must not be gated into a wait its resumer would then have to
   discharge, and an armed suspension is already a park to a port that
   the pause has no reason to pre-empt. So the order is
   **retired → directive → domain-paused → requeue**, and the tick is an
   entry from user mode for all four (§5's edge-3 row).

   **WHICH LEG, stated normatively because revision 15 left it to the
   phrase "user boundary" and the two readings are not equivalent
   (round-13 follow-up).** The entry leg alone does not implement the
   pause. An EC parked in `waiting(futex)` when the pauser proceeds, and
   woken afterwards, never re-enters from user mode on its way back —
   it is dispatched and *returns*. Under an entry-only reading it would
   execute user instructions in the rewritten address space until the
   next tick, which contradicts §0.3's "before executing a single user
   instruction" outright, and falsifies §3.6 W5-N's own soundness
   argument that *"every path from [`waiting`/`claimed`/`pended`] back to
   user code passes the §3.1 rule-3 gate"* — a wake→dispatch→return path
   passes no entry check at all. So:
   - **Return leg (kernel → user), the domain-paused arm ONLY**: every
     path that hands control back to user mode — syscall return, fault
     return, interrupt return, and the arch dispatch trampoline that
     resumes a woken EC — re-reads `cd.paused` and parks instead of
     returning if it is set. This is the leg that makes the pause a
     pause. It is also the leg the quiesced-resume rule (§3.3) constrains,
     and the leg the tree's trampoline currently writes user memory on
     ahead of (§11.13).
   - **Entry leg (user → kernel), all four arms in the order above**:
     this is what discharges an EC that was `running` in user mode when
     the pause landed, and it is the per-EC progress W5-N's boundedness
     column is about.

   `retired` and `directive` do not need the return leg: both are
   asynchronous by construction — a retired EC is caught by the wake IPI
   the retirer sent, an armed directive by the next entry — and neither
   has a caller waiting on a quiesced address space.
   Kernel EC frames run to their own hop (where the commit-failure arm
   finds `retired`) or to syscall completion (the next user-boundary
   event finds it — prompt because the retirer's wake IPI pends until IF
   restores). Together with rule 1's pin gate this covers all three
   abandonment vectors round 3 enumerated: entry checks (rule 3), requeue
   preemption (rule 1), and the hop's own retired arm (which only fires
   for the frame's OWN EC, whose claims were discharged before the hop —
   §2.4 assert).

   **Precedence, normative** (round 7 M-5; this IS the N5 fix, which
   rev 7 recorded only as a consequence in W5's boundedness column and
   never as a rule): **on any entry from user mode, the entry checks
   precede every other action that entry would take.** A periodic tick
   arriving on a user-mode frame *is* such an entry, so a tick that
   finds an unpinned, user-mode EC with `directive_state == armed`
   **consumes the directive** (edge 3, park into the port) — it does
   **not** take the requeue arm. §5's edge-3 row lists directive
   consumption and the preempt tick as sibling triggers; where both are
   enabled, consumption wins. Without this precedence an implementer can
   wire the entry checks into syscall entry, leave the tick
   requeue-first, and silently reintroduce N5 (a target that duty-cycles
   pin-class holds starves its suspender forever) with the whole battery
   still green — which is why §9.2 now asserts it at the requeue claim
   site rather than leaving it to be inferred.

There is no "callee re-enabled IRQs inside a must-complete sequence"
hazard: must-complete work is protected by an unclaimable state (rule 1),
scheduler context (rule 2), the kernel-frame gate (rule 3), or the pin
gate — never by an ambient IRQ mask. (Forecloses class 2.)

### 3.2 The three named sequences

**The park sequence** (`running → parking → hop`), owner core only:

1. All fallible work and all saved-frame reads first (event staging into
   the descriptor). `pin_depth == 0` at the publish (§2.4).
2. **Publish under the reaching locks** (today's futex discipline
   generalized — `futex.zig:434`; port paths `execution_context.zig:1645`
   / `port.zig:613`): **the `parking` CAS first, then the links, both
   inside the final container-lock critical section** (round 6 M1 —
   intra-section order is unobservable under the held lock, so this
   costs nothing). The CAS's failure arm is thereby specified: a retire
   that landed since step 1 (edge 9 may hit a `running` EC at any
   instant) makes the CAS fail on `retired`; the parking core then
   **links nothing**, releases the section, and proceeds as
   outgoing-`retired` — the hop's retired arm finalizes (§4). (Note for
   the record: with links-first the failure arm would ALSO be correct
   under revision 6 — finalize's idempotent unwind and the pop-side
   stale-skip make leftover links harmless — but only became so with N4's
   mechanism; under rev 5 links-first-then-fail was a bug. CAS-first
   removes the question.) §9.2 asserts the order. The same arm applies
   to every §3.2 publish: the directive consumption's edge-3 park
   (§2.5), the rendezvous publish (§8.3), and creation's edge-1 publish
   analog (§8.5). Container locks are IRQ-masked, so no tick lands
   between publish and links and no container-reached waker can see a
   linked EC still `running`. Deadline registration follows the links
   inside the same section.
   **The link precedes the hop; claimability does not** (round 6,
   Phase-3b measurement question, answered from this text): a wait-park
   EC sits LINKED in its containers, in state `parking`, while the owner
   core is still on its kstack — and that is safe with NO wake-side
   kstack barrier because claimability-for-placement begins only at the
   hop's commit CAS (edge 4, `parking → waiting`, performed by hop step
   2 AFTER step 1 released the kstack). Every claim that reaches the
   linked EC pre-hop lands as 5b → `pended`, whose placement is
   discharged by the owner's own hop (edge 6p) — after release, by
   construction. Edge 4 therefore already carries the same at-the-hop
   requirement edge 8 carries: placement-of-claimability at the hop.
   Consequence for the tree: `pending_kstack_release` and every wake-side
   `on_cpu` barrier are compensations for the pre-split machine (terminal
   wait states published pre-hop) and become deletable at migration step
   3/4 — for the same reason edge 8 deleted the re-enqueue guard. The
   Phase-3b measurement is the evidence the barrier's zeros are timing,
   not structure: wake-side barriers were REACHED 89×/boot (x86) and
   856×/boot (arm) while being ENTERED 0 times. S3 is the invariant that
   makes this structural, and the model checks it (InvS3; plus the e4
   falsifier, which dials the `parking` interposition out and must
   violate S3 within a handful of states).

3. Post-publish, pre-hop: bounded work only — lock-bounded local
   operations allowed (the rendezvous delivery lives here, under §2.2's
   descriptor rule, and it acquires the receiver-CD and destination
   run-queue locks — this is expected and legal), no unbounded spins, no
   waits on remote progress. (Rev 3's "no-cycle certificate" for this
   window claimed the owner's path acquires no locks, which its own §8.3
   contradicted — round-3 repair. The correct statement is the bounded-
   work rule here plus the global acyclicity argument in §3.6, which does
   not depend on this window being lock-free.)
4. The hop (§4).

**The dispatch sequence** (`ready → running → PMU handoff → SP on new
kstack`): dequeue (or `yieldTo`-target pick), the S7 domain filter **with
its failure routing**, the `ready → running` CAS,
`current`/`owner_core`/queue-field writes — one `core_locks[core]`
critical section; the park-stack tail then performs teardown drain, the
PMU handoff, one final lifecycle recheck, and the SP/root load. If that
post-PMU recheck observes that a retire/park won after selected/current
commit, dispatch is abandoned: any PMU file restored for the would-be
incoming EC is saved/disabled and its hardware-owner token cleared before
the core returns to `run()`. A `perfmon_state` release may be requested
while another core owns that token, but release/destruction cannot
complete until the owner core clears it; the scheduler keeps a per-core
`SlabRef(PerfmonState)` for the live hardware file so the owner can do
that even if the EC field is concurrently being detached. This is the
invariant that makes a next EC with no perfmon state safe, prevents
threshold PMI state from leaking into the next dispatch, handles
same-core redispatch by restoring from the saved values, and leaves
destroyed perfmon state with no live hardware owner. The same boundary
applies outside dispatch tail: any syscall path that directly programs
PMU hardware (`perfmon_start`/`perfmon_read`) first retires a different
per-core owner through the scheduler before overwriting the register
file. S7-failure routing
(round-3 M-A repair; lock order
corrected round 4 F2): a popped `ready` EC whose domain ref is gen-dead
is **claimed, not retired in place** — the dispatcher CASes
`ready → claimed` under the queue lock it already holds (legal per
R-claim: the queue is the reaching container), releases the queue lock,
then retires the EC as its holder via T2's `claimed` row (marking +
finalize inline; the EC is quiescent). Rev 4 retired it under the queue
lock, which nests the S5 gen-flip inside the core lock —
CoreLock → EcGen, an AB-BA against §3.5's pinned EcGen → CoreLock order
with both sides IRQ-masked. Never a silent drop, either way.

**The wake body** (`claim → discharge`), any waker:

- Claim CAS under the reaching lock (R-claim, §3.5). The winner unlinks
  the episode's containers (including the deadline node), bumps
  `pin_depth` **inside this same masked section** (§2.4 ordering rule),
  and writes the payload (saved frame + descriptor staging). It stages
  **no destination core at all** (round-8 simplicity): every placement
  computes its destination from the fresh descriptor under the
  destination queue lock (round 7 M-2, §4), so a staged copy would be a
  wordless cross-core-readable fact with no discipline attached.
- **Origin `waiting`/`ready` (edge 5a/5c → `claimed`)**: the claimant
  discharges placement itself — placement CAS under the destination lock
  (edges 6/7). Legal from any context including interrupt handlers
  (queue locks are IRQ-masked classes; no waits are involved because the
  origin was quiescent).
- **Origin `parking` (edge 5b → `pended`)**: the claimant writes payload,
  release-stores `payload_done`, and is DONE — no wait, no placement.
  The owner core's hop discharges (§4). This replaces rev 3's
  release-wait wholesale and with it the same-core decline rule and L4's
  carve-out: interrupt-context wakes are never declined and never wait
  (X2, X3). One-shot wake sources (device IRQs, timer-wheel pops) are
  therefore always consumed by exactly one discharge path (§5.1).

### 3.3 Interrupt discipline

- Container locks are IRQ-masked for the hold (the `check_gen_lock`
  IRQ-class rule). Park-sequence step-2 atomicity derives from this.
- **Masking does not stop synchronous exceptions** (round 4): a
  user-copy page fault inside a critical section re-enters the fault
  path and can reach a T1-row-5 claim with the section's locks held.
  Normative rule: **no user-memory access inside any container-lock or
  gen-lock critical section** — SMAP-bracketed reads are hoisted outside
  holds, as today's reply path already does (`port.zig:753-756`).
  Analyzer-checkable (9.3(2)); this is also the boundary condition under
  which T3's W1 row is sound (W1's argument covers maskable IRQs only).
- **The QUIESCED-RESUME RULE. Normative, and new in revision 16 — it is
  the premise §0.3's domain-pause argument rests on, which revisions 14
  and 15 asserted through a citation of the bullet above that does not
  reach it.** Scope first, because the two rules are easy to conflate:
  the bullet above bans user-memory access **inside a hold**; this one
  bans it **outside any hold**, on one specific path, and neither
  implies the other.

  > **From the moment a wake makes an EC of a PAUSED domain runnable
  > (edge 5a, then edge 6) until that EC reaches the §3.1 rule-3
  > domain-paused gate, no kernel code executing on that EC's behalf may
  > read or write that EC's user memory** — not in the wake body, not in
  > the syscall return tail, and not in the arch dispatch trampoline.

  **Why the exposure is real and specific**, rather than a tidiness
  rule: the whole point of the pause is that `idc_read` / `idc_write` /
  `acquire_vmars` operate on a QUIESCED address space, and the predicate
  W5-N waits on covers only the runnable subset (§3.6). `waiting`,
  `claimed` and `pended` ECs are excluded from it by design — that is
  what lets the pauser finish — so the pauser proceeds while they are
  still parked, and a wake arriving afterwards resumes one of them
  concurrently with the rewrite. A kernel access to that EC's user
  memory in that window is a read or write against a mapping the pauser
  may already have unmapped, replaced or copied, performed with
  SMAP/PAN cleared and therefore with no fault gate behind it.

  **What the rule does NOT require**, so it is not read wider than it
  is: register-only work on the saved frame is fine (the frame lives on
  the kernel stack, not in user memory) — this is why `setEventStateGprs`
  and the GPR-backed vreg writers are unaffected and only the
  stack-backed slots (`vreg 0` at `[user_sp + 0]`, `vreg 14` on x86-64 at
  `[user_rsp + 8]`, and `vreg >= 32`) are in scope. Nor does it apply to
  ECs of unpaused domains, which is why the enforcement below is gated on
  `cd.paused` rather than made universal.

  **Two ways to satisfy it, and this document does not pick** (§11.13
  records the call): either the gate is evaluated **before** any
  user-memory access on the resume path — which means the domain-paused
  arm is checked in the dispatch path ahead of the trampoline's flush,
  not merely at syscall entry — or the access is **re-deferred** past the
  gate, i.e. staged work stays staged for a gated EC and is flushed on
  the resume that follows the pause, which is the same deferral
  `port.deliverEvent` already performs once for the TTBR0/CR3 swap.
  **The tree today does neither** (§11.13).

  Enforcement: §9.2 assertion and §9.3(2) analyzer clause. Stated as a
  rule rather than left in §0.3's prose because §0.3 is rationale and
  §0.4 says explicitly that rationale is not what an implementer codes
  against.

  **WHEN it binds: with the pause, not before.** The rule is conditioned
  on `cd.paused`, and the domain pause is DEFERRED out of §12 to bead
  `stygia-qap` (§0.3). At HEAD no domain is ever paused, so the rule is
  **dormant** — it is not an obligation on §12 steps 1–10, and §11.13's
  HEAD violation is not a §12 blocker. It becomes live the moment `qap`
  lands, which is exactly why it is written down now: `qap` must not be
  implemented against a premise nobody recorded.
- **EC-context kernel frames run with IRQs ENABLED. Normative, and new
  in revision 10 (round-9 C-4) — it was the single most load-bearing
  unstated premise in this document.** On entry from user mode the arch
  entry path unmasks IRQs once its saved-state publication is complete,
  and they stay unmasked for the body of the syscall or fault handler,
  except inside the container/gen-lock holds above and the explicitly
  masked windows this document names. **Twelve normative arguments
  depend on it and none of them said so**: §3.1 rule 1 (a preempt tick
  that can never arrive gates nothing), §2.4's C1 ordering rule (whose
  entire argument is that there is "a live preemption point between the
  two instructions"), T2's ready×K row, §2.5's mutual-remote-suspend
  break, and the "preemptible" column of W3, W4 and W5 — including
  §3.6's W3→W5 cycle argument.

  Two things made this urgent rather than pedantic. First, what this
  document *did* say pointed the other way: the bullet this replaces read
  "no kernel code outside `arch/` enables interrupts; today's single
  violation is deleted with its mechanism", and §12 step 5 deletes "the
  last `enableInterrupts()` outside `arch/`" with **no step anywhere
  adding one back**. Second, the tree today is masked: x86-64 `SYSCALL`
  clears IF via `IA32_FMASK` (`arch/x64/cpu.zig`), and aarch64's only
  `daifclr` sites are `cpu.enableInterrupts` and the park primitives —
  so **following §12 literally leaves fewer enable windows than exist
  today**, and every gate above goes vacuous *with the battery still
  fully green*, because the model's `TickPreempt` fires on any unpinned
  `running` EC regardless of what its frame is doing. A model cannot
  catch this: IRQ state is below its granularity and the premise is
  exactly what its atomicity grants for free.

  The rule that remains true, restated correctly: **no kernel code
  outside `arch/` MANIPULATES the interrupt-enable state** — the enable
  is the arch entry path's job and the masked windows are the lock
  classes' job. That is what the deleted `enableInterrupts()` violated;
  it was an ad-hoc re-enable inside a must-complete sequence, not the
  entry-path enable this rule requires.
- The park primitive's masked-halt contract is unchanged.

### 3.4 Atomicity granularity

| Fact | Width | Writer | Cross-core readers | Discipline |
|---|---|---|---|---|
| `ec.state` | 1 byte | chokepoint CAS only | anyone | CAS/acquire; actionable reads re-validated by CAS |
| `ec.owner_core` | 1 byte | dispatching core under its lock | pended discharge, retirer routing, eviction barrier | valid only per §2.4 |
| `ec.pin_depth` | 1 byte | the EC's own core, EC context | that core's tick only | same-core; no atomics; **bump precedes the acquire, decrement follows the release** (§2.4, C1) |
| `ec.mark_state` | **1 bit** | retirer (under the retire CAS's `_gen_lock` exclusivity) SETS or leaves clear; then the §5.2-named discharger CLEARS | terminator's W4 wait; finalize's assert | SPSC hand-off, same shape as `payload_done`: the discharger's clear is a release-store, W4 is the acquire side; writers disjoint in time (the discharger's store is enabled only by observing it SET) (§2.4, M-3) |
| `ec.priority` | 1 byte | the `priority` syscall, under the target's `_gen_lock` | every link site (`EcQueue.enqueue`, futex `WaitNode` key), under the destination container lock | single-word store, **published before any subsequent link**; links that already exist are repaired by the same syscall's re-bucket (§8.1). A `WaitNode`'s copy of the key has ONE writer context — whoever holds that bucket's lock (the parking core at link time, the syscall thereafter) |
| `ec.affinity` | 8 bytes | the `affinity` syscall, under the target's `_gen_lock` | every placement's destination computation, under the destination queue lock | as `ec.priority`; a `ready` target whose new mask excludes its current queue core is MOVED by the 5c claim-move, not by a bare store (§8.1) |
| `ec.directive_port` | 1 word (SlabRef) | the suspender, **written only between its `none → claiming` and `claiming → armed` CASes** — i.e. under the exclusivity the `claiming` state grants | **the owner core only**, at its user-boundary check, to gen-validate and park into | round-10 C-D: rev 10 gave this field no row at all. The suspender never reads it back, so there is no cross-core read discipline to specify — it re-validates the port reference IT holds. That asymmetry is the whole reason the ownership test needs no second word |
| `ec.directive_state` | **4 bytes: `{ state: u8, owner_slot: u24 }`**, one word, single-word CAS (round-10 C-D) | **writer contexts, enumerated in full (round-9 C-1; rev 9's row named two of them and S2/analyzer 9.3(1) pin writers from THIS row)**: (1) a **suspender** CASing `none → suspending` on its OWN word (§2.5.1 CAS 1 — the only case where an EC writes its own directive word); (2) a **suspender** CASing another EC's `none → claiming` and `claiming → armed`, and `(armed, me) → none` on disarm; (3) the **owner core** CASing `(armed, owner) → none` on successful user-boundary consumption; (4) the **owner core** publishing `directive_result` and CASing `(armed, owner) → (failed, owner)` on stale/bad-port or other consume failure; (5) the **matching waiter** CASing `(failed, me) → none` as the failure ack; (6) **finalize** writing the terminal `dead`; and **(7) the slot zero itself** — finalize's `slot zero + freelist` (§8.2, edge 10) writes the all-zeroes `none` over `dead` a few steps after (6), and creation's publish (edge 1) writes `none` into a recycled slot. **Round-11 C-1: this row claimed "four writer contexts, enumerated in full" and was short by exactly this one — the same failure as round-9 C-1, which was also this row being short.** The zero is not a bookkeeping detail: it is what destroys F6's marker, which is why the break disambiguator cannot rest on `dead` | owner entry check; suspender re-check loop; a suspender's own-word check at CAS 1 | payload under claiming→armed exclusivity; terminal `dead` distinguishes retired from consumed (§2.5, F6) only when observed before slot zero. `armed → none` means delivered consume or waiter disarm; owner-side failures instead publish `directive_result` and go `armed → failed`, then the matching waiter acks `failed → none`. The word carries the **identity of the suspender that placed the current arm**, and the suspender's break test and disarm CAS are both on `(armed, me)`, never on the state value — without that the word is an ABA and a suspender can both report success for an undelivered suspension and disarm a third party's directive. An epoch was tried first and TLC refuted it: a bounded counter is itself an ABA (§2.5). Full state set: `none | suspending | claiming | armed | failed | dead` |
| `ec.directive_result` | 8 bytes (`i64`) | owner core, release-store before `(armed, owner) → (failed, owner)` | matching suspender after acquire-observing `(failed, me)` | carries the owner-side consume-failure code only while `directive_state` is `failed`. The matching waiter reads it before CASing `failed → none` and returns the error; the ack does not clear the result because that would be a second, non-atomic word update. Outside `failed`, the value may be stale and no success path reads it |
| `ec.wait.*` | multi-word | per §2.2 | claim/retire winner; owner's hop after `payload_done` | ownership transfers with CAS; reachability-gating sections; `payload_done` release/acquire |
| `ec.ctx` saved-frame payload | multi-word | claim winner only | the EC after re-dispatch | claim CAS + saved-frame ban + discharge ordering |
| `cd.paused` | 1 byte, on the capability domain | the pausing EC, CAS 0 → 1 under the target CD's `_gen_lock` at pause entry, and 0 at resume under the same lock | **every EC of that domain at its own user boundary, on BOTH legs** (§3.1 rule 3's third arm — the kernel → user return leg is the one that catches a woken `waiting` EC, which enters from nowhere); edge 1's publish, under the CD `_gen_lock` it already holds | single word, CAS-arbitrated, so two pausers of one domain serialize and the loser gets E_BUSY. Read at the boundary WITHOUT the lock — a stale FALSE is safe (the EC runs on and is caught at its next boundary; the pauser is still waiting on the runnable predicate), and a stale TRUE cannot occur because only the pauser clears it and it clears after every gated EC has been resumed (§0.3) |
| `ec.current_queue_core` | 1 byte (`u8`; `NOT_IN_RUN_QUEUE` sentinel outside the validity set) | **the party holding the DESTINATION queue lock at the CAS-then-link of edges 1 / 6 / 6p / 8** — i.e. whoever makes the EC `ready` writes it in the same section. Whoever takes it out of `ready` (edge 2's dequeue, a 5c claim, pull-side steal's victim removal, retire's ready row) clears it to the sentinel in the section it already holds. The x86-64 IPC fast path mirrors this in R13's ready-enqueue branches: queue links/tail first, then `current_queue_core = local core`, then unlock | `removeFromQueue`; §8.1's reach-and-validate step 2 (which container am I in); §5.3's run-queue row; pull-side steal's victim scan as a hint only | **valid iff `state == ready`**, poisoned to the sentinel otherwise (debug builds assert it). Single byte, so no tearing; written and cleared only under the queue lock that owns the membership it names, which is the same section the state CAS runs in — so it cannot disagree with `state` at any point a reader can observe both. **A stale read is safe by construction**: the reader re-validates under the lock it was directed to and retries on mismatch (§3.5's drop-and-retry). Steal likewise does not trust this field alone: the victim scan validates actual run-queue membership under the victim lock before claiming/removing |
| `PerfmonState.hw_core` / `release_pending` | 1 byte + 1 bit | the core that restored the PMU file writes/clears `hw_core`; a releaser sets `release_pending` under the PMU state's gen-lock when `hw_core` names another core | scheduler dispatch tail, `perfmon_stop`, EC teardown | `hw_core` is the hardware-owner token. A PMU state may be detached from the EC only after the token is null. Remote release sets `release_pending`, sends a scheduler IPI to the owner, and waits; the owner saves/disables the PMU file, clears the token, and completes destruction through its per-core `SlabRef(PerfmonState)`. The EC field is not the lifetime authority during dispatch tail |
| `PerCore.current` | 8 bytes | owning core (2 sites) | identity compares only | caller-pinned identity rules; bytes intact until finalize |
| `PerCore.active_root` | 8 bytes | owning core, release-after-load | teardown barrier | as today |
| `PerCore.idle_parked` | 1 byte | owning core under its lock | enqueuers under same lock | as today |
| slab gen word | 8 bytes | slab allocator / retire (under `_gen_lock`) | handle resolution | as today |

### 3.5 R-claim: where a claim CAS may be attempted

A claim (any CAS out of `ready`/`waiting`/`parking`) MUST be attempted
only:

- **while holding the lock of the container through which the EC was
  reached** — run-queue lock, port lock, futex bucket lock, deadline-table
  lock, timer-wheel lock, device-region lock (§5.1); or
- **under the EC's own `_gen_lock` with gen validation** for ref-reached
  holders (reply pin, terminate, teardown walks). Retire's CAS+gen-fuse
  runs under the same `_gen_lock`; the fast path's fused publish lives
  inside this hold (§9.4).

**Lock-order pin** (round-3 repair): retire of a `ready` target holds
both the EC `_gen_lock` and the run-queue lock; the canonical order is
**EcGen → CoreLock**. Nothing in the machine takes a core lock and then
an EC gen lock (dispatch, enqueue, and placement never acquire EC gen
locks), so the pair-order is registrable with lockdep as a fixed edge.

**Cross-class lock ordering is OUT OF SCOPE (§0.2), and revisions 10–12
were wrong to make it a project.** Revision 8 asserted a chain
(`wait-container < EC gen < core locks`); round 8 refuted its left edge
against the tree; revisions 10–12 then escalated that into a "blocker"
that gated §8.1, §8.2, §8.5 and six migration steps on a lockdep group
design nobody had asked for. That escalation was the error. The kernel
already has a discipline, it already enforces it, and this machine does
not need to invent a total order. Three sentences replace the project:

1. **Same-class nesting is address-ordered under a named group.** Two
   locks of one class are taken lowest-address-first with the pair
   tagged to a group so lockdep does not fire its same-class overlap
   check. (The x86-64 fast path's `receiver_ec`/`sender_ec` nesting is
   the live instance, and its comment names a group constant
   `EC_NESTED_GROUP` that **does not exist in the tree** — bead
   `stygia-d0q`. That must be fixed; it is a one-line defect, not a
   design question.)
2. **No static cross-class order is asserted.** Lockdep detects cycles
   dynamically from its pair registry. Only one cross-class edge is
   pinned, because retire needs it: **EcGen → CoreLock** (round-3
   repair, re-verified at HEAD with no counterexamples).
3. **Reach-and-validate is solved by DROP-AND-RETRY, not by ordering.**
   A ref-reached party computes its candidate container, takes that
   container's lock, **re-validates under the lock**, and retries on
   mismatch. That is why §8.1's `priority`/`affinity` repair needs no
   order to be settled first: it never holds two classes at once.

**Honest statement of the residual risk, because it is real:** dynamic
cycle detection is strictly weaker than a proven static order. It finds
a cycle only when an execution actually traverses one, so an unexercised
path can carry a latent inversion indefinitely. **This is the risk the
kernel already runs**, on every lock it has, today; this machine neither
adds to it nor is entitled to demand it be retired first.

The FINALIZER's leading container unwind (§8.2, round 5 N4 — retire has
no unwind step) acquires each relevant container lock before the release
body and any free; combined with R-claim this flushes any in-flight
claim attempt before the slot can be reclaimed (the popped-node race
closure, generalizing today's gen-checked `node.ec.lockIrqSave` in
`futex.wake`).

### 3.6 T3 — the wait-for graph over every retained spin

Normative closure table (round 3). Every spin the design retains, with
its context, the party it waits on, that party's own possible blockers,
and the interrupt-frame edges. A new spin may be added only with a new
row proving acyclicity; the analyzer checks the row set against the
callgraph (§9.3(6)).

| # | Spin | Waiter context | Waits on | Provider's blockers | Interrupt-frame edges | Why no cycle |
|---|---|---|---|---|---|---|
| W1 | container/gen lock acquire | any | current holder's bounded critical section | other bounded lock sections (lockdep DAG) | **REWRITTEN IN REVISION 11 (round-10 C-A).** Rev 10 read "holder is IRQ-masked ⇒ cannot be waiting on this interrupt's return" — which is FALSE for the pin class **by definition**, since a pin-class lock is precisely one that is NOT masked at its EC-context acquire sites. The argument now splits by class: an **IRQ-masking class** keeps the original certificate (the holder cannot be waiting on this interrupt's return, because it cannot have taken this interrupt); a **pin-class** lock is safe only because §2.4's third clause forbids it any interrupt-context acquire site at all, so no interrupt can contend for it and the re-entrancy question does not arise | lock DAG + bounded sections; holders never enter spins W3–W6 while holding (contract, asserted). **The pin-class arm's certificate is the §2.4 prohibition, and it is analyzer-checkable (9.3(7)) rather than argued** |
| W2 | owner-hop `payload_done` wait | **scheduler context** (hop, degenerate hop), no locks held | the pended claimant's straight-line body | W1 only (claimant's body acquires only bounded IRQ-masked locks, all released before payload writes) | claimant may be an interrupt body — but it waits on nothing, and (same-core) it completed before the hop can even run | provider has no outgoing edges to W2–W6; same-core case degenerates to no-spin |
| W3 | terminate eviction spin | EC context, `pin_depth == 0`, no locks held | target leaving its core's `current` slot | target's kernel sequence completion + one user-boundary event (tick/IPI-bounded) | none — waiter is preemptible; target needs no interrupt of the waiter to return | target's progress is tick-driven, independent of the waiter — **CONDITIONAL on the two exit conditions below (round-8 C-1); without them this column is FALSE and mutual terminate is a hard two-core deadlock, reached by the model in 7 states**. **(i) Self carve-out**: if the target IS the caller, the wait is skipped entirely — a caller cannot wait for its own eviction. The tree already does this (`execution_context.zig:1028`, `if (ec != caller and ...)`); revision 8 had no such carve-out anywhere, so the tree was SAFER than the design. **(ii) Retired-waiter escape**: the spin also exits if the WAITING EC has itself become `retired`. The tree's `ec != caller` does NOT cover mutual terminate — A terminates B and B terminates A, and both cores pass `ec != caller`. Both callers end `retired` in kernel frames, and a `retired` EC in a kernel frame is moved by NOTHING: the requeue CAS fails on `retired` (§3.1 rule 1) and rule 3's entry checks are user-boundary-gated. Sound because a retired terminator never returns to user mode, so L5 has no observer to disappoint; safe because the frame holds no claim (`pin_depth == 0` at spin entry, rule (b)) |
| W4 | L5 deferred-marking wait (terminate, prior `claimed`/`pended`): **acquire-load of `mark_state` until the owed bit is CLEAR** (§2.4, M-3) | EC context, `pin_depth == 0`, **no locks held**, preemptible | the discharger's bounded body (holder's L6 body, or owner's hop after `payload_done`) — its clearing release-store is the paired write | W1, W2 | none | discharger never waits on the terminator; bound = discharger instructions + scheduling latency, and the acquire/release pairing that bound presumes is now an explicit §3.4 discipline rather than an implicit one |
| W5 | directive-suspender wait | EC context, `pin_depth == 0`, preemptible | target leaving `running`, OR consuming at a boundary | tick (requeue), its own park, or the **arming wake IPI forcing a user-boundary event → entry-check consumption** | none | round-2 verified for the requeue break; round-6 model addendum (N5): the requeue break ALONE is not total — a target duty-cycling pin-class holds can phase-align so the suspender never observes it off-CPU — and W5's termination then rests on rule 3's MANDATORY boundary consumption: every kernel entry from user mode (each periodic tick included) runs the directive arm, so an armed running target consumes within one unpinned tick; §2.5's wake IPI adds promptness for a target that never faults or syscalls. This is a distinct starvation class from N3 (N3: the SPINNER's recheck; N5: the spun-on EVENT), closed by rule 3, not by a fairness assumption — and rule 3's precedence over the requeue arm is what makes it work, which rev 7 left as a consequence and rev 8 states as a rule (round 7 M-5, §3.1). **This column is NOT a bound**: it is termination under assumptions (1)+(2) below, and the round-7 measurements show assumption (2) is the one the model can barely check (§11.7) |
| W5-N | **domain-pause wait** (round-13 C-1 — rewritten; revision 14's row said the pauser "arms N directives", which does not type-check, and asserted "N fixed at entry" by holding the CD `_gen_lock`, which contradicts rule (b) in the same row) | EC context, `pin_depth == 0`, **holding NO lock** — the CD `_gen_lock` is dropped before the wait begins | a PREDICATE, not a set: no EC of the target domain is `running`, `ready` or `parking`. `waiting`/`claimed`/`pended` are not waited on — every path from them back to user code passes the §3.1 rule-3 gate, **and revision 16 is what makes that true rather than hoped for**: such a path is a wake → dispatch → *return*, which passes no ENTRY check at all, so the domain-paused arm is specified on the return leg as well. Excluding these three states is also what creates §3.3's quiesced-resume obligation — the pauser proceeds while they are still parked, so a later wake resumes one concurrently with the rewrite | per EC: its own progress to a user boundary, which is tick-driven exactly as W3's is | none — the waiter is preemptible and no target needs the waiter to return | **the predicate only ever decreases while the wait runs.** Each runnable EC reaches its boundary and gates itself; nothing re-enters the runnable set, because edge 1's publish reads `cd.paused` under the CD `_gen_lock` it already holds and publishes gated (§8.5), and a resume is the pauser's own later act. Rule (b) is satisfied because the pauser holds nothing while spinning; the "N fixed at entry" claim is not needed and is withdrawn. **No cycle**: §0.3's two refusals make a pauser neither a member of the set it pauses nor able to pause while its own domain is paused |
| W6 | `awaitDomainQuiesced` | scheduler context, no locks held | cores republishing roots / evicting dying-domain ECs | W3-like per-core progress | none (ack-while-spinning services shootdowns) | per-core progress is tick-driven; barrier holds nothing they need |
| W7 | retire-from-`pended` `payload_done` pre-wait (edge 9, §8.2) | retire caller: EC-syscall or scheduler context — never interrupt context (asserted) | the pended claimant's straight-line body | W1 only | none | same bounded provider as W2; the wait precedes the retire CAS, so no later observer of `retired` ever waits (F1) |
| W8 | FPU migrate-flush ack (`fpu.zig:337-414`) | EC/scheduler context, IRQ-masked, **holding `request_lock`** | remote core's flush-IPI handler, or inline service at the remote's spin sites | none unbounded: the handler is lock-free and bounded; a remote spinning IRQ-masked services the flush inline (ack-while-spinning) | provider needs an IRQ delivery OR an inline service — never this core's held lock | rule (b) exception; sound per the ack-while-spinning closure below (F4) |
| W9 | TLB shootdown ack wait (`paging.zig:509`) | any, **holding `shootdown_lock`** | every remote core's shootdown ack (IRQ or inline service) | as W8 | as W8 | as W8 (F4) |

**A real cycle in this table, and the argument that breaks it** (round-9
M-1; rev 9 had no such argument anywhere, and W3's and W5's "why no
cycle" columns were each written as if the other row did not exist). A
terminates B while B suspends A: A sits in **W3** waiting for B to leave
its core's `current`, and B sits in **W5** waiting for A to leave
`running` or consume at a boundary. That is a genuine `W3 → W5 → W3`
wait-for cycle between two EC-context frames, and neither §2.5.1's
suspend-cycle rejection nor §3.6 W3's terminate exits touches it — the
two operations are *different*, so no mutual-X check fires, and neither
party is `retired`, so the C-1 escape does not apply.

It terminates for exactly one reason: **both waiters are
requeue-preemptible**, so the tick evicts A from `current`, which is
precisely what B's W5 wait is waiting for; B then completes and A's W3
discharges. **That argument is 100% dependent on §3.3's EC-context
IRQ-enabled rule** (round-9 C-4). If EC context runs masked — which is
what the tree does today and what §12 read as prescribing until revision
10 — the tick never arrives, neither waiter is preemptible, and this is
a hard two-core deadlock with no falsifier in the battery, because the
model grants preemptibility by construction. It is recorded here as the
worked example of why C-4's sentence had to be written: **a wait-for
cycle whose acyclicity certificate is an unstated premise is not a
certificate.**

Rules the table encodes: **(a)** no spin runs in interrupt context except
W1 on IRQ-masked bounded sections — rev 3's interrupt-context release-wait
(the X2 cycle) is deleted, not repaired — and W1's
holder-cannot-be-waiting-on-this-interrupt argument covers **maskable
IRQs only**, which is why §3.3 bans user-memory access (synchronous-
exception entry) inside holds; **(b)** no spin is entered while holding
any lock or claim, **except the two IPI-ack protocols W8/W9** (round 4
F4 — both are retained production mechanisms under §10's lazy-FPU and
translation-quiescence bullets, and rev 4 omitted them). Their
acyclicity rests on the ack-while-spinning closure: every spin in this
table — including W8/W9 themselves and every W1 wait — services inbound
flush/shootdown arms while spinning, so the remote handler a W8/W9
waiter needs can always run (by IRQ delivery on an unmasked core, or
inline at any masked core's spin site) and never needs the waiter's held
lock — and rule (b)'s **spin-entry `pin_depth == 0` assert is normative**
(§9.2): W5's "why no cycle" column is CONDITIONAL on it (round 5 N1 — a
pinned W5 spinner is unpreemptible and two of them deadlock; §2.5).
Enforcement status is §2.5's verified-against-the-tree paragraph: NO
spin-inventory tooling exists today (9.3(6b) is future in its entirety);
the assert and lockdep pin-bumping land with `pin_depth`; **(c)** every provider column bottoms out in bounded
instruction counts plus tick-driven progress, never in "some other spin
completing". **Scheduling assumptions (round 5 N3, GENERALIZED round 6 N6 — the
original N3 statement below is retained struck-through-in-place because
it was falsified, per this document's practice of correcting refuted
claims in the open):**

*N3 as first stated:* "exactly the deliberately preemptible spins —
W3/W4 and W5 — are starvable; pinned continuations are immune."
**Falsified by the second `liveness_c` counterexample**: `DirArm` — the
suspender's own `claiming → armed` step — is unpinned BY DESIGN (§2.5's
deadlock-freedom requires the suspender preemptible), is not a spin, and
starves under the same adversarial tick alignment: every dispatch of the
suspender is preempted before its one store executes. The immunity
boundary is the pin gate, not "spins vs continuations", so EVERY
unpinned kernel continuation is starvable in the adversarial limit.

The true assumption set, stated plainly. **Revision 8 reduces it from
three to two**: (2) is retired by §2.5.1's suspend-cycle rejection, and
with it the model's `AlignmentAssumption` and `SF(DirArm)`. What remains
load-bearing is (1) for every unpinned continuation and (3) for every
bound in this section. The model encodes (1) as per-continuation strong
fairness and (3) as its choice of STRONG over weak fairness:

1. **Continuation progress**: every dispatched kernel continuation
   executes at least one step between consecutive preemptions. (A
   quantum is ~10^6 instructions; `DirArm` is ~2. Physical, but an
   assumption.)
2. ~~**No perpetual cross-core alignment**~~ — **RETIRED IN REVISION 8
   (round 7, C3); kept struck-through-in-place per this document's
   practice.** It read: "independent per-core tick phases do not remain
   adversarially aligned forever — in particular, a W5 spinner is
   infinitely often scheduled while its target is off-CPU, so the disarm
   arm's observation window eventually opens." It was round-6 **N6 face
   (ii)**, and it existed for exactly one purpose: to survive the
   symmetric-suspend livelock. §2.5.1 makes symmetric suspend
   **unreachable**, so the premise is no longer load-bearing — and this
   matters beyond tidiness, because the premise was the one thing in the
   artifact that could not be checked at the scope the rest of the
   battery runs at (no WF/SF form can express an unconditional `[]<>`;
   proof in the model's README). **N6 face (i)'s `SF(DirArm)` goes with
   it**: `LiveSuspender` holds under a fairness set containing neither.
   Both are retained in the model only to define the revision-7 machine
   that the resolution falsifier dials to.
3. **No perpetual interrupt storm** (round 7 minor: rev 7 claimed the
   assumption set was complete at two, and it was not). Every "bounded
   by … plus scheduling latency" in the provider column presumes that a
   core's base continuation eventually executes — i.e. that interrupt
   frames do not de-enable it forever. This is a third assumption, not
   a consequence of the first two, and it is load-bearing for L2's
   "kernel sequence + one user-boundary event", for W2/W4's bounds, and
   for ack-while-spinning. It is visible in the model as the choice of
   STRONG rather than weak fairness on the base step: under WF an
   infinite interrupt storm legitimately starves a hop, and the
   properties fail.

**FIVE** distinct findings, each from a separate round, each a class the
previous enumeration had missed: N3 (spinner recheck), N5 (provider
event), N6 (continuation progress + observation alignment), round 7's C3
3-cycle, and round 8's **C-1 — mutual TERMINATE**. Note what C-1 does to
the story this paragraph told in revision 8. Rev 8 said the fifth class
would come from "every unpinned continuation, every cross-core
observation, and every cycle in the who-waits-on-whom graph", and it was
looking at W5 the whole time. **The fifth class was W3**, it involved no
suspend at all, and it is not a starvation at all but a hard deadlock —
because a `retired` EC in a kernel frame is moved by nothing, so the
mutual case wedges rather than starves. This section's enumeration of
starvable sites was **RECALL-derived**, and it was wrong about which row
was dangerous, not merely incomplete within a row.

**Assume the current enumeration is also incomplete.** The concrete
lesson for revision 9: the shape "two ECs each performing operation X
against the other" is now known to break for X = suspend (N1, N6) and
X = terminate (C-1). Every remaining cross-EC operation in §8.1 —
`priority`, `affinity`, `yieldTo` — deserves the same question asked
explicitly rather than assumed, and each of those answers should be
marked DERIVED or RECALLED when written.
Ack-while-spinning applies to all rows. **Diagnostics-and-terminal
carve-out**: the panic path and
**`power_shutdown` / `power_reboot`** (→ `cpu.powerAction`,
`kernel/syscall/system.zig`) deliberately stop cores and sit outside the
machine's liveness obligations; they are not T3 rows and MUST NOT be
reachable from any non-diagnostic, non-terminal path
(analyzer-checkable). Round 7 minor: the `power_*` family was missing
from this list, which mattered because it is a *syscall* — reachable
from user code by capability, unlike the panic path — so an analyzer
closing 9.3(6b) over the syscall surface would have flagged it as an
unexplained core-stopping path.

**`power_sleep` is NOT in that carve-out, corrected in revision 16.**
Revisions 14 and 15 filed it here as terminal while §0.2 had already
judged it on the test and landed it **OUT by reason B** — the spec says
it RETURNS on wake, so it is not terminal, and it neither moves an EC
between cores nor changes its runnability from the scheduler's view; the
core idles and resumes the same EC. §0.2 asserted in the same breath
that "§3.6's diagnostics carve-out is corrected to say so", and it was
not, so the document contradicted itself across two sections for two
revisions. It is still not a T3 row — it is a halt, not a spin on a
remote word — but the reason is §0.2's exclusion, not terminality, and
an analyzer closing 9.3(6b) must whitelist it on that ground.

---

## 4. The hop

Canonical order: **release first, then commit**.

> **Hop contract.** On the park stack immediately after the swap:
>
> 1. **Release**: overwrite `PerCore.current` and repoint TSS.RSP0 /
>    gs:0 / SP_EL1. By the time the EC is claimable-as-`waiting`, no
>    core's `current` names it.
> 2. **Commit**: act on `outgoing.state`:
>    - `parking` → CAS to `waiting`. Success: claimable, SP and `current`
>      already released.
>    - CAS failed → the failed CAS returns the current value:
>      - `claimed`: (only possible for a rendezvous sender that claimed
>        its receiver — its own state cannot be `claimed`; this arm is
>        for completeness: outgoing `claimed` is unreachable, assert.)
>      - `pended`: a waker claimed this parking EC. Acquire-spin
>        `payload_done` (W2 — bounded), then **discharge**: placement
>        CAS `pended → ready` + link under the destination queue lock,
>        **computing the destination from the FRESH descriptor inside
>        that lock section** (round 7 M-2 — rev 7 said "honoring the
>        staged destination/priority" here while §8.1 said the
>        discharger "reads the fresh descriptor"; the staged core is now
>        a locality hint with no authority, which resolves the
>        contradiction, deletes the only consumer of the staging, and
>        makes an `affinity`/`priority` edit that lands mid-flight
>        take effect at this placement instead of being silently
>        overridden by a stale stage). On placement-CAS
>        failure (`retired`): perform the deferred marking (§8.2), then
>        finalize. The owner core is the holder-of-record for every
>        `pended` obligation, and it is guaranteed to reach this arm:
>        `pended` only exists between the claim and this core's hop
>        step 2, and rule 3.1(1) cannot preempt the park sequence.
>      - `retired`: deferred marking + finalize, **with no wait**: a
>        retire whose observed from-state was `pended` acquire-waited
>        `payload_done` *before* flipping the state (edge 9, §8.2, W7),
>        so by the time any party observes `retired` the claimant's
>        payload is complete. (Rev 4 conditioned a hop-side wait on the
>        hop's own prior observation of `pended` — a fact the retire
>        destroys: on `parking → pended → retired` before the hop's
>        first CAS, the hop never sees `pended` and the state word no
>        longer carries the pend; both readings of that iff failed —
>        round 4 F1.)
>    - `parking(kind=requeue)` → placement CAS `parking → ready` under
>      the destination queue lock, destination computed there from the
>      fresh descriptor (M-2, as above); on failure (`retired`) →
>      finalize.
> 3. Proceed: dispatch tail, or `run()`.
>
> x86 EOIs the in-service scheduler vector before parking, as today.
>
> **Degenerate hop.** A scheduler-context core whose SP was never on the
> outgoing EC's kstack executes the same contract, same order, in place
> (the vCPU pre-loop's rule, §8.1).

Every scheduler exit path goes through the hop or its degenerate form.
Claimable ⇒ kstack-quiescent holds for every slow-path exit; the fast
path meets it via §9.4. The wake side now contains **no waits at all**:
5a/5c claimants discharge inline against quiescent targets; 5b claimants
pend and return. The owner-side `payload_done` wait (W2) is the entire
residue of `on_cpu`, and it runs in scheduler context only.

---

## 5. The transition table

All transitions execute in `kernel/sched/lifecycle.zig` (§9.1) except the
pinned fast-path sites (§9.4). Absent rows are illegal (debug assert on
every CAS). **Fused edges** are declared compositions of rows whose
intermediates are unobservable, legal only when listed in §9.4 and only
if the compressed CAS preserves every component's from-state check and
failure arm — never a plain store (the resurrection shape S8 prevents).

| # | Edge | Actor | Trigger | Precondition | Postcondition |
|---|---|---|---|---|---|
| 1 | *(slab-private)* → `ready` | creator | `publish`, the last step of creation | all fallible work done; nothing externally visible yet; **domain liveness validated under the CD `_gen_lock` inside the publish section** (§8.5). `create_vcpu` follows the same runnable-first shape: the vCPU is published ready and its first dispatch synthesizes the initial `vm_exit` through the normal running→parking path | gen live + linked, one lock section; domain-dead ⇒ private-unwind arm. **Paused-domain arm (round-13 C-1): the same section reads `cd.paused`, and publishes into `waiting(domain_pause)` rather than `ready` when set** — which is what keeps the pauser's runnable predicate from growing underneath it without the pauser holding any lock |
| 2 | `ready` → `running` | dispatching core | dequeue / **`yieldTo` target — qualified in §8.1 (round 7 M-4): `ready` ON THIS CORE'S QUEUE, S7-live, and affinity-mask-admitted; anything else degenerates to a plain `yield`** | inside `core_locks[core]` — a single core lock, which is exactly why the `yieldTo` arm is local-only; S7 filter (failure ⇒ dispatcher retires inline, §3.2); CAS wins | `current`, `owner_core`, queue field — same section; then park-stack tail PMU handoff and SP/root load. If lifecycle is no longer `running` after PMU handoff, save/disable the restored PMU file, clear its owner token, complete any pending PMU-state release, and abandon to `run()` |
| 3 | `running` → `parking` | owner core | blocking syscall, wfi/hlt trap, event-route delivery, directive consumption (user boundary), **domain-paused gate (user boundary, BOTH legs, §0.3 / §3.1 rule 3 — the pause's ONLY route, and it is uniform over the target's prior state; the return leg is subject to §3.3's quiesced-resume rule)**, preempt tick (requeue; `pin_depth == 0`), **plain `yield` and the `yieldTo` caller's own requeue park (requeue — round 6 M4; this list is the closure and had omitted both)**, affinity migration (requeue). **PRECEDENCE (round 7 M-5): where directive consumption and the preempt tick are both enabled — i.e. the tick lands on an unpinned user-mode frame with `directive_state == armed` — CONSUMPTION WINS; the tick is an entry from user mode and §3.1 rule 3 runs its checks before the requeue arm.** | park sequence §3.2 (staging pre-publish; links+CAS under final container lock; requeue = bare CAS) | straight line (bounded work) to the hop |
| 4 | `parking` → `waiting` | owner core | the hop (or degenerate) | SP off kstack / never on it; `current` released (hop step 1) | claimable; `owner_core` poisoned (debug) |
| 5a | `waiting` → `claimed` | any waker/mover (any context) | see T1 (§5.1) + syscall-context sources: the `futex_wake` syscall, recv pop, close propagation, reply via pin, rendezvous pop, suspend of idle-waiter, **`vm_inject_irq` waking a wfi-parked vCPU (round 6 M4; 5b if it races the vCPU's park; no T1 row unless an IRQ-context injection path is ever added, which would require one)** | CAS under R-claim; one winner per episode | holder owns descriptor+frame; unlinks containers incl. deadline node; **holder discharges** (edges 6/7) |
| 5b | `parking` → `pended` | any waker (any context) | same wake sources racing a not-yet-committed park | CAS under R-claim | claimant: unlink + payload + `payload_done` release-store, then DONE. **Owner core discharges at its hop** (§4): placement, finalize-on-retired, deferred marking |
| 5c | `ready` → `claimed` | cross-EC suspender; the dispatcher on S7-filter failure (§3.2, F2); the `affinity` claim-move (§8.1) | `suspend` of a `.ready` target; a popped gen-dead-domain EC; **a cross-EC `affinity` edit whose new mask excludes the target's current queue core (round 7 M-6 — rev 7 applied the closure standard to edge 3 and not to this row, so the rev-7 claim-move it had just introduced was missing from its own trigger list)**. NOT a trigger: a `priority` edit — the new bucket is in the SAME container, so it is an in-lock relink with no state change (§8.1) | inside the target's run-queue lock: unlink + CAS | holder discharges (edge 7; or edge 6 for the claim-move; or retire-as-holder for the S7 route) |
| 6 | `claimed` → `ready` | the holder | wake placement; **domain-pause RESUME — the pauser 5a-claims each paused EC off its domain's list and places it (round-12 C-1: the resume moves N ECs back onto cores, which §0.1 defines as in scope, and revision 13 had no edge for it)** | payload complete; CAS-then-link inside destination queue-lock section, **destination computed there from the fresh descriptor** (M-2) | failure ⇒ `retired` ⇒ holder performs deferred marking + finalize |
| 6p | `pended` → `ready` | **owner core, at its hop** | hop `pended` arm | `payload_done` observed; CAS-then-link inside destination queue-lock section, destination from the fresh descriptor (M-2) | failure ⇒ `retired` ⇒ owner performs deferred marking + finalize |
| 7 | `claimed` → `waiting` | the holder | re-containment: recv pop → reply pin; suspend of ready/idle → port; delivery-failure relink. **Not domain pause**: `waiting(domain_pause)` is published directly by §3.1 rule 3's boundary arm as edge 3 (`running → parking`) followed by the hop to edge 4 (`parking → waiting`), under the CD `_gen_lock`; no holder claim or edge 7 re-containment exists on that route | descriptor re-targeted; CAS-then-link inside destination wait-container lock section (the link's bucket key reads the fresh `ec.priority`, §3.4) | failure ⇒ `retired` ⇒ holder: deferred marking + finalize + undo partial placement |
| 8 | `parking(requeue)` → `ready` | owner core | the hop | placement CAS inside destination queue-lock section, destination from the fresh descriptor (M-2) | failure ⇒ `retired` ⇒ finalize at hop |
| 9 | `{ready, waiting, running, parking, claimed, pended}` → `retired` | retirer | retire | CAS fused with gen flip under `ec._gen_lock` (order EcGen → CoreLock when the run-queue lock is also needed, §3.5); **if the observed from-state is `pended`, acquire-wait `payload_done` before the CAS** (W7; the CAS loop re-dispatches on the fresh state if the owner's discharge wins meanwhile — F1) | routing per the retire matrix (§5.2); marking eager only for stable descriptors, else deferred to the discharger, with terminate waiting (L5) |
| 10 | `retired` → *(freed)* | the designated finalizer (§5.2) | finalize | kstack quiescent per route; pended-origin payload completion guaranteed by edge 9's pre-CAS wait (F1) | **finalize's first act is the idempotent container unwind** (§8.2, N4), then deferred marking, release body (directive → `dead`, F6), kstack unmap (epoch-quarantined), slot zero + freelist |

Not a state edge: remote suspend of a `running` target — directive
protocol (§2.5).

Notes: no `running → ready` edge exists; every transition into `ready` is
CAS-then-link under the destination queue lock (edges 1, 6, 6p, 8);
retire is one operation with all five of today's retire-flavored paths as
callers.

### 5.1 T1 — interrupt-context wake sources (closure table)

Normative. Every path from an IRQ/exception entry to a claim must match a
row. The intended maintenance regime is tooling, not recall (round 3's
meta-finding; `device_region.onIrq` went unenumerated for three
reviews): analyzer rule 9.3(6) — derive the path set from the callgraph
DB, fail CI on an unmatched path — **is a requirement on future analyzer
work, not a current capability** (round 6 M2; no such check exists in
the tree today). Round 4's closure of this table was a manual
re-derivation against the callgraph DB — tool-assisted, human-driven —
and it is the one table that survived hostile re-derivation with zero
defects.

| Source | Today's entry | Persistence | Claim → discharge | Lost-claim semantics |
|---|---|---|---|---|
| futex deadline expiry | tick → `expireTimedWaiters` | periodic scan over intrusive nodes | 5a → claimant places inline; 5b → `pended`, owner's hop places | loser leaves node; winner unlinks (L4) |
| recv deadline expiry | tick → `expireTimedRecvWaiters` | periodic scan (same unified table, §8.4) | same | same |
| timer wheel (one-shot & periodic) | tick → `wheelExpireDue` | **one-shot pop** — the firing consumes the registration | same; the pop is consumed by the claim exactly once — no re-insertion, no replay, no double side-effects (X3) | losing to a racing winner is safe: the wake's meaning is level-encoded (futex word / port event already staged) and the winner delivers it |
| device-region IRQ | device IRQ → `device_region.onIrq` (`device_region.zig:552-586`) — masks the line until userspace acks, then `futex.wake` | **one-shot until user ack** — the would-be acker may be the very EC being woken | same: 5a inline or 5b `pended`; the owner's hop places the waiter, which then runs and acks. **No decline path exists**, so the X3 lost-interrupt (wake dropped, acker parked, line masked forever) is unconstructible | as above — level-encoded ack word |
| event-route delivery from exception/IRQ context (fault, breakpoint, PMU overflow) that rendezvouses with a parked receiver | `fireRouted` → `rendezvousWithReceiver` | event is carried by the suspending EC; receiver wake is the interrupt-context claim | receiver 5a → place inline; receiver 5b → `pended` | claim loss impossible per-episode (one receiver pop per rendezvous, under the port lock) |

Row template for future sources: name the entry, the persistence class
(periodic vs one-shot), and the discharge — which after this revision is
always "5a inline or 5b pended"; the **retry-party column is gone because
no row declines**. That deletion is the X2/X3 closure.

### 5.2 T2 — the retire matrix (closure table)

Normative. Rows: the target's state at retire's CAS. Columns: the
target's own continuation — **U**: next runs user code / last seen in
user mode; **K**: has an in-flight kernel frame (e.g. requeue-preempted
mid-syscall, or currently executing); **K+C**: in-flight kernel frame
holding ≥1 claim or non-IRQ-masked lock (`pin_depth > 0`). Every cell
names the discoverer and finalizer or proves the cell unreachable. X1 was
two empty cells in this matrix.

| State \ cont. | U | K | K+C |
|---|---|---|---|
| `ready` | retirer, inline (EcGen → CoreLock, §3.5) | retirer, inline — safe because the lock dichotomy (§2.4, computed membership) guarantees a requeue-preempted frame holds no lock at all: IRQ-masked sections cannot span a tick, and pin-class holders are never preempted. (Rev 4's "holds nothing whose orphaning matters" rested on a recalled, wrong pin class — F3.) **CONDITIONAL on §2.4's ORDERING rule** (round 7 C1): "pin-class holders are never preempted" is true only if the bump precedes the acquire. Under `lock(); pin_depth += 1;` this cell's justification is FALSE and this row inline-finalizes a frame holding the slab lock — the model reproduces it in four states (`pinord` falsifier, `InvNoPreemptedLockHolder`) | **unreachable**: the pin gate forbids requeue-preempting a pinned frame (X1 cell 1; sound as of F3's computed membership AND C1's ordering rule) |
| `running` | owner core: wake IPI → user-boundary check → hop+finalize | owner core: frame runs to its hop (commit-failure arm) or syscall completion + boundary. **CONDITIONAL on every in-flight kernel frame being able to COMPLETE (round-8 C-1)**: this cell's whole argument is "the frame runs to its hop or to syscall completion", and a terminator parked in the W3 eviction wait for an EC that will never leave `current` does neither. That is not a hypothetical — it is mutual terminate, and TLC reaches it in 7 states. The §3.6 W3 exits (self carve-out; retired terminator abandons the wait) are what make this column true; without them a `retired` EC sits in a kernel frame forever and L2 is violated permanently | same as K: the frame is the running computation — it completes, discharges its claims (`pin_depth → 0`), then discovery at hop/boundary. Never abandoned (§3.1 rules 1+3), and never STUCK (the W3 exits above) |
| `parking` (wait) | n/a (parking is a kernel sequence) | owner's hop commit-failure arm → finalize (whose leading unwind clears the episode's links, §8.2 N4) | reachable — the rendezvous sender holds a claim on its receiver mid-delivery. The sequence is the running computation: it completes delivery (discharging the claim), reaches its hop, hop finds `retired`, finalizes. Routed |
| `parking` (requeue) | n/a | owner's hop placement-CAS fails → finalize; frame's saved continuation has `pin_depth == 0` (it was preempted under the gate) | **unreachable** (pin gate — X1 cell 2) |
| `waiting` | retirer, inline (after unwind under container locks) | **n/a — but NOT for the reason rev 9 gave** (round-9 M-7). Rev 9 said "a waiting EC's park sequence completed", which is false as a universal: §8.3's cross-EC suspend of a `.ready` target reaches `waiting` via **5c + edge 7**, with no park sequence anywhere — the EC was claimed out of a run queue and re-contained by its holder. The cell is still n/a, and the correct reason is the one that covers both routes: **whichever party last placed the EC into `waiting` had discharged its claim and left `pin_depth == 0`** — the parking core by the §2.4 publish assert on the park route, the holder by edge 7's discharge on the 5c route. The conclusion survives; the justification did not | unreachable (`pin_depth == 0` on every route into `waiting`, not just the park route) |
| `claimed` | — target's own frame is parked (origin was `waiting`) or a preempted pin-free frame (origin `ready`); either way it holds nothing | same | discharge belongs to the **holder** (another path): holder's placement-CAS fails → deferred marking + finalize. Holder guaranteed alive: its frame is pin-gated and boundary-gated. `owner_core` is NOT read (invalid, §2.4) |
| `pended` | — | — | discharge belongs to the **owner core's hop**: guaranteed still to come (pended exists only pre-hop-step-2; the park sequence is unpreemptible-away per rule 3.1(1)). Retire itself pre-waits `payload_done` before its CAS (edge 9, W7 — F1), so the hop's retired arm finalizes without waiting. The `claimed` row needs no such pre-wait: its discharger is a live party that learns `retired` from its own failed placement CAS |
| `retired` | — | — | (finalize only; not a retire source) |

Marking column (spec §[terminate] test 07): eager at retire for
stable-descriptor rows (`ready`, `waiting`, `running`); deferred to the
cell's named discharger for `claimed`/`pended`/pin-writing `parking`;
terminate waits for deferred marking before returning (W4, L5). The
column's carrier is the `mark_state` word (§2.4, round 7 M-3) — this
table names the discharger for each cell, and that word is what the
discharger and the terminator hand off through.

### 5.3 T4 — pop/scan sites over wait containers (closure table)

Normative (round 6 M3). The retired-but-linked licence (§8.2, N4) — a
`retired` EC may remain linked in wait containers until its finalize's
unwind — quantifies over EVERY site that pops, scans, or iterates any
wait container. Rev 6 asserted that universal by recall; given this
project's operative lesson (tool-closed T1 survived hostile
re-derivation; recall-closed T2/T3 held all three criticals), that is
exactly where the next critical lives, so the enumeration is now a
table. Each row must confirm: deref only under the container's lock (or
the stated ref-gating), and every actionable read resolved by claim-CAS
(fails on `retired`) or the `stale(ec)` skip (§9.2). **Derivation
column: every row below is RECALL-derived from this document's own
citations — none is tool-derived yet.** Converting this table to a
computed one is part of 9.3(6) (future, per §2.5's enforcement status);
until then, adding a pop site without a row here is a defect by
definition.

| Container | Pop/scan/iterate sites | Deref discipline | Retired-EC handling | Derivation |
|---|---|---|---|---|
| run queue (per core) | edge-2 dequeue; retire's ready-row unlink; S7 claim route; the `affinity` claim-move (5c) and the **`priority` in-lock re-bucket** (§8.1) | under `core_locks[core]` | edge-2 CAS fails on `retired`; pop-side `stale` skip (§9.2); the re-bucket re-validates state + residency under the lock and does nothing to a non-`ready` EC | recall |
| ~~per-core idle slot (§2.1.1)~~ | **ROW DELETED IN REVISION 16 — it is not a container, because there is no idle EC to contain.** §2.1.1 is withdrawn: `idle_ec` is declared, read once unreachably, and never assigned, and the tree parks an idle core on its own park kstack via `parkAndAwaitIRQ` precisely to avoid the cross-core kstack sharing an idle EC caused. A core with an empty run queue holds NO EC, so this row's S1 claim ("the slot counts as the queue") had nothing to quantify over. The row was marked `recall` and was wrong — **which is the T4 table's own standing warning working as intended** | — | — | **was `recall`; now retracted** |
| port queue | recv pop (5a); close propagation; cascade destroys; **`priority` re-bucket** (§8.1 — `Port.waiters` is an `EcQueue` whose `enqueue` keys on `ec.priority` at LINK time and whose `dequeue` never re-reads it, so a bare field store leaves the old selection order standing) | under the port `_gen_lock` | claim CAS fails on `retired`; skip | recall (`port.zig:613`, `sched/priority_queue.zig`) |
| futex buckets (**plural** — one waiter links into every bucket of its multi-word wait) | `futex.wake`'s bucket pop, **plus the same function's re-enqueue of the non-matching nodes it dequeued** (`futex.zig:249,255,364` — multiple paddrs hash to one bucket, so a dequeued node may not match the wake's address; VERIFIED present, round 7); **`priority` re-bucket** of every node of the wait (§8.1 — the `WaitNode` SNAPSHOTS `ec.priority` at park, `futex.zig:427,530`) | under the bucket lock(s), sorted all-buckets discipline for multi-bucket ops | gen-checked `node.ec.lockIrqSave` generalized to claim-CAS-or-skip (§3.5) | recall (`futex.zig:434`) + the cited line numbers, re-checked against the tree in round 7 |
| deadline table | tick scan (`expireTimedWaiters`/`expireTimedRecvWaiters`) | under the table lock | claim CAS fails on `retired`; loser/stale nodes left for the unwind | recall (§8.4) |
| timer wheel | `wheelExpireDue` pop | under the wheel lock | pop finds `retired` ⇒ pop consumed, moot (T1/§8.2) | recall (§5.1) |
| device-region list | `onIrq` waiter lookup | under the device-region lock | claim CAS fails on `retired`; line stays masked (see G6 note, §8.4) | recall (§5.1) |
| **paused-domain EC list** (`kind == .domain_pause`, round-12 C-1) | the pauser's resume walk at syscall completion; §8.2's teardown walk over the same list | under the CD `_gen_lock` | a `retired` EC is skipped by the resume walk (its 5a claim CAS fails); the terminate/teardown path owns it from there | recall |
| **`terminate`'s handle deref** (round-10 M-G — MISSING from rev 10) | the `terminate` syscall resolving an EC handle to a `SlabRef` and retiring through it | ref-reached: caller-CD lock, then EC `_gen_lock` gen validation (R-claim's second arm, §3.5) | claim/retire CAS fails on `retired`; a stale handle returns E_TERM per §[terminate] | recall |
| **domain teardown walk** (round-10 M-G — MISSING from rev 10) | §8.2 phase 2 iterating a dying domain's ECs and retiring each | ref-reached, scheduler context: CD `_gen_lock` for the walk, EC `_gen_lock` per victim | victims already `retired` are skipped; the walk is the retirer for the rest | recall |
| reply-pin handle slot | reply / reply_transfer / delete-E_ABANDONED via the pin | **ref-reached, NOT container-lock-reached**: the pin is a KernelHandle in the HOLDER's domain table; deref under the holder-CD lock with EC `_gen_lock` gen validation (R-claim's second arm, §3.5) | claim CAS fails on `retired`; if the HOLDER domain is itself in teardown, its gen is dead and the handle resolution fails — teardown's handle release owns the slot, and finalize's unwind treats a dead-gen pin as already-unlinked (idempotent skip) | recall (§8.3) |

Two memberships the "under each container's lock" phrasing glosses,
now explicit: a **timed waiter is linked in two container kinds at
once** (its wait container and the deadline table) and a **futex waiter
in as many buckets as its wait spans** — finalize's unwind (§8.2) MUST
visit every container the descriptor names, in the container-lock
discipline of each, and the claim winner's unlink (edge 5a/5b) already
does. The reply pin's unwind order is holder-CD lock, then the EC gen
validation inside it — never the reverse (no EC-gen → CD edge exists;
§3.5's pinned order stays acyclic).

---

## 6. Invariants

### 6.1 Safety

- **S1 (containment).** As §2.1's table; every membership edit inside the
  container's lock section with the state CAS that implies it, or by the
  exclusive holder/retirer/owner-discharger. *(Forecloses 6, 7.)*
- **S2 (single writer).** Every §3.4 fact written only by its named
  writer context; descriptor per §2.2. *(Forecloses 3, 5.)*
- **S3 (kstack quiescence).** SP of any core in `ec.kernel_stack` ⇒ that
  core is `ec.owner_core` and `ec.state ∈ {running, parking, pended}` or
  `retired` pending that core's hop. `ready`, `waiting`, `claimed`, and
  every finalize-eligible configuration imply no core on the kstack.
  *(Forecloses 8's dispatch half; with §5.2 routing, all of 8.)*
- **S4 (claim uniqueness + holder persistence).** One claim winner per
  episode; only the winner writes payload; losers leave registrations
  intact. A won claim is never orphaned: the pin gate (§3.1 rule 1)
  forbids requeue-preempting a claim-holding frame — **which requires
  §2.4's ordering rule on the claim side** (round 7 C1: the bump is
  executed inside the same IRQ-masked reaching-lock section as the claim
  CAS; a bump taken after that section is dropped leaves a window in
  which the frame holds a claim at `pin_depth == 0` and the tick may
  preempt it, which is X1 again) — the user-boundary
  gate (rule 3) forbids entry checks abandoning it, and the hop's retired
  arm applies only to the frame's own EC after its claims are discharged
  (§2.4 assert). *(Forecloses 7, X1.)*
- **S5 (retire fusion).** `gen even ⇔ retired ∨ freed`; one operation
  under `_gen_lock`. *(Forecloses 1.)*
- **S6 (word granularity).** Nothing cross-core-readable wider than a
  word outside CAS-won-exclusivity publication. *(Forecloses 3.)*
- **S7 (dispatch filter + routing).** Edge 2 commits only
  gen-live-domain `ready` ECs; a filter failure claims the popped EC
  (`ready → claimed` under the queue lock) and retires it as holder
  after the lock drops — never a silent drop, and never a
  CoreLock → EcGen inversion (F2). *(M-A residue.)*
- **S8 (placement gate).** Transitions into `ready` are exactly edges 1,
  6, 6p, 8, all CAS-then-link under the destination lock;
  placement failure always routes to the cell's finalizer. Fused
  publishes preserve this. *(Forecloses 6, 7, resurrection.)*
  Not a transition, and therefore not an S8 or S1 event: the `priority`
  in-lock re-bucket (§8.1) unlinks and relinks a `ready` EC **within
  the same run queue, inside that queue's lock section** — the state
  word is not touched and container membership does not change, only
  intra-container position. Every edit that *does* move an EC between
  containers is a claim-move and appears above (round 7 C2/M-6).

### 6.2 Liveness

- **L1 (parks complete).** Publish → hop is bounded work; the sequence is
  never abandoned (rule 3.1(1) fails on `parking`/`pended`). This bounds
  W2 and the pended discharge. Analyzer 9.3(2).
- **L2 (retired ⇒ freed).** Every retire names exactly one finalizer at
  CAS time — the §5.2 matrix is total. Bounds: inline (immediate); owner
  hop (kernel sequence + one user-boundary event, IPI-prompted, or the
  parked-core heartbeat); holder/owner discharge (L6/L1 instructions +
  scheduling). *(Forecloses 1, 4.)*
- **L3 (ready ⇒ dispatched).** The locked park decision + wake-IPI rule,
  normative as today. *(Forecloses 7's lost-enqueue half.)*
- **L4 (deadlines and one-shot wakes fire).** Registrations are unlinked
  only by a claim winner or retirer. There is no decline path (rev 3's
  same-core carve-out is deleted with its rule), so a timed wait cannot
  lose its timeout and a one-shot wake cannot be dropped: the claim
  either wins (discharge per §5.1) or loses to a racing winner whose
  delivery subsumes it (level-encoded payloads, §5.1). *(Forecloses X3.)*
- **L5 (terminate: eviction + marking).** Terminate returns after the
  target leaves its core's `current` slot AND after any deferred marking
  has been performed by the §5.2 discharger. The marking wait is W4:
  lock-free, preemptible, ack-while-spinning, bounded by the discharger's
  instruction count plus scheduling latency. *(M-C.)*
  **Two exits, both normative (round-8 C-1, §3.6 W3):** the wait is
  skipped when the target IS the caller, and abandoned when the caller
  has itself become `retired`. Neither weakens the property as an
  observable: L5 constrains what a terminate *returns* to user mode, and
  in both exits the caller either never waited on itself or is dying and
  will never return at all. Without the second exit, two ECs terminating
  each other deadlock both cores permanently and L2 is violated forever
  — which is the shape L2's "the matrix is total" argument does not
  reach, because the matrix quantifies over the retire TARGET and this
  defect is in the retirER.
- **L6 (wake bodies complete).** Claim → discharge is straight-line:
  payload writes and bounded lock acquires only — **no remote waits of
  any kind** (the release-wait is deleted). Syscall-context bodies are
  pin-gated (not preempted while holding the claim); interrupt-context
  bodies complete within their handler. This bounds W2 and W4.
- **W5 scope note (round-16 model clarification).** The W5 return
  obligation is for a suspender whose own frame remains executable. If a
  later lifecycle operation claims, parks or retires the suspender itself
  while it is requeue-preempted in the W5 loop, the syscall is externally
  blocked or dying; L3/L6/L2 cover that transition, and the EC-lifecycle
  machine does not force a user-level resume request.

---

## 7. The eight failure classes, and where each dies

1. **Orphaned `.exited`.** S5 + L2 (the matrix is total).
2. **Abandoned must-complete frame.** §3.1's three gates cover the three
   abandonment vectors (entry checks, requeue preemption, hop's retired
   arm); teardown — including the dead-mark itself — runs in scheduler
   context (§8.2); creation failure unwinds private state in a
   gate-protected kernel frame (§8.5). The requeue-preemption gate is
   only as good as `pin_depth`'s ORDER (§2.4, round 7 C1): a counter
   bumped after the thing it protects is acquired leaves the gate open
   for exactly the instructions that matter.
3. **Torn state read.** S6/§3.4.
4. **Stranded liveness flag.** No flag exists; the pended hand-off and
   `payload_done` are consumed at a hop that unconditionally runs.
5. **Predicate drift / missing per-arch writer.** One chokepoint, one
   stale predicate, writer-set pinning, paired-arch analyzer.
6. **Ownerless EC.** Edge 1 (publish = containment, domain-gated);
   S7-failure routing retires rather than drops.
7. **Lost wake / lost enqueue / double enqueue.** S4 + S8 + L3 + L4 +
   T1's no-decline closure; publish-under-lock (container-reached) and
   the FP in-lock publish (ref-reached) close the observation windows;
   `pended` latches wake-vs-park with a guaranteed discharger.
8. **Reap while live.** S3 + the §5.2 matrix + R-claim closure + edge
   9's `payload_done` pre-wait before any pended-origin retire (W7) +
   finalize's leading container unwind before any free (N4).

---

## 8. Integration and reclamation

### 8.1 Scheduler

- Dispatch = edge 2 + dispatch sequence (with S7 routing). Preempt =
  edge 3(requeue, pin-gated) + edge 8. Idle parks in scheduler context.
- **vCPU pre-loop**: `ready → running → parking(port_queue) → waiting`
  with `wait.port = exit_port` and commits via the degenerate hop, same
  contract including the `pended` arm — a VMM reply racing the loop lands
  as 5b and the pre-loop's degenerate hop discharges it after
  `payload_done`. There is no separate `exit_port` wait kind.
- `lifecycle.wake(ec, payload)` = claim + payload + (5a/5c) placement or
  (5b) pend. `markReady`'s `.running` arm and every wake-side spin are
  subsumed.
- **`yieldTo`, target side (round 7 M-4)** — rev 7 gave edge 2 the
  trigger "yieldTo target" and never said which targets qualify.
  Normative: the caller dispatches the target **only if it is `ready`
  ON THIS CORE'S QUEUE, passes the S7 domain filter, and its affinity
  mask includes this core**; otherwise the call degenerates to a plain
  `yield` (the caller requeues, edge 3, and the scheduler selects).
  Local-only is what makes edge 2's "one `core_locks[core]` critical
  section" true: pulling a target off another core's queue would need
  two core locks and a new CoreLock→CoreLock order edge, and the claim
  route cannot substitute because there is no `claimed → running` edge.
  The mask check is the part the tree lacks today
  (`scheduler.zig:900` checks state + `domainRefAlive` + local-queue
  residency but not the mask) and it is mandatory: dispatching a target
  whose mask excludes this core defeats `affinity` outright. **Spec
  narrowing, named not hidden**: §[yield]'s Description says "that EC is
  scheduled next", which local-only does not deliver for a target
  queued on another core; §[yield] [test 03] — the observable side
  effect is visible before the caller's next syscall returns — IS
  satisfied, since the target's own core dispatches it. Recorded as a
  maintainer call in §11.12 rather than resolved here.

- **API sufficiency (round 6 M4, corrected in round 7)** — two syscalls
  edit facts the machine had no rows for. Both edit **stable per-EC
  words, not wait-descriptor fields** (§2.2/§3.4), and both share one
  reach-and-validate protocol:

  > **Reach-and-validate** (round 7 M-1; rev 7 said only "descriptor
  > write under the reaching container lock" and specified neither the
  > reach, the re-validation, nor the lock order).
  >
  > 1. Resolve the handle under the caller's CD lock.
  > 2. Under the target's `_gen_lock` with gen validation (R-claim's
  >    second, ref-reached arm — §3.5): **write the word**, and read the
  >    target's state plus the identity of the container(s) it is linked
  >    in. Then **release the gen lock** — never hold it across step 3
  >    for a wait container (see the order below).
  > 3. Repair the existing links by **DROP-AND-RETRY** (§3.5, and this
  >    replaces revisions 10–12's "blocked on a lock-order design"):
  >    take the container lock computed in step 2 and re-validate under
  >    it. **On mismatch there is NO retry** — step 4's argument is the
  >    complete one and this step must not contradict it (round-13): the
  >    word is already written, so every later link reads it fresh, and
  >    the only thing a mismatch costs is the repair of a link that no
  >    longer exists. A retry here would be an unbounded loop on a
  >    remote word with no T3 row, which §3.6 forbids and which step 4
  >    explicitly denies creating. **Only one lock class is held at a
  >    time**, so no cross-class order needs to exist for this to be
  >    correct — which is why it is not blocked on anything. For a
  >    multi-bucket futex wait the buckets are one class and are taken
  >    in the sorted order §5.3 already requires.
  >    Re-validate gen, state, and linkage inside the innermost hold
  >    before touching anything. **The repaired key is a FRESH READ of
  >    `ec.priority` taken inside that innermost hold — never the value
  >    this call wrote** (round-9 C-3). The natural Zig is wrong:
  >    `n.key = new_priority`, using the syscall argument, desyncs the
  >    word from the key permanently whenever two `priority` calls race
  >    one target. A writes 1, B writes 3, both release the gen lock,
  >    then B repairs the link to 3 and A repairs it to 1 — leaving
  >    `ec.priority == 3` with the linked key at 1, forever, because
  >    `dequeue` never re-reads and a parked waiter has no next link.
  >    That is round-8's C-2 defect in its concurrent form, and it is
  >    SILENT: [test 08] reports field0 = 3 while selection uses 1.
  >    Neither caller is doing anything unusual — no cycle, no mutual
  >    relationship, both need only `spri`. **Mirror this for
  >    `affinity`**: the claim-move's destination is computed from a
  >    fresh read of `ec.affinity` under the destination queue lock, not
  >    from the mask this call passed — which is the same rule M-2
  >    already gave every placement ("computes from the fresh
  >    descriptor"), now stated for the repair path too. **The accepted states for a
  >    wait-container repair are `{parking(wait), waiting}`, not
  >    `waiting` alone** (round-8 C-2): a `parking(wait)` EC is already
  >    linked, and an edit arriving while its owner core is still
  >    walking to the hop must repair the link it finds — deferring to
  >    a relink that never happens is exactly the C-2 hole.
  > 4. On re-validation failure the target moved, and **there is no
  >    retry**. The word is already written, and every link created
  >    *after* that write reads it fresh (`EcQueue.enqueue` keys on
  >    `ec.priority` at link time; a claimant's placement computes from
  >    the fresh descriptor, M-2). **Residual, stated exactly rather
  >    than waved at**: a placement that began *before* the write can
  >    create one link carrying the pre-edit key. That requires a wake
  >    racing the edit — so the target is not in the state §[priority]'s
  >    immediacy clause quantifies over — and the exposure is bounded to
  >    that single link: for a run-queue link, one scheduling round,
  >    after which the EC is dispatched and its next enqueue uses the
  >    new key. A single re-dispatch on the fresh state would close even
  >    that, and is a legal strengthening; it is not taken because it
  >    buys a race window nothing observes and costs a second lock
  >    round-trip on every call. Either way: no new spin, no new T3 row.

  - **`affinity` (cross-EC, any target state; kernel bead
    `stygia-me9`)**: consumed at every placement's destination
    computation (edges 1/6/6p/8). State-routed: `ready` **and the new
    mask excludes its queue core** → claim-move (5c under that queue's
    lock, then edge 6 to a satisfying destination); `ready` and the
    mask still admits its queue core → nothing further to do;
    `waiting` → the word alone (a waiting EC has no queue residency to
    repair); `running` → the word alone, honored at the owner core's
    next requeue (tick-bounded, edge 8); `parking`/`pended`/`claimed` →
    the word alone, honored by the in-flight discharger's placement
    (M-2 is what makes this true — under rev 7's staged destination it
    was not).
  - **`priority` (kernel bead `stygia-va7`)** — **rev 7 was WRONG here
    and contradicted the spec** (round 7 C2). Rev 7 said a `ready`
    target must re-place and "all other states take effect at their
    next placement". `specv3.md` §[priority] Description says the
    opposite, verbatim: *"If the target is currently suspended on a
    port or waiting on a futex, the new priority takes effect
    immediately and reorders the target into the appropriate priority
    bucket (this is the mechanism priority inheritance is built on)."*
    [test 06] tests futex wake ordering **and** `recv` selection
    ordering; [test 07] tests effect at the next port event delivery /
    futex wake — i.e. at **selection**, before any placement. Selection
    is bucket-position-determined, not a live field read
    (`EcQueue.enqueue` keys on `ec.priority` at link time and `dequeue`
    never re-reads it; futex waiters snapshot `.priority` into the
    `WaitNode` at park, `futex.zig:427,530`), so "at its next
    placement" is not merely late — for a waiting target it is
    **never**. The machine rule, corrected:
    - `waiting` **and `parking(wait)`** → **re-bucket every wait node
      the descriptor names**, under that container's lock: the port
      queue under the port lock; each futex `WaitNode` in each bucket
      of the wait, under the sorted all-buckets discipline §5.3
      already requires of finalize's unwind. This is a link repair,
      not a claim: state does not change, containment does not move.
      **`parking(wait)` belongs HERE, not with the word-alone states**
      (round-8 C-2; rev 8 put it there and re-opened the defect for the
      one state that matters most). §2.1's containment table is explicit
      that a `parking` EC's "wait episode's containers [are] already
      linked" — §3.2 step 2 puts the links inside the publish section —
      so its bucket key is ALREADY computed and stale. And there is no
      "next link" to fix it: edge 4 (`parking → waiting`) is a state CAS
      that relinks nothing, so the EC arrives in `waiting` still carrying
      the pre-edit key and keeps it for the whole episode. §2.1 calls
      this window one that is "traversed thousands of times per boot".
    - `ready` → **in-lock re-bucket of the same run queue**: unlink +
      relink inside that queue's lock section. **One mechanism, not
      two** — rev 7 offered "5c-claim + edge 6, or an equivalent
      in-lock re-bucket", which is two mechanisms with different lock
      footprints and different races against dispatch. The in-lock
      relink is the one to keep: it holds a single lock, the same one
      dispatch holds, so it cannot race dispatch at all; it changes no
      state (S1 untouched: same container) and performs no transition
      into `ready` (S8 untouched); and it needs no discharger, unlike
      the claim route, which parks the EC in `claimed` where it is not
      dispatchable until someone places it. The general rule this is
      an instance of: **same container ⇒ in-lock relink; different
      container ⇒ claim-move.** Affinity crosses containers, so it
      keeps the claim-move; priority does not, so it does not.
    - `running`/`parking(requeue)`/`pended`/`claimed` → the word alone;
      the next link reads it fresh. `retired` → drop. These four are
      genuinely safe and the reason differs per state, so it is worth
      writing down rather than asserting: `running` has no wait
      containers at all; `parking(requeue)` has none either (§2.1: "or
      a requeue directive") and its edge-8 placement computes the key
      fresh; and `claimed`/`pended` had their containers **unlinked by
      the claim winner** (edges 5a/5b), so their next link — edge 6/6p/7
      — is a genuine relink that reads the fresh word.
    Never a bare field store without the link repair — that store *is*
    the defect (a queued EC keeps its old key until it naturally
    re-enqueues, which for a CPU-bound `ready` EC or a parked waiter
    may be never).

### 8.2 Retire, finalize, and teardown

`lifecycle.retire(ec)`:

1. If the observed state is `pended`: acquire-wait `payload_done` first
   (W7 — bounded by the claimant's L6 body; legal because no retire
   caller is interrupt context, asserted). Then CAS to `retired` fused
   with the gen flip under `ec._gen_lock` (EcGen → CoreLock when the
   ready-row queue lock is also required); the CAS loop re-dispatches on
   the fresh state if the owner's discharge won meanwhile
   (`pended → ready`). This pre-CAS wait is what lets every later
   observer of `retired` — the hop's retired arm above all — proceed
   without waiting (F1).
2. Marking per the §5.2 matrix, recorded in the `mark_state` word
   (§2.4): the owed bit stays CLEAR for stable descriptors and is SET for
   `claimed`/`pended`/pin-writing `parking`, then cleared by the
   cell's named party with a release-store; terminate acquire-waits for the bit to
   clear (W4/L5) so E_ABANDONED-after-return has no E_TERM window.
3. Finalize routing = the §5.2 matrix, total by construction. **Retire
   has no container-unwind step** (round 5 N4 — deleted; see below).

**The container unwind belongs to the finalizer, and to nobody else**
(round 5 N4). Rev 5 made the unwind retire's own step 3 while keeping
the routed finalizers (the hop's retired arm above all) deliberately
wait-free — and named no mechanism ordering the two: the model exhibits,
in seven states, a retire CAS landing between hop-release and
hop-commit, the hop finalizing immediately, and the EC freed while still
linked in its wait containers with the retirer's unwind yet to run — an
unwind that would then walk EC-resident nodes in a zeroed, reusable
slot. Two idempotent unwinders (retirer + finalizer) do not fix this:
the second unwinder must still read the EC's descriptor to discover it
has nothing to do, against a slot the first-to-free may already have
zeroed. The mechanism is therefore single-owner: **`finalize`'s first
act is the idempotent container unwind, under each container's lock
(no-op where the claim winner already unlinked), before the release
body and any free.** Between retire's CAS and its routed finalize, a
`retired` EC MAY remain linked in wait containers; that is legal — the
pop side skips `stale(ec)` (§9.2), a consumed one-shot pop against a
`retired` EC is moot (its wake is level-encoded and the EC is dying),
and bytes stay intact until finalize's zero.

`finalize` runs, in order: the idempotent container unwind (above);
deferred marking (if owed); the release body (routes + bind-ref decs,
exit_port unlink, perfmon, vCPU arch state, FPU-owner clear,
`directive_state → dead` — the terminal value that lets a waiting
suspender distinguish a retired target from a delivered suspension, F6);
kstack unmap (epoch-quarantined); slot zero + freelist. Finalize runs in
EC-syscall or scheduler context only — never interrupt context
(asserted) — and every lock its body takes is IRQ-saving per the
`check_gen_lock` class rule. Grace rules unchanged: bytes intact until
the zero; identity-compare-only for stale bare pointers; payload writers
always hold a claim retire respects, and pended-origin payload
completion precedes the `retired` state itself (edge 9's pre-CAS wait).

**Domain teardown, self-delete path** (`delete(SLOT_SELF)`, no-route
memory-fault) — revised per round-3 M-A: the syscall validates under the
CD lock, releases it, then self-retires (edge 9) and stashes the **CD
ref** in `PerCore.teardown_pending` — the dead-mark has NOT yet happened.
The hop finalizes the caller; the park-stack code consumes the slot and
runs the ENTIRE teardown in scheduler context: **phase 1 (dead-mark,
under the CD `_gen_lock`) and phase 2** (retire every matching EC —
quiescent victims inline, owned victims via IPI — `awaitDomainQuiesced`,
VMAR teardown, handle release, `freeUserAddrSpace`, table blocks, ASID,
`destroyAlreadyMarked`). Rationale: rev 3 dead-marked in EC context
before the self-retire, so a tick in between could requeue-preempt the
caller into a `ready` EC of a dead-marked domain — S7-filtered, never
dispatched, phase 2 never run (class 2 at the exact place the design
claimed deletion). With the dead-mark moved behind the hop, the caller
is preemptible-and-resumable right up to its self-retire, after which
rules 3.1(1)/(3) walk it to the hop; and S7's inline-retire routing
(§3.2) is defense in depth for any dying-domain EC that still lands
`ready`. The domain stays live marginally longer; nothing observable
depends on the dead-mark preceding the caller's park.

**Create-failure path**: unchanged from rev 3 — publish-last creation
means `cleanupPartiallyCreatedCd` unwinds private state in the caller's
kernel frame, protected by the §3.1 gates (not by any liveness claim).

### 8.3 Ports

- **Self-suspend / fault delivery, no receiver**: edge 3 (staging
  pre-publish, links + publish under the port lock), hop. Wakes: 5a/5b.
- **Rendezvous (receiver parked)**, publish-first: stage payload, publish
  `parking(reply_pin, holder=pending)` under the port lock, claim the
  receiver (5a, or 5b → the receiver's own core discharges), drop port
  lock; delivery in the bounded post-publish window (receiver-CD lock —
  pin writes legal per §2.2's iff-rule and its **untimed-sender
  assumption**, now explicit: the sender has no deadline registration,
  so no waker can reach it during the pin write); place the receiver
  (edge 6); hop. A reply arriving pre-hop claims 5b → `pended` → the
  sender's own hop discharges the placement — the modeled replacement
  for today's rendezvous `on_cpu` spin. Mint failure re-links the sender
  to the port queue (pre-hop, under the port lock) rather than stranding
  it [§11.5]; the mint-failure **receiver** arm applies to the 5a-claimed
  receiver only (edge-7 relink) — a 5b-pended receiver's payload +
  `payload_done` delivery is unconditional (its one-shot pop is already
  consumed and its wake is level-encoded; the eventual reply finds the
  sender in the port queue) (round 5 G-RV1). The sender holding the
  receiver's claim while `parking` is the §5.2 parking×K+C cell: the
  sequence completes and discharges before its hop.
- **recv with a queued sender**: pop = 5a claim under the port lock;
  holder mints the pin under the CD lock (sender holder-contained, S1
  intact), places via edge 7; placement failure ⇒ undo mint, deferred
  marking n/a (pin never visible), finalize, re-pop.
- **reply / reply_transfer / delete-E_ABANDONED / E_CLOSED / expiries /
  timer-wheel deliveries**: all `lifecycle.wake` under R-claim; 5a or 5b
  per the target's state; T1 governs the interrupt-context rows.
- **Cross-EC suspend**: `.ready` → 5c + 7; `.idle_wait` → 5a + 7
  (ending `waiting(port)`); `.running` → directive (§2.5, terminal
  re-check/disarm loop); a target observed in `parking`/`pended` is a
  transient — the suspender re-reads until it settles (L1-bounded) and
  dispatches on the settled state, preserving today's observable state
  gate (round 4). Snapshots: by the holder from the frame it owns, or by
  the target's own core from its fresh user trap frame.
- Port lifetime and the vCPU cascade unchanged; cascade destroys are
  `retire` calls.

### 8.4 Futex and timers

- **wait**: edge 3, staging + value checks pre-publish; links + publish
  in the sorted all-buckets section; deadline registration post-publish
  in the same section.
- **wake**: bucket pop under the bucket lock → claim (R-claim) → winner
  unlinks siblings + deadline node → payload → discharge (5a place /
  5b pend).
- **deadline table**: one structure replacing both registries; intrusive
  per-EC node; registration infallible. The tick claims under the table
  lock, drops it, then discharges (5a place or 5b pend) — **no decline
  rule, no same-core carve-out** (deleted with the release-wait). Loser
  ticks leave the node; winners unlink (L4).
- **timer wheel** (`wheelExpireDue`): a T1 row. Its pop is consumed by
  the claim exactly once — 5a inline or 5b pended — so the one-shot
  fire needs no re-insertion or replay and its non-idempotent
  side-effects (counter increments) run once. Rev 3's "applies
  identically; no bespoke path" was false as written because "decline
  and retry" was inexpressible for a pop; with the decline path deleted
  the statement is now true structurally.
- **device-region IRQ** (`onIrq`): a T1 row — the masked-line-until-ack
  one-shot that made X3 critical. Claim + discharge as above; the parked
  acker is placed by its own core's hop; the line unmasks when it runs
  and acks. **G6 (model round), stated rather than implied**: if the
  not-yet-acked acker is cross-EC suspended (5c) while `ready`, the line
  stays masked until it is resumed and runs; if it is retired, the line
  stays masked until device-region teardown releases it. Both are by
  design — the lifecycle machine never re-arms a line on behalf of a
  dead or suspended acker — but userspace owns the consequence.

### 8.5 Creation

Publish-last, fallible-first; the edge-1 publish validates domain
liveness under the CD `_gen_lock` (mutually exclusive with the
scheduler-context dead-mark, which takes the same lock), with the
private-unwind failure arm. The lock-held form is preferred over a
fence-based re-check for auditability. vCPUs may publish into
`waiting(port_queue)` with `wait.port = exit_port`; there is no separate
`exit_port` wait kind. Migration: `create_capability_domain` reordered so
no fallible arm follows a visible mint.

> **<<< IMPLEMENTABLE SPEC — END >>>**
>
> Below this line: enforcement (what is assumed enforced, and honestly
> what is not), essential-complexity notes, maintainer calls, the
> migration plan, and the changelog. §0.2 puts analyzer capability and
> migration sequencing out of scope — they are recorded here, not
> specified here.

<!-- ============================================================= -->
<!-- <<< IMPLEMENTABLE SPEC — END >>>                               -->
<!-- ============================================================= -->

---

## 9. Enforcement

### 9.1 The chokepoint

`kernel/sched/lifecycle.zig` exports `publish`, `dispatchCommit`, `park`,
`hopComplete`, `claim`, `pend`, `place`, `retire`, `finalize`,
`postDirective` — sole writer of `ec.state` (pinned asm excepted); a
comptime table mirrors §5.

### 9.2 Debug-build assertions

- Transition legality on every CAS; placement CASes hold the destination
  lock; `pin_depth == 0` at every hop and at every wait-park publish;
  the requeue claim site asserts the gate; pin-class lock sites bump and
  check `pin_depth` (lockdep integration); retire and finalize assert
  non-interrupt context; retire-from-`pended` asserts `payload_done`
  before its CAS; **every EC-context spin entry (W3/W4/W5) asserts
  `pin_depth == 0`** (T3 rule (b), N1 — W5's deadlock-freedom is
  conditional on it); finalize asserts its container unwind completed
  before the release body runs (N4); **every §3.2 publish asserts
  CAS-before-links within its section, and its failure arm links
  nothing** (M1).
- **EC-context IRQ state (round-9 C-4, §3.3)**: every EC-context spin
  entry (W3/W4/W5) asserts **IRQs ENABLED** as well as
  `pin_depth == 0` — the two together are what "preemptible" means, and
  rev 9 asserted only the second half. Every §3.2 publish and every
  claim site asserts IRQs MASKED (it is inside a container-lock hold).
  These two asserts are cheap and they are the only enforcement that
  exists: no analyzer checks interrupt state, and the model cannot see
  it at all.
- **`pin_depth` ORDER (round 7 C1, §2.4)**: every pin-class acquire site
  asserts `pin_depth > 0` **on entry to the acquire** (the bump already
  executed) and every release site asserts `pin_depth > 0` **after the
  unlock** (the decrement not yet executed) — the two asserts bracket
  the hold and fail exactly on the `lock(); pin_depth += 1;` /
  `pin_depth -= 1; unlock();` orders. Lockdep carries the same check
  dynamically. Every claim site asserts the bump executed **inside** the
  reaching-lock section (same section as the CAS). Companion invariant,
  machine-checked: no `ready` or requeue-`parking` EC holds a pin-class
  lock.
- **Entry-check precedence (round 7 M-5, §3.1 rule 3)**: the requeue
  claim site asserts that it is not reached from a user-mode entry with
  `directive_state == armed` and `pin_depth == 0` — i.e. that the
  directive arm ran first. Without this an implementer can wire the
  entry checks into syscall entry only, leave the tick requeue-first,
  and silently reintroduce N5.
- **Quiesced resume (round-13 follow-up, §3.3, §0.3)**: a **debug-only**
  shadow bit and three asserts. It has to be a bit rather than a direct
  read of `cd.paused`, and the reason is the one that makes the naive
  version wrong: **`cd.paused` is set at pause ENTRY, before the pauser's
  predicate is satisfied**, so an EC that was already `running` in a
  syscall when the pause landed would trip a bare
  `assert(!current_ec.domain.paused)` — and that EC is SAFE, because the
  predicate covers `running` and the pauser has not proceeded. The rule's
  window is narrower than the word: it is the resume path only.
  - **(1)** edge 6's placement sets `ec._dbg_resumed_pre_gate` when it
    places into a domain reading `paused` — i.e. exactly the
    wake-into-a-paused-domain case §3.3's rule is about — in the
    destination queue lock section it already holds.
  - **(2)** every user-memory accessor asserts that bit is CLEAR. The
    accessor set is closed and identifiable precisely because the
    SMAP/PAN bracket is what defines it, which is the same handle
    §9.3(2)'s existing in-hold check already uses.
  - **(3)** §3.1 rule 3's return leg clears the bit when it gates, and
    the `iretq`/`ERET` trampoline asserts it is clear — which is the
    assert with teeth, because it says the gate DOMINATES the accessor
    rather than merely that the two do not co-occur.
    **CORRECTION (revision 16, round-14 N-2): this assert CANNOT fire
    against HEAD, and revision 16 claimed it could.** Assert (1) only sets
    the bit when edge 6 places into a domain reading `paused`; §3.3 states
    that no domain is ever paused at HEAD (the pause is deferred to
    `stygia-qap`), so the bit is never set and (3) is vacuous today —
    correctly, since the hazard it guards does not exist yet. **The
    HEAD-firing property belongs to §9.3(2)'s analyzer clause**, which is
    a static path check over the resume path and does not depend on a
    domain being paused. Two different instruments; revision 16 credited
    one with the other's proof-of-fire.

  Debug-only, so it adds no production word and needs no §3.4 row; §9.2
  is the debug-assertion section and this is what that licence is for.
- **Boundary LEG (round-13 follow-up, §3.1 rule 3) — NOT a runtime
  assertion, corrected in revision 16 (round-14 N-3).** "Assert the arm is
  reachable from both legs" is a statement about the CALLGRAPH, and no
  runtime assert can observe a leg that was never wired. Revision 16 wrote
  it as a §9.2 assert, which is unwritable. It is two instruments instead:
  - **§9.3 static clause**: the domain-paused arm must be reachable from
    BOTH the user-entry path set and the user-return path set. That is the
    same reachability query §9.3(2)'s resume-path clause already needs.
  - **Debug COVERAGE PAIR** (runtime, and this part is writable): two
    counters, one bumped by each leg's gate. A build that exercises a
    pause with either counter at zero has a leg that is not wired.

  Why it matters that this is enforced somewhere: an implementer who wires
  the arm into syscall entry only produces a machine in which a
  futex-woken EC returns to user code inside a paused domain **with the
  whole battery still green** — the model has no domains (G12), so nothing
  here is machine-checked.
- **`mark_state` (round 7 M-3, §2.4)**: retire asserts it writes the
  word exactly once, under the CAS's exclusivity; the discharger asserts
  it observed the bit SET before clearing it; finalize asserts the bit is
  CLEAR when it completes (this replaces rev 7's unattributed
  "deferred-marking-owed flag consumed").
- Into `ready` ⇒ linked in the same section. Hop order
  release-before-commit; outgoing state ∈ {parking, pended, retired}
  (outgoing `claimed` asserts unreachable); pended discharge asserts
  `payload_done`.
- Finalize: 64-way `current` scan + SP-range check; `mark_state` owed bit
  CLEAR; **`directive_state → dead` (F6's marker), NOT merely "cleared"**
  (round-11 minor: this line said "directive cleared" while edge 10 says
  `→ dead`, and an implementer writing from §9.2 codes revision 4's F6
  bug — a dead target indistinguishable from a delivered suspension).
- **The suspender's break disambiguator is assert-checkable because both
  halves are NAMED SNAPSHOTS** (round-11, the reviewer's suggestion):
  the suspender records `armed_port_ref` and `armed_target_ref` when its
  `claiming → armed` CAS wins, and §9.2 asserts at the break that
  `armed_port_ref.gen == port_ref_at_break.gen` and
  `armed_target_ref.gen == target_ref_at_break.gen` — rather than the
  rule resting on prose. Both halves are also modelled (`pok` and `gen`
  in `ECLifecycle.tla`), which retracts revision 11's ledger claim that
  the port half was un-model-checkable.
- Pop-side: `stale(ec)` (`state == retired`) is the only skip predicate —
  except edge 2's S7 filter, which retires inline (asserted as the only
  other pop-side action).
- Descriptor/`owner_core` poisoning outside validity; entry-check
  retired/directive arms assert a user frame.

### 9.3 Static analysis (the existing grain)

1. **Writer-set pinning**: stores to `ec.state`/`PerCore.current` =
   {lifecycle fns} ∪ {listed asm}; symbol-anchored (SAS-style).
2. **Sequence certification**: publish→hop and claim→discharge contain
   no unbounded loops and no remote waits (the release-wait no longer
   exists to whitelist); saved-frame accesses post-publish are
   violations; post-publish descriptor accesses only inside
   reachability-gating sections; user-memory accesses (SMAP brackets)
   inside any container/gen-lock hold are violations (§3.3).
   **Quiesced resume (round-13 follow-up, §3.3's second rule):** on the
   resume path — every callgraph path from a dispatch or edge-6 placement
   entry to a user-mode return — a user-memory access (SMAP/PAN bracket)
   that is not dominated by the §3.1 rule-3 domain-paused gate is a
   violation. **Deliberately conservative**: it cannot tell a
   wake-into-a-paused-domain resume from an ordinary requeue resume, so
   it flags both, and the fix (gate-before-access, or re-deferral) is
   correct for both anyway. This is the same shape as the
   in-hold check one clause up and reuses the same bracket detection;
   what differs is the region, which is a path property rather than a
   lexical one, so it needs the dominance query the closure work in
   9.3(6) needs anyway. **Proof of fire is available today and should be
   the fixture**: run it against HEAD and it must flag
   `arch/x64/interrupts.zig:3003` and `arch/aarch64/cpu.zig:555`
   (§11.13). An implementation of this clause that reports zero against
   HEAD is broken, not clean.
3. **Paired-arch transitions**: every lifecycle site carries an
   arch-neutral ID reachable from both arch entry sets; fused sites are
   x64-only until an aarch64 FP exists.
4. **Container-lock coupling**: R-claim and link/unlink callers hold the
   matching class; lockdep dynamic backstop; the EcGen → CoreLock edge
   registered (§3.5).
5. **Bare-pointer invariant**: unchanged.
6. **Closure-table maintenance** (round 3; STATUS round 6 M2: entirely
   FUTURE work — none of (a)/(b) exists in the tree today): (a) every
   callgraph path from an IRQ/exception entry to `claim`/`wake` must
   match a §5.1 row; (b) every spin (bounded-loop-on-remote-word
   pattern) must match a §3.6 row, and no spin entry is reachable with
   `pin_depth > 0`; (c) the §5.2 matrix's unreachable cells are asserted
   in debug builds. The requirement is that CI fail on an unmatched
   path/spin so the tables are maintained by tooling, not recall —
   round 4 validated the PRINCIPLE empirically (T1, closed by manual
   callgraph-DB re-derivation, survived hostile review; the
   recall-closed tables held all three criticals), but the CI checks
   themselves are unimplemented.
7. **Pin-class computation** (round 4 F3; STATUS round 6 M2: partially
   real — `check_ec_closure` Rule B computes the dichotomy's input but
   is report-only and not in precommit, with the §2.5 blind spots;
   `check_gen_lock` check 6 gates only the mask-everywhere arm): the
   analyzer derives the pin-class lock set — every class with a
   EC-context acquire site **in which a tick can land** (the
   EFFECTIVE-MASK reading, normative per §2.4 — NOT the syntactic "is the
   call `lockIrqSave`?" test, which is what revision 14 applied and got
   wrong) — from the same scan as the
   IRQ-class pass, and requires each such site to be paired with a
   `pin_depth` bump (or converted to an IRQ-saving acquire).
   **Revision 11 adds the third-clause check (round-10 C-A): a class
   with ANY interrupt-context acquire site may not be pin-counted —
   it must mask at every EC-context site.** Deriving that requires an
   IF-state model in `asm_analyzer.zig` (both known hazard sites are raw
   asm and invisible to a Zig-level scan) and `trap_sync` promoted or
   fault entry masked, so exception-context acquires are distinguishable
   from EC-context ones. Neither exists today; this is FUTURE work of
   the same class as 9.3(6), and §2.4's third clause is meanwhile
   enforced by review. Any class
   list written in this document is
   illustrative; the computed set is normative.

### 9.4 The IPC fast path — decided (held in round 3)

**§9.4 IS A MASKED WINDOW, and revision 11 names it as one (round-10
C-A).** Both fused shapes take locks that are IRQ-reachable — the
suspend FP spins on `port.timed_recv_lock` (`interrupts.zig:1379-1385`),
which `expireTimedRecvWaiters` takes from the tick, and the reply FP
takes `core_locks[i]`, which `enqueueOnCore` takes from IRQ. Under
§3.3's EC-context-IRQ-enabled rule these are self-deadlockable unless
the fast path masks across them. The reply path already does
(`:2247`); **the suspend path does not, and must**.

Cost, stated: an added `cli`/`sti` pair on the suspend fast path — the
one path whose entire justification is cycle count — plus the same
window on aarch64. That is a real regression against the measured 485
placements/boot, and it is the honest price of §3.3. The alternative is
to make both classes mask at every EC-context site (§2.4's third clause
applied to them), which costs the same masking without the asm carrying
it explicitly. Either way the cost is paid; **§11.11** is where it gets decided.

Fused compositions of standard edges; the only asm entries in 9.3(1).
Inventory: suspend FP (sender fused park-publish + receiver 5a claim +
payload + edge-2 commit — **a `parking`/5b-shaped receiver ⇒ bail to the
slow path**, which pends it; the FP never implements the pended arm);
reply FP main (sender wake + edge-2 commit + caller requeue); reply FP
atomic-recv arm (caller park or `replyAtomicRecvSendersFallback`); bail
paths (no state written). Decisions, all verified against the real asm in
round 3: (1) the FP takes `core_locks[core]` for its commit section
(R13's bare-reply branch already does, `interrupts.zig:2270-2318`);
(2) the fused sender publish is a CAS with a `retired` arm executed
inside the sender's `_gen_lock` hold (today's Step 9.7–12,
`interrupts.zig:1097-1106`, `:1282-1298` — the existence proof);
(3) post-publish kstack-clean audit (release-build tail verified clean;
trace builds must hoist hooks or disable the FP — the `:1441`/`:2585`
violations are real); mid-asm rsp retarget remains the fallback.

**Measured accounting** (round 6, reverted Phase-3 instrumentation; bead
`stygia-qde`): x86 showed exactly 485 EC placements per boot performed by
no Zig site, zero on aarch64 (which has no FP), arithmetic closing
exactly — that is this section's inventory executing in asm, and the
count closing is the expected signature of fused edges preserving every
component's from-state check. The model encodes both fused shapes as
ideal atomic compositions (`FastPath` = the suspend FP; `ReplyFP` = the
reply FP main: sender wake + edge-2 commit + caller requeue), so the
MACHINE accounts for fused placement; whether the asm CONFORMS to the
ideal composition is exactly this section's decision list plus
`stygia-qde`, and lies outside the model's boundary by design.

---

## 10. Essential complexity — kept deliberately

- **The wake-claim CAS** — the only arbitration mechanism, everywhere.
- **Translation quiescence** (`active_root` + barrier + lock-sweep).
- **Slab gen parity + bytes-intact-until-finalize** + R-claim closure.
- **EC-resident wait storage** (nodes, staging, deadline node).
- **The park-kstack hop**, its degenerate form, release-before-commit.
- **The locked park decision** and the parked-core heartbeat.
- **The spin inventory is §3.6 (T3), normatively closed**: W1 locks, W2
  `payload_done` (hop), W3 eviction, W4 deferred marking, W5 directive,
  W6 domain quiesce, W7 retire-from-pended pre-wait, W8 FPU
  migrate-flush ack, W9 TLB shootdown ack — each with ack-while-spinning
  and an acyclicity row; W8/W9 are rule (b)'s two lock-holding
  exceptions (F4). The release-wait rev 3 carried here is deleted;
  adding any new spin requires a new T3 row (analyzer 9.3(6b)).

---

## 11. Decisions needing the maintainer's call

1. **FP core-lock cost** — decided (take it); revisit only with
   profiling evidence.
2. **FP publish placement** — decided (in-lock CAS + kstack-clean audit
   + trace-hook rule); rsp retarget is the fallback.
3. **Terminate strength** — eviction + deferred-marking completion at
   return (L5, W4); a stricter finalize-wait reading of §[terminate] is
   a spec call.
4. **Remote-suspend semantics** (§2.5, revised per M-B, F5, F6): the
   requester runs the terminal re-check/disarm loop, so a directive can
   no longer pend indefinitely behind an unrelated wait; disarm-failure
   distinguishes consumed (`none`) from retired (`dead` → E_TERM);
   racing suspenders get E_BUSY-class; `parking`/`pended` targets are
   L1-bounded transients. **Targets in non-suspendable waits: spec and
   doc DISAGREE (round 6 M5)** — earlier revisions cited "the spec's
   E_INVAL", but the confirmation against specv3 §[suspend] has now been
   done and it FAILS: §[suspend] licenses E_INVAL for exactly three
   causes and none covers a futex/recv/reply-blocked target. Either
   specv3 grows a cause or this machine returns a different code; the
   maintainer picks (kernel bead `stygia-uyd`). This document no longer
   cites that error as existing.
5. **Rendezvous mint-failure relink** — strictly better than today's
   stranded sender; observable; confirm against §[recv]/§[suspend].
6. **`idle_wait` as a wait kind** — unchanged.
7. **Bounded W5 wait (round 6 N6 — RECOMMENDED ALTERNATIVE, not
   implemented; the case for it is now MEASURED, round 7)**: the
   mutual-suspend livelock the model found is closed in revisions 7–8 by
   assumption (§3.6's alignment assumption). The structural alternative:
   bound the W5 re-check loop — after K iterations, CAS `armed → none`
   UNCONDITIONALLY (the disarm CAS is always safe: failure means the
   target consumed) and return an E_BUSY-class "target did not leave
   `running`". This deletes BOTH N6 assumptions before they are born (no
   continuation-progress dependence for termination, no
   observation-alignment dependence), shrinks T3's argument surface
   (W5's "why no cycle" column becomes "bounded loop, unconditional
   exit"), makes §2.5's word "bounded" true rather than aspirational,
   and is the simpler machine under this document's own acceptance
   criterion.

   **New evidence, and it is the strongest argument in this list.** The
   alignment premise is `[]<>P` for a state predicate P — an
   *unconditional* recurrence. `WF_vars(A)` and `SF_vars(A)`, the two
   forms TLC routes past its general tableau, are both *conditional* on
   `ENABLED A`, so neither can express it (proof in
   `docs/kernel/tla/README.md`, fairness section: any ghost G with
   `ENABLED G = P` gives `SF(G) = ([]<>P ⇒ []<>G)`, which is vacuously
   satisfied in exactly the starved lassos the premise exists to
   exclude). The premise therefore rides the general tableau, and the
   measured consequence is that **`LiveSuspender` is verifiable only at
   the small end of the scope ladder**: PASS at the minimal,
   +pin-lock, +retire, and +suspend rungs, and no convergence at full
   2×2 scope under multi-hour caps — while every property NOT carrying
   the premise clears the same and larger graphs in minutes. That is
   the whole ladder in the README's coverage table.

   So the honest comparison is not "assumption versus mechanism" but
   **"an assumption nobody can check at the scope the rest of the
   battery runs at, versus a mechanism that needs no assumption at
   all."** A design whose correctness argument is the one thing the
   verification apparatus cannot reach is worse than a slightly less
   general design whose argument is a loop bound. Cost: it changes
   §[suspend]'s return semantics — the current "left `running`"
   guarantee becomes "left `running`, or E_BUSY after a bounded wait" —
   which is API-visible spec territory, and it is NOT taken here for
   that reason. It sits adjacent to `stygia-uyd` (the suspend
   state-gate error code, §11.4), and both should be ruled on together:
   if §[suspend] is being touched for the error-code disagreement
   anyway, the bounded wait is the moment to take this too
   (`stygia-8mx`).

8. **PROPOSED SPEC CHANGE — suspend-cycle rejection (round 7, §2.5.1;
   pre-approved by the maintainer CONDITIONAL on the model confirming
   it, which it does).** `specv3.md` is read-only to this document; the
   text below is a proposal for the maintainer to take, not an edit.
   §[suspend] currently has no E_BUSY cause, but E_BUSY already exists
   in the spec's error table (code 4, "target object is in a state that
   disallows the operation"), so this needs no new code — only a new
   cause and a test.

   > **Proposed addition to §[suspend] → Description** (this belongs in
   > the Description, not only in Errors, because it changes how the
   > syscall must be CALLED):
   >
   > When `[1]` is **not** the calling execution context and names a
   > *running* execution context, the call reserves the calling
   > execution context for its duration: while it is in flight the
   > caller cannot itself be suspended, and it cannot suspend a target
   > that is itself performing such a `suspend`. **Concurrent `suspend`
   > calls therefore contend, and E_BUSY is an expected outcome whenever
   > two suspensions overlap in time — not a rare or pathological one,
   > and not limited to the case where the two calls name each other.
   > BOTH of two racing calls may return E_BUSY.** A caller that issues
   > `suspend` from more than one execution context must retry, **and
   > must not retry in a tight loop**: two callers retrying in lockstep
   > can fail each other indefinitely, so a retry must introduce delay
   > or ordering (backoff, or a caller-side lock) rather than spin.
   >
   > Self-suspend is unaffected: `[1]` referencing the calling execution
   > context is delivered directly and reserves nothing (see above —
   > "the syscall returns after the calling EC is resumed").
   >
   > **Proposed addition to §[suspend] → Errors:**
   >
   > **E_BUSY** — `[1]` is itself performing an in-flight `suspend` of
   > another execution context, or the calling execution context is
   > itself the target of an in-flight `suspend`. See Description: this
   > is an expected outcome of concurrent `suspend` calls. The
   > restriction is what makes a cycle of mutually-suspending execution
   > contexts — in which no participant reaches the user-mode boundary
   > at which a suspension is delivered — unrepresentable.
   >
   > *(Editorial note for the maintainer, not proposed spec text: the
   > second clause makes E_BUSY describe the CALLER's state, whereas
   > §[syscall word]'s error table defines E_BUSY as "target object is
   > in a state that disallows the operation". That is a genuine
   > widening of the code's meaning. It is the right code — no other
   > existing code fits a transient, retryable contention failure — but
   > the table's gloss should be widened with it rather than left to
   > contradict this cause.)*
   >
   > **Proposed addition to §[suspend] → Tests:**
   >
   > [test 13] when two execution contexts each hold a `susp` handle to
   > the other and each issues `suspend` targeting the other, the two
   > calls never both return success. Any other outcome is a pass:
   > one succeeds and one returns E_BUSY; **both return E_BUSY**; or the
   > calls do not overlap and one succeeds only after the other has
   > completed. The assertion is on the forbidden outcome only —
   > **it must NOT assert that exactly one succeeds.**
   >
   > [test 14] E_BUSY is a legal return from `suspend` on a valid,
   > permitted, runnable target: a caller that receives it and retries
   > is not observing an error in its own arguments. (Asserted by
   > construction — a test that receives E_BUSY from an otherwise-valid
   > call passes rather than fails.)

   **Second, smaller spec addition in the same section (round-13 C-1):
   `acquire_vmars`, `idc_read` and `idc_write` need an E_BUSY cause.
   NOT URGENT — this rides with bead `stygia-qap`, not with §12**
   (revision 16): the pause is deferred out of the refactor, and at HEAD
   the three syscalls cannot emit this error because they do not pause at
   all. Proposed now so the bead does not have to re-derive it.
   §0.3's domain-pause gate refuses a pause in two cases — the target
   domain contains the calling EC, or the caller's own domain is already
   paused — and those refusals are what make mutual pause
   unrepresentable. `specv3.md` licenses no E_BUSY for any of the three
   syscalls today. Proposed:

   > **E_BUSY** — the target domain contains the calling execution
   > context, or the calling execution context's own domain is itself
   > paused. A caller that retries must back off rather than spin.

   The two clauses are not cosmetic: the first stops a pauser gating
   itself and never reaching its own resume; the second is what makes a
   cycle of mutually-pausing domains unrepresentable, the same shape
   §2.5.1 closes for `suspend`. **Rule on this together with the
   `suspend` addition above and §11.4** — three sections, one opening.

   **Note for whoever writes the test file** (the maintainer has
   approved landing this after the model clears, so a real test will
   exist). [test 13]'s shape is deliberate: it **attempts** to trigger
   the race, and its *failure to race* is a pass. A test demanding that
   the race occur would be timing-dependent and would fail on a machine
   that simply never interleaved the two calls; a test demanding that
   the bad outcome never occur is checkable on every machine, including
   a uniprocessor one. Loop the attempt to give the race chances, but
   never assert that it happened.

   **What is NOT deterministically testable from userspace, and why
   that is acceptable.** The mechanism rejects three cases (§2.5.1):
   the symmetric one, a target that is itself mid-suspend of a third
   EC, and a caller that is itself someone's target. Only the first has
   a clean userspace setup. The other two require holding an EC *inside*
   a `suspend` call at a chosen instant, and the machine deliberately
   makes that window short — a running target consumes its directive
   within one unpinned tick (§3.1 rule 3). So the division of labour is:
   **[test 13] covers the case userspace can construct; the model covers
   the other two** (`InvNoSuspendCycle2`/`InvNoSuspendCycle3`, which
   quantify over all three and hold across every reachable state at
   2×2 and 2c×3e). Do not contort the test suite to reach what the
   model already proves — but do NOT let that argument grow: it is
   valid only while those invariants are actually in the battery.

   The text above is written for mechanism **(B)**, which §2.5.1
   recommends: it refuses the superset (any overlapping suspend) rather
   than detecting cycles, which is why the "expected outcome" sentence
   is in the normative text and not in a note. If the maintainer prefers
   mechanism (A) instead, the second sentence should be deleted and the
   cause narrowed to the two cycle-closing conditions — but (A) does not
   close 3-cycles, so it would also need a further clause or a further
   mechanism. **Rule on this together with §11.4 (`stygia-uyd`, the
   suspend state-gate error code) — both touch §[suspend] and it should
   be opened once.**

9. **Domain restart is absent from this machine entirely (round-9 C-5).
   DECIDED IN REVISION 16 — see the resolution at the end of this item;
   the analysis below is kept because it is what the follow-on will use.**
   `grep -ni restart systems.md` returned **zero** before revision 10.
   `specv3.md` §[restart_semantics] is normative and per-EC — when a
   domain holding `restart` on its self-handle exits (voluntary, fault
   or kill), each EC handle is processed by its `restart_policy`:
   **0 = kill / 1 = restart_at_entry / 2 = persist**.

   - `kill` is edge 9 and is covered.
   - **`restart_at_entry` has NO edge.** An EC in *any* state must be
     forced runnable with its saved frame reset to its original entry
     point. That is not edge 6 (placement of a claimed EC preserves its
     frame), not edge 7, and not a claim-move. The closest existing
     thing is edge 1, which establishes an entry frame — but only on a
     fresh slab slot. Sketch of what it needs: claim the EC by its
     state's normal route (5a from `waiting` with the episode's
     containers unwound, 5c from `ready`, the directive shape from
     `running`), reset the frame under that claim, then place via
     edge 6. The claim/reset/place skeleton exists; the **frame reset
     under a won claim** is the genuinely new step, and it needs a T2
     row of its own because a restart racing a retire must lose.
   - **`persist` is the harder half**: it keeps an EC *running* while
     its domain's VMARs are freed and its handle table rewritten.
     Neither §8.2 nor §8.5 addresses an address-space change under a
     live EC, and it interacts directly with `active_root` and
     translation quiescence (§10, W6) — a running EC on a root that is
     being rewritten is exactly what `awaitDomainQuiesced` exists to
     prevent, so `persist` either needs the barrier or needs to state
     why it is exempt.

   ~~**Recommendation: do NOT scope it out.**~~ **RESOLVED IN REVISION 16
   — the maintainer scoped `restart_at_entry` OUT, and the recommendation
   above is superseded.** The argument for keeping it in was that the
   machine "claims to be sufficient for the syscall API's EC state
   changes", and that claim is about state changes the API can actually
   cause. It cannot cause this one: the kernel implements only the policy
   PLUMBING (`caps/capability.zig:346`/`:581`/`:591`/`:604` —
   `restartPolicyMonotone`, `restartPolicyMask`, create/copy ceiling
   bounding), all eight `tests/suite/cases/restart_semantics_*.zig` cases
   test `E_PERM` bounding rather than restart behaviour, and there is no
   domain-restart implementation anywhere. So committing the machine to an
   edge here would have been routing one value of one policy in a feature
   whose semantics will move when it is designed. **The machine routes it
   when restart semantics are built; the sketch above is what that
   follow-on starts from.** (`persist` is unaffected — it remains OUT by
   §0.2 reason B with its W6 obligation retained, per §0.3.) **The
   meta-finding is the
   more valuable half and is fixed now** (§13, and the model README's
   sufficiency table): that table was derived by walking the spec's
   SYSCALL list, and §[restart_semantics] is not a syscall section — so
   the derivation had a structural blind spot, and a missing row was
   only its symptom.

   > **~~"that walk surfaces restart and nothing else new"~~ — RETRACTED
   > IN REVISION 11, and it was the most damaging sentence in revision
   > 10.** It was false, and worse, it was the kind of false that stops
   > the next person looking. An independent section walk found SIX more
   > gaps, one of them larger than restart itself:
   >
   > - **A domain-pause primitive** (`acquire_vmars` / `idc_read` /
   >   `idc_write`): a domain-wide, N-EC pause carrying a resume
   >   obligation. Architecturally LARGER than restart and **not
   >   additive** — it is not restart's mechanism applied N times.
   > - **`restrict`'s port-refcount cascade**, which wakes suspended
   >   senders with E_CLOSED — a wake this machine's T1/5a routing does
   >   not enumerate.
   > - **`revoke`** — zero mentions in this document.
   > - **The no-route fallback**: `thread_fault` terminates the EC. That
   >   is a kernel-initiated terminate **from exception context**, i.e. a
   >   DIFFERENT ACTOR than T2's terminator, and T2 names actors.
   > - **`delete` of an EC handle** is mapped to edge 9 here, while the
   >   spec says ECs are not destroyed by handle drops.
   > - ~~**`power_sleep`** is filed under §3.6's terminal carve-out, but
   >   the spec says it RETURNS on wake.~~ **CLOSED in revision 16** —
   >   §3.6 no longer files it as terminal; it is OUT by §0.2 reason B,
   >   which is what §0.2 had claimed §3.6 already said.
   >
   > The correct standing statement: **the section walk is a better
   > derivation than the syscall walk and is still not closed.** Treat
   > this table as incomplete until it is derived by tooling, per the
   > same rule §5.1 applies to T1.

10. **~~Lock-order group design~~ — RETRACTED IN REVISION 13 (§0.2,
    §3.5).** Revisions 10–12 escalated a refuted chain into a blocker
    gating §8.1, §8.2, §8.5 and six migration steps. Cross-class lock
    ordering is out of scope: the kernel uses address-ordered same-class
    nesting under a named group plus lockdep's dynamic cycle detection,
    and §8.1's repair uses drop-and-retry so it never holds two classes
    at once. Nothing is blocked. The one real item that came out of this
    is a **one-line tree defect**: `EC_NESTED_GROUP` is named in a
    comment and defined nowhere (bead `stygia-d0q`).

11. **The C-A masking cost, and the analyzer inversion's real price
    (round-11 M-1/M-2/M-7).** **DEFERRED in revision 13**: analyzer
    capability is out of scope (§0.2) and the masking decision is a
    fast-path performance call, not a lifecycle question. Recorded here
    so it is not lost, and NOT to be worked in a lifecycle revision.
    Three decisions, all currently unowned:

    **(a) Who pays §9.4's mask.** The suspend fast path spins on
    `port.timed_recv_lock` unmasked; the reply path already `cli`s.
    Either the suspend path gains a `cli`/`sti` pair — on the one path
    whose entire justification is cycle count — or both classes mask at
    every EC-context site. The cost is paid either way.

    **(b) The (c)/(c2) inversion does NOT catch the hazard, and revision
    11 implied it would (M-1).** Both hazard sites are ALREADY
    `lockIrqSave` at the Zig level; the entire hazard is in raw asm, and
    `asm_analyzer.zig` recognises exactly one shape (single
    `asm volatile` body, x86-64, `lock cmpxchgq`/`andq` at a
    `@offsetOf(T,"_gen_lock")`). The real cost is four items, and the
    load-bearing one revision 11 never named is **resolving a
    `%gs`-relative operand through the per-CPU scratch slot to a named
    lock class** — an IF-state model tells you a loop runs unmasked,
    never *on which class*. Also corrected: "masking at fault entry" is
    already true on both arches (x64 installs every IDT entry as
    `interrupt_gate`; `trap_gate` is used nowhere), so that is not the
    obstacle — the obstacle is that `check_gen_lock` classifies by entry
    symbol and aarch64's `handleSyncLowerEl` multiplexes SVC and aborts.

    **(c) The inversion flips the documented blind spots from FAIL-SAFE
    to FAIL-OPEN (M-2), and that is the part to rule on first.** Under
    the old rule an unresolved IRQ entry produced a false POSITIVE
    (demand the mask anyway); under the inverted rule a class is
    permitted unmasked-and-pin-counted unless *proven* IRQ-reachable, so
    `tlbShootdownHandler`'s unresolved seed becomes a false NEGATIVE.
    Revision 11's "check 6 keeps its teeth everywhere else" is the wrong
    reading, and §3.6 W1's rewritten certificate inherits the direction.
    **Recommendation: keep the inversion but make unresolved reachability
    fail CLOSED** — an entry the tool cannot resolve counts as
    IRQ-reachable, so the class must mask. That preserves the old rule's
    safe direction while gaining the new rule's coverage.

12. **`yieldTo` against a target queued on another core (round 7 M-4)**: §8.1 codifies the target-side rule as local-only + S7 +
   affinity-mask. **Two of those three are what the tree does; the MASK
   IS NOT** — corrected in revision 16 (round-14 sufficiency N-1). The
   target-pick guard at `sched/scheduler.zig:900` is
   `t.state == .ready and domainRefAlive(t) and state.run_queue.remove(t)`:
   local-only (this core's queue) and S7 (`domainRefAlive`) are both
   there, and there is no affinity check on `t` at all — the four
   `affinity` mentions nearby (`:852-863`) are the CALLER's own
   `cur.affinity` local-allowed test, a different rule about a different
   EC. §13's own M-4 entry has said "the mask check is new; the tree
   lacks it" since revision 8, so this sentence contradicted the
   changelog. It also had **no §12 step**, which is now fixed at step 4.
   The model encodes and which keeps edge 2 inside a single `core_locks[core]`
   section. §[yield]'s Description says "that EC is scheduled next",
   and a `ready` EC on another core's queue is runnable, so local-only
   under-delivers that sentence; §[yield] [test 03] (the target's
   observable side effect is visible before the caller's next syscall
   returns) IS satisfied, because the target's own core dispatches it.
   The maintainer picks: accept the narrowing and note it against
   §[yield], or take the cross-core arm and with it a
   CoreLock → CoreLock order edge that nothing else in the machine
   needs. This document does not resolve it silently in either
   direction.

13. **The dispatch trampoline writes user memory on the resume path, and
    the quiesced-resume rule (§3.3) makes that a decision rather than an
    accident (round-13 follow-up).** DERIVED — callgraph DB plus the two
    sites read directly, both arches; not recalled.
    **SCHEDULING: this rides with bead `stygia-qap`, NOT with §12.** The
    rule is conditioned on `cd.paused`; the pause is deferred out of the
    refactor (§0.3), and at HEAD no domain is ever paused, so these two
    sites are harmless today and none of §12 steps 1–10 is blocked on
    them. Recorded now because `qap` cannot be implemented correctly
    without this decision already made.

    **What the tree does.** The final step of dispatch flushes staged
    event state into the resumed EC's USER memory, after the address-space
    swap and before the return to user mode, with SMAP/PAN cleared for the
    access:

    - `arch/x64/interrupts.zig:3003` (`switchTo`) —
      `writeUserSyscallWord(ec.ctx, ec.pending_event_word)` into
      `[user_rsp + 0]`, then `writeUserVreg14` into `[user_rsp + 8]`.
    - `arch/aarch64/cpu.zig:555` (`loadEcContextAndReturn`) — the same
      `writeUserSyscallWord` into `[sp_el0 + 0]`; aarch64's vreg 14 is
      GPR-backed at x13 so only the first write leaves the kernel stack.

    Both are correct as written and their comments explain why the
    deferral exists: the value is staged while the target is PARKED, at
    which point the kernel is still in the *other* party's CR3/TTBR0, so
    the write has to wait for the swap. The deferral is the fix for one
    problem; it is what creates this one.

    **There are TWO staging sites, and both stage onto an EC parked in a
    port wait** — which is exactly the state W5-N's predicate excludes,
    so this is not an edge of the exposure but its centre:
    - `sched/port.zig:2023` — onto the **receiver** of a rendezvous
      delivery. Its own comment: *"only safe at iretq time — both the
      sender-already-waiting path and the rendezvous path can run with a
      different CR3 active here"*.
    - `sched/port.zig:1018` — onto the **sender** being resumed by a
      `reply`, i.e. an EC exiting `suspend`.

    (`caps/capability_domain.zig:833`/`:1016` stage onto `caller`, which
    is `running`, so those are outside the window. Enumerating the
    staging sites is a `grep -rn pending_event_word_valid` away and
    should be re-derived, not recalled, whenever this item is revisited.)

    **Why it collides with the pause.** A `recv` waiter sits in
    `waiting(port_queue)`, which W5-N's predicate deliberately does not
    cover — that exclusion is what lets the pauser finish. So: pauser
    proceeds; a sender in an UNPAUSED domain rendezvous-delivers; the
    receiver goes `claimed` → `ready` → dispatched on some core; the
    trampoline writes two words into its user stack while
    `idc_write`/`acquire_vmars` is rewriting exactly that address space.
    The write is downstream of every gate — it is the last thing before
    `iretq`/`ERET` — so no placement of the §3.1 rule-3 check inside Zig
    can dominate it. Cross-domain IDC is the ordinary case here, not an
    exotic one.

    **The call.** §3.3 names two ways to satisfy the rule and this
    document does not pick, because the choice is an arch-path decision
    with costs the design cannot weigh from here:
    - **(i) Gate ahead of the flush** — evaluate the domain-paused arm
      in the dispatch path before the trampoline, and park rather than
      resume. Costs a `cd.paused` load on every dispatch and puts a park
      decision inside the arch return path, which §3.2's park sequence
      currently keeps out of arch code.
    - **(ii) Re-defer the flush** — leave `pending_event_word_valid` set
      for a gated EC, so the staged word survives the pause and is
      flushed by the resume that follows it. Costs nothing on the common
      path and reuses machinery that already exists (the flag is already
      a deferral), but it makes the staged word outlive a pause, so
      §8.2's teardown walk must clear it and the resume walk must not
      double-flush.

    (ii) looks smaller from the design side and (i) is the one that
    generalises to any future user-memory access on the resume path. The
    maintainer picks. **Whichever is picked, §9.3(2)'s new clause must
    flag both sites when run against pre-fix HEAD** — an implementation
    of that clause that reports zero here has not been shown to work.

---

## 12. Migration

Each step lands green and deletes a mechanism. **Read the precondition
below and the closure note at the end of this section before starting
step 1** — the first is a gate the implementer may not open, and the
second names what is deliberately NOT here.

**PRECONDITION OF STEPS 1 AND 9 — not the implementer's call.** Both
steps promote an analyzer into gating CI. `tests/precommit.sh:563-564`
says in as many words that gating the `[0d]` EC-closure stage is **a
pending maintainer decision** and must not be promoted without one. So a
triage pass over that stage's current findings plus **maintainer sign-off
on promotion** is a precondition of step 1, and again of step 9 for
9.3(2)–(6). Neither step starts without it.

1. **Chokepoint extraction** (+ transition asserts, analyzer 9.3(1)).
   **DIAGNOSTICS — scoped BY THE TEST, not by bead tag.** Revision 15
   said "drop diagnostics" unqualified, which is tree-wide; revision 16
   replaced that with a hand-written bead enumeration, and the
   enumeration was both incomplete and self-contradictory (round-14
   sufficiency B-3). What goes at step 1 is exactly **§0.1's own test**:
   an instrument that reports EC-lifecycle or scheduler state. That is
   `leak_tag` (`sched/execution_context.zig:341`, writers `:779`/`:919`/
   `:2100`) and the EC-state diagnostic writers. Everything whose subject
   is memory, handle tables or timers stays, because §0.1's test excludes
   it — but **do not take that list from this paragraph**; derive it:
   `grep -rn 'stygia-2u0\|stygia-afo\|stygia-9zr' kernel --include='*.zig'`.
   Revision 16 wrote "**`stygia-2u0`** — two sites" when the tag has
   **24 sites across 7 files**, and in the same breath said to drop
   `leak_tag` while keeping the `stygia-2u0` instruments — and `leak_tag`
   IS `stygia-2u0`. A bead tag is not a scope boundary; the test is.

   **PORT OBLIGATION (replaces revision 16's "the counters survive
   through step 6", which is not executable — round-14 sufficiency
   B-3).** The orphan census at `syscall/dispatch.zig` reads fields that
   four different steps delete or rename, so "leave it alone until step
   6" instructs an implementer to leave a file that will not compile:

   | census reads | at | step that moves it |
   |---|---|---|
   | `ec.on_cpu` | `:239`, `:251` | **step 5** (reap side; see 4a) |
   | `ec.suspend_port` | `:240` | step 3 (folds into `ec.wait.port`) |
   | `ec.pending_reply_holder` | `:256` | step 3 (`ec.wait.reply_holder`) |
   | `ec.leak_tag` | `:253` | step 1 (above) |

   **So: every step that deletes or renames a field the census reads
   updates the census IN THE SAME STEP.** The counters themselves retire
   at step 6, once the structural fix 4b is ordered around has landed.

   **And the silent one, which is worse than any of the four.**
   `by_state: [6]u32` (`:212`) and `orphan_by_state: [6]u32` (`:234`) are
   sized to the tree's CURRENT `State` enum — six members (`running`,
   `ready`, `suspended_on_port`, `futex_wait`, `idle_wait`, `exited`).
   **This machine's word has SEVEN states** (§2.1). Their guards are
   `if (st < ctx.by_state.len)`, so from the step that widens the enum the
   census does not fail to compile — **it silently stops counting the new
   state**. That defeats the rider's whole purpose, since its point is
   that the census must be TRUSTWORTHY at 4b. **Widen both histograms
   with the enum, in the step that widens it.**

   **Tag correction:** the census is tagged **`stygia-2u0`**
   (`syscall/dispatch.zig:199`), not `stygia-afo`; only its CD-orphan
   additions (`orphan_by_state` and the surrounding block) carry
   `stygia-afo`. Revision 16 attributed the whole census to `afo`.
   The genuinely `afo` instruments — which are the ones 4b's ordering
   depends on — are `p2_enter`/`p2_after_reap`/`p2_walk_done`/`p2_residue`
   (`caps/capability_domain.zig:1314-1339`), `in_phase2` +
   `noteFrameAbandoned` (`:1343-1366`), and
   `slow_post_*`/`inline_finalize_*` (`sched/execution_context.zig:105-143`).
   Those, plus a census kept honest by the port obligation above, are
   what make 4b's constraint checkable; they retire at step 6.
2. **Retire fusion** (+ the §5.2 matrix as the routing table; the
   stable/deferred marking split, carried by the `mark_state` word —
   §2.4, M-3 — with its release/acquire pairing and the finalize
   assert). Deletes divergent reap predicates and the odd-gen-`.exited`
   shape. **Read a green step-2 pass narrowly: the DEFERRED arm is inert
   here.** `mark_state`'s SET rows are `claimed`, `pended` and pin-writing
   `parking`, and none of those exists yet — `claimed`/`pended` arrive at
   step 3 and `pin_depth` at step 4 — so this step ships the word, the
   release/acquire pairing and W4/L5's terminator wait with a writer that
   never fires. The N=100 pass therefore exercises **only the eager arm**;
   it does not validate the split.
3. **Claimed/pended hand-offs.** Introduce **`ec.wait`, the §2.2 wait
   descriptor, by name** — this is the machine's second-largest new
   construct and revisions up to 15 introduced it only by implication,
   via `payload_done` — together with `claimed`, `pended`, R-claim,
   placement CASes, `payload_done`, and the hop's pended arm for every
   wake/move; add the T1 rows (device-region, timer wheel).
   **The descriptor FOLD lands here too, and it is fast-path asm work,
   not a struct rename**: `suspend_port` (34 refs / 5 files, **15 of them
   in `arch/x64/interrupts.zig`**) and `pending_reply_holder`/`_domain`/
   `_slot` (**48** refs / 5 files — 21 is `pending_reply_holder` alone) become `ec.wait.{port, reply_holder}`.
   They are written by hand through `@offsetOf(ExecutionContext, …)` at
   `arch/x64/interrupts.zig:1267-1271`, `:1330-1332`, `:1408`,
   `:2120-2123`, `:2560-2565`, behind a layout-drift `@compileError` at
   `:319`, so nesting them one struct deeper re-derives every one of
   those offsets and the guard.
   **TIMED REGISTRIES — this step unifies the FUTEX registry ONLY**, i.e.
   **`timed_waiters[64]`** (§2.6's deleted-signal table names it; revision
   16's text said "the futex timed registry" and never the field).
   Revision 15 said "both timed registries" and that could not compile on
   x86-64, because `timed_recv_waiters` is not a Zig-only structure: it is
   threaded through `SyscallScratch` and walked by hand-written assembly
   (`arch/x64/interrupts.zig:201`, `:260`, the `@compileError` drift guard
   at `:289`, `:336`, and the inline `removeTimedRecvWaiter` at
   `:1378-1402` — an `xchgl` spin on `timed_recv_lock` plus a linear scan
   comptime-bounded by `MAX_TIMED_RECV_WAITERS`). §8.4's single intrusive
   per-EC node deletes both the array the asm indexes and the bound it
   formats. **`timed_recv_waiters` therefore moves to step 8**, with the
   rest of the fast-path asm — which also keeps step 8's own back-
   constraint true: the `xchgl` spin step 8 says must be masked no later
   than 4c is `interrupts.zig:1379-1385`, i.e. the spin that survives
   because step 3 no longer deletes it. Revision 15 asserted both, and
   both could not hold.
   Deletes: ALL wake-side `on_cpu` spins (with no release-wait replacing
   them), the `markReady` `.running` arm,
   `propagateClosedToSenders`' divergent ordering, the **futex** timed
   registry.
4. **Hop-completes-everything + pin gate.** **INTERNAL ORDER IS
   NORMATIVE (round-10 C-B) — this step is not atomic and its parts
   must land in this sequence:**
   **(4a) the deletions AND the mechanism that answers them.** Revision
   15 said "the deletions first" and listed only deletions, which is not
   landable: `on_cpu`'s replacement IS the hop completing everything
   (§2.6, "quiescence is structural (S3)"), and `takePendingReleaseByte`
   (`sched/scheduler.zig:722-729`) literally returns
   `@ptrCast(&pending.on_cpu)` at `:729` — its consumers are `scheduler.zig:2016`
   and `:2078`, `arch/aarch64/cpu.zig:468`, `arch/x64/interrupts.zig:2899`
   — so deleting the flag before its answer exists removes the answer
   with nothing answering. **4a is therefore: the publish-under-lock park
   sequence, `current` written only at commit/hop, release-before-commit,
   and the degenerate hop, TOGETHER WITH the deletions they enable** —
   **three** of §2.3/§2.6's four named PerCore companions
   (`post_park_clear_on_cpu`, `pending_kstack_release`,
   `pending_cross_enqueue`) plus their stash/consume machinery, the
   scattered `clearCurrentEc` sites, and the disowned-current escapes.

   **`on_cpu` DOES NOT go here, and neither does the fourth companion.
   Scheduling both correctly is what stops 4a from shipping a
   triple-fault (round-14 sufficiency B-2).** `on_cpu` has TWO consumer
   families and they die in different steps:
   - **Wake side — already gone at step 3**: the five spins
     (`sched/futex.zig:299`/`:702`, `sched/scheduler.zig:2129`,
     `sched/port.zig:187`/`:2111`). §2.6's `on_cpu` row covers exactly
     these and nothing else, which is why leaning on that row to justify
     deleting the flag here is a category error.
   - **Reap side — LIVE UNTIL STEP 5**, because it gates
     `pending_zombie[64]`, and the tree states the consequence in as many
     words at `arch/x64/interrupts.zig:2892-2898`: *"reaping an `on_cpu`
     EC unmaps the kstack mapped via TSS.RSP0 and triple-faults the next
     ring transition."* The gate sites are `sched/scheduler.zig:2016-2018`
     and `:2078` and `:552`, `arch/x64/interrupts.zig:2899`,
     `arch/aarch64/cpu.zig:468`.

   So **`on_cpu` and `pending_zombie[64]` are ONE mechanism — a column and
   the gate that makes reaping it safe — and they are deleted together at
   step 5**, along with `postZombie` / `takeOwnPendingZombie` /
   `claimOwnZombieInline` and the two arch reap loops. Deleting the gate
   at 4a while the column it guards lives through 4a, 4b and 4c is a
   triple-fault scheduled three steps ahead of the thing that would
   remove the hazard.

   Revision 16 wrote "the **four** named PerCore companions" and then
   listed `pending_kstack_release`, `post_park_clear_on_cpu`,
   `pending_cross_enqueue` **and a phrase** — substituting "the
   stash/consume machinery" for the one field whose gate `on_cpu` is.
   §2.3 (`:778`) and §2.6 (`:1357`) both name the fourth as
   `pending_zombie[64]`. The miscount is what hid the hazard, which is
   the argument for naming fields rather than gesturing at families.
   Two of those deletions depend on the entry mask for CORRECTNESS, not
   merely for performance, which is why they precede 4c:
   `pending_kstack_release`'s single-producer assert rests entirely on
   "every stash is followed by a hop before the next stash site can
   run", which is the mask and nothing else; and `destroyPhase2`
   carries an in-tree measurement of what happens when that assumption
   breaks — **1354 of 6228 phase-2 destroys (22%) never reached the end
   of the caller-EC reap, orphaning 192 ECs by pass ~14**. **That
   measurement is HISTORICAL: it is already closed at HEAD** by the
   two-stage `stygia-afo` fix (`caps/capability_domain.zig:1420-1436`
   records `p2_enter == p2_after_reap` over 10428 destroys;
   `sched/execution_context.zig:2210-2216` closed the walk). It is
   retained because it is the evidence for the ordering, not because the
   defect is live.
   **(4b) the ad-hoc enable must go before the enable arrives.**
   Revision 15 offered two alternatives here and **alternative B was a
   no-op**: the "temporary explicit mask over `destroyPhase2`" it
   proposed already exists at `caps/capability_domain.zig:1381-1382`, and
   thirteen lines later `:1394` states why that mask is not sufficient on
   its own. The real hole is `destroyExecutionContextLocked` re-enabling
   interrupts around its `postZombie` fallback at
   `sched/execution_context.zig:2224-2225`. **So 4b IS a deliverable, not
   a choice between escape hatches: the ad-hoc `enableInterrupts()` at
   `execution_context.zig:2225` and the `pending_zombie` cross-core
   fallback it guards are HOISTED OUT OF STEP 5 INTO 4b.** They are
   listed in step 5's Deletes clause as their design home; their landing
   order is here, before 4c, and step 5 notes them as already gone. (The
   alternative, if that hoist proves too large to carry alone, is to pull
   the §8.2 scheduler-context teardown move — step 6 — forward instead;
   that is the structural fix, and it is feasible now that 4a carries the
   hop step 6 is built on. Revision 15's alternative A was circular only
   because the hop sat in 4c.) What must NOT happen is 4c landing the
   entry-path enable while `:2225` still re-enables interrupts inside a
   must-complete sequence.
   **And `pin_depth` is NOT the refuted `preempt_block` counter, which an
   implementer WILL find mid-step and lose a day to.** The comment at
   `caps/capability_domain.zig:1408-1418` records a `PerCore` depth
   counter that made `yieldTo` return instead of switching and
   "deadlocks the machine inside the FIRST suite pass". It is
   structurally the gate 4c ships, and it is sound here only because
   **both of its stated causes die in 4a** — `pending_kstack_release`,
   and the wake-side spins step 3 already deleted. Say so at the point of
   use rather than leaving the refutation to be rediscovered.
   **(4c) then the entry-path enable, the pin gate, §2.4's bump/acquire
   ORDER with its §9.2 bracket asserts, and the user-boundary entry gates
   with §3.1 rule 3's precedence.**
   **ADDS the arch entry-path
   IRQ enable (§3.3, round-9 C-4) — in THIS step, not a later one:** the
   pin gate is a filter on preemption, and shipping it while EC context
   still runs IRQ-masked ships a gate with nothing to gate, silently
   voiding rule 1, the C1 ordering rule, T2's ready×K cell and all three
   preemptible-spin columns. Requeue via `parking(requeue)` gated on
   `pin_depth`, with **§2.4's bump/acquire ORDER and its §9.2 bracket
   asserts landing in the same step as the counter** (C1 — the counter
   without the order does not discharge T2's ready×K cell, so shipping
   them apart ships a gate that does not gate); user-boundary entry gates
   **with §3.1 rule 3's precedence — the tick's directive arm before its
   requeue arm** (M-5).
   **Also lands §8.1's `yieldTo` AFFINITY-MASK GATE, which HEAD does not
   have and which had no step until revision 16 (round-14 N-1).** §8.1
   and §5's edge-2 row both make it mandatory — a `yieldTo` target must
   be `ready` on THIS core's queue, S7-live, **and affinity-mask-admitted**,
   or the call degenerates to a plain `yield`. The tree's guard
   (`sched/scheduler.zig:900`) has the first two and not the mask, so
   today `yieldTo` can dispatch a target onto a core its own affinity mask
   excludes. It lands here because this is the step that rewrites the
   edge-2 dispatch section the guard sits in; it is §8.1 work and could
   ride step 10 instead, but **not later than step 10** — it is a
   spec-conformance gate and must not sit behind the most deferrable step
   in the plan.
   **Also lands `current_queue_core`'s §3.4 discipline, which HEAD does
   not implement.** §3.4 requires it cleared under the same lock **on
   every exit from `ready`**. At HEAD it is cleared at
   `sched/scheduler.zig:914`, `:1434`, `:1691`, `:1705` and
   `sched/execution_context.zig:1876` — and `:1691`/`:1705` are
   **reader-side self-repair inside the search fallback**, not exits from
   `ready`. Revision 14 gave the field a §3.4 row and no step landed it;
   this is that step for the Zig sites. (Its x64-asm half goes with step
   8 — the fast path maintains the field nowhere, which is why a §9.2
   S1-containment assert built on it would be checking a field that lies
   on x86-64. README ledger **G13**.)
   Deletes (all of 4a's, restated as the step's net effect): THREE of the
   four PerCore companions (`post_park_clear_on_cpu`,
   `pending_kstack_release`, `pending_cross_enqueue`) and their
   stash/consume machinery, scattered `clearCurrentEc` sites,
   disowned-current escapes. **NOT `on_cpu` and NOT `pending_zombie[64]`
   — both at step 5, see 4a.**
5. **State-word retire handoff + directive.** Introduces **`ec.directive_state`
   and `ec.directive_port` by name** (§2.5, §3.4) — revision 16 shipped this
   step saying only "the directive", and the closure check flags a field
   named in a §3.4 row and in no step (round-14 N-8). — **this step also lands
   §2.5's ARM OWNERSHIP (`{ state: u8, owner_slot: u24 }`) and the
   two-part break disambiguator (round-11 M-6: revision 11 landed
   neither in any step — `grep owner_slot` over §12 found zero — while
   shipping the directive protocol they protect). Without them this
   step ships round-10 C-D's ABA and round-11 C-1's false SUCCESS.**
   — **and this step LANDS
   round-8 C-1's W3 exits (§3.6 W3: the self carve-out and the
   retired-terminator escape), which revision 10 wrote normatively and
   then scheduled into no migration step at all (round-10 M-E).** That
   is the fix for a hard two-core deadlock **live in the tree today**
   (bead `stygia-noi`); it cannot sit outside the migration plan. It
   belongs here because this is the step that introduces the
   state-word retire handoff the escape is expressed against. (With
   M-B re-check, and
   **§2.5.1's suspend-cycle rejection in the same step** — the directive
   word gains its `suspending` value and the suspender's self-mark CAS;
   shipping the directive protocol without it ships the N1/N6 shapes).
   Deletes: **`on_cpu` (its REAP-SIDE gates — the wake-side spins went at
   step 3; see 4a for why the two halves split across steps) together with
   `pending_zombie[64]`, which those gates exist to make safe to reap**;
   `postZombie` / `takeOwnPendingZombie` / `claimOwnZombieInline` and the
   two arch reap loops (`arch/x64/interrupts.zig:2899`,
   `arch/aarch64/cpu.zig:468`) go in the same step, because a column and
   the gate that guards it are one mechanism;
   `ZOMBIE_WAKE_RETRY_SPINS`, the last **ad-hoc** `enableInterrupts()`
   outside `arch/` (the one inside a must-complete sequence — NOT the
   entry-path enable step 4 adds, §3.3; exactly one site,
   `sched/execution_context.zig:2225`, which correctly excludes the
   aarch64 EL0 `wfi` trap's enable noted at `sched/scheduler.zig:1264`),
   `last_dispatched_core` (→ `owner_core`), today's
   remote-suspend state flip.
   **Two of those are design-homed here but LAND EARLIER, at 4b**: the
   ad-hoc `enableInterrupts()` and the `pending_zombie` cross-core
   fallback it guards. By the time this step runs they are already gone;
   what remains here is the rest of `pending_zombie[64]` and its
   drain/post/claim functions. See step 4b for why the order is forced.
   **And one thing `pending_zombie` is currently the ONLY mechanism for,
   which must route somewhere before it goes**: deferring the CALLER
   EC's finalize off its own kstack during phase 2.
   `caps/capability_domain.zig:1497-1503` reaps the caller EC while the
   frame is standing on that EC's stack, and `claimOwnZombieInline`
   (`sched/scheduler.zig:2055-2079`) exists solely for that
   configuration. After this step the finalize routes to the frame's own
   later hop, which works — but §5.2's matrix has no cell for **a frame
   that keeps running an unbounded body after its own retire**, so state
   the routing here rather than discovering it at N=100.
6. **Scheduler-context teardown, dead-mark included** (M-A): self-retire
   → hop → phase 1 + phase 2 on the park stack; S7 inline-retire
   routing. **ADDS `PerCore.teardown_pending`** (§2.3, §8.2 — the
   self-produced/self-consumed request that carries the self-delete
   teardown and its pre-teardown CD ref across the hop). §2.6 lists it
   among the words the machine ADDS as "the honest price", and no step
   named it before revision 16 — the same closure gap `committed_ec` had.
   Deletes the phase-2 IRQ-mask fragility, `keep_ref`, the
   EC-context dead-mark window, and — now that the structural fix is in —
   the `stygia-afo` counters step 1 held back.
7. **Publish-last creation with the CD-locked liveness gate.**
8. **Fast-path conformance** (core lock; in-lock CAS publish;
   kstack-clean audit; trace-hook rule; 5b-receiver bail pinned).
   **AND §9.4's suspend-path mask (round-11 M-6) — which must land NO
   LATER THAN step 4c**, not here: step 4c adds the entry-path enable,
   and from that instant the suspend FP's unmasked `xchgl` spin on
   `port.timed_recv_lock` (`arch/x64/interrupts.zig:1379-1385`) is
   self-deadlockable against the timer tick. That spin is live at 4c
   **because step 3 no longer deletes it** — see step 3's timed-registry
   note; revision 15 asserted both that step 3 deleted it and that it
   was still a hazard at 4c, and only one of those can be true.
   Steps 5, 6 and 7 each ride a full N=100 bare-metal pass, and running
   any of them with a single-core self-deadlock live is exactly the
   class of error step 4's internal ordering was rewritten to prevent.
   **This step also lands `timed_recv_waiters`' unification into §8.4's
   single intrusive per-EC node** — deferred here from step 3 because it
   is an asm rewrite, not a re-offset: `SyscallScratch`'s
   `timed_recv_waiters_ptr`/`timed_recv_lock_ptr` and their
   `@compileError` drift guards (`arch/x64/interrupts.zig:201`, `:260`,
   `:289`, `:336`) and the inline `removeTimedRecvWaiter` scan at
   `:1378-1402` all go, the scan becoming an intrusive-node unlink.
   **Deletes: `committed_ec`** (17 refs / 3 files; decl
   `sched/scheduler.zig:180`, writes `:916`/`:1517`/`:1525`, clears
   `:1289`, `arch/aarch64/cpu.zig:541`, `arch/x64/interrupts.zig:2961`,
   readers `scheduler.zig:1838` `awaitDomainQuiesced` and `:2067`
   `claimOwnZombieInline`). §0.1 names it as one of the FOUR signals for
   which redundancy is met literally, and no step named it until now.
   §2.3 halves the deletion — the slow path goes at step 4's "`current`
   written only at commit/hop", the fast path here — so the field can
   only actually go at this step. A surviving `committed_ec` is
   conservative (the barrier waits longer), which is why this is the last
   step rather than an earlier one, but leaving it in falsifies §0.1's
   stated deliverable.
   Also: the x64 fast path's R13 ready-enqueue branches must keep the
   same `current_queue_core` discipline as Zig enqueue sites: publish the
   local core id after queue links/tail and before releasing the core
   lock.
9. **Analyzer completion**: rules 9.3(2)–(6) — including the T1/T3
   closure checks — into precommit CI, subject to the maintainer
   sign-off named as a precondition above.
   **9.3(7)'s pin-class DERIVATION — the effective-mask computation,
   report-only — must land NO LATER THAN step 4** (round-10 M-E), not
   here: step 4 ships the pin gate, and the gate's correctness depends
   on the computed class set. Shipping the gate against a recalled class
   list is exactly what F3 was.
   **§2.4's THIRD CLAUSE lands HERE, not at step 4, and revision 15 had
   this wrong.** Revision 15 back-constrained the whole of 9.3(7) to
   step 4 — including the third-clause check (no pin-class lock may have
   an interrupt-context acquire site) — while §9.3(7)'s own STATUS says
   that check cannot be built yet: it needs an IF-state model in
   `asm_analyzer.zig` and `trap_sync` promoted or fault entry masked, and
   **neither exists**. DERIVED, not recalled:
   `tools/check_gen_lock/src/asm_analyzer.zig` is 1493 lines and models
   LOCK state per register — `grep -cE '\b(cli|sti)\b'` over it returns
   **0**; there is no IF tracking in it at all. (Use the word-anchored
   pattern: the unanchored `grep -c 'cli\|sti'` returns **16**, every one
   of them the substring `sti` inside `substitution`/`substituted`.
   Revision 16 cited the unanchored command with the anchored result — the
   conclusion was right and the stated evidence refuted it, which in a
   claim labelled DERIVED is the whole defect.) So step 4 was gated on work the
   document itself classifies as unbuildable at HEAD. The third clause is
   **meanwhile enforced by review**, exactly as §2.4 already says it is.
   **9.3(2) cannot be turned on gating against HEAD without a hoist
   obligation, and no step carries one.** 9.3(2) forbids user-memory
   accesses (SMAP brackets) inside any container/gen-lock hold. There are **four `userAccessBegin` CALL sites outside `arch/`** (the
   in-`arch/` hits are the helper definition and doc comments, not
   copy windows) — `syscall/port.zig:191`, `syscall/reply.zig:214`,
   `memory/vmar.zig:807`, `memory/vmar.zig:877` — and **two of the four
   are inside gen-lock holds**:
   `memory/vmar.zig:807` (under `v._gen_lock` taken at `:780`) and `:877`
   (taken at `:852`) — the tree comment at `:800-804` acknowledges the
   hazard and dodges it by rejecting `.unmapped` rather than hoisting.
   §11.13 adds two more, against 9.3(2)'s new quiesced-resume clause:
   `arch/x64/interrupts.zig:3003` and `arch/aarch64/cpu.zig:555`.
   **So either the hoist lands with this step, or 9.3(2) goes in
   REPORT-ONLY first and is promoted after.** Note the two `vmar.zig`
   sites are the same call sites bead `stygia-qap` must restructure, so
   the cheapest sequencing is report-only here and hoist-with-`qap`.
10. **`priority`/`affinity` re-bucketing** (§8.1, round 7 C2/M-1;
    beads `stygia-va7`, `stygia-me9`): the two words gain their named
    writer and the reach-and-validate protocol; the `ready` in-lock
    relink and the `waiting` all-container re-bucket replace today's
    bare field stores. Deletes the silently-deferred-re-bucket defect
    (a queued EC keeping its old key until it naturally re-enqueues —
    for a parked futex waiter, never). This step is **spec-visible**:
    §[priority] [test 06] and [test 07] pass only after it lands, and
    they are the only instruments that check it — the TLA+ battery is
    structurally blind here (README ledger G9).

Steps 3–6 and 8 are the risk core; each rides a full N=100 bare-metal
pass before the next lands. Step 10 rides `specv3.md` §[priority]'s
tests instead.

**What is deliberately NOT in this plan, so its absence is not read as an
omission** (§12's first review found five blockers, and the one that
recurs across revisions is this shape — a mechanism written normatively
into §§0–9 and scheduled nowhere):

- **The domain-wide pause** — `cd.paused`, `.domain_pause`, §3.1 rule 3's
  third boundary arm, edge 1's gated publish, edge 7's paused-list arm,
  W5-N, §0.3's two refusals, §3.3's quiesced-resume rule, §9.2's
  quiesced-resume asserts, §11.8's E_BUSY addition and §11.13. **All
  DEFERRED to bead `stygia-qap`** (§0.3). It would sit after step 6, and
  nothing in steps 1–10 depends on it.
- **`restart_at_entry`** — not a design obligation of this machine until
  restart semantics exist (§0.3). No edge, no §5.2 row, no step.
- **Cross-class lock ordering** — out of scope entirely by §0.2; §11.10
  is retracted and nothing here is gated on it.
- **Words the machine does NOT change, so they need no step** — listed
  because the closure check flags them every time and an unexplained flag
  costs the next reader the same hour twice: `PerCore.active_root` (§2.3,
  "retained unchanged", with `awaitDomainQuiesced`), `PerCore.idle_parked`
  (§3.4, "as today" — and see §2.1.1's withdrawal for why it is the only
  idleness fact), and `PerCore.current_ec`, which is not deleted but
  **RENAMED** to `PerCore.current` and lands under that name at step 4.

**FOUND BY THE CLOSURE CHECK, BOTH NOW RESOLVED.** Running that check
(the last paragraph of this section: grep §12 for each mechanism's name)
against revision 16's own §12 turned up two mechanisms named nowhere.
`PerCore.teardown_pending` had an unambiguous home and is now at step 6.
The other was resolved by the maintainer in the other direction:

- **§2.1.1's per-core idle EC — WITHDRAWN, and deliberately given NO
  step.** The section was normative and defined S1's containment answer
  for an EC that does not exist: `idle_ec` is declared at
  `sched/scheduler.zig:184`, read once unreachably at `:1521`, and
  **never assigned**. Building one to satisfy the paragraph would
  **regress a fixed bug** — `:1098` records that `parkAndAwaitIRQ`
  replaced the idle EC precisely to kill the cross-core kstack sharing it
  caused, where several idle cores held stale `gs:0` into one suspended
  EC's kstack. So §2.1.1 is withdrawn, its §5.3 T4 container row is
  deleted, and **S1 is restated where it mattered: a core with an empty
  run queue holds NO EC — idleness is a fact about a CORE
  (`PerCore.idle_parked`), not a state of any EC, and raises no
  containment obligation.** The dead field and its stale declaration
  comment are a cleanup, not this machine's business.

**Three deferrals, three shapes, and the pattern is worth naming.** The
pause is deferred because it is unimplemented and unmodelled;
`restart_at_entry` because the feature it belongs to does not exist; the
idle EC because **the tree deliberately does something better**. Only the
first is likely to come back as written. The common cause is that all
three were carried as design obligations on the strength of a paragraph
rather than a check against the tree.

Everything else that §§0–9 states normatively has a step above. That
closure is the property to re-check after any edit to §§0–9.

**WHAT SURVIVED A HOSTILE READ — round 14's sufficiency reviewer
independently re-derived these against the tree and found them EXACT.**
Recorded because "which citations have been checked by someone other than
their author" is information an implementer needs and nothing else in this
document carries it. Confirmed clean:

- **Step 5's "exactly one ad-hoc `enableInterrupts()` outside `arch/`"** —
  the site is `sched/execution_context.zig:2225`, and the exclusion of the
  aarch64 EL0 `wfi` trap's enable is correct.
- **Step 8's `committed_ec` enumeration** — decl, three writes, three
  clears, two readers; exact, and §2.3's argument that the field can only
  go at step 8 holds.
- **`current_queue_core`'s five clear sites**, including the finding that
  two of them are reader-side self-repair rather than exits from `ready`.
- **The `vmar` stubs** — `quiesceDomain`/`resumeDomain` empty, called from
  `idc_read`/`idc_write`, and `acquire_vmars` with no pause call at all.
- **The restart plumbing** — policy-only, with all eight
  `restart_semantics_*` cases testing `E_PERM` bounding.
- **§11.13's sites** — both dispatch-tail user-memory writes and both
  staging sites.
- **Step 3's and step 8's entire asm inventory** — the `suspend_port` and
  `pending_reply_*` `@offsetOf` sites, the layout-drift `@compileError`
  guards, and the `timed_recv_waiters` scratch threading.

**THE CLOSURE CHECK, and its known blind spot — stated because revision
16's first version of it missed three things and round 14 found them
(B-1, N-1, N-8).** The check was "grep §12 for each mechanism's name".
That is necessary and not sufficient, and it fails in three distinct
ways. Two are fixable mechanically; the third is not, and pretending
otherwise is how the check earns trust it has not got.

1. **Multiple spellings — FIXED by deriving the spelling, not typing
   it.** The idle EC survived a withdrawal in five places because the
   sweep grepped `'idle slot\|idle_slot'`, a spelling set written from
   memory, while the document also uses `idle-slot` (hyphen), `idle_ec`
   and `idle EC`. **Take the identifier verbatim from the doc's own code
   blocks and table cells; never retype it.** For a field, that is the
   §2.3 struct text and the §3.4 row's first column.
2. **Never enumerated — FIXED by deriving the mechanism LIST from the
   document's own tables.** `directive_port` has a §2.6 entry and a §3.4
   row and zero §12 mentions, and no hand-written list caught it because
   no hand-written list contained it. **The mechanism list is the first
   column of §3.4's word table plus §2.6's added/deleted table** — both
   machine-readable — not a list anyone recalls. Extract those columns
   and difference them against §12.
3. **NAMELESS MECHANISMS — NOT FIXABLE BY A NAME GREP, and this section
   says so plainly rather than implying coverage it does not have.**
   §8.1's `yieldTo` affinity-mask gate is a RULE, not a word: it adds no
   field, renames nothing, and has no identifier to grep for. It was
   mandatory, absent from the tree, and absent from §12, and the name
   check could not have found it in principle. The partial mitigation is
   a SECOND index over a different feature: **every normative-modal
   sentence inside the `<<< IMPLEMENTABLE SPEC >>>` markers — "MUST",
   "mandatory", "normative", "may not" — needs a §12 step or an explicit
   exclusion.** That is a sentence-level sweep, not a name sweep, and it
   would have caught this one. **The residual, stated: a rule with
   neither an identifier nor a modal verb is not catchable by either
   sweep, and only an adversarial read finds it.** Round 14 is the
   instrument for that, and it is the reason the closure check is a floor
   and not a proof.

---

## 13. Changelog

**Revision 16 (2026-08-02)** — closes the one thing revision 15's C-1 fix
ASSERTED rather than made checkable. **Doc-only: no model change, so no
revision-15 verdict went stale.**

- **The quiesced-resume rule is now normative (§3.3), and it was a
  parenthetical before.** §0.3's argument that the pause needs no
  per-state routing on 5a/5c turns on a `waiting(futex)` target running
  "the tail of its own futex return in KERNEL code — which touches no
  user memory (§3.3 bans that inside holds anyway)". **The parenthetical
  does not carry the claim.** §3.3's ban is on user-memory access inside
  container-lock and gen-lock holds; a syscall return tail is not inside
  a hold, so the citation is to a rule about a different region. And the
  exposure it was papering over is specific: W5-N's predicate covers the
  RUNNABLE subset only — which is exactly what lets the pauser finish —
  so once the pauser proceeds, a later wake can make a `waiting` EC of
  that domain `running` in kernel code while `idc_read`/`idc_write`/
  `acquire_vmars` is mid-flight. The rule is now stated in §3.3 in its
  own right, with a §9.2 assertion pair and a §9.3(2) analyzer clause,
  because a premise nobody can execute is a premise nobody has checked —
  the same argument revision 12 made about §2.5's arm CAS.
- **WHICH LEG of the user boundary the domain-paused arm is checked on is
  now normative (§3.1 rule 3), and the two readings are not equivalent.**
  Revision 15 said the `retired`, `directive` and domain-paused arms
  "fire only on entry from user mode" while §0.3 said a gated EC "parks
  at the boundary before executing a single user instruction" and §3.6
  W5-N justified excluding `waiting`/`claimed`/`pended` from the
  predicate on the ground that "every path from them back to user code
  passes the §3.1 rule-3 gate". **A wake → dispatch → syscall-return path
  passes no entry check at all**, so under the entry-only reading a
  futex-woken EC returns to user code inside a paused domain and W5-N's
  own soundness argument is false. The domain-paused arm is now specified
  on **both** legs, with the return leg named as the one that makes the
  pause a pause; `retired` and `directive` stay entry-only and the reason
  is stated. §9.2 asserts the arm is reachable from both legs, because
  the model has no domains and this assert is the only enforcement there
  is.
- **§11.13 — the tree violates the quiesced-resume rule at HEAD on BOTH
  arches, and this is a decision, not a bug report.** DERIVED, not
  recalled: the dispatch tail flushes `pending_event_word` into
  `[user_sp + 0]` and `pending_event_rip` into the vreg-14 slot after the
  CR3/TTBR0 swap and before the `iretq`/`ERET`, SMAP/PAN cleared
  (`arch/x64/interrupts.zig:3003`, `arch/aarch64/cpu.zig:555`). It is a
  kernel write to a woken EC's user stack on the rendezvous-wake resume
  path, downstream of any gate placeable in Zig. The deferral is itself a
  correctness fix (`port.deliverEvent` stages the word while the kernel
  is still in the *sender's* address space) — it solves one problem and
  creates this one. §11.13 states the two ways out and does not pick.
  The §9.3(2) clause has its proof-of-fire built in: run it against
  pre-fix HEAD and it must flag both sites, and an implementation that
  reports zero has not been shown to work.

**Revision 16, second half — §12 was REVIEWED FOR THE FIRST TIME and it
failed.** Five blockers, and the dominant pattern is the one §13 has now
caught three times (round-10 M-E, round-11 M-6, and here): **a mechanism
written normatively into §§0–9 and scheduled into no §12 step.** This
time at the largest scale yet. Two maintainer decisions and the repairs:

- **The domain-wide pause is DEFERRED out of the refactor** to bead
  `stygia-qap` (maintainer decision). It appeared in nine normative
  places and zero migration steps. Every normative section stays — the
  design is good and the follow-on uses it verbatim — and only its
  MIGRATION STATUS changes, in the same shape `restart_at_entry` carries.
  Three reasons, in §0.3: it is unimplemented at HEAD
  (`memory/vmar.zig:1606`/`:1610` are `_ = cd;` stubs and `acquire_vmars`
  has no pause call at all, so deferring regresses nothing), it is
  UNMODELLED in the battery (ledger G12), and nothing in steps 1–10
  depends on it. §0.3 also records that the follow-on is a
  RESTRUCTURING, not a stub-fill: `vmar.zig:780`/`:848` hold `_gen_lock`
  across both the pause point and the SMAP window, which W5-N and §9.2
  both forbid. §3.3's quiesced-resume rule and §11.13 are marked dormant
  until that bead lands, so neither is a §12 blocker.
- **`restart_at_entry` is downgraded from "IN, deferred" to NOT A DESIGN
  OBLIGATION** (maintainer decision). Revisions 13–15 promised it an
  edge, which commits the machine to routing one value of one policy in
  a feature that does not exist and whose semantics will move when it is
  designed. The tree agrees: only the policy plumbing is implemented
  (`caps/capability.zig:346`/`:581`/`:591`/`:604`) and all eight
  `restart_semantics_*` cases test `E_PERM` bounding, not restart
  behaviour. The analysis of what the edge would look like is KEPT; only
  its status is demoted.
- **Step 3 no longer deletes a registry the x64 fast-path asm scans
  inline.** `timed_recv_waiters` is threaded through `SyscallScratch` and
  walked by hand-written assembly with its own `@compileError` drift
  guards, so §8.4's intrusive-node unification could not compile on
  x86-64 at step 3 — and revision 15 simultaneously claimed step 3
  deleted the `xchgl` spin AND that the spin was still a 4c hazard. Step
  3 now unifies the FUTEX registry only; `timed_recv_waiters` moves to
  step 8; step 8's back-constraint is restated against what survives.
- **Step 4's 4a/4b/4c decomposition now says where the REPLACEMENT
  lands.** 4a was "the deletions first" and listed only deletions, which
  is not landable — `on_cpu`'s replacement IS the hop completing
  everything, and `takePendingReleaseByte` (`sched/scheduler.zig:722-728`)
  literally returns `&pending.on_cpu`. 4a is now the deletions **and** the
  mechanism they depend on; 4c is the entry-path enable, the pin gate,
  §2.4's bump/acquire order with its §9.2 brackets, and the boundary
  gates with rule 3's precedence. All FOUR PerCore companions are named,
  not two.
- **4b's alternative B was a no-op and is replaced.** The "temporary
  explicit mask over `destroyPhase2`" it proposed already exists at
  `caps/capability_domain.zig:1381-1382`, and `:1394` says thirteen lines
  later why it is insufficient. The real constraint is that step 5's
  deletion of the ad-hoc `enableInterrupts()`
  (`sched/execution_context.zig:2225`) and the `pending_zombie` fallback
  it guards must land no later than 4c. Two corrections ride with it: the
  22% orphan measurement 4b is written around is **already closed at
  HEAD** by the two-stage `stygia-afo` fix, and is retained as evidence
  for the ordering rather than as a live defect; and step 4 now says why
  `pin_depth` is not the refuted `preempt_block` counter at `:1408-1418`,
  because both of that counter's stated causes die in 4a.
- **Step 9 no longer gates step 4 on unbuildable tooling.** §9.3(7)'s own
  STATUS says the third-clause check needs an IF-state model in
  `asm_analyzer.zig` that does not exist — verified:
  `tools/check_gen_lock/src/asm_analyzer.zig` is 1493 lines and models
  LOCK state per register, with **zero** `cli`/`sti` tracking. The
  pin-class DERIVATION (effective-mask, report-only) lands by step 4; the
  third clause lands at step 9 and is meanwhile enforced by review, which
  is what §2.4 already said. Maintainer sign-off on promoting
  `tests/precommit.sh`'s `[0d]` stage to gating is now an explicit
  precondition of steps 1 and 9, per that file's own `:563-564`.
- **Step 1's "drop diagnostics" was the one genuine OVERSHOOT** and is
  scoped to `leak_tag` plus the EC-state writers. As written it was
  tree-wide and would have taken instruments belonging to `stygia-2u0`
  and `stygia-9zr`, neither of which touches EC lifecycle or scheduler
  state — §0.1's own test excludes them. Rider: the `stygia-afo`
  counters survive through step 6, because they are the only instruments
  that measure the abandonment 4b is ordered around.
- **Non-blocking, all landed in the same pass:** `committed_ec` gains its
  deletion step (8, and §2.3 is why it can only be 8); `ec.wait` is
  introduced by name at step 3 along with the `suspend_port` /
  `pending_reply_holder` fold and its 19 x64-asm `@offsetOf` sites;
  §9.3(2)'s two in-hold SMAP violations (`memory/vmar.zig:807`/`:877`)
  get an explicit report-only-first-or-hoist obligation at step 9;
  `current_queue_core`'s §3.4 discipline gets its step (4 for the Zig
  sites, 8 for the fast path), with the note that HEAD's `:1691`/`:1705`
  clears are reader-side self-repair rather than exits from `ready`;
  step 2's deferred-marking arm is flagged inert so a green step-2 pass
  is not misread as validating the split; and step 5 states where the
  caller-EC finalize routes once `pending_zombie` goes, since §5.2 has no
  cell for a frame running an unbounded body after its own retire.
- **§2.4's blockquote no longer contradicts itself.** It opened "the set
  is NOT empty — revision 13's 'EMPTY at HEAD' was refuted" and closed
  three paragraphs later with "revision 13's 'the class is empty at HEAD'
  is correct". An implementer reading top-down to derive step 4's class
  set read the refuted answer first. The conclusion is now stated up
  front and the three derivation steps are labelled as such.
- **§12 now ends with a CLOSURE CHECK, and running it found two more.**
  The recurring failure is a mechanism written normatively into §§0–9 and
  scheduled nowhere, so the section now states the check that catches it:
  **grep §12 for each mechanism's name**, mechanically, rather than
  reading §12 and judging. Running it against revision 16's own §12
  turned up **`PerCore.teardown_pending`** — a word §2.6 lists among
  those the machine ADDS, unnamed in any step, now at step 6 — and
  **§2.1.1's per-core idle EC**, which was normative, defined S1's
  containment answer for that EC, was UNMODELLED (ledger G7 — since
  CLOSED by the withdrawal below, the model having been right), and whose
  slot at `sched/scheduler.zig:184` is declared and read and **never
  assigned** at HEAD (`:1098` handles the "no `idle_ec` set up" case
  outright). Reading had missed both across sixteen revisions; the grep
  found them in one pass.
- **§2.1.1 is WITHDRAWN (maintainer decision), and it is the most
  instructive of revision 16's three deferrals because here the tree is
  not merely different — it is deliberately BETTER.** `parkAndAwaitIRQ`
  replaced the idle EC to kill a real bug, recorded at
  `sched/scheduler.zig:1098`: several idle cores held stale `gs:0` into
  one suspended EC's kstack and concurrently pushed IRQ frames onto it
  from kernel mode, stomping each other's saved state and surfacing as
  `iretq` #GP or NO-EC page faults. **Building an idle EC to satisfy a
  doc paragraph would have regressed that fix**, which is why the answer
  is withdrawal and NOT a §12 step. Landing with it: §5.3's T4 row for
  the "per-core idle slot" is deleted (it is not a container — there is
  no EC to contain), §2.3's `PerCore` drops the field with the reason
  in-line, and **S1's answer is restated where the withdrawal touched
  it**: a core with an empty run queue holds NO execution context; it
  parks on its own park kstack, which is core-owned storage rather than
  an EC container; idleness is a fact about a CORE, recorded in
  `PerCore.idle_parked`, not a state of any EC — so it raises no
  containment obligation and S1 is untouched. Explicitly NOT affected:
  the `.idle_wait` EC state and `wait.kind == .idle`, which are real and
  live (the aarch64 EL0 `wfi` trap at
  `arch/aarch64/exceptions.zig:737`, x86-64 `#GP`-on-`hlt` at
  `arch/x64/exceptions.zig:260`, and `suspend` accepts such a target) —
  those are a USER EC choosing to idle, which is a different thing from a
  core having no EC to run.
- **Three deferrals in one revision, three different shapes, one common
  cause.** The pause: unimplemented and unmodelled. `restart_at_entry`:
  the feature it belongs to does not exist. The idle EC: the tree
  deliberately does something better. All three had been carried as
  design obligations on the strength of a paragraph rather than a check
  against the tree, and all three were surfaced by mechanical checks —
  the §12 grep and `grep -rn` over the kernel — not by rereading.

**Revision 16, third pass — ROUND 14's REVIEWS.** Parity: **no blocking
findings** (G12/G13 accurate, every `U*/G*/N*` label resolves).
Sufficiency: **NOT CLEAN, three blocking**, all of the form "an
instruction that cannot be executed as written" — and two of them inside
paragraphs revision 16 wrote to fix that exact class, which is the
standing lesson arriving again.

- **B-1 — D3 was applied in three places out of FIVE.** `idle slot`
  survived at §2.1's lifecycle word and containment table, §3.2's
  dispatch sequence, §5's edge-2 trigger and §6.1's S8. Consequences,
  each independent: §6.1's S1 is defined as *"As §2.1's table"*, so S1
  itself still said a `ready` EC may live in the idle slot; §5.3's T4 had
  a hole it calls "a defect by definition", because two rows named a pop
  site whose row was deleted; and S8 named a route into `ready` with no
  edge number, actor or trigger — an un-routed transition inside the
  closure invariant. All five fixed. **Why the closure check missed it is
  the more useful half**: the sweep grepped `'idle slot\|idle_slot'`, a
  spelling set written FROM MEMORY, while the document also uses
  `idle-slot`, `idle_ec` and `idle EC`. The check reproduced the exact
  failure mode it exists to prevent, one level up. §12 now states the
  three ways a name grep fails and what replaces it.
- **B-2 — §12 step 4a scheduled a TRIPLE-FAULT.** 4a deleted `on_cpu`
  while step 5 kept `pending_zombie[64]`, leaving the zombie column live
  across 4a/4b/4c **with its gate removed** — and the tree states the
  consequence at `arch/x64/interrupts.zig:2892-2898`: *"reaping an
  `on_cpu` EC unmaps the kstack mapped via TSS.RSP0 and triple-faults the
  next ring transition."* `on_cpu`'s two consumer families split by step
  (wake side at 3, reap side at 5); the flag and the column are ONE
  mechanism and now die together at step 5. **The miscount that hid it
  was in the same sentence**: 4a said "the four named PerCore companions"
  and listed three fields plus a phrase, substituting "the stash/consume
  machinery" for `pending_zombie[64]` — the one field whose gate `on_cpu`
  is. Fields are now named.
- **B-3 — the census rider was unexecutable across four steps.** "The
  counters survive through step 6" instructs an implementer to leave a
  file that will not compile: the census reads `on_cpu` (step 5),
  `suspend_port` and `pending_reply_holder` (step 3) and `leak_tag`
  (step 1). Replaced with a **port obligation** — every step that deletes
  or renames a field the census reads updates the census in the same
  step. **Plus a silent one that is worse**: `by_state`/`orphan_by_state`
  are `[6]u32`, sized to the tree's six-member `State` enum, while this
  machine's word has SEVEN states, and their `st < len` guards mean the
  census does not fail to compile — it **under-counts**, defeating the
  rider's entire purpose. Widen with the enum. Two tag corrections: the
  census is `stygia-2u0`, not `stygia-afo`; and `leak_tag` is `stygia-2u0`
  too, so "drop `leak_tag`" and "the `stygia-2u0` instruments stay"
  contradicted each other outright — that enumeration named 2 of **24**
  tagged sites across 7 files. Step 1 is now scoped by §0.1's TEST, with
  the bead list derived rather than written.
- **N-1 — §8.1's `yieldTo` affinity-mask gate: mandatory, absent from the
  tree, absent from §12, and §11.12 claimed it was "what the tree does".**
  Verified: `sched/scheduler.zig:900` guards on `ready` + `domainRefAlive`
  and nothing else; the nearby `affinity` mentions are the CALLER's own
  test. §11.12 corrected, gate scheduled at step 4. **And it is the
  sharpest evidence for the closure check's limit: the mechanism has no
  NAME.** It adds no field and renames nothing, so a name grep could not
  have found it in principle. §12 now carries a second, sentence-level
  sweep over normative modals, and states the residual plainly.
- **N-4 — DERIVED evidence that its own command refutes.** Step 9 cited
  `grep -c 'cli\|sti'` over `asm_analyzer.zig` returning 0; it returns
  **16**, every hit the substring `sti` inside `substitution`. The
  conclusion was right and the stated evidence was wrong, which in a
  claim labelled DERIVED is the whole defect. Now `grep -cE
  '\b(cli|sti)\b'` → 0, with the trap recorded.
- **N-2/N-3/N-5/N-6/N-7, same pass.** §9.2's quiesced-resume assert (3)
  claimed a HEAD proof-of-fire that is impossible by its own construction
  (the bit is never set at HEAD because no domain is ever paused) — that
  property belongs to §9.3(2)'s analyzer clause, a different instrument.
  §9.2's "asserts it is reachable from BOTH legs" is not writable as a
  runtime assertion and is now a §9.3 static clause plus a debug coverage
  pair. §2.4's rule sentence and §9.3(7) both still stated the SYNTACTIC
  reading while the blockquote declared effective-mask normative, so a
  top-down reader built the reading revision 14 got wrong; and §2.4
  credited `check_gen_lock` with carving a site out "by name" when (c2) is
  an **interprocedural greatest fixpoint** — the tool is stronger than the
  doc said, which matters because it is the evidence effective-mask
  membership is computable at all. Citation drift in DERIVED claims fixed:
  `suspend_port` in x64 interrupts is **15** not 19; the
  `pending_reply_*` trio is **48** refs not 21 (21 is the one field);
  `vmar.zig:877`'s gen-lock is at **`:852`**; the SMAP count is **four
  call sites OUTSIDE `arch/`**, not four tree-wide;
  `takePendingReleaseByte`'s `&pending.on_cpu` is at **`:729`**; and
  §2.1.1's cited grep needed its glob quoted for this project's zsh.
  `TeardownRequest` was used as a type and defined nowhere.
- **The closure check now returns CLOSED**, re-run after the fixes with
  the mechanism list DERIVED from §3.4's and §2.6's tables rather than
  recalled: every word is either in a numbered step or in the explicit
  exclusion list. It caught `directive_port`, `directive_state` and
  `timed_waiters[64]` (all now named in steps) and flagged
  `PerCore.active_root`, `PerCore.idle_parked` and `PerCore.current_ec`
  as unchanged-or-renamed, which are now stated exclusions.

**Revision 15 (2026-08-02)** — closes round 13's single blocker.

- **C-1 (the domain pause had no route for a `running` target)**: §2.1
  makes `running` unclaimable except by retire and a §2.5 directive, and
  §2.5's directive has exactly one consume arm which parks into a PORT —
  while §0.3's own argument establishes a pause has no port. Two earlier
  routings both failed to type-check (rev 13's "N applications of the
  suspend edge", rev 14's "arms N directives"), and the common case — a
  debugger pausing a live domain — had no route at all. **Fixed with
  shape (b), the per-domain gate**, which is strictly smaller than
  giving the directive a kind and a second payload: a `cd.paused` word,
  a third arm on §3.1 rule 3's boundary check, and resume via 5a + edge
  6. **§2.5 is untouched** — no kind discriminator, no second payload,
  no CD gen lock newly introduced into the park sequence, no change to
  the break disambiguator.
  Three things landed with it, each of which the review showed was
  load-bearing: **(1)** the no-cycle argument is now REAL rather than
  borrowed — §2.5.1's self-mark is about `suspend` and nothing said a
  pauser executes it, so §0.3 states the domain-level analogue directly
  (refuse if the target domain contains the caller; refuse if the
  caller's own domain is already paused), with the E_BUSY spec addition
  in §11.8. **(2)** per-state routing on 5a/5c is not needed and the
  reason is stated: the gate is at the boundary, so it catches every EC
  uniformly — a `waiting(futex)` target is neither claimed (which would
  destroy the wait) nor left to run user code (it parks at its boundary
  after only kernel-side tail work). **(3)** W5-N's contradiction with
  rule (b) is resolved by dropping the "N fixed at entry" claim: the
  pauser holds no lock and waits on a predicate over the RUNNABLE subset
  only, which cannot grow because edge 1's publish already reads
  `cd.paused` under the CD `_gen_lock` it holds.
- **§8.1 steps 3/4 no longer contradict each other on retry.** Step 4's
  argument is complete, so step 3 now says there is no retry — the
  retry reading would have been an unbounded loop on a remote word with
  no T3 row, which §3.6 forbids and step 4 denies creating.
- **§2.4 states WHICH READING its computed rule uses.** Revision 14
  applied the syntactic one (is the call `lock()` or `lockIrqSave()`?)
  and concluded the vCPU gen-lock sites were a tree defect. The
  analyzer applies the **effective-mask** reading — can a tick land in
  this hold? — and it cannot: `enterGuest` is bracketed at
  `scheduler.zig:598`/`:618` and `check_gen_lock` (c2) carves it out by
  name. **Effective-mask is now normative**, revision 13's "class is
  empty at HEAD" is restored, and revision 14's tree defect is
  withdrawn — including its prescription to convert to
  `lockWithGenIrqSave`, a `GenLock` method that does not exist on
  `SlabRef`.
- **§0.1 no longer overclaims.** The machine ADDS words; what §6
  delivers is one writer and one validity predicate per fact.
  Redundancy is literal for the four deleted signals and derivational
  for the rest.
- **`restart_at_entry` marked DEFERRED** to a named follow-on: it has no
  rows in §5/§5.2/§12, and "plus one T2 row" understated that.

**Revision 14 (2026-08-02)** — closes round 12's blocking set. **The
boundary is now a TEST, not an enumeration** — *does this affect EC
lifecycle or scheduler state: where an EC is, what core it is on,
whether it is runnable?* — because an enumeration is exactly what
drifted: revision 13 wrote one and it contradicted itself eight lines
apart. Exclusions now name WHICH of two reasons applies: **solved
elsewhere** (lock ordering, analyzer capability, migration sequencing —
related to EC lifecycle, but another instrument already handles them and
duplicating it here is complexity this machine must not carry) or
**genuinely does not touch EC state**.

- **C-1 (the domain pause: primitive IN, callers OUT, eight lines
  apart)**: §0.2 scoped `idc_read`/`idc_write`/`acquire_vmars` out under
  "does not move an EC" while §0.3 named the primitive they implement as
  IN. `specv3.md` says verbatim at `:722`, `:1894` and `:1952` that each
  **pauses every EC in the domain**. Fixed: the pause AND its resume are
  in §0.1, the three syscalls are named as the callers, only their
  VMAR/handle work is out. Revision 13's "N applications of the existing
  suspend edge" **did not type-check** — every suspend route ends in
  `waiting(port_queue)` and §[suspend] requires a port handle, delivers
  an event and resumes via a reply capability, and these three pass no
  port, deliver no event and resume from inside the same syscall. Four
  pieces added, and no more: **`wait.kind = .domain_pause`** (explicitly
  NOT a kernel-synthesized internal port — a synthetic port would need
  minting, refcounting, teardown-on-domain-death and invisibility to
  `recv`, which is more machinery than a wait kind), its container = the
  paused domain's EC list under the CD `_gen_lock` (a container §8.2
  already walks), a **T4 row**, and the **resume edge** (edge 6, the
  pauser 5a-claims each paused EC and places it). Plus **W5-N** in §3.6:
  one pauser, N targets — a shape W5's row did not describe. Its
  termination is W5's argument per target plus the conjunction, and the
  load-bearing part is that **a pauser is an EC, so pausing a domain
  containing a pauser is a suspend cycle and §2.5.1 already rejects it.**
- **M-4 (`current_queue_core`, the eighth signal — now discharged)**: it
  was retained by §2.6 with no §3.4 row, no named writer, no width and
  no validity set — verbatim the argument §2.2 used to DELETE the staged
  destination. **KEPT and given the row**: written under the destination
  queue lock at the CAS-then-link of edges 1/6/6p/8, cleared under the
  same lock on every exit from `ready`, valid iff `state == ready` and
  poisoned otherwise, and safe when stale because every reader
  re-validates under the lock it points at (§3.5's drop-and-retry). Kept
  rather than deleted because deleting it reinstates the 64-core sweep
  §2.6 records as removed. **All eight legacy signals are now
  discharged**, which is §0.1's deliverable.
- **M-3 (the pin class is NOT empty, and revision 13's conclusion was
  refuted by §2.4's own next paragraph)**: the two NAMED classes do
  leave the set — both are `lockIrqSave` at every acquire at HEAD,
  converted in `f1215bbf5`, and the doc's line numbers were stale — but
  the **gen-lock classes are in the set** via plain `SlabRef.lock()` at
  genuine EC-context sites (`vm_runloop.zig:73` and neighbours, both
  arches). A rule about what the code must do is not a filter that
  empties the computed set. Consequence, and it is load-bearing:
  §5.2's `ready × K` justification goes **back to the original two-arm
  dichotomy**, because revision 13's "every class masks" strengthening
  is false at HEAD — with §3.3's IRQs-enabled rule a tick can land
  inside the vCPU run loop's gen-lock hold, a frame neither masked nor
  pin-counted. Those sites are a **tree defect**: convert to
  `lockWithGenIrqSave`.
- **Battery apparatus (M-1)**: revision 12/13's `RESULT: FAIL` was the
  runner, not the model — two `run.sh` instances raced and collided on
  TLC metadir names (TLC derives the directory from the current time, so
  two runs starting in the same second abort). `run.sh` now **refuses to
  start when a TLC run is in flight** and makes metadirs PID-unique.
  `InvNoFalseSuspendSuccess` added to `small`/`medium`/`large`/`xlarge`
  so round-11 C-1's invariant is carried by the main safety configs
  rather than only by its own two gates, and **`-deadlock` dropped from
  `dirf6fix`** so the fix-check can show the two-part disambiguator
  introduces no wedge.
- **Non-blocking, deliberately deferred** (round-12's own bar): M-2's
  `dead` modelling is ledgered rather than modelled, the results-section
  rewrite, and every header/table staleness item. These are hygiene and
  land alongside implementation.

**Revision 13 (2026-08-02)** — **SCOPE CORRECTION.** The mechanism has
been stable for six rounds; what churned was the boundary. §0 is new,
normative, and at the top: the machine owns the EC lifecycle and every
state change that moves an EC on, off, or between cores, and the
deliverable is §6's invariants making §2.6's eight legacy signals
provably redundant. Everything else is named OUT with a reason so it
cannot be re-opened as an omission.

- **§0 added** — IN scope, OUT of scope with reasons, and the three
  BORDERLINE cases resolved explicitly. All three resolve to LESS
  machinery than earlier revisions proposed: `restart_at_entry` is one
  edge (claim by the state's normal route, frame reset under the won
  claim, edge 6, one T2 row); **domain-wide pause needs no design of its
  own** — the movement it causes is N applications of the existing
  suspend edge, and revision 11's "architecturally larger than restart"
  assessment was about the primitive, not about the part this machine
  owns; `restrict`/`revoke` wakes ride edge 5a's existing
  close-propagation trigger, no new edge.
- **§3.5's chain project RETRACTED, and with it §11.10's blocker.**
  Revisions 10–12 turned a refuted chain into a blocker gating §8.1,
  §8.2, §8.5 and six migration steps on a lockdep group design nobody
  had asked for. That escalation was the error. Cross-class lock
  ordering is out of scope: the kernel uses **address-ordered
  same-class nesting under a named group**, **no static cross-class
  order** (lockdep detects cycles dynamically from its pair registry,
  with `EcGen → CoreLock` the one pinned edge retire needs), and
  **drop-and-retry** for reach-and-validate — compute, lock,
  re-validate, retry — which never holds two classes at once and was
  therefore never blocked. The residual risk is stated honestly:
  dynamic detection is strictly weaker than a proven order and finds a
  cycle only when an execution traverses one. **That is the risk the
  kernel already runs on every lock it has.** One real item survives as
  a tree defect, not a design question: `EC_NESTED_GROUP` is named in a
  comment and defined nowhere (bead `stygia-d0q`).
- **§0.4 + `<<< IMPLEMENTABLE SPEC >>>` markers** delimit what an
  implementer codes against (§2–§8) from what is context (§0, §1, §9's
  enforcement notes, §10–§13). §3 is inside the markers deliberately and
  the deviation is named: §5's edge table cites it normatively at nearly
  every row.
- **Round-11 C-1 FIXED** (in scope — it is a lost-wake-class defect and
  squarely the problem this document exists to solve): finalize writes
  `directive_state → dead` and then zeroes the slot in the same routine,
  converting `dead` back to `none`, so a preempted suspender returns
  SUCCESS for a TERMINATED target. Two-part disambiguator — the port's
  gen AND the **target's** gen, gen-stale ⇒ E_TERM. §3.4 gains its
  **fifth** writer row (the slot zero itself, plus creation's publish
  into a recycled slot). **Modelled** with a ghost delivered-bit,
  contrary to revision 11's ledger claim that it was not checkable:
  historically `dirf6` fired and `dirf6fix` was clean; after dpin,
  `dirf6` is an expected-clean stale-gate closure because the directive
  waiter pins the target through ack/return, and both halves of the
  disambiguator remain modelled (`pok`, `gen`).
- **Round-11 C-2 FIXED**: the pin class re-derived against HEAD. Both
  named members are `lockIrqSave` at every acquire and were converted in
  commit `f1215bbf5`; the doc's line numbers were stale. **The class is
  EMPTY at HEAD** — **and that conclusion was itself wrong; see revision
  14, which corrects it: the two NAMED classes leave the set, but the
  gen-lock classes are in it via plain `SlabRef.lock()`, so §5.2's
  ready×K stays on the two-arm dichotomy.** `pin_depth` stays
  load-bearing regardless because it counts CLAIMS.
- **Round-11 M-3**: `InvNoForeignDisarm` is analytically vacuous under
  `DIR_OWNED = TRUE` — stated plainly, with the falsifier named as the
  whole of that gate's content and a reachability probe (`pr5`) proving
  the drop/disarm path is exercised.
- **Round-11 M-0**: five sites still prescribed the refuted epoch,
  including the bolded lead-in an implementer reads as the rule. Fixed.
- **DEFERRED, explicitly, as outside §0's boundary**: the analyzer
  inversion cost and §9.4's masking decision (§11.11, recorded not
  worked), §12's step ordering, the domain-pause design, `persist`,
  `revoke`/`restrict` cascade mechanics, `power_sleep`, the three-class
  lock cycle (retracted with the chain project), and README/changelog
  bookkeeping beyond keeping the results accurate.

**Revision 12 (2026-08-02)** — closes review round 11 (C-1, C-2, nine
majors). The enumerations all held this round — T1–T4 and §8.1's routing
were independently re-derived and found complete. **What failed was the
PARITY DIFF, and it is the diff that would have caught C-1.**

- **C-1 (the W5 break returns SUCCESS for a TERMINATED target, because
  finalize's own `slot zero` destroys F6's `dead` marker)**: §5 edge 10
  and §8.2 order the release body to write `directive_state → dead` and
  then `slot zero + freelist` *a few steps later in the same routine* —
  and `none` must be the all-zeroes encoding or a recycled slot is
  permanently unsuspendable (round-9 C-1). So the zero converts `dead`
  back to `none`, and a suspender preempted across a terminate reads
  `none`, re-validates the port (alive), and returns SUCCESS where the
  correct return is E_TERM. Round-4 F6 re-opened by a later step of its
  own edge-10 row. **Fix: the break disambiguator is TWO-PART** — the
  port's gen AND the **target's `SlabRef` gen**, gen-stale ⇒ E_TERM.
  §3.4's row gains its **fifth** writer (the slot zero itself, plus
  creation's publish into a recycled slot) — the same row was short in
  round 9 for the same reason.
  **Why the model missed it, which is the finding that matters:** the
  model kept `dir = "dead"` on freed ECs forever, so a suspender always
  read `dead` → E_TERM — **the model was strictly SAFER than the design
  at exactly the point the design was wrong**, and revision 11's ledger
  entry ("not model-checkable — no port") did not cover it because the
  port is irrelevant to this arm. Now modelled: finalize writes `none`
  and flips a slab gen, the suspender snapshots the target's gen at arm,
  ghost `dfs` catches a false SUCCESS, `DIR_GENCHK` is the switch,
  `dirf6` historically fired, and `dirf6fix` is clean. After dpin,
  `dirf6` is an expected-clean stale-gate closure because the directive
  waiter pins the target through ack/return. **Both halves of the
  disambiguator are now modelled** (`pok` for the port, `gen` for the
  target), so revision 11's un-model-checkable claim is retracted
  outright, and §9.2 carries them as NAMED SNAPSHOTS
  (`armed_port_ref.gen`, `armed_target_ref.gen`) rather than prose.
- **C-2 (§2.4's evidence is stale and its third clause has a
  counterexample in both of its own named members)**: §2.4 stated as
  fact that `SlabAllocator.lock` and the kstack `freelist_lock` are
  "plain `lock()`". **At HEAD every acquire in both is `lockIrqSave`**
  (`secure_slab.zig:507,669,718`; `stack.zig:185,204,234`), both carry
  in-tree comments reading *"Always taken with `lockIrqSave`, never
  plain `lock`"*, and they were converted in commit `f1215bbf5` —
  *"mask IRQs at every acquire of four IRQ-reachable lock classes"* —
  after lockdep caught the hazard live. **The tree fixed this before the
  document noticed.** Re-derived: under §2.4's own computed rule neither
  is a pin class today, and under revision 11's third clause neither may
  ever be (both are IRQ-reachable). **The pin class is EMPTY at HEAD.**
  Stated as a finding, with what it does and does not invalidate: §5.2's
  ready×K justification gets STRONGER (the masking arm alone discharges
  it), `pin_depth` remains fully load-bearing because it counts CLAIMS
  and X1 is a claim defect, and the third clause plus C1's ordering rule
  are retained as standing rules over a currently-empty set — which is
  precisely why F3 made membership computed rather than named.
- **M-0**: §2.5's bolded break-analysis lead-in still prescribed the
  EPOCH that TLC refuted, forty-four lines above the proof — the second
  revision running in which that bullet, which reads like the loop body,
  prescribed something the section below disproves. Fixed at all five
  sites.
- **M-1/M-2/M-7**: the (c)/(c2) inversion catches NEITHER hazard site
  (both are already `lockIrqSave` at the Zig level; the hazard is
  entirely in asm), the real unnamed cost is resolving a `%gs`-relative
  operand to a named lock class, "masking at fault entry" is already
  true on both arches, and the inversion flips the documented blind
  spots from fail-safe to **fail-open**. All three now live in a real
  §11 item (§11.11) instead of §11.4, which is Remote-suspend
  semantics and covered none of it. **Recommendation recorded: keep the
  inversion but make unresolved reachability fail CLOSED.**
- **M-3**: `InvNoForeignDisarm` is **analytically vacuous** under
  `DIR_OWNED = TRUE` — the disarm guard forces `dsrc = u`, so the
  ghost's update term is identically FALSE. Stated plainly, with the
  falsifier named as the whole of that gate's content, plus a new
  reachability probe (`pr5`) proving the drop/disarm path is exercised.
  `diraba`/`dirabafix` also moved off `TERM_BUDGET = 0, CR_BUDGET = 0`,
  where the mechanism's premise was true by construction.
- **M-4/M-5**: the README's results were from a superseded module and
  its "Honest confidence" section claimed a `cr1fullself` PASS that the
  results table in the same file contradicted; and §11.9's retracted
  sentence **survived verbatim** in the README section that carries the
  walk — the one place it could still stop a reader looking. Both fixed.
- **M-6**: §12 landed neither arm ownership nor §9.4's suspend-path
  mask, while step 4c adds the enable that makes the unmasked `xchgl`
  spin self-deadlockable — with steps 5/6/7 each riding an N=100 pass.
  Both now have steps.
- **M-8**: parity table updated for revision 11's constructs, including
  two real divergences it should have caught (`owner_slot` written at
  the ARM in the doc and at the CLAIM in the model; separate field
  rather than packed, so the u24 narrowing is unmodelled).
- **M-9**: a **three-class lock cycle** assembles from three normative
  edges (`CDGen → EcGen`, `EcGen → CoreLock`, `CoreLock → CDGen`) while
  §5.3 certifies acyclicity over a class set §3.5 calls MISSING
  ENTIRELY. §8.5, §8.2 and migration step 7 join the blocked list.
- Minors: §9.2 said "directive cleared" where edge 10 says `→ dead` (an
  implementer writing from §9.2 codes F6's bug); the status header's
  review history gained round 10.

**Revision 11 (2026-08-01)** — closes review round 10 (C-A, C-B, C-D,
majors). **Scope note: this revision fixes what is already covered and
deliberately starts NO scope expansion.** Restart (§11.9) and the
domain-pause primitive each get their own revision, per the maintainer's
decision; nothing is scoped out.

- **C-A (the new IRQ rule had no re-entrancy arm, making two fast-path
  locks self-deadlockable)**: §2.4's dichotomy is a *preemption* rule —
  `pin_depth` stops the tick dispatching away and does nothing to stop
  the interrupt running on this stack and taking the same lock. That
  distinction did not exist while EC context was ambiently masked; §3.3
  created it and revision 10 constrained it nowhere. Verified in the
  tree: `port.timed_recv_lock` is spun on by raw asm on the suspend fast
  path (`interrupts.zig:1379-1385`) with **no `cli` on that path** — the
  file's only `cli` is at `:2247`, on reply — while
  `expireTimedRecvWaiters` takes it from the tick; and `core_locks[i]`
  is taken by raw `xchgl` at `:2273` and from IRQ by `enqueueOnCore`,
  with the comment at `:2237-2245` recording that hazard **locally and
  generalising it nowhere**. §2.4 gains a **third normative clause: no
  pin-class lock may have an interrupt-context acquire site**; §3.6 W1's
  acyclicity column is rewritten (it read "holder is IRQ-masked", false
  for the pin class *by definition*); §9.4 is named a masked window with
  its cost stated (a `cli`/`sti` pair on the one path whose whole
  justification is cycle count); 9.3(7) gains the check.
  **§2.5's "check 6 must learn the pin-counted arm" is WITHDRAWN** — it
  told the one analyzer that demands a mask to stand down in the very
  revision that created the hazard. Rules (c)/(c2) flip to *forbidding*
  unmasked EC-context acquires on IRQ-reachable classes, which needs
  `trap_sync` promoted (or fault entry masked) and an IF-state model in
  `asm_analyzer.zig`, since both hazard sites are raw asm. Stated as
  real work, not implied.
- **C-B (§12 step 4 ordered the enable against the pin gate and nothing
  else)**: two things need the entry mask for CORRECTNESS —
  `pending_kstack_release`'s single-producer assert, and `destroyPhase2`,
  whose in-tree measurement records **1354 of 6228 phase-2 destroys
  (22%) never reaching the end of the caller-EC reap, orphaning 192 ECs
  by pass ~14**, with the structural fix at step 6. Step 4 now has a
  normative internal order: deletions first, then either the teardown
  move is pulled ahead of the enable or step 4 carries a temporary mask
  over `destroyPhase2`, then the enable and the pin gate.
- **C-D + M-A (one change): deleting `dropped` created an ABA.**
  Exclusivity holds only while the word is non-`none`, and the C-1 fix
  makes the owner write `armed → none` for both consumption and a drop.
  Two failures, in a window a full quantum wide: the `claiming` arm
  still reported **unconditional SUCCESS** (it is defined as a proxy for
  having passed through `none`, so it inherited exactly the ambiguity
  C-1 repaired), and the fresh-`armed` arm let a suspender **disarm a
  third party's directive**. Revision 10 also carried a flat internal
  contradiction — the break-analysis bullet, which reads like the loop
  body, said `none` ⇒ success with no re-validation twelve lines above
  the text requiring it. The resolution attaches to **the word no longer
  being MY arm**, not to any value: `directive_state` becomes
  `{ state: u8, owner_slot: u24 }`, the disarm CAS is on `(armed, me)`,
  and the loop breaks on ownership. **Identity rather than an epoch is a
  MODEL RESULT**: an epoch was specified first, and TLC showed a bounded
  epoch is itself an ABA (wrapped in four `drop → claim → arm` bumps);
  an 8-bit epoch wraps in 256 while the W5 spinner has no bound at all.
  Modelled: `DirDrop` (the stale-port arm the model never had — there is
  no port or gen in the module, so the whole family was unreachable),
  `dsrc`-gated break and disarm, ghost `dbad`, invariant
  `InvNoForeignDisarm`, falsifier `diraba`, fix-check `dirabafix`.
- **M-B**: §8.1 still mandated the refuted order at the point of use,
  citing "the order `futex.wake` already uses" — the very claim §3.5
  retracted. The step is now marked BLOCKED at the point of use, with
  the orders recorded as candidates; and the header now actually says
  C-2 is DEFERRED behind §11.10 (revision 10's changelog claimed it did
  and it did not).
- **M-C**: §11.10's blocker was under-scoped to §8.1. It also governs
  finalize's leading unwind (steps 2–3), retire of a `waiting` target —
  whose `EcGen → Container` nesting is a **live AB-BA against
  `priority`** — and the suspender's disarm re-dispatch.
- **M-D**: added `ProbeNoTermSuspendCycle`. `t1full`'s LiveTerm PASS was
  billed as machine-checking the W3→W5→W3 cycle and would have been
  vacuous if the configuration were never reached; the probe fires, so
  it is not.
- **M-E**: §12 now lands round-8 C-1's W3 exits (step 5) — the fix for a
  deadlock live in the tree appeared in no migration step — and requires
  9.3(7) no later than step 4, which ships the gate that depends on it.
- **M-F**: §2.2's fourth writer is safe by FIELD DISJOINTNESS, now
  stated, with the consequence that 9.3(1) must pin writers per field.
- **M-G**: T4 gains `terminate`'s handle deref and the teardown walk.
- **Retracted immediately (§11.9)**: revision 10's "that walk surfaces
  restart and nothing else new" was false and was the kind of false that
  stops the next reviewer looking. Six further gaps are now listed,
  including a **domain-pause primitive architecturally larger than
  restart and not additive**.
- Minors: the `mark_state` collapse finished in §2.4's declaration
  comment and §2.6; README de-staled (`mst` → `mo`, G10's §11.9 → §11.10,
  the confidence section); two orphan configs deleted.

**Revision 10 (2026-08-01)** — closes review round 9 (C-1–C-5 + majors).
**The first revision that changes NO mechanism**: all five criticals were
text or apparatus, and the one that looked like a machine change —
deleting the directive word's `dropped` value — turned out to be doc-only,
because `dropped` was never modelled. `ECLifecycle.tla` is unchanged, so
no model verdict went stale and the revision-9 battery carries over
intact. That is a first for this artifact and worth naming: the
mechanisms have stopped moving, and what was still wrong was what the
document SAID and what its tooling actually RAN.

- **C-1 (`dropped` had no clearing rule; fixed by DELETION)**: rev 9's
  fourth directive terminal was modelled on `dead`, but `dead` is written
  by finalize on an EC being freed, so "never cleared" is correct there
  and was inherited without its justification. On a live EC one
  stale-port drop left every future suspender's `none → claiming` CAS
  failing forever — the EC **permanently unsuspendable**, hence
  permanently undebuggable, by ordinary means (arm, destroy the port,
  let the target reach its boundary). §2.5 now has the owner CAS
  `armed → none` exactly as in the consumed case, with the **suspender
  re-validating the port gen itself** after observing `none` — sound
  because claim/arm exclusivity means at most one suspender per target.
  Deleting the value also removed the stuck state, the missing §3.4
  writer row, a new model action, and an unlicensed error code (M-6).
  Same word, same round: §2.5's declaration comment was missing BOTH
  `suspending` and `dropped`, and §3.4's row — which S2 and analyzer
  9.3(1) pin writers from — named two of its **four** writer contexts.
  Both enumerated in full.
- **C-2 (`run.sh` could not exit 0, and `mterm` was in no runnable
  script)**: the script was a rev-8 artifact invoking eight deleted
  configs, so it returned non-zero unconditionally, and it ran NONE of
  the round-7/8 falsifiers — every published verdict had come from
  invocations outside it while `README.md` claimed it "reproduces every
  check". Critical by this document's own claim discipline, which is
  then unsatisfiable. Concretely `TERM_ESCAPE` was ungated: a revision
  dropping the retired-terminator escape would have reintroduced C-1's
  two-core deadlock silently. Rewritten against the real config set with
  `mterm` gated on `"Deadlock reached"`.
- **C-3 (two concurrent `priority` calls desync the word from the bucket
  key, permanently and silently)**: no cycle, no mutual relationship,
  both callers need only `spri`. A writes 1, B writes 3, both drop the
  gen lock, B repairs the link to 3, A repairs it to 1 — `ec.priority`
  is 3 and the linked key is 1, forever, because `dequeue` never
  re-reads and a parked waiter has no next link; [test 08] reports 3
  while selection uses 1. Round-8 C-2's defect in its concurrent form.
  Fixed with one clause M-2 had already written for the other word: the
  repaired key is a **fresh read of `ec.priority` taken inside the
  innermost hold**, never the value this call wrote; mirrored for
  `affinity`'s claim-move destination.
- **C-4 (the IRQ state of EC context was never stated, and §12 removed
  the only place it was established)** — the deepest. Twelve normative
  arguments need EC-context frames to be tick-preemptible; the doc
  stated an IRQ state for scheduler context only, and what it did say
  pointed the other way (§3.3's "no kernel code outside `arch/` enables
  interrupts", §12 step 5 deleting the last enable with no step adding
  one). The tree agrees it is masked today: x86-64 `SYSCALL` clears IF
  via `IA32_FMASK`; aarch64's only `daifclr` sites are
  `enableInterrupts` and the park primitives. Following §12 literally
  left FEWER enable windows than exist today, and every dependent gate
  — rule 1, the C1 ordering rule, `pinord`'s relevance, T2's ready×K
  cell, all three preemptible-spin columns — would have gone vacuous
  **with the battery fully green**, because the model grants
  preemptibility by construction. §3.3 now states the rule normatively,
  §9.2 asserts IRQs-enabled at spin entry (not just `pin_depth == 0`),
  and §12 step 4 ADDS the entry-path enable in the same step as the pin
  gate.
- **C-5 (domain restart absent, and the DERIVATION METHOD is why)**:
  `grep -ni restart` returned zero while §[restart_semantics] is
  normative and per-EC. `restart_at_entry` has no edge — forcing an EC
  runnable with its frame reset to the entry point is not edge 6, not 7,
  not a claim-move — and `persist` keeps an EC running while its
  domain's VMARs are freed, colliding with `active_root`/W6. The
  instructive half is the method: the sufficiency table was derived by
  walking the spec's SYSCALL list, and §[restart_semantics] is not a
  syscall section. §11.9 carries my read (in scope, needs a new edge,
  `persist` is the harder half, open it deliberately rather than bolt it
  on); the model README's table is re-derived from the spec's SECTION
  list, which surfaces restart and nothing else new.
- **Majors**: M-1's real `W3 → W5 → W3` cycle (A terminates B while B
  suspends A) is written into §3.6 with its break — which is 100%
  dependent on C-4, and is the worked example of why an unstated premise
  is not a certificate; M-3, the header now says C-2 is DEFERRED behind
  §11.10, not closed; M-4, §2.2's writer list goes to **four** (the
  `priority` re-bucket does write `ec.wait`'s futex nodes); M-7, T2's
  `waiting`×K reason is corrected (§8.3's `.ready` → 5c+7 route reaches
  `waiting` with no park sequence, so the right reason is that every
  route into `waiting` leaves `pin_depth == 0`); M-8/M-9, the
  `mark_state` collapse to one bit finished in the five remaining
  places, and the README de-staled.
- Simplicity: `dropped` deleted; `crsafeself.cfg` deleted (byte-identical
  CONSTANTS to `small`, a strict subset of its invariants, same 181,326
  states); `run.sh`'s dead block deleted.

**Revision 9 (2026-08-01)** — closes review round 8 (C-1–C-3 + eight
majors). Every critical was a **completeness failure of an enumeration
revision 8 itself wrote**: §3.6's starvable shapes (the fifth class was
W3, not W5), §8.1's state list (`parking(wait)` is already linked), and
§3.5's lock classes (the left edge is refuted and a fourth class was
missing). That is the fourth round with this signature, so every
enumeration in this revision now carries an explicit
**DERIVED**/**RECALLED** marker.

- **C-1 (CRITICAL — mutual terminate deadlocks two cores; live in the
  tree, bead `stygia-noi`)**: A and B each hold a `term` handle to the
  other and both are running. A retires B, B retires A, and both enter
  the W3 eviction wait for the other. A `retired` EC in a kernel frame
  is moved by NOTHING — the requeue CAS fails on `retired` and rule 3's
  entry checks are user-boundary-gated. **TLC reports a plain deadlock
  in 7 states**, not merely an L2/L5 violation. The tree guards
  `if (ec != caller ...)` (`execution_context.zig:1028`) which covers
  SELF-terminate only; both cores pass it. Revision 8 had no carve-out
  anywhere in W3/L5/T2, so **the tree was safer than the design**.
  Rev 9 adds both exits to §3.6 W3 and §6.2 L5: the self carve-out, and
  a retired terminator abandoning the wait. The model's `Terminate` is
  split into `TermStart`/`TermRetire` so the caller's own mid-syscall
  retirement is expressible at all, self-terminate is now modelled (rev
  8 excluded it citing §8.2 — a WRONG citation: §8.2 is
  `delete(SLOT_SELF)` on a capability DOMAIN, and §[terminate] licenses
  no error for a self target), and `mterm` is a permanent falsifier.
- **C-2 (CRITICAL — the priority fix re-opened in `parking`)**: §8.1
  routed `parking` with the word-alone states. False for
  `parking(wait)`: §2.1's containment table says its wait containers are
  already linked, §3.2 step 2 puts the links inside the publish section,
  and edge 4 relinks nothing — so it reaches `waiting` carrying the
  stale bucket key and keeps it for the whole episode, in a window §2.1
  calls traversed thousands of times per boot. `parking(wait)` now
  routes with `waiting`; the re-validation state set widens to
  `{parking(wait), waiting}`; `parking(requeue)` keeps word-alone, and
  the reason each remaining state is safe is now written per state
  rather than asserted collectively.
- **C-3 (CRITICAL — §3.5's lock chain is refuted)**: rev 8 asserted
  `wait-container < EC gen < core locks` as derived fact. The right edge
  is sound; the LEFT edge is false — `port.zig:463-465` states the
  tree's canonical order as **EC → Port**, and `futex.wake` traverses
  the EC/bucket pair in both directions, made safe by an ascending-index
  discipline and a group opt-out rather than by any chain. The CD
  gen-lock class was missing entirely and §8.5 contradicts the chain's
  shape. §3.5 now retracts the claim in place, keeps only the verified
  edge, and §11.10 records that **§8.1's reach protocol cannot be
  implemented until a lockdep group design exists** — this is a blocker,
  not a preference. **Claim-discipline note (round-9 M-3): C-2 is
  therefore DEFERRED BEHIND §11.10, not closed.** The `parking(wait)`
  routing rule is correct and written, but nothing in §8.1 can be
  implemented until the lock order is settled — a reader must not read
  C-2 as a shipped fix.
- **M-1**: doc and model disagreed on when the self-mark is taken — the
  model marked unconditionally, before a target was even chosen, giving
  a strictly wider E_BUSY contract than §2.5 scopes or §11.8 describes.
  The model now marks only on the directive path, with the target
  resolved and observed `running`, and re-validates at CAS 2.
- **M-2**: §11.8 rewritten — self-suspend explicitly excluded (it
  collided with §[suspend]'s existing self text), **both** racing calls
  may legitimately return E_BUSY so [test 13] must not assert
  exactly-one, a naive retry loop can livelock so the Description now
  requires backoff, and the shift in E_BUSY's meaning from describing
  the target to describing the caller is flagged for the error table.
- **M-3**: §2.5's stale-port drop arm left the directive word's fate
  unstated and both readings are wrong — leaving it `armed` spins the
  suspender forever, clearing it to `none` reports SUCCESS for a
  suspension that never happened. Rev 9 added a `dropped` terminal;
  **revision 10 deletes it again** (round-9 C-1) — see below.
- Simplicity: the staged destination is deleted from `ec.wait` outright
  (M-2 removed its only authoritative consumer, leaving a
  cross-core-readable field with no §3.4 row); `mark_state` collapses
  from a tri-state to **one bit**; seven dead `c1*`/`"pair"`-liveness
  configs dropped.

**Revision 8 (2026-08-01)** — closes review round 7 (C1, C2, M-1–M-6 +
minors). Carried semantic deltas and DELETED more than it added (the
staged destination as placement authority, one of two priority
mechanisms, the model's `dst` field and `mo`/`mk` pair), shrinking the
safety state spaces 39–87%.

- **C3 (suspend cycles — REJECTED, not survived; §2.5.1, and the
  largest change in revision 8)**: every directive-path liveness
  finding this project has produced (N1's deadlock, N6's livelock) is
  the same shape — symmetric suspend. Rather than surviving it by
  assumption, revision 8 makes it unreachable. Two mechanisms are
  modelled: **(A)** the maintainer's pair-locked check (both EC gen
  locks, lowest slot first, reject if the target is already suspending
  the caller) and **(B)** the recommended self-mark (the suspender CASes
  its OWN word `none → suspending` before claiming the target's; a
  `suspending` word is not claimable). Both retire **both N6
  assumptions** — `LiveSuspender` holds with neither `SF(DirArm)` nor
  the alignment premise, and the same rung that took 2min03s under the
  premise takes 13–18s without it. (B) is recommended on two measured
  grounds: (A)'s slot-index order is an AB-BA against the x86-64
  fast-suspend path's existing role-ordered EC-gen-lock nesting (which
  additionally claims a lockdep group constant that **does not exist**),
  and (A) is pairwise so it does not close 3-cycles — the model reaches
  one in 14 states, where (B) holds across **6,179,060** (`cr3self`,
  revision 15; was 109,626 at revision 11). Proposed
  `specv3.md` §[suspend] text and test in §11.8; **`specv3.md` is not
  edited by this document.**
- **C1 (CRITICAL — `pin_depth`'s ORDER against the acquire was
  unspecified, and the default reading re-opens F3)**: §2.4 gains the
  normative ordering rule — the increment precedes acquisition of the
  protected thing (before a pin-class `lock()`; *inside* the IRQ-masked
  reaching-lock section for a claim), the decrement follows its release
  or discharge — plus the §9.2 bracket asserts. Rev 7's sentence
  ("incremented at claim-win and pin-class acquire") permitted
  `lock(); pin_depth += 1;`, and pin-class locks are by definition
  *not* IRQ-masked at their EC-context acquire sites, so a tick lands
  in the gap, reads `pin_depth == 0`, and requeue-preempts a
  slab-lock-holding frame — after which other allocators spin
  IRQ-masked on a lock whose holder sits `ready`, and T2's ready×K row
  inline-retires it on an argument the window falsifies. Model: new
  `PIN_BUMP_FIRST` switch and the `pinord` falsifier — with the order
  dialed out, `InvNoPreemptedLockHolder` (T2's ready×K justification
  as an invariant) fires in four states. The claim-side half is
  explicitly NOT model-checked and says so (a claim CAS sits inside a
  section this model makes atomic).
- **C2 (CRITICAL — the doc contradicted `specv3.md`)**: rev 7's §8.1
  said a priority edit of a non-`ready` target "takes effect at its
  next placement"; §[priority] says the opposite verbatim for a target
  suspended on a port or waiting on a futex, and [test 06]/[test 07]
  test it at *selection*. Since selection is bucket-position-determined
  (`EcQueue.enqueue` keys at link time, `dequeue` never re-reads;
  futex `WaitNode`s snapshot at park), "next placement" was not late
  but never. §8.1 now mandates re-bucketing every linked wait node
  under its container lock, with the sorted all-buckets discipline for
  multi-bucket futex waits. The doc was the bug; the spec was not
  touched.
- **M-1 (the "fourth descriptor writer")**: resolved by DELETION, not
  machinery — `priority`/`affinity` are stable per-EC words, not
  `ec.wait` fields (a `running` EC has both), so §2.2's writer
  enumeration was already complete. They get §3.4 rows with named
  writers (so 9.3(1)/S2 has something to pin) and one shared
  reach-and-validate protocol with an explicit no-retry rule.
  Writing that protocol surfaced a second, latent gap: rev 7 named only
  the EcGen → CoreLock pair, which is not enough to say how a
  ref-reached party reaches a *wait* container — and the obvious
  reading (gen lock, then bucket lock) is an AB-BA against
  `futex.wake`'s Bucket → EcGen (`futex.zig`, verified). §3.5 now
  states the full chain **wait-container locks < EC `_gen_lock` < core
  locks**, from which both previously-named edges fall out, plus the
  two consequences it forces: the reach takes container-then-gen for a
  wait container and gen-then-queue for the run queue (not an
  inconsistency — it is the chain's shape), and finalize's leading
  unwind must NOT hold the gen lock across its container locks.
- **M-2 (staged destination vs fresh descriptor)**: §4 said the pended
  arm honors the staged destination, §8.1 said the discharger reads the
  fresh descriptor. Resolved by deleting the staged destination as
  placement authority: every placement computes from the fresh
  descriptor under the destination queue lock, and a staged core is a
  locality hint. Erases the model's ghost G2 and its `dst` field.
- **M-3 (the deferred-marking fact had no word)**: §2.4 gains
  `mark_state` (one bit after round 8's collapse) with its §3.4 row, its writers,
  and the acquire/release pairing W4's bound had assumed silently. The
  model's private `mo`/`mk` pair collapses into it.
- **M-4 (`yieldTo` target side underdetermined)**: §8.1 codifies
  local-only + S7 + affinity-mask (the mask check is new; the tree
  lacks it), with the spec narrowing for remote-queued targets named
  as §11.12 rather than hidden.
- **M-5 (the N5 fix existed only as a consequence)**: §3.1 rule 3 and
  §5's edge-3 row now state the precedence as a RULE — on any entry
  from user mode the entry checks run first, so a tick on an unpinned
  user-mode armed EC consumes rather than requeues — with a §9.2
  assert at the requeue claim site, because an implementer who wires
  the checks into syscall entry only reintroduces N5 with the battery
  still green.
- **M-6 (edge 5c's trigger closure)**: gains the rev-7 affinity
  claim-move, and records why `priority` is NOT a 5c trigger (same
  container ⇒ in-lock relink; different container ⇒ claim-move).
- Minors: §2.5's "bounded" W5 wait corrected (it terminates under
  stated assumptions, which is not a bound); §3.6's assumption set
  corrected from two to three (the no-interrupt-storm premise that
  SF-over-WF carries); §3.6's diagnostics carve-out gains the
  `power_*` syscall family; T4's futex row citation made precise and
  VERIFIED against the tree (the re-enqueue of non-matching nodes is
  real, `futex.zig:249,255,364`); T4's port-queue, run-queue and futex
  rows gain the new re-bucket sites; §11.7's case for the bounded W5
  wait rewritten from the round-7 measurements.

**Revision 7 (2026-07-31)** — closes review round 6 (M1–M6 + minors; no
criticals — every rev-6 mechanism survived constructed-interleaving
attack). Text/assert-level only; the machine's states, edges, and
mechanisms are unchanged from rev 6, so the rev-6 model verdicts carry
over except where the README schedules re-runs.

- **M1 (park-publish CAS failure arm was unspecified)**: every §3.2
  publish now orders the `parking` CAS BEFORE the links inside its
  container-lock section (intra-section order is unobservable, so this
  is free) and specifies the failure arm: retire won since staging ⇒
  link nothing, proceed as outgoing-`retired`. §9.2 asserts the order.
  Recorded: under rev 6's N4 mechanism links-first would ALSO have been
  correct (idempotent finalize unwind + stale skip) — under rev 5 it was
  a bug; CAS-first removes the question. Model: the fused publish action
  is exactly faithful (its state guard IS the CAS; no change needed).
- **M2 (enforcement text was partly fictional)**: §2.5's
  enforcement-honesty paragraph rewritten to verified tree reality —
  what exists (check_gen_lock with repaired IRQ pass and check 6's
  mask-everywhere arm; check_ec_closure Rule A/Rule B, REPORT-ONLY, not
  in precommit) with four named blind spots (no spin-inventory detection
  anywhere; Rule B's GenLock/SlabRef UNRESOLVED; `[unreachable]`
  contexts unproven; `tlbShootdownHandler` unresolved in both tools so
  W9 paths are unchecked-not-clean); 9.3(6) marked future in its
  entirety, 9.3(7) marked partially-real; §5.1's "maintained by
  tooling" corrected to requirement-not-capability; the check-6 vs
  F3 pin-counted-arm tension recorded.
- **M3 (retired-but-linked licence rested on a recall universal)**: new
  closure table **T4 (§5.3)** — every pop/scan/iterate site over every
  wait container kind, each row confirming lock-held deref +
  claim-CAS-or-skip, every row marked RECALL-derived (the marking is
  the finding; tool derivation is 9.3(6) future work). Reply pin
  specified as ref-reached (holder-CD lock + EC gen validation;
  dead-gen holder domain ⇒ teardown owns the slot, unwind skips
  idempotently); idle slot given its row; dual membership (timed
  waiter: container + deadline table; futex waiter: multiple buckets)
  stated with the unwind obligated to visit every named container.
- **M4 (API sufficiency)**: edge 3's trigger closure gains plain
  `yield` and the `yieldTo` caller's requeue park; edge 5a gains
  `vm_inject_irq` waking a wfi-parked vCPU (5b if racing the park);
  §8.1 gains the `affinity` (bead `stygia-me9`) and `priority` (bead
  `stygia-va7`) routing rules — both are descriptor data consumed at
  placement, with ready-target edits as claim-moves under the queue
  lock, and the priority defect corrected from the review's "ordering
  corruption" to the real shape: silently deferred re-bucketing.
- **M5 (suspend state gate cites an undefined error)**: specv3
  §[suspend]'s E_INVAL causes do not cover futex/recv/reply-blocked
  targets; the doc no longer cites that error as existing and §11.4
  now records the spec/doc disagreement for the maintainer (bead
  `stygia-uyd`).
- **M6 (claim discipline)**: the header's "green" claim is now gated on
  a full `run.sh` exit-0 against the exact text; PENDING coverage rows
  mean pending.
- **N5 + N6 (two further starvation classes, found by the liveness
  battery after this revision opened — folded in here since rev 7 is the
  open working revision)**: N5 — the model wrongly treated rule-3
  boundary consumption as optional; a pin-duty-cycling target starved
  the suspender; closed as model infidelity (the tick IS an entry from
  user mode; consumption rides the periodic tick, §3.6 W5 row), no doc
  mechanism change. N6 — mutual suspend, half-armed: the suspender's own
  `claiming → armed` continuation is tick-starvable (falsifying N3's
  immunity claim, corrected in place in §3.6) and the disarm arm's
  observation window is cross-core-alignment-starvable; closed BY STATED
  ASSUMPTION (§3.6's generalized assumption set + the model's named
  `AlignmentAssumption`), with the structural alternative (bounded W5
  wait) written up as §11.7 for the maintainer. Meta-lesson recorded in
  §3.6: three starvation classes from three runs ⇒ the starvable-site
  enumeration was recall-closed.
- Minors: `owner_core` validity narrowed (claimed-origin retirees have
  none — T2 consistency); G6 stated on the device row (masked line
  after suspend/retire of the acker is by design, userspace owns it);
  model-side stale comments and headers scheduled with the README's
  re-run list.
- **Round-6 addenda (measurement-driven, folded into the open working
  revision)**: the §3.2 edge-4 paragraph (the link precedes the hop;
  CLAIMABILITY does not — answered from this text against the Phase-3b
  barrier measurement, with the model's e4 falsifier as its teeth:
  publish-claimable-before-hop violates S3 in 3 states); the `pended`
  zero-fire justification (§2.1 — timing zero, not structure; the
  alternatives are the falsified release-wait/decline); §9.4's measured
  fused-placement accounting (`stygia-qde`; both fused shapes now
  encoded as ideal compositions, `FastPath` + `ReplyFP`, which the
  model shows reach ZERO states the slow paths cannot — the "declared
  compositions of rows" claim, machine-checked); the M4 affinity
  claim-move encoded (`AffMove`); and the LiveSuspender checkability
  profile (the alignment premise is provably outside WF/SF's fast
  path; verdicts are laddered per-scope with hard timeouts — README —
  standing evidence in §11.7's favor).

**Revision 6 (2026-07-31)** — closes the model round (round 5: the TLA+
model at `docs/kernel/tla/`, findings N1–N4 + enumeration repairs), and
is co-evolved with that model: the battery is green against this text
with the real mechanisms and no model-invented fences, and every
falsifier (X1–X3 dialed to rev 3; F1's two readings dialed to rev 4; N4
with the unwind mechanism dialed out) still fails. Governing criterion:
the simplest machine that is correct and sufficient for the syscall
API — this revision REMOVES a step (below) as well as adding text.

- **N4 (unwind/finalize ordering was asserted, never enforced)**: rev 5
  put the container unwind inside retire (step 3) and listed "unwind
  complete" as a finalize precondition, with no mechanism ordering the
  two — TLC exhibits freed-while-linked in 7 states. Mechanism adopted,
  simpler than both review candidates: **retire's unwind step is
  DELETED; the idempotent container unwind is finalize's first act**
  (§8.2, edge 10, §3.5, §2.1 retired row). One unwinder, owned by
  whoever frees; the wait-free retired arm (F1) is preserved; a
  `retired` EC may legally remain linked until its finalize (pop-side
  `stale` skip covers it). The dual-unwinder alternative was rejected
  because the second unwinder must read the EC's descriptor to discover
  it has nothing to do — against a possibly-zeroed slot.
- **N1 (W5's deadlock-freedom is conditional on rule (b))**: §2.5's
  mutual-suspend break holds only for UNPINNED spinners; F3's computed
  pin class (slab, kstack-freelist) makes "suspend while holding a
  pin-class lock" a hard cross-core deadlock, found by the model in
  seconds. Rule (b)'s spin-entry `pin_depth == 0` assert is now
  normative (§2.5, §3.6, §9.2); enforcement today is runtime
  (assert + lockdep) — statically checking spin-entry pin-freedom is
  recorded as a future 9.3(6b) obligation, not claimed as a current
  analyzer capability (§2.5).
- **N3 (W3/W4/W5 bounds carry a scheduling assumption)**: stated in
  §3.6 — one recheck executes between consecutive preemptions; pinned
  continuations are immune; exactly W3/W4/W5 are starvable in the
  adversarial-alignment limit. The model encodes it as per-spin strong
  fairness.
- **N2**: no doc change (a model-side narrowing, kept in the model's
  ledger as the worked example of literal parity).
- **Enumeration/definition repairs from the model round**: `payload_done`
  cleared by its discharger at placement/finalize (§2.2, G8);
  `claiming → armed` is a CAS whose failure (finalize's `dead`, or a
  recycled slot) returns E_TERM without writing a freed word (§2.5,
  G-D1); the directive reset is atomic with the edge-3 publish (§2.5,
  G-D2); the loop-break analysis covers observing a third party's
  `claiming` (= consumed) (§2.5, G-D3); the rendezvous mint-failure
  receiver arm is 5a-only, 5b delivery unconditional (§8.3, G-RV1).
- **Removals tried against the battery and adopted in the model**
  (state-space, not semantics): the write-only `timed` descriptor mirror
  (the armed one-shot registration already encodes wait flavor) and the
  zero-work pre-hop interleaving step. Removals tried and REJECTED:
  `pended` and the W7 pre-wait cannot go — their falsifiers fire without
  them (X2/X3; F1's two readings). The directive's `claiming`
  intermediate and `dead` terminal are retained on protocol grounds
  (directive_port write exclusivity; F6's retired-vs-consumed
  distinguishability), not battery evidence — the battery carries no
  falsifier for either.
- Deliberately unchanged: everything rev 5 verified — the W7 pre-CAS
  wait, the wait-free retired arm, the pin gate and computed pin class,
  T1, the same-word CAS argument, S8, the §9.4 decisions.

**Revision 5 (2026-07-31)** — closes adversarial review round 4 (F1–F6 +
minors). Round 4's character: every critical was a single wrong condition
or un-computed enumeration inside a correct mechanism, found by the
closure tables exactly where they were tool-closed (T1: flawless under
hostile re-derivation) and not where they were recall-closed (T2/T3: all
three criticals). Fixes are minimal and local; the TLA+ model targets
this revision.

- **F1 (hop's retired arm conditioned on a fact retire destroys)**: the
  `payload_done` wait moves from the hop's retired arm to **retire
  itself** — a retire observing `pended` acquire-waits `payload_done`
  *before* its CAS (edge 9, §8.2 step 1, T3 row W7; legal since no
  retire caller is interrupt context), so every later observer of
  `retired` proceeds without waiting (§4). The `claimed` row needs no
  pre-wait — its discharger learns `retired` from its own failed
  placement CAS (noted in T2).
- **F2 (S7 inline retire inverted the pinned EcGen → CoreLock order)**:
  the dispatcher now CASes `ready → claimed` under the queue lock it
  holds (R-claim-legal), drops the lock, and retires as holder via T2's
  `claimed` row (§3.2, S7, edge 5c).
- **F3 (pin class wrong in both directions)**: membership is computed,
  not named — every lock class with a non-IRQ-saving EC-context acquire
  site is a pin class (analyzer 9.3(7)); `tree_mutex` is out (IRQ-masked
  at every acquire), `SlabAllocator.lock` and the kstack `freelist_lock`
  are in; the normative dichotomy (mask everywhere or pin-count) is what
  discharges T2's ready×K cell (§2.4, T2).
- **F4 (T3 missed two lock-holding production spins)**: rows W8 (FPU
  migrate-flush ack, holding `request_lock`) and W9 (TLB shootdown ack,
  holding `shootdown_lock`); rule (b) restated honestly with the
  ack-while-spinning closure as their acyclicity argument (§3.6, §10).
- **F5 (M-B re-check ran before the wait, once)**: the suspender's
  re-check/disarm is a terminal loop after (and interleaved with) the
  left-`running` wait (§2.5).
- **F6 (disarm-failure conflated consumed with finalized)**: finalize
  sets `directive_state` to a distinct terminal `dead`; the suspender
  maps it to E_TERM (§2.5, §3.4, §8.2).
- Minors: sync exceptions inside IRQ-masked sections stated normatively
  — no user-memory access inside container/gen-lock holds, the boundary
  condition for W1 (§3.3, §3.6 rule (a), 9.3(2)); finalize's context and
  IRQ-safety obligations stated (§8.2, §9.2); diagnostics carve-out for
  panic (§3.6); the `futex_wake` syscall added
  to edge 5a's sources; `suspend` against a `parking`/`pended` target
  specified as an L1-bounded transient (§8.3, §11.4).
- Upheld in round 4 and untouched: T1 (all five rows verified against
  the callgraph DB across both arches), the claim-CAS/hop-CAS same-word
  argument, `pended` uniqueness and owner-guaranteed discharge,
  `payload_done` as SPSC release/acquire, the mutual-suspend break under
  the pin gate, the teardown reorder, S8 anti-resurrection, and the
  §9.4 asm citations.

**Revision 4 (2026-07-31)** — closes adversarial review round 3 (X1–X3,
M-A–M-C, text repairs), and adopts its method finding:

- **Method**: three normative closure tables added — T1 interrupt-context
  wake sources (§5.1), T2 retire matrix (§5.2), T3 wait-for graph
  (§3.6) — with analyzer rule 9.3(6) keeping them closed against the
  callgraph DB. The fixes below were derived from the tables.
- **X1 (requeue-preempted claim holder retired + inline-finalized)**:
  `pin_depth` byte gates requeue preemption (§2.4, §3.1 rule 1) —
  claim-holding frames are never preempted, so both X1 windows are
  unreachable cells in T2; S4/L6's holder-persistence now cites the gate
  instead of falsely citing rule 3.1(3). Generalized to non-IRQ-masked
  locks (`tree_mutex`) so T2's ready×K cell is safely routable.
- **X2 + X3 (interrupt-context 5b: wait deadlocks, decline drops)**: the
  dilemma is dissolved by deleting both horns. All parking-origin claims
  now target **`pended`** (new state): claim + payload + `payload_done`,
  and the **owner core's hop discharges** placement / finalize /
  deferred marking (§2.1, §3.2, §4, edges 5b/6p). Because the claim CAS
  and the hop's commit CAS share the state word, the hop cannot miss a
  pend (no descriptor-flag race, no fences). Deleted outright: the
  interrupt-context release-wait (X2's cycle is unconstructible — §3.6
  rule (a)), the same-core decline rule, and L4's carve-out (no decline
  path exists — one-shot sources in T1 are consumed exactly once, X3).
  The syscall-context release-wait is deleted too — 5b is uniform.
  `device_region.onIrq` and `wheelExpireDue` are enumerated T1 rows.
- **M-A (dead-mark in EC context / S7 silent drop)**: the self-delete
  dead-mark moves behind the hop into scheduler context —
  `teardown_pending` now carries the pre-teardown CD ref and the park
  stack runs phase 1 + phase 2 (§8.2); S7 filter failures retire the
  popped EC inline under the queue lock instead of silently dropping it
  (§3.2, S7).
- **M-B (indefinitely pending directive)**: decided — the suspender
  re-checks after arming and disarms-with-redispatch/error (§2.5,
  §11.4).
- **M-C (L5 marking wait unspecified)**: the wait is W4 in T3 —
  lock-free, preemptible, ack-while-spinning, bounded by discharger
  instructions + scheduling (§L5).
- **Text repairs**: §3.2's false no-cycle certificate replaced by the
  bounded-work rule + T3's global argument; EcGen → CoreLock pinned for
  edge 9 (§3.5); the untimed-rendezvous-sender assumption stated (§2.2,
  §8.3); §10's spin inventory is now T3 by reference; retire routing for
  `claimed` no longer reads `owner_core` (invalid there — §2.4, T2).
- Deliberately unchanged: everything round 3 verified — F1's in-lock FP
  publish (checked against the real asm), F5, F6a, the mailbox
  deletions, the degenerate hop, M2's holder containment, the slow-path
  C1 fix.

**Revision 3 (2026-07-31)** — closed round 2 (F1–F12): FP publish moved
inside the `_gen_lock` hold with a retired-arm CAS and kstack-clean audit
(F1/F7); interrupt-context same-core 5b decline rule (F2 — superseded in
rev 4 by `pended`); user-boundary entry-check gate (F3); deferred
abandoned-marking (F4/F12); saved-frame/descriptor rule split (F5);
CD-locked publish liveness gate (F6a); create-unwind protection restated
(F6b); release-before-commit hop order (F8); two-word directive (F9);
timer wheel classified (F10 — completed in rev 4's T1); release-wait
lock/bound contract (F11 — deleted in rev 4).

**Revision 2 (2026-07-31)** — closed round 1 (C1–C3, M1–M5, m1–m3):
publish-under-lock park sequence; `claimed` holdership + placement CAS +
R-claim; suspend edges + directive protocol; degenerate hop; recv pop as
claim; publish-last creation + `teardown_pending`; FP core lock; idle
slot, boundedness scoping, heartbeat wording, per-EC deadline capacity.
