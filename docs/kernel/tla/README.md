# TLA+ model of the EC-lifecycle machine (model rev 16 / `systems.md` rev 16)

TLC-checked model of the execution-context lifecycle state machine
specified in `docs/kernel/systems.md`. **The transition relation is still
the model revision-15 graph that the recorded exit-0 battery ran
against.** Revision 16 adds artifact coverage (`t1d_min`/`pr4d_min`) and corrects
the scope of `LiveSuspender` for a suspender that is itself externally
parked or killed; it does not add a domain-pause model. The systems-doc
half of revision 16 is doc-only for the model: it states a premise, fixes
which leg of the user boundary one arm is checked on, and records a tree
obligation, all invisible to a model that has no domains and no user
memory. That parity gap is ledger entry **G12**, and G12 is the largest
open one in the artifact.

Revisions 6 through 10 were CO-EVOLVED with this model: model findings
(N1–N6) were fed back into the doc, doc findings back into the model, and
neither artifact is cited without the other. Built from the doc (plus
`systems-review.md` for round-1 history); kernel sources are consulted
only to CHECK a doc claim, never to supply one — rounds 7, 8, 9 and the
round-13 follow-up did exactly that, and **four times the tree
contradicted the design**: round 8's C-1 (the tree's self-terminate
carve-out that the doc lacked), round 8's C-3 (`port.zig` declaring the
opposite lock order to the one the doc had just derived), round 9's C-4
(`IA32_FMASK` masking IRQs on SYSCALL, against a premise the doc never
stated but twelve arguments needed), and revision 16's §11.13 (the
dispatch trampoline writing a resumed EC's user stack after the
address-space swap, against the premise §0.3's domain-pause argument
rests on). **All four were found by reading the tree, none by running
TLC**, which is the standing argument for why a green battery is a floor
and not a ceiling.

**Round 8 in one paragraph, and it is the important one.** Three
criticals, and **all three were completeness failures of enumerations
revision 8 itself wrote**: §3.6's starvable shapes (the fifth class was
W3 — mutual TERMINATE — not W5, and it is a hard deadlock rather than a
starvation), §8.1's state list (`parking(wait)` is already linked, so
the round-7 priority fix re-opened in the one state that matters most),
and §3.5's lock classes (the left edge of the chain is refuted by the
tree, which declares the opposite order outright). C-1 is **live in the
kernel today**. The standing consequence: **every enumeration in this
artifact now carries an explicit DERIVED or RECALLED marker**, and a
RECALLED one is to be read as a defect that has not been found yet.

**Round 7 in one paragraph.** Two criticals that the machine-checked
battery was structurally incapable of finding — C1, an instruction ORDER
one level below the model's atomicity, and C2, a contradiction with a
document the model does not read — plus C3, a maintainer proposal that
replaced an ASSUMPTION with a MECHANISM and, in doing so, removed the one
premise in the artifact that could not be checked at realistic scope. The
round's shape is the lesson: six rounds of findings came from
constructing interleavings; this round's came from reading what the words
permit an implementer to write, from reading the spec next to the design,
and from asking whether a fix generalised.

## Standing methodology: how to make a liveness property checkable

Not a round's fix — **the technique that works on this model**, written
down because it took three revisions to find and will be needed again.

**1. Give each property its own MINIMAL fairness set.** TLC's liveness
check is single-threaded and its cost scales with the number of fairness
constraint INSTANCES it must track at every node of the product graph,
not with graph size. A blanket `SpecFair` forces every property to pay
for every other property's assumptions. The building blocks are defined
in the module (`FairCPU`, `FairUnwind`, `FairTick`, `FairDisp`,
`FairFire`, `FairSpinTerm`, `FairSpinDir`) and composed per property
(`SpecL1`, `SpecL2`, `SpecL3`, `SpecL4`, `SpecL5`, `SpecL6`, `SpecTrm`,
`SpecSus`).

**2. Ladder the scope, smallest first, and record the verdict per rung.**
A verdict at a small scope is worth more than no verdict at a large one,
and the ladder tells you exactly where checkability ends.

**3. Read the resulting verdict as a statement about assumptions.** A
PASS under `SpecTrm` says "this property holds given FairCPU, FairUnwind,
FairDisp, FairTick, FairSpinTerm" — which is a stronger and more useful
claim than a PASS under a set nobody has justified per-property.

**The measurement that establishes this.** `LiveTerm` had NO verdict for
three revisions: rev 7 produced none, rev 8's two attempts were killed
after 73 minutes of pure temporal checking, rev 9's 2c×3e attempt did not
converge in 90. Under `SpecTrm` at a laddered scope it passes in **10,
11 and 13 seconds**. Nothing about the machine changed — only which
constraints TLC was asked to track. Dropping `FairSpinDir` and
`FairFire`, which `LiveTerm` does not need, is the entire difference.

**The limit of the technique, equally standing.** It does not rescue the
2c×3e scope for any property that genuinely needs `FairDisp`, because
that family is `SF(DispatchOrS7(c,e))` and scales as |Cores| × |ECs| — 6
instances at 3 ECs against 4 at 2. `q7` is the demonstration: `LiveTerm`
under its minimal set, at 3 ECs, still did not converge. When a property
needs `FairDisp`, ladder the EC count down rather than the timeout up.

**Standing line, earned three times over: in this protocol, any identity
that can be reconstructed by reuse is not an identity.** Round 10's epoch
(a bounded counter wraps, so a `drop → claim → arm` cycle restores a
suspender's snapshot); round 12's `gen` (one bit, flipped at finalize and
RESET by `CreateEC`, so a recycled slot returned the snapshot value); and
round 12's `DirArm` guard (below), which is the same lesson in the GUARD
rather than in the value. Any new field that a suspender snapshots and
later compares must be checked against reuse before it is trusted.

**And the fourth instance of that line is about THIS ARTIFACT'S OWN
TOOLING, which is why it is written here rather than in a scratch file
(revision 16).** `out/*.log` persist across revisions — TLC overwrites a
config's log only when that config next runs. A watcher built to capture
the revision-15 graph sizes of the four `RUN_SLOW` configs was gated on
"the log file exists AND contains `total distinct states`", which is true
of *every* log the moment it is written and stays true forever. It fired
instantly against logs dated **08-01**, from earlier revisions, and
returned four confident, precisely-formatted, entirely wrong numbers
(`t1full` 954,936; `cr1fullself` 362,652; `liveness_a`/`liveness_b`
1,087,956) that were about to be used to size a scope cut. They were
caught by checking file mtimes against the run's start time and
discarded. **This is the recall-closed failure wearing a tool's
clothes**: the answer came from a command rather than from memory, which
is exactly the property that makes it feel trustworthy, and it was still
an answer about the wrong input. The standing line applies verbatim —
**any identity that can be reconstructed by reuse is not an identity** —
and here the identity was *"this log belongs to this revision"*, with
mtime the missing discriminator. **Rule: any check over `out/` must gate
on freshness (`out/$f.log -nt <marker created after the run started>`),
never on existence-plus-content.** The same hazard applies to the callgraph
DB and to any cached artifact keyed on something coarser than the thing it
describes; `ensure_callgraph_db`'s stale-IR defect (`stygia-8qz`) was this
identical shape one layer down.

**Why bother with the model when the doc already says it — the best
answer this artifact has.** `systems.md` §2.5 has required, since
**revision 6**, that the arm be a CAS that fails on a recycled slot:
*"if finalize set `dead` (or the slot was recycled; gen-stale) between
the claim and the arm, the arm CAS fails and the suspender returns E_TERM
without writing a freed slot's word"* (round-5 G-D1). The model's
`DirArm` guard was `dir = "claiming"` **alone for six revisions** — it
checked neither that the claim was the arming suspender's own nor that
the slot had survived — and **nothing caught it**, because until revision
12 the model had no gen for the check to be about. Round 12's
`InvNoFalseSuspendSuccess`, added to guard the lost-wake defect this
whole exercise exists to kill, then found unfaithfulness in the guard on
that same defect, in `medium`, at 14 million states. The doc did not
move. **A doc sentence nobody can execute is a sentence nobody has
checked.**

**Parity-diff discipline (new in revision 12, and the round-11 lesson).**
Round 11's C-1 was a doc mechanism the model did not have — and worse, the
model was **strictly safer than the design at exactly the point the design
was wrong** (it kept `dead` on freed ECs forever, so the false-SUCCESS arm
was unreachable). A green battery over a safer-than-the-design model is
the most dangerous shape this artifact can take, because every gate still
fires. The rule now: **after any doc change to a mechanism, diff the
mechanism's steps against the model's actions field by field and ledger
every gap**, including gaps where the model is CONSERVATIVE — those are
not free, they are places a real defect cannot be reached. The §2.5 row
below is the worked example.

**Enumeration discipline (new in revision 9, and the round-8 lesson).**
Every enumeration in this artifact and in `systems.md` is now marked
**DERIVED** (closed against the tree or the callgraph DB) or
**RECALLED** (written from memory). Round 8's three criticals were all
completeness failures of RECALLED enumerations that revision 8 presented
as facts. Current status of the ones that matter: T1 is DERIVED
(callgraph DB, survived hostile re-derivation); T2, T3, T4 and §8.1's
state routing are RECALLED; §3.5's lock chain was RECALLED, presented as
derived, and refuted. **Read every RECALLED marker as a defect that has
not been found yet** — that has been the outcome four rounds running.

**SCOPE (revision 13, normative — `systems.md` §0).** This model checks
the **EC lifecycle and every state change that moves an EC on, off, or
between CPU cores**, and nothing else. Out of scope, with reasons in
§0.2: kernel-wide lock ordering (the kernel uses address-ordered
same-class nesting plus lockdep's dynamic cycle detection; the chain
project revisions 10–12 built is retracted), analyzer capability,
migration sequencing, and anything that does not move an EC between
cores — VMAR work, handle-table rewriting, capability cascades, power
management. **Do not read a green battery here as a statement about any
of those.** Several rounds' findings were about them; they are recorded
in `systems.md` §11 as deferred, not fixed.

**Parity discipline.** An earlier version of this model targeting revision 4
silently repaired round-4's F1 with a persistent pended-origin flag the
design explicitly forecloses (`systems.md` §2.1: the pend fact lives in the
state word, not a descriptor flag) — and returned green on a revision that
does not work. The operative rule since: **when the spec is ambiguous or
wrong, encode the literal reading and flag it; never encode what you think
it meant.** Every action in `ECLifecycle.tla` cites the spec text it
implements; the parity table below maps every modelled mechanism to its
section; every divergence and ambiguity is a numbered ledger entry (U*/G*),
and every model-exposed result a finding (N*). Any edit to the module or to
`systems.md` must update this file before a green run is cited.

**And the mirror rule, added in round 7: where `systems.md` and
`specv3.md` disagree, the SPEC wins and the doc is the bug.** Round 7's
C2 is the worked example — rev 7's §8.1 said a priority edit takes effect
"at the next placement" for a waiting target; §[priority]'s Description
says immediately, with two tests. `specv3.md` is READ-ONLY; a genuine
spec GAP goes to §11 as a maintainer call, never to a silent narrowing.

## How to re-run

```sh
cd docs/kernel/tla
./run.sh                            # the DEFAULT battery: 31 configs + sany
RUN_XLARGE=1 ./run.sh               # + xlarge (3c x 4e safety)
RUN_SLOW=1   ./run.sh               # + measured t1full, full t1d, cr1fullself, liveness_a/b
RUN_XLARGE=1 RUN_SLOW=1 ./run.sh    # all 37; hours, launch it detached
```

The former full `medium` aggregate (`ECLifecycle_medium.cfg`) is no
longer in the default battery. After dpin/dres it was stopped on
2026-08-03 after more than an hour at roughly **598M generated / 133.6M
distinct / 11.9M queued** states. It remains on disk as an extended
measurement target, not as current default evidence.

**Always launch a long run DETACHED** — `setsid nohup ... & disown` —
because an agent tool timeout will otherwise kill the JVM mid-battery and
the transcript will look like a failure it is not. Knobs: `TLC_HEAP`
(default `5g`), `TLC_WORKERS` (default 4 — raising it does nothing for
the liveness phase, which is single-threaded), `TLC_TIMEOUT` (default
7200 s **per config**; an unexpected timeout fails the battery.
`t1full` and full `t1d` are measured-unconverged `RUN_SLOW` rows: they
pass only if generation completed, the timeout landed in the temporal
phase, and the distinct state count stays within the recorded drift
band). `run.sh` refuses to start if another TLC JVM is live, and gates
each launch on ≥ 3.5 GiB available.

`run.sh` exits non-zero unless every clean-expected run is clean AND every
gate reproduces its expected violation. **Round-9 C-2 is why this
sentence is now trustworthy**: the previous script was a revision-8
artifact invoking eight deleted configs, so it could not exit 0 under any
circumstances, and it ran none of the round-7/8 falsifiers — every
verdict in this file had come from invocations outside it while it
claimed to "reproduce every check". `TERM_ESCAPE` in particular was
ungated, so a revision dropping the retired-terminator escape would have
reintroduced C-1's deadlock silently. **Any config added to this
directory must be added to `run.sh` in the same change.** Logs with full traces land in `out/`. Gate configs
marked `-deadlock` disable TLC's deadlock detection so a shallower artifact
cannot shadow the targeted violation; all revision-8 runs keep deadlock
detection ON.

**`LiveTerm`'s status going into rev 8, stated plainly because it was
easy to misread.** The rev-7 battery never produced a `LiveTerm`
verdict at ANY scope: the 2×2 full-scope run (`c2`) hit
`UNCONVERGED(3600s)` — the `-lncheck final` artifact below, not a
property result — and the 2×3 per-property runs (`mp1`–`mp7`, of which
`mp7` is `LiveTerm`) never executed, because the batch stopped at
`c1full`. So "W3/W4 terminate-returns" was carried by rev 7 as an
unchecked obligation, not a green one. The rev-8 coverage table gives
its actual verdict.

**Liveness runs and `-lncheck final` (standing rule — violated twice, at
cost, in round 7).** TLC interleaves liveness checking with state
generation by default. When the spec carries an expensive temporal
assumption (`SpecFairAligned`'s raw `[]<>` tableau), those periodic
mid-generation checks dominate: the same configuration spent 53 of 60
minutes GENERATING with periodic checks and under a minute with
`-lncheck final` — and the symptom (a timeout during generation) does not
point at the cause. Round 7 inherited two `UNCONVERGED(3600s)` rows,
`c1full` and `c2`, that were BOTH this artifact: the batch runner in use
set the flag for `run.sh` entries but not for its own. `c2`, once re-run
with the flag, passes in minutes. **Every liveness entry in every runner
must carry it**; `run.sh` does, and the two rows are recorded as
runner artifacts, not verdicts.

**Symmetry and VIEW on liveness configs — evaluated in round 7, both
DECLINED, with measurements.** Anyone re-running this battery will notice
that `SYMMETRY Symm` is on the safety configs and on none of the liveness
ones, and that no `VIEW` is used. That is deliberate:

- **All eight temporal properties ARE formula-symmetric.** `LiveParking`,
  `LiveRetired`, `LiveReady`, `LiveWake`, `LiveMark`, `LiveClaim`,
  `LiveSuspender`, `LiveTerm` are each `\A e \in ECs: P(e) ~> Q(e)`, with
  no named EC, no named core, and no predicate that distinguishes cores.
  So the *property* side of the soundness condition is satisfied for every
  one of them.
- **TLC's implementation is nonetheless unsound here, and says so.**
  Running a liveness config with `SYMMETRY Symm` produces: *"Warning:
  Declaring symmetry during liveness checking is dangerous. It might cause
  TLC to **miss violations** of the stated liveness properties. Please
  check liveness without symmetry defined."* Missing a violation is the
  fatal direction — a green run under symmetry would silently retire a
  coverage gap, which is strictly worse than a slow run. **Measured** on
  the old `crfals` falsifier: symmetry cut the graph 1,768 → 457 distinct
  (3.87×, close to the theoretical 4× at 2×2) and the known violation
  still fired. After dpin+dres, the same trick still timed out in final
  temporal checking (32,552 product states under a 180s cap). Not adopted.
  Symmetry stays on the safety configs, where it is sound.
- **VIEW: exactly one component is projectable, and it saves nothing.** A
  view is sound only for components no action guard reads, because TLC
  skips a state whose view was already seen — so a projected component
  that can affect future behaviour causes real successors never to be
  generated. `mo` is read by `TermWait`'s W4 guard, `dsrc` by
  `DirClaim`'s cycle check, `pin`/`plk` by the pin gate, `tb`/`cb`/`db`
  by the budget-bounded actions. Only `po` qualifies (the module's
  contract: "NO protocol action reads po"), and only in configs that do
  not check `InvRetiredPdOrdered`. **Measured**: `ViewNoPo` on `crfals`
  gave 1,768 → 1,768 distinct — a **0%** reduction, because `po` is
  already determined by the rest of the state. `ViewNoPo` is kept in the
  module as the worked negative result, and used nowhere.
- **`-workers` stays at 4.** TLC parallelises state generation but its
  liveness check is single-threaded, so raising it does nothing for the
  phase that costs the time.

The lever that actually worked was not a TLC setting: retiring
`AlignmentAssumption` via symmetric-suspend rejection (finding C3) took
the minimal `LiveSuspender` rung from 2min03s to 13s by moving the check
off TLC's general tableau and back onto the WF/SF fast path.

**And the cost driver that remains is the FAIRNESS-CONSTRAINT SET, not
the graph size** — a second measured result, and the reason more workers
would not help. Compare runs on the SAME 56,726-state graph:
`liveness_a` checks THREE properties under `SpecFairCore` (14 constraint
instances at 2×2) in 437s, while `cr1fullself` checks ONE property under
`SpecFairN3` (18 instances — the same set plus N3's `SF(TermWait)` and
`SF(DirLoop)` per core) and takes far longer. The two added constraints
are exactly the per-spin SFs finding N3 introduced, and `TermWait`'s
enabledness is itself a quantified expression (`\A c2 \in Cores:
cores[c2].cur # t`) that TLC must evaluate at every node of the product.
So the N3 assumptions cost real checking time on top of being
assumptions — which is one more argument for designing them away rather
than carrying them, the same argument C3 just won for N6.

**Memory budget (this host, hard rule).** ONE TLC JVM at a time, explicit
heap bound (`-Xmx6g` on an otherwise-quiet host, `-Xmx3g` under load),
fixed `-workers 4`, and a `free -m` >= 4 GiB gate before each launch. Do
NOT run TLC with `-workers auto` on this box: it reads the core count,
oversubscribes, and has already driven the host (which carries an ~8 GiB
ML job plus concurrent build/qemu agents) to the edge of swap-thrashing.
If a config does not fit the budget, reduce its scope and record the
reduction here — never raise the bound. `out/` and `states/` are
gitignored; keep all generated output under them.

## Files

| File | Purpose |
|---|---|
| `ECLifecycle.tla` | the model: rev 16 plus the dispatch-tail/PMU hardware-owner extension, with older/defective machines as switches |
| `ECProbes.tla` | reachability probes (`pr1`–`pr5`, with `pr4`, `pr4d`, and `pr4d_min` all checking `ProbeNoTermSuspendCycle` at their paired scopes) |
| `run.sh` | **runs every config below except the `q*` set, `dirabafix`, the oversized full `medium`, and full `pr4d`; exits non-zero on any deviation** |
| `ECLifecycle_small.cfg` | 2c × 2e, ALL features, full safety battery + both cycle invariants |
| `ECLifecycle_medium_nodir.cfg` | default 2c × 3e non-directive aggregate: RV, pin-lock, S7, fast path, suspend, term budget 2, symmetry |
| `ECLifecycle_medium.cfg` | extended/manual 2c × 3e full directive aggregate, symmetry. **Oversized after dpin/dres; not default evidence.** Two documented scope cuts in-file: `DIR_DROP = FALSE` and `CR_BUDGET = 0` |
| `ECLifecycle_large.cfg` | 3c × 3e, core + rendezvous, symmetry |
| `ECLifecycle_xlarge.cfg` | 3c × 4e, core only, symmetry (`RUN_XLARGE=1`) |
| `ECLifecycle_cr3self.cfg` | 2c × 3e cycle invariants — the 3-cycle question at 3 ECs. **Documented scope cut in-file**: `DIR_DROP = FALSE`, `CR_BUDGET = 0` |
| `ECLifecycle_dirf6{,fix}.cfg` | round-11 C-1's false-SUCCESS arm: `dirf6` is now an expected-clean stale-gate closure under dpin; `dirf6fix` is the target-gen repair check |
| `ECLifecycle_pmu_release.cfg` | focused PMU release/destruction lifetime check with per-core `phw` hardware refs and safe remote migration enabled; default battery |
| `ECLifecycle_pr{4,4d,4d_min,5}.cfg` | the round-10/11/16 probes (`ProbeNoTermSuspendCycle`, `ProbeNoDisarm`); full `pr4d` is extended/manual evidence paired with full `t1d` |
| `ECLifecycle_t1{min,s,r,d_min,d,full}.cfg` | **`LiveTerm` ladder under `SpecTrm`**, its minimal fairness set; `t1d_min` is the default directive-bearing replacement rung, while full `t1d` and `t1full` are extended/manual measured-unconverged rows |
| `ECLifecycle_cr1minself.cfg` | focused `LiveSuspender` under `SpecSus` (neither N6 assumption), paired with `crfals` |
| `ECLifecycle_cr1fullself.cfg` | extended `LiveSuspender` under `SpecFairN3` (neither N6 assumption), `RUN_SLOW=1` only |
| `ECLifecycle_liveness_{a,b}.cfg` | L1/L2/L6 and L3/L4/L5 at 2×2 under `SpecFairCore` |
| `ECLifecycle_mtermfix.cfg` | the round-8 C-1 repair at the mutual-terminate scope |
| **falsifiers** | |
| `ECLifecycle_rev3_x{1,2,3}.cfg` | rev 3: expect `InvS4Holder` / deadlock / `InvNoLostOneShot` |
| `ECLifecycle_rev4_f1{a,b}.cfg` | rev 4 F1's two readings: `f1a` is now clean under target claim pins; `f1b` still expects deadlock |
| `ECLifecycle_n4.cfg` | rev-5 literal unwind ordering: expects `InvS1` |
| `ECLifecycle_e4.cfg` | publish-claimable-before-hop: expects `InvS3` |
| `ECLifecycle_pinord.cfg` | round-7 C1 `lock(); pin_depth += 1;`: expects `InvNoPreemptedLockHolder` |
| `ECLifecycle_crcyc.cfg` | round-7 C3, no rejection: expects `InvNoSuspendCycle2` |
| `ECLifecycle_cr3.cfg` | round-7 C3, `"pair"` at 3 ECs: expects `InvNoSuspendCycle3` |
| `ECLifecycle_crfals.cfg` | round-7 C3, no rejection + no N6 assumptions at the focused no-drop `SpecSus` scope: expects a temporal violation |
| `ECLifecycle_mterm.cfg` | **round-8 C-1, no retired-terminator escape: expects a DEADLOCK** |
| `ECLifecycle_pmu_remote_falsifier.cfg` | remote PMU stale-ref bug: `PMU_SAFE_MIGRATION = FALSE` expects `InvPmuHwCoreRefCoherent` |
| `ECLifecycle_pr{1,2,3}.cfg` | the reachability probes (violation = pass) |
| **not in `run.sh`** | |
| `ECLifecycle_q{1..7}.cfg`, `q7d` | per-property liveness at 2c × 3e. `q7` did not converge in 90 min; kept because the scope question is open, NOT because they pass |
| `ECLifecycle_dirabafix.cfg` | round-10 C-D identity-gated repair config; kept on disk but not run because the clean invariant is analytically vacuous under `DIR_OWNED = TRUE` |
| `ECLifecycle_medium.cfg` | extended/manual full directive 2c × 3e aggregate; stopped after dpin/dres and not default evidence |
| `ECLifecycle_pr4d.cfg` | extended/manual full-scope non-vacuity probe paired with full `t1d`; kept on disk but not in the default battery |


**Config taxonomy** (which machine each family describes). DERIVED from
`ls ECLifecycle_*.cfg` and `grep -n '\.cfg' run.sh`, not from memory —
an earlier version of this paragraph named `c2`, `mp*` and a `c1*`
ladder, **none of which are on disk**; they were deleted in revisions
	9–11 and the taxonomy kept describing them. There are **50 `.cfg` files**
	and `run.sh` invokes **39**; the 11 it does not are `q1`–`q7`, `q7d`,
`dirabafix`, full `medium`, and full `pr4d`, each with its reason
recorded in `run.sh` itself.

`small`/`medium_nodir`/`large`/`xlarge`, every gate, every probe,
`liveness_a`/`liveness_b`, the `t1*` ladder and the `*self` files all run
the BLESSED machine, `CYCLE_REJECT = "self"`. The `cr*` files without
`self` (`cr3`, `crcyc`, `crfals`) run mechanism **(A)** `"pair"` or
`"none"` and exist to show what each does and does not close.
`SpecFairAligned` survives in the module as the rev-7 machine's spec and
is used by no live config — the 13s-vs-2min03s measurement it backs is
history, not a runnable comparison.

Machine switches: `PENDED`/`PIN_GATE` (FALSE+FALSE = the rev-3 machine),
`F1_MODE` (`"rev5"` = W7 pre-CAS wait; `"nowait"`/`"alwayswait"` = the two
readings of rev 4's hop-side iff), `FIN_UNWIND` (TRUE = revision 6's N4
mechanism, the finalizer-owned unwind; FALSE = the revision-5 literal
machine), **`PIN_BUMP_FIRST`** (TRUE = revision 8's normative `pin_depth`
order; FALSE = `lock(); pin_depth += 1;`, the round-7 C1 falsifier),
**`CYCLE_REJECT`** (`"self"` = the recommended suspend-cycle rejection and
the machine the battery blesses; `"pair"` = the maintainer's pair-locked
form, which closes 2-cycles but not 3-cycles; `"none"` = the rev-7
machine, a falsifier — round-7 C3), and **`TERM_ESCAPE`** (TRUE = the
round-8 C-1 repair, a retired terminator abandons the W3/W4 wait; FALSE =
revision 8, where mutual terminate deadlocks two cores — gated by
`mterm`, which round-9 C-2 found was in NO runnable script).
Feature gates: `SUSPEND_ON` (5c + recv-pop + edge 7), `RV_ON` (rendezvous
window), `DIR_ON` (directive), `PINLOCK_ON` (pin-class locks), `S7_ON`
(dead-domain filter route), `CR_BUDGET` (edge-1 creation), `TERM_BUDGET`
(retires).

## Parity table (spec section -> model construct)

| Spec | Model | Notes |
|---|---|---|
| §2.1 lifecycle word, 7 states | `ecs[e].st`, CAS = guarded atomic actions | + `"freed"` as the post-edge-10 pseudo-state |
| ~~§2.1.1 idle EC~~ | **nothing to model — §2.1.1 WITHDRAWN in doc rev 16** | **G7 CLOSED by the doc retracting.** There is no per-core idle EC (`idle_ec` never assigned; `parkAndAwaitIRQ` is the real mechanism and replaced it to fix a cross-core kstack-sharing bug). A core with an empty run queue holds no EC, so the model having none is faithful, not a gap. Unaffected: the `.idle_wait` EC state / `wait.kind == .idle`, which are a USER EC choosing to idle |
| §2.2 wait descriptor | `pk/shot/pd` fields; payload writes abstract | saved-frame ban surfaces only as `InvNoUAF`; the timed-vs-port flavor is encoded by `shot` alone. **Rev 8: the staged destination `dst` is DELETED (M-2)** — §2.2 now calls staging a locality hint and every placement computes its destination fresh |
| §2.2 `payload_done` | `pd`; claimant release-store = `WakePendDone`/`IrqPendDone`/`RvDeliver` pended arm | reset at discharge (G8) |
| §2.2 "what is NOT in here" (M-1) | **no model construct, deliberately** | `priority`/`affinity` are stable per-EC words; their *ordering* effect is below set-queue granularity and their *destination* effect is the nondeterministic placement below |
| §2.3 per-core words | `cores[c].q/cur/pc/outg`; `pc` now distinguishes `dispatchPmu` and `dispatchLoad` from `ecrun`; `committed_ec` etc. absent as designed | queues are sets, FIFO abstracted. `teardown_pending` is deliberately unmodelled; see G16 |
| §2.4 `owner_core` | `own`, NULL outside validity set | poison = NULL |
| §2.4 `pin_depth` + pin class (F3) | `pin`; wake/suspend claim actions pin the protected target EC, pin-class locks pin the executing EC via `PinAcq`/`PinRel`; `dpin` is the running-target remote-directive lifetime pin | "computed membership" is the analyzer's job; model has one representative class. `RetireEnabled` gates on target `pin = 0` and `dpin = FALSE`; `InvPinCells` permits transient ready publish pins because containment is still the run queue. `dpin` is deliberately separate because Zig's directive waiter pin blocks retire/finalize but must not block the target owner's tick/boundary directive consumption |
| §2.4 `pin_depth` ORDER (C1) | `PIN_BUMP_FIRST` + `plk \in {none,held,preB,postD}` + `PinBump`/`PinUnlock` + `InvNoPreemptedLockHolder` | **pin-class half CHECKED** (the `pinord` falsifier); **claim half BELOW GRANULARITY and not checked** — see finding C1 |
| §2.4 `mark_state` (M-3) | `mo` (one BIT) | rev 7's private `mo`/`mk` pair collapsed into the doc's one word, then to one BIT in round 8 — the variable is `mo`, not `mst`; `TermWait`'s W4 guard is the acquire side |
| §2.5 directive | `dir` word; abstract `dres` result; `dpin` target pin; `DirClaim/DirArm/DirLoop/DirConsume/DirFail/DirDrop`; finalize -> `"dead"` (F6) | F5 loop literal; G-D1/G-D2/G-D3 closed in rev 6; N1. `DirClaim` takes the running target `dpin` and every `DirLoop`/arm-abort exit releases it. `DirFail` and `DirDrop` are owner-consume-failure terminals: owner publishes result then `armed -> failed`; only the matching waiter reads `dres` while failed and acks `failed -> none`, so failure cannot be reported as suspend success. `dres` may be stale outside `failed` |
| §2.5 directive word, six values / result ack | `dir \in {none, suspending, claiming, armed, failed, dead}`; `dres \in {none, fail}` abstracts `directive_result`, meaningful only while `dir = failed`; writers = `DirSelfMark` (own word), `DirClaim`/`DirArm`/`DirLoop` (target's), `DirConsume` + `TickPreempt`'s rule-3 arm (owner success), `DirFail` and `DirDrop` (owner failure), finalize (`dead`) | **PARITY GAP FOUND IN ROUND 9, now closed by deleting the doc side**: rev 9's §2.5 added a sixth value `dropped` that was **never modelled** — so the rev-9 battery was green on a machine that did not contain the mechanism the doc had just acquired. Round-9 C-1 deleted `dropped` for independent reasons (it had no clearing rule and made a target permanently unsuspendable), which incidentally restored parity then. Current parity includes the implemented `failed` terminal and waiter ack, distinct from the deleted stale-port `dropped` value: stale/bad port is now modelled as `failed`, not `none`; the ack does not clear `dres`, because clearing the word and result is not one atomic update |
| §2.5 break disambiguator + arm ownership (round-10 C-D, round-11 C-1) | `DIR_OWNED` + `dsrc` (ownership); `DIR_GENCHK` + `gen`/`dgen` (target-gen half); `pok` (port half); `DirDrop` for stale/bad-port failure; `DirFail` + `dres` for other owner-consume failure; ghosts `dbad`/`dfs`; `InvNoForeignDisarm`, `InvNoFalseSuspendSuccess`; falsifier `diraba`, stale-gate closure `dirf6`, fix `dirf6fix`, probe `pr5` | Current doc and implementation install `owner_slot` at the successful claim (`none → claiming`) and retain it through `armed`/`failed`; the model mirrors that with `dsrc`. Remaining modelling divergence: the doc PACKS `{state:u8, owner_slot:u24}` into one word for a single-word CAS and the model keeps `dir` and `dsrc` as separate fields, so **the u24 narrowing and the single-word-CAS property are unmodelled**. Result payloads are collapsed to one failure class (`dres = fail`), which is sufficient for the lifecycle correctness point: only delivered consume sets `dlv`, and every owner consume failure is acked by the matching waiter as an error, not success. `InvNoForeignDisarm` is additionally VACUOUS under `DIR_OWNED = TRUE` (M-3) — the falsifier carries that gate |
| §2.5.1 suspend-cycle rejection (C3) | `CYCLE_REJECT`; `dsrc`; `"self"` adds the `"suspending"` value + `DirSelfMark`/`DirSelfAbort` (UNFUSED — two CASes, no lock between) ; `InvNoSuspendCycle2`/`3` | the mechanism is checked by SAFETY invariants, which is the right instrument for a reachability question; its PAYOFF (retiring both N6 assumptions) is checked by `LiveSuspender` under the focused `SpecSus` rung paired with `crfals` |
| §3.6 assumption (2), no cross-core alignment | **RETIRED** — `AlignmentAssumption`/`SpecFairAligned` now describe only the rev-7 machine (`CYCLE_REJECT = "none"`), which is a falsifier | the impossibility proof for expressing it as fairness is kept as history, so nobody retries the ghost route |
| §3.1(1) preempt gate | `TickPreempt` guards: CAS-from-`running` + own `pin = 0` + not in `ClaimPCs` under `PIN_GATE`; the directive owner's boundary arm ignores `dpin` | `ClaimPCs` is the explicit IRQ-disabled claim-continuation gate now that claim pins live on the protected target. The `dpin` split is load-bearing: a remote waiter pin must block retire, not suppress the owner's user-boundary directive check |
| §3.1(2) sched ctx never dispatches from irq | structural: irq frames never dispatch | |
| §3.1(3) boundary entry checks **and their precedence (M-5)** — **FOUR arms, not three** | `BoundaryRetired`; `TickPreempt`'s rule-3 arm (consume beats requeue); `dir # "armed"` parity guards on every user-boundary initiator | the precedence is now a doc RULE and a §9.2 assert, not only a model behavior — that gap was M-5. **Two honesty notes revision 15's row lacked.** (a) The doc's order is `retired → directive → domain-paused → requeue`; the **domain-paused arm is unmodelled** (G12), so the model checks a 3-arm precedence against a 4-arm rule. (b) Of the three modelled arms, only `directive → requeue` is FALSIFIABLE here: `BoundaryRetired` and `DirConsume` are **never simultaneously enabled** (their guards are disjoint on `st`), so `retired → directive` cannot be violated in this model and its "check" is vacuous. It rests on the §9.2 assert and on review, not on the battery — say so rather than let the row imply coverage |
| §3.2 park sequence | `UserPark` (publish atomic, W1), then the hop | rev-7 M1 (CAS-before-links) is the fused action's guard semantics — no model change |
| §5.3 T4 pop/scan closure | claims/pops only inside container-atomic actions; `FireAt`'s retired-pop arm | T4's row set is doc-side; the model's containers are abstracted |
| §8.1 `affinity` (ready target, mask excludes) | `AffMove` (5c + edge 6, discharging via `WakePlace`) | |
| §8.1 `affinity` (other states) | collapsed into the nondeterministic placement destination | over-approximates every mask |
| §8.1 `priority` | **no model action, and rev 8 says why precisely** | the `waiting` and `ready` arms are LINK REPAIRS: no state change, no containment change, same container. At this model's granularity (queues are sets; there is no intra-container position) they are the identity transition. What C2 changed is doc-normative and test-visible, not state-machine-visible |
| §8.1 `yieldTo` target side (M-4) | `DispatchEC(c,e)` requires `e \in cores[c].q` — local-only by construction | the S7 filter is `~ecs[e].dd`; the affinity-mask check is below granularity (masks unmodelled) |
| §9.4 both fused shapes | `FastPath` (suspend FP), `ReplyFP` (reply FP main) | asm conformance out of boundary (`stygia-qde`) |
| §3.2 edge-4 claimability-at-the-hop | `E4_AT_HOP` switch + the e4 falsifier | the Phase-3b barrier-zero question, answered with teeth |
| §3.2 dispatch sequence + S7 (F2), including park-stack tail | `DispatchEC` (selected/current commit) -> `DispatchPmu` (`pmuSwitch`) -> `DispatchLoad` (final context load); `DispatchAbort{Pre,After}Pmu` for lifecycle loss after commit; `PmuRelease` for perfmon-state release/destruction completion; `S7Claim` -> `S7Retire` | lock-order half of F2 outside boundary. `InvPmuTailOwned` checks that at most one per-core PMU hardware ref names an EC; `InvPmuHwCoreRefCoherent` checks both `hw -> phw` and reverse `phw -> hw`; `InvPmuNoReleasedHw` checks release/destruction cannot complete while any PMU hardware token is live |
| §3.2 wake body | `WakeStart` (5a/5b) + `WakePlace`/`WakePendDone`; `FireAt` + irq frame bodies | |
| §3.3 IRQ discipline | masked sections = atomic actions; handler-active = masked (no nesting) | sync-exception rule outside boundary |
| §3.5 R-claim | claims only inside container-atomic actions (pop+claim fused) or retire | gen-lock half abstracted (no gen) |
| §3.6 T3 spins (**10 rows**) | W1 = atomicity; W2 = `HopCommitPended` pd guard; W3/W4 = `TermWait`; W5 = `DirLoop`; W7 = `RetireEnabled` pd guard | W6, W8, W9 **not modelled** — and **W5-N (the domain-pause predicate wait) is not modelled either**, which revision 15's row omitted entirely: it accounted for 9 of 10 rows and read as complete. W5-N is the only PREDICATE-shaped wait in §3.6 and it belongs to G12 |
| §3.6 assumption (3), no interrupt storm | `SF_vars(BaseStep)` (STRONG, not weak) | rev 7 claimed the set was complete at two; this is the third, and it was always encoded — just not counted |
| §4 hop | `HopRelease` (release first) -> `HopCommit{Wait,Requeue,Pended,Retired,Claimed}` | retired arm waits for NOTHING (F1); **rev 8: every commit arm that places picks its destination at placement time (M-2)** |
| §5 edges 1..10 | 1 = Init + `CreateEC`; 2 = `DispatchEC` + `StealDispatch`, followed by the split dispatch tail; 3 = `UserPark`/`TickPreempt`/`DirConsume`/`RvStart`; 4/6p/8/10 = hop arms; 5a/5b = `WakeStart`/`FireAt`/`RvStart`; 5c = `SuspendStart`/`S7Claim`/`AffMove` + `StealClaim`'s ready claim/removal; 6 = `WakePlace`/`RvDeliver`/`IrqWakePlace` + live-domain `StealAbandon`; 7 = `SuspendPlace`; 9 = `RetireEC`/`Terminate` + `StealDropDead` for DomDie-after-steal-claim | every edge has >= 1 action |
| §5.1 T1 sources | one generic one-shot (`shot`) = deadline/wheel/device rows; rendezvous row = `RvStart` | periodic-scan loser protocol below granularity |
| §5.2 T2 matrix | `RetireEcsAfter` rows + routed discovery actions; marking column = `mo` (one bit) | ready x K+C / requeue x K+C unreachability = `InvPinCells` + `InvNoPreemptedLockHolder` |
| §8.2 retire + finalize | W7 guard; target `pin = 0` and `dpin = FALSE` drain gates in `RetireEnabled`; NO retire unwind step — finalize's first act is the idempotent unwind (`FIN_UNWIND`) | mirrors `markRetiring` -> `waitPinsDrained` -> retire/dead-gen bump, including the directive waiter's running-target pin |
| §8.3 rendezvous | `RvStart` + `RvDeliver` | G-RV1 |
| §8.5 creation | `CreateEC` (publish-last) | CD-lock liveness gate not modelled |
| §9.2 asserts | invariants: `InvHopUnpinned`, `InvHopNoClaimedOutgoing`, `InvRetiredPdOrdered`, `InvPmuTailOwned`, `InvPmuHwCoreRefCoherent`, `InvPmuNoReleasedHw`, **`InvNoPreemptedLockHolder`**; publish/wait pin=0 guards | `InvHopUnpinned` checks the outgoing frame's pin-class lock state, not external target pins or preemptible claim continuations held by another EC. The PMU invariants are hardware-owner/release ownership assertions, not a full PMU counter model |
| S1/S3/S4/S8 | `InvS1`, `InvS3`, `InvS4Holder`+`InvS4Pended`; S8 by construction | S2/S5/S6 and S7's lock half outside boundary |
| L1-L6, W3/W4/W5 | `LiveParking/Retired/Ready/Wake/Mark/Claim/Term/Suspender` | L3 states DISPATCH, not merely "leaves ready" |
| §0.3 / §3.4 domain pause (`cd.paused`), §2.2 `wait.kind = .domain_pause`, §3.1 rule 3's third arm, §5 edge 1's gated publish, §3.6 W5-N | **NOTHING. No variable, no action, no invariant.** | **G12** — the largest open gap. The model has no domains beyond a per-EC `dd` flag. Round-13 C-1's whole fix, plus revision 16's quiesced-resume rule and boundary-leg fix, are doc-only. G12 carries the four lost properties and the design for closing it. `waiting(domain_pause)` is a boundary edge-3/edge-4 route, not edge 7 |
| §3.4 `current_queue_core` | **no model field** | **G13** — MP. Run-queue membership IS `cores[c].q`; the field is a cache of a fact the model computes, so a coherent field would add no reachability. What is still lost is generic CACHE INCOHERENCE, which needs two words and the model has one; the prior x64 asm writer gap is closed by the R13 ready-enqueue metadata repair |
| §3.3 quiesced-resume rule (rev 16) | **not modelled, and not modellable here** | user memory is entirely below this model's granularity — there is no user address space in the state. Enforcement is §9.2's assert pair and §9.3(2)'s analyzer clause; §11.13 records the HEAD violation. Folded into G12 |

## Divergence & ambiguity ledger

Labels: **MP** = model more permissive than spec (over-approximation: safe
for bug-finding, may show unreal traces), **LP** = model less permissive
(prunes real interleavings — the dangerous direction), **INC** =
incomparable/reconstruction.

- **U3 (fixed)** — was LP, removed. `UserPark` once guarded untimed parks
  on another EC being lively; no spec counterpart.
- **U4** — compression, stated: retire of `ready`/`waiting` is retire +
  inline finalize in ONE action (T2 "retirer, inline" — same caller,
  sequential, no other named party); the parking/claimed/pended rows are
  NOT compressed.
- **U5** — frame death: finalize resets the dead frame's `pc`/`tg`.
- **U6 (PMU hardware-owner ghost)** — compression, stated. `ecs[e].hw`
  abstracts `PerfmonState.hw_core`, and `phw[c]` abstracts
  `pmu_hw_refs[c]`. The pair is persistent across `DispatchLoad`, so it
  now covers the long-running ownership interval rather than only the
  dispatch tail. With `PMU_SAFE_MIGRATION = TRUE`, `DispatchPmu` retires
  every old per-core ref for the EC before installing the new owner. With
  `PMU_SAFE_MIGRATION = FALSE`, it reproduces the reviewed old behavior:
  `hw` migrates while a remote `phw` entry remains live, and the
  non-caller remote syscall falsifier can clear `hw` while leaving that
  `phw` entry behind. `InvPmuTailOwned` covers duplicate hardware refs;
  `InvPmuHwCoreRefCoherent` covers both `hw -> phw` and reverse
  `phw -> hw`. `ecs[e].prel` models perfmon-state release/destruction
  completion separately from the hardware token. The model still abstracts
  actual counter values, threshold PMI re-arm cadence, `perfmon_read`
  sampling values, and the bounded duration of release-pending waits.
- **G1** — INC, gate-only. Rev 3's hop behavior on a commit-CAS observing
  an already-advanced state is unspecified; the gate machine has an
  "owner proceeds" arm or it wedges on benign schedules.
- **~~G2~~ (ERASED in rev 8, round-7 M-2)** — was MP: "who stages the
  placement destination for an interrupt-origin pend is unstated; the
  model lets the claimant stage a nondeterministic core." The doc
  resolved the underlying contradiction by deleting the staged
  destination as placement authority, so there is no longer a staging
  step whose author could be unstated. Placement policy remains outside
  the boundary (the destination is nondeterministic AT PLACEMENT), but
  that is now the doc's own statement rather than a model gap.
- **G3 (fixed)** — was LP, now MP. Edge 8 does not fix the requeue
  destination; `HopCommitRequeue` places on a nondeterministic
  destination.
- **G4 (fixed)** — resolved by design change; see N4. `RetireUnwind`
  survives only as the rev-5-literal falsifier.
- **G5 (resolved)** — T2's "pin-writing `parking`" marking deferral is
  encoded literally.
- **G6** — doc soft spot (stands, now stated doc-side): a device-woken,
  not-yet-acked EC can be suspended (5c) or retired while `ready`; the
  line stays masked. §8.4 states it; userspace owns the consequence.
- **~~G7~~ (CLOSED in rev 16 — by DELETING THE DOC SIDE, not by
  modelling).** Was: "LP. The per-core idle EC (§2.1.1) is unmodelled; an
  idle-slot-specific containment race would be invisible here."
  **§2.1.1 is withdrawn**: there is no per-core idle EC. `idle_ec` is
  declared at `sched/scheduler.zig:184`, read once unreachably at
  `:1521`, and **never assigned**; the tree parks an idle core on its own
  park kstack via `parkAndAwaitIRQ`, and `:1098` records that this
  replaced the idle EC specifically to kill a cross-core kstack-sharing
  bug. So there is no idle slot, no idle-slot containment race, and
  nothing for the model to be missing. **The model was right and the doc
  was wrong** — which is the opposite of this ledger's usual direction
  and worth recording as such: a gap entry can close because the design
  retracts, not only because the model catches up. (Same shape as the
  round-9 `dropped` row in the parity table.) A core with an empty run
  queue holds no EC at all, so the model's absence of an idle EC is now
  FAITHFUL rather than an over-simplification.
- **G8 (closed in rev 6)** — `payload_done` is cleared by the discharger.
- **G-D1/G-D2/G-D3 (closed in rev 6)** — the arm CAS, the reset atomic
  with the publish, and the `claiming` break case.
- **G-RV1 (closed in rev 6)** — the mint-failure receiver arm is 5a-only.
- **G9 (NEW, rev 8, MP — round-7 C2's residue)** — the `priority`
  re-bucket is modelled as nothing at all. That is *sound* here (it is
  the identity transition at this granularity: no state change, no
  containment change) but it means the model contributes NOTHING to C2's
  correctness. What checks C2 is `specv3.md` [test 06]/[test 07] and the
  doc's lock protocol; do not cite a green battery as evidence about
  priority ordering.
- **G11 (NEW, rev 14, LP — round-12 M-2; LEDGERED, not modelled, per
  round-12's blocking bar).** The model **never writes `dir = "dead"`**.
  The value occurs only in `TypeOK`'s domain; every finalize site writes
  `"none"`, because revision 12 modelled §8.2's `slot zero` (round-11
  C-1) and collapsed the release body's two writes into one. So §2.5's
  *"`dead` is still mapped to E_TERM"* and §3.4's *"terminal `dead`
  distinguishes retired from consumed"* are **entirely unmodelled**, and
  `InvNoArmedFreed`'s stated justification is stale. **This is LP — the
  dangerous direction** — because the `dead` arm of the break analysis
  is unreachable, so no run can exercise it. It is not a soundness
  problem for what IS checked (the zero is the later of the two writes,
  so modelling only it is modelling the state a racing suspender
  actually observes, which is round-11 C-1's whole point), but the
  `dead` arm gets no coverage at all. **Fix when convenient: model the
  release body as TWO writes — `dead`, then the zero to `none` — so both
  arms are reachable.** Recorded rather than fixed because round 12's
  bar puts parity bookkeeping below the blocking set, and this is the
  same shape as the C-1 the parity discipline was rewritten for, in the
  row that fix touched.
- **G10 (rev 8, MP — round-7 M-1's residue; its LOCK-ORDER half REFUTED
  in round 8, C-3)** — the reach-and-validate protocol (handle → gen
  lock → container lock → re-validate) is doc-side only, and that part
  stands: the model's actions are guarded on current state, so
  "re-validate after acquiring the lock" is true by construction.
  **What does NOT stand is the lock chain rev 8 derived while writing
  it.** Rev 8 asserted `wait-container < EC gen < core locks` as derived
  fact. Round 8 checked it against the tree: the RIGHT edge
  (`EcGen → CoreLock`) is sound with no counterexamples, but the LEFT
  edge is false — `port.zig:463-465` states the tree's canonical order
  as **`EC → Port`** in as many words, and `futex.wake`, the function
  the edge was derived FROM, traverses the EC/bucket pair in *both*
  directions (bucket then `node.ec` at `futex.zig:273`; then from inside
  that hold, `removeNodesExcept` → a further bucket acquire at
  `futex.zig:219`), made safe by an ascending-index discipline and a
  `FUTEX_BUCKET_GROUP` opt-out rather than by any chain. A fourth class
  (CD gen locks) was missing from the chain entirely. **Lock order is
  outside this model's boundary — TLC contributed nothing to finding
  this and would not have caught it.**
  **XREF CORRECTED (revision 15/16): this entry used to say "recorded as
  a blocker in `systems.md` §11.10: §8.1's re-bucketing must not be
  implemented against a guessed order, and what is actually needed is a
  lockdep group design that does not exist". That is no longer what
  §11.10 says.** §11.10 was **RETRACTED in revision 13** (§0.2, §3.5):
  revisions 10–12 escalated the refuted chain into a blocker gating
  §8.1, §8.2, §8.5 and six migration steps, and revision 13 withdrew
  both the chain and the blocker — the kernel uses address-ordered
  same-class nesting under a named group plus lockdep's dynamic cycle
  detection, and §8.1's repair uses drop-and-retry so it never holds two
  classes at once. **Nothing is blocked.** What survives from §11.10 is
  a one-line tree defect about `EC_NESTED_GROUP`, not a design gate.
  Cross-class lock ordering is OUT of scope by §0.2, and the correct
  reading of this ledger entry is now the sentence above it: the model
  is silent here, and it was a reviewer reading `port.zig` — not a
  battery — that produced the finding.
- **G12 (NEW, rev 15/16, LP — the largest open parity gap in the
  artifact; LEDGERED, not modelled, and the reason is stated rather than
  implied).** **The domain pause is UNMODELLED IN ITS ENTIRETY.** Round
  13's C-1 fix — `cd.paused` (§3.4), §3.1 rule 3's third boundary arm,
  edge 1's gated publish (§5), `wait.kind = .domain_pause` (§2.2), W5-N
  (§3.6), §0.3's two refusals — has **no TLA+ variable, no action and no
  invariant**. The model has no domains at all beyond a per-EC `dd`
  (dead-domain) flag, which is a different fact. Revision 16's additions
  (the quiesced-resume rule, the boundary-leg fix, §11.13) sit inside the
  same gap.

  **This is the shape the parity discipline was rewritten for**, and it
  is worth being blunt: round 11's C-1 was a doc mechanism the model did
  not have, the battery was green throughout, and every gate still fired.
  This is that again, one mechanism later — except that this time it is
  **recorded before** anyone cites the green run rather than after.

  **What is LOST, concretely** — four properties nothing checks:
  1. **The pauser terminates.** W5-N is a T3 row with a
     PREDICATE-shaped wait, the only one in §3.6. Its termination
     argument is that the runnable set only ever decreases, which rests
     on edge 1's publish reading `cd.paused` under the CD `_gen_lock`.
     Nothing executes that argument.
  2. **No EC of a paused domain reaches user code while paused.** This
     is the pause's entire point and it is a safety invariant — the
     cheap direction — and it is unstated in the model.
  3. **Mutual pause is unrepresentable.** §0.3's second refusal is the
     domain-level analogue of §2.5.1's self-mark. The self-mark version
     IS modelled and IS gated (`crcyc`, `cr3`); the domain version is
     not, so the one mechanism of this shape that has never been
     falsification-tested is the newest one.
  4. **The boundary LEG.** Revision 16 found by reading that an
     entry-only reading of §3.1 rule 3 falsifies W5-N's own soundness
     argument. A model with a return-leg boundary action would have made
     that a reachability question instead of a reading question.

  **Why it is ledgered and not modelled, honestly.** Three reasons, and
  none of them is "it is hard".

  First and decisively: **the mechanism has been DEFERRED out of the
  `systems.md` §12 refactor entirely**, by maintainer decision, to bead
  `stygia-qap` (§0.3, revision 16). It is unimplemented at HEAD —
  `memory/vmar.zig:1606`/`:1610` are empty `_ = cd;` stubs and
  `acquire_vmars` has no pause call at all — so nothing is being built
  against it and no step of §12 depends on it. **The model work belongs
  with that bead, and doing it now would put a validated model in front
  of a design decision the bead has not made yet** (the §11.13 call
  between gate-before-flush and re-deferral is open). G12 is the record
  that keeps the two in step.

  Second: the module is the artifact the kernel refactor is building
  against, and the extended battery that must re-validate any change to
  it takes hours under the one-JVM rule — so a module edit lands as its
  own revision with its own full battery, not as a side effect of a doc
  round.

  Third: modelling it properly is not a small delta. It needs a domain
  map, a `paused` word, a pauser role, a return-leg boundary action the
  model does not currently have (dispatch puts an EC `running` and user
  mode is implicit), and it multiplies the state space at exactly the
  scopes that already needed cuts.

  **The design, so the next revision is mechanical rather than
  open-ended.** Variables: `dom \in [ECs -> Domains]` (fixed at `Init`,
  no migration), `paused \in [Domains -> BOOLEAN]`, and `pauser \in
  [Domains -> ECs \cup {NULL}]`. Actions: `PauseStart(u, d)` — guarded
  on `dom[u] # d` (refusal 1), `~paused[dom[u]]` (refusal 2) and
  `~paused[d]`, sets `paused[d]` and `pauser[d] := u`; `PauseProceed(u)`
  — guarded on no `e` with `dom[e] = d` in `{running, ready, parking}`,
  the W5-N predicate; `PauseResume(u, d)` — clears the word, then 5a +
  edge 6 per gated EC; `BoundaryPause(e)` — the return-leg arm, an
  edge-3 park into `waiting("dpause")` guarded on `paused[dom[e]]`, at
  precedence below `BoundaryRetired` and the directive arm. Edge 1's
  `CreateEC` gains the gated-publish arm. Invariants:
  `InvNoPausedUserCode` (no `e` with `paused[dom[e]]` is `running` and
  past its gate), `InvNoPauseCycle`. Property: `LivePause` —
  `pauser[d] # NULL ~> ~paused[d]` — under a minimal fairness set, which
  per the standing methodology is the thing to get right first.
  Falsifiers, one per must-land, because a mechanism with no falsifier is
  decoration: **`dpub`** (edge 1 publishes `ready` into a paused domain —
  expect `LivePause` to fail, the pauser starves on a growing set);
  **`dcyc`** (drop refusal 2 — expect `InvNoPauseCycle` or a deadlock);
  **`dleg`** (gate on the entry leg only — expect `InvNoPausedUserCode`,
  which is revision 16's finding turned into a machine check).
  Expected cost: this is a 2c × 2e / 2-domain job. Do not attempt it at
  the `medium` scope. **Sequencing: this work is `stygia-qap`'s first
  step, not its last** — the bead exists because the mechanism is
  unimplemented, and the whole point of the deferral is that it gets a
  validated model BEFORE an implementation, which is the one discipline
  the reverted rev-7 refactor violated.
- **G13 (rev 14/16, MP — LEDGERED, not modelled; x64 writer gap closed in the scheduler-steal implementation).**
  **`current_queue_core` has no model field.** §3.4 gave it a row in
  revision 14 (1 byte, `NOT_IN_RUN_QUEUE` sentinel, written by the party
  holding the DESTINATION queue lock at the CAS-then-link of edges
  1/6/6p/8, cleared under the same lock on every exit from `ready`,
  valid iff `state = ready`), and the model has nothing corresponding.

  **Unlike G12 this one is close to harmless, and the reason is worth
  stating precisely rather than waving at.** The field is a **cache of a
  fact the model already represents exactly**: run-queue membership is
  `cores[c].q`, so "which core's queue is `e` in" is
  `CHOOSE c \in Cores : e \in cores[c].q`, computed rather than stored.
  Every model action that would write the field already updates the set
  in the same atomic step, including `StealClaim`'s victim removal and
  `StealAbandon`'s republish. A model field would be a redundant
  projection with no independent behaviour — adding it could only add
  states, never reachability. Marked MP rather than LP for that reason.

  **What is nonetheless LOST is the one thing that can actually go
  wrong**: the field is a *separate word* in the tree and the set is not,
  so **CACHE INCOHERENCE — the field disagreeing with real membership —
  is not expressible here.** §3.4 argues that away structurally (written
  and cleared only under the queue lock that owns the membership it
  names, in the same section as the state CAS, and a stale read is
  re-validated by §3.5's drop-and-retry). The known x86-64 IPC fast-path
  exception is closed: R13's direct ready enqueue and atomic-recv
  fallback now write `current_queue_core` to the local core id after the
  queue links/tail and before the core-lock release, and poison
  `owner_core` to `NOT_IN_RUN_QUEUE`. The model still cannot express a
  future incoherent cache writer without adding a second word, so the
  row remains MP and ledgered rather than modelled.
- **G14 (NEW, rev 16, LP — round-14 PARITY review's headline finding, and
  the one nobody would have caught by reading the model or the doc alone,
  because it is only visible where the two MEET).**
  **`PerCore.idle_parked` (§3.4) and §6.2's L3 — the locked park decision
  plus the wake-IPI rule — are normative, sit INSIDE the
  `<<< IMPLEMENTABLE SPEC >>>` markers, and have no model construct, no
  parity row and no ledger entry.** `grep idle_parked README.md` returned
  zero before this entry.

  **Why that is not merely another unmodelled row: a fairness constraint
  is standing in for the mechanism.** `LiveReady` (L3) is checked under
  `SpecL3`, which conjoins `FairDisp = SF_vars(DispatchOrS7(c,e))`, and
  the only justification this file gives for `FairDisp` is *"stands for
  the FIFO order the set-queue abstraction loses."* That is not what it is
  doing here. The failure L3 exists to foreclose is **a core parked with a
  non-empty run queue because no wake IPI was sent** — the lost-enqueue
  half of failure class 7. With no `idle_parked` and no IPI in the model,
  that state is **not representable**, and strong fairness on dispatch
  then *forces* the dispatch to happen regardless. So a green `LiveReady`
  is not evidence about L3's mechanism; it is evidence about a machine in
  which L3's failure mode cannot occur.

  **This is the VACUITY family wearing a fairness constraint's clothes,
  and that framing is the point.** The artifact already knows to ask "is
  the configuration this property is about actually REACHED?" — that is
  what every `pr*` probe exists for, and what round-10 M-D forced for
  `t1full`. G14 is the same question asked one level down: not *is the
  state reached*, but *is the failure the property forbids even
  expressible*. A probe cannot catch this one, because there is no state
  to probe for — the mechanism whose absence matters is an IPI that is
  never modelled. **The tell is generic and worth carrying forward: when a
  fairness constraint's stated justification is about ABSTRACTION LOSS
  (`FairDisp` "stands for FIFO order"), check whether it is also silently
  supplying the EFFECT of an unmodelled mechanism.** A constraint
  justified as recovering lost detail is doing something different from
  one that assumes a mechanism works.

  **What is LOST:** L3's mechanism — the locked park decision and the wake
  IPI — is unchecked at every scope, and the property named after it
  passes anyway. **Fix direction, for whoever models the domain pause
  (G12) and needs a boundary action anyway:** give `PerCore` a `parked`
  flag, make dispatch-from-parked require an explicit `WakeIpi` action,
  and re-check `LiveReady` under a `FairDisp` weakened to WF — then dial
  the IPI out as the falsifier. Until then, **do not cite a green
  `LiveReady` as evidence that L3 holds.**
- **G15 (NEW, rev 16, INC — round-14 parity review; RECORDED, not fixed,
  and the reasoning is the reason it is recorded).** **`InvS3` is
  NARROWER than S3, and the narrowing was unnamed.** The formula is
  `st \in {...} => ks = NULL`; S3's prose is a two-part implication whose
  **owner-identity half is UNREPRESENTABLE in this model**: `ks` ranges
  over `Cores \cup {NULL}`, a single core, so "two cores on one kstack"
  cannot be stated at all — there is no second slot to disagree.

  This is not an overstatement of what the battery checks. The half the
  design leans on for the Phase-3b barrier deletion is the STATE half,
  which IS checked and IS falsified by the `e4` gate — so the load-bearing
  claim stands. But it is an **unnamed narrowing of an invariant the
  refactor depends on**, and unnamed narrowings are exactly what this
  ledger exists to stop being unnamed.

  **Note the shape, because it is the same one that killed the idle EC
  (G7): a fact that cannot be stated because the state space has one slot
  where the design has two.** There the missing second slot was an EC per
  core; here it is a core per kstack. Any invariant whose prose quantifies
  over a PAIR should be checked against the model's arity before it is
  believed to be encoded.
- **G16 (NEW, rev 16, LP — preliminary reviewer parity blocker,
  LEDGERED, not modelled).** **`PerCore.teardown_pending` and
  `TeardownRequest` are normative in §2.3/§8.2 but have no TLA+ field.**
  The model represents the lifecycle consequence of teardown with
  `DomDie` (dead-domain marking) plus `RetireEC`; it does not represent
  the per-core park-stack handoff that carries the CD ref across the
  self-delete hop.

  **What is lost:** the model cannot check that the request is produced
  before self-retire, consumed exactly once on the park stack, or that the
  same CD ref is held across dead-mark and phase 2. Those are
  implementation-ordering facts below the current per-EC lifecycle graph.
  The marked spec now defines the payload shape directly:
  `{ kind: self_delete | no_route_fault, cd: SlabRef(CapabilityDomain) }`.

  **Why not model it here:** doing so properly needs the same domain
  structure G12 needs (`Domain`, CD refs, and scheduler-context phase-1/
  phase-2 ownership). A standalone Boolean would be a ledger-silencing
  token: it would not prove ref identity, exactly-once consumption, or
  dead-mark ordering. This gap should close with G12 / `stygia-qap`, not
  as a fake projection in the EC-only model.

## Validation gates — results

### Round 3 (rev-3 machine: `PENDED = FALSE, PIN_GATE = FALSE`)

- **X1** — `InvS4Holder` violated: e2's wake body claims parked e1, is
  requeue-preempted mid-body (no pin gate), hop places it `ready` with
  the claim held, retire's ready row inline-finalizes it. e1 orphaned in
  `claimed` forever, its holder freed.
- **X2** — hard deadlock: both cores mid-park in the pre-hop window; each
  core's tick claims the EC parked on the OTHER core and release-waits on
  its kstack release; each needed hop-release is the base continuation
  BENEATH the other core's live interrupt frame.
- **X3** — `InvNoLostOneShot` violated: a same-core interrupt fire on a
  mid-park EC declines after atomically consuming the one-shot pop; no
  retry party exists; the EC commits to `waiting` forever, line masked.

### Round 4 F1 (rev-4 machine: `F1_MODE` readings)

Rev 4 conditioned the hop's retired-arm `payload_done` wait on the hop's
own prior observation of `pended` — a fact retire destroys. Target claim
pins now close the old don't-wait UAF by making retire wait for the
pended claimant's target pin to drain; the always-wait reading still
fails:

- **f1a, don't-wait** — historically violated `InvNoUAF`: park; 5b pend
  (claimant mid-payload); retire (no W7); the owner's hop finalized with
  no wait. With target claim pins, the claimant pins the target until
  `payload_done`/holder discharge and `RetireEnabled` waits `pin = 0`, so
  the stale gate is now expected clean.
- **f1b, always-wait** — deadlock: retire of a plain `parking` EC (no
  claimant ever existed); the hop's retired arm waits on a `payload_done`
  with no writer; the owner core wedges.

### Round 7 C1 (`PIN_BUMP_FIRST = FALSE`)

- **pinord** — `InvNoPreemptedLockHolder` violated in **4 states**:
  dispatch e1; `PinAcq` takes the pin-class lock with the `pin_depth`
  bump not yet executed (`plk = "preB"`, `pin = 0`); `TickPreempt` reads
  `pin_depth == 0`, passes the §3.1 rule-1 gate, and wins the
  `running → parking(requeue)` CAS. The EC is now a requeue-preempted
  frame **holding a pin-class lock** — which is precisely the
  configuration T2's ready×K cell declares unreachable and retires
  inline on that basis. This is the resolution proof for §2.4's ordering
  rule.

### Round 7 C3 (`CYCLE_REJECT = "none"`, and `"pair"` at 3 ECs)

- **crcyc** — `InvNoSuspendCycle2` violated: with no rejection, two ECs
  are mutually suspending. The rev-7 machine's shape, reached in a
  handful of states.
- **crfals** — `LiveSuspender` violated, under `SpecSus` with NEITHER N6
  assumption and with the stale/bad-port owner-failure branch scoped out.
  This is the pair that matters: `cr1minself` PASSES the same focused
  obligation with the mechanism on, so the mechanism — not the assumptions
  — is what carries W5 at the calibration scope. The old drop-bearing
  `SpecFairN3` row is stale after dpin+dres: it reaches final temporal
  checking and does not converge under the runner cap.
- **cr3** — `InvNoSuspendCycle3` violated in **14 states** with the
  `"pair"` mechanism ENABLED, at 2 cores × 3 ECs:
  `DispatchEC, DispatchEC, DirClaim, TickPreempt, HopRelease,
  HopCommitRequeue, DispatchEC, DirClaim, TickPreempt, HopRelease,
  HopCommitRequeue, DispatchEC, DirClaim` → `e1.dsrc = e3,
  e2.dsrc = e1, e3.dsrc = e2`. Each suspender is requeue-preempted in
  `dirC`, freeing its core for the next — no exotic timing, just the
  preempt-requeue-dispatch cycle this machine runs constantly. The
  `"self"` mechanism holds at the same scope (`cr3self`, 109,626
  states), which is why it is the one recommended.

## Findings

### C1 (round 7, doc-side critical; model gained a gate) — an ORDER below the previous granularity

**What it is.** §2.4 said "incremented at claim-win and pin-class
acquire; decremented at discharge/release" and never ordered the bump
against the acquire. `lock(); pin_depth += 1;` is the default an engineer
writes. Pin-class locks are *by definition* not IRQ-masked at their
EC-context acquire sites — that property is what puts a class in the set
— so the gap between the two instructions is a live preemption point.

**Why the rev-7 battery could not see it.** `WakeStart` and `PinAcq`
fused the claim/acquire with the `pin+1`, so green transferred only to
bump-first implementations. Same category as round-6's M1 (the
publish-CAS/link order) — an ordering below model granularity.

**What rev 8 does about it.** Two different things for the two halves,
and the difference is the honest part:

- **Pin-class-lock half: now CHECKED.** `PinAcq`/`PinRel` gained a
  switchable split. Under `PIN_BUMP_FIRST` (the machine) they stay FUSED
  — and that is faithful, not a compression of the defect: under the
  normative order the intermediates are "pinned but not yet holding" and
  "no longer holding but still pinned", `pin_depth` is the only field any
  other action reads (it gates `TickPreempt`), so both intermediates are
  guard-equivalent to the fused state. Splitting them would add an
  interleaving point containing no observable work — exactly what the
  rev-6 sweep deleted with the pre-hop step. Under `~PIN_BUMP_FIRST` the
  half-states are real and `InvNoPreemptedLockHolder` fires in 4 states.
  **Cost of this addition to the machine's state space: zero** (the
  machine's `PinAcq` is unchanged; only a `plk` value renaming).
- **Claim half: NOT checked, and cannot be at this granularity.** A claim
  CAS happens inside an IRQ-masked reaching-lock section, which this
  model represents as one atomic action. Putting the bump "inside that
  section" is therefore true by construction in the model, and an
  implementation that puts it *outside* is not expressible. That half
  rests entirely on §2.4's sentence and the §9.2 assert. Recording it as
  checked would be exactly the round-4 parity failure repeated.

### C2 (round 7, doc-side critical; NO model impact, and that is the finding)

The doc contradicted the spec. §[priority]'s Description, verified
verbatim against `specv3.md`: *"If the target is currently suspended on a
port or waiting on a futex, the new priority takes effect immediately and
reorders the target into the appropriate priority bucket."* [test 06]
tests futex wake ordering AND `recv` selection ordering; [test 07] tests
effect at the next port event delivery / futex wake. Rev 7's §8.1 said
non-`ready` targets "take effect at their next placement".

Checked against the tree, because the severity depends on whether
selection re-reads the field: `PriorityQueue.enqueue` keys on
`@field(item, priority_field)` at LINK time and `dequeue` scans levels
without ever reading the item's priority (`sched/priority_queue.zig`);
`Port.waiters` is such a queue; futex waiters snapshot `.priority` into
the `WaitNode` at park (`sched/futex.zig:427,530`). So for a waiting
target "at the next placement" is not late — it is **never**.

**The model contributes nothing here** (ledger G9). Both corrected arms
are link repairs: state unchanged, container unchanged, only
intra-container position — the identity transition where queues are sets.
This is worth saying loudly because it is the shape of finding a green
battery is structurally incapable of catching, and the round-7 reviewer
found it by reading the spec, not by running anything.

### Round 9 (five criticals, none invalidating a mechanism)

The first round in which every critical was **text or apparatus**. That
is worth recording as a signal rather than a milestone: the mechanisms
had stabilised, and what remained wrong was what the artifact SAID and
what its tooling actually RAN.

- **C-1 — `dropped` had no clearing rule.** Round-8's M-3 added a fourth
  directive terminal and modelled it on `dead` — but `dead` is written by
  finalize on an EC being freed, so "never cleared" is correct THERE and
  was inherited without its justification. On a live EC it meant one
  stale-port drop left every future suspender's `none → claiming` CAS
  failing forever: the EC becomes **permanently unsuspendable**, i.e.
  permanently undebuggable, by ordinary means. The historical fix deleted
  `dropped`; the current implementation/model do **not** encode stale
  owner-side consume failure as success-like `armed -> none`. They publish
  `directive_result`, transition `armed -> failed`, and let the matching
  waiter read the result while failed and ack `failed -> none`. The ack
  deliberately does not clear `directive_result`, whose value may be stale
  outside `failed`. That keeps the deletion's benefit (no
  stuck stale terminal) without reintroducing false OK. Also fixed in the
  same word: §2.5's declaration comment was missing BOTH `suspending` and
  `dropped`, and §3.4's row — which S2 and analyzer 9.3(1) pin writers
  from — named two of the word's writer contexts.
- **C-2 — `run.sh` could not exit 0 and gated none of the new
  falsifiers.** See the note above; the script is rewritten against the
  real config set.
- **C-3 — two concurrent `priority` calls permanently desync the word
  from the bucket key.** No cycle, no mutual relationship, both callers
  need only `spri`: A writes 1, B writes 3, both drop the gen lock, B
  repairs the link to 3, A repairs it to 1. Final state `ec.priority == 3`
  with the linked key at 1, forever, because `dequeue` never re-reads and
  a parked waiter has no next link — and SILENT, since [test 08] reports
  field0 = 3 while selection uses 1. Round-8's C-2 defect in its
  concurrent form. Fixed with one clause that M-2 had already written for
  the other word: **the repaired key is a fresh read of `ec.priority`
  taken inside the innermost hold, never the value this call wrote**,
  mirrored for `affinity`'s claim-move destination.
- **C-4 — the IRQ state of EC context was never stated, and §12 removed
  the only place it was established.** The deepest one. Twelve normative
  arguments depend on EC-context frames being tick-preemptible — §3.1
  rule 1's existence, §2.4's C1 ordering rule (whose whole argument is
  "a live preemption point between the two instructions"), T2's ready×K
  row, §2.5's mutual-remote-suspend break, W3/W4/W5's "preemptible"
  columns, and the W3→W5 cycle break of M-1 — and the doc stated an IRQ
  state for scheduler context ONLY. What it did say pointed the other
  way, and the tree agrees: x86-64 `SYSCALL` clears IF via `IA32_FMASK`,
  and aarch64's only `daifclr` sites are `enableInterrupts` and the park
  primitives, so **syscall bodies run masked today** and §12 step 5
  deleted the last enable with no step adding one. **A green battery
  cannot catch this**: `TickPreempt` fires on any unpinned `running` EC
  regardless of frame state, so the premise is exactly what the model's
  atomicity grants for free. Fixed with a normative §3.3 rule, a §9.2
  spin-entry assert (IRQs enabled, not just `pin_depth == 0`), and a §12
  step-4 that ADDS the entry-path enable alongside the pin gate.
- **C-5 — domain restart is absent from the machine, and the DERIVATION
  METHOD is why.** `grep -ni restart systems.md` → zero, while
  `specv3.md` §[restart_semantics] is normative and per-EC
  (`0=kill / 1=restart_at_entry / 2=persist`). `restart_at_entry` has no
  edge — an EC in any state must be forced runnable with its frame reset
  to the entry point, which is not edge 6, not 7, not a claim-move — and
  `persist` keeps an EC running while its domain's VMARs are freed. **The
  instructive part is the method**: this README's sufficiency table was
  derived by walking the spec's SYSCALL list, and `§[restart_semantics]`
  is not a syscall section. **STATUS as of rev 16: `restart_at_entry` is
  no longer an obligation** — downgraded by maintainer decision once the
  tree showed only policy plumbing exists (see the sufficiency table).
  The FINDING is unaffected and is the reason this entry stays: what C-5
  caught was a derivation method, not a missing edge. A blind spot in the
  derivation, of which the
  missing rows are only a symptom. The table below is re-derived from the
  spec's SECTION list.

### C-1 (round 8, CRITICAL, LIVE IN THE TREE) — mutual terminate is a hard two-core deadlock

**The shape.** A and B each hold a `term` handle to the other, both
running. A retires B — B's kernel frame keeps running. B retires A. Both
enter the W3 eviction wait for the other. **A `retired` EC in a kernel
frame is moved by nothing**: the requeue CAS fails on `retired` (§3.1
rule 1) and rule 3's entry checks are user-boundary-gated only. Neither
ever leaves its core's `current` slot, so neither wait ever discharges.

**Why revision 8's model could not see it.** `Terminate` was ONE action
whose guard required the caller to be `running`, which made the caller's
own retirement *mid-syscall* inexpressible — and with it the entire
mutual shape. Revision 8 also excluded self-terminate outright, citing
§8.2. That citation was **wrong**: §8.2 is `delete(SLOT_SELF)` on a
capability *domain*, a different syscall, and `specv3.md` §[terminate]
licenses no error at all for a self target, so `terminate(self())` must
succeed and belongs in the model.

**Repair and confirmation.** `Terminate` splits into `TermStart` (guard
`st = "running"`, `pc → "termR"`) and `TermRetire` (guard `pc = "termR"`,
`st \in {running, retired}`), and self-terminate is now modelled.
Confirmed as predicted: **TLC reports a plain `Deadlock reached`, not
merely a `LiveTerm` violation, in 7 states** —
`DispatchEC, TermStart, DispatchEC, TermStart, TermRetire, TermRetire`,
ending with both ECs `retired`, both `pc = "termW"`, each naming the
other, each still `current` on its own core, and nothing enabled
anywhere. `mterm` is now a permanent falsifier; `mtermfix` is the same
scope with the repair dialed in (clean, 9,585 states).

**What the repair is.** Two exit conditions on the W3/W4 wait: the
**self carve-out** (target IS the caller — which the tree already has at
`execution_context.zig:1028`, and which revision 8's doc lacked
entirely, making the tree safer than the design), and the
**retired-waiter escape** (a terminator that has itself been retired
abandons the wait). The escape is sound because a retired terminator
never returns to user mode, so L5 has no observer; and safe because the
frame holds no claim (`pin_depth == 0` at spin entry).

### C3 (round 7, maintainer proposal) — suspend cycles: reject them, don't survive them

**The proposal.** Every directive-path liveness finding this project has
produced is the same shape. N1: two suspenders in the W5 wait, each
holding a pin-class lock, each unpreemptible under the pin gate — hard
deadlock. N6: two suspenders, one stalled at `claiming → armed`,
phase-locked away from the user boundary — livelock. Self-suspend is
trivial; third-party suspend is bounded by rule 3 at one unpinned tick.
**Symmetric suspend is the only shape that breaks.** So forbid it instead
of assuming it away.

**Why the naive form is wrong, and it matters.** "CAS the target's
directive only if it hasn't named me" does NOT work: the two intents live
in two different words (A arms B's, B arms A's), so both CASes can succeed
concurrently — the check A needs reads **A's own** word while A's action
writes **B's**. A correct mechanism must make a two-word check-and-act
indivisible. `CYCLE_REJECT` encodes three machines: `"none"` (the rev-7
machine, the falsifier), `"pair"` (the maintainer's two-gen-lock form),
and `"self"` (the refinement below).

**Result 1 — the mechanism works, and it retires BOTH N6 assumptions.**
Under `"pair"`/`"self"`, checked with **no `AlignmentAssumption` and no
`SF_vars(DirArm)`**. The current calibration rung uses `SpecSus`, the
per-property `LiveSuspender` fairness set (FairCPU, FairUnwind, FairDisp,
FairTick, FairSpinDir), so stale TermWait/Fire fairness instances do not
dominate the temporal phase:

- mutual suspend UNREACHABLE at 2×2, all features: **PASS** (now
  carried by `small`, which holds both cycle invariants).
- `crcyc` — same, mechanism dialed out: `InvNoSuspendCycle2` **violated**,
  so the check is load-bearing rather than decorative.
- `cr1minself` — `LiveSuspender` **PASS** at the focused no-drop scope.
- `crfals` — same focused obligation/fairness, mechanism dialed out:
  `LiveSuspender` **FAILS**. That failure is the proof that the mechanism
  and not the assumptions is carrying W5. The previous drop-bearing
  `SpecFairN3` calibration is now a stale gate: current TLC reaches the
  temporal phase (129,072 product states) and stalls there.

**Result 2 — but `"pair"` closes the SHAPE, not the CLASS.** The check is
pairwise, and a 3-cycle (a suspends b, b suspends c, c suspends a) passes
every pairwise test individually. `cr3` reaches one in **14 states** at
2 cores × 3 ECs with the mechanism enabled: `DispatchEC, DispatchEC,
DirClaim, TickPreempt, HopRelease, HopCommitRequeue, DispatchEC, DirClaim,
…` — each suspender requeue-preempted in `dirC`, freeing its core for the
next. Final state `e1.dsrc = e3, e2.dsrc = e1, e3.dsrc = e2`.
`InvNoSuspendCycle3` is that probe; it exists precisely because the
maintainer asked whether mutual suspend is the only cycle or just the
first one found. It is the first one found.

**Result 3 — `"pair"`'s lock order is an AB-BA against the existing
tree.** Audited rather than assumed, because no analyzer covers lock
order. Exactly one nested EC-gen-lock ↔ EC-gen-lock site exists in the
kernel: the x86-64 fast-suspend asm path, which takes `receiver_ec` then
`sender_ec` and holds both across the reply-handle mint. **It orders them
by ROLE, not by slot index** — so whenever `slot(sender) < slot(receiver)`
a slot-index rule takes the same pair in the opposite order. Today the two
sites cannot contend, because the fast path's receiver is `waiting` when
its lock is taken while both of `"pair"`'s ECs are `running` — but that is
a recall-closed universal over two code paths, which is this project's
documented failure mode. Compounding it: the asm comment claims the site
is tagged `ordered_group=2 (EC_NESTED_GROUP)`, and **`EC_NESTED_GROUP` is
defined nowhere in `kernel/` or `tools/`** — round-6 M2's tool-reality
drift, still live.

**Result 4 — `"self"` closes what `"pair"` leaves open, measured on the
same probes.** Same scopes, same invariants, mechanism swapped:

| probe | scope | `"pair"` | `"self"` |
|---|---|---|---|
| *(the `"pair"`-mechanism configs were deleted in revision 11; `small` carries both cycle invariants at the same scope)*
| `cr3` / `cr3self` | 2c × 3e, directive only | **`InvNoSuspendCycle3` VIOLATED, 14 states** | **PASS** (109,626 states, 2s) |
| `crcyc` (mechanism off) | 2c × 2e | `InvNoSuspendCycle2` VIOLATED | — |

**The refinement, and why it is recommended.** `"self"`: the suspender
first CASes **its own** word `none → suspending`, then the target's
`none → claiming`. A `suspending` word is not claimable, so no EC is ever
both a suspender and a suspend target — and every cycle, of every length,
is composed entirely of ECs that are both. One extra enum value, two
single-word CASes on words already in the protocol, **no second lock and
no lock order at all**, so Result 3 evaporates and Result 2 is closed by
construction. Modelled UNFUSED (two CASes on different words with no lock
between them), because fusing them would hide the real interleaving in
which both parties self-mark and both then fail — a legal E_BUSY pair, not
a wedge.

**How long the mark is held — traced, not assumed, because it sets the
E_BUSY rate.** `DirSelfMark` sets it; `DirClaim` and `DirArm`'s success
arm do NOT clear it; it is cleared only where the syscall RETURNS —
`DirSelfAbort` (CAS-2 failed), `DirArm`'s E_TERM arm, and both `DirLoop`
exits. So the mark spans the **whole syscall including the W5 wait**, and
the consequence is userspace-visible: **any two overlapping cross-EC
suspends can produce E_BUSY, cycle or not.** E_BUSY is an expected
outcome of concurrent suspends, not a pathological one — §11.8's proposed
spec text says so in normative language rather than in a note, because
the difference is whether a debugger author writes a retry on purpose or
discovers one in production.

Cost, stated: `"self"` rejects three cases where `"pair"` rejects one —
(1) the symmetric case, (2) a target that is mid-suspend of an unrelated
third EC, (3) a caller that is itself someone's suspend target. An
early-release variant (clear the mark right after the target-claim CAS)
would make E_BUSY rare and appears to remain correct by a longer
argument — a claimed EC cannot self-mark, and every participant in a
cycle is claimed — but that is a multi-step reachability claim, where
held-for-the-whole-syscall is the one-sentence invariant the model
actually checks. Recorded in §2.5.1 as the optimisation to evaluate IF
the E_BUSY rate matters, with its own model run required first.

### N1 — T3 rule (b) is load-bearing for W5, and F3 widened its blast radius

With pin-class locks modelled and no spin-entry assert, TLC finds in
seconds: two suspenders mutually in the W5 directive wait, each holding a
pin-class lock, each therefore UNPREEMPTIBLE under the very pin gate F3
introduced — a hard cross-core deadlock. **Rev 6: CLOSED** — §2.5/§3.6/§9.2
make the spin-entry `pin_depth == 0` assert normative. Enforcement honesty
(per the doc): the assert is runtime today; static entry-context
pin-freedom checking is a FUTURE 9.3(6b) obligation, not a current
capability. **Rev 8 note:** C1 is N1's neighbour — N1 says the spinner
must not be pinned, C1 says the pin must be *taken* before the thing it
protects. Both are about `pin_depth` meaning what it claims to mean at
every instant, and neither is enforced by anything but an assert today.

### N2 — my own narrowing, caught by TLC

Encoding `DirLoop`'s break as `dir \in {none, dead}` (the doc's enumerated
outcomes) instead of the literal `dir # armed` produced a 3-party wedge.
The literal loop dissolves it. Kept as the worked example of why the
parity rule says LITERAL — in both directions.

### N3 — W3/W4/W5 bounds assume no adversarial tick alignment

Under disjunction-level fairness TLC exhibits a schedule where the
preempt-requeue-dispatch cycle always lands before the terminate-wait's
recheck executes. **Rev 6: documented** in §3.6. **Its immunity claim
("pinned continuations are immune") was later FALSIFIED by N6** and is
corrected in place in the doc rather than quietly edited out.

### N4 — retire's unwind vs routed finalize: asserted, not enforced

§8.2 (rev 5) ordered the container unwind INSIDE retire and listed
"container unwind complete" as a finalize precondition — with no mechanism
making the hop's deliberately wait-free retired arm wait for it. TLC, 6
states: the EC is FREED while still linked in its wait containers.
**Rev 6: CLOSED with a mechanism simpler than either review candidate** —
retire's unwind step is DELETED; the idempotent unwind is finalize's first
act. The dual-unwinder candidate was rejected: the second unwinder must
read the EC's descriptor to discover it has nothing to do, against a slot
the first-to-free may already have zeroed.

### N5 — the disarm path alone cannot carry W5's termination

A 24k-state lasso where the suspend TARGET duty-cycles pin-class acquires
(unpreemptible inside each hold), phase-locked so the suspender's disarm
arm is never enabled while the suspender runs, and the armed directive is
never consumed because the model treated boundary consumption as optional.
That last part was model infidelity: §3.1 rule 3 fires the directive arm
on EVERY entry from user mode, and each of the lasso's ticks IS such an
entry. Fix (module, mechanism B — deliberately NOT `SF(DirConsume)`, which
would force a documented-unforced request): `TickPreempt` gained the rule-3
arm, so consumption's eventuality rides the already-justified
`SF(TickPreempt)` with NO new fairness constraint. The old README rationale
("the disarm path must carry W5 alone") is REFUTED by the lasso and
corrected here, not papered over. **Round 7 M-5 completed this**: the fix
lived only in the model and in W5's boundedness column; it is now a doc
RULE (§3.1 rule 3's precedence paragraph) with a §9.2 assert, because an
implementer who wires entry checks into syscall entry but leaves the tick
requeue-first reintroduces N5 with the battery still green.

### N6 — mutual suspend, half-armed: two more starvation faces

Post-N5, a NEW lasso on the full space: both ECs suspend each other; one
arms and enters `dirW`; the other's `DirArm` — the `claiming -> armed`
continuation of an already-started suspend syscall — is starved because
every dispatch is tick-preempted before the store executes. Its `dirC`
frame is a KERNEL frame, so rule 3 correctly never consumes the armed
directive sitting on it. The armed side's disarm arm needs holder-current
AND target-off-CPU simultaneously — phase-locked away, and no action
fairness can force an enabledness. The model is FAITHFUL; the property
over-promised relative to the STATED assumptions. Resolution: doc §3.6
corrects N3's falsified immunity claim in place and states the true
assumptions; the model adds `SF_vars(DirArm)` (a continuation, not a
request) and the named `AlignmentAssumption` conjoined visibly in
`SpecFairAligned` — never folded into `Fairness`. **Round 7's measurements
turn N6's resolution into an open question of its own; see the fairness
section and the honest-confidence section.**

## Removals exercised (the simplicity direction)

Each tried against the full battery + all falsifiers:

- **Retire's separate unwind step** — REMOVED (the N4 resolution; a
  doc-level deletion, not just model state).
- **`timed` descriptor mirror field** — REMOVED: write-only in the model.
- **The dedicated zero-work pre-hop step** — REMOVED: it added an
  interleaving point containing no work.
- **The staged placement destination `dst`** — **REMOVED in rev 8**
  (round-7 M-2). It was the only consumer of claim-time staging, it
  contradicted §8.1's fresh-descriptor rule, and it erased ghost G2. Its
  removal also made every placement's destination a placement-time
  choice, which is what an affinity edit landing mid-flight requires.
  **Measured effect on the battery: safety state spaces fell 39–87%**
  (small 87,384 → 53,552; medium 4,974,418 → 3,027,554; large 101,459 →
  19,968; xlarge 1,330,422 → 168,882), and every liveness run got
  correspondingly cheaper. A deletion that makes the artifact both
  simpler and more checkable is the ideal shape of this exercise.
- **The model's `mo`/`mk` boolean pair** — **REMOVED in rev 8**,
  collapsed into the single `mo` bit the doc acquired (M-3). Two
  booleans encoded four combinations for a three-valued fact.
- **The second `priority` mechanism** — **REMOVED in rev 8** (C2/M-6).
  Rev 7 offered "5c-claim + edge 6, **or** an equivalent in-lock
  re-bucket" — two mechanisms, different lock footprints, different races
  against dispatch. Only the in-lock relink survives, and the general
  rule it instantiates (same container ⇒ in-lock relink; different
  container ⇒ claim-move) also explains why `affinity` keeps the
  claim-move.
- **`AlignmentAssumption` + `SF_vars(DirArm)` (both N6 assumptions)** —
  **REMOVABLE as of round 7's C3**, and this is the largest deletion in
  the artifact's history: it removes an ASSUMPTION from the trusted base
  rather than a construct from the model. Under `CYCLE_REJECT`,
  `LiveSuspender` holds under the focused `SpecSus` rung, which contains
  neither. Held in the module for now only because they define the rev-7
  machine that the `crfals` falsifier dials to; delete outright if the
  maintainer takes the §11.8 spec change. Secondary win, measured before
  dpin+dres: without the raw `[]<>` conjunct the minimal rung ran in 13s
  instead of 2min03s.
- **`pended` / W7** — removal REJECTED: dialing either out is exactly the
  rev-3 / rev-4-F1 machine and the corresponding falsifiers fire.
- **Directive `claiming` / `dead`** — removal REJECTED on protocol
  grounds (port-write exclusivity; retired-vs-consumed
  distinguishability), NOT battery evidence. Honest status: the battery
  would stay green without them.
- **Proposed, NOT adopted and NOT battery-tested (maintainer call,
  §11.3)**: collapse the eager/deferred marking split to always-deferred.
  Plausibly correct by the same discharge argument, but it lengthens
  terminate's return bound and touches §[terminate] test-07 timing — an
  API-visible change this exercise does not own.

## Fairness (liveness runs) — each assumption argued

Three fairness sets exist. `SpecFair` carries every constraint below;
`SpecFairCore` omits the two per-spin SFs (the N3 assumptions) and is used
for the groups that do not check `LiveTerm`/`LiveSuspender` — a property
passing under the weaker set is the stronger result. `SpecFairAligned`
adds the named `AlignmentAssumption`.

- `SF_vars(BaseStep(c))` — a CPU executes its enabled continuation; STRONG
  because interrupt frames repeatedly de-enable base steps, and under WF an
  infinite interrupt storm legitimately starves the hop. **This IS §3.6's
  third assumption** (round-7 minor: rev 7 said the assumption set was
  complete at two and it was not — the no-storm premise was always here,
  just uncounted). `BaseStep` contains only continuations of already-started
  bounded work, never new requests — including rev 8's `PinBump` and
  `PinUnlock`, which complete a pin-class lock episode whose `lock()` has
  already succeeded, and which are disabled entirely under
  `PIN_BUMP_FIRST` (they exist only in the C1 falsifier machine, whose
  configs are safety-only anyway).
- `SF_vars(TermWait(c))`, `SF_vars(DirLoop(c))` — per-spin SF for the two
  deliberately-preemptible waits (N3): tick period >> one recheck.
- `SF_vars(DirArm(c))` — per-continuation SF (N6 face (i)): `DirArm` is
  bounded, already-committed work — the same category as
  `BaseStep`/`TermWait`/`DirLoop`, not a request.
- `WF_vars(IrqStep(c))` — a live handler frame is the only runnable thing
  on its core (L6 straight-line bodies).
- `SF_vars(TickPreempt(c))` — the periodic timer fires.
- `SF_vars(DispatchOrS7(c,e))` — stands for the FIFO order the set-queue
  abstraction loses.
- `SF_vars(FireAny(e))` — armed T1 sources eventually fire.
- `WF_vars(RetireUnwind(e))` — retire step 3 is the retirer's synchronous
  continuation (rev-5-literal machine only).
- **No fairness** on `UserPark`, `WakeStart`, `SuspendStart`, `RecvPop`,
  `FastPath`, `ReplyFP`, `RvStart`, `DirClaim`, `DirConsume`, `PinAcq`,
  `CreateEC`, `Terminate`, `RetireEC`, `AffMove`, `DomDie`: new requests,
  and forcing them could mask liveness bugs. N5's lesson lives elsewhere:
  directive consumption's EVENTUALITY is carried by `TickPreempt`'s rule-3
  arm under the existing `SF(TickPreempt)`, never by forcing
  `DirConsume`.

### `AlignmentAssumption` — not fairness, and provably not expressible as fairness

Stated: *a `dirW` holder whose target's directive stays armed is
infinitely often scheduled while its target is off-CPU.* It is conjoined
only in `SpecFairAligned`, the `LiveSuspender` configs' spec, so a reader
who asks what a green run assumed finds it in the SPECIFICATION NAME the
cfg declares.

**Why it cannot be a ghost-fairness action — the argument, restated
tightly because round 7 asked for it to be re-attempted.** The premise is
`[]<>P` for a state predicate P: an *unconditional* recurrence.
`WF_vars(A)` and `SF_vars(A)` — the two forms TLC special-cases and routes
past its general tableau — are both *conditional on `ENABLED A`*:

  `SF_vars(A)  =  []<>ENABLED<<A>>_vars  =>  []<><<A>>_vars`

Every such formula has enabledness in the ANTECEDENT. So:

1. A ghost action `G` that is a no-op on `vars` has `<<G>>_vars = FALSE`,
   hence `ENABLED<<G>>_vars = FALSE`, hence `SF_vars(G) = TRUE`
   vacuously. Useless.
2. Give `G` a ghost variable to toggle and subscript the fairness with
   `<<vars, g>>`. Then `ENABLED G = P`, and
   `SF_{<<vars,g>>}(G) = ([]<>P => []<>G-taken)`. Since `G` is taken
   whenever `P` holds and nothing blocks it, this reduces to `[]<>P =>
   []<>P` — a tautology, and vacuously satisfied in exactly the starved
   lassos the premise exists to exclude. Useless.
3. Make the ghost FORCE `P` — i.e. guard real actions on ghost state so
   that a run of `~P` cannot continue. This is no longer an assumption
   but a *state-graph restriction*: it prunes reachable behaviors, which
   invalidates the transfer of the safety verdicts obtained on the
   unrestricted graph, and it asserts a strictly STRONGER premise
   (bounded-K misalignment rather than infinitely-often alignment). It
   also widens the graph with the counter.
4. Note the same argument applies to the real `DirLoop` disarm arm: the
   assumption is precisely `[]<>ENABLED(disarm)`, which is the antecedent
   of the `SF(DirLoop)` we already have. Adding SF to a finer-grained
   split of `DirLoop` therefore buys nothing — in N6's lasso the disarm
   arm's enabledness is never true, so any SF over it is vacuous.

There is no fourth option. The premise rides TLC's general tableau.

**What WAS re-attempted in round 7, and measured.** The one
transformation that is genuinely cost-relevant without changing the
formula is *placement*: `Spec /\ Assumption => Live` and
`Spec => (Assumption => Live)` are the same formula but not the same job
for TLC (spec-side raw `[]<>` conjunct versus implied-temporal
antecedent). `LiveSuspenderAligned == AlignmentAssumption => LiveSuspender`
and `ECLifecycle_c1tp.cfg` exist to measure exactly that against `c1t`.
The result is in the coverage table; whichever way it lands it is a
measurement, not a weakening — the assumption is still named, still
stated in full, and still one hop from the config.

**Consequence, and it now feeds a maintainer decision.** `LiveSuspender`'s
verdict is deliberately LADDERED across scopes, and round 7 added rungs to
narrow the band between the last PASS and the full scope. A mechanism
whose correctness rests on a premise that cannot be checked at the scope
the rest of the battery runs at is a real argument for a design that needs
no premise at all.

**STATUS after round 7's C3 — this whole subsection is on its way out.**
Symmetric-suspend rejection makes the premise unnecessary: with
`CYCLE_REJECT` on, `LiveSuspender` holds under the focused `SpecSus` rung,
which contains neither N6 assumption. The measured consequence before
dpin+dres was the one predicted above — with the raw `[]<>` conjunct gone,
the minimal rung dropped from **2min03s to 13s**. After dpin+dres, the old
drop-bearing `SpecFairN3` calibration became a stale gate, so
`crfals`/`cr1minself` now use the no-drop `SpecSus` scope: `crfals` still
fails and `cr1minself` still passes. `AlignmentAssumption` and
`SpecFairAligned` survive in the module only to describe the **rev-7
machine** (`CYCLE_REJECT = "none"`). If the maintainer takes the spec
change (§11.8), the assumption should be deleted outright and this
subsection kept only as history — including the impossibility proof above,
which stays true and is the reason nobody should try the ghost-fairness
route again.

## Results

### Revision 15 recorded battery, plus revision 16 recovery deltas

**`./run.sh` exits 0 against model revision 15 — verified, not
asserted.** Transcript: `out/rev15_runsh_EXIT0.txt` (`RESULT: OK`,
`RUNSH_EXIT=0`). `out/` is gitignored, so the durable copy of these
verdicts is the commit message of the revision-15 commit.

**Scope of that exit-0, stated exactly, because it is not the whole
battery.** The recorded revision-15 DEFAULT battery was **29 configs +
sany**: 14 falsification gates, 5 reachability probes, 6 safety configs,
4 liveness configs. Revision 16's runner adds `t1d_min` and `pr4d_min`, and the
dpin recovery reclassifies `dirf6` as expected-clean, and dpin+dres move
the `LiveSuspender` calibration pair (`crfals`/`cr1minself`) to a focused
no-drop `SpecSus` scope, making the current default **31 configs + sany**:
12 falsification gates, 2 stale-gate closures (`f1a`, `dirf6`), 6
reachability probes, 6 safety configs, and 5 liveness configs. Six
further configs live in `run.sh` behind `RUN_XLARGE=1` / `RUN_SLOW=1` —
`xlarge`, `t1full`, full `t1d`, `cr1fullself`, `liveness_a`,
`liveness_b`. `t1full` and full `t1d` are measured-unconverged rows, not
green liveness verdicts. The remaining revision-11 figures are **STALE**:
they have not been re-run since the model gained six per-EC fields in
revisions 11–13 (`gen`, `dgen`, `dlv`, `pok`, `dfs`, `dbad`). Treat each
stale row as having NO verdict on the current machine until the extended
battery lands here. `crfals` is the calibration point for how large that
gap is: the old config now reaches final temporal checking at 129,072
product states and stalls there under the runner cap.

Round-16 gate split: the old default `medium` safety row is replaced by
`medium_nodir`. Full `medium` remains on disk as an extended/manual
target, but it is not current default evidence because the dpin/dres graph
was stopped after more than an hour at ~598M generated / ~133.6M distinct
/ ~11.9M queued states.

| | Config | Latest recorded verdict / current runner expectation |
|---|---|---|
| syntax | `sany` | PASS |
| gates | `x1` `x2` `x3` `f1b` `n4` `e4` `pinord` `crcyc` `cr3` `crfals` `mterm` `diraba` | **all 12 FIRED** |
| stale-gate closure | `f1a` / `dirf6` | **PASS** under target claim pins / dpin |
| probes | `pr1`–`pr5` | **all 5 FIRED** (the violation IS the pass) |
| safety | `mtermfix` | PASS 9,585 |
| | `dirf6fix` | PASS 483,636 |
| | `small` | PASS 2,957,560 |
| | `large` | PASS 68,733 |
| | `cr3self` | PASS 6,179,060 |
| | `medium_nodir` | PASS 125,570 (targeted 2026-08-03, 3g/2 workers, 5s) |
| liveness | `t1min` / `t1s` / `t1r` | PASS 9,585 / 10,237 / 11,969 |
| | `t1d_min` | PASS 596,529 (targeted 2026-08-03, 3g/2 workers, 52m39s; 1,193,058 product states) |
| probe | `pr4d_min` | **FIRED** `ProbeNoTermSuspendCycle` (targeted 2026-08-03, 3g/2 workers, 3,446 distinct) |
| | `cr1minself` | PASS 79,936 (focused `SpecSus`/no-drop scope; 3m57s at 3g/2 workers) |
| **not run / stale** | `xlarge` `cr1fullself` `liveness_a` `liveness_b` | **NO CURRENT VERDICT** |
| **manual extended** | `medium` | **NO CURRENT DEFAULT VERDICT**; stopped 2026-08-03 at ~598M generated / ~133.6M distinct / ~11.9M queued |
| **manual extended** | full `t1d` | **MEASURED UNCONVERGED**; reached final temporal checking at 1,548,068 distinct / 3,096,136 product states, then timed out |

**Revision-16 `t1d_min` / `pr4d_min` recovery verdict.** The default
directive-bearing `LiveTerm` rung is now the bounded pair
`ECLifecycle_t1d_min.cfg` / `ECLifecycle_pr4d_min.cfg`: 2 cores x 2 ECs,
`TERM_BUDGET = 2`, `DIR_ON = TRUE`, `DIR_OWNED = TRUE`,
`DIR_GENCHK = TRUE`, dpin/dres/failed semantics intact, and unrelated
multipliers off (`SUSPEND_ON = FALSE`, no fast path, rendezvous,
pin-lock episodes, S7 route, drop budget, or slot recycling). Targeted
low-worker validation on 2026-08-03 (`TLC_HEAP=3g`, `TLC_WORKERS=2`)
PASSed `t1d_min`: **596,529 distinct states**, **1,193,058** product
states, temporal phase 51m38s, total 52m39s (`out/t1d_min_target.log`).
Its paired probe `pr4d_min` FIRED the expected
`ProbeNoTermSuspendCycle` violation at **3,446 distinct states**
(`out/pr4d_min_target.log`). So the bounded row is both clean and
non-vacuous over the W3 -> W5 -> W3 shape it exists to cover. This is a
targeted verdict, not a full default-battery transcript; a fresh
`./run.sh` exit-0 is still the durable battery gate.

**What moved and what was lost.** Full `ECLifecycle_t1d.cfg` remains on
disk, with full `ECLifecycle_pr4d.cfg` as its exact mirrored probe, but
it is not a default gate and must not be cited as a PASS. The current
full row reached final temporal checking at **1,548,068 distinct /
3,096,136 product states** and then timed out. The bounded default pair
proves `LiveTerm` with the directive protocol live and proves the
terminate/directive cycle is reachable at exactly those bounded
constants. It does **not** recover a full 2c x 2e directive liveness
verdict with non-directive suspend, drop budget, or any unrelated feature
multiplier enabled.

**Current Dewey-parity run (2026-08-03).** `TLC_HEAP=3g TLC_WORKERS=2
./run.sh` previously failed only because the runner still expected
`dirf6` to fire. `dirf6` is now clean (524,888 distinct states) because
the model includes the directive waiter's running-target pin, so the old
terminate/finalize/reuse false-success trace is blocked before the
target can be finalized. The runner now treats `dirf6` as an expected
stale-gate closure. A fresh full `TLC_HEAP=3g TLC_WORKERS=2 ./run.sh`
exit-0 is still the durable battery gate.

**Revision-16 medium split verdict.** `ECLifecycle_medium_nodir.cfg`
keeps the old 2c × 3e / `TERM_BUDGET = 2` aggregate shape with
`RV_ON`, `PINLOCK_ON`, `S7_ON`, `FASTPATH` and `SUSPEND_ON` enabled, but
sets `DIR_ON = FALSE`. A targeted low-worker run
(`TLC_HEAP=3g`, `TLC_WORKERS=2`) PASSed in 5s with **562,109 generated /
125,570 distinct / 0 queued** states (`out/medium_nodir_target.log`).
This is the replacement default safety row. It is not a statement that
the full directive medium graph passed.

No separate default 2c × 3e directive+terminate-only row was added. The
directive terminate concern is covered by the `t1d_min`/`pr4d_min` pair:
`t1d_min` is the bounded directive-bearing `LiveTerm` verdict and
`pr4d_min` proves the W3 -> W5 -> W3 shape is reached at the matching
constants. The remaining directive safety concerns live in `diraba`,
`dirf6`, `dirf6fix`, and `small`. Adding another cheap default row with
RV/pin-lock/S7 disabled would duplicate that targeted evidence and still
would not restore the lost aggregate fact below.

**Revision-16 `cr1fullself` recovery classification.** The old
`LiveSuspender == pc = "dirW" ~> pc # "dirW"` property fails at full 2x2
on the current graph. The counterexample is not a missing W5 discharge:
the suspender enters `dirW`, is tick-preempted and requeued, then another
EC suspends it into `waiting` while the original target retires/frees.
At that point the saved continuation is still `dirW`, but the suspender
is no longer executing and no modelled rule promises a future user resume
request. The revised property treats `waiting`/`claimed`/`pended` and
`retired`/`freed` as legitimate external exits, matching the scoping
style of `LiveReady`'s claim/retire exits rather than assuming progress
for an EC another lifecycle operation has parked or killed. This is a
model/spec correction, not a lifecycle bug mask; a fresh full
`cr1fullself` verdict for the widened property is still an extended-run
claim and must be recorded separately when run.

**VACUITY DISCLOSURE — which invariant lines are DEAD at which scope
(revision 16, round-14 parity review).** Revision 15 disclosed this for
`dirabafix` alone and reported the rest as unqualified PASS, and "PASS"
reads as coverage. **DERIVED, not hand-written**: for each config, the
`INVARIANT` lines are read from its `.cfg` and each is matched against the
switch its predicate's fields depend on, taken from `ECLifecycle.tla`.

| config | invariants | dead | why |
|---|---|---|---|
| `small` | 17 | **2** | `InvNoSuspendCycle3` (a 3-cycle needs 3 ECs; has 2) · `InvNoForeignDisarm` (M-3: under `DIR_OWNED = TRUE` the disarm guard forces `dsrc = u`, so the update term is identically FALSE) |
| `medium_nodir` | 14 | 0 | directive invariants are deliberately absent, not counted as covered |
| full `medium` | 17 | **1** | extended/manual only; `InvNoForeignDisarm`, same M-3 argument |
| `large` | 14 | **3** | `DIR_ON = FALSE` kills `InvNoArmedFreed` and `InvNoFalseSuspendSuccess` · `PINLOCK_ON = FALSE` kills `InvNoPreemptedLockHolder` |
| `xlarge` | 14 | **3** | identical to `large` |
| `cr3self` | 3 | 0 by switch analysis, **but see below** | |
| `mtermfix` / `dirf6fix` | 1 / 2 | 0 | |

**Coverage ledger for the demoted full `medium` row.** Every invariant
that was live in the old default `medium` has a replacement row, but the
replacement is now a split rather than one aggregate pass:

| old live `medium` fact | current default/replacement evidence |
|---|---|
| `TypeOK`, `InvS1`, `InvS3`, `InvS4Holder`, `InvS4Pended`, `InvPinCells`, `InvHopUnpinned`, `InvNoLostOneShot`, `InvHopNoClaimedOutgoing`, `InvRetiredPdOrdered`, `InvNoUAF` | `medium_nodir` at the same 2c × 3e / term-2 aggregate scope |
| `InvNoPreemptedLockHolder` | `medium_nodir` keeps `PINLOCK_ON = TRUE`; `pinord` is the load-bearing falsifier |
| `InvNoSuspendCycle2`, `InvNoSuspendCycle3` | `medium_nodir` keeps suspend enabled at 3 ECs; `crcyc`/`cr3` are the load-bearing falsifiers and `cr3self` keeps the focused 3-cycle row |
| `InvNoArmedFreed` | `small` remains the default all-feature clean row; there is no current default 3-EC aggregate directive pass |
| `InvNoFalseSuspendSuccess` | `dirf6`/`dirf6fix` carry the targeted false-success closure and repair check; `small` remains the all-feature clean row |

**Lost fact, stated plainly:** no default config is now "3 EC, all
features, one aggregate pass." The default evidence is deliberately split
between `medium_nodir` for the 3-EC non-directive aggregate, `small` for
the all-feature aggregate at 2 ECs, and the directive-specific rows.

**None of this is wrong and every dead line has its falsifier elsewhere**
— `InvNoSuspendCycle3` fires in `cr3`, `InvNoForeignDisarm` in `diraba`,
`InvNoPreemptedLockHolder` in `pinord`; `InvNoFalseSuspendSuccess` is
covered by the `dirf6` stale-gate closure, `dirf6fix`, and the
directive-bearing replacement rows. The point is that the coverage
lives in the targeted rows, not in a single clean aggregate row, and a
results table that prints "PASS 2,957,560" invites the opposite reading.

**`cr3self` needs the argument the script cannot make.** Switch analysis
finds nothing dead, but its two cycle invariants hold **by construction**
under `CYCLE_REJECT = "self"` — the mechanism is what makes them true, so
the clean run establishes `TypeOK` and deadlock-freedom at 3 ECs and is
not independent evidence about cycles. `crcyc` and `cr3` carry that
content. This is the same shape as M-3's argument and it is
mechanism-analytic rather than switch-analytic, which is exactly the class
a derived check cannot reach — noted so the gap in the derivation is
visible rather than implied.

**DETERMINISM — measured, and it is the only such evidence the battery
has (revision 16).** The default battery has now been run **twice
independently** against revision 15: once as `./run.sh`
(`out/rev15_runsh_EXIT0.txt`) and once as the leading phase of
`RUN_XLARGE=1 RUN_SLOW=1 ./run.sh` (`out/rev15_full_battery.txt`), hours
apart, on a host whose load differed substantially between them (the
second overlapped three full `tests/precommit.sh` gauntlets). Diffing the
verdict lines of the two transcripts, restricted to the 29 default
configs plus `sany`, gives **zero differences — all 30 lines identical,
every distinct-state count bit-for-bit**, including `medium` at
37,637,315 and `cr1minself` at 58,600.

Why this is worth recording rather than assuming: TLC is parallel
(`-workers 4`) and its state-queue order is not deterministic, so
identical *counts* are a real result about the search being exhaustive
rather than an obvious one. **The consequence is what matters — a future
run that disagrees with these numbers is a genuine change in the model or
the config, not scheduling noise.** Without this measurement, any future
discrepancy would have had two explanations and no way to choose between
them.

**Three configs carry documented scope cuts, and the cut is written into
the `.cfg` file, not only here.** `cr3self` and full `medium` set
`DIR_DROP = FALSE`; `medium_nodir`, full `medium` and `xlarge` set
`CR_BUDGET = 0`. What is
LOST, stated as the discipline requires: with `DIR_DROP = FALSE` the
stale/bad-port owner failure path is not exercised **at 3 ECs** — it is
covered at 2 by `dirf6`/`dirf6fix`, so a defect in that path that needs a
third EC to construct would not be found; with `CR_BUDGET = 0` there is **no slab
reuse at all** in those runs, so every ABA shape that depends on a
recycled slot is unreachable there — which is precisely the family
`gen`/`dgen` exist to guard, and it is covered only at the smaller
scopes. The full directive medium split was also forced: after dpin/dres,
the old default full `medium` run was stopped after more than an hour at
~598M generated / ~133.6M distinct / ~11.9M queued states.

**`dirabafix` is on disk and NOT in `run.sh`** (`run.sh:156-166`), and
the reason is round-12 M-3's own finding: under `DIR_OWNED = TRUE` the
disarm guard forces `dsrc = u`, so `InvNoForeignDisarm`'s update term is
identically FALSE and the invariant holds **a priori**. A clean run would
establish `TypeOK` and deadlock-freedom at that scope and say nothing
about the ownership mechanism. The falsifier `diraba` is the whole of
that gate's content.

### Revision 11 — superseded figures, kept for the growth record

**Everything in this subsection is a REVISION-11 verdict.** It is kept
because the state-space growth across revisions is itself evidence — a
green run on a smaller space was green about less — and because the
`t1full`, `liveness_a`, `liveness_b` and `cr1fullself` analysis below is
the only analysis those configs have. **Do not cite any number here as a
statement about the current machine.**

**Revision 10 made NO model change at all, so no revision-11 verdict went
stale at the time.** Round 9's five criticals were text and apparatus: the one that
looked like a machine change — deleting the directive word's `dropped`
value (C-1) — turned out to be doc-only, because `dropped` was never
modelled in the first place (see the parity-gap row above). `ECLifecycle.tla`
is byte-identical to the module the revision-9 battery ran against, and
every figure below is from that battery. This is the first revision in
this artifact's history where that is true. The machine the battery blesses is
`TERM_ESCAPE = TRUE`,
`CYCLE_REJECT = "self"`, `PIN_BUMP_FIRST = TRUE`, `F1_MODE = "rev5"`,
`FIN_UNWIND = TRUE`, `E4_AT_HOP = TRUE`. Every other setting names an
older or defective machine and is a gate.

**State spaces GREW sharply from revision 8** — `small` 56,726 →
181,326, `large` 19,968 → 68,733, `xlarge` 168,882 → 732,044, `medium`
2.5M → 30.9M. That is the C-1 repair working: splitting `Terminate` and
admitting `terminate(self())` makes reachable a whole family of
behaviours revision 8 could not express. A green run on the smaller
space was green about less.

**Falsification gates and stale-gate closures — each live falsifier must
FIRE with its own violation string; `f1a` and `dirf6` are expected-clean
closures under target claim pins and dpin respectively.**

| Gate | Machine dialed to | Expected violation | Verdict |
|---|---|---|---|
| `x1` / `x2` / `x3` | rev 3 | `InvS4Holder` / deadlock / `InvNoLostOneShot` | FIRED (2,501 / 612 / 54) |
| `f1a` / `f1b` | rev 4 F1, both readings | clean stale-gate closure / deadlock | PASS (3,944) / FIRED (487) |
| `n4` | rev-5 literal unwind ordering | `InvS1` | FIRED (556) |
| `e4` | publish-claimable-before-hop | `InvS3` | FIRED (20) |
| `pinord` | `lock(); pin_depth += 1;` (round-7 C1) | `InvNoPreemptedLockHolder` | FIRED (82) |
| `crcyc` | no cycle rejection (round-7 C3) | `InvNoSuspendCycle2` | FIRED (884) |
| `cr3` | `"pair"` rejection at 3 ECs (round-7 C3) | `InvNoSuspendCycle3` | FIRED (40,498) |
| `crfals` | no cycle rejection, N6 assumptions absent | temporal (`LiveSuspender`) | FIRED (1,768) |
| **`mterm`** | **no retired-waiter escape (round-8 C-1)** | **deadlock** | **FIRED (2,678) — 7 states** |
| `dirf6` | round-11 C-1 false-SUCCESS shape under dpin | clean stale-gate closure | PASS (524,888) |

**Reachability probes — the violation IS the pass.** `pr1` (1,441),
`pr2` (537), `pr3` (1,601) all FIRED — plus **`pr4` (round-10 M-D):
`ProbeNoTermSuspendCycle` FIRED (12,298), proving `t1full`'s `LiveTerm`
PASS is not vacuous over a W3→W5→W3 configuration that never occurs.**

**Safety — TLC deadlock detection ON.**

| Config | Scope / features | Distinct states | Verdict |
|---|---|---|---|
| `small` | 2c × 2e, ALL features | 181,326 | PASS (3s) |
| `medium` | 2c × 3e, ALL features, term 2, symmetry | 30,932,046 | PASS (431s) |
| `large` | 3c × 3e, core + rendezvous, symmetry | 68,733 | PASS (3s) |
| `xlarge` | 3c × 4e, core only, symmetry | 732,044 | PASS (37s) |
| `mtermfix` | the C-1 repair at the mutual-terminate scope | 9,585 | PASS (1s) |
| `cr3self` | 2c × 3e + both cycle invariants | 982,534 | PASS (8s) |

**Liveness.** All runs carry `-lncheck final`. `SpecFairN3` contains
N3's two per-spin SFs and NEITHER N6 assumption. `SpecTrm` is the
per-property minimal set for `LiveTerm` (round-7 follow-up: split by
fairness constraint, so a verdict records which assumptions it rests
on).

| Config | Property | Spec | Verdict |
|---|---|---|---|
| `cr1minself` | `LiveSuspender` (W5) | `SpecFairN3` | PASS (56s) |
| `liveness_a` | L1, L2, L6 | `SpecFairCore` | **PASS (2,133s)** — 1,087,956 product nodes, 6 branches |
| `liveness_b` | L3, L4, L5 | `SpecFairCore` | **PASS (1,726s)** |
| `q7` | `LiveTerm`, 2c × 3e, **directive OFF** | `SpecTrm` | **UNCONVERGED (5,400s cap)** — 300,120 states generated in seconds, then 90 min of pure temporal checking on 900,360 product nodes with no verdict |
| `cr1fullself` | `LiveSuspender`, full 2×2 | `SpecFairN3` | not re-run on the rev-9 graph — the slot went to `LiveTerm`, which had never been verified at all. Rev-8 verdict (PASS, 2,225s) stands for the rev-8 machine only |
| **`t1min`** | **`LiveTerm` (W3/W4), 2c × 2e, terminate only** | `SpecTrm` | **PASS (10s, 9,585)** |
| **`t1s`** | `LiveTerm` + cross-EC suspend / recv-pop | `SpecTrm` | **PASS (11s, 10,237)** |
| **`t1r`** | `LiveTerm` + rendezvous + pin-class locks | `SpecTrm` | **PASS (13s, 11,969)** |
| **`t1full`** | **`LiveTerm`, FULL 2×2, ALL features** | `SpecTrm` | **PASS (2,487s, 477,468 states)** — and this is the config that settles round-9 M-1, see below |

**Round-9 M-1's `W3 → W5 → W3` cycle is machine-checked, and `t1full` is
where.** A terminates B while B suspends A: A waits in W3 for B to leave
`current`, B waits in W5 for A to leave `running`. Neither §2.5.1's
suspend-cycle rejection nor round-8 C-1's terminate exits touches it —
the operations differ, so no mutual-X check fires, and neither party is
`retired`. `t1full` has `SUSPEND_ON`, `DIR_ON` and `TERM_BUDGET = 2` at
2 cores × 2 ECs, so the shape is constructible, and `LiveTerm` **PASSES**
across all 477,468 states. The verdict's dependency is explicit and is
the point: `SpecTrm` includes `FairTick`, and `FairTick` is the model's
stand-in for "the periodic tick arrives" — which is true in the model by
construction and true in the kernel only under §3.3's EC-context
IRQ-enabled rule (round-9 C-4). **So the cycle's acyclicity certificate
is machine-checked GIVEN a premise the model cannot check.** That is the
cleanest illustration in the artifact of where this instrument stops.
(`q7d` was built to probe M-1 at 2c × 3e and is not needed: `q7` already
showed that scope does not converge, and `t1full` answers the question at
a scope that does.)

**`LiveTerm` HAS A VERDICT — the first in this artifact's history.** Rev
7 produced none, rev 8's two attempts were killed without converging, and
rev 9's `q7` did not converge at 2c × 3e. The thing that worked was not a
bigger timeout: it was **laddering the scope while using the
per-property MINIMAL fairness set**, exactly the discipline that
LiveSuspender needed. `LiveTerm` holds at 2 cores × 2 ECs across three
rungs — terminate-only, +cross-EC suspend/recv, +rendezvous/pin-locks —
in **10, 11 and 13 seconds**, against 73 minutes of non-convergence for
the same property under full `SpecFair` at the same core count. The
verdict rests on exactly `FairCPU`, `FairUnwind`, `FairDisp`, `FairTick`
and `FairSpinTerm` (N3's W3/W4 per-spin SF), and on **neither N6
assumption** — which is now a recorded fact rather than an assumption
about an assumption. What made the difference is dropping `FairSpinDir`
and `FairFire`, which `LiveTerm` does not need and which the blanket
`SpecFair` was forcing TLC to track at every node.

**`q7`: the probe is now meaningful but still cannot be RUN, and that is
the honest state.** It asks whether a terminate-wait alone can wedge with
no suspend involved. It asks whether a
terminate-wait alone can wedge with no suspend involved — and under
revision 8's single-action `Terminate` it could never have answered,
because the mutual shape was inexpressible. Under revision 8's single-action
`Terminate` it could never have answered, because the mutual shape was
inexpressible — which is exactly why round 8 found C-1 by READING and not
by running: the probe written to catch this class was structurally blind
to it. With the split in, the shape is now reachable at `q7`'s scope (2
cores × 3 ECs, `DIR_ON = FALSE`, `TERM_BUDGET = 2`) — but the run does
not converge, so **`LiveTerm` remains unverified at every scope, for the
third revision running.** What C-1 changed is that the shape is no longer
merely unchecked: its worst case is now checked by a SAFETY gate
(`mterm`, 7 states, and `mtermfix` clean), which is the right instrument
for a wedge anyway. What stays open is whether some *other*
terminate-side liveness failure exists at 3 ECs.

**The per-property minimal fairness sets, and what each verdict now
rests on** (round-7 follow-up, delivered). `FairCPU` = SF(BaseStep) +
WF(IrqStep); `FairUnwind` = WF(RetireUnwind); `FairTick` =
SF(TickPreempt); `FairDisp` = SF(DispatchOrS7) — the family that scales
as |Cores| × |ECs|; `FairFire` = SF(FireAny); `FairSpinTerm` /
`FairSpinDir` = N3's two per-spin SFs.

| Property | Minimal set (`SpecX`) | Notably does NOT need |
|---|---|---|
| L1 `LiveParking`, L5 `LiveMark`, L6 `LiveClaim` | `FairCPU` + `FairUnwind` | `FairDisp`, `FairTick`, both per-spin SFs |
| L4 `LiveWake` | `FairCPU` + `FairUnwind` | `FairFire` — the *firing* is not what a consumed pop's discharge waits on |
| L3 `LiveReady` | + `FairDisp` | `FairTick` |
| L2 `LiveRetired` | + `FairDisp` + `FairTick` | both per-spin SFs |
| **`LiveTerm`** (`SpecTrm`, **verified**) | + `FairSpinTerm` | `FairSpinDir`, `FairFire`, and **both N6 assumptions** |
| `LiveSuspender` (`SpecSus`) | + `FairSpinDir` | `FairSpinTerm`, and both N6 assumptions (retired by C3) |

The `LiveTerm` row is the one that paid off immediately: dropping
`FairSpinDir` and `FairFire` from the set TLC must track is what turned
73 minutes of non-convergence into 10 seconds.

**Why the 3-EC liveness runs will not converge, restated with a third
data point.** `cr3live` (28 min), `cr3liveself` (20 min) and now `q7`
(90 min) all died in the temporal phase after generating their state
spaces in seconds. The driver is the FAIRNESS-CONSTRAINT COUNT, not
graph size: at 2 cores × 3 ECs the `DispatchOrS7` family alone is 6
instances and the total is 22, against 14 at 2×2. `q7` was the test of
the round-7 remedy — split by fairness constraint, giving `LiveTerm`
only the constraints it needs (`SpecTrm`: FairCPU, FairUnwind,
FairDisp, FairTick, FairSpinTerm) — and **the remedy was not enough**.
`FairDisp` is the family that scales with |Cores| × |ECs| and
`LiveTerm` genuinely needs it, so the minimal set is not much smaller
than the full one. The next thing to try is not a bigger timeout: it is
dropping to 2 ECs where `LiveTerm` is checkable, and accepting that the
3-EC scope is out of reach for any property carrying `FairDisp`.

## Sufficiency for the syscall API (acceptance condition 3)

Every EC state change the API can cause, mapped to a named edge with a
named actor, or explicitly out of scope with a reason.

**DERIVATION: the spec's SECTION list, top to bottom (round-9 C-5).** The
round-7 version of this table walked the spec's SYSCALL list, which is a
strict subset — `§[restart_semantics]` is normative, per-EC, and not a
syscall section, so it was structurally invisible to that walk. The
missing rows were the symptom; the method was the defect. **Re-walking the section list is a BETTER derivation than the syscall
walk and is still NOT CLOSED (round-11 M-5).** Revision 10 claimed here
that the walk "surfaces exactly one new lifecycle-affecting section
(restart) and confirms the rest". That sentence was retracted in
`systems.md` §11.9 in revision 11 and **survived verbatim right here**,
in the section that actually carries the walk — which is the one place
it could still stop a reader looking. It was false: an independent walk
found **six** further gaps, the largest being a **domain-pause
primitive** (`acquire_vmars`/`idc_read`/`idc_write`) that is
architecturally larger than restart and NOT additive, plus `restrict`'s
port-refcount cascade waking suspended senders with E_CLOSED, `revoke`
(zero mentions in `systems.md`), the no-route fallback's
kernel-initiated terminate from EXCEPTION context (a different actor
than T2's terminator), `delete` of an EC handle mapped to edge 9 against
a spec that says ECs are not destroyed by handle drops, and
`power_sleep` filed as terminal when the spec says it returns on wake.
Treat this table as incomplete until it is tool-derived. The sections
below are confirmed only in the sense that the walk reached them:
`§[Lifetimes]` is covered by
retire/finalize, `§[device_irq]` is a T1 row, `§[event_state]` is §2.2's
snapshot, `§[power]` is §3.6's carve-out, and
`§[port_io_virtualization]`, `§[vm_policy]`, `§[event_type]`,
`§[handle_attachments]`, `§[vm_exit_state]`, `§[time]`, `§[rng]`,
`§[system_info]` cause no EC state change. Rows that cannot change a
lifecycle word are still listed, because "omitted" and "cannot" are the
distinction a closure table exists to make.

| API surface | Machine (systems.md) | Model | Actor |
|---|---|---|---|
| blocking waits: `futex_wait_val`, `futex_wait_change`, `recv` (no sender), `suspend` (self), wfi/hlt trap | edge 3 (wait) | `UserPark` (+`DirConsume` for directive parks; `DirFail`/`DirDrop` for owner-side directive failure with no park) | the EC's own core |
| `futex_wake`, `reply`, `recv` pop, close propagation (`clear_event_route`, port destroy), deadline/timer expiries, device-IRQ delivery | edges 5a/5b + T1 | `WakeStart`, `FireAt` | any waker; 5a claimant discharges, 5b claimant pends |
| `vm_inject_irq` waking a wfi-parked vCPU | edge 5a source list (M4) | collapsed into `WakeStart`/`FireAt` | injector |
| `recv` re-containment, reply-pin | edges 5a+7 | `RecvPop` -> `SuspendPlace` | the holder |
| cross-EC `suspend`: ready / idle-wait / running | 5c+7 / 5a+7 / directive §2.5 | `SuspendStart`->`SuspendPlace`, `RecvPop` path, `DirClaim/DirArm/DirLoop/DirConsume/DirFail/DirDrop` | suspender; owner core consumes or publishes failure |
| **cross-EC `suspend` that would close a suspend CYCLE (C3)** | §2.5.1: refused with an E_BUSY-class error — **not a state change at all**, which is the point: the pathological caller is charged and the machine's normal path is untouched | `DirSelfMark`'s guard (`"self"`) or `DirClaim`'s (`"pair"`); `InvNoSuspendCycle2`/`3` | the caller, which returns the error |
| `yield` (caller side), `yieldTo` caller requeue | edge 3 trigger list (M4) | collapsed into `TickPreempt`'s transition | owner core |
| **`yieldTo` target side (M-4, NEW in rev 8)** | edge 2, restricted: `ready` **on this core's queue** + S7 filter + affinity mask; else degenerate to plain `yield` | `DispatchEC(c,e)` — local-only by construction (`e \in cores[c].q`) | the calling core |
| preemption, affinity-migration requeue | edges 3(requeue)+8 | `TickPreempt` + `HopCommitRequeue` | owner core's tick |
| **tick landing on an armed, unpinned, user-mode EC (M-5)** | edge 3 (wait) — consumption BEATS requeue, §3.1 rule 3 precedence | `TickPreempt`'s rule-3 arm | owner core's tick |
| `affinity`, ready target whose new mask excludes its queue core | §8.1: 5c claim-move + edge 6 | `AffMove` (discharges via `WakePlace`) | the editing EC, as holder |
| `affinity`, all other states | §8.1: the word alone; honored at the next placement's destination computation | collapsed: placement destinations are nondeterministic, which over-approximates every mask | the in-flight discharger |
| **`priority`, waiting target (C2 — rev 7 had this WRONG)** | §8.1: re-bucket every linked wait node under its container lock (port lock; sorted all-buckets for futex) | **no action — the identity transition here** (no state change, no containment change; queues are sets, so intra-container position does not exist). Ledger G9 | the editing EC, under the reaching container lock |
| **`priority`, ready target** | §8.1: in-lock relink within the SAME run queue — no claim, no state change | as above, no action | the editing EC, under that queue's lock |
| `priority`, other states | §8.1: the word alone; the next link reads it fresh | as above | the next linker |
| `terminate`; `delete`/`revoke` of an EC handle; cascade destroys | edge 9 + W3/W4 + L5 | `Terminate`/`TermWait` (+ env `RetireEC` for teardown walks) | terminator; §5.2 names the finalizer |
| `create_execution_context`, `acquire_ecs`, `create_vcpu` | edge 1 | Init + `CreateEC` (`ready`; vCPU initial `vm_exit` is synthesized by first dispatch and normal wait publication) | creator |
| `delete(SLOT_SELF)` domain teardown; vCPU pre-loop | §8.2 / §8.1 | OUT OF SCOPE, stated: scheduler-context teardown phases and the degenerate-hop loop | park-stack code |
| `timer_arm` / `timer_rearm` / `timer_cancel` | T1 one-shot registration lifecycle (§5.1, §8.4) | `shot \in {none,armed,consumed}`; `FireAny` | the arming EC; the tick |
| IPC fast paths | §9.4 fused compositions | `FastPath`, `ReplyFP` as ideal atomic compositions | pinned asm sites |
| **§[restart_semantics] `restart_policy = 0` (kill)** | edge 9 | `RetireEC` / `Terminate` | the exiting domain's teardown |
| **§[restart_semantics] `restart_policy = 1` (restart_at_entry)** | **NOT A DESIGN OBLIGATION as of `systems.md` rev 16** (maintainer decision), downgraded from revisions 13–15's "IN, deferred". The tree implements only the policy PLUMBING — `caps/capability.zig:346`/`:581`/`:591`/`:604` — and all eight `tests/suite/cases/restart_semantics_*.zig` test `E_PERM` ceiling bounding, not restart behaviour; there is no domain-restart implementation anywhere. Promising it an edge committed the machine to routing one value of one policy in a feature that does not exist. The analysis is kept and its status demoted: **NO EDGE EXISTS (round-9 C-5)** — an EC in ANY state must be forced runnable with its saved frame reset to its entry point. Not edge 6 (placement preserves the frame), not edge 7, not a claim-move; edge 1 establishes an entry frame but only on a fresh slot. Needs claim-by-state-route + **frame reset under the won claim** + edge 6, and a T2 row so a restart racing a retire loses | **not modelled** | — |
| **§[restart_semantics] `restart_policy = 2` (persist)** | **NOT ADDRESSED** — keeps an EC *running* while its domain's VMARs are freed and handle table rewritten. §8.2/§8.5 do not cover an address-space change under a live EC, and it collides directly with `active_root` / translation quiescence (W6): a running EC on a root being rewritten is what `awaitDomainQuiesced` exists to prevent | **not modelled** | — |
| `power_shutdown` / `power_reboot` | **not an EC state change** — terminal core-stopping paths, §3.6 carve-out (added in rev 8) | not modelled, by carve-out | — |
| `power_sleep` | **not an EC state change, but NOT by the terminal carve-out** — the spec says it RETURNS on wake, so it is not terminal. OUT by §0.2 reason B: the core idles and resumes the same EC. Revisions 14–15 filed it under §3.6's terminal carve-out while §0.2 said the opposite; **corrected in revision 16** | not modelled, by §0.2 exclusion | — |
| **`acquire_vmars` / `idc_read` / `idc_write`** | **THEY DO CHANGE EC STATE, and an earlier version of this table said they could not.** `specv3.md` `:722`/`:1894`/`:1952` say each **pauses every EC in the target domain**: §3.1 rule 3's third boundary arm, an edge-3 park into `waiting(domain_pause)`, edge 1's gated publish, plus the W5-N wait the caller performs. There is no edge-7 domain-pause route | **NOT MODELLED — see G12** | the pauser (entry/resume); each gated EC itself (the park) |
| `sync`, `restrict`, `ack`, `perfmon_*`, all VMAR/page-frame/VM-policy calls, `create_port`, `bind_event_route`, `snapshot`, `remap`, `map_*`/`unmap*` | **cannot change any EC's lifecycle word.** `sync` refreshes a handle snapshot; `ack` unmasks a line (the acker is `running` throughout); the rest touch capability, memory or perfmon state only. (`restrict`'s port-refcount cascade WAKES suspended senders — that wake is in scope, via edge 5a's close-propagation trigger, and is listed separately in §0.1) | not modelled, correctly | — |

Two rows in that table are the round-7 additions that closed acceptance
condition 3's gaps: `yieldTo`'s target side had no rule at all, and the
tick-vs-directive precedence had a model behavior but no rule.

## Abstraction boundary — what a green run does NOT claim

**Whatever this model declares atomic IS atomic.** TLC verifies the
protocol at the granularity declared here. A pass says nothing about
codegen, field-level atomicity, assembly ordering, cache coherence, or
memory-model subtleties — a model at this level would have blessed the
real 24-byte torn read this project hit on aarch64. Specifically outside
the boundary: W1 lock internals and **lock ordering** — the one verified
edge (EcGen → CoreLock), the chain round 8 REFUTED and retracted (C-3),
and F2's lock-order half: all lockdep's domain, none of it checkable
here, and round 8 is the demonstration that a wrong claim in this area
survives a fully green battery; slab gen / S5 fusion
and every stale-handle race; S2/S6 writer- and width-discipline; domains
beyond a per-EC dead flag; W6/W8/W9; the §9.4 fast path's asm conformance;
§3.3's sync-exception rule; **the entire domain-pause mechanism (G12) —
`cd.paused`, `.domain_pause`, W5-N, both no-cycle refusals, the boundary
leg, and §3.3's quiesced-resume rule**; **descriptor-write windows and
instruction orders below action granularity — including C1's claim-side
bump**; queue
ordering, priorities and bucket position (which is why C2 is
model-invisible); affinity masks; capacity/E_NOMEM. Those belong to the
§9.3 analyzers, the §9.2 asserts, lockdep, and the N=100 bare-metal
campaign.

## Honest confidence assessment

*(Verdict tables follow this section; read them together.)*

What the green battery establishes: at 2–3 ECs and 2–3 cores (the 4-EC
rung is `xlarge`, which has no rev-15 verdict yet), the rev-15
protocol — the seven-state CAS word, both hand-off shapes, the pended
split with W7's pre-CAS wait, the wait-free retired arm, the
finalizer-owned container unwind, the pin gate with F3's widened class and
now C1's ordering rule, the hop contract with placement-time destinations,
T2's routing carried by `mark_state`, the directive protocol with F5's
loop, F6's `dead` and rev 6's arm-CAS, the S7 claim route, and the
rendezvous window's parking×K+C cell — has no reachable lost wake,
orphaned claim, use-after-free of the modelled kind, containment breach,
or wedge, at the declared atomicity.

The model's resolution is demonstrated rather than presumed: dialed to
rev 3 it rediscovers X1/X2/X3; dialed to either reading of rev 4's F1 it
fails in under ten states; dialed to the rev-5 literal unwind it fails in
seven; dialed to the pre-split publish shape it violates S3 in three; and
dialed to `lock(); pin_depth += 1;` it violates T2's ready×K justification
in four. Its own narrowing (N2) was caught and corrected against the
literal text.

**Things a green rev-15 run does NOT establish. Read (0) first — it is
the largest one and it is newer than the rest:**

0. **THE DOMAIN PAUSE IS NOT IN THIS MODEL AT ALL (G12).** Not the
   `cd.paused` gate, not `.domain_pause`, not W5-N's predicate wait, not
   either of §0.3's two no-cycle refusals, not edge 1's gated publish,
   not the boundary leg, not §3.3's quiesced-resume rule. It is the
   NEWEST mechanism in `systems.md` and the one with the **least**
   evidence behind it — every other mechanism in the list above has at
   least one falsifier proving its fix load-bearing, and this one has
   none. Two of its defects have already been found by READING rather
   than running (revision 16: the asserted user-memory premise, and the
   boundary leg that falsified W5-N's own soundness argument), which is
   the empirical case for modelling it rather than an argument that
   reading suffices. G12 carries the four lost properties, the design,
   and three named falsifiers to build with it.
1. **C1's claim-side half is unchecked** and cannot be checked at this
   granularity. Only the pin-class-lock half has a falsifier. If the
   kernel bumps `pin_depth` after dropping the reaching container lock,
   nothing here notices.
2. **C2 is entirely outside the model.** The priority re-bucket is the
   identity transition where queues are sets. Its evidence is
   `specv3.md` [test 06]/[test 07] and the doc's lock protocol — never
   this battery.
3. **`LiveSuspender` is now verified at FULL 2×2 scope, and was not
   before.** Under the rev-7 machine the property was checkable only at
   the lower rungs, for a structural reason: the alignment premise is
   provably outside WF/SF's fast path (proof above), so it rides TLC's
   general tableau, and `c1full` returned nothing after 59 minutes of
   pure temporal checking. Round 7 resolved this rather than living with
   it: symmetric-suspend rejection retires both N6 assumptions, and
   `cr1fullself` — full scope, all features, neither assumption — passed
   in 37 minutes **ON THE REVISION-8 MODULE, and has not been re-run
   since** (round-11 M-4: this section claimed the PASS un-caveated
   while the results table in the same file said it was not re-run and
   `out/cr1fullself.log` ends mid-run with no verdict — the
   un-caveated version was the one in the section named "honest").
   **And round-11 M-4 THEN RECURRED INSIDE THIS PARAGRAPH — revision 16
   is striking it (round-14 parity review).** The sentence here read
   *"What IS current is `LiveTerm`'s full ladder including `t1full` at
   full 2×2"*, one sentence after narrating this exact failure for
   `cr1fullself`, while the results table in this same file lists
   `t1full` as having **no rev-15 verdict at all**. What is actually
   current is the **`t1min` / `t1s` / `t1r` rungs — all
   `DIR_ON = FALSE`** — plus `cr1minself` at the minimal rung.

   **The parity consequence is the load-bearing half, and it is the
   `t1d_min` argument arriving from the other direction.** `pr4` FIRED at revision
   15, at CONSTANTS identical to `t1full.cfg` — so the battery carries a
   live non-vacuity certificate **for a verdict that does not exist**.
   Meanwhile the three rungs that DO pass are all `DIR_ON = FALSE`, a
   scope where the `W3 → W5 → W3` cycle is not merely unobserved but
   **structurally unreachable** (no directive, so no `dirW`). A probe
   firing is evidence about the scope it runs at, not about whichever
   verdict happens to be cited near it — and nothing but the CONSTANTS
   mirror ties the two together, which is why revision 16 writes that
   coupling into paired `.cfg` headers and pairs the default bounded
   `t1d_min` row with `pr4d_min`. Full `t1d`/`pr4d` remains on disk as
   extended/manual evidence, but full `t1d` is currently
   measured-unconverged rather than green. The caveat that replaces the
   struck clause is narrower and is (4).

4. **Suspend-cycle rejection closes the shape that was found, and the
   pairwise form does not close the class.** A 3-cycle is reachable in 14
   states under the maintainer's `"pair"` mechanism. The `"self"`
   refinement closes cycles of every length by construction and needs no
   second lock — which also removes an AB-BA the `"pair"` form would have
   created against the x86-64 fast-suspend path's existing, role-ordered
   EC-gen-lock nesting. Until the maintainer rules on §11.8, the machine
   the battery blesses is the one with `CYCLE_REJECT` enabled; the rev-7
   machine (`"none"`) is retained only as the falsifier that shows the
   mechanism is load-bearing. **And the meta-lesson stands: N3 → N5 → N6
   → C3's 3-cycle is four rounds in which the enumeration of starvable
   shapes was wrong. Treat the current one as incomplete too.**

What survives as assumption, and is stated in both artifacts: §3.6's three
assumptions (per-quantum continuation progress; no perpetual cross-core
alignment; no perpetual interrupt storm), plus everything in the
abstraction-boundary section. The implementation obligation the model
cannot discharge: the kernel must actually wire the rule-(b) assert, the
C1 ordering asserts, and the M-5 precedence assert into every relevant
path, and keep the pin-class set computed (9.3(7)) — a green model with an
unwired assert protects nothing.

Everything beyond the boundary and the bounded scope remains
unestablished. A green run here is one closed layer — the
interleaving-protocol layer — of a multi-instrument argument.
