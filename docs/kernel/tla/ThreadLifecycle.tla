---------------------------- MODULE ThreadLifecycle ----------------------------
(***************************************************************************)
(* TLA+ model of the Stygia thread lifecycle machine,           *)
(* docs/kernel/systems.md revision 16 (2026-08-02). Revision 8 carried     *)
(* three semantic deltas from rev 7, all encoded here: the staged          *)
(* placement destination is no longer placement authority (placement       *)
(* computes from the fresh descriptor under the destination lock -- the    *)
(* `dst` field is DELETED, round-7 M-2), the deferred-marking fact         *)
(* acquires a real word (`mo`, one BIT after round-8's simplicity pass,    *)
(* private mo/mk pair -- round-7 M-3), and `pin_depth`'s bump/acquire      *)
(* ORDER becomes normative with a falsifier (`PIN_BUMP_FIRST`, round-7     *)
(* C1). Constant switches reproduce the older machines for the gates:      *)
(*                                                                        *)
(*   PENDED   = TRUE : rev 5. Parking-origin claims (edge 5b) go to        *)
(*              `pended`; claimant writes payload, release-stores          *)
(*              payload_done, and is done; the owner core's hop            *)
(*              discharges (edge 6p). Retire of a `pended` target          *)
(*              acquire-waits payload_done BEFORE its CAS (edge 9, W7,     *)
(*              round-4 F1), so no later observer of `retired` waits.      *)
(*   PENDED   = FALSE: rev 3. Parking-origin claims go to `claimed`; the   *)
(*              claimant RELEASE-WAITS for the owner's hop to release the  *)
(*              kstack, then places -- from interrupt context too (X2).    *)
(*              Interrupt-context wakes of a parking thread owned by the SAME  *)
(*              core DECLINE (rev-3 F2's rule) -- the one-shot pop is      *)
(*              consumed with no retry party (X3).                         *)
(*   PIN_GATE = TRUE : rev 5. The preempt tick requeue-preempts only       *)
(*              frames with pin_depth = 0 (round-3 X1 fix; membership of   *)
(*              the pin class per round-4 F3 -- claims AND pin-class       *)
(*              locks, the latter modelled by PinAcq/PinRel).              *)
(*   PIN_GATE = FALSE: rev 3. Claim-holding frames can be requeue-         *)
(*              preempted, become `ready`, and be retired + inline-        *)
(*              finalized, orphaning their claim (X1).                     *)
(*                                                                        *)
(* PARITY RULE (learned the hard way in the round-4 parity review): every  *)
(* action in this module cites the spec text it implements, and when the   *)
(* spec is ambiguous the LITERAL reading is encoded and the ambiguity is   *)
(* logged in README.md -- never a charitable repair. The README carries a  *)
(* section-by-section parity table; keep it in sync with any edit here.    *)
(*                                                                        *)
(* Abstraction boundary: whatever this model declares atomic IS atomic.   *)
(* IRQ-masked lock-held critical sections (W1) are single actions; field  *)
(* atomicity, codegen, and memory-model ordering are NOT modelled -- see  *)
(* README.md. Round 7 is the standing reminder that this boundary is      *)
(* where findings hide: BOTH of its criticals were invisible here. C1 is  *)
(* an instruction ORDER one level below the declared atomicity (rev 8     *)
(* pulls the pin-class-lock half of it INTO the model; the claim-side     *)
(* half stays outside and says so), and C2 is a contradiction with        *)
(* specv3.md, a document this model does not read at all.                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Cores,        \* set of cores, e.g. {c1, c2}
  Threads,          \* set of (non-idle) threads, e.g. {e1, e2}
  NULL,         \* model value: absent thread / core / holder / irq frame
  VCPU_THREADS,     \* subset of Threads that execute guest mode when dispatched
  VCPU_CANCEL,  \* BOOLEAN: arch cancel request + forced VM-exit ack exists
  PENDED,       \* BOOLEAN: rev-5 pended hand-off + W7 (X2/X3/F1)
  PIN_GATE,     \* BOOLEAN: rev-5 pin_depth requeue-preemption gate (X1/F3)
  SUSPEND_ON,   \* BOOLEAN: cross-thread suspend of a READY target (5c+7).
  REQUEUE_ON,   \* BOOLEAN: independent claim-move scope gate for RecvPop
                \* (port receive re-containment) and AffMove (thread
                \* affinity). Both claim a target the caller does not own
                \* and discharge it through an existing holder path
                \* (suspC and wakeC respectively). Every recorded config
                \* sets this equal to SUSPEND_ON, preserving the original
                \* transition relation and state counts.
  FASTPATH,     \* BOOLEAN: the fused IPC fast path (Sec 9.4)
  RV_ON,        \* BOOLEAN: the rendezvous window (Sec 8.3) -- a sender
                \*          holding its receiver's claim while itself
                \*          `parking` (T2's parking x K+C cell)
  DIR_ON,       \* BOOLEAN: the suspend directive protocol (Sec 2.5, W5)
  PINLOCK_ON,   \* BOOLEAN: pin-class lock holds (Sec 2.4, F3 surface)
  S7_ON,        \* BOOLEAN: dead-process dispatch filter + S7 claim route
                \*          (Sec 3.2, F2 state-machine half)
  WAKE_IPI,     \* BOOLEAN: G14 locked enqueue sends a wake to a parked core.
                \* FALSE is the missing-wake falsifier.
  G16_ON,       \* BOOLEAN: model self-delete's scheduler-stack handoff.
  G16_DROP_REF, \* BOOLEAN: falsifier: consumer loses the process ref.
  DROP_BUDGET,  \* Nat: stale/bad-port owner failure events (DirDrop is the
                \* only unbounded generator in the directive machine --
                \* arm/fail/ack/arm cycles freely -- and at 3 Threads that
                \* alone drove dirabafix past 274M states and an OOM.
                \* Bounded like TERM_BUDGET/CR_BUDGET.
  TERM_BUDGET,  \* Nat: retire() calls (environment + thread-context terminate)
  CR_BUDGET,    \* Nat: edge-1 creations after Init (slab reuse)
  F1_MODE,      \* "rev5"       : retire pre-waits payload_done (W7, F1 fix)
                \* "nowait"     : rev 4's iff, read as don't-wait when the
                \*                hop never observed `pended` -> UAF gate
                \* "alwayswait" : rev 4's iff, read as always-wait at the
                \*                hop's retired arm -> deadlock gate
  E4_AT_HOP,    \* BOOLEAN. TRUE = the machine: claimability-for-placement
                \* begins at the hop's commit CAS (edge 4); pre-hop the thread
                \* is `parking` and claims land as `pended`. FALSE = the
                \* pre-split tree's shape (terminal wait state published
                \* while the owner is still on the kstack) -- the e4
                \* falsifier: InvS3 must fire (Sec 3.2 rev 7, Phase-3b).
  FIN_UNWIND,   \* BOOLEAN. TRUE = revision 6's N4 mechanism: the container
                \* unwind belongs to the FINALIZER alone -- finalize's
                \* first act is the idempotent unwind, and retire has no
                \* step 3 (Sec 8.2 rev 6). FALSE = the revision-5 literal
                \* machine: retire owns the unwind as a separate step after
                \* its CAS, and nothing orders it against a routed
                \* finalizer -- the N4 falsifier (freed-while-linked).
  DIR_GENCHK,   \* BOOLEAN. TRUE = revision 12's TWO-PART break
                \* disambiguator (round-11 C-1): the suspender
                \* re-validates the TARGET's slab gen as well as its
                \* port's, and a gen-stale target is E_TERM. FALSE =
                \* revision 11, which re-validated only the port -- and
                \* since finalize's own `slot zero` (Sec 8.2, edge 10)
                \* overwrites F6's `dead` marker with the all-zeroes
                \* `none`, a suspender whose target was terminated,
                \* finalized and zeroed reads `none` with a LIVE port
                \* and returns SUCCESS. Round-4 F6 re-opened by a later
                \* step of its own edge-10 row.
  DIR_OWNED,    \* BOOLEAN. TRUE = revision 11's ARM-OWNERSHIP test
                \* (round-10 C-D): the suspender's loop breaks when the
                \* word is no longer ITS arm, and its disarm CAS is gated
                \* on the same fact. The test is the arming suspender's
                \* IDENTITY, not a counter -- and that choice is a model
                \* RESULT, not a preference. Revision 11 first specified
                \* a bounded epoch bumped on every exit from `armed`;
                \* TLC found the epoch is ITSELF an ABA, wrapping in a
                \* DirDrop/DirLoop/DirClaim/DirArm cycle (mod-4 wrap in four
                \* bumps), and an 8-bit epoch wraps in 256 while the W5
                \* spinner has NO bound at all (Sec 2.5 terminates by
                \* assumption, not by a count). Identity does not wrap:
                \* the suspender is a LIVE thread while it spins, so its own
                \* slot cannot be recycled underneath it.
                \* FALSE = revision 10's value-based break -- the ABA.
                \* FALSE = revision 10's VALUE-based break -- the ABA:
                \* a suspender reports success for a suspension that was
                \* dropped/failed, and can disarm a third party's directive.
  DIR_DROP,     \* BOOLEAN. TRUE = the owner's stale/bad-port failure arm
                \* exists (Sec 2.5). It publishes dres and armed->failed;
                \* the matching waiter acks failed->none.
  CYCLE_REJECT, \* "none" | "pair" | "self". SYMMETRIC-SUSPEND
                \* REJECTION, three machines (round-7 maintainer
                \* proposal + the round-7 refinement of it):
                \*
                \*  "none" -- the revision-7 machine: symmetric suspend
                \*    is REACHABLE and survived only by assumption (N6's
                \*    SF(DirArm) + AlignmentAssumption). The falsifier.
                \*
                \*  "pair" -- the maintainer's proposal. A suspend of a
                \*    running target takes BOTH thread gen locks, lowest slot
                \*    index first, and fails with a cycle error if the
                \*    target is already suspending the CALLER. The naive
                \*    one-CAS form does NOT work: the two intents live in
                \*    two different words (A arms B's, B arms A's), so
                \*    both CASes can succeed concurrently -- the check A
                \*    needs ("has B armed ME?") reads A's OWN word while
                \*    A's action writes B's. Holding both locks is what
                \*    makes check-and-arm one atomic decision, and they
                \*    are RELEASED BEFORE the W5 wait (waiting inside
                \*    them would rebuild N1 exactly). Closes 2-cycles.
                \*    Does NOT close 3-cycles -- see InvNoSuspendCycle3
                \*    and the cr3 gate, which reach one in 14 states.
                \*
                \*  "self" -- the refinement. NO second lock and no lock
                \*    ORDER at all: the suspender first CASes its OWN
                \*    directive word none -> "suspending", then CASes the
                \*    target's none -> "claiming". A target whose word is
                \*    "suspending" is not claimable, so no thread can be a
                \*    suspender and a suspend TARGET at the same time --
                \*    and every cycle, of every length, consists entirely
                \*    of Threads that are both. Two single-word CASes on
                \*    words already in the protocol; one new enum value.
                \*    Costs strictly more rejection than "pair" (a
                \*    suspend of a target that is itself suspending an
                \*    unrelated third thread is refused too).
  TERM_ESCAPE,  \* BOOLEAN. TRUE = revision 9's MUTUAL-TERMINATE repair
                \* (round-8 C-1): a terminator that has itself been
                \* retired abandons the W3/W4 wait. FALSE = rev 8,
                \* where mutual terminate is a hard two-core deadlock.
  PIN_BUMP_FIRST \* BOOLEAN. TRUE = revision 8's normative pin_depth
                \* ORDER (Sec 2.4, round-7 C1): the increment PRECEDES
                \* acquisition of the thing it protects and the decrement
                \* FOLLOWS its release. For the pin-class lock class this
                \* is `pin_depth += 1; lock();` / `unlock(); pin_depth -=
                \* 1;`. FALSE = `lock(); pin_depth += 1;` (and the mirror
                \* on release) -- the default an engineer writes, and the
                \* C1 falsifier: pin-class locks are BY DEFINITION not
                \* IRQ-masked at their thread-context acquire sites, so a tick
                \* lands in the gap, reads pin_depth = 0, wins the
                \* running -> parking(requeue) CAS, and requeue-preempts a
                \* lock-HOLDING frame. InvNoPreemptedLockHolder -- T2's
                \* ready x K justification ("a requeue-preempted frame
                \* holds no lock at all") stated as an invariant -- must
                \* fire. See README C1 for what this switch does and does
                \* NOT cover (the claim-side bump stays below granularity:
                \* it sits inside an IRQ-masked reaching-lock section that
                \* this model makes atomic by construction).
ASSUME TERM_BUDGET \in Nat /\ CR_BUDGET \in Nat /\ DROP_BUDGET \in Nat
ASSUME VCPU_THREADS \subseteq Threads
ASSUME VCPU_CANCEL \in BOOLEAN
ASSUME F1_MODE \in {"rev5","nowait","alwayswait"}
ASSUME E4_AT_HOP \in BOOLEAN
ASSUME PIN_BUMP_FIRST \in BOOLEAN
ASSUME CYCLE_REJECT \in {"none","pair","self"}
ASSUME TERM_ESCAPE \in BOOLEAN
ASSUME DIR_DROP \in BOOLEAN
ASSUME DIR_OWNED \in BOOLEAN
ASSUME DIR_GENCHK \in BOOLEAN
ASSUME SUSPEND_ON \in BOOLEAN
ASSUME REQUEUE_ON \in BOOLEAN
ASSUME WAKE_IPI \in BOOLEAN
ASSUME G16_ON \in BOOLEAN
ASSUME G16_DROP_REF \in BOOLEAN

(***************************************************************************)
(* State                                                                   *)
(*                                                                        *)
(* threads[e]: st  - lifecycle word (Sec 2.1)                                 *)
(*         pk  - parking kind: "wait" | "requeue" | "none" (Sec 2.2)      *)
(*         (timed-vs-port wait flavor is encoded by `shot`: armed at the  *)
(*         publish iff the wait has a one-shot interrupt source -- a     *)
(*         rev-6 simplification; a separate `timed` field was write-only) *)
(*         shot - the one-shot registration: "none"|"armed"|"consumed"    *)
(*         own - owner_core (Sec 2.4); NULL outside its validity set      *)
(*         pin - lifecycle pin depth (Sec 2.4). Claim holders pin the     *)
(*               TARGET thread whose lifecycle/slab generation they protect;  *)
(*               pin-class lock holders pin their own executing thread.       *)
(*         pd  - payload_done handshake bit (Sec 2.2)                     *)
(*         po  - GHOST ONLY (history): the claim CAS came from `parking`. *)
(*               Rev 5 keys NOTHING on this: the pend fact lives in the   *)
(*               state word (Sec 2.1) and retire pre-waits payload_done   *)
(*               (edge 9, W7), so NO protocol action reads po. It feeds   *)
(*               only InvRetiredPdOrdered and trace readability. The      *)
(*               round-4 parity review caught this model's previous       *)
(*               version using po as protocol state -- a silent F1        *)
(*               repair the design forecloses.                            *)
(*         hld - claim holder identity: NULL, [ty|->"thread", id|->e], or     *)
(*               [ty|->"irq", cid|->c]                                    *)
(*         am  - affinity-admitted cores. Affinity mask 0 is represented   *)
(*               by Cores (admitted everywhere); nonzero masks are a       *)
(*               nonempty subset.                                         *)
(*         mo  - `mark_state` (Sec 2.4, M-3): the deferred-              *)
(*               marking OWED bit. Round 8 collapsed it from a           *)
(*               tri-state to one bit: nothing ever distinguished        *)
(*               "never owed" from "owed and discharged", so the third   *)
(*               value was unreachable information. Rev 7 had this       *)
(*               fact ONLY in the model (a private mo/mk pair) despite    *)
(*               its being cross-core and multi-writer -- retirer sets    *)
(*               owed, a DIFFERENT core's discharger sets done, a THIRD   *)
(*               core's terminator spins on it (W4). Rev 8 gives it a     *)
(*               word with the SPSC hand-off discipline of payload_done,  *)
(*               and the model's two booleans collapse into it.           *)
(*         (rev 8 REMOVED `dst`, the staged placement destination:        *)
(*         round-7 M-2. Sec 4's pended arm said "honoring the staged      *)
(*         destination" while Sec 8.1 said the discharger "reads the      *)
(*         fresh descriptor" -- a contradiction. Rev 8 deletes the        *)
(*         staged core AS PLACEMENT AUTHORITY: every placement computes   *)
(*         its destination from the fresh descriptor under the            *)
(*         destination queue lock, so the destination is chosen AT        *)
(*         PLACEMENT (\E d \in Cores at each placement action) rather     *)
(*         than latched at claim. This also erases ghost G2 -- there is   *)
(*         no longer a staging step whose author was unstated.)           *)
(*         pc  - the thread's saved kernel continuation: "user" (boundary),   *)
(*               "wakeC" (mid wake body, holding a claim on tg),          *)
(*               "suspC" (mid suspend body), "relwait" (rev-3 release-    *)
(*               wait, thread context)                                        *)
(*         tg  - wake/suspend body target                                 *)
(*         ks  - core currently on this thread's kstack, or NULL (S3)         *)
(*         vm  - arch execution submode for VCPU_THREADS only: "host" means   *)
(*               ordinary kernel/user-boundary execution; "guest" means   *)
(*               the owner is in guest execution and a scheduler IPI is   *)
(*               not, by itself, a lifecycle boundary; "cancel" means a   *)
(*               remote retire requested an arch vCPU cancel/kick and     *)
(*               teardown waits for the owner-side VM-exit acknowledgement*)
(*                                                                        *)
(* cores[c]: q    - run queue (set; FIFO order abstracted, see README)    *)
(*           cur  - PerCore.current                                       *)
(*           pc   - scheduler-side continuation: "idle" | "ecrun" |       *)
(*                  "dispatchLoad" | "hopRel" |           *)
(*                  "hopCommit" | "stealCommit"                           *)
(*           outg - outgoing thread being walked through park-sequence/hop    *)
(*           parked - §3.4 idle_parked: empty-queue park decision under the  *)
(*                    queue lock; dispatch waits for a wake IPI.             *)
(*           wake - an enqueue committed a wake IPI for a parked core.       *)
(*           pending - TeardownRequest staged before self-retire; carries    *)
(*                     process id, generation, and producing thread.         *)
(*           active - the same reference after park-stack consumption and    *)
(*                    until phase 2 finishes.                                *)
(*           irq  - nested interrupt frame: NULL or                       *)
(*                  [op|->"wake", tgt|->e, ph|->"place"|"pend"|"relwait"] *)
(*                  While irq[c] # NULL the base continuation of c CANNOT *)
(*                  step: the frame must return first. Handlers run       *)
(*                  masked, so at most one frame is in flight per core.   *)
(*                                                                        *)
(* tb: remaining retire() budget.                                         *)
(***************************************************************************)
VARIABLES
  threads,    \* per-thread record (fields above plus, new in the rev-5 retarget:
          \*   lnk - REIFIED wait-container linkage: linked in exactly one
          \*         wait episode's containers (S1's wait half, checked
          \*         rather than assumed)
          \*   plk - pin-class lock episode (SlabAllocator.lock-style; F3):
          \*         "none" | "held" (lock held AND pin-counted) |
          \*         "preB" (lock held, the pin_depth bump NOT yet
          \*         executed) | "postD" (pin_depth already decremented,
          \*         lock NOT yet released). The two half-states are
          \*         reachable only under ~PIN_BUMP_FIRST -- the round-7
          \*         C1 falsifier. Under the machine's normative order
          \*         (bump-before-acquire, decrement-after-release) the
          \*         corresponding intermediates are pin_depth > 0 while
          \*         NOT holding, which gates preemption exactly as the
          \*         fused state does and is read by nothing else, so the
          \*         machine keeps PinAcq/PinRel FUSED (a zero-work
          \*         interleaving point, removed by the same rule that
          \*         removed the pre-hop step -- README removals).
          \*   dir - directive word:
          \*         none|suspending|claiming|armed|failed|dead (Sec 2.5)
          \*   dres- directive result, abstracted to none|fail. Meaningful
          \*         only while dir = "failed"; it may be stale outside that
          \*         state. The owner publishes fail before armed -> failed
          \*         when it cannot consume the directive, including stale/bad
          \*         port; the matching waiter reads it, acks by clearing
          \*         failed -> none, and returns the real error.
          \*   dpin- remote-directive target pin. This models the
          \*         suspender's tryPinLive(target_thread) through the W5 wait.
          \*         It blocks retire/finalize but deliberately does NOT
          \*         gate the target owner's tick or boundary consumption:
          \*         pin is the thread's own preemption/claim pin abstraction,
          \*         dpin is an external waiter-held lifetime pin.
          \*   dsrc- the thread that claimed/armed this directive (NULL when
          \*         dir = none|dead). Meaningful only while
          \*         dir \in {claiming, armed, failed}. This is the word the
          \*         symmetric-suspend check reads: a suspender u of
          \*         target t rejects iff threads[u].dsrc = t, i.e. "my own
          \*         directive is already claimed BY my target".
          \*   dd  - the thread's process is gen-dead (S7 filter input)
  cores,  \* per-core record; pc gains "rvdeliver" (rendezvous delivery
          \* window, a pre-hop park-sequence phase holding a claim) and
          \* "s7ret" (S7 retire-as-holder, after the queue lock drops)
  processes, \* G16 process phase/generation/consume count
  tb,     \* remaining retire budget (environment retire + terminate)
  cb,     \* remaining edge-1 creation budget
  db,     \* remaining process-death events (S7 surface)
  pb      \* remaining stale-port drop events (round-12)
vars == <<threads, cores, processes, tb, cb, db, pb>>

States   == {"ready","running","parking","waiting","claimed","pended",
             "retired","finalizing","freed"}
Holders  == {NULL} \cup [ty: {"thread"},  id: Threads]
                   \cup [ty: {"irq"}, cid: Cores]
                   \cup [ty: {"cpu"}, cid: Cores]   \* S7 retire-as-holder
IrqFrames == {NULL} \cup [op: {"wake"}, tgt: Threads,
                          ph: {"place","pend","relwait"}]
TeardownRefs == {NULL} \cup [proc: Threads, gen: 0..1,
                            owner: Threads,
                            kind: {"self_delete","unhandled_fault"}]
\* thread saved-continuation values:
\*   user   - at/returning to the user boundary
\*   wakeC  - holds a 5a/edge-6 claim, placement pending
\*   suspC  - holds a 5c/5a claim, edge-7 re-containment pending
\*   pendC  - 5b claimant: payload + payload_done release-store pending
\*   rvC    - rendezvous sender park-sequence, holding the receiver claim
\*   relwait- rev-3 only: thread-context release-wait
\*   dirC   - suspender between directive claim and arm (Sec 2.5)
\*   dirW   - suspender in the terminal re-check/disarm loop (W5)
\*   termW  - terminator in the eviction + deferred-marking wait (W3/W4)
ThreadPCs == {"user","wakeC","suspC","pendC","rvC","relwait",
          "dirM","dirC","dirW","termR","termW","teardown"}
ClaimPCs == {"wakeC","suspC","pendC","rvC","relwait"}
\*   dirM - CYCLE_REJECT = "self" only: the suspender has marked its OWN
\*          directive word "suspending" (CAS 1) and has not yet claimed
\*          its target's (CAS 2). Modelled UNFUSED because the two CASes
\*          are on different words with no lock between them -- fusing
\*          them would hide the real interleaving in which both parties
\*          self-mark and both then fail, which is a legal E_BUSY pair.

TypeOK ==
  /\ threads \in [Threads -> [st: States,
                      pk: {"none","wait","requeue"},
                      shot: {"none","armed","consumed"},
                      own: Cores \cup {NULL},
                      pin: 0..2,
                      pd: BOOLEAN,
                      po: BOOLEAN,
                      hld: Holders,
                      am: SUBSET Cores,
                      mo: BOOLEAN,   \* mark_state: deferred marking OWED (round-8 simplicity)
                      pc: ThreadPCs,
                      tg: Threads \cup {NULL},
                      ks: Cores \cup {NULL},
                      vm: {"host","guest","cancel"},
                      lnk: BOOLEAN,
                      plk: {"none","held","preB","postD"},
                      dir: {"none","suspending","claiming","armed","failed","dead"},
                      dres: {"none","fail"},
                      dpin: BOOLEAN,
                      dbad: BOOLEAN, \* GHOST: a foreign disarm happened
                      gen: 0..7,     \* slab gen. ADVANCES at finalize and is
                                     \* INHERITED by CreateThread -- never reset.
                                     \* Round-12: it was 0..1 flipped at
                                     \* finalize and RESET by CreateThread, which
                                     \* is an ABA, and TLC found it: A arms B,
                                     \* RetireThread(B), CreateThread reuses the slot
                                     \* with gen back at the snapshot value,
                                     \* DirLoop breaks and reports SUCCESS.
                                     \* Same lesson as the refuted epoch. The
                                     \* real requirement, stated in Sec 2.5:
                                     \* the gen must not wrap within one W5
                                     \* wait -- which for the 64-bit slab gen
                                     \* is the argument S5 already relies on.
                                     \* Width 8 here exceeds TERM+CR budgets,
                                     \* so it cannot wrap at model scope.
                      dgen: 0..7,    \* suspender's snapshot of tg's gen
                      dlv: BOOLEAN,  \* GHOST, ON THE SUSPENDER: my arm was
                                     \* delivered. Round-13: this was on the
                                     \* TARGET and a later suspender's arm
                                     \* reset it, erasing whether the EARLIER
                                     \* arm had been delivered -- so a
                                     \* correct SUCCESS was scored as false.
                                     \* Per-arm facts cannot live in a slot
                                     \* the next arm reuses; same shape as
                                     \* the epoch and the gen reset.
                      pok: BOOLEAN,  \* the CURRENT arm's port is still live
                                     \* (round-11: the reviewer's "named
                                     \* snapshot" -- this is the model side
                                     \* of Sec 9.2's armed_port_ref.gen
                                     \* check, so BOTH halves of the break
                                     \* disambiguator are now checkable and
                                     \* the rev-11 ledger entry claiming
                                     \* otherwise is retracted)
                      dfs: BOOLEAN,  \* GHOST: returned SUCCESS falsely
                      dsrc: Threads \cup {NULL},
                      proc: Threads,
                      dd: BOOLEAN]]
  /\ cores \in [Cores -> [q: SUBSET Threads,
                          cur: Threads \cup {NULL},
                          parked: BOOLEAN, wake: BOOLEAN,
                          pending: TeardownRefs, active: TeardownRefs,
                          pc: {"idle","dispatchLoad",
                               "ecrun","hopRel","hopCommit",
                               "rvdeliver","s7ret","stealCommit"},
                          outg: Threads \cup {NULL},
                          irq: IrqFrames]]
  /\ processes \in [Threads -> [phase: {"live","queued","dead","done"},
                               gen: 0..1, consumes: 0..1]]
  /\ tb \in 0..TERM_BUDGET
  /\ cb \in 0..CR_BUDGET
  /\ db \in 0..1
  /\ pb \in 0..DROP_BUDGET
  /\ \A e \in Threads: threads[e].dir = "failed" => threads[e].dres = "fail"
  /\ \A e \in Threads: threads[e].am # {}

ThreadCtx(c) == /\ cores[c].pc = "ecrun"
            /\ cores[c].irq = NULL
            /\ cores[c].cur # NULL

(***************************************************************************)
(* Init: every thread starts `ready` in some core's run queue.                 *)
(***************************************************************************)
Init ==
  /\ \E f \in [Threads -> Cores], p \in [Threads -> Threads]:
       /\ (~G16_ON => p = [e \in Threads |-> e])
       /\ cores = [c \in Cores |->
                    [q |-> {e \in Threads : f[e] = c},
                     cur |-> NULL, pc |-> "idle", outg |-> NULL, irq |-> NULL,
                     parked |-> FALSE, wake |-> FALSE,
                     pending |-> NULL, active |-> NULL]]
       /\ threads = [e \in Threads |->
                  [st |-> "ready", pk |-> "none",
                   shot |-> "none", own |-> NULL, pin |-> 0, pd |-> FALSE,
                   po |-> FALSE, hld |-> NULL, am |-> Cores,
                   mo |-> FALSE,
                   pc |-> "user", tg |-> NULL, ks |-> NULL,
                   vm |-> "host",
                   lnk |-> FALSE, plk |-> "none", dir |-> "none",
                   dres |-> "none", dpin |-> FALSE,
                   dbad |-> FALSE, gen |-> 0, dgen |-> 0,
                   dlv |-> FALSE, pok |-> TRUE, dfs |-> FALSE,
                   dsrc |-> NULL, proc |-> p[e], dd |-> FALSE]]
       /\ processes = [q \in Threads |->
                         [phase |-> "live", gen |-> 0, consumes |-> 0]]
  /\ tb = TERM_BUDGET
  /\ cb = CR_BUDGET
  /\ db = IF S7_ON THEN 1 ELSE 0
  /\ pb = DROP_BUDGET

(***************************************************************************)
(* G14: the empty-queue decision and a subsequent enqueue are both under
   core_locks[c]. A parked core cannot dispatch until its committed wake
   IPI arrives. Every ready placement sets `wake` in the same action that
   adds the queue entry when it observes `parked`. *)
ParkDecision(c) ==
  /\ cores[c].pc = "idle" /\ cores[c].cur = NULL
  /\ cores[c].irq = NULL /\ cores[c].q = {}
  /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ ~cores[c].parked
  /\ cores' = [cores EXCEPT ![c].parked = TRUE]
  /\ UNCHANGED <<processes, threads, tb, cb, db, pb>>

WakeIpi(c) ==
  /\ cores[c].parked /\ cores[c].wake
  /\ cores' = [cores EXCEPT ![c].parked = FALSE, ![c].wake = FALSE]
  /\ UNCHANGED <<processes, threads, tb, cb, db, pb>>

(***************************************************************************)
(* Edge 2: dispatch. One core_locks[c] critical section (Sec 3.2). The S7  *)
(* process filter gates the commit; filter failure takes the S7Claim route  *)
(* below, never a silent drop (S7).                                        *)
(*                                                                         *)
(***************************************************************************)
DispatchThread(c, e) ==
  /\ cores[c].pc = "idle" /\ cores[c].irq = NULL /\ ~cores[c].parked
  /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ e \in cores[c].q /\ threads[e].st = "ready"
  /\ ~threads[e].dd                                    \* S7 filter passes
  /\ c \in threads[e].am
  /\ cores' = [cores EXCEPT ![c].q = @ \ {e}, ![c].cur = e,
                            ![c].pc = "dispatchLoad"]
  /\ threads' = [threads EXCEPT ![e].st = "running", ![e].own = c, ![e].ks = c]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

DispatchAbort(c) ==
  LET e == cores[c].cur IN
  /\ cores[c].pc = "dispatchLoad" /\ cores[c].irq = NULL /\ e # NULL
  /\ threads[e].st # "running"
  /\ cores' = [cores EXCEPT ![c].cur = NULL, ![c].pc = "idle"]
  /\ threads' = IF threads[e].st = "retired"
            THEN [threads EXCEPT ![e].st = "finalizing", ![e].mo = FALSE,
                             ![e].ks = NULL,
                             ![e].own = NULL, ![e].pk = "none",
                             ![e].hld = NULL, ![e].dir = "dead",
                             ![e].dres = "none", ![e].dpin = FALSE, ![e].dlv = FALSE,
                             ![e].dsrc = NULL, ![e].pc = "user",
                             ![e].tg = NULL]
            ELSE [threads EXCEPT ![e].ks = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

DispatchLoad(c) ==
  LET e == cores[c].cur IN
  /\ cores[c].pc = "dispatchLoad" /\ cores[c].irq = NULL /\ e # NULL
  /\ threads[e].st = "running"
  /\ cores' = [cores EXCEPT ![c].pc = "ecrun"]
  /\ threads' = [threads EXCEPT ![e].vm =
                        IF e \in VCPU_THREADS THEN "guest" ELSE "host"]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Sec 3.2 / S7 / edge 5c (F2): a popped gen-dead-process thread is CLAIMED     *)
(* under the queue lock the dispatcher already holds (R-claim-legal),      *)
(* then -- after the lock drops (next action) -- retired as holder via     *)
(* T2's `claimed` row. Rev 4 retired it in place under the queue lock,     *)
(* nesting ThreadGen inside CoreLock against the Sec 3.5 pinned order; the     *)
(* lock-order half of F2 is outside this model (W1 is atomic), but the     *)
(* claim-then-retire-as-holder state shape is checked here.                *)
S7Claim(c, e) ==
  /\ S7_ON
  /\ cores[c].pc = "idle" /\ cores[c].irq = NULL /\ ~cores[c].parked
  /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ e \in cores[c].q /\ threads[e].st = "ready"
  /\ c \in threads[e].am
  /\ threads[e].dd                                     \* S7 filter fails
  /\ cores' = [cores EXCEPT ![c].q = @ \ {e}, ![c].pc = "s7ret",
                            ![c].outg = e]
  /\ threads' = [threads EXCEPT ![e].st = "claimed",
                        ![e].hld = [ty |-> "cpu", cid |-> c]]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Pull-side work stealing: after c drains deferred requeues and finds its *)
(* local queue empty, it drops c's run-queue lock with IRQs still masked,  *)
(* takes one victim lock v, scans that ACTUAL victim queue high-to-low /   *)
(* FIFO (queue order abstracted here), and claims a ready thread admitted by   *)
(* c's affinity. The claim pins the thread, removes it from the victim queue,  *)
(* and leaves dispatch/abandon to the thief after it reacquires c's lock.  *)
StealClaim(c, v, e) ==
  /\ c # v
  /\ cores[c].pc = "idle" /\ cores[c].irq = NULL /\ ~cores[c].parked
  /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ cores[c].q = {}
  /\ e \in cores[v].q                              \* ready-in-victim-queue
  /\ threads[e].st = "ready" /\ threads[e].own = NULL
  /\ c \in threads[e].am                               \* affinity-admitted thief
  /\ ~threads[e].dd
  /\ cores' = [cores EXCEPT ![v].q = @ \ {e},
                            ![c].pc = "stealCommit", ![c].outg = e]
  /\ threads' = [threads EXCEPT ![e].st = "claimed",
                        ![e].hld = [ty |-> "cpu", cid |-> c],
                        ![e].pin = @ + 1]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Reacquired thief lock, no local work arrived: claimed -> ready ->       *)
(* running dispatch commit. The intermediate ready state is compressed but *)
(* the commit is still the edge-2 ready-to-running authority. The stolen   *)
(* thread then enters the same dispatch-tail split as ordinary dequeue. The    *)
(* canPublishReady recheck is represented by the live-process guard: ProcessDie *)
(* may interleave after StealClaim while c's lock was dropped.             *)
StealDispatch(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "stealCommit" /\ cores[c].irq = NULL
  /\ cores[c].q = {}
  /\ threads[e].st = "claimed"
  /\ threads[e].hld = [ty |-> "cpu", cid |-> c]
  /\ ~threads[e].dd
  /\ cores' = [cores EXCEPT ![c].cur = e, ![c].pc = "dispatchLoad",
                            ![c].outg = NULL]
  /\ threads' = [threads EXCEPT ![e].st = "running", ![e].own = c,
                        ![e].ks = c, ![e].hld = NULL,
                        ![e].pin = @ - 1]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Reacquired thief lock, local ready work arrived while c's lock was      *)
(* dropped: local work wins. The stolen claim is abandoned with no core    *)
(* lock held through the placement path, then becomes ready in some        *)
(* affinity-admitted destination queue if the process is still publishable. *)
StealAbandon(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "stealCommit" /\ cores[c].irq = NULL
  /\ cores[c].q # {}
  /\ threads[e].st = "claimed"
  /\ threads[e].hld = [ty |-> "cpu", cid |-> c]
  /\ ~threads[e].dd
  /\ \E d \in threads[e].am:
       /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL,
                                 ![d].q = @ \cup {e}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
       /\ threads' = [threads EXCEPT ![e].st = "ready", ![e].own = NULL,
                             ![e].hld = NULL, ![e].pin = @ - 1]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* ProcessDie can run while the thief has dropped and re-acquired locks around *)
(* stealCommit. Implementation rechecks canPublishReady before dispatch and*)
(* enqueueOnCore rechecks before abandon placement; an unpublishable stolen*)
(* claim cannot be dispatched or requeued. Abstract the S7-style teardown  *)
(* by discharging the thief's holder pin and finalizing the stolen thread.     *)
StealDropDead(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "stealCommit" /\ cores[c].irq = NULL
  /\ threads[e].st = "claimed"
  /\ threads[e].hld = [ty |-> "cpu", cid |-> c]
  /\ threads[e].pin > 0
  /\ threads[e].dd
  /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL]
  /\ threads' = [threads EXCEPT ![e].st = "finalizing", ![e].mo = FALSE,
                        ![e].hld = NULL, ![e].pin = @ - 1,
                        ![e].dir = "dead", ![e].dres = "none",
                        ![e].dpin = FALSE,
                        ![e].dlv = FALSE, ![e].dsrc = NULL,
                        ![e].own = NULL, ![e].pc = "user",
                        ![e].tg = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* The dispatcher, as holder, retires + finalizes the quiescent thread (T2     *)
(* `claimed` row, holder discharge; marking deferred-to-holder = done      *)
(* here). If an environment retire won the race first, the holder learns   *)
(* `retired` and performs deferred marking + finalize (same row).          *)
S7Retire(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "s7ret" /\ cores[c].irq = NULL
  /\ threads[e].st \in {"claimed","retired"}
  /\ threads' = [threads EXCEPT ![e].st = "finalizing", ![e].mo = FALSE,
                        ![e].hld = NULL, ![e].dir = "dead", ![e].dres = "none", ![e].dpin = FALSE, ![e].dlv = FALSE, ![e].dsrc = NULL,
                        ![e].own = NULL,
                        ![e].pc = "user", ![e].tg = NULL]
  /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Environment: a process dies (teardown phase 1 dead-mark, abstracted).    *)
ProcessDie ==
  /\ S7_ON /\ db > 0 /\ db' = db - 1
  /\ \E e \in Threads:
       /\ threads[e].st \notin {"retired","freed"}
       /\ threads' = [threads EXCEPT ![e].dd = TRUE]
  /\ UNCHANGED <<processes, cores, tb, cb, pb>>

(***************************************************************************)
(* Edge 3 (wait): the park sequence, steps 1-2 (Sec 3.2). Staging plus     *)
(* publish-under-the-reaching-locks is one atomic action (IRQ-masked lock  *)
(* section); deadline/one-shot registration is inside the same section.    *)
(* Round 6 M1: the doc now orders the CAS BEFORE the links inside the      *)
(* section and specifies the failure arm (retire won since staging =>      *)
(* link nothing, proceed as outgoing-retired). The fused atomic action     *)
(* remains exactly faithful to that: the st = "running" guard IS the CAS   *)
(* -- when retire wins first the action is disabled, nothing links, and    *)
(* the thread takes the boundary/hop retired route. Intra-section order is     *)
(* unobservable at this granularity (W1), so no model change is needed.    *)
(***************************************************************************)
UserPark(c) ==
  LET e == cores[c].cur IN
  /\ ThreadCtx(c) /\ threads[e].pc = "user" /\ threads[e].st = "running"
  /\ threads[e].vm = "host"
  /\ threads[e].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[e].shot = "none"
  /\ threads[e].pin = 0          \* Sec 2.4 assert: pin_depth = 0 at publish
  \* (U3 repaired: an earlier version guarded untimed parks on another thread
  \*  being lively -- no spec counterpart; removed. An all-asleep system is
  \*  the Quiescent terminal, not a modelling problem.)
  /\ \E sh \in {"armed","none"}:   \* armed = timed/device wait (T1 source)
       threads' = [threads EXCEPT ![e].st = IF E4_AT_HOP THEN "parking"
                                    ELSE "waiting",
                          \* ~E4_AT_HOP = the e4 falsifier: publish the
                          \* terminal wait state pre-hop, owner still on
                          \* the kstack -- todays tree shape; InvS3 fires
                          ![e].pk = "wait", ![e].lnk = TRUE,
                          ![e].shot = sh, ![e].vm = "host"]
  /\ cores' = [cores EXCEPT ![c].pc = "hopRel", ![c].outg = e]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

VcpuGuestExit(c) ==
  LET e == cores[c].cur IN
  /\ ThreadCtx(c) /\ e \in VCPU_THREADS
  /\ threads[e].pc = "user" /\ threads[e].st = "running"
  /\ threads[e].vm = "guest"
  /\ threads[e].shot = "none"
  /\ threads[e].pin = 0
  /\ threads' = [threads EXCEPT ![e].st = "parking", ![e].pk = "wait",
                        ![e].lnk = TRUE, ![e].vm = "host"]
  /\ cores' = [cores EXCEPT ![c].pc = "hopRel", ![c].outg = e]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Sec 3.2 step 3 (bounded post-publish pre-hop window) is zero-length     *)
(* for plain parks in this model (rev-6 simplification: a dedicated       *)
(* PrehopDone step added an interleaving point with no work in it; the    *)
(* 5b-race window survives as the gap before HopRelease, which any        *)
(* interrupt arrival can occupy). The rendezvous variant of the window    *)
(* DOES carry work and keeps its own phase ("rvdeliver").                 *)

(***************************************************************************)
(* The hop (Sec 4): release first, then commit.                            *)
(***************************************************************************)
HopRelease(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "hopRel" /\ cores[c].irq = NULL
  /\ cores' = [cores EXCEPT ![c].cur = NULL, ![c].pc = "hopCommit"]
  /\ threads' = [threads EXCEPT ![e].ks = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Hop step 2, commit arm: parking(wait) -> waiting (edge 4).              *)
HopCommitWait(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "hopCommit" /\ cores[c].irq = NULL
  /\ threads[e].st = "parking" /\ threads[e].pk = "wait"
  /\ threads' = [threads EXCEPT ![e].st = "waiting", ![e].pk = "none",
                        ![e].own = NULL]           \* owner poisoned
  /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Hop step 2, requeue arm: parking(requeue) -> ready (edge 8), placement  *)
(* CAS under THE DESTINATION queue lock. Edge 3 lists both preempt (same   *)
(* core) and affinity migration (another core) as requeue triggers and     *)
(* edge 8 does not fix the destination, so it is nondeterministic here     *)
(* (G3: an earlier draft hard-coded same-core and hid cross-core requeue   *)
(* placement interleavings).                                               *)
HopCommitRequeue(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "hopCommit" /\ cores[c].irq = NULL
  /\ threads[e].st = "parking" /\ threads[e].pk = "requeue"
  /\ \E d \in Cores:
       /\ threads' = [threads EXCEPT ![e].st = "ready", ![e].pk = "none",
                             ![e].own = NULL]
       /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL,
                                 ![d].q = @ \cup {e}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Hop step 2, pended arm (rev 5, edge 6p): wait payload_done (spin W2,    *)
(* scheduler context), then place. Owner core is holder-of-record.         *)
(* Rev 8 (M-2): the destination is COMPUTED HERE, from the fresh           *)
(* descriptor, inside the destination queue-lock section -- not read from  *)
(* a destination the claimant latched (which is what rev 7's "honoring     *)
(* the staged destination" said, contradicting Sec 8.1's "reads the fresh  *)
(* descriptor"). Nondeterministic over Cores: placement POLICY is outside  *)
(* the boundary, and the affinity mask is descriptor data.                 *)
HopCommitPended(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "hopCommit" /\ cores[c].irq = NULL
  /\ threads[e].st = "pended"
  /\ threads[e].pd                                     \* W2 acquire-spin
  /\ threads' = [threads EXCEPT ![e].st = "ready", ![e].pk = "none",
                        ![e].own = NULL, ![e].po = FALSE,
                        ![e].pd = FALSE,
                        ![e].shot = "none"]        \* pop discharged
  /\ \E d \in Cores:
       cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL,
                              ![d].q = @ \cup {e}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Hop step 2, retired arm (rev 5, Sec 4): deferred marking + finalize     *)
(* WITH NO WAIT. A retire whose observed from-state was `pended`           *)
(* acquire-waited payload_done BEFORE flipping the state (edge 9, W7), so  *)
(* by the time any party observes `retired` the claimant's payload is      *)
(* complete. This arm reads neither payload_done nor any pend-origin       *)
(* flag: rev 4 conditioned a hop-side wait on the hop's own prior          *)
(* observation of `pended` -- a fact the retire destroys -- and both       *)
(* readings of that iff failed (round-4 F1). The previous version of this  *)
(* model silently repaired F1 with a persistent `po` descriptor flag the   *)
(* design forecloses; `po` is now ghost-only.                              *)
(* In rev 3 only: a retired thread still claim-held (hld # NULL) is finalized  *)
(* by its release-wait holder, not here (reconstructed arm, README G1).    *)
HopCommitRetired(c) ==
  LET e == cores[c].outg IN
  /\ cores[c].pc = "hopCommit" /\ cores[c].irq = NULL
  /\ threads[e].st = "retired"
  /\ F1_MODE = "alwayswait" => threads[e].pd
     (* rev 4's iff, always-wait reading: the hop's retired arm waits     *)
     (* payload_done unconditionally -- for a retire whose origin was     *)
     (* plain `parking` (no claimant ever existed) there is no writer     *)
     (* and the owner wedges: the F1 deadlock gate.                       *)
  /\ IF PENDED \/ threads[e].hld = NULL
     THEN threads' = [threads EXCEPT ![e].st = "finalizing", ![e].mo = FALSE,
                             ![e].po = FALSE,
                             ![e].pd = FALSE, ![e].own = NULL,
                             ![e].pk = "none",
                             ![e].hld = NULL, ![e].dir = "dead", ![e].dres = "none", ![e].dpin = FALSE, ![e].dlv = FALSE, ![e].dsrc = NULL,
                             ![e].pc = "user", ![e].tg = NULL,
                             (* Rev 6 (FIN_UNWIND): finalize's FIRST act  *)
                             (* is the idempotent container unwind under  *)
                             (* each container's lock -- one unwinder,    *)
                             (* owned by whoever frees (Sec 8.2 rev 6,    *)
                             (* the N4 mechanism). Under the rev-5        *)
                             (* literal machine (~FIN_UNWIND) finalize    *)
                             (* absorbs only the consumed-pop bookkeeping *)
                             (* and an armed registration/linked          *)
                             (* container survives the free: the N4      *)
                             (* falsifier (InvS1 freed => unlinked).      *)
                             ![e].lnk = IF FIN_UNWIND THEN FALSE ELSE @,
                             ![e].shot = IF FIN_UNWIND \/ @ # "armed"
                                         THEN "none" ELSE @]
     ELSE threads' = threads        \* rev 3: release-wait holder owns finalize
  /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Hop step 2, failed-CAS `claimed` arm: reachable only in rev 3 (a        *)
(* release-wait claimant owns placement; the owner just releases and       *)
(* moves on). Because rev 3's claimant may complete its release-wait       *)
(* between our hop's release and commit steps, the failed CAS can also     *)
(* observe the target already placed (ready/running) or already            *)
(* holder-finalized (freed); the owner has nothing to do in those cases    *)
(* either. Under PENDED all of these are the Sec 9.2 unreachable assert,   *)
(* checked by invariant InvHopNoClaimedOutgoing.                           *)
HopCommitClaimed(c) ==
  LET e == cores[c].outg IN
  /\ ~PENDED
  /\ cores[c].pc = "hopCommit" /\ cores[c].irq = NULL
  /\ threads[e].st \in {"claimed","ready","running","freed"}
  /\ cores' = [cores EXCEPT ![c].pc = "idle", ![c].outg = NULL]
  /\ UNCHANGED <<processes, threads, tb, cb, db, pb>>

(***************************************************************************)
(* Preemption (Sec 3.1 rule 1): the tick's requeue preempt. Claim-gated    *)
(* (CAS succeeds only from `running`) AND, in rev 5, pin-gated. The        *)
(* handler body (CAS + return + walk to hop) is fused into one action --   *)
(* it runs IRQ-masked and touches only this core plus the one CAS.         *)
(***************************************************************************)
TickPreempt(c) ==
  LET e == cores[c].cur IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ e # NULL
  /\ threads[e].pc # "teardown"  \* G16: syscall/fault entry stays IRQ-masked
  /\ threads[e].st = "running"
  /\ threads[e].vm = "host"
  /\ PIN_GATE => threads[e].pin = 0
  /\ PIN_GATE => threads[e].pc \notin ClaimPCs
     \* Current claim continuations run in the IRQ-disabled reaching-lock
     \* section until they publish/drop and release the TARGET pin. Before
     \* target pins, the claimant's own pin accidentally modelled this gate.
  /\ IF threads[e].pc = "user" /\ threads[e].pin = 0 /\ threads[e].dir = "armed"
        /\ threads[e].shot = "none"
     THEN (* Sec 3.1 rule 3 (round-6 N5): the tick IS an entry from user  *)
          (* mode; the directive arm fires there and consumes -- edge-3   *)
          (* park into the port, exactly DirConsume's body. Liveness of   *)
          (* consumption rides SF(TickPreempt) (the periodic timer); the  *)
          (* Sec 2.5 wake IPI is the promptness mechanism, below this     *)
          (* granularity. A pinned or kernel-frame thread takes the plain     *)
          (* requeue arm (entry from kernel: no directive arm, rule 3).   *)
          /\ threads' = IF threads[e].dsrc # NULL
                    THEN [threads EXCEPT ![e].st = "parking", ![e].pk = "wait",
                                     ![e].lnk = TRUE, ![e].vm = "host",
                                     ![e].dir = "none", ![e].dres = "none",
                                     ![threads[e].dsrc].dlv = TRUE,  \* the ARMER
                                     ![e].dsrc = NULL]
                    ELSE [threads EXCEPT ![e].st = "parking", ![e].pk = "wait",
                                     ![e].lnk = TRUE, ![e].vm = "host",
                                     ![e].dir = "none", ![e].dres = "none"]
          /\ cores' = [cores EXCEPT ![c].pc = "hopRel", ![c].outg = e]
     ELSE /\ threads' = [threads EXCEPT ![e].st = "parking", ![e].pk = "requeue",
                                ![e].vm = "host"]
          /\ cores' = [cores EXCEPT ![c].pc = "hopRel", ![c].outg = e]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Sec 3.1 rule 3: user-boundary entry check discovers `retired` and       *)
(* walks the frame to its hop, whose retired arm finalizes.                *)
BoundaryRetired(c) ==
  LET e == cores[c].cur IN
  /\ ThreadCtx(c) /\ threads[e].pc = "user" /\ threads[e].st = "retired"
  /\ threads[e].vm = "host"
  /\ threads[e].pin = 0    \* own pins/pin-class locks discharged pre-hop (2.4)
  /\ cores' = [cores EXCEPT ![c].pc = "hopRel", ![c].outg = e]
  /\ UNCHANGED <<processes, threads, tb, cb, db, pb>>

(* Arch vCPU cancellation acknowledgement (stygia-8xl). A remotely retired
 * vCPU can be stuck below the generic scheduler boundary while the owner
 * executes guest code. The lifecycle contract is not "scheduler IPI is
 * enough"; retire must publish an arch cancel/kick, the architecture must
 * force a VM exit, and only the owner-side acknowledgement converts the thread
 * back to ordinary host execution where BoundaryRetired can run.          *)
VcpuCancelExit(c) ==
  LET e == cores[c].cur IN
  /\ VCPU_CANCEL
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ e # NULL
  /\ e \in VCPU_THREADS
  /\ threads[e].st = "retired"
  /\ threads[e].vm = "cancel"
  /\ threads' = [threads EXCEPT ![e].vm = "host"]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(***************************************************************************)
(* The wake body, syscall context (futex wake / reply / recv-side): claim  *)
(* under the reaching lock (R-claim), then discharge. The claim and the    *)
(* discharge are separate steps: the window between them is where X1       *)
(* lives. The lifecycle pin is acquired on the target before the claim     *)
(* CAS, as `tryPinLive`/`begin*ClaimPinned` do in the implementation.      *)
(***************************************************************************)
WakeStart(c) ==
  LET w == cores[c].cur IN
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[w].shot = "none"
  /\ \E t \in Threads \ {w}:
      \/ (* edge 5a: waiting -> claimed; winner unlinks the episode's     *)
         (* containers (lnk) incl. the deadline node (shot)               *)
         /\ threads[t].st = "waiting"
         /\ threads' = [threads EXCEPT ![t].st = "claimed",
                               ![t].hld = [ty |-> "thread", id |-> w],
                               ![t].shot = "none",
                               ![t].pin = @ + 1, ![t].lnk = FALSE,
                               ![w].pc = "wakeC",
                               ![w].tg = t]
      \/ (* edge 5b, rev 5: parking -> pended. The claimant's remaining   *)
         (* body (pc = "pendC") is payload + payload_done, then DONE --   *)
         (* it never re-reads the state word (Sec 3.2).                   *)
         /\ PENDED
         /\ threads[t].st = "parking" /\ threads[t].pk = "wait"
         /\ threads' = [threads EXCEPT ![t].st = "pended", ![t].po = TRUE,
                               ![t].pd = FALSE,
                               ![t].hld = [ty |-> "thread", id |-> w],
                               ![t].shot = "none",
                               ![t].pin = @ + 1, ![t].lnk = FALSE,
                               ![w].pc = "pendC",
                               ![w].tg = t]
      \/ (* edge 5b, rev 3: parking -> claimed + thread-context release-wait *)
         /\ ~PENDED
         /\ threads[t].st = "parking" /\ threads[t].pk = "wait"
         /\ threads' = [threads EXCEPT ![t].st = "claimed",
                               ![t].hld = [ty |-> "thread", id |-> w],
                               ![t].shot = "none",
                               ![t].pin = @ + 1, ![t].lnk = FALSE,
                               ![w].pc = "relwait",
                               ![w].tg = t]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* Edge 6: claimed -> ready, holder places under the destination lock.     *)
(* Rev 8 (M-2): the destination is computed here from the fresh            *)
(* descriptor inside that lock section, not read from a claim-time stage.  *)
WakePlace(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "wakeC" /\ threads[w].st \in {"running","retired"}
  /\ threads[t].st = "claimed"
  /\ threads' = [threads EXCEPT ![t].st = "ready", ![t].hld = NULL,
                        ![t].pin = @ - 1,
                        ![w].pc = "user", ![w].tg = NULL]
  /\ \E d \in Cores: cores' = [cores EXCEPT ![d].q = @ \cup {t}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Rev-5 5b claimant completion: payload + payload_done release-store,     *)
(* then DONE (no wait, no placement, Sec 3.2). The claimant reads no       *)
(* state: while pd = FALSE nobody can move the thread out of `pended` (the     *)
(* hop's pended arm waits pd -- W2; retire pre-waits pd -- W7).            *)
WakePendDone(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "pendC" /\ threads[w].st \in {"running","retired"}
  /\ threads' = [threads EXCEPT ![t].pd = TRUE, ![t].hld = NULL,
                        ![t].pin = @ - 1,
                        ![w].pc = "user", ![w].tg = NULL]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* Holder's placement CAS fails (`retired`): deferred marking + finalize   *)
(* (retire matrix `claimed` row).                                          *)
WakeTgtRetired(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "wakeC" /\ threads[w].st \in {"running","retired"}
  /\ threads[t].st = "retired"     \* no po read: a wakeC claim is 5a-origin
  /\ threads' = [threads EXCEPT ![t].st = "finalizing", ![t].mo = FALSE,
                        ![t].hld = NULL,
                        ![t].pin = @ - 1,
                        ![t].shot = "none", ![t].dir = "dead", ![t].dres = "none", ![t].dpin = FALSE, ![t].dlv = FALSE, ![t].dsrc = NULL,
                        ![w].pc = "user", ![w].tg = NULL]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* Rev 3 only: thread-context release-wait -- the claimant of a parking-origin *)
(* claim spins until the owner's hop releases the kstack, then places.     *)
RelwaitPlace(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ ~PENDED
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "relwait" /\ threads[w].st \in {"running","retired"}
  /\ threads[t].ks = NULL                              \* the release-wait
  /\ IF threads[t].st = "claimed"
     THEN /\ threads' = [threads EXCEPT ![t].st = "ready", ![t].hld = NULL,
                                ![t].own = NULL,
                                ![t].pk = "none", ![t].pin = @ - 1,
                                ![w].pc = "user", ![w].tg = NULL]
          /\ \E d \in Cores: cores' = [cores EXCEPT ![d].q = @ \cup {t}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
     ELSE /\ threads[t].st = "retired"
          /\ threads' = [threads EXCEPT ![t].st = "finalizing", ![t].mo = FALSE,
                                ![t].hld = NULL,
                                ![t].pin = @ - 1,
                                ![t].dir = "dead", ![t].dres = "none", ![t].dpin = FALSE, ![t].dlv = FALSE, ![t].dsrc = NULL,
                                ![w].pc = "user", ![w].tg = NULL]
          /\ cores' = cores
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(***************************************************************************)
(* Cross-thread suspend of a ready target: edge 5c (ready -> claimed under the *)
(* run-queue lock) then edge 7 (claimed -> waiting, re-containment into a  *)
(* port wait).                                                             *)
(***************************************************************************)
SuspendStart(c) ==
  LET w == cores[c].cur IN
  /\ SUSPEND_ON
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[w].shot = "none"
  /\ \E t \in Threads \ {w}:
       /\ threads[t].st = "ready"
       /\ LET qc == CHOOSE c2 \in Cores: t \in cores[c2].q IN
            /\ cores' = [cores EXCEPT ![qc].q = @ \ {t}]
            /\ threads' = [threads EXCEPT ![t].st = "claimed",
                                  ![t].hld = [ty |-> "thread", id |-> w],
                                  ![t].pin = @ + 1, ![w].pc = "suspC",
                                  ![w].tg = t]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

SuspendPlace(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "suspC" /\ threads[w].st \in {"running","retired"}
  /\ threads[t].st = "claimed"
  /\ threads' = [threads EXCEPT ![t].st = "waiting",
                        ![t].hld = NULL, ![t].pin = @ - 1, ![t].lnk = TRUE,
                        ![w].pc = "user", ![w].tg = NULL]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

SuspendTgtRetired(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "suspC" /\ threads[w].st \in {"running","retired"}
  /\ threads[t].st = "retired"
  /\ threads' = [threads EXCEPT ![t].st = "finalizing", ![t].mo = FALSE,
                        ![t].hld = NULL, ![t].pin = @ - 1,
                        ![t].dir = "dead", ![t].dres = "none", ![t].dpin = FALSE, ![t].dlv = FALSE, ![t].dsrc = NULL,
                        ![w].pc = "user", ![w].tg = NULL]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(***************************************************************************)
(* The rendezvous window (Sec 8.3, publish-first): stage payload, publish  *)
(* the sender `parking(reply_pin)` AND claim the parked receiver in the    *)
(* same port-lock section, drop the lock; delivery runs in the bounded     *)
(* post-publish window (Sec 3.2 step 3); place the receiver; hop. The      *)
(* sender holds the receiver's claim while itself `parking`; current       *)
(* implementation pins the receiver whose lifecycle is protected, not the  *)
(* sender. The sender is untimed (the                                      *)
(* Sec 2.2 untimed-sender assumption: no deadline registration, so no      *)
(* waker can reach it during the pin write).                               *)
(***************************************************************************)
RvStart(c) ==
  LET s == cores[c].cur IN
  /\ RV_ON
  /\ ThreadCtx(c) /\ threads[s].pc = "user" /\ threads[s].st = "running"
  /\ threads[s].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[s].shot = "none" /\ threads[s].pin = 0
  /\ \E r \in Threads \ {s}:
      \/ (* receiver parked: 5a claim *)
         /\ threads[r].st = "waiting"
         /\ threads' = [threads EXCEPT
              ![s].st = "parking", ![s].pk = "wait",
              ![s].lnk = TRUE, ![s].vm = "host",
              ![s].pc = "rvC", ![s].tg = r,
              ![r].st = "claimed", ![r].hld = [ty |-> "thread", id |-> s],
              ![r].pin = @ + 1, ![r].shot = "none", ![r].lnk = FALSE]
      \/ (* receiver itself mid-park: 5b claim -> pended; the receiver's  *)
         (* own core discharges (Sec 8.3)                                 *)
         /\ PENDED
         /\ threads[r].st = "parking" /\ threads[r].pk = "wait"
         /\ threads' = [threads EXCEPT
              ![s].st = "parking", ![s].pk = "wait",
              ![s].lnk = TRUE, ![s].vm = "host",
              ![s].pc = "rvC", ![s].tg = r,
              ![r].st = "pended", ![r].po = TRUE, ![r].pd = FALSE,
              ![r].hld = [ty |-> "thread", id |-> s],
              ![r].pin = @ + 1, ![r].shot = "none", ![r].lnk = FALSE]
  /\ cores' = [cores EXCEPT ![c].pc = "rvdeliver", ![c].outg = s]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* The delivery in the bounded pre-hop window. Runs regardless of the      *)
(* sender's own state; the receiver pin prevents target retirement until   *)
(* this holder publishes or drops the claim.                               *)
(* Branches on the claim the sender itself won:                            *)
(*  - claimed receiver: mint ok -> place (edge 6); mint failure -> relink  *)
(*    receiver (edge 7 delivery-failure arm) and the sender stays parked   *)
(*    in the port queue (Sec 11.5); receiver retired -> holder marking +   *)
(*    finalize (edge 6 failure arm).                                       *)
(*  - pended receiver: payload + payload_done, DONE (5b claimant body;     *)
(*    mint-failure ordering for this branch is unspecified in the doc --   *)
(*    README gap G-RV1 -- literal reading: no failure arm).                *)
RvDeliver(c) ==
  LET s == cores[c].outg
      r == threads[s].tg IN
  /\ cores[c].pc = "rvdeliver" /\ cores[c].irq = NULL
  /\ \/ /\ threads[r].st = "claimed"
        /\ \/ /\ threads' = [threads EXCEPT            \* mint ok: edge 6 placement
                    ![r].st = "ready", ![r].hld = NULL,
                    ![r].pin = @ - 1,
                    ![s].pc = "user", ![s].tg = NULL]
              /\ \E d \in Cores:
                   cores' = [cores EXCEPT ![c].pc = "hopRel",
                                          ![d].q = @ \cup {r}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
           \/ /\ threads' = [threads EXCEPT           \* mint failure: edge 7
                    ![r].st = "waiting", ![r].hld = NULL,
                    ![r].pin = @ - 1, ![r].lnk = TRUE,
                    ![s].pc = "user", ![s].tg = NULL]
              /\ cores' = [cores EXCEPT ![c].pc = "hopRel"]
     \/ /\ threads[r].st = "pended"
        /\ threads' = [threads EXCEPT
             ![r].pd = TRUE, ![r].hld = NULL, ![r].pin = @ - 1,
             ![s].pc = "user", ![s].tg = NULL]
        /\ cores' = [cores EXCEPT ![c].pc = "hopRel"]
     \/ /\ threads[r].st = "retired"                  \* claimed-origin only:
        (* retire of a pended r pre-waits pd, which only this delivery    *)
        (* could set -- so a retired r here came from `claimed`.          *)
        /\ threads' = [threads EXCEPT
             ![r].st = "finalizing", ![r].mo = FALSE,
             ![r].hld = NULL, ![r].pin = @ - 1,
             ![r].dir = "dead", ![r].dres = "none", ![r].dpin = FALSE, ![r].dlv = FALSE, ![r].dsrc = NULL,
             ![s].pc = "user", ![s].tg = NULL]
        /\ cores' = [cores EXCEPT ![c].pc = "hopRel"]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(***************************************************************************)
(* The suspend directive (Sec 2.5): none -> claiming -> armed -> none |    *)
(* failed | dead. `failed` carries dres and is cleared only by the         *)
(* matching waiter ack; success is only actual consume/rendezvous. The     *)
(* suspender holds a target lifetime pin (`dpin`) from the successful      *)
(* directive claim through every waiter return, but remains preemptible    *)
(* throughout (W5); `dpin` blocks retire, not the owner's tick/consume.    *)
(***************************************************************************)
(* CYCLE_REJECT = "self", CAS 1: the suspender marks its OWN directive    *)
(* word none -> "suspending" before it touches the target's. That single   *)
(* word is the whole mechanism, and the correctness argument is one        *)
(* sentence: A CYCLE REQUIRES EVERY PARTICIPANT TO BE BOTH SUSPENDER AND   *)
(* TARGET; THE SELF-MARK MAKES THOSE MUTUALLY EXCLUSIVE. So cycles of      *)
(* EVERY length are closed, without detecting cycles at all.               *)
(*                                                                        *)
(* HOLD DURATION -- this sets the E_BUSY rate, so it is normative          *)
(* (Sec 2.5.1): the mark is held for the WHOLE syscall. DirClaim and       *)
(* DirArm's success arm deliberately do NOT clear it; it is released only  *)
(* where the call RETURNS -- DirSelfAbort (CAS 2 failed), DirArm's E_TERM  *)
(* arm, and both DirLoop exits. Consequence: ANY two overlapping cross-thread  *)
(* suspends can yield E_BUSY, cycle or not. An early-release variant       *)
(* (clear right after CAS 2) would make E_BUSY rare and appears to stay    *)
(* correct by a longer argument, but it is not what this module checks.    *)
DirSelfMark(c) ==
  LET u == cores[c].cur IN
  /\ DIR_ON /\ CYCLE_REJECT = "self"
  /\ ThreadCtx(c) /\ threads[u].pc = "user" /\ threads[u].st = "running"
  /\ threads[u].dir = "none"     \* fails if someone is suspending US (E_BUSY)
  /\ threads[u].pin = 0          \* T3 rule (b), as DirClaim
  (* ROUND-8 M-1: the mark is taken ONLY on the directive path, i.e. only *)
  (* once the suspender has resolved a target and observed it `running`.  *)
  (* Rev 8 marked UNCONDITIONALLY, before the target was even chosen,     *)
  (* which reserved the caller for every cross-thread suspend including the   *)
  (* 5c (`ready`) and 5a (`idle_wait`) routes that never touch a          *)
  (* directive -- a strictly wider E_BUSY contract than Sec 2.5 scopes    *)
  (* or than Sec 11.8's proposed spec text describes. The observation is  *)
  (* racy, and deliberately so: the target may leave `running` before     *)
  (* CAS 2, and DirClaim re-validates.                                    *)
  /\ \E t \in Threads \ {u}:
       /\ threads[t].st = "running"
       /\ threads' = [threads EXCEPT ![u].dir = "suspending", ![u].pc = "dirM",
                             ![u].tg = t]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* CAS 2 failed (the target was not claimable -- it is itself suspending,  *)
(* or already claimed, or left `running`): return E_BUSY and release the   *)
(* self-mark. Bounded continuation of an already-started syscall.          *)
DirSelfAbort(c) ==
  LET u == cores[c].cur IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ u # NULL
  /\ threads[u].pc = "dirM" /\ threads[u].st \in {"running","retired"}
  /\ threads' = [threads EXCEPT ![u].dir = "none", ![u].pc = "user"]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

DirClaim(c) ==
  LET u == cores[c].cur IN
  /\ DIR_ON
  /\ ThreadCtx(c) /\ threads[u].st = "running"
  /\ threads[u].pc = (IF CYCLE_REJECT = "self" THEN "dirM" ELSE "user")
  /\ threads[u].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[u].pin = 0
     (* T3 rule (b) / W5 waiter-context column: the directive wait may     *)
     (* not be entered holding any lock or claim -- "asserted". WITHOUT    *)
     (* this guard TLC finds a hard deadlock in seconds: two suspenders    *)
     (* mutually in dirW, each holding a pin-class lock, neither           *)
     (* preemptible under the very pin gate F3 widened -- the spec's       *)
     (* mutual-suspend break (Sec 2.5) is CONDITIONAL on this assert.     *)
     (* See README, finding N1.                                            *)
  /\ CYCLE_REJECT = "self" => threads[u].dir = "suspending"   \* CAS 1 done
  /\ \E t \in (IF CYCLE_REJECT = "self" THEN {threads[u].tg} ELSE Threads \ {u}):
       \* under "self" the target was resolved at CAS 1 and is RE-VALIDATED
       \* here (it may have left `running` since); under the other machines
       \* the target is chosen here as before
       /\ threads[t].st = "running"      \* suspend of a running target
       /\ threads[t].dir = "none"        \* CAS none -> claiming (loser E_BUSY)
       (* Under "self" this SAME guard is the whole cycle check: a target *)
       (* that is itself an active suspender has dir = "suspending", not  *)
       (* "none", so it is not claimable. No second lock, no lock order.  *)
       (* SYMMETRIC-SUSPEND REJECTION (rev 8, Sec 2.5). Under both thread   *)
       (* gen locks -- taken lowest slot index first, which is what      *)
       (* makes check-and-arm ONE atomic decision and what this single   *)
       (* action represents -- the caller rejects if its OWN directive   *)
       (* is already claimed by the target: t is suspending u, so        *)
       (* arming t would close a 2-cycle. Exactly one of a symmetric     *)
       (* pair can win, because the pair-ordered acquire serialises      *)
       (* them and the loser then observes the winner's write.           *)
       (* The locks are RELEASED before the W5 wait (DirLoop) is         *)
       (* entered -- waiting inside them would rebuild N1.               *)
       /\ CYCLE_REJECT = "pair" => threads[u].dsrc # t
       /\ threads' = [threads EXCEPT ![t].dir = "claiming", ![t].dpin = TRUE,
                             ![t].dsrc = u,
                             ![u].pc = "dirC", ![u].tg = t,
                             ![u].dgen = threads[t].gen]
          (* ROUND-12: the gen snapshot belongs HERE, where the suspender  *)
          (* acquires its reference to the target -- not at DirArm. Taken  *)
          (* at the arm it is sampled AFTER any recycle, so a slot that    *)
          (* was freed and reused between claim and arm reads as fresh.    *)
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* Write directive_port; then CAS `claiming -> armed`; wake IPI            *)
(* (abstracted). Rev 6 (G-D1 closed): a CAS, not a store -- a finalize     *)
(* that set `dead` (or a recycled slot, `none`; gen-staleness folded in)   *)
(* fails the CAS and the suspender returns E_TERM without ever writing a   *)
(* freed slot's word.                                                      *)
DirArm(c) ==
  LET u == cores[c].cur
      t == threads[u].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ u # NULL
  /\ threads[u].pc = "dirC" /\ threads[u].st \in {"running","retired"}
  (* ROUND-12: Sec 2.5's G-D1 arm CAS, encoded at last. The guard was     *)
  (* `dir = "claiming"` ALONE for six revisions, which lets a suspender    *)
  (* arm a claim that is not its own and arm a RECYCLED slot -- exactly    *)
  (* what G-D1 has forbidden since revision 6: "if finalize set `dead`     *)
  (* (or the slot was recycled; gen-stale) between the claim and the arm,  *)
  (* the arm CAS fails and the suspender returns E_TERM without writing a  *)
  (* freed slot's word." Nothing exercised it until revision 12 gave the   *)
  (* model a gen for the check to be about; `InvNoFalseSuspendSuccess`     *)
  (* then found it in `medium` at 14M states.                              *)
  /\ IF /\ threads[t].dir = "claiming"
        /\ threads[t].dsrc = u              \* MY claim, not a third party's
        /\ threads[t].gen = threads[u].dgen     \* slot not recycled since the claim
     THEN threads' = [threads EXCEPT ![t].dir = "armed", ![t].pok = TRUE,
                             ![u].pc = "dirW", ![u].dlv = FALSE]
     ELSE threads' = [threads EXCEPT ![u].pc = "user", ![u].tg = NULL,
                             ![t].dpin = FALSE,
                             ![u].dir = IF CYCLE_REJECT = "self"
                                        THEN "none" ELSE @]     \* E_TERM
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* The terminal re-check/disarm loop (round-4 F5 form). Steps exist only   *)
(* when the loop can decide; the pure spin (target running, still armed)   *)
(* is stuttering -- the spinner is preemptible with pin = 0 (W5).          *)
(* On breaking because directive_state left `armed`: `none` = consumed     *)
(* (success), `dead` = finalize cleared it (E_TERM, round-4 F6). On a      *)
(* disarm CAS win the re-dispatch by settled state is abstracted to        *)
(* returning to user (the 5c / 5a re-dispatch paths exist as their own     *)
(* model actions; transients re-read per Sec 8.3).                         *)
DirLoop(c) ==
  LET u == cores[c].cur
      t == threads[u].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ u # NULL
  /\ threads[u].pc = "dirW" /\ threads[u].st \in {"running","retired"}
  (* ROUND-10 C-D + M-A. Rev 10's loop broke on `dir # "armed"` and had  *)
  (* NO re-validation anywhere -- i.e. the model literally encoded the    *)
  (* pre-rev-10 bug while the doc described the fix. The break is now on  *)
  (* ARM OWNERSHIP, so it is insensitive to which value the word holds:   *)
  (* a fresh `claiming` or a fresh `armed` from a THIRD party both read   *)
  (* as "my arm ended", which is the fact the suspender actually needs.   *)
  /\ \/ /\ IF DIR_OWNED THEN \/ threads[t].dir # "armed"
                            \/ threads[t].dsrc # u      \* not MY arm any more
                       ELSE threads[t].dir # "armed"
        /\ ~(threads[t].dir = "failed" /\ threads[t].dsrc = u)
        (* LITERAL Sec 2.5: "if directive_state != armed -> break". The   *)
        (* spec's break analysis enumerates only `none` (consumed) and    *)
        (* `dead` (E_TERM), but a third party's fresh `claiming` is also  *)
        (* observable here -- derived meaning: armed reaches claiming     *)
        (* only through none, so the suspension was consumed (README gap  *)
        (* G-D3). An earlier draft of this model broke only on            *)
        (* {none,dead} -- narrower than the spec -- and TLC produced a    *)
        (* 3-party wedge from that narrowing (README N2).                 *)
        (* ROUND-11 C-1: the DISAMBIGUATOR. Rev 11 re-validated only the *)
        (* PORT, which is not enough: Sec 8.2's edge-10 release body      *)
        (* writes `dead` and then `slot zero + freelist` a few steps      *)
        (* later in the SAME routine, and `none` must be all-zeroes or a  *)
        (* recycled slot is permanently unsuspendable (round-9 C-1). So   *)
        (* the zero converts `dead` back to `none`, and a suspender whose *)
        (* target was terminated + finalized reads `none` beside a LIVE   *)
        (* port and returns SUCCESS -- round-4 F6 re-opened by a later    *)
        (* step of its own row. Fix: also re-validate the TARGET's gen.   *)
        /\ LET staleGen == threads[t].gen # threads[u].dgen
               concludesSuccess ==
                 /\ ~threads[u].dlv     \* MY arm was never delivered
                 /\ threads[t].pok    \* port re-validation passes (rev 11)
                 /\ threads[t].dir # "dead"  \* G11: terminal marker fails suspend
                 /\ ~(DIR_GENCHK /\ staleGen)  \* target gen (rev 12, C-1)
           IN threads' = [threads EXCEPT ![u].pc = "user", ![u].tg = NULL,
                                 ![u].dfs = @ \/ concludesSuccess,
                                 ![t].dpin = FALSE,
                                 ![u].dir = IF CYCLE_REJECT = "self"
                                            THEN "none" ELSE @]
     \/ /\ threads[t].dir = "failed"
        /\ threads[t].dsrc = u
        /\ threads[t].dres = "fail"
        (* Owner-side consume failure is a terminal result for THIS arm,   *)
        (* not success. The matching waiter reads dres while the word is   *)
        (* failed, ACKs by clearing the word, and returns the real error   *)
        (* abstracted by dres = "fail"; dres may remain stale afterward.   *)
        /\ threads' = [threads EXCEPT ![t].dir = "none",
                              ![t].dpin = FALSE,
                              ![t].dsrc = NULL,
                              ![u].pc = "user", ![u].tg = NULL,
                              ![u].dir = IF CYCLE_REJECT = "self"
                                         THEN "none" ELSE @]
     \/ /\ threads[t].dir = "armed"
        /\ DIR_OWNED => threads[t].dsrc = u   \* still MY arm (C-D failure 2)
        /\ threads[t].st # "running"                  \* left `running`
        /\ threads' = [threads EXCEPT ![t].dir = "none",  \* disarm CAS wins
                              ![t].dpin = FALSE,
                              ![t].dbad = @ \/ (threads[t].dsrc # u),  \* GHOST
                              ![t].dsrc = NULL,
                              ![u].pc = "user", ![u].tg = NULL,
                              ![u].dir = IF CYCLE_REJECT = "self"
                                         THEN "none" ELSE @]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* Owner-side stale/bad-port consume failure. This keeps the historical    *)
(* DirDrop name and DROP_BUDGET switch because the configs use them, but   *)
(* it no longer models stale port as `armed -> none`. The owner publishes  *)
(* failure and transitions `armed -> failed`; only the matching waiter      *)
(* acks failed -> none in DirLoop. dres may remain stale after the ack.     *)
DirDrop(c) ==
  LET e == cores[c].cur IN
  /\ DIR_ON /\ DIR_DROP
  /\ pb > 0 /\ pb' = pb - 1
  /\ ThreadCtx(c) /\ threads[e].pc = "user" /\ threads[e].st = "running"
  /\ threads[e].dir = "armed"
  /\ threads[e].dsrc # NULL
  /\ threads[e].pin = 0
  /\ threads' = [threads EXCEPT ![e].pok = FALSE,     \* the port went stale
                        ![e].dres = "fail", ![e].dir = "failed"]
  /\ UNCHANGED <<processes, cores, tb, cb, db>>

(* Other owner-side consume failure with a live target/port. Same result   *)
(* publication/ack protocol as DirDrop; separate so stale-port failures    *)
(* can remain budgeted for old ABA scopes.                                 *)
DirFail(c) ==
  LET e == cores[c].cur IN
  /\ DIR_ON
  /\ ThreadCtx(c) /\ threads[e].pc = "user" /\ threads[e].st = "running"
  /\ threads[e].dir = "armed"
  /\ threads[e].dsrc # NULL
  /\ threads[e].pok
  /\ threads[e].shot = "none" /\ threads[e].pin = 0
  /\ threads' = [threads EXCEPT ![e].dres = "fail", ![e].dir = "failed"]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* Owner-side consumption at a user-boundary entry check (Sec 3.1 rule 3): *)
(* gen-validate the port (abstracted), standard edge-3 park into it.       *)
(* `directive_state` resets to none "after the park commits" -- LITERAL    *)
(* reading chosen: the edge-3 publish is the park's commit, so the reset   *)
(* is atomic with the publish (README gap G-D2 records the alternative     *)
(* hop-commit reading and its observable difference).                      *)
DirConsume(c) ==
  LET e == cores[c].cur IN
  /\ ThreadCtx(c) /\ threads[e].pc = "user" /\ threads[e].st = "running"
  /\ threads[e].dir = "armed"
  /\ threads[e].shot = "none" /\ threads[e].pin = 0
  /\ threads' = IF threads[e].dsrc # NULL
            THEN [threads EXCEPT ![e].st = "parking", ![e].pk = "wait",
                             ![e].lnk = TRUE, ![e].vm = "host",
                             ![e].dir = "none",
                             ![threads[e].dsrc].dlv = TRUE,   \* credit the ARMER
                             ![e].dsrc = NULL]
            ELSE [threads EXCEPT ![e].st = "parking", ![e].pk = "wait",
                             ![e].lnk = TRUE, ![e].vm = "host",
                             ![e].dir = "none"]
  /\ cores' = [cores EXCEPT ![c].pc = "hopRel", ![c].outg = e]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(***************************************************************************)
(* T1: interrupt-context wake sources. One generic one-shot source stands  *)
(* for deadline expiry and device-IRQ delivery: the pop is    *)
(* consumed by the claim exactly once (both run under the same reaching    *)
(* lock, so pop+claim is one atomic action -- W1 masking).                 *)
(* The handler's remaining body (place / payload / release-wait) is the    *)
(* nested interrupt frame: while it is live the interrupted continuation   *)
(* below it CANNOT resume.                                                 *)
(***************************************************************************)
FireAt(c, e) ==
  /\ cores[c].irq = NULL
  /\ threads[e].shot = "armed"
  /\ \/ (* 5a from interrupt context: waiting target, place inline *)
        /\ threads[e].st = "waiting"
        /\ threads' = [threads EXCEPT ![e].st = "claimed", ![e].shot = "consumed",
                              ![e].hld = [ty |-> "irq", cid |-> c],
                              ![e].pin = @ + 1, ![e].lnk = FALSE]
        /\ cores' = [cores EXCEPT ![c].irq =
                      [op |-> "wake", tgt |-> e, ph |-> "place"]]
     \/ (* 5b from interrupt context, rev 5: pend and be done *)
        /\ PENDED
        /\ threads[e].st = "parking" /\ threads[e].pk = "wait"
        /\ threads' = [threads EXCEPT ![e].st = "pended", ![e].shot = "consumed",
                              ![e].po = TRUE, ![e].pd = FALSE,
                              ![e].hld = [ty |-> "irq", cid |-> c],
                              ![e].pin = @ + 1, ![e].lnk = FALSE]
        /\ cores' = [cores EXCEPT ![c].irq =
                      [op |-> "wake", tgt |-> e, ph |-> "pend"]]
     \/ (* pop finds the target already `retired` (retire CAS done, its   *)
        (* container unwind still pending -- the G4 window): the claim    *)
        (* CAS fails on `retired`, the pop is consumed, the wake is moot  *)
        (* (the thread is dying and its wake payload is level-encoded).       *)
        /\ threads[e].st = "retired"
        /\ threads' = [threads EXCEPT ![e].shot = "none"]
        /\ cores' = cores
     \/ (* rev 3, same-core: DECLINE -- the pop is consumed, no claim, no  *)
        (* retry party. This is X3: for a one-shot source the wake is      *)
        (* lost permanently.                                               *)
        /\ ~PENDED
        /\ threads[e].st = "parking" /\ threads[e].pk = "wait"
        /\ threads[e].own = c
        /\ threads' = [threads EXCEPT ![e].shot = "consumed"]
        /\ cores' = cores
     \/ (* rev 3, cross-core: claim + interrupt-context release-wait (X2) *)
        /\ ~PENDED
        /\ threads[e].st = "parking" /\ threads[e].pk = "wait"
        /\ threads[e].own # c
        /\ threads' = [threads EXCEPT ![e].st = "claimed", ![e].shot = "consumed",
                              ![e].hld = [ty |-> "irq", cid |-> c],
                              ![e].pin = @ + 1, ![e].lnk = FALSE]
        /\ cores' = [cores EXCEPT ![c].irq =
                      [op |-> "wake", tgt |-> e, ph |-> "relwait"]]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Interrupt frame body: inline placement (5a discharge).                  *)
IrqWakePlace(c) ==
  LET f == cores[c].irq
      t == f.tgt IN
  /\ f # NULL /\ f.op = "wake" /\ f.ph = "place"
  /\ IF threads[t].st = "claimed"
     THEN /\ threads' = [threads EXCEPT ![t].st = "ready", ![t].hld = NULL,
                                ![t].pin = @ - 1, ![t].shot = "none"]
          /\ \E d \in Cores:
               cores' = [cores EXCEPT ![c].irq = NULL, ![d].q = @ \cup {t}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
     ELSE /\ threads[t].st = "retired"          \* holder's placement CAS fails
          /\ threads' = [threads EXCEPT ![t].st = "finalizing", ![t].mo = FALSE,
                                ![t].hld = NULL, ![t].pin = @ - 1,
                                ![t].shot = "none",
                                ![t].dir = "dead", ![t].dres = "none", ![t].dpin = FALSE, ![t].dlv = FALSE, ![t].dsrc = NULL]
          /\ cores' = [cores EXCEPT ![c].irq = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Interrupt frame body: rev-5 5b claimant completion, then RETURN.        *)
IrqPendDone(c) ==
  LET f == cores[c].irq
      t == f.tgt IN
  /\ f # NULL /\ f.op = "wake" /\ f.ph = "pend"
  /\ threads' = [threads EXCEPT ![t].pd = TRUE, ![t].hld = NULL,
                        ![t].pin = @ - 1]
  /\ cores' = [cores EXCEPT ![c].irq = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Rev 3 only: the interrupt-context release-wait. The frame spins on the  *)
(* target's kstack release; the interrupted continuation beneath it (which *)
(* may be this core's OWN pre-hop park sequence) cannot run until it       *)
(* returns. This edge is the X2 deadlock.                                  *)
IrqRelwait(c) ==
  LET f == cores[c].irq
      t == f.tgt IN
  /\ f # NULL /\ f.op = "wake" /\ f.ph = "relwait"
  /\ threads[t].ks = NULL                              \* the release-wait
  /\ IF threads[t].st = "claimed"
     THEN /\ threads' = [threads EXCEPT ![t].st = "ready", ![t].hld = NULL,
                                ![t].own = NULL,
                                ![t].pk = "none", ![t].pin = @ - 1,
                                ![t].shot = "none"]
          /\ \E d \in Cores:
               cores' = [cores EXCEPT ![c].irq = NULL, ![d].q = @ \cup {t}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
     ELSE /\ threads[t].st = "retired"
          /\ threads' = [threads EXCEPT ![t].st = "finalizing", ![t].mo = FALSE,
                                ![t].hld = NULL, ![t].pin = @ - 1,
                                ![t].shot = "none",
                                ![t].dir = "dead", ![t].dres = "none", ![t].dpin = FALSE, ![t].dlv = FALSE, ![t].dsrc = NULL]
          /\ cores' = [cores EXCEPT ![c].irq = NULL]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(***************************************************************************)
(* Edge 9 + Sec 5.2 retire matrix + Sec 8.2 step 1. Shared row operators:  *)
(* used by the environment retirer (teardown walks, scheduler context)     *)
(* and by the thread-context Terminate frame (W3/W4).                          *)
(*                                                                        *)
(* W7 (rev 5, round-4 F1): a retire observing `pended` acquire-waits      *)
(* payload_done BEFORE its CAS -- modelled as the pd conjunct in           *)
(* RetireEnabled, a blocking guard. The CAS-loop re-dispatch on a fresh   *)
(* state (owner's discharge winning meanwhile) is inherent: each row is   *)
(* guarded by the CURRENT state. Sec 9.2: "retire-from-`pended` asserts   *)
(* `payload_done` before its CAS" is invariant InvRetiredPdOrdered.       *)
(* In rev 3 (~PENDED) there is no `pended` state and no W7.               *)
(* Current implementation retire marks the target retiring, waits target  *)
(* lifecycle pins to drain, then performs retire/dead-gen bump under the   *)
(* slab lock. The model represents that wait as pin = 0 in RetireEnabled. *)
(***************************************************************************)
RetireEnabled(e) ==
  /\ threads[e].st \in {"ready","waiting","running","parking","claimed","pended"}
  /\ threads[e].pin = 0
  /\ ~threads[e].dpin
  /\ (threads[e].st = "pended" /\ F1_MODE = "rev5") => threads[e].pd
     \* W7 pre-CAS wait (rev 5). Under F1_MODE # "rev5" (the rev-4 F1
     \* gates) retire flips a pended thread with the payload incomplete.

(* T2 marking column: eager for stable descriptors (ready/waiting/running  *)
(* and pin-free parking); deferred to the named discharger for             *)
(* claimed/pended and pin-writing parking (the rendezvous sender).         *)
(* Rev 8 (M-3): `mark_state` is one word -- "none" (no retire yet),        *)
(* "owed" (deferred, a named discharger owes it), "done". The retirer's    *)
(* write happens under the retire CAS's own exclusivity; the discharger's  *)
(* owed -> done is a release-store enabled only by observing "owed"; the   *)
(* terminator's W4 is the acquire side. Same SPSC hand-off shape as        *)
(* payload_done, and the model's rev-7 mo/mk pair collapses into it.       *)
RetireThreadsAfter(e) ==
  CASE threads[e].st = "ready" ->                      \* inline finalize; the
         \* frame dies with the slot (pc/tg reset) -- safe per T2 ready x
         \* K: the lock dichotomy + pin gate mean it holds nothing
         [threads EXCEPT ![e].st = "finalizing", ![e].mo = FALSE,
                     ![e].shot = "none",
                     ![e].own = NULL, ![e].pk = "none",
                     ![e].lnk = FALSE, ![e].dir = "dead", ![e].dres = "none", ![e].dpin = FALSE, ![e].dlv = FALSE, ![e].dsrc = NULL,
                     ![e].pc = "user", ![e].tg = NULL]
    [] threads[e].st = "waiting" ->                    \* inline, after unwind
         [threads EXCEPT ![e].st = "finalizing", ![e].mo = FALSE,
                     ![e].shot = "none",
                     ![e].own = NULL, ![e].lnk = FALSE, ![e].dir = "dead", ![e].dres = "none", ![e].dpin = FALSE, ![e].dlv = FALSE, ![e].dsrc = NULL,
                     ![e].pc = "user", ![e].tg = NULL]
    [] threads[e].st = "running" ->                    \* boundary/hop discovery
         [threads EXCEPT ![e].st = "retired", ![e].mo = FALSE,
                     ![e].vm = IF e \in VCPU_THREADS /\ threads[e].vm = "guest"
                                THEN IF VCPU_CANCEL THEN "cancel" ELSE "guest"
                                ELSE "host"]
    [] threads[e].st = "parking" ->                    \* hop discovery; marking
         \* deferred iff pin-writing (T2 marking column). The container
         \* unwind is retire STEP 3, after this CAS (Sec 8.2) -- it is the
         \* separate RetireUnwind action, NOT atomic with the CAS (G4).
         [threads EXCEPT ![e].st = "retired",
                     ![e].mo = (threads[e].pin > 0)]
    [] threads[e].st = "claimed" ->                    \* holder discharges
         [threads EXCEPT ![e].st = "retired", ![e].mo = TRUE]
    [] threads[e].st = "pended" ->                     \* owner's hop discharges
         [threads EXCEPT ![e].st = "retired", ![e].mo = TRUE]

RetireCoresAfter(e) ==
  IF threads[e].st = "ready"
  THEN LET qc == CHOOSE c \in Cores: e \in cores[c].q IN
         [cores EXCEPT ![qc].q = @ \ {e}]
  ELSE cores

(* Environment retirer (scheduler-context teardown walks etc.).            *)
RetireThread(e) ==
  /\ tb > 0
  /\ tb' = tb - 1 /\ UNCHANGED <<processes, cb, db, pb>>
  /\ RetireEnabled(e)
  /\ threads' = RetireThreadsAfter(e)
  /\ cores' = RetireCoresAfter(e)

(* G16: the same lifecycle machine now represents self-delete's process
   reference crossing the thread-stack to park-stack boundary. A request
   is produced before the caller self-retires. The consumer can begin only
   after the caller has left `current` and clears `pending` as it takes
   ownership in `active`; that reference stays through phase 2. Process
   IDs are abstract slab identities and `gen` prevents an ABA handoff. *)
QueueTeardown(c) ==
  LET w == cores[c].cur
      p == threads[w].proc IN
  /\ G16_ON /\ ThreadCtx(c)
  /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ processes[p].phase = "live"
  /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ \E kind \in {"self_delete","unhandled_fault"}:
       cores' = [cores EXCEPT ![c].pending =
                  [proc |-> p, gen |-> processes[p].gen,
                   owner |-> w, kind |-> kind]]
  /\ threads' = [threads EXCEPT ![w].pc = "teardown"]
  /\ processes' = [processes EXCEPT ![p].phase = "queued"]
  /\ UNCHANGED <<tb, cb, db, pb>>

SelfRetireForTeardown(c) ==
  LET w == cores[c].cur IN
  /\ G16_ON /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL
  /\ w # NULL /\ threads[w].pc = "teardown"
  /\ cores[c].pending # NULL /\ cores[c].pending.owner = w
  /\ RetireEnabled(w)
  /\ threads' = [RetireThreadsAfter(w) EXCEPT ![w].pc = "user"]
  /\ cores' = RetireCoresAfter(w)
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

ConsumeTeardown(c) ==
  LET req == cores[c].pending
      p == req.proc IN
  /\ G16_ON /\ req # NULL /\ cores[c].active = NULL
  /\ cores[c].pc = "idle" /\ cores[c].cur = NULL
  /\ threads[req.owner].proc = p
  /\ threads[req.owner].st \in {"retired","finalizing","freed"}
  /\ threads[req.owner].ks = NULL
  /\ processes[p].phase = "queued"
  /\ processes[p].gen = req.gen /\ processes[p].consumes = 0
  /\ cores' = [cores EXCEPT ![c].pending = NULL,
                            ![c].active = IF G16_DROP_REF THEN NULL ELSE req]
  /\ processes' = [processes EXCEPT ![p].phase = "dead",
                                   ![p].consumes = 1]
  /\ threads' = [e \in Threads |->
                   IF threads[e].proc = p
                   THEN [threads[e] EXCEPT !.dd = TRUE]
                   ELSE threads[e]]
  /\ UNCHANGED <<tb, cb, db, pb>>

TeardownRetire(c, e) ==
  LET req == cores[c].active IN
  /\ G16_ON /\ req # NULL /\ processes[req.proc].phase = "dead"
  /\ threads[e].proc = req.proc /\ RetireEnabled(e)
  /\ threads' = RetireThreadsAfter(e)
  /\ cores' = RetireCoresAfter(e)
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

FinishTeardown(c) ==
  LET req == cores[c].active
      p == req.proc IN
  /\ G16_ON /\ req # NULL
  /\ processes[p].phase = "dead" /\ processes[p].gen = req.gen
  /\ \A e \in Threads: threads[e].proc = p => threads[e].st = "freed"
  /\ cores' = [cores EXCEPT ![c].active = NULL]
  /\ processes' = [processes EXCEPT ![p].phase = "done",
                                   ![p].gen = (@ + 1) % 2]
  /\ UNCHANGED <<threads, tb, cb, db, pb>>

(* REVISION-5 LITERAL ONLY (~FIN_UNWIND): retire's step-3 container        *)
(* unwind as a separate retirer continuation after its CAS, running        *)
(* CONCURRENTLY with the routed finalizer -- nothing orders them, which    *)
(* is finding N4 (it can run post-freed: an unwind walking a finalized     *)
(* slot). Revision 6 DELETES this step: the finalizer owns the unwind      *)
(* (one unwinder, one discharger), so under FIN_UNWIND this action does    *)
(* not exist.                                                              *)
RetireUnwind(e) ==
  /\ ~FIN_UNWIND
  /\ threads[e].st \in {"retired","freed"}
  /\ threads[e].lnk \/ threads[e].shot = "armed"
  /\ threads' = [threads EXCEPT ![e].lnk = FALSE, ![e].shot = "none"]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* G11: finalize publishes a terminal directive marker before the slab
   release body clears the slot to all zeroes. Keep that intermediate value
   reachable so a competing directive waiter can observe failure. Reuse is
   held until the clear; a new thread must never inherit a dead directive. *)
ClearFreedDirective(e) ==
  /\ threads[e].st = "finalizing" /\ threads[e].dir = "dead"
  /\ threads' = [threads EXCEPT ![e].st = "freed", ![e].dir = "none",
                        ![e].gen = (@ + 1) % 8]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* thread-context terminate (L5), SPLIT in revision 9 (round-8 C-1).        *)
(*                                                                        *)
(* Rev 8 modelled terminate as ONE action whose guard required the caller *)
(* to be `running`. That made the caller's own retirement mid-syscall     *)
(* INEXPRESSIBLE, and with it the entire mutual-terminate shape. It also  *)
(* excluded self-terminate, citing Sec 8.2 -- a WRONG citation: Sec 8.2  *)
(* is `delete(SLOT_SELF)` on a process, a different syscall.    *)
(* specv3 Sec [terminate] licenses no error for a self target, so        *)
(* `terminate(self())` must succeed and the model must contain it.       *)
(*                                                                        *)
(* The split: TermStart is the syscall entry (caller must be running);   *)
(* TermRetire performs the edge-9 retire and enters the W3/W4 wait, and  *)
(* its guard admits st = "retired" -- so the window in which the CALLER  *)
(* is itself retired between the two steps is now reachable. That window *)
(* is exactly round-8 C-1: A and B each terminate the other, both end up *)
(* `retired` in kernel frames, and a retired thread in a kernel frame is     *)
(* moved by NOTHING (the requeue CAS fails on `retired`; rule 3's checks *)
(* are user-boundary-gated). Without TERM_ESCAPE that is a hard two-core *)
(* deadlock -- the falsifier.                                             *)
TermStart(c) ==
  LET w == cores[c].cur IN
  /\ tb > 0 /\ tb' = tb - 1 /\ UNCHANGED <<processes, cb, db, pb>>
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"      \* rule-3 entry check intercepts (N5)
  /\ threads[w].pin = 0            \* W3/W4 waiter context: no claims, no locks
  /\ \E t \in Threads:             \* INCLUDING w -- terminate(self()) is legal
       threads' = [threads EXCEPT ![w].pc = "termR", ![w].tg = t]
  /\ cores' = cores

(* The edge-9 retire itself, then the wait. Guard admits a caller that   *)
(* was retired since TermStart -- the C-1 window.                        *)
TermRetire(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "termR" /\ threads[w].st \in {"running","retired"}
  /\ RetireEnabled(t)          \* includes the W7 pd pre-wait for `pended`
  /\ threads' = [RetireThreadsAfter(t) EXCEPT ![w].pc = "termW"]
  /\ cores' = RetireCoresAfter(t)
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Target already gone (freed, or otherwise not retirable): specv3       *)
(* Sec [terminate] -- a stale handle returns E_TERM. Without this arm a  *)
(* caller wedges in termR, which would be a MODELLING artifact rather    *)
(* than a design defect.                                                  *)
TermStale(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "termR" /\ threads[w].st \in {"running","retired"}
  /\ ~RetireEnabled(t)
  /\ threads' = [threads EXCEPT ![w].pc = "user", ![w].tg = NULL]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* W3 (target evicted from its core's `current`) + W4 (deferred marking  *)
(* discharged), with TWO carve-outs:                                      *)
(*                                                                        *)
(*  - t = w: the SELF-terminate carve-out. This is what the tree already *)
(*    does (`thread.zig:1028`, `if (thread != caller and ...)`,   *)
(*    "Self-terminate is excluded: the caller cannot wait for its own    *)
(*    eviction"). Rev 8's doc had NO such carve-out anywhere in W3/L5/T2 *)
(*    -- the tree was safer than the design.                             *)
(*                                                                        *)
(*  - TERM_ESCAPE: the rev-9 repair for MUTUAL terminate, which the      *)
(*    tree's `thread != caller` does NOT cover (both cores pass it). A       *)
(*    terminator that has ITSELF been retired abandons the wait. Sound   *)
(*    because a retired terminator never returns to user mode, so L5's   *)
(*    "terminate returns after eviction + marking" has no observer; and  *)
(*    safe because the frame holds no claim (pin = 0 at spin entry, T3   *)
(*    rule (b)). Dialing it FALSE reproduces the C-1 deadlock.           *)
TermWait(c) ==
  LET w == cores[c].cur
      t == threads[w].tg IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ w # NULL
  /\ threads[w].pc = "termW" /\ threads[w].st \in {"running","retired"}
  /\ \/ /\ TERM_ESCAPE
        /\ threads[w].st = "retired"
     \/ /\ \/ t = w                                  \* self carve-out
           \/ \A c2 \in Cores: cores[c2].cur # t      \* W3: eviction
        /\ ~threads[t].mo                        \* W4: deferred marking
           \* acquire-load of `mark_state` (Sec 2.4, M-3); the discharger's
           \* owed -> done is the paired release-store.
  /\ threads' = [threads EXCEPT ![w].pc = "user", ![w].tg = NULL]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(***************************************************************************)
(* Pin-class lock holds (Sec 2.4, round-4 F3): a lock class with a         *)
(* non-IRQ-saving thread-context acquire site (SlabAllocator.lock, kstack      *)
(* freelist_lock) bumps pin_depth for the hold. This is what makes the     *)
(* F3 family visible: without the gate, a preempted holder lands in T2's   *)
(* ready x K+C cell.                                                       *)
(*                                                                        *)
(* ROUND-7 C1 -- the ORDER of the bump against the acquire.                *)
(* Rev 7 said only "incremented at claim-win and pin-class acquire;        *)
(* decremented at discharge/release" and never ordered the two. Pin-class  *)
(* locks are BY DEFINITION not IRQ-masked at their thread-context acquire      *)
(* sites -- that is the property that puts a class in the set -- so the    *)
(* gap in `lock(); pin_depth += 1;` is a live preemption point: a tick     *)
(* lands there, reads pin_depth = 0, wins the running -> parking(requeue)  *)
(* CAS, and requeue-preempts a frame HOLDING the lock. Rev 8 (Sec 2.4,     *)
(* Sec 9.2) makes the order normative: the increment precedes acquisition  *)
(* of the protected thing, the decrement follows its release.              *)
(*                                                                        *)
(* PIN_BUMP_FIRST = TRUE (the machine): PinAcq/PinRel stay FUSED. This is  *)
(* faithful, not a compression of the defect: under the normative order    *)
(* the intermediates are "pinned but not yet holding" / "no longer holding *)
(* but still pinned", and pin_depth is the ONLY thing any other action     *)
(* reads (it gates TickPreempt), so both intermediates are guard-          *)
(* equivalent to the fused state. Splitting them would add an interleaving *)
(* point containing no observable work -- exactly what the rev-6 sweep     *)
(* deleted with the pre-hop step.                                          *)
(* PIN_BUMP_FIRST = FALSE (the falsifier): the two half-states become      *)
(* real and InvNoPreemptedLockHolder must fire.                            *)
(***************************************************************************)
PinAcq(c) ==
  LET e == cores[c].cur IN
  /\ PINLOCK_ON
  /\ ThreadCtx(c) /\ threads[e].pc = "user" /\ threads[e].st = "running"
  /\ threads[e].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[e].plk = "none"
  /\ IF PIN_BUMP_FIRST
     THEN threads' = [threads EXCEPT ![e].plk = "held", ![e].pin = @ + 1]
     ELSE threads' = [threads EXCEPT ![e].plk = "preB"]   \* lock(), bump pending
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* ~PIN_BUMP_FIRST only: the deferred `pin_depth += 1` after the acquire.  *)
PinBump(c) ==
  LET e == cores[c].cur IN
  /\ ~PIN_BUMP_FIRST
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ e # NULL
  /\ threads[e].pc = "user" /\ threads[e].st \in {"running","retired"}
  /\ threads[e].plk = "preB"
  /\ threads' = [threads EXCEPT ![e].plk = "held", ![e].pin = @ + 1]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

PinRel(c) ==
  LET e == cores[c].cur IN
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ e # NULL
  /\ threads[e].pc = "user" /\ threads[e].st \in {"running","retired"}
  /\ threads[e].plk = "held"
  /\ IF PIN_BUMP_FIRST
     THEN threads' = [threads EXCEPT ![e].plk = "none", ![e].pin = @ - 1]
     ELSE threads' = [threads EXCEPT ![e].plk = "postD", ![e].pin = @ - 1]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(* ~PIN_BUMP_FIRST only: the release that follows the decrement -- C1's    *)
(* mirror window on the way out.                                           *)
PinUnlock(c) ==
  LET e == cores[c].cur IN
  /\ ~PIN_BUMP_FIRST
  /\ cores[c].pc = "ecrun" /\ cores[c].irq = NULL /\ e # NULL
  /\ threads[e].pc = "user" /\ threads[e].st \in {"running","retired"}
  /\ threads[e].plk = "postD"
  /\ threads' = [threads EXCEPT ![e].plk = "none"]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(***************************************************************************)
(* Edge 1 beyond Init: publish-last creation into a freed slot (slab       *)
(* reuse), then ready placement under the destination run-queue lock (S8). *)
(* vCPU create uses the same runnable-first shape: the initial vm_exit is  *)
(* synthesized by first dispatch and the normal running->parking wait      *)
(* publication, not by publishing the new thread directly into a port wait     *)
(* container. The exit-port vCPU list/bind pin is outside this model's     *)
(* wait-container `lnk` bit; the implementation holds a lifecycle pin and *)
(* the port lock across list publication + enqueue. The process-lock           *)
(* process-liveness gate and private-unwind arm are not modelled (processes  *)
(* are one flag).                                                         *)
(***************************************************************************)
CreateThread(c) ==
  LET w == cores[c].cur IN
  /\ cb > 0 /\ cb' = cb - 1 /\ UNCHANGED <<processes, tb, db, pb>>
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ \E e \in Threads \ {w}, d \in Cores:
       /\ threads[e].st = "freed" /\ threads[e].dir = "none"
       /\ threads' = [threads EXCEPT ![e] =
                     [st |-> "ready",
                      pk |-> "none", shot |-> "none",
                      own |-> NULL, pin |-> 0, pd |-> FALSE, po |-> FALSE,
                     hld |-> NULL, am |-> Cores,
                     mo |-> FALSE,
                     pc |-> "user", tg |-> NULL, vm |-> "host",
                     ks |-> NULL, lnk |-> FALSE, plk |-> "none",
                     dir |-> "none", dres |-> "none", dpin |-> FALSE, dbad |-> FALSE,
                     gen |-> threads[e].gen,   \* INHERIT, never reset (round-12)
                     dgen |-> 0,
                     dlv |-> FALSE, pok |-> TRUE, dfs |-> FALSE,
                     dsrc |-> NULL, proc |-> threads[w].proc,
                     dd |-> FALSE]]
       /\ cores' = [cores EXCEPT ![d].q = @ \cup {e}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]

(***************************************************************************)
(* recv with a queued sender (Sec 8.3): pop = 5a claim under the port      *)
(* lock; the holder mints the pin (sender holder-contained, S1 intact)     *)
(* and places via edge 7 -- the waiting -> claimed -> waiting cycle.       *)
(* Discharged through the same edge-7 body as suspend (SuspendPlace).     *)
(***************************************************************************)
RecvPop(c) ==
  LET w == cores[c].cur IN
  /\ REQUEUE_ON      \* port receive re-containment, not cross-thread suspend
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[w].shot = "none"
  /\ \E t \in Threads \ {w}:
       /\ threads[t].st = "waiting"
       /\ threads' = [threads EXCEPT ![t].st = "claimed",
                             ![t].hld = [ty |-> "thread", id |-> w],
                             ![t].shot = "none", ![t].pin = @ + 1, ![t].lnk = FALSE,
                             ![w].pc = "suspC",
                             ![w].tg = t]
  /\ UNCHANGED <<processes, cores, tb, cb, db, pb>>

(***************************************************************************)
(* Sec 9.4: the fused IPC fast path (suspend FP shape): sender fused       *)
(* park-publish + receiver 5a claim + payload + edge-2 commit, one         *)
(* compressed CAS composition whose intermediates are unobservable. A      *)
(* parking (5b-shaped) receiver fails the st = "waiting" guard: the FP     *)
(* bails to the slow path, which pends it -- the FP never implements the   *)
(* pended arm.                                                             *)
(***************************************************************************)
FastPath(c) ==
  LET s == cores[c].cur IN
  /\ FASTPATH
  /\ ThreadCtx(c) /\ threads[s].pc = "user" /\ threads[s].st = "running"
  /\ threads[s].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[s].shot = "none" /\ threads[s].pin = 0
  /\ \E r \in Threads \ {s}:
       /\ threads[r].st = "waiting"                    \* 5b-shaped => bail
       /\ threads' = [threads EXCEPT
                    ![s].st = "waiting",
                    ![s].own = NULL, ![s].ks = NULL,
                    ![s].vm = "host", ![s].lnk = TRUE,
                    ![r].st = "running", ![r].own = c, ![r].ks = c,
                    ![r].shot = "none", ![r].lnk = FALSE]
       /\ cores' = [cores EXCEPT ![c].cur = r]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* Sec 9.4's SECOND fused shape, the reply FP main: sender wake (5a       *)
(* claim) + edge-2 commit + caller requeue, one compressed composition     *)
(* whose intermediates are unobservable. The reply target r takes the      *)
(* replier w's core; w is requeued (fused parking(requeue) -> ready        *)
(* placement, destination nondeterministic per G3). A 5b-shaped (parking)  *)
(* r fails the guard: the FP bails to the slow path, which pends it.       *)
(* Measured accounting: systems.md 9.4 / bead stygia-qde.                  *)
ReplyFP(c) ==
  LET w == cores[c].cur IN
  /\ FASTPATH
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[w].shot = "none" /\ threads[w].pin = 0
  /\ \E r \in Threads \ {w}, d \in Cores:
       /\ threads[r].st = "waiting"                   \* 5b-shaped => bail
       /\ threads' = [threads EXCEPT
            ![r].st = "running", ![r].own = c, ![r].ks = c,
            ![r].shot = "none", ![r].lnk = FALSE,
            ![w].st = "ready", ![w].own = NULL, ![w].ks = NULL,
            ![w].vm = "host", ![w].pk = "none"]
       /\ cores' = [cores EXCEPT ![c].cur = r, ![d].q = @ \cup {w}, ![d].wake = IF WAKE_IPI /\ cores[d].parked THEN TRUE ELSE @]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(* M4's affinity claim-move: cross-thread `affinity` on a READY target whose   *)
(* new mask excludes its current queue core = 5c claim under that queue's  *)
(* lock + edge-6 placement (the destination computed at placement from     *)
(* the fresh mask, M-2). Discharges through the EXISTING WakePlace /       *)
(* WakeTgtRetired holder path (pc = "wakeC") -- no new discharge           *)
(* machinery. Rev 8's companion rule (Sec 8.1): a `priority` edit of a     *)
(* `ready` target is an IN-LOCK re-bucket of the SAME queue -- no claim,   *)
(* no state change, hence no model action. The dividing rule is            *)
(* container-valued: same container => in-lock relink, different           *)
(* container => claim-move.                                                *)
AffMove(c) ==
  LET w == cores[c].cur IN
  /\ REQUEUE_ON      \* thread affinity claim-move, not cross-thread suspend
  /\ ThreadCtx(c) /\ threads[w].pc = "user" /\ threads[w].st = "running"
  /\ threads[w].dir # "armed"    \* rule-3 entry check intercepts (N5)
  /\ threads[w].shot = "none"
  /\ \E t \in Threads \ {w}:
       /\ threads[t].st = "ready"
       /\ LET qc == CHOOSE c2 \in Cores: t \in cores[c2].q IN
            /\ cores' = [cores EXCEPT ![qc].q = @ \ {t}]
            /\ threads' = [threads EXCEPT ![t].st = "claimed",
                                  ![t].hld = [ty |-> "thread", id |-> w],
                                  ![t].pin = @ + 1, ![w].pc = "wakeC",
                                  ![w].tg = t]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

(***************************************************************************)
(* Quiescent termination: every thread freed or blamelessly asleep. Gives the  *)
(* final state a self-loop so TLC's deadlock detection only fires on       *)
(* genuinely wedged configurations.                                        *)
(***************************************************************************)
Quiescent ==
  /\ \A c \in Cores: /\ cores[c].pc = "idle" /\ cores[c].irq = NULL
                     /\ cores[c].cur = NULL
                     /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ \A e \in Threads: \/ threads[e].st = "freed"
                   \/ (threads[e].st = "waiting" /\ threads[e].shot # "consumed")

Terminating == Quiescent /\ UNCHANGED vars

(***************************************************************************)
(* Next                                                                    *)
(***************************************************************************)
(* Continuations of already-started bounded work (fairness-forced).        *)
BaseStep(c) ==
  \/ HopRelease(c)
  \/ HopCommitWait(c) \/ HopCommitRequeue(c) \/ HopCommitPended(c)
  \/ HopCommitRetired(c) \/ HopCommitClaimed(c)
  \/ BoundaryRetired(c) \/ VcpuCancelExit(c)
  \/ WakePlace(c) \/ WakePendDone(c) \/ WakeTgtRetired(c)
  \/ RelwaitPlace(c)
  \/ SuspendPlace(c) \/ SuspendTgtRetired(c)
  \/ RvDeliver(c) \/ S7Retire(c)
  \/ DispatchAbort(c) \/ DispatchLoad(c)
  \/ StealDispatch(c) \/ StealAbandon(c) \/ StealDropDead(c)
  \/ DirArm(c) \/ DirLoop(c) \/ DirSelfAbort(c)
  \/ TermWait(c) \/ TermRetire(c) \/ TermStale(c) \/ PinRel(c)
  \/ SelfRetireForTeardown(c)
  \/ PinBump(c) \/ PinUnlock(c)
     \* both disabled under PIN_BUMP_FIRST (the machine); they exist only
     \* to let the C1 falsifier's lock episode complete after the window

IrqStep(c) == IrqWakePlace(c) \/ IrqPendDone(c) \/ IrqRelwait(c)

FireAny(e) == \E c \in Cores: FireAt(c, e)

(* Dispatch-slot consumers: the edge-2 commit or the S7 claim route.       *)
DispatchOrS7(c, e) == DispatchThread(c, e) \/ S7Claim(c, e)
StealAny(c, e) == \E v \in Cores: StealClaim(c, v, e)

(* Directive-cycle scoped safety machine. The cr/cr3self gates need 3 Threads  *)
(* to cover the cycle shape on 2 cores, including W5's preemptible/yield   *)
(* requeue path so the third thread can run.                                *)
(* remote-drop, the split dispatch tail, stealing, or the rest of the      *)
(* lifecycle surface. This keeps ordinary dispatch as one edge and then    *)
(* exercises only the suspend-directive protocol plus the minimal owner    *)
(* and hop outcomes needed to move directive waiters off-core.             *)
DirectiveDispatchThread(c, e) ==
  /\ cores[c].pc = "idle" /\ cores[c].irq = NULL /\ ~cores[c].parked
  /\ cores[c].pending = NULL /\ cores[c].active = NULL
  /\ e \in cores[c].q /\ threads[e].st = "ready"
  /\ ~threads[e].dd
  /\ c \in threads[e].am
  /\ cores' = [cores EXCEPT ![c].q = @ \ {e}, ![c].cur = e,
                            ![c].pc = "ecrun"]
  /\ threads' = [threads EXCEPT ![e].st = "running", ![e].own = c, ![e].ks = c]
  /\ UNCHANGED <<processes, tb, cb, db, pb>>

DirectiveBaseStep(c) ==
  \/ HopRelease(c)
  \/ HopCommitWait(c)
  \/ HopCommitRequeue(c)
  \/ DirArm(c)
  \/ DirLoop(c)
  \/ DirSelfAbort(c)

DirectiveRequest(c) ==
  \/ DirSelfMark(c)
  \/ DirClaim(c)
  \/ DirConsume(c)
  \/ DirFail(c)
  \/ DirDrop(c)

DirectiveNext ==
  \/ \E c \in Cores:
       \/ \E e \in Threads: DirectiveDispatchThread(c, e)
       \/ DirectiveRequest(c)
       \/ DirectiveBaseStep(c)
       \/ TickPreempt(c)
       \/ ParkDecision(c) \/ WakeIpi(c)
  \/ \E e \in Threads: ClearFreedDirective(e)
  \/ Terminating

SpecDirNF == Init /\ [][DirectiveNext]_vars

(* New requests (never fairness-forced).                                   *)
Request(c) ==
  \/ UserPark(c) \/ VcpuGuestExit(c) \/ WakeStart(c) \/ SuspendStart(c) \/ RecvPop(c)
  \/ FastPath(c) \/ ReplyFP(c) \/ RvStart(c) \/ DirClaim(c)
  \/ DirSelfMark(c)
  \/ DirConsume(c) \/ DirFail(c) \/ DirDrop(c) \/ PinAcq(c) \/ CreateThread(c) \/ TermStart(c)
  \/ AffMove(c) \/ QueueTeardown(c)

Next ==
  \/ \E c \in Cores:
       \/ \E e \in Threads: DispatchOrS7(c, e)
       \/ \E e \in Threads: StealAny(c, e)
       \/ Request(c)
       \/ BaseStep(c) \/ IrqStep(c) \/ TickPreempt(c)
       \/ ParkDecision(c) \/ WakeIpi(c)
       \/ ConsumeTeardown(c) \/ FinishTeardown(c)
       \/ \E e \in Threads: TeardownRetire(c, e)
  \/ \E e \in Threads: FireAny(e) \/ RetireThread(e) \/ RetireUnwind(e)
                       \/ ClearFreedDirective(e)
  \/ ProcessDie
  \/ Terminating

SpecNF == Init /\ [][Next]_vars

(***************************************************************************)
(* Fairness (justifications in README.md):                                 *)
(*  - SF BaseStep(c):  a CPU in kernel code keeps executing; every        *)
(*    BaseStep action is a continuation of already-started bounded work,  *)
(*    never a new request. STRONG fairness because interrupt frames       *)
(*    repeatedly de-enable the base continuation: WF would allow an       *)
(*    infinite interrupt storm to starve, e.g., the hop's retired arm     *)
(*    forever. Every liveness bound in systems.md (L2's "kernel sequence  *)
(*    + one user-boundary event", W2/W4's bounds, ack-while-spinning)     *)
(*    presupposes no such storm.                                          *)
(*  - WF IrqStep(c):   interrupt bodies are straight-line (L6) and,       *)
(*    once entered, the frame is the only runnable thing on the core, so  *)
(*    weak fairness suffices.                                             *)
(*  - SF TickPreempt(c): the periodic timer fires; a repeatedly           *)
(*    preemptible thread is eventually preempted (same storm argument).       *)
(*  - SF DispatchOrS7(c,e): stands for FIFO queue order, which the set    *)
(*    abstraction of the run queue loses; covers the S7 claim route too.  *)
(*  - SF FireAny(e):   an armed deadline/device source eventually   *)
(*    fires (T1 persistence), even though busy irq slots may transiently  *)
(*    block delivery.                                                     *)
(* No fairness on WakeStart/SuspendStart/UserPark/FastPath/RetireThread:      *)
(* those are new requests, and forcing them could mask liveness bugs.     *)
(***************************************************************************)
Fairness ==
  /\ \A c \in Cores: /\ SF_vars(BaseStep(c))
                     /\ WF_vars(IrqStep(c))
                     /\ WF_vars(WakeIpi(c))
                     /\ SF_vars(TickPreempt(c))
                     (* Per-spin SF for the two deliberately-preemptible  *)
                     (* waits (W3/W4 terminate, W5 directive): disjunction *)
                     (* -level SF(BaseStep) is satisfiable by hop steps   *)
                     (* while the spinner's recheck is starved by a       *)
                     (* preempt-always-lands-first schedule. T3's "bounded *)
                     (* by discharger instructions + scheduling latency"  *)
                     (* implicitly excludes that adversarial alignment    *)
                     (* (tick period >> one recheck); these constraints   *)
                     (* encode exactly that. See README (fairness, N3).   *)
                     /\ SF_vars(TermWait(c))
                     /\ SF_vars(DirLoop(c))
                     (* N6 face (i): DirArm is the continuation of an   *)
                     (* already-started suspend syscall -- bounded,      *)
                     (* committed work, the same category as BaseStep/   *)
                     (* TermWait/DirLoop ("continuations of already-     *)
                     (* started bounded work, never new requests").      *)
                     (* Disjunction-level SF(BaseStep) is satisfiable by *)
                     (* the requeue-hop steps while DirArm starves (the  *)
                     (* second liveness_c lasso): per-continuation SF    *)
                     (* encodes the Sec 3.6 assumption that a dispatched *)
                     (* continuation executes >= 1 step per quantum.     *)
                     /\ SF_vars(DirArm(c))
  /\ \A c \in Cores, e \in Threads: SF_vars(DispatchOrS7(c, e))
  /\ \A e \in Threads: /\ SF_vars(FireAny(e))
                   /\ WF_vars(RetireUnwind(e))
                   /\ WF_vars(ClearFreedDirective(e))
                      \* retire step 3 is the retirer's own synchronous
                      \* continuation; it always completes (Sec 8.2)

SpecFair == SpecNF /\ Fairness

(* A deliberately WEAKER fairness set for the liveness groups that do not *)
(* check the two preemptible-spin obligations (LiveTerm / LiveSuspender): *)
(* it omits SF(TermWait) and SF(DirLoop) -- the N3 per-spin assumptions.  *)
(* A property verified under FairnessCore holds a fortiori under          *)
(* Fairness, so using it where sufficient is a STRONGER result (fewer     *)
(* assumptions) as well as a cheaper check.                               *)
FairnessCore ==
  /\ \A c \in Cores: /\ SF_vars(BaseStep(c))
                     /\ WF_vars(IrqStep(c))
                     /\ WF_vars(WakeIpi(c))
                     /\ SF_vars(TickPreempt(c))
  /\ \A c \in Cores, e \in Threads: SF_vars(DispatchOrS7(c, e))
  /\ \A e \in Threads: /\ SF_vars(FireAny(e))
                   /\ WF_vars(RetireUnwind(e))
                   /\ WF_vars(ClearFreedDirective(e))

SpecFairCore == SpecNF /\ FairnessCore

(***************************************************************************)
(* `Fairness` MINUS `SF_vars(DirArm)` -- i.e. N3's two per-spin            *)
(* constraints and nothing from N6. This is the fairness set the           *)
(* SYMMETRIC-SUSPEND REJECTION experiment runs under (round-7 maintainer   *)
(* proposal): if `LiveSuspender` holds here with CYCLE_REJECT = TRUE, then *)
(* BOTH N6 assumptions are retired -- face (i)'s SF(DirArm) and face       *)
(* (ii)'s AlignmentAssumption -- because the mutual-suspend shape that     *)
(* produced them is no longer reachable. Passing under a WEAKER fairness   *)
(* set is the stronger result, and this one also drops the raw []<>        *)
(* tableau entirely, so it should be far cheaper to check.                 *)
(***************************************************************************)
FairnessN3 ==
  /\ \A c \in Cores: /\ SF_vars(BaseStep(c))
                     /\ WF_vars(IrqStep(c))
                     /\ SF_vars(TickPreempt(c))
                     /\ SF_vars(TermWait(c))
                     /\ SF_vars(DirLoop(c))
  /\ \A c \in Cores, e \in Threads: SF_vars(DispatchOrS7(c, e))
  /\ \A e \in Threads: /\ SF_vars(FireAny(e))
                   /\ WF_vars(RetireUnwind(e))
                   /\ WF_vars(ClearFreedDirective(e))

SpecFairN3 == SpecNF /\ FairnessN3

(***************************************************************************)
(* PER-PROPERTY MINIMAL FAIRNESS (round-7 follow-up). Measured finding:    *)
(* TLC's liveness cost is driven by the NUMBER of fairness constraint      *)
(* instances, not by graph size -- liveness_a checks THREE properties on   *)
(* 56,726 states in 437s under 14 instances, while cr1fullself checks ONE  *)
(* on the same graph under 18 and takes 2,225s. At 2 cores x 3 Threads the     *)
(* count grows worst in the DispatchOrS7 family (2x3 = 6 instances), which *)
(* is exactly why the 3-thread liveness runs did not converge.                 *)
(*                                                                        *)
(* So: split by FAIRNESS CONSTRAINT rather than by scope. Each property    *)
(* is checked under the smallest set it actually needs, and the verdict    *)
(* then RECORDS which assumptions it rests on -- which is more useful      *)
(* than a green run under a set nobody has justified per-property.         *)
(* Building blocks, smallest first:                                       *)
(***************************************************************************)
FairCPU ==            \* the floor: a CPU executes its enabled continuation,
                      \* and a live interrupt frame runs to its return
  \A c \in Cores: SF_vars(BaseStep(c)) /\ WF_vars(IrqStep(c))
                 /\ WF_vars(WakeIpi(c))

FairUnwind ==         \* retire step 3 is the retirer's own continuation
  \A e \in Threads: WF_vars(RetireUnwind(e))
                   /\ WF_vars(ClearFreedDirective(e))

FairTick ==           \* the periodic timer fires
  \A c \in Cores: SF_vars(TickPreempt(c))

FairDisp ==           \* stands for the FIFO order the set-queue abstraction
                      \* loses; the family that grows as |Cores| x |Threads|
  \A c \in Cores, e \in Threads: SF_vars(DispatchOrS7(c, e))

FairDispWeak ==
  \A c \in Cores, e \in Threads: WF_vars(DispatchOrS7(c, e))

FairFire ==           \* armed T1 sources eventually fire
  \A e \in Threads: SF_vars(FireAny(e))

FairSpinTerm == \A c \in Cores: SF_vars(TermWait(c))   \* N3, W3/W4
FairSpinDir  == \A c \in Cores: SF_vars(DirLoop(c))    \* N3, W5

FairTeardown ==
  /\ \A c \in Cores: /\ WF_vars(ConsumeTeardown(c))
                     /\ WF_vars(FinishTeardown(c))
                     /\ SF_vars(SelfRetireForTeardown(c))
  /\ \A c \in Cores, e \in Threads: WF_vars(TeardownRetire(c, e))

(* Per-property specs. Each names EXACTLY the constraints its property    *)
(* needs; a PASS is then a statement about those assumptions and no       *)
(* others. Where a smaller set was tried and failed, the failure is the   *)
(* evidence that the constraint is load-bearing -- record it, do not      *)
(* silently widen the set.                                                *)
SpecL1  == SpecNF /\ FairCPU /\ FairUnwind                      \* LiveParking
SpecL6  == SpecNF /\ FairCPU /\ FairUnwind                      \* LiveClaim
SpecL5  == SpecNF /\ FairCPU /\ FairUnwind                      \* LiveMark
SpecL4  == SpecNF /\ FairCPU /\ FairUnwind                      \* LiveWake
SpecL3  == SpecNF /\ FairCPU /\ FairUnwind /\ FairDispWeak      \* LiveReady, G14
SpecG16 == SpecNF /\ FairCPU /\ FairUnwind /\ FairDisp /\ FairTick
                   /\ FairTeardown
SpecL2  == SpecNF /\ FairCPU /\ FairUnwind /\ FairDisp /\ FairTick  \* LiveRetired
SpecTrm == SpecNF /\ FairCPU /\ FairUnwind /\ FairDisp /\ FairTick
                  /\ FairSpinTerm                                \* LiveTerm
SpecSus == SpecNF /\ FairCPU /\ FairUnwind /\ FairDisp /\ FairTick
                  /\ FairSpinDir                                 \* LiveSuspender

(* Focused directive/terminate scope for the default t1d_min/pr4d_min pair.
 * This is not a weaker LiveTerm property: the property and the directive
 * protocol are unchanged. The transition relation excludes model surfaces
 * that are orthogonal to W3/W4 and W5 (dispatch-tail splitting,
 * pull-side stealing, S7, rendezvous, fast path, pin-lock episodes, slot
 * recycling) so this row remains a checkable thread lifecycle slice instead of
 * inheriting every later scheduler multiplier through SpecNF.             *)
TermDirRequest(c) ==
  \/ TermStart(c)
  \/ DirSelfMark(c) \/ DirClaim(c) \/ DirConsume(c) \/ DirFail(c) \/ DirDrop(c)

TermDirNext ==
  \/ \E c \in Cores:
       \/ \E e \in Threads: DirectiveDispatchThread(c, e)
       \/ TermDirRequest(c)
       \/ BaseStep(c) \/ IrqStep(c)
       \/ TickPreempt(c)
       \/ ParkDecision(c) \/ WakeIpi(c)
  \/ \E e \in Threads: FireAny(e) \/ RetireThread(e) \/ RetireUnwind(e)
                       \/ ClearFreedDirective(e)
  \/ Terminating

SpecTermDirNF == Init /\ [][TermDirNext]_vars

FairTermDirCPU ==
  \A c \in Cores: SF_vars(BaseStep(c)) /\ WF_vars(IrqStep(c))
                 /\ WF_vars(WakeIpi(c))

FairTermDirDisp ==
  \A c \in Cores, e \in Threads: SF_vars(DirectiveDispatchThread(c, e))

SpecTrmDir == SpecTermDirNF /\ FairTermDirCPU /\ FairUnwind
                            /\ FairTermDirDisp /\ FairTick
                            /\ FairSpinTerm

(***************************************************************************)
(* THE ALIGNMENT ASSUMPTION (round-6 N6, face (ii)) -- read this before    *)
(* citing any green LiveSuspender run.                                     *)
(*                                                                        *)
(* W5's termination in the MUTUAL-suspend case requires observing the     *)
(* other side off-CPU: the disarm arm needs holder-current AND            *)
(* target-not-running SIMULTANEOUSLY. No action fairness can supply       *)
(* that -- SF on the disarm arm is vacuous when its enabledness is        *)
(* starved -- so the design's (physically sound) premise that             *)
(* independent per-core tick phases do not remain adversarially aligned   *)
(* forever must be stated as a TEMPORAL ASSUMPTION, conjoined visibly     *)
(* here, never folded into Fairness. systems.md 3.6 states it prose-side; *)
(* this is its formal twin: a dirW holder whose target's directive stays  *)
(* armed is infinitely often scheduled while its target is off-CPU.       *)
(***************************************************************************)
AlignmentAssumption ==
  \A e \in Threads:
    []<>( IF threads[e].pc = "dirW"
          THEN \/ threads[threads[e].tg].dir # "armed"
               \/ (\E c \in Cores: /\ cores[c].cur = e
                                    /\ cores[c].pc = "ecrun"
                                    /\ cores[c].irq = NULL
                                    /\ threads[threads[e].tg].st # "running")
          ELSE TRUE )

SpecFairAligned == SpecNF /\ Fairness /\ AlignmentAssumption

(***************************************************************************)
(* Safety invariants (Sec 6.1)                                             *)
(***************************************************************************)

(* S1: state implies containment -- including the REIFIED wait-container   *)
(* half: `waiting` and wait-`parking` are linked in exactly one wait       *)
(* episode's containers (lnk); every other state is linked in none        *)
(* (claim winners and retire's unwind do the unlinking).                   *)
InvS1 ==
  \A e \in Threads:
    /\ (\A c \in Cores: e \in cores[c].q => threads[e].st = "ready")
    /\ threads[e].st = "ready" =>
         Cardinality({c \in Cores: e \in cores[c].q}) = 1
    /\ threads[e].st = "running" =>
         threads[e].own # NULL /\ cores[threads[e].own].cur = e
    /\ threads[e].st \in {"waiting","claimed","pended","retired","finalizing","freed"} =>
         \A c \in Cores: e \notin cores[c].q
    /\ (threads[e].st = "waiting"
          \/ (threads[e].st = "parking" /\ threads[e].pk = "wait")) => threads[e].lnk
    \* `retired` is deliberately absent from the no-linkage clause: the
    \* retired-but-linked licence (Sec 8.2 rev 6, T4) -- links may
    \* persist until finalize's leading unwind, pop-side skips stale.
    \* `freed` IS included: under FIN_UNWIND (the rev-6 N4 mechanism,
    \* finalizer-owned unwind) freed-while-linked is unreachable; under
    \* ~FIN_UNWIND (the rev-5 literal machine) it is the n4 falsifier.
    /\ (threads[e].st \in {"ready","running","claimed","pended","finalizing","freed"}
          \/ (threads[e].st = "parking" /\ threads[e].pk = "requeue")) =>
         ~threads[e].lnk

(* S3: kstack quiescence -- claimable/claimed-quiescent states imply no    *)
(* core on the kstack. (`pended`/`parking`/`running`/pre-hop `retired`     *)
(* legitimately keep the owner on it.)                                     *)
InvS3 ==
  \A e \in Threads:
    threads[e].st \in {"ready","waiting","claimed","finalizing","freed"} => threads[e].ks = NULL

(* S4: claim uniqueness + holder persistence. A won claim always has a     *)
(* live discharger: the holding frame still exists (not finalized) and is  *)
(* still aimed at the target. Violated by rev 3's X1.                      *)
HolderLive(e) ==
  LET h == threads[e].hld IN
  /\ h # NULL
  /\ h.ty = "thread" => /\ threads[h.id].st # "freed"
                    /\ threads[h.id].pc \in {"wakeC","suspC","pendC",
                                         "rvC","relwait"}
                    /\ threads[h.id].tg = e
  /\ h.ty = "irq" => /\ cores[h.cid].irq # NULL
                     /\ cores[h.cid].irq.tgt = e
  /\ h.ty = "cpu" => /\ cores[h.cid].pc \in {"s7ret","stealCommit"}
                     /\ cores[h.cid].outg = e

InvS4Holder ==
  \A e \in Threads:
    /\ threads[e].st = "claimed" => HolderLive(e)
    /\ (threads[e].st = "pended" /\ ~threads[e].pd) => HolderLive(e)

(* Rev 4: the pended discharger (the owner core's hop) is guaranteed       *)
(* still to come (Sec 5.2 pended row).                                     *)
InvS4Pended ==
  \A e \in Threads:
    threads[e].st = "pended" =>
      /\ threads[e].own # NULL
      /\ \/ cores[threads[e].own].outg = e
         \/ cores[threads[e].own].cur = e

(* Rev 4 T2 unreachable cells (X1 closure): no pin-class-holding frame is *)
(* ever requeue-`parking`, and every hop is entered without an outgoing    *)
(* pin-class lock. Claim continuations may be preempted after pinning the  *)
(* protected target; the target pin, not the claimant, gates target retire. *)
(* `ready` may carry a transient target lifecycle pin while a holder       *)
(* publishes/enqueues it; containment remains the run queue, and           *)
(* RetireEnabled waits pin = 0.                                           *)
InvPinCells ==
  \A e \in Threads:
    (threads[e].st = "parking" /\ threads[e].pk = "requeue") => threads[e].pin = 0

InvHopUnpinned ==
  \A c \in Cores:
    (cores[c].pc \in {"hopRel","hopCommit"}
       /\ cores[c].outg # NULL) =>
      threads[cores[c].outg].plk = "none"

(* ROUND-7 C1. T2's ready x K justification, stated as an invariant: "a    *)
(* requeue-preempted frame holds no lock at all -- IRQ-masked sections     *)
(* cannot span a tick, and pin-class holders are never preempted."         *)
(* The second half is true only if the pin_depth bump ORDERS BEFORE the    *)
(* acquire (Sec 2.4 rev 8). Under PIN_BUMP_FIRST this is implied by        *)
(* InvPinCells (holding => pin > 0 => not ready / not requeue-parking);    *)
(* under ~PIN_BUMP_FIRST the tick lands in the unpinned window and this    *)
(* fires -- which is what makes the ordering rule load-bearing rather      *)
(* than decorative. Consequences the invariant stands in for: other        *)
(* allocators then spin IRQ-masked (W1) on a class whose holder sits       *)
(* `ready` (hard deadlock if that holder is queued on a spinning core),    *)
(* and T2's ready x K row inline-retires it on an argument that is now     *)
(* false.                                                                  *)
InvNoPreemptedLockHolder ==
  \A e \in Threads:
    (threads[e].st = "ready"
       \/ (threads[e].st = "parking" /\ threads[e].pk = "requeue")) =>
      threads[e].plk = "none"

(* ROUND-7 maintainer proposal, the MECHANISM's own safety statement:      *)
(* no two Threads are ever mutually suspending. `threads[t].dsrc = u` reads "u is  *)
(* suspending t", so a 2-cycle is threads[b].dsrc = a /\ threads[a].dsrc = b.      *)
(* This is a SAFETY property and therefore orders of magnitude cheaper to  *)
(* check than the liveness runs it protects: it holds under CYCLE_REJECT   *)
(* and must FAIL without it (the `crcyc` gate), which is what proves the   *)
(* check is load-bearing rather than decorative.                           *)
(*                                                                        *)
(* SCOPE, stated because it is the proposal's real question: this is       *)
(* PAIRWISE. The check a suspender performs -- "is my own directive        *)
(* already claimed by my target?" -- detects 2-cycles only. A 3-cycle      *)
(* (a suspends b, b suspends c, c suspends a) passes every pairwise        *)
(* check. `InvNoSuspendCycle3` below is the corresponding probe at 3 Threads;  *)
(* if it fires, the mechanism closes the shape that WAS found and not the  *)
(* class, and the write-up must say so.                                    *)
(* ROUND-10 C-D failure 2, caught by a HISTORY GHOST rather than by a     *)
(* state predicate. The first attempt at this invariant asserted that a    *)
(* dirW suspender's target is never `armed` with a foreign owner -- which  *)
(* the epoch fix does NOT provide and should not: the suspender is         *)
(* ALLOWED to sit transiently on a foreign arm, it just must never ACT on  *)
(* one. So the property is about the action. `dbad` is set the moment a    *)
(* disarm fires against an arm the disarmer did not place; no protocol     *)
(* action reads it.                                                        *)
(*                                                                        *)
(* C-D failure 1 (reporting SUCCESS for an owner-side failure) is checked  *)
(* by the `failed`/dres path: owner failures are acked by the matching     *)
(* waiter and do not set dlv. Port result payloads are abstracted to one   *)
(* failure value because lifecycle correctness only needs error-vs-success.*)
InvNoForeignDisarm == \A e \in Threads: ~threads[e].dbad

(* ROUND-11 C-1. A suspender must never return SUCCESS for a suspension   *)
(* that was never delivered. With DIR_GENCHK = FALSE (revision 11:        *)
(* re-validate the port only) a terminated-and-zeroed target reads `none` *)
(* beside a live port and the suspender reports success -- F6 re-opened.  *)
(* This is the arm revision 11's ledger wrongly called un-model-checkable *)
(* "because there is no port": the PORT is irrelevant to it, and the      *)
(* TARGET's gen is checkable with a ghost.                                *)
InvNoFalseSuspendSuccess == \A e \in Threads: ~threads[e].dfs

InvNoSuspendCycle2 ==
  \A a, b \in Threads: ~(threads[a].dsrc = b /\ threads[b].dsrc = a)

InvNoSuspendCycle3 ==
  \A a, b, cc \in Threads:
    ~(/\ a # b /\ b # cc /\ a # cc
      /\ threads[a].dsrc = b /\ threads[b].dsrc = cc /\ threads[cc].dsrc = a)

(* T1 no-decline closure (X3): `consumed` means "the one-shot pop was      *)
(* taken and its discharge is not yet complete" (it is cleared at          *)
(* placement or finalize). A consumed pop therefore always implies a       *)
(* claim/pend/retire discharge in flight -- never a thread still sitting in   *)
(* its wait episode with the registration gone and nobody claiming.        *)
InvNoLostOneShot ==
  \A e \in Threads:
    threads[e].shot = "consumed" =>
      threads[e].st \in {"claimed","pended","retired"}

(* Sec 9.2: outgoing `claimed` at the hop asserts unreachable.             *)
InvHopNoClaimedOutgoing ==
  \A c \in Cores:
    (PENDED /\ cores[c].pc = "hopCommit" /\ cores[c].outg # NULL) =>
      threads[cores[c].outg].st # "claimed"

(* Sec 9.2 / round-4 F1 regression invariant: "retire-from-`pended`        *)
(* asserts `payload_done` before its CAS" -- i.e. a pended-origin thread is    *)
(* never observable as `retired` with its payload incomplete. `po` is the  *)
(* ghost history bit recording pended origin; no protocol action reads it. *)
InvRetiredPdOrdered ==
  \A e \in Threads:
    (PENDED /\ threads[e].st = "retired" /\ threads[e].po) => threads[e].pd

(* stygia-8xl: a retired vCPU may be temporarily current only in the
 * cancel-pending arch-owned state, never still executing raw guest code.
 * The root teardown/quiescence side reads this as: current_thread = RETD is
 * still non-quiescent until the owner acknowledges the cancel and clears
 * current through the ordinary hop/finalize path.                         *)
InvVcpuModeCoherent ==
  \A e \in Threads:
    threads[e].vm # "host" =>
      /\ e \in VCPU_THREADS
      /\ threads[e].st \in {"running","retired"}
      /\ \E c \in Cores:
           /\ cores[c].cur = e
           /\ cores[c].pc = "ecrun"

InvRetiredVcpuCancelled ==
  \A e \in Threads:
    (e \in VCPU_THREADS /\ threads[e].st = "retired" /\ threads[e].vm # "host") =>
      /\ VCPU_CANCEL
      /\ threads[e].vm = "cancel"

(* The UAF gate for rev 4's don't-wait F1 reading: a 5b claimant's         *)
(* payload/payload_done writes land in the target's saved frame and        *)
(* descriptor -- if the target can be FINALIZED (kstack unmapped, slot     *)
(* zeroed) while the claimant's body is still in flight, that write is a   *)
(* use-after-free.                                                         *)
(* Ghost closure invariant for rev 6's G-D1 arm-CAS: an armed directive   *)
(* never exists on a finalized slot (the plain-store reading could write  *)
(* `armed` over finalize's `dead`). Under DirArm's CAS this is            *)
(* unreachable; the invariant pins the closure. The `claiming`/`dead`     *)
(* protocol elements themselves have no battery falsifier -- retained on  *)
(* protocol grounds, labeled doc-only in the README ledger.               *)
InvNoArmedFreed ==
  \A e \in Threads: threads[e].st = "freed" => threads[e].dir # "armed"

(* G14: an enqueuer that sees the locked park decision must leave a wake
   pending with its queue insertion. WAKE_IPI=FALSE violates this invariant
   at the first enqueue into a parked core. *)
InvParkedQueueHasWake ==
  \A c \in Cores: (cores[c].parked /\ cores[c].q # {}) => cores[c].wake

(* G16: phase `queued` owns exactly one request with the original process
   generation; phase `dead` owns exactly one consumed reference on the park
   stack. The consume count forbids a second phase-1 entry for that process.
   A lost or mismatched reference fails this invariant before phase 2. *)
PendingFor(p) ==
  {c \in Cores: IF cores[c].pending = NULL THEN FALSE
                ELSE cores[c].pending.proc = p}
ActiveFor(p) ==
  {c \in Cores: IF cores[c].active = NULL THEN FALSE
                ELSE cores[c].active.proc = p}

InvTeardownRefHandoff ==
  \A p \in Threads:
    /\ processes[p].phase = "queued" =>
         /\ Cardinality(PendingFor(p)) = 1
         /\ Cardinality(ActiveFor(p)) = 0
         /\ LET c == CHOOSE c2 \in PendingFor(p): TRUE IN
              /\ cores[c].pending.gen = processes[p].gen
              /\ threads[cores[c].pending.owner].proc = p
         /\ processes[p].consumes = 0
    /\ processes[p].phase = "dead" =>
         /\ Cardinality(ActiveFor(p)) = 1
         /\ Cardinality(PendingFor(p)) = 0
         /\ LET c == CHOOSE c2 \in ActiveFor(p): TRUE IN
              /\ cores[c].active.gen = processes[p].gen
              /\ threads[cores[c].active.owner].proc = p
              /\ threads[cores[c].active.owner].ks = NULL
         /\ processes[p].consumes = 1
    /\ processes[p].phase = "done" =>
         /\ Cardinality(PendingFor(p)) = 0
         /\ Cardinality(ActiveFor(p)) = 0
         /\ processes[p].consumes = 1

InvNoUAF ==
  /\ \A e \in Threads:
       threads[e].pc = "pendC" => threads[threads[e].tg].st # "freed"
  /\ \A c \in Cores:
       (cores[c].irq # NULL /\ cores[c].irq.ph = "pend") =>
         threads[cores[c].irq.tgt].st # "freed"

(***************************************************************************)
(* Liveness (Sec 6.2), checked under SpecFair                              *)
(***************************************************************************)
LiveParking ==   \* L1: parks complete (the sequence is never abandoned)
  \A e \in Threads: threads[e].st = "parking" ~> threads[e].st # "parking"

LiveRetired ==   \* L2: retired => freed (the retire matrix is total)
  \A e \in Threads: threads[e].st = "retired" ~> threads[e].st = "freed"

LiveVcpuCancel == \* stygia-8xl: arch cancel/kick eventually exits guest
  \A e \in Threads: threads[e].vm = "cancel" ~> threads[e].vm = "host"

LiveReady ==     \* L3: a ready thread is DISPATCHED (reaches `running`),
                 \* unless legitimately taken first by a 5c/S7 claim or a
                 \* retire -- the only other exits from `ready` (S8)
  \A e \in Threads:
    threads[e].st = "ready" ~>
      threads[e].st \in {"running","claimed","retired","freed"}

LiveWake ==      \* L4: a consumed one-shot pop is eventually discharged
                 \* (placement into ready, or finalize of a retired target)
  \A e \in Threads:
    threads[e].shot = "consumed" ~> threads[e].shot # "consumed"

LiveMark ==      \* L5: deferred marking is eventually discharged
  \A e \in Threads: threads[e].mo ~> ~threads[e].mo

LiveClaim ==     \* L6: every claim/pend hand-off is discharged
  \A e \in Threads:
    threads[e].st \in {"claimed","pended"} ~>
      threads[e].st \notin {"claimed","pended"}

LiveSuspender == \* W5: the suspender's terminal re-check/disarm loop
                 \* returns (Sec 2.5: consumed, disarmed, or E_TERM)
                 \* unless another lifecycle operation externally parks or
                 \* kills the suspender itself. The latter is the same
                 \* liveness scoping as LiveReady's claimed/retired exits:
                 \* no property forces a future user resume request.
  \A e \in Threads:
    threads[e].pc = "dirW" ~>
      \/ threads[e].pc # "dirW"
      \/ threads[e].st \in {"waiting","claimed","pended","retired","freed"}

LiveTerm ==      \* L5/W3/W4: terminate returns (eviction + marking done)
  \A e \in Threads: threads[e].pc = "termW" ~> threads[e].pc # "termW"

LiveTeardown ==
  \A p \in Threads: processes[p].phase = "queued" ~>
                     processes[p].phase = "done"

(* ROUND-7: the SAME obligation as `SpecFairAligned |= LiveSuspender`,     *)
(* with the assumption moved from the SPECIFICATION to the PROPERTY.       *)
(*   SpecNF /\ Fairness /\ Assumption  =>  Live                            *)
(* and                                                                    *)
(*   SpecNF /\ Fairness  =>  (Assumption => Live)                          *)
(* are the same formula; they are NOT the same job for TLC (spec-side raw  *)
(* []<> conjunct versus implied-temporal antecedent). This exists so the   *)
(* two placements can be MEASURED against each other at a scope both       *)
(* complete at, rather than guessed. It is not a weakening: the assumption *)
(* is still named, still stated in full, and still one hop from the config *)
(* that cites it -- `ThreadLifecycle_c1tp.cfg` names it in its PROPERTY line.  *)
LiveSuspenderAligned == AlignmentAssumption => LiveSuspender

(***************************************************************************)
(* Symmetry (safety-only configs)                                          *)
(***************************************************************************)
Symm == Permutations(Cores) \cup Permutations(Threads)

(***************************************************************************)
(* VIEW (round 7). A view is sound only for components that NO action      *)
(* guard reads: TLC skips a state whose view was already seen, so if a     *)
(* projected component can affect future behaviour, real successors are    *)
(* never generated and violations are MISSED. In this module exactly one   *)
(* component qualifies -- `po`, the ghost history bit recording that a     *)
(* claim came from `parking`. The module's own contract says it: "NO       *)
(* protocol action reads po." It feeds ONE invariant                       *)
(* (`InvRetiredPdOrdered`) and trace readability, nothing else.            *)
(*                                                                        *)
(* Therefore this view is usable ONLY in a config that does NOT check      *)
(* `InvRetiredPdOrdered` -- otherwise merging states that differ only in   *)
(* `po` can skip the very state that would have violated it. Every other   *)
(* candidate is disqualified by a guard: `mo` is read by TermWait (W4),    *)
(* `dsrc` by DirClaim's "pair" check, `plk`/`pin` by the pin gate, and     *)
(* tb/cb/db gate the budget-bounded actions.                               *)
(***************************************************************************)
ViewNoPo ==
  << [e \in Threads |-> [threads[e] EXCEPT !.po = FALSE]], cores, tb, cb, db, pb >>

=============================================================================
