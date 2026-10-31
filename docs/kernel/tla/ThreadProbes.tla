--------------------------------- MODULE ThreadProbes ---------------------------------
(* Reachability gates (permanent deliverable, round-6 minor): each probe   *)
(* asserts the ABSENCE of a state the battery's meaning depends on         *)
(* reaching, so TLC violating it PROVES the surface is exercised. run.sh   *)
(* runs each as an expect_violation gate; a probe that stops firing means  *)
(* the model lost coverage -- report it, never delete it.                  *)
EXTENDS ThreadLifecycle

(* T2's parking x K+C cell actually reached: a rendezvous sender retired   *)
(* MID-DELIVERY while holding its receiver's claim.                        *)
ProbeNoRetiredRvSender ==
  \A e \in Threads: ~(threads[e].st = "retired" /\ threads[e].pc = "rvC")

(* The 5b-shaped rendezvous receiver branch actually reached.              *)
ProbeNoRvPendedReceiver ==
  \A e \in Threads:
    ~(threads[e].pc = "rvC" /\ threads[e].tg # NULL
        /\ threads[threads[e].tg].st = "pended")

(* ROUND-10 M-D, updated in revision 16. `t1full`'s old LiveTerm PASS was *)
(* billed as machine-checking the W3 -> W5 -> W3 cycle (A terminates B    *)
(* while B suspends A), but revision 15's t1full scope no longer          *)
(* converges: 8,131,498 distinct states and a temporal-phase timeout.     *)
(* `t1d` is the current directive-bearing LiveTerm rung, and `pr4d` is    *)
(* its exact CONSTANTS mirror. TLC violating this probe proves that rung  *)
(* actually reaches the cycle it exists to cover.                         *)
ProbeNoTermSuspendCycle ==
  \A a, b \in Threads:
    ~(/\ a # b
      /\ threads[a].pc = "termW" /\ threads[a].tg = b
      /\ threads[b].pc = "dirW"  /\ threads[b].tg = a)

(* ROUND-11 M-3. `InvNoForeignDisarm` is ANALYTICALLY VACUOUS under       *)
(* DIR_OWNED = TRUE: the disarm action's own guard forces dsrc = u, so    *)
(* the ghost's update term is identically FALSE and the invariant holds   *)
(* a priori. `dirabafix`'s clean run therefore establishes TypeOK and     *)
(* deadlock-freedom, NOT the ownership mechanism -- the falsifier         *)
(* `diraba` is the whole of that gate's content. What this probe adds is  *)
(* the other half of the honesty: TLC violating it proves the disarm path *)
(* is EXERCISED at all, so the clean run is at least a statement about a  *)
(* reachable path rather than an unvisited one.                           *)
ProbeNoDisarm ==
  \A e \in Threads: ~(threads[e].dir = "none" /\ threads[e].dbad = FALSE
                  /\ threads[e].dsrc = NULL /\ threads[e].pok = FALSE)

(* Retire-from-pended (the W7 pre-wait path) actually reached.             *)
ProbeNoRetireFromPended ==
  \A e \in Threads: ~(threads[e].st = "retired" /\ threads[e].po)

(* G11: prove the finalizer's terminal directive publication is reachable
   before the slot-zero action clears it. A green safety run without this
   probe could still skip the state whose suspend result matters. *)
ProbeNoFinalizingDead ==
  \A e \in Threads: ~(threads[e].st = "finalizing" /\ threads[e].dir = "dead")

(* G16: phase 2 must be reachable from a staged request through self-retire,
   hop, park-stack consumption, and release of the same process reference. *)
ProbeNoTeardownDone ==
  \A p \in Threads: processes[p].phase # "done"

(* G16: an external retire can win after the request is queued and before
   the caller's own retirement CAS. The continuation still has to hop. *)
ProbeNoRemoteRetiredTeardown ==
  \A e \in Threads:
    ~(threads[e].pc = "teardown" /\ threads[e].st = "retired"
      /\ processes[threads[e].proc].phase = "queued")
(* §[restart_semantics] positive and failure reachability. *)
ProbeNoRestartSuccess ==
  \A p \in Threads: ~processes[p].snapshotCopied
ProbeNoRestartSnapshotFallback ==
  \A p \in Threads: ~(processes[p].phase = "dead" /\
    ~processes[p].snapshotGood /\ processes[p].consumes = 1)
ProbeNoRestartZeroSurvivorFallback ==
  \A p \in Threads: ~(processes[p].phase = "dead" /\
    processes[p].snapshotGood /\ processes[p].consumes = 1 /\
    \A e \in Threads: threads[e].proc = p => threads[e].rp # 1)
ProbeNoRestartReplyDrop ==
  \A p \in Threads: processes[p].reply # "refused"
ProbeNoRestartReplyKeep ==
  \A p \in Threads: ~(processes[p].snapshotCopied /\
    processes[p].replyKeep /\ processes[p].reply = "pending")
ProbeNoPersistSurvivor ==
  \A p \in Threads: ~(processes[p].snapshotCopied /\
    \E e \in Threads: threads[e].proc = p /\ threads[e].rp = 2 /\
      threads[e].st \notin {"retired","finalizing","freed"})
====================================================================================
