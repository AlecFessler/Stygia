--------------------------------- MODULE ECProbes ---------------------------------
(* Reachability gates (permanent deliverable, round-6 minor): each probe   *)
(* asserts the ABSENCE of a state the battery's meaning depends on         *)
(* reaching, so TLC violating it PROVES the surface is exercised. run.sh   *)
(* runs each as an expect_violation gate; a probe that stops firing means  *)
(* the model lost coverage -- report it, never delete it.                  *)
EXTENDS ECLifecycle

(* T2's parking x K+C cell actually reached: a rendezvous sender retired   *)
(* MID-DELIVERY while holding its receiver's claim.                        *)
ProbeNoRetiredRvSender ==
  \A e \in ECs: ~(ecs[e].st = "retired" /\ ecs[e].pc = "rvC")

(* The 5b-shaped rendezvous receiver branch actually reached.              *)
ProbeNoRvPendedReceiver ==
  \A e \in ECs:
    ~(ecs[e].pc = "rvC" /\ ecs[e].tg # NULL
        /\ ecs[ecs[e].tg].st = "pended")

(* ROUND-10 M-D. `t1full`'s LiveTerm PASS was billed as machine-checking  *)
(* the W3 -> W5 -> W3 cycle (A terminates B while B suspends A). That is  *)
(* worth nothing if the configuration is never REACHED in those 477,468   *)
(* states -- LiveTerm holds vacuously over a shape that never occurs.     *)
(* This is the probe standard applied to the artifact's own certificate:  *)
(* TLC violating it proves the cycle is constructible, so the PASS is     *)
(* about something.                                                       *)
ProbeNoTermSuspendCycle ==
  \A a, b \in ECs:
    ~(/\ a # b
      /\ ecs[a].pc = "termW" /\ ecs[a].tg = b
      /\ ecs[b].pc = "dirW"  /\ ecs[b].tg = a)

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
  \A e \in ECs: ~(ecs[e].dir = "none" /\ ecs[e].dbad = FALSE
                  /\ ecs[e].dsrc = NULL /\ ecs[e].pok = FALSE)

(* Retire-from-pended (the W7 pre-wait path) actually reached.             *)
ProbeNoRetireFromPended ==
  \A e \in ECs: ~(ecs[e].st = "retired" /\ ecs[e].po)
====================================================================================
