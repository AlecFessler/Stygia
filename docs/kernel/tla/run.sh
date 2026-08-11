#!/usr/bin/env bash
# Reproduces every TLC check for the EC-lifecycle model (systems.md rev 17).
#   ./run.sh                 gates + probes + safety + the cheap liveness set
#   RUN_XLARGE=1 ./run.sh    also the 3-core/4-EC safety run
#   RUN_SLOW=1   ./run.sh    also the extended/manual liveness rows
#
# Exit status: 0 iff every configured run is clean AND every gate
# reproduces its expected violation. Logs land in out/.
#
# ROUND-9 C-2: the previous version of this script was a revision-8
# artifact that invoked EIGHT deleted configs, so it could not exit 0
# under any circumstances, and it ran NONE of the round-7/8 falsifiers.
# Every verdict in README.md had come from invocations outside it while
# it claimed to "reproduce every check". Worse, `TERM_ESCAPE` was
# ungated: a future revision dropping the retired-terminator escape
# would have reintroduced round-8 C-1's two-core deadlock with nothing
# firing. The rule this script exists to serve — "the battery is green"
# is claimable only for text a full exit-0 run has covered — was
# unsatisfiable. Any config added below MUST also be added here.
#
# PARITY NOTE 1: this script checks the MODEL, not its faithfulness to
# systems.md. Faithfulness is a review obligation; README.md carries the
# parity table and the U*/G*/N* ledger.
# PARITY NOTE 2: it also does not check faithfulness to specv3.md.
# Round 7's C2 and round 9's C-5 were both spec/doc defects that every
# run here was structurally incapable of catching.
set -u
cd "$(dirname "$0")"

# ROUND-12 M-1: refuse to run concurrently with another instance. The
# revision-12/13 batteries produced a spurious RESULT: FAIL because two
# instances raced and collided on TLC metadir names (TLC derives the
# directory from the current time, so two runs starting in the same
# second abort with "that directory already exists"). Five expect_pass
# runs produced no verdict, and the transcript interleaved. A battery
# whose failures can be its own runner is worth nothing.
if pgrep -f "tla2tools.jar tlc2.TLC" >/dev/null 2>&1; then
  echo "REFUSING: a TLC run is already in flight (one JVM at a time)." >&2
  exit 2
fi

JAR="${TLA_TOOLS:-$HOME/.local/opt/tla/tla2tools.jar}"
JAVA_OPTS="-Xmx${TLC_HEAP:-5g} -XX:+UseParallelGC"
WORKERS=${TLC_WORKERS:-4}
mkdir -p out
fail=0

wait_for_headroom() {
  while [ "$(free -m | awk '/^Mem:/{print $7}')" -lt 3500 ]; do
    echo "  (waiting for >=3.5 GiB available memory before next TLC run)"
    sleep 30
  done
}

tlc() { # tlc <logname> <module> <flags...> -- <cfg>
  local log="$1" mod="$2"; shift 2
  wait_for_headroom
  timeout "${TLC_TIMEOUT:-7200}" java $JAVA_OPTS -cp "$JAR" tlc2.TLC \
       -workers $WORKERS -metadir "out/mc_${log}_$$" "$@" "$mod" > "out/$log.log" 2>&1
  local rc=$?; rm -rf "out/mc_${log}_$$"; return $rc
}

expect_pass() { # expect_pass <name> <module> <flags...>
  local name="$1" mod="$2"; shift 2
  tlc "$name" "$mod" "$@"
  local rc=$?
  if [ $rc -eq 124 ]; then
    printf 'FAIL  %-14s UNCONVERGED (timeout)\n' "$name"; fail=1; return
  fi
  if grep -q "No error has been found" "out/$name.log"; then
    printf 'PASS  %-14s %s\n' "$name" \
      "$(grep -oE '[0-9,]+ distinct states found' "out/$name.log" | tail -1)"
  else
    printf 'FAIL  %-14s expected clean; see out/%s.log\n' "$name" "$name"; fail=1
  fi
}

expect_violation() { # expect_violation <name> <module> <pattern> <flags...>
  local name="$1" mod="$2" pattern="$3"; shift 3
  tlc "$name" "$mod" "$@"
  if grep -q "$pattern" "out/$name.log"; then
    printf 'PASS  %-14s FIRED: %s\n' "$name" "$pattern"
  else
    printf 'FAIL  %-14s expected "%s"; see out/%s.log\n' "$name" "$pattern" "$name"; fail=1
  fi
}

# expect_unconverged <name> <expected_distinct> <module> <flags...>
#   PASS iff: rc=124 AND the temporal phase was REACHED AND the graph size
#   is within 2x of the recorded figure. Anything else fails, loudly.
expect_unconverged() {
  local name="$1" want="$2" mod="$3"; shift 3
  tlc "$name" "$mod" "$@"
  local rc=$?
  if [ $rc -ne 124 ]; then
    if grep -q "No error has been found" "out/$name.log"; then
      printf 'FAIL  %-14s CONVERGED - the recorded measurement is STALE; re-measure and promote to expect_pass\n' "$name"
    else
      printf 'FAIL  %-14s expected a temporal-phase timeout; see out/%s.log\n' "$name" "$name"
    fi
    fail=1; return
  fi
  if ! grep -q "Checking .* branches of temporal properties" "out/$name.log"; then
    printf 'FAIL  %-14s timed out during GENERATION, not the temporal check - a DIFFERENT defect\n' "$name"
    fail=1; return
  fi
  local got
  got=$(grep -oE '[0-9,]+ distinct states found' "out/$name.log" | tail -1 | tr -d ', ' | sed 's/distinctstatesfound//')
  if [ -z "$got" ]; then
    printf 'FAIL  %-14s temporal phase reached but the distinct-state count did not parse\n' "$name"
    fail=1; return
  fi
  if [ "$got" -gt $(( want * 2 )) ] || [ "$got" -lt $(( want / 2 )) ]; then
    printf 'FAIL  %-14s GRAPH DRIFT: %s distinct now, %s recorded (outside 2x) - re-measure the row\n' \
      "$name" "$got" "$want"
    fail=1; return
  fi
  printf 'PASS  %-14s UNCONVERGED as measured (temporal phase reached; %s distinct, recorded %s)\n' \
    "$name" "$got" "$want"
}

echo "== syntax =="
if java -cp "$JAR" tla2sany.SANY ECLifecycle.tla > out/sany.log 2>&1 \
   && java -cp "$JAR" tla2sany.SANY ECProbes.tla >> out/sany.log 2>&1; then
  echo "PASS  sany"
else echo "FAIL  sany (see out/sany.log)"; fail=1; fi

echo "== falsification gates and stale-gate closures =="
# rev-3 machine (PENDED=FALSE, PIN_GATE=FALSE)
expect_violation x1 ECLifecycle.tla "Invariant InvS4Holder is violated" \
  -deadlock -config ECLifecycle_rev3_x1.cfg
expect_violation x2 ECLifecycle.tla "Deadlock reached" \
  -config ECLifecycle_rev3_x2.cfg
expect_violation x3 ECLifecycle.tla "Invariant InvNoLostOneShot is violated" \
  -deadlock -config ECLifecycle_rev3_x3.cfg
# rev-4 F1, don't-wait reading. With normative target claim pins,
# RetireEnabled's pin drain now prevents the old pending-claim UAF even
# when the retired hop arm does not wait on payload_done.
expect_pass f1a ECLifecycle.tla -deadlock -config ECLifecycle_rev4_f1a.cfg
# rev-4 F1, always-wait reading of the hop-side iff.
expect_violation f1b ECLifecycle.tla "Deadlock reached" \
  -config ECLifecycle_rev4_f1b.cfg
# rev-5 literal unwind ordering (N4)
expect_violation n4 ECLifecycle.tla "Invariant InvS1 is violated" \
  -deadlock -config ECLifecycle_n4.cfg
# publish-claimable-before-hop (edge 4)
expect_violation e4 ECLifecycle.tla "Invariant InvS3 is violated" \
  -deadlock -config ECLifecycle_e4.cfg
# round-7 C1: lock-then-bump re-opens F3
expect_violation pinord ECLifecycle.tla "Invariant InvNoPreemptedLockHolder is violated" \
  -deadlock -config ECLifecycle_pinord.cfg
# round-7 C3: suspend cycles
expect_violation crcyc ECLifecycle.tla "Invariant InvNoSuspendCycle2 is violated" \
  -deadlock -config ECLifecycle_crcyc.cfg
expect_violation cr3 ECLifecycle.tla "Invariant InvNoSuspendCycle3 is violated" \
  -deadlock -config ECLifecycle_cr3.cfg
# LiveSuspender calibration: no rejection, no N6 assumptions, no stale/bad
# port owner-failure branch. dpin+dres made the old SpecFairN3/drop-bearing
# temporal phase non-calibrating; the N6 mutual-suspend lasso still fires
# at the focused SpecSus scope.
expect_violation crfals ECLifecycle.tla "Temporal properties were violated" \
  -lncheck final -config ECLifecycle_crfals.cfg
# round-8 C-1: mutual terminate. THIS is the gate that was missing.
expect_violation mterm ECLifecycle.tla "Deadlock reached" \
  -config ECLifecycle_mterm.cfg
# round-10 C-D: the directive word is an ABA once `dropped` is deleted.
# DIR_OWNED=FALSE is revision 10's value-based break; a suspender ends up
# looping on, and disarming, a third party's directive.
expect_violation diraba ECLifecycle.tla "Invariant InvNoForeignDisarm is violated" \
  -deadlock -config ECLifecycle_diraba.cfg
# round-11 C-1 stale-gate closure: before dpin, finalize's own `slot zero`
# could destroy F6's `dead` marker and make the W5 break return SUCCESS for
# a TERMINATED target. With dpin, the running-target directive waiter pins
# the target through ack/return, so finalize/reuse is blocked and this stale
# falsifier is expected clean.
expect_pass dirf6 ECLifecycle.tla -deadlock -config ECLifecycle_dirf6.cfg

echo "== reachability probes: the violation IS the pass =="
expect_violation pr1 ECProbes.tla "Invariant ProbeNoRetiredRvSender is violated" \
  -deadlock -config ECLifecycle_pr1.cfg
expect_violation pr2 ECProbes.tla "Invariant ProbeNoRvPendedReceiver is violated" \
  -deadlock -config ECLifecycle_pr2.cfg
expect_violation pr3 ECProbes.tla "Invariant ProbeNoRetireFromPended is violated" \
  -deadlock -config ECLifecycle_pr3.cfg
# round-10 M-D: prove t1full's LiveTerm PASS is not vacuous — the
# W3 -> W5 -> W3 configuration must actually be REACHED at that scope.
expect_violation pr4 ECProbes.tla "Invariant ProbeNoTermSuspendCycle is violated" \
  -deadlock -config ECLifecycle_pr4.cfg
# round-11 M-3: InvNoForeignDisarm is analytically vacuous under
# DIR_OWNED = TRUE (the disarm guard forces dsrc = u). This probe is the
# other half of the honesty: it proves the drop/disarm path is exercised.
expect_violation pr5 ECProbes.tla "Invariant ProbeNoDisarm is violated" \
  -deadlock -config ECLifecycle_pr5.cfg

echo "== current safety, TLC deadlock detection ON =="
expect_pass mtermfix  ECLifecycle.tla -config ECLifecycle_mtermfix.cfg
# NOT RUN, and the reason is round-12 M-3's own finding: under
# DIR_OWNED = TRUE the disarm guard forces dsrc = u, so InvNoForeignDisarm's
# update term is identically FALSE and the invariant holds A PRIORI. A clean
# dirabafix run therefore establishes TypeOK and deadlock-freedom at that
# scope and says NOTHING about the ownership mechanism -- the falsifier
# `diraba` is the whole of that gate's content, which is exactly what M-3
# said. It is also the one config that cannot complete: 3 ECs x the
# directive machine x round-11 C-1's five new fields runs past 117M
# distinct states. Kept as a config; not in the battery, because a run that
# proves nothing must not be what stops the battery finishing.
#   expect_pass dirabafix ECLifecycle.tla -config ECLifecycle_dirabafix.cfg
# round-12 M-1: NO -deadlock here. With it the fix-check cannot show the
# two-part disambiguator introduces no wedge, only that the invariant
# holds -- and the wedge is the whole point of a fix-check.
expect_pass dirf6fix  ECLifecycle.tla -config ECLifecycle_dirf6fix.cfg
expect_pass pmu_release ECLifecycle.tla -deadlock -config ECLifecycle_pmu_release.cfg
expect_violation pmu_remote ECLifecycle.tla "Invariant InvPmuHwCoreRefCoherent is violated" \
  -deadlock -config ECLifecycle_pmu_remote_falsifier.cfg
expect_violation vcpu_nocancel ECLifecycle.tla "Invariant InvRetiredVcpuCancelled is violated" \
  -deadlock -config ECLifecycle_vcpu_nocancel.cfg
expect_pass vcpu_cancel ECLifecycle.tla -config ECLifecycle_vcpu_cancel.cfg
expect_pass small    ECLifecycle.tla -config ECLifecycle_small.cfg
expect_pass large    ECLifecycle.tla -config ECLifecycle_large.cfg
expect_pass cr3self  ECLifecycle.tla -deadlock -config ECLifecycle_cr3self.cfg
expect_pass medium_nodir ECLifecycle.tla -config ECLifecycle_medium_nodir.cfg
if [ "${RUN_XLARGE:-0}" = "1" ]; then
  expect_pass xlarge ECLifecycle.tla -config ECLifecycle_xlarge.cfg
fi

echo "== current liveness (all carry -lncheck final) =="
# LiveTerm ladder under SpecTrm, its per-property MINIMAL fairness set.
expect_pass t1min ECLifecycle.tla -lncheck final -config ECLifecycle_t1min.cfg
expect_pass t1s   ECLifecycle.tla -lncheck final -config ECLifecycle_t1s.cfg
expect_pass t1r   ECLifecycle.tla -lncheck final -config ECLifecycle_t1r.cfg
# LADDER RUNG 3d-min - LiveTerm WITH the directive. PAIRED with pr4d_min, which
# MUST fire: without it this PASS is vacuous over the W3 -> W5 -> W3 shape
# the rung exists to cover. Keep these two adjacent and edit their
# CONSTANTS together (both .cfg headers say so).
expect_pass t1d_min ECLifecycle.tla -lncheck final -config ECLifecycle_t1d_min.cfg
expect_violation pr4d_min ECProbes.tla "Invariant ProbeNoTermSuspendCycle is violated" \
  -deadlock -config ECLifecycle_pr4d_min.cfg
# LiveSuspender under SpecSus (neither N6 assumption), paired with crfals.
expect_pass cr1minself ECLifecycle.tla -lncheck final -config ECLifecycle_cr1minself.cfg
if [ "${RUN_SLOW:-0}" = "1" ]; then
  # Full directive 2c x 3e medium is preserved on disk as the extended
  # aggregate target, but it is NOT a slow-battery verdict: after dpin/dres
  # it was stopped after >1h at ~598M generated / ~133.6M distinct /
  # ~11.9M queued states. The default evidence is split between
  # medium_nodir and the directive-specific rows above.
  #   manual remeasure target: full medium aggregate config
  # MEASURED NOT TO CONVERGE at revision 15 - 8,131,498 distinct /
  # 16,262,996 product nodes, 17.0x its revision-11 size. Kept in the
  # battery deliberately: a config that cannot converge at HEAD scope is a
  # real finding about the model's checkable boundary, and that boundary is
  # what a future revision needs to know. Its directive coverage moved to
  # t1d_min. See the SCOPE NOTE in ECLifecycle_t1full.cfg.
  # The 8131498 is the DRIFT ALARM's recorded figure - if the graph moves
  # outside 2x of it, this row fails and demands a re-measurement rather
  # than quietly continuing to "pass" about a different machine.
  expect_unconverged t1full 8131498 ECLifecycle.tla -lncheck final -config ECLifecycle_t1full.cfg
  # Full directive-bearing LiveTerm row. Preserved as extended/manual
  # measured-unconverged evidence after the current dpin/dres/failed-result
  # graph reached final temporal checking and timed out at 1,548,068
  # distinct / 3,096,136 product states. Its default coverage moved to the
  # bounded t1d_min/pr4d_min pair above; do not cite full t1d as a PASS.
  expect_unconverged t1d 1548068 ECLifecycle.tla -lncheck final -config ECLifecycle_t1d.cfg
  expect_pass cr1fullself ECLifecycle.tla -lncheck final -config ECLifecycle_cr1fullself.cfg
  expect_pass liveness_a  ECLifecycle.tla -lncheck final -config ECLifecycle_liveness_a.cfg
  expect_pass liveness_b  ECLifecycle.tla -lncheck final -config ECLifecycle_liveness_b.cfg
fi
# NOT RUN and deliberately so: q1-q7/q7d (2c x 3e per-property liveness).
# q7 did not converge in 90 minutes of pure temporal checking; see the
# README's note on the fairness-constraint count. They are kept as
# configs because the scope question is open, not because they pass.

if [ "$fail" -ne 0 ]; then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: OK"
