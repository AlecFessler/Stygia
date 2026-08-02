#!/usr/bin/env bash
# Reproduces every TLC check for the EC-lifecycle model (systems.md rev 15).
#   ./run.sh                 gates + probes + safety + the cheap liveness set
#   RUN_XLARGE=1 ./run.sh    also the 3-core/4-EC safety run
#   RUN_SLOW=1   ./run.sh    also the multi-thousand-second liveness runs
#
# Exit status: 0 iff every revision-10 run is clean AND every gate
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

echo "== syntax =="
if java -cp "$JAR" tla2sany.SANY ECLifecycle.tla > out/sany.log 2>&1 \
   && java -cp "$JAR" tla2sany.SANY ECProbes.tla >> out/sany.log 2>&1; then
  echo "PASS  sany"
else echo "FAIL  sany (see out/sany.log)"; fail=1; fi

echo "== falsification gates: every fix must be shown load-bearing =="
# rev-3 machine (PENDED=FALSE, PIN_GATE=FALSE)
expect_violation x1 ECLifecycle.tla "Invariant InvS4Holder is violated" \
  -deadlock -config ECLifecycle_rev3_x1.cfg
expect_violation x2 ECLifecycle.tla "Deadlock reached" \
  -config ECLifecycle_rev3_x2.cfg
expect_violation x3 ECLifecycle.tla "Invariant InvNoLostOneShot is violated" \
  -deadlock -config ECLifecycle_rev3_x3.cfg
# rev-4 F1, both readings of the hop-side iff
expect_violation f1a ECLifecycle.tla "Invariant InvNoUAF is violated" \
  -deadlock -config ECLifecycle_rev4_f1a.cfg
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
# round-11 C-1: finalize's own `slot zero` destroys F6's `dead` marker, so
# the W5 break returns SUCCESS for a TERMINATED target. Needs non-zero
# TERM/CR budgets: the defect requires a real finalize and a real reuse.
expect_violation dirf6 ECLifecycle.tla "Invariant InvNoFalseSuspendSuccess is violated" \
  -deadlock -config ECLifecycle_dirf6.cfg

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

echo "== revision 15: safety, TLC deadlock detection ON =="
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
expect_pass small    ECLifecycle.tla -config ECLifecycle_small.cfg
expect_pass large    ECLifecycle.tla -config ECLifecycle_large.cfg
expect_pass cr3self  ECLifecycle.tla -deadlock -config ECLifecycle_cr3self.cfg
expect_pass medium   ECLifecycle.tla -config ECLifecycle_medium.cfg
if [ "${RUN_XLARGE:-0}" = "1" ]; then
  expect_pass xlarge ECLifecycle.tla -config ECLifecycle_xlarge.cfg
fi

echo "== revision 15: liveness (all carry -lncheck final) =="
# LiveTerm ladder under SpecTrm, its per-property MINIMAL fairness set.
expect_pass t1min ECLifecycle.tla -lncheck final -config ECLifecycle_t1min.cfg
expect_pass t1s   ECLifecycle.tla -lncheck final -config ECLifecycle_t1s.cfg
expect_pass t1r   ECLifecycle.tla -lncheck final -config ECLifecycle_t1r.cfg
# LiveSuspender under SpecFairN3 (neither N6 assumption).
expect_pass cr1minself ECLifecycle.tla -lncheck final -config ECLifecycle_cr1minself.cfg
if [ "${RUN_SLOW:-0}" = "1" ]; then
  expect_pass t1full      ECLifecycle.tla -lncheck final -config ECLifecycle_t1full.cfg
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
