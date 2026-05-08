/-
SlabProof.Sequential
====================

Single-thread small-step semantics for one slab slot.  Establishes:

  * P1' : every reachable word's `gen` equals the argument of the most
          recent `setGen` op (or the initial gen if there is none).
  * P3  : if any operation in a trace is a successful
          `lockWithGen(expected)`, then the word immediately before that
          step was `(expected <<< 1) | 0`.  Combined with P1', this
          gives: a successful lock on `expected` requires that the most
          recent `setGen` was `setGen expected` (and no one had locked
          + not-unlocked since).

Concurrent.lean re-uses these invariants under TSO interleaving.
-/
import SlabProof.Word

namespace SlabProof

/-- Operations a thread can issue against a single GenLock. -/
inductive Op where
  /-- Call `setGenRelease(g)` on the slot. -/
  | setGen   (g : Nat)
  /-- Call `lockWithGen(expected)` on the slot. -/
  | lockTry  (expected : Nat)
  /-- Call `unlock`. -/
  | unlock
  deriving Repr

/-- Result of one step.  `stale` only fires for `lockTry` whose CAS
    failed. -/
inductive StepResult where
  | ok
  | stale
  deriving Repr, DecidableEq

/-- One sequential step. -/
@[simp] def step (w : Word) : Op → Word × StepResult
  | .setGen g => (Word.setGenRelease w g, .ok)
  | .lockTry expected =>
    match Word.casLockWithGen w expected with
    | some w' => (w', .ok)
    | none    => (w, .stale)
  | .unlock => (Word.unlock w, .ok)

/-- A trace is a list of ops; `run` folds `step` left-to-right. -/
def run (w0 : Word) : List Op → Word
  | []      => w0
  | o :: os => run (step w0 o).1 os

@[simp] theorem run_nil (w : Word) : run w [] = w := rfl

@[simp] theorem run_cons (w : Word) (o : Op) (os : List Op) :
    run w (o :: os) = run (step w o).1 os := rfl

/-! ### P1' : invariant — the gen reflects the last setGen arg. -/

/-- `lastSetGen g0 ops` is the argument of the most recent `setGen` in
    `ops`, or `g0` if `ops` contains no `setGen`. -/
def lastSetGen (g0 : Nat) : List Op → Nat
  | [] => g0
  | .setGen g :: rest  => lastSetGen g rest
  | .lockTry _ :: rest => lastSetGen g0 rest
  | .unlock :: rest    => lastSetGen g0 rest

theorem run_gen_eq_lastSetGen (w0 : Word) :
    ∀ (ops : List Op), (run w0 ops).gen = lastSetGen w0.gen ops := by
  intro ops
  induction ops generalizing w0 with
  | nil => simp [run, lastSetGen]
  | cons o os ih =>
    cases o with
    | setGen g =>
      simp [run, step, Word.setGenRelease, lastSetGen]
      have := ih { gen := g, lock := false }
      simpa using this
    | lockTry e =>
      simp [run, step, lastSetGen]
      split
      · rename_i w' heq
        have hg : w'.gen = w0.gen :=
          Word.casLockWithGen_preserves_gen heq
        have := ih w'
        rw [hg] at this
        exact this
      · exact ih w0
    | unlock =>
      simp [run, step, Word.unlock, lastSetGen]
      have := ih { gen := w0.gen, lock := false }
      simpa using this

/-! ### P3 : sequential UAF safety. -/

/-- If a `lockTry expected` succeeds during a trace, then the word the
    CAS observed had `gen = expected` and `lock = false`. -/
theorem lockTry_success_observed
    (w : Word) (expected : Nat)
    (h : (step w (.lockTry expected)).2 = .ok) :
    w.gen = expected ∧ w.lock = false := by
  simp [step] at h
  split at h
  · rename_i _w' heq
    exact Word.casLockWithGen_success_gen_eq heq
  · exact absurd h (by simp)

/-- After a `setGen g`, the word's gen is exactly `g`. -/
theorem setGen_gen (w : Word) (g : Nat) :
    (step w (.setGen g)).1.gen = g := rfl

/-- After a `setGen g`, the word's lock is `false`. -/
theorem setGen_lock (w : Word) (g : Nat) :
    (step w (.setGen g)).1.lock = false := rfl

/-- After a successful lock, the lock bit is `true`. -/
theorem lockTry_success_locks
    (w : Word) (expected : Nat)
    (h : (step w (.lockTry expected)).2 = .ok) :
    (step w (.lockTry expected)).1.lock = true := by
  simp [step] at *
  split at h <;> rename_i heq
  · -- success branch: post-CAS word has lock = true
    simp [Word.casLockWithGen] at heq
    obtain ⟨⟨_, _⟩, heq2⟩ := heq
    rw [← heq2]
  · simp at h

/-- The full P3 statement: if the trace ends with `lockTry expected` and
    that step succeeded, then immediately before the lock the gen was
    `expected` and the lock was clear.  Together with
    `run_gen_eq_lastSetGen` this means: a successful
    `lockWithGen(expected)` requires that the most recent `setGen` arg
    was `expected`. -/
theorem trace_ends_in_successful_lock
    (w0 : Word) (ops : List Op) (expected : Nat)
    (hres : (step (run w0 ops) (.lockTry expected)).2 = .ok) :
    (run w0 ops).gen = expected ∧ (run w0 ops).lock = false := by
  exact lockTry_success_observed (run w0 ops) expected hres

/-- Corollary: a successful lock on `expected` implies `lastSetGen w0.gen
    ops = expected`. -/
theorem lock_success_implies_lastSetGen
    (w0 : Word) (ops : List Op) (expected : Nat)
    (hres : (step (run w0 ops) (.lockTry expected)).2 = .ok) :
    lastSetGen w0.gen ops = expected := by
  have := trace_ends_in_successful_lock w0 ops expected hres
  rw [run_gen_eq_lastSetGen] at this
  exact this.1

/-- Headline sequential UAF claim, contrapositive of
    `lock_success_implies_lastSetGen`.  Whenever the most recent
    `setGen` arg is *not* `expected` (canonically: a destroy issued
    `setGen (expected + 1)` and no subsequent `setGen` returned the
    gen to `expected`), a fresh `lockTry expected` issues `.stale`,
    not `.ok`.  This is the single-thread shape of the durable safety
    claim that the TSO version generalises. -/
theorem sequential_uaf_after_destroy
    (w0 : Word) (ops : List Op) (expected : Nat)
    (h : lastSetGen w0.gen ops ≠ expected) :
    (step (run w0 ops) (.lockTry expected)).2 = .stale := by
  cases hres : (step (run w0 ops) (.lockTry expected)).2 with
  | stale => rfl
  | ok    => exact (h (lock_success_implies_lastSetGen w0 ops expected hres)).elim

end SlabProof
