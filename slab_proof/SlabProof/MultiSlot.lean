/-
SlabProof.MultiSlot
===================

Multi-slot generalization.  Closes the prior reviewer's "single-slot
abstraction conflates pointers" gap.

The TSO machine has `mem : Loc → Nat`, so distinct word locations
naturally model distinct slabs.  This file:

  * Generalises `lockedCas` to `lockedCasAt`, taking the slot's word
    location `wl : Loc` as a parameter.
  * Proves `lockedCasAt_mem_other`: a CAS at `wl1` does not affect
    `mem` at any other location `wl2 ≠ wl1`.  Distinct slots' word
    locations are disjoint.
  * Lifts to `RefAt` (generalised SlabRef carrying both word-loc and
    gen) and shows two refs to different slots reference disjoint
    memory.
-/
import SlabProof.TSO
import SlabProof.Concurrent
import SlabProof.SlabRef

namespace SlabProof
namespace MultiSlot

open TSO

/-! ## §1 Parametric locked CAS -/

/-- Locked CAS on an arbitrary word location `wl`.  The original
    `Machine.lockedCas` is the special case `wl = WORD = 0`. -/
def lockedCasAt (m : Machine) (c : Core) (wl : Loc) (expected : Nat) :
    Machine × Bool :=
  let m' := Machine.drainAll m c
  let cur := m'.mem wl
  let w := Word.decode cur
  match Word.casLockWithGen w expected with
  | some w' => (m'.setMem wl (Word.encode w'), true)
  | none    => (m', false)

/-- The original `lockedCas` is `lockedCasAt` at `WORD`. -/
theorem lockedCas_eq_lockedCasAt (m : Machine) (c : Core) (expected : Nat) :
    Machine.lockedCas m c expected = lockedCasAt m c WORD expected := rfl

/-! ## §2 Multi-slot disjointness -/

/-- The post-CAS state's `mem wl2` equals the post-self-drain `mem wl2`
    when `wl1 ≠ wl2`.  The CAS at `wl1` only writes `wl1`. -/
theorem lockedCasAt_mem_other
    (m : Machine) (c : Core) (wl1 wl2 : Loc) (expected : Nat)
    (hne : wl1 ≠ wl2) :
    (lockedCasAt m c wl1 expected).1.mem wl2 =
      (Machine.drainAll m c).mem wl2 := by
  unfold lockedCasAt
  simp only [Word.casLockWithGen, Word.decode]
  have hne' : wl2 ≠ wl1 := fun h => hne h.symm
  by_cases hcond : (Machine.drainAll m c).mem wl1 / 2 = expected ∧
                   (Machine.drainAll m c).mem wl1 % 2 = 0
  · simp [hcond, Machine.setMem, if_neg hne']
  · simp [hcond, Machine.setMem]

/-- The post-CAS state's `bufs c` is empty (the CAS drains it). -/
theorem lockedCasAt_bufs_self_empty
    (m : Machine) (c : Core) (wl : Loc) (expected : Nat) :
    (lockedCasAt m c wl expected).1.bufs c =
      (Machine.drainAll m c).bufs c := by
  unfold lockedCasAt
  simp only [Word.casLockWithGen, Word.decode]
  by_cases hcond : (Machine.drainAll m c).mem wl / 2 = expected ∧
                   (Machine.drainAll m c).mem wl % 2 = 0
  · simp [hcond, Machine.setMem]
  · simp [hcond, Machine.setMem]

/-- The post-CAS state's `bufs c'` for `c' ≠ c` is unchanged. -/
theorem lockedCasAt_bufs_other
    (m : Machine) (c c' : Core) (wl : Loc) (expected : Nat)
    (hne : c ≠ c') :
    (lockedCasAt m c wl expected).1.bufs c' = m.bufs c' := by
  unfold lockedCasAt
  simp only [Word.casLockWithGen, Word.decode]
  by_cases hcond : (Machine.drainAll m c).mem wl / 2 = expected ∧
                   (Machine.drainAll m c).mem wl % 2 = 0
  · simp [hcond, Machine.setMem]
    exact TSO.drainAll_buf_other m c c' hne
  · simp [hcond, Machine.setMem]
    exact TSO.drainAll_buf_other m c c' hne

/-! ## §3 Multi-slot SlabRef -/

namespace SlabRef

/-- A `RefAt` is a generalised SlabRef carrying both the slot's word
    location and the snapshotted gen.  Refs to different slots have
    different `word_loc`s. -/
structure RefAt where
  word_loc : Loc
  gen : Nat
  deriving Repr, DecidableEq

/-- Multi-slot lock — at the slot identified by `ref.word_loc`. -/
def lockAt (m : Machine) (c : Core) (ref : RefAt) : Machine × Bool :=
  lockedCasAt m c ref.word_loc ref.gen

/-- Refs to different slots reference disjoint memory: a `lockAt` on
    `ref1` doesn't change the value of `mem` at `ref2.word_loc` (when
    the slots are distinct). -/
theorem different_slot_mem_disjoint
    (m : Machine) (c : Core) (ref1 ref2 : RefAt)
    (hne : ref1.word_loc ≠ ref2.word_loc) :
    (lockAt m c ref1).1.mem ref2.word_loc =
      (Machine.drainAll m c).mem ref2.word_loc :=
  lockedCasAt_mem_other m c ref1.word_loc ref2.word_loc ref1.gen hne

/-- A `lockAt` on slot `ref1` does not perturb `mem` at any other
    slot.  In particular, if `ref2`'s slot is already past its
    lifetime (`mem ref2.word_loc` shows the freed gen), `ref2`'s
    slot remains in the freed state after the `ref1` lockAt.

    Combined with `lockAt = lockedCasAt`, this means a stale ref's
    own subsequent `lockAt` reads the same word it would have read
    without the cross-slot operation — it cannot succeed. -/
theorem stale_ref_at_other_slot_unaffected
    (m : Machine) (c : Core) (ref1 ref2 : RefAt)
    (hC : m.bufs c = [])
    (hSlot : ref1.word_loc ≠ ref2.word_loc)
    (hStale :
      m.mem ref2.word_loc = Word.encode { gen := ref2.gen + 1, lock := false }) :
    (lockAt m c ref1).1.mem ref2.word_loc =
      Word.encode { gen := ref2.gen + 1, lock := false } := by
  have hDrain : Machine.drainAll m c = m := by
    unfold Machine.drainAll
    rw [hC]; rfl
  have h1 : (lockAt m c ref1).1.mem ref2.word_loc =
              (Machine.drainAll m c).mem ref2.word_loc :=
    lockedCasAt_mem_other m c ref1.word_loc ref2.word_loc ref1.gen hSlot
  rw [h1, hDrain]
  exact hStale

end SlabRef
end MultiSlot
end SlabProof
