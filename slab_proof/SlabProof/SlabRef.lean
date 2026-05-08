/-
SlabProof.SlabRef
=================

Handle-level safety lift for the GenLock primitive.

Production code never calls `lockedCas` directly — every slab-backed
access goes through `SlabRef(T).lock` (`secure_slab.zig:226-302`).  A
`SlabRef` carries (a) a pointer to the slot, and (b) the generation
snapshotted at issuance time.  Calling `.lock` does
`self.ptr._gen_lock.lockWithGen(self.gen, ...)` — i.e. the underlying
`lockedCas` with the snapshotted gen as `expected`.

This file establishes the SlabRef-level safety theorems by reduction
to the `Word` + `Machine` theorems in `Concurrent.lean`.  The "pointer"
part of `SlabRef` is not load-bearing for safety — what matters is the
gen snapshot — so we model `Ref := { gen : Nat }` and treat the slot's
`WORD` location as fixed.  Multiple SlabRefs to the *same* slot at
*different* gens (the "arbitrary parallel pointer ownership" threat
shape) is captured by quantifying over the `Ref` argument.

Safety theorems:
  * `lock_success_iff_word_matches`     — `lock` success precisely
                                           characterized by mem WORD.
  * `disjoint_refs_at_most_one_succeeds`— two refs at different gens
                                           can't both have a successful
                                           lock from one state.
  * `lock_after_retired_destroy_fails`  — stale ref after
                                           `setGenRelease(ref.gen+1)`
                                           has drained — fails on gen.
  * `lock_after_realloc_fails`          — stale ref after destroy
                                           AND realloc both drained —
                                           still fails (gen is now
                                           ref.gen+2).
  * `lock_in_destroy_window_fails`      — destroy in progress, gen-bump
                                           buffered but maybe not drained
                                           yet — fails on lock-bit OR gen.
-/
import SlabProof.TSO
import SlabProof.Concurrent

namespace SlabProof
namespace SlabRef

open TSO

/-- A handle to a slab slot.  Carries the gen snapshotted at issuance
    time.  In real code this is paired with a `*T`, but the pointer is
    not load-bearing for safety reasoning — only the gen is. -/
structure Ref where
  gen : Nat
  deriving Repr, DecidableEq

/-- `SlabRef.lock`: do a locked CAS at WORD with the snapshotted gen as
    `expected`.  Mirrors `secure_slab.zig:253-256`:

      pub fn lock(self: Self, src: SrcLoc) AccessError!*T {
          try self.ptr._gen_lock.lockWithGen(@intCast(self.gen), src);
          return self.ptr;
      }
-/
def lock (m : Machine) (c : Core) (ref : Ref) : Machine × Bool :=
  Machine.lockedCas m c ref.gen

/-- `SlabRef.unlock`: clear the lock bit.  In real code this is a
    `fetchAnd ¬1` release operation; we model it as a buffered store
    that re-installs `(ref.gen << 1) | 0`, which is what the consumer
    would have observed prior to acquiring. -/
@[simp] def unlock (m : Machine) (c : Core) (ref : Ref) : Machine :=
  m.bufStore c WORD (Word.encode { gen := ref.gen, lock := false })

/-! ## §1 Foundational equivalence: lock = lockedCas -/

/-- `SlabRef.lock` is precisely `lockedCas` with the ref's gen.  A trivial
    unfolding, but exposes the equivalence so theorems about the latter
    transfer to the former. -/
theorem lock_eq_lockedCas (m : Machine) (c : Core) (ref : Ref) :
    SlabRef.lock m c ref = Machine.lockedCas m c ref.gen := rfl

/-! ## §2 Lock success characterization -/

/-- A successful `SlabRef.lock` precisely corresponds to the post-drain
    `mem WORD` being the canonical encoding of `(ref.gen, lock := false)`. -/
theorem lock_success_iff_word_matches
    (m : Machine) (c : Core) (ref : Ref) :
    (SlabRef.lock m c ref).2 = true ↔
      (Machine.drainAll m c).mem WORD =
        Word.encode { gen := ref.gen, lock := false } := by
  rw [lock_eq_lockedCas]
  constructor
  · -- Forward: lockedCas success ⇒ post-drain mem WORD has canonical form.
    intro h; exact lockedCas_success_word_eq m c ref.gen h
  · -- Reverse: post-drain mem WORD = canonical ⇒ CAS succeeds.
    intro h
    unfold Machine.lockedCas
    simp [h, Word.decode_encode, Word.casLockWithGen]

/-! ## §3 Disjoint refs: distinct gens give at most one success -/

/-- From a single state with empty consumer buffer, two refs with
    different gens cannot both have a successful `lock` — they require
    `mem WORD` to be different encodings, which is impossible. -/
theorem disjoint_refs_at_most_one_succeeds
    (m : Machine) (c : Core) (ref1 ref2 : Ref)
    (hC : m.bufs c = [])
    (hne : ref1.gen ≠ ref2.gen) :
    ¬ ((SlabRef.lock m c ref1).2 = true ∧ (SlabRef.lock m c ref2).2 = true) := by
  intro ⟨h1, h2⟩
  rw [lock_eq_lockedCas] at h1 h2
  have hDrain : Machine.drainAll m c = m := by
    unfold Machine.drainAll
    rw [hC]; rfl
  have hw1 := lockedCas_success_word_eq m c ref1.gen h1
  have hw2 := lockedCas_success_word_eq m c ref2.gen h2
  rw [hDrain] at hw1 hw2
  rw [hw1] at hw2
  -- encode {ref1.gen, false} = encode {ref2.gen, false} ⇒ ref1.gen = ref2.gen
  simp [Word.encode] at hw2
  exact hne (by omega)

/-! ## §4 UAF prevention against retired destroys -/

/-- After a destroy `setGenRelease(ref.gen + 1)` has globally retired
    (mem WORD shows the freed gen), a stale ref at `ref.gen` cannot
    successfully lock. -/
theorem lock_after_retired_destroy_fails
    (m : Machine) (c : Core) (ref : Ref)
    (hC : m.bufs c = [])
    (hRetired : m.mem WORD = Word.encode { gen := ref.gen + 1, lock := false }) :
    (SlabRef.lock m c ref).2 = false := by
  rw [lock_eq_lockedCas]
  apply stale_rejected_gen m c ref.gen hC
  rw [hRetired]
  simp [Word.encode]

/-- After a destroy AND realloc have both retired (slot is now live at
    `ref.gen + 2`), a stale ref at `ref.gen` still fails — gen has
    moved past, never to return. -/
theorem lock_after_realloc_fails
    (m : Machine) (c : Core) (ref : Ref)
    (hC : m.bufs c = [])
    (hRealloc : m.mem WORD = Word.encode { gen := ref.gen + 2, lock := false }) :
    (SlabRef.lock m c ref).2 = false := by
  rw [lock_eq_lockedCas]
  apply stale_rejected_gen m c ref.gen hC
  rw [hRealloc]
  simp [Word.encode]

/-! ## §5 Destroy-window: in-progress destroy is also safe -/

/-- A stale ref's `lock` fails throughout the destroy window — the
    composed pre/post drain theorem from `Concurrent.lean`, lifted to
    the `SlabRef` API. -/
theorem lock_in_destroy_window_fails
    (m : Machine) (P C : Core) (ref : Ref) (k : Nat)
    (hPC : P ≠ C)
    (hC : m.bufs C = [])
    (hLocked : m.mem WORD = Word.encode { gen := ref.gen, lock := true })
    (hBufP : m.bufs P =
      [{ loc := WORD,
         val := Word.encode { gen := ref.gen + 1, lock := false } }]) :
    let m_k := Nat.rec (motive := fun _ => Machine) m
                 (fun _ acc => Machine.drainOne acc P) k
    (SlabRef.lock m_k C ref).2 = false := by
  intro m_k
  rw [lock_eq_lockedCas]
  exact destroy_window_safe m P C ref.gen k hPC hC hLocked hBufP

end SlabRef
end SlabProof
