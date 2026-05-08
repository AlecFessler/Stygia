/-
SlabProof.Weak
==============

Models `cmpxchgWeak`'s spurious-failure behavior.

Real Zig at `secure_slab.zig:177` calls `cmpxchgWeak`, which is
allowed to fail spuriously (return `none`) even when the comparand
matches.  The slab's retry loop (`secure_slab.zig:176-184`) handles
this by re-reading and re-CASing if the gen still matches.

The safety question for spurious failure: can it cause unsoundness?
Specifically, can a spurious failure make a stale CAS succeed where
a strong CAS would have failed?  Answer: no — spurious failure is
strictly more conservative (false negatives only, never false
positives).

We model this by giving `Machine.lockedCasWeak` an additional Bool
parameter `spuriousFail` controlled by the scheduler.  When
`spuriousFail = true`, the CAS returns `false` and doesn't write,
regardless of the comparand.  When `spuriousFail = false`, behaviour
matches the strong CAS.

Theorem: every spurious-CAS theorem holds with the same proof — the
spurious-failure path is a strict refinement that fewer-than-or-equal
strong-CAS successes occur.  In particular `lockedCasWeak_success_implies_word_eq`,
`destroy_window_pre_drain_weak`, etc.

This is a small extension that closes the "weak CAS not modeled"
gap from the prior review.
-/
import SlabProof.TSO
import SlabProof.Concurrent
import SlabProof.Reaper
import SlabProof.Invariant

namespace SlabProof
namespace Weak

open TSO

/-- Locked CAS with a scheduler-controlled spurious-failure bit.
    `spuriousFail = true` ⇒ always fail (no state change to mem WORD).
    `spuriousFail = false` ⇒ behave like the strong CAS. -/
def lockedCasWeak (m : Machine) (c : Core) (expected : Nat)
    (spuriousFail : Bool) : Machine × Bool :=
  let m' := Machine.drainAll m c
  let cur := m'.mem WORD
  let m'' := m'.setSaw c (some cur)
  if spuriousFail then
    (m'', false)
  else
    Machine.lockedCas m c expected

/-! ## §1 Spurious failure cannot succeed -/

/-- A spuriously-failed CAS always has `.snd = false`. -/
theorem lockedCasWeak_spurious_fails
    (m : Machine) (c : Core) (expected : Nat) :
    (lockedCasWeak m c expected true).2 = false := by
  unfold lockedCasWeak; simp

/-- A weak CAS with `spuriousFail = false` matches the strong CAS. -/
theorem lockedCasWeak_strong_eq
    (m : Machine) (c : Core) (expected : Nat) :
    lockedCasWeak m c expected false = Machine.lockedCas m c expected := by
  unfold lockedCasWeak; simp

/-! ## §2 Safety transfers from strong to weak -/

/-- Spurious failure preserves the success-implies-word-eq guarantee:
    if a weak CAS succeeded, the same conclusion holds. -/
theorem lockedCasWeak_success_implies_word_eq
    (m : Machine) (c : Core) (expected : Nat) (spurious : Bool)
    (hok : (lockedCasWeak m c expected spurious).2 = true) :
    (Machine.drainAll m c).mem WORD =
      Word.encode { gen := expected, lock := false } := by
  cases spurious with
  | true =>
    -- Spurious always fails; contradicts hok.
    have := lockedCasWeak_spurious_fails m c expected
    rw [this] at hok
    exact (Bool.false_ne_true hok).elim
  | false =>
    rw [lockedCasWeak_strong_eq] at hok
    exact TSO.lockedCas_success_word_eq m c expected hok

/-- Spurious failure cannot make a stale ref's CAS succeed.  Direct
    consequence of the above: if a weak CAS succeeds at `expected`,
    the post-drain mem WORD must still match the canonical encoding —
    spurious failure can only DELAY this, not bypass the test. -/
theorem stale_ref_weak_cas_fails
    (m : Machine) (c : Core) (cur expected : Nat) (spurious : Bool)
    (hC : m.bufs c = [])
    (hCur : m.mem WORD = Word.encode { gen := cur, lock := false })
    (hne : cur ≠ expected) :
    (lockedCasWeak m c expected spurious).2 = false := by
  cases spurious with
  | true => exact lockedCasWeak_spurious_fails m c expected
  | false =>
    rw [lockedCasWeak_strong_eq]
    -- mem WORD = encode {cur, false}; stale_rejected_gen handles it.
    apply TSO.stale_rejected_gen m c expected hC
    rw [hCur]; simp [Word.encode]
    exact hne

/-- Pre-drain destroy-window safety transfers to weak CAS. -/
theorem destroy_window_pre_drain_weak
    (m : Machine) (P C : Core) (expected : Nat) (spurious : Bool)
    (hPC : P ≠ C)
    (hC : m.bufs C = [])
    (hLocked : m.mem WORD = Word.encode { gen := expected, lock := true }) :
    (lockedCasWeak m C expected spurious).2 = false := by
  cases spurious with
  | true => exact lockedCasWeak_spurious_fails m C expected
  | false =>
    rw [lockedCasWeak_strong_eq]
    exact TSO.destroy_window_pre_drain m P C expected hPC hC hLocked

end Weak
end SlabProof
