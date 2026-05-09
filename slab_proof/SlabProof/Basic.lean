/-
SlabProof.Basic
===============

Mechanized safety proof for the Stygia GenLock + SecureSlab two-phase
allocate / publish protocol under x86-TSO.

Concrete artifact under proof: `kernel/memory/allocators/secure_slab.zig`
in this repo.  The Zig implementation pairs every slab-backed `*T` with a
64-bit `_gen_lock` word

    word = (gen << 1) | lock_bit

and exposes (a) a release-store that flips the gen
(`GenLock.setGenRelease`), (b) an acquire-CAS that locks the slot iff the
caller's snapshotted `expected_gen` still matches the live word
(`GenLock.lockWithGen`), and (c) a release-fetchAnd that clears the lock
bit (`GenLock.unlock`).

Theorem chain
-------------

  P1  (`Word.lean`)           Word integrity: every transition preserves
                              the `(gen << 1) | lock_bit` decomposition.
  P2  (`Word.lean`)           Parity invariant: `setGenRelease(g)` makes
                              the gen exactly `g`; `lockWithGen` only
                              flips the lock bit; `unlock` only clears it.
  P3  (`Sequential.lean`)     Sequential UAF safety: in any single-thread
                              trace, if `lockWithGen(expected)` succeeds,
                              the word at the CAS-success point was
                              `(expected << 1) | 0`; after a destroy
                              (`setGenRelease(expected+1)`), no further
                              `lockWithGen(expected)` can succeed without
                              a prior `setGenRelease(expected)`.
  P4  (`Concurrent.lean`)     TSO publication: under the TSO operational
                              model in `TSO.lean`, after a producer core
                              executes (writes-to-T-fields) ; (release-
                              store of the new gen), any consumer core
                              whose `lockWithGen(new_gen)` succeeds
                              observes those writes.
  P5  (`Concurrent.lean`)     TSO UAF safety: a stale ref carrying
                              `expected_gen` cannot succeed in
                              `lockWithGen(expected_gen)` after any other
                              core's `setGenRelease(g')` with
                              `g' ≠ expected_gen` has globally retired.

The TSO model (`TSO.lean`) follows the standard SPARC/x86-TSO operational
semantics: per-core FIFO store buffers, plain stores buffer, plain loads
read the youngest matching buffered store or fall through to memory,
locked RMW (`cmpxchgWeak`/`fetchAnd`) drains the issuing core's buffer
and is globally serialized.  We restrict to a single shared 64-bit
location plus a single shared payload location to keep the search space
tractable; the same argument generalizes to any disjoint set of payload
locations because TSO is per-location for plain accesses and globally
serialized for locked RMW.
-/

namespace SlabProof

/-- Parity of a natural: `Even n ↔ n % 2 = 0`, `Odd n ↔ n % 2 = 1`.
    Stated as a Bool-valued helper for `decide`/`omega`-friendly use. -/
@[simp] def isOdd (n : Nat) : Bool := n % 2 == 1

@[simp] def isEven (n : Nat) : Bool := n % 2 == 0

theorem isOdd_succ_isEven (n : Nat) : isOdd (n + 1) = isEven n := by
  simp [isOdd, isEven, Nat.add_mod]
  cases h : n % 2 with
  | zero => simp
  | succ k =>
    have : k = 0 := by omega
    subst this; simp

theorem isEven_succ_isOdd (n : Nat) : isEven (n + 1) = isOdd n := by
  simp [isOdd, isEven, Nat.add_mod]
  cases h : n % 2 with
  | zero => simp
  | succ k =>
    have : k = 0 := by omega
    subst this; simp

theorem not_odd_and_even (n : Nat) : ¬ (isOdd n = true ∧ isEven n = true) := by
  intro ⟨ho, he⟩
  simp [isOdd, isEven] at ho he
  omega

end SlabProof
