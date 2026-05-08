/-
SlabProof.Word
==============

The 64-bit gen+lock word and its three primitive transitions, modelled
abstractly as natural numbers.  The Zig source uses `std.atomic.Value(u64)`
but every operation we model touches only the bottom-bit / shift-1
encoding, so we sidestep `UInt64` overflow reasoning by working in `Nat`
and asserting the gen fits in 63 bits where needed.

Encoding mirrors `secure_slab.zig`:

    word = (gen <<< 1) ||| lock_bit       -- gen : 63-bit, lock_bit ∈ {0,1}

The Zig source places these constraints inline:
  * `setGenRelease(g)`  stores `(g <<< 1) ||| 0`            (release)
  * `lockWithGen(g)`    CAS `(g<<<1)|0` ↦ `(g<<<1)|1`       (acquire on succ)
  * `unlock()`          fetchAnd ¬1                          (release)
  * `currentGen()`      load and shift-right 1               (monotonic)

See `kernel/memory/allocators/secure_slab.zig` for the originals.
-/
import SlabProof.Basic

namespace SlabProof

/-- The 64-bit gen+lock word.  `gen` is the high 63 bits; `lock` is the
    low bit.  We store them split for readable proofs and only reify into
    a single `Nat` at the boundary. -/
structure Word where
  gen : Nat
  lock : Bool
deriving DecidableEq, Repr

namespace Word

/-- Reify a `Word` to its on-the-wire `Nat` representation
    `(gen <<< 1) ||| lock`. -/
@[simp] def encode (w : Word) : Nat :=
  2 * w.gen + (if w.lock then 1 else 0)

/-- Decode an arbitrary `Nat` to a `Word`.  Inverse of `encode` (proven
    below). -/
@[simp] def decode (n : Nat) : Word :=
  { gen := n / 2, lock := n % 2 == 1 }

@[simp] theorem decode_encode (w : Word) : decode (encode w) = w := by
  cases w with
  | mk g b =>
    cases b <;> simp [encode, decode] <;> omega

@[simp] theorem encode_decode (n : Nat) : encode (decode n) = n := by
  simp [encode, decode]
  have hdm : 2 * (n / 2) + n % 2 = n := by
    have := Nat.div_add_mod n 2; omega
  by_cases h : n % 2 = 1
  · simp [h]; omega
  · have h0 : n % 2 = 0 := by omega
    simp [h0]; omega

/-- The "freshly grown" zero word: gen = 0 (even, freed), lock = 0. -/
@[simp] def zero : Word := { gen := 0, lock := false }

/-- The transition triggered by `GenLock.setGenRelease(new_gen)`:
    overwrite the entire word with `(new_gen <<< 1) | 0`. -/
@[simp] def setGenRelease (_w : Word) (new_gen : Nat) : Word :=
  { gen := new_gen, lock := false }

/-- The CAS in `GenLock.lockWithGen(expected_gen)` succeeds iff the word
    is exactly `(expected_gen <<< 1) | 0`. -/
@[simp] def casLockWithGen (w : Word) (expected_gen : Nat) : Option Word :=
  if w.gen = expected_gen ∧ w.lock = false then
    some { gen := w.gen, lock := true }
  else
    none

/-- `GenLock.unlock`: clears the lock bit, leaves gen alone. -/
@[simp] def unlock (w : Word) : Word :=
  { gen := w.gen, lock := false }

/-- A slot is "live" when its gen is odd and the lock is unset. -/
@[simp] def isLive (w : Word) : Prop := isOdd w.gen = true

/-- A slot is "freed" when its gen is even.  This is the parity that
    `lockWithGen` rejects. -/
@[simp] def isFreed (w : Word) : Prop := isEven w.gen = true

/-! ### P1: word integrity – every transition preserves the encoding. -/

theorem encode_setGenRelease (w : Word) (g : Nat) :
    encode (setGenRelease w g) = 2 * g := by
  simp [encode, setGenRelease]

theorem encode_unlock (w : Word) :
    encode (unlock w) = 2 * w.gen := by
  simp [encode, unlock]

theorem encode_casLockWithGen_success
    {w w' : Word} {g : Nat}
    (h : casLockWithGen w g = some w') :
    encode w' = 2 * g + 1 := by
  simp [casLockWithGen] at h
  obtain ⟨⟨hg, hb⟩, heq⟩ := h
  subst heq
  simp [encode, hg]

/-! ### P2: parity invariant. -/

theorem setGenRelease_gen (w : Word) (g : Nat) :
    (setGenRelease w g).gen = g := rfl

theorem unlock_gen (w : Word) : (unlock w).gen = w.gen := rfl

theorem casLockWithGen_preserves_gen
    {w w' : Word} {g : Nat}
    (h : casLockWithGen w g = some w') :
    w'.gen = w.gen := by
  simp [casLockWithGen] at h
  obtain ⟨⟨hg, _⟩, heq⟩ := h
  subst heq; rfl

/-- The CAS only succeeds on a slot whose gen matches the expected value
    AND whose parity is whatever the caller's `expected_gen` parity is.
    In the protocol the caller always passes an odd `expected_gen`
    (asserted in Zig at `lockWithGen`'s parity check), so success
    guarantees the slot was alive (odd gen) and unlocked. -/
theorem casLockWithGen_success_gen_eq
    {w w' : Word} {g : Nat}
    (h : casLockWithGen w g = some w') :
    w.gen = g ∧ w.lock = false := by
  simp [casLockWithGen] at h
  exact h.1

theorem casLockWithGen_no_succ_on_locked
    {w : Word} {g : Nat} (h : w.lock = true) :
    casLockWithGen w g = none := by
  simp [casLockWithGen, h]

theorem casLockWithGen_no_succ_on_wrong_gen
    {w : Word} {g : Nat} (h : w.gen ≠ g) :
    casLockWithGen w g = none := by
  simp [casLockWithGen, h]

end Word
end SlabProof
