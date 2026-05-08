/-
SlabProof.Concurrent
====================

TSO-level safety, v2.  Re-derived against the buffered-release-store
TSO model in `TSO.lean`.

Layered structure:
  §1 Drain mechanics (`drainOne`/`drainAll` lemmas).
  §2 FIFO commit lemma — `drainAll` of buf `xs` writes every entry to
     `mem` in order; the final `mem l` is the last buffered write to `l`.
  §3 Locked-CAS observation lemma — a successful CAS at `expected`
     observed `mem WORD = encode { gen := expected, lock := false }`.
  §4 Generalized publication — for any list of payload stores ending
     in a release-store of `g`, after producer drains and consumer
     CAS-succeeds at `g`, every payload location reflects its last
     buffered value.
  §5 Stale rejection in two windows: pre-drain (lock bit set blocks
     the CAS) and post-drain (gen mismatch blocks it).
  §6 Destroy-window theorem — the entire window from "producer holds
     the lock at expected" through "producer's setGenRelease(expected+1)
     drains" is safe against stale CAS at expected.
-/
import SlabProof.TSO
import SlabProof.Sequential

namespace SlabProof
namespace TSO

/-! ## §1 Drain mechanics -/

theorem drainOne_buf_self
    (m : Machine) (c : Core) (e : BufEntry) (rest : List BufEntry)
    (h : m.bufs c = e :: rest) :
    (Machine.drainOne m c).bufs c = rest := by
  unfold Machine.drainOne
  rw [h]
  simp [Machine.setBuf, Machine.setMem]

theorem drainOne_buf_other
    (m : Machine) (c c' : Core) (h : c ≠ c') :
    (Machine.drainOne m c).bufs c' = m.bufs c' := by
  unfold Machine.drainOne
  cases hbc : m.bufs c with
  | nil => rfl
  | cons e rest =>
    simp [Machine.setBuf, Machine.setMem, h, Ne.symm h]

theorem drainOne_empty_buf (m : Machine) (c : Core) (h : m.bufs c = []) :
    Machine.drainOne m c = m := by
  unfold Machine.drainOne
  rw [h]

/-- `drainOne` writes the head's value to the head's location and
    leaves all other locations unchanged. -/
theorem drainOne_mem_head
    (m : Machine) (c : Core) (e : BufEntry) (rest : List BufEntry)
    (h : m.bufs c = e :: rest) :
    (Machine.drainOne m c).mem e.loc = e.val := by
  unfold Machine.drainOne
  rw [h]
  simp [Machine.setBuf, Machine.setMem]

theorem drainOne_mem_other
    (m : Machine) (c : Core) (e : BufEntry) (rest : List BufEntry) (l : Loc)
    (h : m.bufs c = e :: rest) (hl : l ≠ e.loc) :
    (Machine.drainOne m c).mem l = m.mem l := by
  unfold Machine.drainOne
  rw [h]
  simp [Machine.setBuf, Machine.setMem, hl]

/-! ## §2 FIFO commit lemma

`drainAll m c` empties `c`'s buffer.  Stronger: at the end, for every
location `l`, `(drainAll m c).mem l` equals the value of the *last*
buffered write to `l` from `c`'s buffer, falling back to the original
`m.mem l` if no such write exists in `c`'s buffer.
-/

/-- `lastWriteTo xs l` returns the value of the youngest entry in `xs`
    whose location is `l`, or `none` if no such entry exists. -/
def lastWriteTo : List BufEntry → Loc → Option Nat
  | [], _ => none
  | e :: rest, l =>
    match lastWriteTo rest l with
    | some v => some v
    | none   => if e.loc = l then some e.val else none

/-- After draining the entire buffer, the issuing core's buffer is
    empty. -/
theorem drainAll_buf_empty (m : Machine) (c : Core) :
    (Machine.drainAll m c).bufs c = [] := by
  unfold Machine.drainAll
  -- Inductive principle on the buffer list, not on `c`.  We strengthen
  -- to: for any state `m'` and any list `xs`, the foldl over `xs` using
  -- `drainOne acc c` — when `m'.bufs c = ys` and `xs.length ≥ ys.length`
  -- — empties `c`'s buffer.  Easiest: induct on `m.bufs c`.
  generalize hbuf : m.bufs c = bs
  induction bs generalizing m with
  | nil => simp [hbuf]
  | cons e rest ih =>
    simp [hbuf, List.foldl]
    -- After drainOne, the head is popped and rest of fold continues.
    -- New buffer of c is `rest`; iterate length is `rest.length + 1`,
    -- but our remaining fold has length `rest.length`.
    -- Use ih with the new state.
    have hbuf' : (Machine.drainOne m c).bufs c = rest :=
      drainOne_buf_self m c e rest hbuf
    -- After the fold, buf c becomes `[]` because we drain `rest.length`
    -- more times starting from a buffer of length `rest.length`.
    have := ih (Machine.drainOne m c) hbuf'
    -- The inductive hypothesis says: foldl over `rest` of drainOne on
    -- (drainOne m c) ends with bufs c = []. But our fold is over the
    -- ORIGINAL `e :: rest` (`bs`); however `simp [hbuf, List.foldl]`
    -- rewrote `bs` away. Let's invoke `this`.
    -- The goal should now be: (foldl ... rest (drainOne m c)).bufs c = []
    -- which is exactly `this`.
    exact this

/-- `drainAll` doesn't touch the buffers of other cores. -/
theorem drainAll_buf_other
    (m : Machine) (c c' : Core) (h : c ≠ c') :
    (Machine.drainAll m c).bufs c' = m.bufs c' := by
  unfold Machine.drainAll
  generalize hbuf : m.bufs c = bs
  induction bs generalizing m with
  | nil => simp
  | cons e rest ih =>
    simp [List.foldl]
    have hbuf' : (Machine.drainOne m c).bufs c = rest :=
      drainOne_buf_self m c e rest hbuf
    have hother : (Machine.drainOne m c).bufs c' = m.bufs c' :=
      drainOne_buf_other m c c' h
    rw [← hother]
    exact ih (Machine.drainOne m c) hbuf'

/-- Core FIFO commit lemma.  After `drainAll m c`:
      * if `c`'s original buffer had any write to `l`, `mem l` is the
        value of the last such write;
      * otherwise `mem l` is unchanged.
    Stated as an `Option`-valued equation via `lastWriteTo`.
-/
theorem drainAll_mem_eq
    (m : Machine) (c : Core) (l : Loc) :
    (Machine.drainAll m c).mem l =
      match lastWriteTo (m.bufs c) l with
      | some v => v
      | none   => m.mem l := by
  unfold Machine.drainAll
  generalize hbuf : m.bufs c = bs
  induction bs generalizing m with
  | nil => simp [List.foldl, lastWriteTo]
  | cons e rest ih =>
    simp [List.foldl]
    -- After drainOne, mem at e.loc = e.val and mem at l ≠ e.loc unchanged.
    have hbuf' : (Machine.drainOne m c).bufs c = rest :=
      drainOne_buf_self m c e rest hbuf
    have ih' := ih (Machine.drainOne m c) hbuf'
    rw [ih']
    -- Goal: match lastWriteTo rest l on (drainOne m c).mem l = ...
    --       which equals match lastWriteTo (e :: rest) l with...
    cases hlw : lastWriteTo rest l with
    | some v => simp [lastWriteTo, hlw]
    | none =>
      simp [lastWriteTo, hlw]
      by_cases hloc : e.loc = l
      · simp [hloc]
        rw [← hloc]
        exact drainOne_mem_head m c e rest hbuf
      · have hne : l ≠ e.loc := fun heq => hloc heq.symm
        simp [hloc]
        exact drainOne_mem_other m c e rest l hbuf hne

/-! ## §3 Locked-CAS observation -/

/-- The locked CAS observes `(drainAll m c).mem WORD`. -/
theorem lockedCas_observed
    (m : Machine) (c : Core) (expected : Nat) :
    (Machine.lockedCas m c expected).1.consSaw c =
      some ((Machine.drainAll m c).mem WORD) := by
  unfold Machine.lockedCas
  simp [Machine.setSaw, Machine.setMem]
  split <;> simp

/-- If the locked CAS succeeded, the post-drain memory at WORD decoded
    to `{ gen := expected, lock := false }`. -/
theorem lockedCas_success_word_eq
    (m : Machine) (c : Core) (expected : Nat)
    (hok : (Machine.lockedCas m c expected).2 = true) :
    (Machine.drainAll m c).mem WORD = Word.encode { gen := expected, lock := false } := by
  unfold Machine.lockedCas at hok
  simp [Word.casLockWithGen, Word.decode] at hok
  by_cases hcond : (Machine.drainAll m c).mem WORD / 2 = expected ∧
                   (Machine.drainAll m c).mem WORD % 2 = 0
  · obtain ⟨hg, hb⟩ := hcond
    have := Nat.div_add_mod ((Machine.drainAll m c).mem WORD) 2
    simp [Word.encode]; omega
  · simp [hcond] at hok

/-- The CAS fails if `mem WORD` decodes to anything other than
    `{ gen := expected, lock := false }`. -/
theorem lockedCas_fails_if
    (m : Machine) (c : Core) (expected : Nat)
    (h : (Machine.drainAll m c).mem WORD ≠ Word.encode { gen := expected, lock := false }) :
    (Machine.lockedCas m c expected).2 = false := by
  cases hres : (Machine.lockedCas m c expected).2 with
  | false => rfl
  | true  =>
    have := lockedCas_success_word_eq m c expected hres
    exact (h this).elim

/-! ## §4 Generalized publication theorem

For a producer whose buffer ends in a release-store of `g` and contains
arbitrary prior payload-stores, draining the producer commits every
payload write AND installs the new gen at WORD.  A consumer with empty
buffer running `lockedCas g` then succeeds AND observes every payload
write at its last buffered value (for `l ≠ WORD`).
-/

/-- Auxiliary: if the buffer's last-write-to-l is `some v`, FIFO commit
    gives `mem l = v` after drainAll. -/
theorem publication_payload
    (m : Machine) (P : Core) (l : Loc) (v : Nat)
    (h : lastWriteTo (m.bufs P) l = some v) :
    (Machine.drainAll m P).mem l = v := by
  rw [drainAll_mem_eq, h]

/-- After `drainAll P` of a buffer whose last WORD-store is at `g`,
    `mem WORD = encode { gen := g, lock := false }`. -/
theorem publication_word
    (m : Machine) (P : Core) (g : Nat)
    (h : lastWriteTo (m.bufs P) WORD = some (Word.encode { gen := g, lock := false })) :
    (Machine.drainAll m P).mem WORD = Word.encode { gen := g, lock := false } := by
  rw [drainAll_mem_eq, h]

/-- The CAS preserves `mem l` for any `l ≠ WORD` (the locked CAS only
    touches WORD). -/
theorem lockedCas_mem_other
    (m : Machine) (c : Core) (expected : Nat) (l : Loc) (hl : l ≠ WORD) :
    (Machine.lockedCas m c expected).1.mem l = (Machine.drainAll m c).mem l := by
  unfold Machine.lockedCas
  simp [Machine.setSaw, Machine.setMem]
  split <;> simp [hl]

/-- The full publication theorem.  After producer drains and consumer
    CAS-succeeds at `g`, every payload location `l ≠ WORD` reflects the
    producer's last buffered write to `l`. -/
theorem publication
    (m : Machine) (P C : Core) (g : Nat) (l : Loc) (v : Nat)
    (hPC : P ≠ C)
    (hl : l ≠ WORD)
    (hC : m.bufs C = [])
    (hWord : lastWriteTo (m.bufs P) WORD = some (Word.encode { gen := g, lock := false }))
    (hPay : lastWriteTo (m.bufs P) l = some v) :
    let m₁ := Machine.drainAll m P
    let r  := Machine.lockedCas m₁ C g
    r.2 = true ∧
    r.1.mem l = v := by
  intro m₁ r
  -- After producer drainAll: WORD = encode {g,false}, l = v.
  have hWord1 : m₁.mem WORD = Word.encode { gen := g, lock := false } :=
    publication_word m P g hWord
  have hPay1 : m₁.mem l = v := publication_payload m P l v hPay
  -- Consumer's buffer is still empty after producer drained.
  have hC1 : m₁.bufs C = [] := by
    show (Machine.drainAll m P).bufs C = []
    rw [drainAll_buf_other m P C hPC]; exact hC
  -- Consumer's drainAll is a no-op.
  have hDrainC : Machine.drainAll m₁ C = m₁ := by
    show Machine.drainAll m₁ C = m₁
    unfold Machine.drainAll
    rw [hC1]; rfl
  refine ⟨?_, ?_⟩
  · -- CAS succeeds because mem WORD has the canonical encoding.
    show (Machine.lockedCas m₁ C g).2 = true
    unfold Machine.lockedCas
    rw [hDrainC]
    simp [Word.casLockWithGen, Word.decode, hWord1, Word.encode]
  · -- CAS preserves mem l for l ≠ WORD; that's hPay1.
    show (Machine.lockedCas m₁ C g).1.mem l = v
    rw [lockedCas_mem_other m₁ C g l hl, hDrainC]
    exact hPay1

/-! ## §5 Stale rejection in two windows

Two reasons a stale `lockedCas C expected` fails:

  (a) `mem WORD` after `drainAll C` shows the lock-bit set:
      `(decode (mem WORD)).lock = true`.  CAS rejects on lock-bit.
  (b) `mem WORD` after `drainAll C` shows a different gen:
      `(decode (mem WORD)).gen ≠ expected`.  CAS rejects on gen.

These are independently proved; the destroy-window theorem (§6) is a
case-split that reduces to one of them depending on whether the
producer's setGenRelease has drained.
-/

/-- (a) Lock-bit window: if `mem WORD` decodes to `lock = true`, the
    consumer CAS fails regardless of the gen. -/
theorem stale_rejected_locked
    (m : Machine) (c : Core) (expected : Nat)
    (hC : m.bufs c = [])
    (hLocked : m.mem WORD % 2 = 1) :
    (Machine.lockedCas m c expected).2 = false := by
  have hDrain : Machine.drainAll m c = m := by
    unfold Machine.drainAll
    rw [hC]; rfl
  apply lockedCas_fails_if
  rw [hDrain]
  intro heq
  -- encode { gen, lock := false } has even value, but mem WORD is odd.
  rw [heq] at hLocked
  simp [Word.encode] at hLocked

/-- (b) Gen-mismatch window: if `mem WORD` decodes to gen ≠ expected,
    the CAS fails. -/
theorem stale_rejected_gen
    (m : Machine) (c : Core) (expected : Nat)
    (hC : m.bufs c = [])
    (hGenMismatch : m.mem WORD / 2 ≠ expected) :
    (Machine.lockedCas m c expected).2 = false := by
  have hDrain : Machine.drainAll m c = m := by
    unfold Machine.drainAll
    rw [hC]; rfl
  apply lockedCas_fails_if
  rw [hDrain]
  intro heq
  rw [heq] at hGenMismatch
  simp [Word.encode] at hGenMismatch

/-! ## §6 Destroy-window safety

A producer holding the slot's lock at `expected` (so `mem WORD = encode
{ gen := expected, lock := true }`) issues a buffered
`setGenRelease(expected+1)`.  Until that buffered store drains, every
other core's stale CAS at `expected` fails on the lock-bit (case a);
once it drains, it fails on the gen-mismatch (case b).  Throughout the
window, no stale CAS succeeds.
-/

/-- Pre-drain: producer holds the lock and has buffered the gen-bump,
    but it hasn't drained yet.  `mem WORD` still shows the locked old
    state.  Any other core's CAS at `expected` fails on the lock-bit. -/
theorem destroy_window_pre_drain
    (m : Machine) (P C : Core) (expected : Nat)
    (hPC : P ≠ C)
    (hC : m.bufs C = [])
    (hLocked : m.mem WORD = Word.encode { gen := expected, lock := true }) :
    (Machine.lockedCas m C expected).2 = false := by
  apply stale_rejected_locked m C expected hC
  rw [hLocked]
  simp [Word.encode]

/-- Post-drain: the producer's setGenRelease(expected+1) has drained;
    `mem WORD` now decodes to gen = expected+1.  Stale CAS at expected
    fails on the gen-mismatch. -/
theorem destroy_window_post_drain
    (m : Machine) (C : Core) (expected : Nat)
    (hC : m.bufs C = [])
    (hPostDrain : m.mem WORD = Word.encode { gen := expected + 1, lock := false }) :
    (Machine.lockedCas m C expected).2 = false := by
  apply stale_rejected_gen m C expected hC
  rw [hPostDrain]
  simp [Word.encode]

/-- The destroy-window safety theorem.  Starting from a state where the
    producer holds the lock at `expected` and has buffered exactly one
    setGenRelease(expected+1) at the tail of its buffer, every reachable
    intermediate state (any number of `drainOne P` steps applied to the
    producer) is safe against a consumer's stale CAS at `expected`. -/
theorem destroy_window_safe
    (m : Machine) (P C : Core) (expected : Nat) (k : Nat)
    (hPC : P ≠ C)
    (hC : m.bufs C = [])
    -- Producer holds the lock: mem WORD = encoded locked-old.
    (hLocked : m.mem WORD = Word.encode { gen := expected, lock := true })
    -- Producer's buffer is exactly the buffered gen-bump store.
    (hBufP : m.bufs P =
      [{ loc := WORD,
         val := Word.encode { gen := expected + 1, lock := false } }]) :
    -- Apply `k` drainOne P steps.
    let m_k := Nat.rec (motive := fun _ => Machine) m
                 (fun _ acc => Machine.drainOne acc P) k
    (Machine.lockedCas m_k C expected).2 = false := by
  intro m_k
  -- The producer's buffer has length 1.  After 0 drains: mem WORD =
  -- locked-old (pre-drain case).  After ≥1 drain: mem WORD = encoded
  -- gen+1 (post-drain case).
  cases k with
  | zero =>
    -- m_k = m
    have : m_k = m := rfl
    rw [this]
    -- C's buffer is still empty, mem WORD still locked.
    exact destroy_window_pre_drain m P C expected hPC hC hLocked
  | succ k' =>
    -- After at least one drainOne P, the buffer's single entry has
    -- committed and mem WORD is now encode { gen+1, false }.
    -- After 1 drain, the buffer is empty; subsequent drains are no-ops.
    -- We only need: mem WORD = encode {gen+1, false} AND m_k.bufs C = [].
    have hMemSucc : (Machine.drainOne m P).mem WORD =
        Word.encode { gen := expected + 1, lock := false } := by
      apply drainOne_mem_head m P
        { loc := WORD,
          val := Word.encode { gen := expected + 1, lock := false } }
        []
        hBufP
    have hBufSucc : (Machine.drainOne m P).bufs P = [] :=
      drainOne_buf_self m P _ [] hBufP
    have hC_succ : (Machine.drainOne m P).bufs C = m.bufs C :=
      drainOne_buf_other m P C hPC
    -- For any n ≥ 1, iterating drainOne P starting from `m` n times
    -- gives `drainOne m P` (the first iteration empties the buffer;
    -- subsequent iterations are no-ops).
    have hIter :
        ∀ n, Nat.rec (motive := fun _ => Machine) m
              (fun _ acc => Machine.drainOne acc P) (n + 1) =
             Machine.drainOne m P := by
      intro n
      induction n with
      | zero => rfl
      | succ n ih =>
        -- Goal: drainOne (Nat.rec m … (n+1)) P = drainOne m P
        -- Use ih to rewrite the inner Nat.rec.
        show Machine.drainOne
                (Nat.rec (motive := fun _ => Machine) m
                  (fun _ acc => Machine.drainOne acc P) (n + 1))
                P = Machine.drainOne m P
        rw [ih]
        exact drainOne_empty_buf (Machine.drainOne m P) P hBufSucc
    have hm_k : m_k = Machine.drainOne m P := hIter k'
    rw [hm_k]
    apply destroy_window_post_drain (Machine.drainOne m P) C expected
    · rw [hC_succ]; exact hC
    · exact hMemSucc

end TSO
end SlabProof
