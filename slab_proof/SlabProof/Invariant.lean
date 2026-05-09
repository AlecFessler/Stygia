/-
SlabProof.Invariant
===================

Real per-action induction over the reaper-phase invariant.

Replaces the round-3 vacuous `WordWellFormed_universal` with a
substantive inductive proof.  Starting from any `InReaperPhase`
machine state and applying any sequence of reaper-respecting
actions yields a state that is still in the reaper phase — and a
stale CAS at the original gen fails throughout.

`ReaperAction g P` constrains the trace to the actions a real
destroy + realloc cycle can issue:
  * `drain c`           — any core may drain its own buffer.
  * `payloadStore c l v` with `l ≠ WORD` — any core writes payload bytes.
  * `releaseSetGen P g₁` with `g₁ ∈ {g+1, g+2}` — only the producer
                             writes to WORD: the destroy gen-bump
                             (g+1) or the realloc-publish (g+2).
  * `lockedCasWord c e` — any core may attempt a locked CAS at any
                             expected.  Success is gated by the model.

`unlockWord` is excluded — `secure_slab.zig:609-642` shows the destroy
path uses `setGenRelease` for the gen-flip, never a separate unlock.
-/
import SlabProof.TSO
import SlabProof.Concurrent
import SlabProof.SlabRef
import SlabProof.Reaper

namespace SlabProof
namespace Invariant

open TSO Reaper

/-! ## §1 The reaper-action grammar -/

inductive ReaperAction (g : Nat) (P : Core) : Action → Prop where
  | drain         (c : Core) : ReaperAction g P (.drain c)
  | payloadStore  (c : Core) (l : Loc) (v : Nat) (hl : l ≠ WORD) :
      ReaperAction g P (.payloadStore c l v)
  | releaseSetGen_g1 : ReaperAction g P (.releaseSetGen P (g + 1))
  | releaseSetGen_g2 : ReaperAction g P (.releaseSetGen P (g + 2))
  | lockedCasWord (c : Core) (e : Nat) : ReaperAction g P (.lockedCasWord c e)

/-! ## §2 Per-action preservation -/

/-- `drainOne c` preserves `InReaperPhase g P`. -/
theorem drainOne_preserves
    (g : Nat) (P c : Core) (m : Machine)
    (hPhase : InReaperPhase g P m) :
    InReaperPhase g P (Machine.drainOne m c) := by
  obtain ⟨hMem, hBufP, hOther⟩ := hPhase
  cases hBuf : m.bufs c with
  | nil =>
    have hId : Machine.drainOne m c = m := TSO.drainOne_empty_buf m c hBuf
    rw [hId]; exact ⟨hMem, hBufP, hOther⟩
  | cons e rest =>
    -- Prove the three components separately.
    have hMem' : MemReaperValid g (Machine.drainOne m c) := by
      unfold MemReaperValid
      by_cases hEloc : e.loc = WORD
      · -- WORD-targeted commit; c must be P, and val is reaper-valid.
        have hcP : c = P := by
          by_cases h : c = P
          · exact h
          · exfalso
            apply hOther c h e _ hEloc
            rw [hBuf]; exact List.mem_cons_self
        subst hcP
        have hval := hBufP e (by rw [hBuf]; exact List.mem_cons_self) hEloc
        have hMemNew : (Machine.drainOne m c).mem WORD = e.val := by
          have := TSO.drainOne_mem_head m c e rest hBuf
          rw [hEloc] at this
          exact this
        rw [hMemNew]
        rcases hval with h1 | h2
        · right; left; exact h1
        · right; right; right; left; exact h2
      · have hUnch : (Machine.drainOne m c).mem WORD = m.mem WORD := by
          have hne : (WORD : Loc) ≠ e.loc := fun heq => hEloc heq.symm
          exact TSO.drainOne_mem_other m c e rest WORD hBuf hne
        rw [hUnch]; exact hMem
    have hBufP' : BufWordReaperValid g (Machine.drainOne m c) P := by
      unfold BufWordReaperValid
      by_cases hcP : c = P
      · subst hcP
        have hP_new : (Machine.drainOne m c).bufs c = rest :=
          TSO.drainOne_buf_self m c e rest hBuf
        intro e' he' hloc
        rw [hP_new] at he'
        apply hBufP e' _ hloc
        rw [hBuf]; exact List.mem_cons_of_mem _ he'
      · have hUnch : (Machine.drainOne m c).bufs P = m.bufs P :=
          TSO.drainOne_buf_other m c P hcP
        rw [hUnch]; exact hBufP
    have hOther' : OtherCoresNoWord P (Machine.drainOne m c) := by
      unfold OtherCoresNoWord
      intro c' hc'P e' he' hEloc'
      by_cases hcEq : c' = c
      · subst hcEq
        have hP_new : (Machine.drainOne m c').bufs c' = rest := by
          have := TSO.drainOne_buf_self m c' e rest
          exact this hBuf
        rw [hP_new] at he'
        -- e' is in rest, which is a subset of e :: rest = m.bufs c'.
        apply hOther c' hc'P e' _ hEloc'
        rw [hBuf]; exact List.mem_cons_of_mem e he'
      · have hUnch : (Machine.drainOne m c).bufs c' = m.bufs c' :=
          TSO.drainOne_buf_other m c c' (fun h => hcEq h.symm)
        rw [hUnch] at he'
        exact hOther c' hc'P e' he' hEloc'
    exact ⟨hMem', hBufP', hOther'⟩

/-- `drainAll c` preserves the invariant by iterating `drainOne`. -/
theorem drainAll_preserves
    (g : Nat) (P c : Core) (m : Machine)
    (hPhase : InReaperPhase g P m) :
    InReaperPhase g P (Machine.drainAll m c) := by
  unfold Machine.drainAll
  generalize hbuf : m.bufs c = bs
  induction bs generalizing m with
  | nil =>
    simp; exact hPhase
  | cons e rest ih =>
    simp [List.foldl]
    have hbuf' : (Machine.drainOne m c).bufs c = rest :=
      TSO.drainOne_buf_self m c e rest hbuf
    apply ih
    · exact drainOne_preserves g P c m hPhase
    · exact hbuf'

/-- `payloadStore c l v` with `l ≠ WORD` preserves the invariant. -/
theorem payloadStore_preserves
    (g : Nat) (P c : Core) (l : Loc) (v : Nat) (m : Machine)
    (hl : l ≠ WORD)
    (hPhase : InReaperPhase g P m) :
    InReaperPhase g P (Machine.payloadStore m c l v) := by
  obtain ⟨hMem, hBufP, hOther⟩ := hPhase
  refine ⟨hMem, ?_, ?_⟩
  · -- bufs P: unchanged if c ≠ P, else gains non-WORD entry.
    intro e' he' hloc
    by_cases hcP : c = P
    · subst hcP
      simp [Machine.payloadStore, Machine.bufStore, Machine.setBuf] at he'
      rcases he' with he' | he'
      · exact hBufP e' he' hloc
      · rw [he'] at hloc; exact (hl hloc).elim
    · simp [Machine.payloadStore, Machine.bufStore, Machine.setBuf,
            Ne.symm hcP] at he'
      exact hBufP e' he' hloc
  · intro c' hc'P e' he' hEloc'
    by_cases hcEq : c' = c
    · subst hcEq
      simp [Machine.payloadStore, Machine.bufStore, Machine.setBuf] at he'
      rcases he' with he' | he'
      · exact hOther c' hc'P e' he' hEloc'
      · rw [he'] at hEloc'; exact (hl hEloc').elim
    · -- c' ≠ c so payloadStore on c doesn't touch bufs c'.
      simp only [Machine.payloadStore, Machine.bufStore, Machine.setBuf,
                 if_neg (fun h : c' = c => hcEq h)] at he'
      exact hOther c' hc'P e' he' hEloc'

/-- `releaseSetGen P (g+1)` preserves the invariant. -/
theorem releaseSetGen_g1_preserves
    (g : Nat) (P : Core) (m : Machine)
    (hPhase : InReaperPhase g P m) :
    InReaperPhase g P (Machine.releaseSetGen m P (g + 1)) := by
  obtain ⟨hMem, hBufP, hOther⟩ := hPhase
  refine ⟨hMem, ?_, ?_⟩
  · intro e' he' hloc
    simp [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf] at he'
    rcases he' with he' | he'
    · exact hBufP e' he' hloc
    · rw [he']; left; rfl
  · intro c' hc'P e' he' hEloc'
    -- bufs c' for c' ≠ P unchanged by releaseSetGen P.
    simp only [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf,
               if_neg (fun h : c' = P => hc'P h)] at he'
    exact hOther c' hc'P e' he' hEloc'

/-- `releaseSetGen P (g+2)` preserves the invariant. -/
theorem releaseSetGen_g2_preserves
    (g : Nat) (P : Core) (m : Machine)
    (hPhase : InReaperPhase g P m) :
    InReaperPhase g P (Machine.releaseSetGen m P (g + 2)) := by
  obtain ⟨hMem, hBufP, hOther⟩ := hPhase
  refine ⟨hMem, ?_, ?_⟩
  · intro e' he' hloc
    simp [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf] at he'
    rcases he' with he' | he'
    · exact hBufP e' he' hloc
    · rw [he']; right; rfl
  · intro c' hc'P e' he' hEloc'
    simp only [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf,
               if_neg (fun h : c' = P => hc'P h)] at he'
    exact hOther c' hc'P e' he' hEloc'

/-- `lockedCasWord c expected` preserves the invariant.

    The CAS first drains c's own buffer (preserved by `drainAll_preserves`),
    then performs the atomic test+swap.  Success requires post-drain mem
    WORD = encode {expected, false}; combined with `MemReaperValid`,
    that constrains expected ∈ {g+1, g+2}.  The new mem WORD is then
    encode {expected, true}, still reaper-valid. -/
theorem lockedCas_preserves
    (g : Nat) (P c : Core) (expected : Nat) (m : Machine)
    (hPhase : InReaperPhase g P m) :
    InReaperPhase g P (Machine.lockedCas m c expected).1 := by
  -- Step 1: drainAll m c is in reaper phase.
  have hPhase' : InReaperPhase g P (Machine.drainAll m c) :=
    drainAll_preserves g P c m hPhase
  obtain ⟨hMem', hBufP', hOther'⟩ := hPhase'
  -- Step 2: derive the post-CAS state's components from cases on
  -- whether the CAS observed a match.
  by_cases hok : (Machine.lockedCas m c expected).2 = true
  · -- Success: by `lockedCas_success_word_eq`, pre-CAS mem WORD = encode {expected, false}.
    have hPre := TSO.lockedCas_success_word_eq m c expected hok
    -- hMem' + hPre force expected ∈ {g+1, g+2}.
    have hExp : expected = g + 1 ∨ expected = g + 2 := by
      rcases hMem' with h | h | h | h | h
      all_goals
        rw [hPre] at h
        simp [Word.encode] at h
      · omega
      · left; omega
      · omega
      · right; omega
      · omega
    -- Compute post-CAS state via direct unfolding.
    have hStateMem : (Machine.lockedCas m c expected).1.mem WORD =
                       Word.encode { gen := expected, lock := true } := by
      unfold Machine.lockedCas
      simp only [hPre, Word.decode_encode, Word.casLockWithGen]
      simp [Machine.setMem]
    have hStateBufs : (Machine.lockedCas m c expected).1.bufs =
                        (Machine.drainAll m c).bufs := by
      unfold Machine.lockedCas
      simp only [hPre, Word.decode_encode, Word.casLockWithGen]
      simp [Machine.setMem]
    refine ⟨?_, ?_, ?_⟩
    · -- mem WORD post-CAS is encode {expected, true}.
      unfold MemReaperValid
      rw [hStateMem]
      rcases hExp with h | h
      · subst h; right; right; left; rfl
      · subst h; right; right; right; right; rfl
    · -- bufs P unchanged.
      unfold BufWordReaperValid
      intro e' he' hloc
      rw [hStateBufs] at he'
      exact hBufP' e' he' hloc
    · -- bufs c' for c' ≠ P unchanged.
      unfold OtherCoresNoWord
      intro c' hc'P e' he' hEloc'
      rw [hStateBufs] at he'
      exact hOther' c' hc'P e' he' hEloc'
  · -- Failure: post-state has same mem and bufs as drainAll.
    have hFail : (Machine.lockedCas m c expected).2 = false := by
      cases hres : (Machine.lockedCas m c expected).2 with
      | true  => exact (hok hres).elim
      | false => rfl
    have hStateMem : (Machine.lockedCas m c expected).1.mem =
                       (Machine.drainAll m c).mem := by
      unfold Machine.lockedCas at hFail ⊢
      simp [Machine.setMem] at *
      split at hFail <;> simp_all
    have hStateBufs : (Machine.lockedCas m c expected).1.bufs =
                       (Machine.drainAll m c).bufs := by
      unfold Machine.lockedCas at hFail ⊢
      simp [Machine.setMem] at *
      split at hFail <;> simp_all
    refine ⟨?_, ?_, ?_⟩
    · unfold MemReaperValid
      rw [hStateMem]
      exact hMem'
    · unfold BufWordReaperValid
      intro e' he' hloc
      rw [hStateBufs] at he'
      exact hBufP' e' he' hloc
    · unfold OtherCoresNoWord
      intro c' hc'P e' he' hEloc'
      rw [hStateBufs] at he'
      exact hOther' c' hc'P e' he' hEloc'

/-! ## §3 The composed step preservation -/

theorem step_preserves
    (g : Nat) (P : Core) (m : Machine) (a : Action)
    (hPhase : InReaperPhase g P m)
    (hAct : ReaperAction g P a) :
    InReaperPhase g P (TSO.step m a) := by
  cases hAct with
  | drain c               => exact drainOne_preserves g P c m hPhase
  | payloadStore c l v hl => exact payloadStore_preserves g P c l v m hl hPhase
  | releaseSetGen_g1      => exact releaseSetGen_g1_preserves g P m hPhase
  | releaseSetGen_g2      => exact releaseSetGen_g2_preserves g P m hPhase
  | lockedCasWord c e     => exact lockedCas_preserves g P c e m hPhase

/-! ## §4 The run-level theorem -/

theorem run_preserves
    (g : Nat) (P : Core) (m : Machine) (actions : List Action)
    (hPhase : InReaperPhase g P m)
    (hAll : ∀ a ∈ actions, ReaperAction g P a) :
    InReaperPhase g P (TSO.run m actions) := by
  induction actions generalizing m with
  | nil => exact hPhase
  | cons a as ih =>
    have h1 : ReaperAction g P a := hAll a (List.mem_cons_self)
    have h2 : ∀ b ∈ as, ReaperAction g P b :=
      fun b hb => hAll b (List.mem_cons_of_mem _ hb)
    have hStep := step_preserves g P m a hPhase h1
    exact ih (TSO.step m a) hStep h2

/-! ## §5 The composed UAF safety theorem

This is the headline result.  Starting from any reaper-phase machine
state and any sequence of reaper-respecting actions, no consumer's
stale `SlabRef.lock` at the original gen `g` can succeed — proved by
real induction on the action list, not by single-state delegation.
-/

theorem run_reaper_uaf_safe
    (g : Nat) (P C : Core) (m : Machine) (actions : List Action)
    (ref : SlabRef.Ref)
    (hPhase : InReaperPhase g P m)
    (hAll : ∀ a ∈ actions, ReaperAction g P a)
    (hC : (TSO.run m actions).bufs C = [])
    (hRef : ref.gen = g) :
    (SlabRef.lock (TSO.run m actions) C ref).2 = false :=
  inReaperPhase_implies_stale_lock_fails g P C
    (TSO.run m actions) ref
    (run_preserves g P m actions hPhase hAll) hC hRef

/-! ## §6 Entry lemma — derive `InReaperPhase` from real operations

The preservation theorems above show the invariant *stays* true; the
entry lemma below shows it *becomes* true.  Starting from a "live
unlocked" state at gen `g`, after the destroy-side core `P`

  (a) successfully executes `lockedCasWord g`  (acquires the slot's lock), and
  (b) issues the buffered `releaseSetGen P (g+1)` (the gen-bump store),

the resulting machine satisfies `InReaperPhase g P`.  Combined with
`run_reaper_uaf_safe`, this gives an end-to-end UAF safety story:

  pre-state (live, gen = g, no buffered WORD writes from any core)
    →  P does the destroy-acquire CAS + gen-bump enqueue
    →  reaper-phase invariant established
    →  any sequence of reaper-grammar actions
    →  no stale ref at gen g succeeds in `SlabRef.lock`.

The entry preconditions match what the real Zig destroy paths
(`destroy`, `destroyLocked`, `bumpDeadGenLocked`) start from: a slot
that's currently live + unlocked at the caller's snapshotted gen, with
no other in-flight WORD-store. -/

theorem enters_reaper_phase
    (g : Nat) (P : Core) (m : Machine)
    (hMem : m.mem WORD = Word.encode { gen := g, lock := false })
    (hBufP : ∀ e ∈ m.bufs P, e.loc ≠ WORD)
    (hOther : OtherCoresNoWord P m) :
    (Machine.lockedCas m P g).2 = true ∧
    InReaperPhase g P
      (Machine.releaseSetGen (Machine.lockedCas m P g).1 P (g + 1)) := by
  -- Producer's drain leaves `mem WORD` intact: there are no buffered
  -- WORD-stores in P's buffer.
  have hPostDrainWord : (Machine.drainAll m P).mem WORD =
      Word.encode { gen := g, lock := false } := by
    rw [TSO.drainAll_mem_unchanged_no_writes m P WORD hBufP]; exact hMem
  -- The CAS at expected = g succeeds against post-drain `(g, false)`.
  have hCasOk : (Machine.lockedCas m P g).2 = true := by
    unfold Machine.lockedCas
    simp [hPostDrainWord, Word.decode_encode, Word.casLockWithGen]
  -- Post-CAS state: mem WORD = encode (g, true); bufs match drainAll's bufs.
  have hM1Mem : (Machine.lockedCas m P g).1.mem WORD =
      Word.encode { gen := g, lock := true } := by
    unfold Machine.lockedCas
    simp only [hPostDrainWord, Word.decode_encode, Word.casLockWithGen]
    simp [Machine.setMem]
  have hStateBufs : (Machine.lockedCas m P g).1.bufs =
                    (Machine.drainAll m P).bufs := by
    unfold Machine.lockedCas
    simp only [hPostDrainWord, Word.decode_encode, Word.casLockWithGen]
    simp [Machine.setMem]
  have hM1BufP : (Machine.lockedCas m P g).1.bufs P = [] := by
    rw [hStateBufs]; exact TSO.drainAll_buf_empty m P
  have hM1BufOther : ∀ c, c ≠ P →
      (Machine.lockedCas m P g).1.bufs c = m.bufs c := by
    intro c hc
    rw [hStateBufs]
    exact TSO.drainAll_buf_other m P c (fun h => hc h.symm)
  -- m2 = releaseSetGen of post-CAS state. mem WORD untouched (buffered).
  have hM2Mem :
      (Machine.releaseSetGen (Machine.lockedCas m P g).1 P (g + 1)).mem WORD =
        Word.encode { gen := g, lock := true } := by
    simp [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf]
    exact hM1Mem
  have hM2BufP :
      (Machine.releaseSetGen (Machine.lockedCas m P g).1 P (g + 1)).bufs P =
        [{ loc := WORD,
           val := Word.encode { gen := g + 1, lock := false } }] := by
    simp [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf]
    rw [hM1BufP]
  have hM2BufOther : ∀ c, c ≠ P →
      (Machine.releaseSetGen (Machine.lockedCas m P g).1 P (g + 1)).bufs c =
        m.bufs c := by
    intro c hc
    have hcne : c ≠ P := hc
    simp [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf, hcne]
    exact hM1BufOther c hc
  refine ⟨hCasOk, ?_, ?_, ?_⟩
  · -- MemReaperValid g m2 — first disjunct (locked old gen).
    unfold MemReaperValid
    rw [hM2Mem]; left; rfl
  · -- BufWordReaperValid g m2 P — only entry is the buffered (g+1, false).
    unfold BufWordReaperValid
    intro e he hloc
    rw [hM2BufP] at he
    simp at he
    rw [he]
    left; rfl
  · -- OtherCoresNoWord P m2 — other cores' bufs unchanged from m.
    unfold OtherCoresNoWord
    intro c hc e he hEloc
    rw [hM2BufOther c hc] at he
    exact hOther c hc e he hEloc

/-! ## §7 End-to-end UAF safety theorem

Compose the entry lemma with the run-induction.  Any consumer with a
stale ref at `ref.gen = g` cannot acquire the slot, no matter what
sequence of reaper-respecting actions follows the destroy-side
acquire + gen-bump. -/

theorem end_to_end_uaf_safe
    (g : Nat) (P C : Core) (m : Machine) (actions : List Action)
    (ref : SlabRef.Ref)
    (hMem : m.mem WORD = Word.encode { gen := g, lock := false })
    (hBufP : ∀ e ∈ m.bufs P, e.loc ≠ WORD)
    (hOther : OtherCoresNoWord P m)
    (hAll : ∀ a ∈ actions, ReaperAction g P a)
    (hC : (TSO.run
            (Machine.releaseSetGen (Machine.lockedCas m P g).1 P (g + 1))
            actions).bufs C = [])
    (hRef : ref.gen = g) :
    (Machine.lockedCas m P g).2 = true ∧
    (SlabRef.lock
      (TSO.run
        (Machine.releaseSetGen (Machine.lockedCas m P g).1 P (g + 1))
        actions) C ref).2 = false := by
  obtain ⟨hCasOk, hPhase⟩ := enters_reaper_phase g P m hMem hBufP hOther
  exact ⟨hCasOk, run_reaper_uaf_safe g P C _ actions ref hPhase hAll hC hRef⟩

/-! ## §8 Durable cross-phase safety

The reaper-phase invariant in §1-§7 is per-phase: it covers a single
destroy → realloc cycle and excludes downstream reader unlocks (the
grammar's `OtherCoresNoWord P` is broken the moment any reader other
than P writes to WORD).

Chained reaper phases — e.g. destroy at gen `g`, realloc to `g+2`,
some new reader acquires + releases, then a future destroy at `g+2`
— need a *weaker* invariant that does not pin a single producer.
The right invariant is monotonic:

  every value visible at WORD (in memory, or in any core's buffered
  store to WORD) decodes to a gen strictly greater than the original
  ref's gen.

Once the gen has advanced past the ref's snapshot, no sequence of
later actions can bring it back: every WORD-write — destroy bumps,
realloc publishes, reader unlocks — preserves the gen-floor.  The
ref is durably stale.

This subsumes all of §1-§7 for a ref at `g` whose phase has fully
retired (`mem WORD` now decodes to gen ≥ g+1 with no buffered store
< g+1).  It is the load-bearing claim for "no use-after-free *ever*"
under arbitrary downstream concurrency. -/

/-- Every value reachable via `mem WORD` or a buffered-WORD store
    decodes to a gen strictly greater than `g`.  This is the gen
    floor that, once crossed, can never be uncrossed by the action
    grammar below (`DurableAction`). -/
def WordGenAbove (g : Nat) (m : Machine) : Prop :=
  m.mem WORD / 2 > g ∧
  ∀ c (e : TSO.BufEntry), e ∈ m.bufs c → e.loc = WORD → e.val / 2 > g

/-- Action grammar that preserves `WordGenAbove g`.  No producer
    pinned: any core may issue any of these.  The crucial restriction
    is that any WORD-store carries a value whose decoded gen exceeds
    `g`.  Locked CASes are free — their precondition (mem WORD's gen
    matches expected, which already exceeds `g`) ensures the post-
    state's gen also exceeds `g`. -/
inductive DurableAction (g : Nat) : Action → Prop where
  | drain         (c : Core) : DurableAction g (.drain c)
  | payloadStore  (c : Core) (l : Loc) (v : Nat) (hl : l ≠ WORD) :
      DurableAction g (.payloadStore c l v)
  | releaseSetGen (c : Core) (g' : Nat) (h : g' > g) :
      DurableAction g (.releaseSetGen c g')
  | unlockWord    (c : Core) (g' : Nat) (h : g' > g) :
      DurableAction g (.unlockWord c g')
  | lockedCasWord (c : Core) (e : Nat) : DurableAction g (.lockedCasWord c e)

/-! ### §8.1 Per-action preservation -/

theorem durable_drainOne_preserves
    (g : Nat) (c : Core) (m : Machine)
    (h : WordGenAbove g m) :
    WordGenAbove g (Machine.drainOne m c) := by
  obtain ⟨hMem, hBufs⟩ := h
  cases hBuf : m.bufs c with
  | nil =>
    have hId : Machine.drainOne m c = m := TSO.drainOne_empty_buf m c hBuf
    rw [hId]; exact ⟨hMem, hBufs⟩
  | cons e rest =>
    refine ⟨?_, ?_⟩
    · -- mem WORD post-drainOne: either e.loc = WORD (committed e.val), or unchanged.
      by_cases hEloc : e.loc = WORD
      · have hMemNew : (Machine.drainOne m c).mem WORD = e.val := by
          have := TSO.drainOne_mem_head m c e rest hBuf
          rw [hEloc] at this; exact this
        rw [hMemNew]
        exact hBufs c e (by rw [hBuf]; exact List.mem_cons_self) hEloc
      · have hne : (WORD : Loc) ≠ e.loc := fun heq => hEloc heq.symm
        rw [TSO.drainOne_mem_other m c e rest WORD hBuf hne]
        exact hMem
    · intro c' e' he' hloc
      by_cases hcEq : c' = c
      · subst hcEq
        have hP_new : (Machine.drainOne m c').bufs c' = rest :=
          TSO.drainOne_buf_self m c' e rest hBuf
        rw [hP_new] at he'
        exact hBufs c' e'
          (by rw [hBuf]; exact List.mem_cons_of_mem _ he') hloc
      · rw [TSO.drainOne_buf_other m c c' (fun h => hcEq h.symm)] at he'
        exact hBufs c' e' he' hloc

theorem durable_drainAll_preserves
    (g : Nat) (c : Core) (m : Machine)
    (h : WordGenAbove g m) :
    WordGenAbove g (Machine.drainAll m c) := by
  unfold Machine.drainAll
  generalize hbuf : m.bufs c = bs
  induction bs generalizing m with
  | nil => simp; exact h
  | cons e rest ih =>
    simp [List.foldl]
    have hbuf' : (Machine.drainOne m c).bufs c = rest :=
      TSO.drainOne_buf_self m c e rest hbuf
    apply ih
    · exact durable_drainOne_preserves g c m h
    · exact hbuf'

theorem durable_payloadStore_preserves
    (g : Nat) (c : Core) (l : Loc) (v : Nat) (m : Machine)
    (hl : l ≠ WORD)
    (h : WordGenAbove g m) :
    WordGenAbove g (Machine.payloadStore m c l v) := by
  obtain ⟨hMem, hBufs⟩ := h
  refine ⟨hMem, ?_⟩
  intro c' e' he' hloc
  by_cases hcEq : c' = c
  · subst hcEq
    simp [Machine.payloadStore, Machine.bufStore, Machine.setBuf] at he'
    rcases he' with he' | he'
    · exact hBufs c' e' he' hloc
    · rw [he'] at hloc; exact (hl hloc).elim
  · simp only [Machine.payloadStore, Machine.bufStore, Machine.setBuf,
               if_neg (fun h : c' = c => hcEq h)] at he'
    exact hBufs c' e' he' hloc

theorem durable_releaseSetGen_preserves
    (g : Nat) (c : Core) (g' : Nat) (m : Machine)
    (hgt : g' > g)
    (h : WordGenAbove g m) :
    WordGenAbove g (Machine.releaseSetGen m c g') := by
  obtain ⟨hMem, hBufs⟩ := h
  refine ⟨hMem, ?_⟩
  intro c' e' he' hloc
  by_cases hcEq : c' = c
  · subst hcEq
    simp [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf] at he'
    rcases he' with he' | he'
    · exact hBufs c' e' he' hloc
    · rw [he']
      simp [Word.encode]; omega
  · simp only [Machine.releaseSetGen, Machine.bufStore, Machine.setBuf,
               if_neg (fun h : c' = c => hcEq h)] at he'
    exact hBufs c' e' he' hloc

theorem durable_unlockWord_preserves
    (g : Nat) (c : Core) (g' : Nat) (m : Machine)
    (hgt : g' > g)
    (h : WordGenAbove g m) :
    WordGenAbove g (Machine.unlockWord m c g') := by
  obtain ⟨hMem, hBufs⟩ := h
  refine ⟨hMem, ?_⟩
  intro c' e' he' hloc
  by_cases hcEq : c' = c
  · subst hcEq
    simp [Machine.unlockWord, Machine.bufStore, Machine.setBuf] at he'
    rcases he' with he' | he'
    · exact hBufs c' e' he' hloc
    · rw [he']
      simp [Word.encode]; omega
  · simp only [Machine.unlockWord, Machine.bufStore, Machine.setBuf,
               if_neg (fun h : c' = c => hcEq h)] at he'
    exact hBufs c' e' he' hloc

theorem durable_lockedCas_preserves
    (g : Nat) (c : Core) (expected : Nat) (m : Machine)
    (h : WordGenAbove g m) :
    WordGenAbove g (Machine.lockedCas m c expected).1 := by
  -- Step 1: drainAll preserves the floor.
  have hDrain : WordGenAbove g (Machine.drainAll m c) :=
    durable_drainAll_preserves g c m h
  obtain ⟨hMemD, hBufsD⟩ := hDrain
  -- Step 2: case-split on success.
  by_cases hok : (Machine.lockedCas m c expected).2 = true
  · -- Success forces post-drain mem WORD = encode {expected, false},
    -- which means expected = (post-drain mem WORD)/2 > g.
    have hPre := TSO.lockedCas_success_word_eq m c expected hok
    have hExpGt : expected > g := by
      rw [hPre] at hMemD
      simp [Word.encode] at hMemD
      omega
    have hStateMem : (Machine.lockedCas m c expected).1.mem WORD =
                       Word.encode { gen := expected, lock := true } := by
      unfold Machine.lockedCas
      simp only [hPre, Word.decode_encode, Word.casLockWithGen]
      simp [Machine.setMem]
    have hStateBufs : (Machine.lockedCas m c expected).1.bufs =
                        (Machine.drainAll m c).bufs := by
      unfold Machine.lockedCas
      simp only [hPre, Word.decode_encode, Word.casLockWithGen]
      simp [Machine.setMem]
    refine ⟨?_, ?_⟩
    · rw [hStateMem]
      simp [Word.encode]; omega
    · intro c' e' he' hloc
      rw [hStateBufs] at he'
      exact hBufsD c' e' he' hloc
  · -- Failure: post-state has same mem and bufs as drainAll.
    have hFail : (Machine.lockedCas m c expected).2 = false := by
      cases hres : (Machine.lockedCas m c expected).2 with
      | true  => exact (hok hres).elim
      | false => rfl
    have hStateMem : (Machine.lockedCas m c expected).1.mem =
                       (Machine.drainAll m c).mem := by
      unfold Machine.lockedCas at hFail ⊢
      simp [Machine.setMem] at *
      split at hFail <;> simp_all
    have hStateBufs : (Machine.lockedCas m c expected).1.bufs =
                       (Machine.drainAll m c).bufs := by
      unfold Machine.lockedCas at hFail ⊢
      simp [Machine.setMem] at *
      split at hFail <;> simp_all
    refine ⟨?_, ?_⟩
    · rw [hStateMem]; exact hMemD
    · intro c' e' he' hloc
      rw [hStateBufs] at he'
      exact hBufsD c' e' he' hloc

/-! ### §8.2 Step + run preservation -/

theorem durable_step_preserves
    (g : Nat) (m : Machine) (a : Action)
    (h : WordGenAbove g m)
    (hAct : DurableAction g a) :
    WordGenAbove g (TSO.step m a) := by
  cases hAct with
  | drain c                  => exact durable_drainOne_preserves g c m h
  | payloadStore c l v hl    => exact durable_payloadStore_preserves g c l v m hl h
  | releaseSetGen c g' hgt   => exact durable_releaseSetGen_preserves g c g' m hgt h
  | unlockWord c g' hgt      => exact durable_unlockWord_preserves g c g' m hgt h
  | lockedCasWord c e        => exact durable_lockedCas_preserves g c e m h

theorem durable_run_preserves
    (g : Nat) (m : Machine) (actions : List Action)
    (h : WordGenAbove g m)
    (hAll : ∀ a ∈ actions, DurableAction g a) :
    WordGenAbove g (TSO.run m actions) := by
  induction actions generalizing m with
  | nil => exact h
  | cons a as ih =>
    have h1 : DurableAction g a := hAll a List.mem_cons_self
    have h2 : ∀ b ∈ as, DurableAction g b :=
      fun b hb => hAll b (List.mem_cons_of_mem _ hb)
    exact ih (TSO.step m a) (durable_step_preserves g m a h h1) h2

/-! ### §8.3 Headline durable UAF safety

If a ref's gen is `g` and the gen-floor `WordGenAbove g` holds, every
state along any sequence of `DurableAction g` actions rejects the
ref's lock — including the per-step "every intermediate state, not
just the last" universal claim that the per-phase theorem in §5
omits. -/

theorem durable_state_uaf_safe
    (g : Nat) (m : Machine) (c : Core) (ref : SlabRef.Ref)
    (h : WordGenAbove g m)
    (hC : m.bufs c = [])
    (hRef : ref.gen = g) :
    (SlabRef.lock m c ref).2 = false := by
  apply SlabRef.lock_fails_unless_canonical m c ref hC
  obtain ⟨hMem, _⟩ := h
  intro heq
  rw [heq, hRef] at hMem
  simp [Word.encode] at hMem

/-- Per-step durable safety: at *every* prefix of the action list,
    not just the final state, a stale ref at `ref.gen = g` cannot
    succeed. -/
theorem durable_run_uaf_safe
    (g : Nat) (m : Machine) (c : Core) (actions : List Action)
    (ref : SlabRef.Ref)
    (h : WordGenAbove g m)
    (hAll : ∀ a ∈ actions, DurableAction g a)
    (hC : (TSO.run m actions).bufs c = [])
    (hRef : ref.gen = g) :
    (SlabRef.lock (TSO.run m actions) c ref).2 = false :=
  durable_state_uaf_safe g (TSO.run m actions) c ref
    (durable_run_preserves g m actions h hAll) hC hRef

/-- Bridge from the per-phase invariant to the durable invariant.
    Once the producer's destroy gen-bump has globally retired and
    the slot's WORD now decodes to ≥ `g+1`, the durable invariant
    holds, and *any* downstream action grammar (including reader
    unlocks, future destroys at `g+2`, `g+4`, …) preserves it. -/
theorem reaper_phase_retired_implies_durable
    (g : Nat) (P : Core) (m : Machine)
    (hPhase : InReaperPhase g P m)
    (hRetired : m.mem WORD / 2 ≥ g + 1) :
    WordGenAbove g m := by
  obtain ⟨_, hBufP, hOther⟩ := hPhase
  refine ⟨by omega, ?_⟩
  intro c e he hloc
  -- Either c = P (use hBufP) or c ≠ P (use hOther — but then hOther
  -- says e.loc ≠ WORD, contradicting hloc).
  by_cases hcP : c = P
  · subst hcP
    rcases hBufP e he hloc with hv | hv
    · rw [hv]; simp [Word.encode]
    · rw [hv]; simp [Word.encode]
  · exact (hOther c hcP e he hloc).elim

/-! ## §9 Asm fast-path bridge: discharge `g' > g` from a bracketing CAS

`DurableAction.unlockWord c g'` carries the premise `g' > g` to model
the kernel's asm fast-path `andq $-2, _gen_lock(%base)` — a non-LOCK#
AND on x86, modelled here as a buffered release-store of the gen-bit-
cleared word.  `tools/check_gen_lock`'s asm pass verifies that every
such `andq` is *bracketed* by a prior `lock cmpxchgq` against the same
`_gen_lock`; the bracketing CAS's success establishes the gen, and
the andq preserves it while clearing the lock bit.

In real code, the `g'` carried by the andq is exactly the gen the
bracketing CAS observed.  Under the floor `WordGenAbove g`, the CAS's
success forces `expected > g` (post-self-drain `mem WORD / 2 = expected`,
and the floor says that quantity exceeds `g`).  The two lemmas below
mechanise this chain: users no longer need to thread the `g' > g`
obligation by hand. -/

/-- The bracketing-CAS-success lemma.  A successful `lockedCas` at
    `expected` against a state satisfying the floor `WordGenAbove g`
    implies `expected > g`.

    Discharges the `g' > g` premise of `DurableAction.unlockWord` for
    any asm-fast-path andq whose bracketing `lock cmpxchgq` succeeded
    under the floor — closes the prior informality where the chain had
    to be threaded by the user. -/
theorem unlockWord_gen_above_of_successful_cas
    (g : Nat) (c : Core) (expected : Nat) (m : Machine)
    (h : WordGenAbove g m)
    (hCasOk : (Machine.lockedCas m c expected).2 = true) :
    expected > g := by
  have hPre := TSO.lockedCas_success_word_eq m c expected hCasOk
  have hDrain : WordGenAbove g (Machine.drainAll m c) :=
    durable_drainAll_preserves g c m h
  obtain ⟨hMemD, _⟩ := hDrain
  rw [hPre] at hMemD
  simp [Word.encode] at hMemD
  omega

/-- Constructor-form companion of `unlockWord_gen_above_of_successful_cas`.
    The asm fast-path's `unlockWord c expected` is admissible in
    `DurableAction g` when paired with a successful bracketing
    `lockedCas` at `expected` against a state satisfying the floor.
    Plug directly into `durable_run_preserves` / `durable_run_uaf_safe`
    via the action grammar's `unlockWord` constructor. -/
theorem durableAction_unlockWord_of_successful_cas
    (g : Nat) (c : Core) (expected : Nat) (m : Machine)
    (h : WordGenAbove g m)
    (hCasOk : (Machine.lockedCas m c expected).2 = true) :
    DurableAction g (.unlockWord c expected) :=
  DurableAction.unlockWord c expected
    (unlockWord_gen_above_of_successful_cas g c expected m h hCasOk)

end Invariant
end SlabProof
