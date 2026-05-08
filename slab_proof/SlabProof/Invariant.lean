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
      simp [Machine.setSaw, Machine.setMem]
    have hStateBufs : (Machine.lockedCas m c expected).1.bufs =
                        (Machine.drainAll m c).bufs := by
      unfold Machine.lockedCas
      simp only [hPre, Word.decode_encode, Word.casLockWithGen]
      simp [Machine.setSaw, Machine.setMem]
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
      simp [Machine.setSaw, Machine.setMem] at *
      split at hFail <;> simp_all
    have hStateBufs : (Machine.lockedCas m c expected).1.bufs =
                       (Machine.drainAll m c).bufs := by
      unfold Machine.lockedCas at hFail ⊢
      simp [Machine.setSaw, Machine.setMem] at *
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

end Invariant
end SlabProof
