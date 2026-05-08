/-
SlabProof — top-level safety theorem for Zag's GenLock + SecureSlab
====================================================================

Safety artifact for `kernel/memory/allocators/secure_slab.zig`.

Layered structure:

  Word.lean          — 64-bit gen+lock word, encode/decode, primitive ops.
  Sequential.lean    — single-thread state-machine + invariants (P3).
  TSO.lean           — operational TSO model: per-core FIFO store buffers,
                       buffered release-stores, locked-CAS = self-drain
                       + atomic test-and-swap.
  Concurrent.lean    — TSO drain mechanics, FIFO commit lemma,
                       publication, two stale-rejection windows,
                       destroy-window safety.
  SlabRef.lean       — handle-level lift: Ref := { gen : Nat },
                       SlabRef.lock = lockedCas, disjoint refs, UAF
                       prevention against retired destroys.
  Reaper.lean        — full destroy → zero → realloc cycle.  Defines
                       `InReaperPhase` as a non-trivial state predicate
                       and proves the four reaper-window states all
                       reject stale CASes.
  Invariant.lean     — *real per-action induction* over `InReaperPhase`.
                       Closes the prior reviewer's "vacuous run-invariant"
                       gap.  `step_preserves`, `run_preserves`, and the
                       composed `run_reaper_uaf_safe` quantify over
                       arbitrary action lists.
  MultiSlot.lean     — multi-slot generalization.  `lockedCasAt` is
                       parametric in word location; refs to different
                       slots reference disjoint memory.  Closes the
                       "single-slot conflates pointers" gap.
  Weak.lean          — `cmpxchgWeak` spurious-failure model.  Spurious
                       fail strictly more conservative than strong CAS;
                       all safety theorems transfer.

Build: `cd /home/alec/Zag/slab_proof && lake build`.

Reviewer items 1-3 (Core/Loc lift, buffered release, N-payload
publication) closed in v2.  Items 4 (run-invariant), 5 (SlabRef), 6
(reaper cycle) closed in v3.  v4 closes the framing-vs-substance gaps
the fresh-eyes reviewer flagged on v3:
  * Vacuous Invariant → real per-action induction over `InReaperPhase`.
  * Reaper state-disjunction → composed with run-induction.
  * Single-slot SlabRef → multi-slot generalization with disjointness.
  * cmpxchgWeak spurious failure → modeled and shown to preserve safety.
-/
import SlabProof.Basic
import SlabProof.Word
import SlabProof.Sequential
import SlabProof.TSO
import SlabProof.Concurrent
import SlabProof.SlabRef
import SlabProof.Reaper
import SlabProof.Invariant
import SlabProof.MultiSlot
import SlabProof.Weak

namespace SlabProof

-- ─── Sequential ─────────────────────────────────────────────────────
#check @lock_success_implies_lastSetGen

-- ─── TSO foundations ────────────────────────────────────────────────
#check @TSO.drainAll_mem_eq                      -- FIFO commit lemma
#check @TSO.lockedCas_success_word_eq
#check @TSO.lockedCas_fails_if

-- ─── TSO publication and stale rejection ────────────────────────────
#check @TSO.publication
#check @TSO.stale_rejected_locked
#check @TSO.stale_rejected_gen
#check @TSO.destroy_window_pre_drain
#check @TSO.destroy_window_post_drain
#check @TSO.destroy_window_safe

-- ─── SlabRef API (handle-level safety) ──────────────────────────────
#check @SlabRef.lock_eq_lockedCas
#check @SlabRef.lock_success_iff_word_matches
#check @SlabRef.disjoint_refs_at_most_one_succeeds
#check @SlabRef.lock_after_retired_destroy_fails
#check @SlabRef.lock_after_realloc_fails
#check @SlabRef.lock_in_destroy_window_fails

-- ─── Reaper cycle phase predicate ───────────────────────────────────
#check @Reaper.InReaperPhase
#check @Reaper.MemReaperValid
#check @Reaper.BufWordReaperValid
#check @Reaper.OtherCoresNoWord
#check @Reaper.inReaperPhase_implies_stale_lock_fails

-- ─── Real per-action induction ──────────────────────────────────────
#check @Invariant.ReaperAction
#check @Invariant.drainOne_preserves
#check @Invariant.drainAll_preserves
#check @Invariant.payloadStore_preserves
#check @Invariant.releaseSetGen_g1_preserves
#check @Invariant.releaseSetGen_g2_preserves
#check @Invariant.lockedCas_preserves
#check @Invariant.step_preserves
#check @Invariant.run_preserves
#check @Invariant.run_reaper_uaf_safe       -- the headline result

-- ─── Multi-slot generalization ──────────────────────────────────────
#check @MultiSlot.lockedCasAt
#check @MultiSlot.lockedCas_eq_lockedCasAt
#check @MultiSlot.lockedCasAt_mem_other
#check @MultiSlot.lockedCasAt_bufs_self_empty
#check @MultiSlot.lockedCasAt_bufs_other
#check @MultiSlot.SlabRef.RefAt
#check @MultiSlot.SlabRef.lockAt
#check @MultiSlot.SlabRef.different_slot_mem_disjoint

-- ─── cmpxchgWeak spurious failure ───────────────────────────────────
#check @Weak.lockedCasWeak
#check @Weak.lockedCasWeak_spurious_fails
#check @Weak.lockedCasWeak_strong_eq
#check @Weak.lockedCasWeak_success_implies_word_eq
#check @Weak.stale_ref_weak_cas_fails
#check @Weak.destroy_window_pre_drain_weak

end SlabProof
