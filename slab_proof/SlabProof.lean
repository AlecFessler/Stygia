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

v5 closes the Lamport-style audit follow-ups:
  * Entry lemma — `enters_reaper_phase` derives `InReaperPhase` from a
    real destroy-side acquire + buffered gen-bump, so the run-induction
    no longer assumes its own premise.  `end_to_end_uaf_safe` composes
    entry + run.
  * `MultiSlot.stale_ref_at_other_slot_unaffected` — replaces the
    placeholder `True := trivial` cross-slot stub with an actual proof.
  * Dead-code purge — `Sequential.lastTouchClearedLock`, an unused
    helper whose three recursive cases collapsed to the same
    expression, has been removed.

v6 closes the second-round Lamport audit gaps:
  * `Sequential.sequential_uaf_after_destroy` — the headline single-
    thread UAF claim is now an explicit theorem, not implicit
    in the chain `lock_success_implies_lastSetGen` ∘ `lockTry_success_observed`.
  * `SlabRef.lock_fails_unless_canonical` — state-level necessary-and-
    sufficient form: a stale lock fails iff post-drain `mem WORD`
    differs from the canonical `encode { ref.gen, false }`.  Subsumes
    every per-window case (`stale_rejected_locked`, `stale_rejected_gen`,
    pre/post-drain destroy windows) and is the load-bearing lemma
    for cross-phase durable safety.
  * `Invariant.WordGenAbove` + `DurableAction` + `durable_run_uaf_safe`
    — chained-phase UAF safety.  Once `mem WORD`'s decoded gen has
    advanced past `ref.gen`, an action grammar that admits *every*
    real reader path (drain, payload store, release-store of a
    higher gen, locked CAS, **reader unlock**) preserves the gen
    floor.  The stale ref is rejected at every prefix of any such
    run, not just at the end of one reaper phase.
  * `Invariant.reaper_phase_retired_implies_durable` — bridge from
    the per-phase invariant of v3-v5 to the durable invariant: once
    the destroy gen-bump has globally retired, the per-phase grammar
    can be released and the durable grammar takes over.
  * `consSaw` field — removed from `Machine`.  It was set on every
    locked CAS and never read by any safety theorem.

Modelling assumptions (operational, out of scope of this artifact)
------------------------------------------------------------------

These are stated explicitly because the safety claims are conditional
on them.  The proof does not establish them — they are facts about
the surrounding kernel that must hold for the mechanized theorems
to apply to the running primitive.

  A1. **Slot-address stability.**  The proof models WORD as a fixed
      `Loc : Nat` whose `mem` is total and unconditionally readable.
      The Zig `lockWithGen` dereferences `&self.word` on every CAS,
      and on the failure path (`secure_slab.zig:178`) issues a plain
      monotonic load from the same address.  For these loads to be
      sound — i.e. not themselves UAF — the slot's vaddr must remain
      mapped, and the `_gen_lock` field must remain at the same
      offset, for the lifetime of any outstanding stale ref.  The
      `SecureSlab` allocator structurally guarantees this: slots are
      allocated from a comptime-reserved demand-paged region, never
      returned to a global allocator, and `_gen_lock` is at offset 0
      of every slab-backed T (enforced by `validateT`).  This proof
      assumes that structural guarantee; it does not prove it.

  A2. **Gen-counter non-wrap.**  The proof works in `Nat`; the real
      word uses `u63`, wrapping at 2⁶³.  Two distinct logical
      lifetimes whose gens alias modulo 2⁶³ would be indistinguishable
      to the CAS.  At the kernel's destroy rate this corresponds to
      >10² years of sustained per-slot churn.

  A3. **x86-TSO memory model.**  The TSO operational semantics in
      `TSO.lean` (per-core FIFO store buffers, locked RMW = self-
      drain + globally-serialized test-and-swap, plain stores buffer)
      is the SPARC/x86-TSO standard.  ARM64's RCsc/release-acquire
      model is *not* covered — the same Zig source compiles correctly
      on both architectures (release/acquire orderings give the
      ARM64 backend the right barriers), but the operational proof
      argument would have to be re-stated against an axiomatic
      ARMv8 memory model.

Scope carve-outs (NOT covered by the safety claim)
--------------------------------------------------

  S1. **`forEachAlive` and `GenLock.lock` (no-gen variant).**  The
      Zig source exposes two reader paths whose UAF safety is *not*
      proved here:
        * `SecureSlab.forEachAlive` (`secure_slab.zig:591-605`) reads
          `ptr._gen_lock.currentGen()` (a plain monotonic load) before
          deciding whether to invoke a visitor with a bare `*T`.  The
          Zig comment delegates UAF responsibility to the visitor:
          "callers must take the per-slot gen-lock themselves if they
          need exclusive access to T's fields."
        * `GenLock.lock` / `GenLock.lockOrdered` (no-gen spin-CAS,
          `secure_slab.zig:61-70`) is used by paths that already hold
          a *T from a pinned reference chain (no handle, no staleness
          check).
      Both paths' UAF safety rests on caller-side discipline that is
      not machine-checked.  The mechanized claim covers only the
      `SlabRef.lock` / `lockWithGen` path.

  S2. **Reaper grammar over-approximation.**  `Invariant.ReaperAction`
      admits `releaseSetGen P (g+2)` (the realloc publish) at any
      point in a trace, including before `releaseSetGen P (g+1)` (the
      destroy gen-bump) has committed.  The real implementation
      serialises destroy → freelist push → realloc pop.  The proof
      is a strict over-approximation: every real trace satisfies the
      grammar, but the grammar admits traces that the implementation
      never produces.  Safety transfers (more permissive ⇒ same
      conclusion); tightness does not.  The durable-safety grammar
      `DurableAction` is similarly over-approximating by design.
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
#check @sequential_uaf_after_destroy

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
#check @SlabRef.lock_fails_unless_canonical
#check @SlabRef.lock_success_forces_canonical

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

-- ─── Entry lemma + end-to-end composition ───────────────────────────
#check @Invariant.enters_reaper_phase
#check @Invariant.end_to_end_uaf_safe

-- ─── Durable cross-phase safety ─────────────────────────────────────
#check @Invariant.WordGenAbove
#check @Invariant.DurableAction
#check @Invariant.durable_drainOne_preserves
#check @Invariant.durable_drainAll_preserves
#check @Invariant.durable_payloadStore_preserves
#check @Invariant.durable_releaseSetGen_preserves
#check @Invariant.durable_unlockWord_preserves
#check @Invariant.durable_lockedCas_preserves
#check @Invariant.durable_step_preserves
#check @Invariant.durable_run_preserves
#check @Invariant.durable_state_uaf_safe
#check @Invariant.durable_run_uaf_safe        -- the cross-phase headline
#check @Invariant.reaper_phase_retired_implies_durable

-- ─── Multi-slot generalization ──────────────────────────────────────
#check @MultiSlot.lockedCasAt
#check @MultiSlot.lockedCas_eq_lockedCasAt
#check @MultiSlot.lockedCasAt_mem_other
#check @MultiSlot.lockedCasAt_bufs_self_empty
#check @MultiSlot.lockedCasAt_bufs_other
#check @MultiSlot.SlabRef.RefAt
#check @MultiSlot.SlabRef.lockAt
#check @MultiSlot.SlabRef.different_slot_mem_disjoint
#check @MultiSlot.SlabRef.stale_ref_at_other_slot_unaffected

-- ─── cmpxchgWeak spurious failure ───────────────────────────────────
#check @Weak.lockedCasWeak
#check @Weak.lockedCasWeak_spurious_fails
#check @Weak.lockedCasWeak_strong_eq
#check @Weak.lockedCasWeak_success_implies_word_eq
#check @Weak.stale_ref_weak_cas_fails
#check @Weak.destroy_window_pre_drain_weak

end SlabProof
