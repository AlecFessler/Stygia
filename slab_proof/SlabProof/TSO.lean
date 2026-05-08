/-
SlabProof.TSO
=============

Operational TSO model — v2.  Addresses the soundness gaps the v1 model
(`drain-then-store` releaseSetGen, two-element Core inductive, single
Loc inductive) papered over:

  * `Core := Nat`, `Loc := Nat`.  The gen+lock word lives at `WORD := 0`;
    payload locations are `1, 2, 3, ...`.
  * `releaseSetGen` is a *buffered* release-store (`bufStore c WORD ...`),
    matching the real Zig `_gen_lock.setGenRelease`'s `.release` ordering
    (a plain MOV on x86 that does sit in the producer's store buffer).
  * `lockedCas` drains the *issuing* core's buffer, then atomically tests
    + swaps the global `mem WORD`.
  * `unlockWord` is also a buffered release-store of the lock-bit-clear
    transition.

The substantive load-bearing lemma is `drainAll_buffer_commits` (proved
in `Concurrent.lean`): after `drainAll c`, `mem l` for every location
`l` reflects the *last* buffered write to `l` from `c`'s buffer (in FIFO
order), or the original `mem l` if no such buffered write exists.  This
is the TSO-FIFO property the publication theorem rides on.
-/
import SlabProof.Word

namespace SlabProof
namespace TSO

/-- Cores are identified by a natural number.  Real machines have a
    finite set, but for the proofs nothing about finiteness is
    load-bearing — every theorem ranges over an arbitrary core or pair
    of cores. -/
abbrev Core := Nat

/-- Memory locations are also `Nat`.  By convention `WORD = 0` is the
    gen+lock word; locations `1, 2, …` are payload bytes (a "slot's
    field at byte offset i" is `i + 1`, conceptually).  Theorems are
    stated for arbitrary `l : Loc`, with the special case `WORD`
    singled out for the gen+lock structure. -/
abbrev Loc := Nat

/-- The fixed location of the gen+lock word. -/
def WORD : Loc := 0

structure BufEntry where
  loc : Loc
  val : Nat
  deriving Repr

/-- TSO machine state.  Each core has its own FIFO store buffer
    (`bufs c`); `mem` is globally-visible memory; `consSaw` records
    the value each core's most recent locked CAS observed (used by the
    publication / stale-rejection theorems to refer to "what core c
    saw"). -/
structure Machine where
  bufs    : Core → List BufEntry
  mem     : Loc → Nat
  consSaw : Core → Option Nat

namespace Machine

@[simp] def empty : Machine :=
  { bufs := fun _ => []
  , mem := fun _ => 0
  , consSaw := fun _ => none }

/-- Update the buffer of a single core. -/
@[simp] def setBuf (m : Machine) (c : Core) (b : List BufEntry) : Machine :=
  { m with bufs := fun c' => if c' = c then b else m.bufs c' }

/-- Update memory at a single location. -/
@[simp] def setMem (m : Machine) (l : Loc) (v : Nat) : Machine :=
  { m with mem := fun l' => if l' = l then v else m.mem l' }

/-- Update consSaw for a single core. -/
@[simp] def setSaw (m : Machine) (c : Core) (v : Option Nat) : Machine :=
  { m with consSaw := fun c' => if c' = c then v else m.consSaw c' }

/-- TSO read with self-store-buffer forwarding: youngest matching
    buffered entry from `c`'s buffer, else memory. -/
def read (m : Machine) (c : Core) (l : Loc) : Nat :=
  match (m.bufs c).reverse.find? (fun e => e.loc = l) with
  | some e => e.val
  | none   => m.mem l

/-- Append a buffered store. -/
@[simp] def bufStore (m : Machine) (c : Core) (l : Loc) (v : Nat) : Machine :=
  m.setBuf c (m.bufs c ++ [{ loc := l, val := v }])

/-- Drain the head of `c`'s buffer to memory. -/
def drainOne (m : Machine) (c : Core) : Machine :=
  match m.bufs c with
  | []       => m
  | e :: rest =>
    (m.setBuf c rest).setMem e.loc e.val

/-- Drain `c`'s entire buffer.  Folds `drainOne` over `c`'s own
    buffer length (each step removes one head, so the buffer is
    empty after `(bufs c).length` steps). -/
def drainAll (m : Machine) (c : Core) : Machine :=
  (m.bufs c).foldl (fun acc _ => drainOne acc c) m

/-- Locked CAS on the gen+lock word.  Drains the issuing core's
    buffer first, then atomically tests + swaps. -/
def lockedCas (m : Machine) (c : Core) (expected : Nat) : Machine × Bool :=
  let m' := drainAll m c
  let cur := m'.mem WORD
  let w := Word.decode cur
  let m'' := m'.setSaw c (some cur)
  match Word.casLockWithGen w expected with
  | some w' => (m''.setMem WORD (Word.encode w'), true)
  | none    => (m'', false)

/-- Buffered release-store of `(g <<< 1) | 0` to WORD.  This matches
    the real `GenLock.setGenRelease` — a plain `.release` store on
    x86, which goes into the issuing core's store buffer. -/
@[simp] def releaseSetGen (m : Machine) (c : Core) (g : Nat) : Machine :=
  m.bufStore c WORD (Word.encode { gen := g, lock := false })

/-- Buffered release-store of `(g <<< 1) | 1` to WORD.  Used by tests
    to model "lock bit set" without actually doing the CAS.  Real
    code uses the locked CAS to acquire the lock — see `lockedCas`. -/
@[simp] def bufferedSetWord (m : Machine) (c : Core) (g : Nat) (lock : Bool) : Machine :=
  m.bufStore c WORD (Word.encode { gen := g, lock := lock })

/-- Unlock the gen+lock word: buffered store of `(g <<< 1) | 0`.  In
    practice always paired with a known `g` from a prior locked op. -/
@[simp] def unlockWord (m : Machine) (c : Core) (g : Nat) : Machine :=
  m.bufStore c WORD (Word.encode { gen := g, lock := false })

/-- Buffered plain payload store to location `l ≠ WORD`. -/
@[simp] def payloadStore (m : Machine) (c : Core) (l : Loc) (v : Nat) : Machine :=
  m.bufStore c l v

end Machine

/-- One small-step program action. -/
inductive Action where
  | drain         (c : Core)
  | payloadStore  (c : Core) (l : Loc) (v : Nat)
  | releaseSetGen (c : Core) (g : Nat)
  | lockedCasWord (c : Core) (expected : Nat)
  | unlockWord    (c : Core) (g : Nat)
  deriving Repr

/-- Single-step transition. -/
def step (m : Machine) : Action → Machine
  | .drain c             => Machine.drainOne m c
  | .payloadStore c l v  => Machine.payloadStore m c l v
  | .releaseSetGen c g   => Machine.releaseSetGen m c g
  | .lockedCasWord c e   => (Machine.lockedCas m c e).1
  | .unlockWord c g      => Machine.unlockWord m c g

def run (m0 : Machine) : List Action → Machine
  | []      => m0
  | a :: as => run (step m0 a) as

@[simp] theorem run_nil (m : Machine) : run m [] = m := rfl

@[simp] theorem run_cons (m : Machine) (a : Action) (as : List Action) :
    run m (a :: as) = run (step m a) as := rfl

end TSO
end SlabProof
