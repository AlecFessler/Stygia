//! Lazy FPU save/restore.
//!
//! The kernel itself is built without SSE/NEON (see `cpu_features_sub`
//! in build.zig), so user-mode FP/SIMD state survives across syscalls
//! and interrupts untouched in the CPU registers. There is no eager
//! FXSAVE/FXRSTOR on syscall entry/exit and no save/restore on context
//! switch — eviction happens only when a different thread on the same core
//! actually issues an FP/SIMD instruction and traps the FPU-disabled
//! bit (CR0.TS on x86-64, CPACR_EL1.FPEN on aarch64).
//!
//! Per core, `scheduler.core_states[core_id].last_fpu_owner` names the
//! thread whose FP regs currently live in that core's hardware. The
//! receiving-side bookkeeping in `arm` only writes the trap-arm bit
//! when the new dispatch target differs from this slot, avoiding
//! redundant CR-writes (each costs a vmexit under KVM).
//!
//! Cross-core migration: if a stolen thread's FP state still lives on a
//! different core's registers, the destination core sends an IPI to
//! the source core to FXSAVE into the thread's own buffer and clear its
//! `last_fpu_owner` slot. See `migrateFlush`.
//!
//! Spec §[thread] lazy FPU.

const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const spin_diag = stygia.utils.spin_diag;
const scheduler = stygia.sched.scheduler;

const Thread = stygia.sched.thread.Thread;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;

/// Called from the arch-specific FP-trap handler (#NM on x64,
/// ESR_EL1.thread=0x07 on aarch64). Swaps FPU state ownership on this core
/// from the previous owner (if any) to `current`, then clears the
/// trap. Safe to call with interrupts disabled (which is the natural
/// state inside an exception entry).
pub fn handleTrap(current: *Thread) void {

    const core_id: u8 = @truncate(arch.smp.coreID());
    const per_core = &scheduler.core_states[core_id];

    // Clear the trap FIRST. FXSAVE and FXRSTOR themselves raise #NM
    // when CR0.TS is set (Intel SDM Vol 2A "FXSAVE — Operation"), so
    // calling fpuSave/fpuRestore below with the trap still armed
    // would recursively re-fault and overflow the kernel stack.
    arch.cpu.fpuClearTrap();
    per_core.fpu_trap_armed = false;

    if (per_core.last_fpu_owner) |prev_ref| {
        // caller-pinned: prev FPU owner is either still alive (handle
        // refcount) or being torn down — `last_fpu_core` clear in
        // `flushIpiHandler` keeps this slot consistent.
        const p = prev_ref.ptr;
        if (p == current) {
            // Same thread re-acquiring on the same core. Regs are still
            // valid — no save, no restore, just leave the trap clear.
            return;
        }
        arch.cpu.fpuSave(&p.fpu_state);
        p.last_fpu_core = null;
    }

    arch.cpu.fpuRestore(&current.fpu_state);
    per_core.last_fpu_owner = SlabRef(Thread).init(current, current._gen_lock.currentGen());
    current.last_fpu_core = core_id;
}

/// Clear `thread` from any core's `last_fpu_owner` slot. Called from
/// `terminate` / `destroyThreadLocked` before the gen-bump
/// + kstack-free, so the next FP trap on `thread.last_fpu_core` doesn't
/// `fpuSave(&thread.fpu_state)` into a slab slot that's about to be
/// freed (or already has been, with the slot reallocated to a
/// different live thread). Mirrors the cancel-on-destroy pattern used
/// for `futex_wait_nodes` / `timed_recv_waiters`.
///
/// Only the core named by `thread.last_fpu_core` could have the slot
/// pointing at this thread (set/cleared atomically with the slot). If the
/// thread is on the local core's FPU-owner slot, clear it directly; if
/// remote, send a flush IPI (which is what `flushIpiHandler` is for).
/// For now we just clear the slot directly via the per-core pointer
/// — there's no concurrency concern because (a) the thread isn't running
/// on the named core (either `terminate` is from another core, or
/// the thread is parked / .exited), and (b) FPU traps on the named core
/// for a different thread would re-evict and clear the slot anyway.
/// Validate a core id that was read back out of an thread field rather than
/// derived from `coreID()` on the core we are currently running on.
///
/// `thread.last_fpu_core` is only ever written as `@truncate(coreID())` (see
/// `fpuSwap`) or cleared to null, so by construction it is always either
/// null or a live core index. A value outside `[0, MAX_CORES)` therefore
/// means we observed the slab slot mid-recycle — the thread is being torn
/// down under us and the byte we read is not a core id at all. 0xFF is
/// the value that shows up in practice, matching both
/// `LAST_DISPATCHED_NEVER` and a never-written byte.
///
/// Unchecked, that escapes straight into `flush_slot_state[]` /
/// `core_states[]` as a wild subscript:
///   `KERNEL PANIC: index out of bounds: index 255, len 64 @ drainLocalFlush`
///
/// Gate it where the stored value is read, not at each subscript. The
/// deliberate tradeoff: we return null (skip the flush) rather than
/// assert, because the thread this refers to is already being destroyed —
/// there is no live FPU state left worth saving into a dying slab slot,
/// and turning a teardown race into a kernel panic would be strictly
/// worse than skipping work that no longer has an owner.
/// Re-send the cross-core FPU flush IPI every this many failed
/// completion checks. Only the target core can bump `done_seq`, and a
/// halted target needs an interrupt to get there, so the request must be
/// re-armed rather than sent once. See the spin in `migrateFlush`.
const FLUSH_IPI_RETRY_SPINS: u32 = 1024;

inline fn storedCore(raw: ?u8) ?u8 {
    const c = raw orelse return null;
    if (c >= scheduler.MAX_CORES) return null;
    return c;
}

pub fn clearFromLastFpuOwner(thread: *Thread) void {
    const core = storedCore(thread.last_fpu_core) orelse return;
    const per_core = &scheduler.core_states[core];
    if (per_core.last_fpu_owner) |ref| {
        if (ref.ptr == thread) per_core.last_fpu_owner = null;
    }
    thread.last_fpu_core = null;
}

// ── Cross-core flush IPI: epoch-stamped + per-target-serialized ──────
//
// `migrateFlush` is the requester side of the cross-core lazy-FPU flush
// IPI. The arch-owned mailbox (`cpu.fpu_flush_mailbox[target]`) carries
// the thread pointer and a `done` bit; the IDT (#NM-vec `IntVecs.fpu_flush`
// on x86-64, SGI 2 on aarch64) lands on the target core and calls
// `flushIpiHandler` to FXSAVE the regs into `thread.fpu_state`.
//
// The unhardened version of this protocol (a naive write-mailbox /
// send-IPI / spin-on-`done`) has two bugs that this module fixes:
//
//   1. **Symmetric-flush deadlock.** Callers (`switchTo` line ~2873)
//      run with IRQs masked (IF=0 on x86, DAIF.I=1 on aarch64). Two
//      cores R and T that simultaneously decide to flush each other
//      both spin with IRQs off; neither's IPI-vector handler ever
//      fires; both wedge until something else perturbs the system.
//
//   2. **Stale-IPI double-process.** The arch mailbox has only one
//      thread slot and one bool. If a late-delivered IPI fires after the
//      original requester has already observed `done = true` and
//      moved on, the receiver re-reads `requested_thread` (still the
//      old thread pointer — nobody clears it) and re-FXSAVEs into
//      `thread.fpu_state`. The thread may have migrated to yet another core
//      by then; FXSAVE captures the WRONG hardware state into its
//      buffer. Likewise, the inline-service path described below can
//      race with the IDT vector against the same arch slot.
//
// Fixes:
//
//   * **Per-target requester serialization.** `flush_slot_state[T]`
//     carries a tiny atomic spinlock (`request_lock`) that exactly one
//     requester holds while owning `mailbox[T]`. Acquiring is bounded
//     by an IPI roundtrip; releasing happens after the request is
//     observed complete. No two requesters can stomp each other's
//     mailbox writes for the same target.
//
//   * **fpu-owned epoch counters.** `request_seq` and `done_seq` per
//     target slot. The requester bumps `request_seq` after writing the
//     mailbox; the receiver writes `done_seq = request_seq` after
//     processing. The requester spins on `done_seq == my_seq` instead
//     of the arch mailbox `done` bool — this dodges the missed-edge
//     race where the requester samples `done = true` from its OWN
//     completion but then a later requester immediately re-clears it.
//
//   * **Atomic-claim handler.** `flushIpiHandler` (and the
//     spin-loop's inline-service path) atomically swap
//     `mailbox[me].requested_thread` to null before processing. First
//     claimer wins; subsequent observers see null and no-op. Combined
//     with the seq-number guard (`request_seq > done_seq`), this
//     makes both stale-IPI fires AND inline-service-vs-IDT-fire races
//     idempotent.
//
//   * **Cooperative inline-service.** While `migrateFlush` spins
//     (with IRQs masked) waiting for its own request to complete, it
//     ALSO services pending requests targeting THIS core. This breaks
//     symmetric-flush deadlock without relaxing the IRQ mask — both
//     stuck cores cooperatively drain each other's mailboxes.
//
// AB-BA freedom: `request_lock` is per target, never held across
// acquiring another target's lock. Cycle-of-N flushes (R→T→C→R)
// resolve by inline-service: each core's spin services the request
// targeted at it, all locks release in topological order.
//
// Why not change the arch mailbox shape: the `FpuFlushMailbox` struct
// is owned by `arch-x64-core` / `arch-aarch64-core`. Adding fields
// would cross subsystem boundaries. The fix keeps the arch mailbox
// as the IPI-transport carrier and layers fpu-owned sequencing state
// on top, indexed by the same core_id.

const FlushSlot = struct {
    /// Per-target spinlock. Acquired by requesters before writing
    /// `mailbox[target]`. CAS true → claimed; release with store(false).
    /// Padded to a cache line so adjacent slots don't false-share under
    /// concurrent multi-target traffic.
    request_lock: std.atomic.Value(bool) align(64) = std.atomic.Value(bool).init(false),

    /// Monotonic sequence number bumped by the requester at request
    /// time (under `request_lock`), AFTER writing
    /// `mailbox[target].requested_thread`. Wraps cleanly at u32 (one
    /// flush per ~5 ns × 2^32 = ~21 s of continuous flushing — the
    /// receiver only compares == against done_seq, so wrap is harmless).
    request_seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Sequence number of the most recently completed request. Written
    /// by whichever receiver path (IDT-driven `flushIpiHandler` or
    /// peer-spin `drainLocalFlush`) wins the atomic claim of the
    /// arch mailbox. Requester spins on `done_seq == my_seq`.
    done_seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

var flush_slot_state: [scheduler.MAX_CORES]FlushSlot = [_]FlushSlot{.{}} ** scheduler.MAX_CORES;

/// Inner save: if this core still owns `thread`'s regs, FXSAVE them into
/// `thread.fpu_state` and clear the per-core slot. Always clears
/// `thread.last_fpu_core` so the thread's next dispatch on any core treats its
/// `fpu_state` buffer as authoritative.
///
/// FPU trap discipline: FXSAVE / FXRSTOR raise `#NM` when CR0.TS is
/// set (Intel SDM Vol 2A "FXSAVE — Operation"). On the source core,
/// the trap may be armed at IPI-arrival time (the prior context
/// switch armed it because the now-running thread isn't the FPU owner).
/// We must clear the trap before the FXSAVE — and, since this flush
/// is an EVICTION (`last_fpu_owner = null` after), leave the trap in
/// the cleared state with `fpu_trap_armed = false` to preserve the
/// scheduler's invariant `fpu_trap_armed ↔ CR0.TS`. The next
/// `switchTo` on this core will observe `last_fpu_owner == null`,
/// recompute `desired_armed = true`, and re-arm.
inline fn doFlushSave(local_core: u8, thread: *Thread) void {
    const per_core = &scheduler.core_states[local_core];
    if (per_core.last_fpu_owner) |ref| {
        // caller-pinned: identity compare on `last_fpu_owner` slot.
        if (ref.ptr == thread) {
            // Clear the trap before FXSAVE — even on the IDT/SGI path
            // where the IPI may arrive on a core whose TS bit was set
            // by an earlier `switchTo` to a non-FPU-owning thread.
            // `fpuClearTrap` is a no-op on TS=0 and a CR0 write on
            // TS=1; we eat the cost here because it's mandatory for
            // FXSAVE not to recursively trap.
            if (per_core.fpu_trap_armed) {
                arch.cpu.fpuClearTrap();
                per_core.fpu_trap_armed = false;
            }
            arch.cpu.fpuSave(&thread.fpu_state);
            per_core.last_fpu_owner = null;
        }
    }
    thread.last_fpu_core = null;
}

/// Try to claim and process a pending flush request targeting THIS core.
/// Used both by the IDT/SGI handler (`flushIpiHandler`) and by the
/// `migrateFlush` spin loop. Idempotent under
/// races: at most one caller wins the atomic claim of the arch mailbox
/// slot, and the seq-number guard short-circuits stale or already-done
/// invocations.
fn drainLocalFlush(local_core: u8) void {
    const slot = &flush_slot_state[local_core];

    // Seq-guard: the requester writes mailbox.requested_thread (release),
    // then bumps request_seq (release), then sends IPI. We acquire-load
    // request_seq; if it equals done_seq, no pending work — either no
    // request was ever posted, or some prior receiver already processed
    // the latest. Skip cleanly; the arch-side ackDone (called by the
    // IDT wrapper after we return) is harmless.
    const req = slot.request_seq.load(.acquire);
    const done = slot.done_seq.load(.acquire);
    if (req == done) return;

    // Atomic claim of the arch mailbox slot. First-claimer wins; losers
    // see null and bail. This makes inline-service-vs-IDT-fire safe.
    const arch_mailbox = arch.cpu.fpuFlushMailbox(local_core);
    const opaque_ptr = @atomicRmw(?*anyopaque, &arch_mailbox.requested_thread, .Xchg, null, .acq_rel) orelse return;
    const thread: *Thread = @ptrCast(@alignCast(opaque_ptr));

    doFlushSave(local_core, thread);

    // Publish completion. Requester spins on done_seq == my_seq;
    // because the request_lock serializes requesters per target,
    // done_seq cannot leapfrog a pending requester's seq in the
    // direction that would cause a missed wakeup.
    slot.done_seq.store(req, .release);
}

/// Service a cross-core FPU flush request targeting THIS core from
/// inside an unbounded barrier spin (stygia-8xl).
///
/// ## Why every IRQ-masked barrier must call this
///
/// `migrateFlush` is a blocking cross-core protocol: the destination
/// core publishes a request, IPIs the source core, and then SPINS —
/// with interrupts masked, because it is reached through
/// `interrupts.switchTo` — until the source core saves the FP regs.
/// It is careful to service ITS OWN mailbox while spinning, precisely
/// so two cores flushing each other cannot wedge.
///
/// Every other unbounded wait in the kernel got only half of that
/// discipline. `serviceTlbMaintenanceWhileSpinning` was added so a
/// spinner could not go deaf to shootdown IPIs; nothing was ever added
/// for the FPU mailbox. And these waits are reached from the SYSCALL
/// path, where `IA32_FMASK` clears IF on entry and no handler re-enables
/// it — so a core spinning in one of them is deaf to the flush IPI for
/// as long as it spins.
///
/// That closes a wait-for cycle with no participant able to yield:
///
///   core A: `terminate(X)` retired X, saw `X.owner_core == B`, and now
///           spins in `routeRetiredFinalize` until B drops X from
///           `current_thread`. IRQs masked (syscall).
///   core B: dispatching X — `current_thread` is already published — is
///           inside `interrupts.switchTo` → `migrateFlush(X)`, waiting
///           for A to flush X's FP regs. IRQs masked.
///
/// B cannot reach `dispatchTailBody` (which would notice X is retired
/// and discharge it), so A's condition never becomes false. The
/// terminal photograph is a core holding a RETIRED, gen-dead thread in
/// `current_thread` with ready Threads stranded behind a second wedged core.
///
/// ## Why doing the save HERE is sound
///
/// Note carefully what does NOT justify this: "the flush IPI could have
/// fired at this instruction anyway." At these call sites it provably
/// could not — that deafness is the whole bug — so that argument is
/// circular and must not be used.
///
/// The actual argument is about WHEN, not whether. The request is
/// sitting in this core's LAPIC IRR and will be delivered the instant IF
/// is restored, which happens at the `sysretq`/`iretq` ending this
/// syscall, before any user instruction runs. The handler would then
/// perform exactly this mutation. So the drain cannot produce a state
/// the machine was not already going to reach; it only reaches it
/// EARLIER. What remains is to show that the reorder is harmless for
/// every reader of the state `doFlushSave` touches.
///
/// `fpu_state` and CR0.TS are quick. The drained thread's `fpu_state` is
/// read by the requesting core only after it observes `done_seq`, which
/// we publish last. CR0.TS / `fpu_trap_armed` clear early, and the
/// kernel is built without SSE/NEON, so no kernel instruction between
/// here and the return can raise #NM: clearing TS early can only remove
/// a trap, never introduce one.
///
/// `last_fpu_owner` needs the full list, because it has SIX readers and
/// two of them are hand-rolled asm reading struct offsets:
///
///   1. `doFlushSave` (this file) — the drain itself. The mailbox claim
///      is an atomic Xchg, so exactly one drainer wins.
///   2. `handleTrap` (this file) — cannot run in between, per the #NM
///      argument above. On the next USER FP instruction it sees null and
///      re-establishes ownership, identically to the post-IPI timeline.
///   3. `interrupts.switchTo` — CAN run in between (`syscallDispatch`
///      tail-calls `hopParkRun`). Sees null, recomputes
///      `desired_armed = true`, re-arms. That is precisely the recovery
///      `doFlushSave`'s own comment specifies, and what it would do
///      after an IPI-driven flush.
///   4. the IPC SUSPEND fast path (`arch/x64/interrupts.zig`, which
///      passes `@offsetOf(PerCore, "last_fpu_owner")` and
///      `fpu_trap_armed` into a naked stub) — cannot run in between.
///      The asm classifier runs at `syscallEntry`, strictly before
///      `syscallDispatch`, and either completes to `sysretq` without
///      ever reaching the slow path (so no barrier here runs at all) or
///      bails to `.Lsyscall_slow_path` BEFORE dispatch. It cannot
///      re-enter on this core until the next syscall entry — which is
///      after IF is restored and therefore after the pending IPI has
///      been taken, so it reads the same state on either timeline.
///   5. the IPC REPLY fast path — identical argument, same two offsets.
///   6. `clearFromLastFpuOwner` (this file) — CAN run in between, and
///      does whenever pins are outstanding: `terminate` drains inside
///      `waitForPinsDrained` (whose body runs only when
///      `pin_depth != 0`) and only then calls it. Safe in both
///      branches, but NOT for the same reason, and the second one is
///      easy to get wrong:
///        - If it names the thread we just drained, `doFlushSave` already
///          nulled that thread's `last_fpu_core` — unconditionally, at its
///          tail, outside both `if`s — so `storedCore` returns null and
///          it exits before touching any slot.
///        - If it names a DIFFERENT thread, our slot may still name it.
///          `doFlushSave`'s inner `if (ref.ptr == thread)` can be false —
///          the mailbox named Y while our slot named X — and then
///          `clearFromLastFpuOwner(X)` does match and does null the
///          slot. That is NOT a no-op. It is still correct, because in
///          exactly that branch the drain touched NONE of
///          `last_fpu_owner`, `fpu_trap_armed` or CR0.TS — only
///          `Y.last_fpu_core` and `done_seq`, neither of which this
///          reader consults for X. So nothing is reordered for this
///          reader at all, and nulling the slot is what it would have
///          done on either timeline. It is the function's whole job.
///
/// One precision on the reorder framing above: where the drained and
/// undrained timelines DIFFER, they differ toward MORE trap-arming,
/// never less. In the `switchTo`-in-between case, draining makes it see
/// null and arm TS; not draining lets it see the stale owner, arm TS,
/// `iretq` into the new thread, and only then take the IPI — which clears
/// TS and nulls the slot, leaving that thread running with another thread's FP
/// registers live and no trap armed. The reorder is not state-identical;
/// it is safe in the direction that matters.
///
/// Supporting, not load-bearing: `migrateFlush` already calls
/// `drainLocalFlush` with IRQs masked, so masked-context draining is an
/// established mode for this code rather than a new one.
pub fn serviceLocalFlushWhileSpinning() void {
    drainLocalFlush(@truncate(arch.smp.coreID()));
}

/// IPI handler invoked on the source core when another core needs to
/// take ownership of `thread`'s FPU state across a migration. Saves the
/// regs (if this core still owns them) and clears `last_fpu_owner`
/// so the source core won't try to save them again on its next trap.
///
/// The `thread` argument is supplied by the arch-side IDT/SGI dispatcher
/// from its own load of `mailbox.requested_thread`. We re-claim the
/// mailbox atomically here and trust the seq-number bookkeeping over
/// the dispatcher's captured pointer — if a peer's inline-service has
/// already drained the slot, we no-op even though the dispatcher
/// passed us a non-null pointer.
pub fn flushIpiHandler(_: *Thread) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    drainLocalFlush(core_id);
}

/// Cross-core FPU flush — if `thread.last_fpu_core` names a different core
/// than the calling one, the destination core would FXRSTOR from a
/// stale `thread.fpu_state` because the live regs still sit on the source
/// core. Coordinate via the per-target arch mailbox + IPI:
///
///   1. Acquire `flush_slot_state[src].request_lock` (serializes
///      requesters; while spinning, drain incoming flushes targeting
///      THIS core to break symmetric-flush deadlock).
///   2. Write `mailbox[src].requested_thread = thread`, bump
///      `flush_slot_state[src].request_seq`. The arch mailbox `done`
///      bool is unused by this protocol (the IDT wrapper still sets
///      it via `ackDone` after the handler returns; we don't read it).
///   3. Send the FPU-flush IPI to `src`.
///   4. Spin on `done_seq == my_seq`. While spinning, also drain
///      incoming flushes (same as step 1).
///   5. Release `request_lock`.
///
/// All atomic accesses use acquire/release pairing; the request_lock
/// + seq-number protocol together guarantee:
///   * exactly-once processing of each request (first claimant of the
///     mailbox slot's atomic-swap wins; stale IPIs read null and no-op).
///   * no missed wakeups (the requester's seq is unique within the
///     lock-protected window; done_seq advances monotonically to it).
///   * deadlock freedom under arbitrary cycles of mutual flushes
///     (each spinning core cooperatively services its own mailbox).
pub fn migrateFlush(thread: *Thread) void {
    // `storedCore` gate: `last_fpu_core` came out of a slab slot that a
    // concurrent teardown may be recycling. See its doc for why an
    // out-of-range value is skipped rather than asserted.
    const src_core = storedCore(thread.last_fpu_core) orelse return;
    const cur_core: u8 = @truncate(arch.smp.coreID());
    if (src_core == cur_core) return;

    const slot = &flush_slot_state[src_core];

    // Acquire the per-target requester lock. Only one requester at a
    // time may own mailbox[src_core]. While waiting, cooperatively
    // service requests targeting our own core — the holder may itself
    // be inside a migrateFlush spin waiting on US.
    while (slot.request_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
        // Ack-while-spinning (stygia-rs6 mechanism 9): this spin runs
        // with IRQs masked (reached through `switchTo`), so without it
        // a core parked here is deaf to the shootdown IPI another core
        // is inside `waitForShootdownAcks` waiting for.
        spin_diag.note(.fpu_mailbox, 0);
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        arch.cpu.cpuRelax();
        drainLocalFlush(cur_core);
    }
    defer slot.request_lock.store(false, .release);

    // Bump our request seq under the lock. The lock guarantees no
    // concurrent requester can overlap our seq window.
    const my_seq = slot.request_seq.load(.monotonic) +% 1;

    // Write the arch mailbox: requested_thread first (release pairing
    // with the receiver's atomic-swap acquire), then bump request_seq
    // (release pairing with the receiver's seq load). The arch
    // mailbox's `done` bool field is left as-is — our completion
    // signal is `done_seq`, not `done`. The IDT/SGI wrapper will set
    // `done = true` via `ackDone` after our handler returns; nothing
    // in this protocol reads it, but we keep the wrapper's existing
    // contract intact.
    const arch_mailbox = arch.cpu.fpuFlushMailbox(src_core);
    @atomicStore(?*anyopaque, &arch_mailbox.requested_thread, thread, .release);
    slot.request_seq.store(my_seq, .release);

    arch.cpu.sendFpuFlushIpi(src_core);

    // Spin on our seq's completion. Inline-service own slot to break
    // symmetric-flush deadlock. The spin terminates as soon as the
    // receiver path bumps done_seq to my_seq (see drainLocalFlush);
    // because the lock prevents any later requester from advancing
    // the seq, this is unambiguous.
    //
    // Re-arm the IPI periodically instead of relying on the single send
    // above. Only `src_core` can bump `done_seq`, and it only does so
    // from `drainLocalFlush` — reached via the flush-IPI handler or its
    // own dispatch path. A core halted in `parkAndAwaitIRQ` does neither
    // until an interrupt lands, so a single flush IPI that is lost,
    // coalesced with another pending delivery, or raced against the
    // target entering its park leaves us spinning here forever against a
    // core that is never going to move again — while we hold
    // `request_lock` and (via `switchTo`) run with IRQs masked.
    //
    // Structurally the same send-once-then-spin defect as the
    // `postZombie` loops in thread.zig, and it presents
    // identically: one core live but emitting nothing, another parked
    // with ready Threads stranded in its own run_queue.
    var flush_spins: u32 = 0;
    while (slot.done_seq.load(.acquire) != my_seq) {
        if (flush_spins % FLUSH_IPI_RETRY_SPINS == 0) {
            arch.cpu.sendFpuFlushIpi(src_core);
        }
        flush_spins +%= 1;
        spin_diag.note(.fpu_mailbox, 1);
        // Ack-while-spinning — see the request_lock spin above.
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        arch.cpu.cpuRelax();
        drainLocalFlush(cur_core);
    }
}
