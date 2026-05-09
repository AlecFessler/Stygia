//! Lazy FPU save/restore.
//!
//! The kernel itself is built without SSE/NEON (see `cpu_features_sub`
//! in build.zig), so user-mode FP/SIMD state survives across syscalls
//! and interrupts untouched in the CPU registers. There is no eager
//! FXSAVE/FXRSTOR on syscall entry/exit and no save/restore on context
//! switch — eviction happens only when a different EC on the same core
//! actually issues an FP/SIMD instruction and traps the FPU-disabled
//! bit (CR0.TS on x86-64, CPACR_EL1.FPEN on aarch64).
//!
//! Per core, `scheduler.core_states[core_id].last_fpu_owner` names the
//! EC whose FP regs currently live in that core's hardware. The
//! receiving-side bookkeeping in `arm` only writes the trap-arm bit
//! when the new dispatch target differs from this slot, avoiding
//! redundant CR-writes (each costs a vmexit under KVM).
//!
//! Cross-core migration: if a stolen EC's FP state still lives on a
//! different core's registers, the destination core sends an IPI to
//! the source core to FXSAVE into the EC's own buffer and clear its
//! `last_fpu_owner` slot. See `migrateFlush`.
//!
//! Spec §[execution_context] lazy FPU.

const builtin = @import("builtin");
const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const kprof = stygia.kprof.trace_id;
const scheduler = stygia.sched.scheduler;

const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;

/// Called from the arch-specific FP-trap handler (#NM on x64,
/// ESR_EL1.EC=0x07 on aarch64). Swaps FPU state ownership on this core
/// from the previous owner (if any) to `current`, then clears the
/// trap. Safe to call with interrupts disabled (which is the natural
/// state inside an exception entry).
pub fn handleTrap(current: *ExecutionContext) void {
    kprof.enter(.fpu_swap);
    defer kprof.exit(.fpu_swap);

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
            // Same EC re-acquiring on the same core. Regs are still
            // valid — no save, no restore, just leave the trap clear.
            return;
        }
        arch.cpu.fpuSave(&p.fpu_state);
        p.last_fpu_core = null;
    }

    arch.cpu.fpuRestore(&current.fpu_state);
    per_core.last_fpu_owner = SlabRef(ExecutionContext).init(current, current._gen_lock.currentGen());
    current.last_fpu_core = core_id;
}

/// Clear `ec` from any core's `last_fpu_owner` slot. Called from
/// `terminate` / `destroyExecutionContextLocked` before the gen-bump
/// + kstack-free, so the next FP trap on `ec.last_fpu_core` doesn't
/// `fpuSave(&ec.fpu_state)` into a slab slot that's about to be
/// freed (or already has been, with the slot reallocated to a
/// different live EC). Mirrors the cancel-on-destroy pattern used
/// for `futex_wait_nodes` / `timed_recv_waiters`.
///
/// Only the core named by `ec.last_fpu_core` could have the slot
/// pointing at this EC (set/cleared atomically with the slot). If the
/// EC is on the local core's FPU-owner slot, clear it directly; if
/// remote, send a flush IPI (which is what `flushIpiHandler` is for).
/// For now we just clear the slot directly via the per-core pointer
/// — there's no concurrency concern because (a) the EC isn't running
/// on the named core (either `terminate` is from another core, or
/// the EC is parked / .exited), and (b) FPU traps on the named core
/// for a different EC would re-evict and clear the slot anyway.
pub fn clearFromLastFpuOwner(ec: *ExecutionContext) void {
    const core = ec.last_fpu_core orelse return;
    const per_core = &scheduler.core_states[core];
    if (per_core.last_fpu_owner) |ref| {
        if (ref.ptr == ec) per_core.last_fpu_owner = null;
    }
    ec.last_fpu_core = null;
}

// ── Cross-core flush IPI: epoch-stamped + per-target-serialized ──────
//
// `migrateFlush` is the requester side of the cross-core lazy-FPU flush
// IPI. The arch-owned mailbox (`cpu.fpu_flush_mailbox[target]`) carries
// the EC pointer and a `done` bit; the IDT (#NM-vec `IntVecs.fpu_flush`
// on x86-64, SGI 2 on aarch64) lands on the target core and calls
// `flushIpiHandler` to FXSAVE the regs into `ec.fpu_state`.
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
//      EC slot and one bool. If a late-delivered IPI fires after the
//      original requester has already observed `done = true` and
//      moved on, the receiver re-reads `requested_thread` (still the
//      old EC pointer — nobody clears it) and re-FXSAVEs into
//      `ec.fpu_state`. The EC may have migrated to yet another core
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

/// Per-arch accessor for the IPI-transport mailbox. Owned by
/// `arch-x64-core` / `arch-aarch64-core`; we read its `requested_thread`
/// and `done` fields here. Indexed by *target* core (the core whose
/// hardware will receive the IPI and run the FXSAVE).
inline fn archFlushMailbox(core: u8) *ArchFpuFlushMailbox {
    return switch (builtin.cpu.arch) {
        .x86_64 => &stygia.arch.x64.cpu.fpu_flush_mailbox[core],
        .aarch64 => &stygia.arch.aarch64.cpu.fpu_flush_mailbox[core],
        else => unreachable,
    };
}

const ArchFpuFlushMailbox = switch (builtin.cpu.arch) {
    .x86_64 => stygia.arch.x64.cpu.FpuFlushMailbox,
    .aarch64 => stygia.arch.aarch64.cpu.FpuFlushMailbox,
    else => unreachable,
};

/// Send the lazy-FPU flush IPI to `target_core`. x86-64 uses the
/// dedicated IDT vector `IntVecs.fpu_flush`; aarch64 uses SGI 2.
/// Both wire into the same in-IRQ-context handler that calls
/// `flushIpiHandler` after reading the EC pointer from the mailbox.
inline fn sendFpuFlushIpi(target_core: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const vec = @intFromEnum(stygia.arch.x64.interrupts.IntVecs.fpu_flush);
            stygia.arch.x64.apic.sendIpiToCore(target_core, vec);
        },
        .aarch64 => {
            // SGI 2 — see arch/aarch64/exceptions.zig dispatchIrq.
            stygia.arch.aarch64.gic.sendIpiToCore(target_core, 2);
        },
        else => unreachable,
    }
}

/// Inner save: if this core still owns `ec`'s regs, FXSAVE them into
/// `ec.fpu_state` and clear the per-core slot. Always clears
/// `ec.last_fpu_core` so the EC's next dispatch on any core treats its
/// `fpu_state` buffer as authoritative.
///
/// FPU trap discipline: FXSAVE / FXRSTOR raise `#NM` when CR0.TS is
/// set (Intel SDM Vol 2A "FXSAVE — Operation"). On the source core,
/// the trap may be armed at IPI-arrival time (the prior context
/// switch armed it because the now-running EC isn't the FPU owner).
/// We must clear the trap before the FXSAVE — and, since this flush
/// is an EVICTION (`last_fpu_owner = null` after), leave the trap in
/// the cleared state with `fpu_trap_armed = false` to preserve the
/// scheduler's invariant `fpu_trap_armed ↔ CR0.TS`. The next
/// `switchTo` on this core will observe `last_fpu_owner == null`,
/// recompute `desired_armed = true`, and re-arm.
inline fn doFlushSave(local_core: u8, ec: *ExecutionContext) void {
    const per_core = &scheduler.core_states[local_core];
    if (per_core.last_fpu_owner) |ref| {
        // caller-pinned: identity compare on `last_fpu_owner` slot.
        if (ref.ptr == ec) {
            // Clear the trap before FXSAVE — even on the IDT/SGI path
            // where the IPI may arrive on a core whose TS bit was set
            // by an earlier `switchTo` to a non-FPU-owning EC.
            // `fpuClearTrap` is a no-op on TS=0 and a CR0 write on
            // TS=1; we eat the cost here because it's mandatory for
            // FXSAVE not to recursively trap.
            if (per_core.fpu_trap_armed) {
                arch.cpu.fpuClearTrap();
                per_core.fpu_trap_armed = false;
            }
            arch.cpu.fpuSave(&ec.fpu_state);
            per_core.last_fpu_owner = null;
        }
    }
    ec.last_fpu_core = null;
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
    const arch_mailbox = archFlushMailbox(local_core);
    const opaque_ptr = @atomicRmw(?*anyopaque, &arch_mailbox.requested_thread, .Xchg, null, .acq_rel) orelse return;
    const ec: *ExecutionContext = @ptrCast(@alignCast(opaque_ptr));

    doFlushSave(local_core, ec);

    // Publish completion. Requester spins on done_seq == my_seq;
    // because the request_lock serializes requesters per target,
    // done_seq cannot leapfrog a pending requester's seq in the
    // direction that would cause a missed wakeup.
    slot.done_seq.store(req, .release);
}

/// IPI handler invoked on the source core when another core needs to
/// take ownership of `ec`'s FPU state across a migration. Saves the
/// regs (if this core still owns them) and clears `last_fpu_owner`
/// so the source core won't try to save them again on its next trap.
///
/// The `ec` argument is supplied by the arch-side IDT/SGI dispatcher
/// from its own load of `mailbox.requested_thread`. We re-claim the
/// mailbox atomically here and trust the seq-number bookkeeping over
/// the dispatcher's captured pointer — if a peer's inline-service has
/// already drained the slot, we no-op even though the dispatcher
/// passed us a non-null pointer.
pub fn flushIpiHandler(_: *ExecutionContext) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    drainLocalFlush(core_id);
}

/// Cross-core FPU flush — if `ec.last_fpu_core` names a different core
/// than the calling one, the destination core would FXRSTOR from a
/// stale `ec.fpu_state` because the live regs still sit on the source
/// core. Coordinate via the per-target arch mailbox + IPI:
///
///   1. Acquire `flush_slot_state[src].request_lock` (serializes
///      requesters; while spinning, drain incoming flushes targeting
///      THIS core to break symmetric-flush deadlock).
///   2. Write `mailbox[src].requested_thread = ec`, bump
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
pub fn migrateFlush(ec: *ExecutionContext) void {
    const src_core = ec.last_fpu_core orelse return;
    const cur_core: u8 = @truncate(arch.smp.coreID());
    if (src_core == cur_core) return;

    const slot = &flush_slot_state[src_core];

    // Acquire the per-target requester lock. Only one requester at a
    // time may own mailbox[src_core]. While waiting, cooperatively
    // service requests targeting our own core — the holder may itself
    // be inside a migrateFlush spin waiting on US.
    while (slot.request_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
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
    const arch_mailbox = archFlushMailbox(src_core);
    @atomicStore(?*anyopaque, &arch_mailbox.requested_thread, ec, .release);
    slot.request_seq.store(my_seq, .release);

    sendFpuFlushIpi(src_core);

    // Spin on our seq's completion. Inline-service own slot to break
    // symmetric-flush deadlock. The spin terminates as soon as the
    // receiver path bumps done_seq to my_seq (see drainLocalFlush);
    // because the lock prevents any later requester from advancing
    // the seq, this is unambiguous.
    while (slot.done_seq.load(.acquire) != my_seq) {
        arch.cpu.cpuRelax();
        drainLocalFlush(cur_core);
    }
}
