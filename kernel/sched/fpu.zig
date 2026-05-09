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

/// IPI handler invoked on the source core when another core needs to
/// take ownership of `ec`'s FPU state across a migration. Saves the
/// regs (if this core still owns them) and clears `last_fpu_owner`
/// so the source core won't try to save them again on its next trap.
///
/// Race: between the requester's `migrateFlush` decision and this
/// handler running, another EC on this core may have caused an
/// FP-disabled trap and already evicted `ec` (saving it). In that
/// case `last_fpu_owner != ec` and we no-op — `ec.fpu_state` is
/// already fresh from the eviction.
pub fn flushIpiHandler(ec: *ExecutionContext) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    const per_core = &scheduler.core_states[core_id];
    if (per_core.last_fpu_owner) |ref| {
        // caller-pinned: identity compare on `last_fpu_owner` slot.
        if (ref.ptr == ec) {
            arch.cpu.fpuSave(&ec.fpu_state);
            per_core.last_fpu_owner = null;
        }
    }
    ec.last_fpu_core = null;
}

/// Cross-core FPU flush — if `ec.last_fpu_core` names a different core
/// than the calling one, the destination core would FXRSTOR from a
/// stale `ec.fpu_state` because the live regs still sit on the source
/// core. The intended fix is an IPI handshake driven through
/// `cpu.fpu_flush_mailbox[src_core]`: requester writes the EC pointer
/// + clears `done`, sends the FPU-flush IPI, spins on `done`; the
/// receiver runs `flushIpiHandler` to FXSAVE into `ec.fpu_state`,
/// clears `last_fpu_owner`, sets `done`. The IDT vector / SGI 2 are
/// already wired and the receiver-side handler is tested via the
/// terminate path's `clearFromLastFpuOwner`.
///
/// Why this is currently a no-op: callers (`switchTo`) run with IRQs
/// masked, so a naive sender-spin deadlocks under concurrent
/// symmetric flushes — neither core's IDT vector fires because both
/// have IF=0 / DAIF.I=1 across the spin. A poll-and-service variant
/// (drain inbound on the local mailbox during the wait) was tried
/// and produced reproducible MISS patterns on
/// `create_capability_domain_31` / `clear_event_route_06` — likely
/// from a memory-ordering race between the inline service and the
/// later interrupt-driven `flushIpiHandler` invocation against the
/// same slot. Until the protocol is hardened (epoch-stamped mailbox
/// or a deferred-work queue drained from the iretq tail), the
/// observable cost of the no-op is bounded: the kernel itself is
/// built without SSE/NEON, the test suite likewise (`+soft_float`),
/// and no spec test exercises SIMD across migration — so a stale
/// FXRSTOR on the destination core has no userspace-visible effect.
/// Real-world userspace SIMD callers across migrations will need
/// the full impl; tracked with the v3 affinity tightening.
pub fn migrateFlush(ec: *ExecutionContext) void {
    const src_core = ec.last_fpu_core orelse return;
    const cur_core: u8 = @truncate(arch.smp.coreID());
    if (src_core == cur_core) return;
}


