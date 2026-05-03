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

const zag = @import("zag");

const arch = zag.arch.dispatch;
const kprof = zag.kprof.trace_id;
const scheduler = zag.sched.scheduler;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;

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

