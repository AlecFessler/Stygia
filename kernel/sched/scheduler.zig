//! Per-core scheduler — owns the run queues, dispatches ECs, handles
//! preemption + voluntary yield, tracks the current EC per core, and
//! coordinates lazy-FPU eviction across cores.
//!
//! Each core has a `PerCore` slot holding its run queue (priority-
//! ordered intrusive PQ over EC.next), the currently dispatched EC,
//! the last-FPU-owner EC, and a flag for whether CR0.TS is currently
//! armed. Cross-core enqueue is supported (the source core sends an
//! IPI to the destination if the destination is idle).

const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const ec_log = zag.utils.ec_log;
const kprof = zag.kprof.trace_id;
const port_mod = zag.sched.port;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const Priority = zag.sched.execution_context.Priority;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;

/// Intrusive priority queue of ECs, linked through the EC's `next`
/// field and ordered by `priority`. Shared by per-core run queues and
/// port wait queues. Futex buckets use a separate WaitNode-based queue
/// (see sched/futex.zig).
pub const EcQueue = zag.sched.priority_queue.PriorityQueue(
    ExecutionContext,
    "next",
    "priority",
    @typeInfo(Priority).@"enum".fields.len,
);

/// Maximum cores the scheduler supports. Matches `affinity` mask width.
pub const MAX_CORES: u8 = 64;

/// Per-EC quantum between preemption ticks. Spec doesn't pin this.
///
/// x86 uses 2 ms — matches the old kernel and gives the LAPIC one-shot
/// timer (which auto-disarms on fire per Intel SDM Vol 3A §13.5.4) a
/// reasonable round-robin granularity.
///
/// Aarch64 uses 16 ms because the generic timer is level-sensitive at
/// the GIC: the timer line stays asserted as long as ISTATUS=1, which
/// lets a tick that fires while the kernel is still inside the previous
/// SVC handler re-pend at the GIC the moment EOI clears the active bit.
/// The next ERET to userspace then drops PSTATE.I, the pending tick
/// fires before any user instruction completes, and a freshly-dispatched
/// low-priority EC (e.g. the W in `reply_05`'s `yieldEc(W)`) gets robbed
/// of its first-instruction window. Higher-priority queue residents then
/// starve W indefinitely. A longer quantum gives explicitly-yielded
/// targets enough head start to make observable progress before the next
/// tick re-enters the scheduler. See ARM ARM D11.2.4 (timer condition),
/// D13.8.20 (CNTV_CTL), and IHI 0048B §3.2 (level-sensitive PPI).
pub const TIMESLICE_NS: u64 = switch (builtin.cpu.arch) {
    .aarch64 => 16_000_000,
    else => 2_000_000,
};

/// Per-core scheduler state. One entry per active core in `core_states[]`.
///
/// `?SlabRef(EC)` requires a tagged-union layout that's not extern-
/// compatible, so `PerCore` is a regular struct. No current asm path
/// references field offsets here — the IPC fast path goes through
/// `SyscallScratch` (extern) which caches the `*ExecutionContext`
/// raw value separately.
pub const PerCore = struct {
    /// Priority-ordered intrusive PQ over EC.next. Drained by
    /// `dequeue` on context switch / yield / preempt.
    run_queue: EcQueue = .{},

    /// EC currently dispatched on this core. `null` ⇒ core is idle.
    /// SlabRef so the cross-core readers (FPU flush / `coreRunning`)
    /// can detect a freed-then-reallocated slot via gen mismatch.
    current_ec: ?SlabRef(ExecutionContext) = null,

    /// EC whose FP/SIMD state currently lives in this core's CPU
    /// registers. May be a different EC than `current_ec` (lazy FPU —
    /// eviction happens on the next FP-disabled trap, not on context
    /// switch). `null` if no EC has used FP on this core since boot.
    last_fpu_owner: ?SlabRef(ExecutionContext) = null,

    /// Whether CR0.TS / FPEN is currently armed on this core. Tracked
    /// here so we don't issue redundant CR-writes (each one costs a
    /// vmexit under KVM).
    fpu_trap_armed: bool = false,

    /// Per-core idle EC. Allocated at perCoreInit; runs `hlt`/`wfi`
    /// when the run queue is empty. Pinned to this core via affinity.
    idle_ec: ?SlabRef(ExecutionContext) = null,

    /// EC handed off to this core for deferred destroy. Set by a remote
    /// `terminate` when the target was the running EC on this core —
    /// freeing kstack pages + slab slot inline would race with this
    /// core's still-in-flight syscall handler. The next `switchTo` on
    /// this core finalizes the destroy after the kstack/CR3 swap moves
    /// execution onto the new EC's stack. Single-slot is enough: a
    /// second pending termination on the same core blocks until this
    /// one is reaped.
    ///
    /// Stored as `SlabRef(ExecutionContext)` (rather than bare pointer)
    /// to satisfy the gen-lock-analyzer fat-pointer invariant — the gen
    /// captured at posting time is the *post-bump* even gen, and reap
    /// callers only use `pending_zombie.ptr` for identity comparison
    /// + `finalizeDestroyMarkedDead` (which already operates on a
    /// `*EC` bypassing gen-lock checks because the slot is in its
    /// post-bump-pre-destroyAlreadyMarked state). No `lockWithGen`
    /// against this ref ever runs; the field type is just a contract
    /// declaration.
    pending_zombie: ?SlabRef(ExecutionContext) = null,
};

/// Per-core scheduler state. Indexed by core id (APIC ID on x86-64,
/// MPIDR on aarch64). Only the first `arch.smp.coreCount()` entries
/// are populated.
pub var core_states: [MAX_CORES]PerCore = [_]PerCore{.{}} ** MAX_CORES;

/// Parallel array of per-core spinlocks guarding `core_states[i]`'s
/// `run_queue` and `current_ec`. Held only across queue ops and a
/// snapshot of `current_ec`; never held across `loadEcContextAndReturn`.
/// Kept out of `PerCore` itself so the IPC fast-path's hardcoded field
/// offsets (72/80) inside `extern struct PerCore` stay pinned.
///
/// Lock order: `core_locks[i]` is its own class; cross-core enqueue may
/// acquire the target core's lock while holding the local core's lock,
/// so the class is registered as ordered to opt out of pair-edge
/// cycle detection. Callers must always release before invoking
/// scheduler dispatch (`switchTo` / `loadEcContextAndReturn`).
pub var core_locks: [MAX_CORES]SpinLock = [_]SpinLock{.{ .class = "sched.core_lock" }} ** MAX_CORES;

/// Lockdep group tag for `core_locks`. Non-zero so that overlapping
/// per-core lock holds (e.g. cross-core enqueue grabbing target while
/// holding local) don't seed a phantom AB-BA cycle in the lock graph.
pub const SCHED_CORE_GROUP: u32 = 0x5C00; // arbitrary non-zero tag

/// Set true after `globalInit` returns. Read by the boot path before
/// enqueueing the root service's initial EC.
pub var initialized: bool = false;

// ── Init ─────────────────────────────────────────────────────────────

/// Boot-time global init — called once on the BSP before SMP brings
/// other cores up. Initializes `core_states[0]`'s idle EC and any
/// scheduler-wide state.
pub fn globalInit() !void {
    initialized = true;
}

/// Per-core init — called once per core during SMP bring-up after the
/// core's APIC / GIC is online. Arms the per-core preemption timer so
/// the scheduler tick fires every `TIMESLICE_NS` and round-robin
/// between equal-priority ECs is honored. Without this call no LAPIC
/// timer interrupt ever fires and a CPU-bound EC runs forever until
/// it voluntarily yields.
pub fn perCoreInit() void {
    arch.time.getPreemptionTimer().armInterruptTimer(TIMESLICE_NS);
    // Enable hardware virtualization on this core (VMXON / EFER.SVME +
    // host save area). Required before any vCPU on this core can
    // VMLAUNCH/VMRUN; safe no-op when the platform doesn't support
    // hardware virt.
    arch.vm.vmPerCoreInit();
    // Per-core PMU enable. AMD PerfMonV2 (Zen 4+) requires writing
    // PerfCntrGlobalCtl on each core or every PMC stays gated even
    // with PerfEvtSel.EN set; on Intel and pre-PerfMonV2 AMD this is
    // a no-op. Must precede kprofTraceCountersPerCoreInit so the trace
    // counters tick on PerfMonV2 hardware.
    arch.pmu.pmuPerCoreInit();
    // Program kprof trace counters (PMC0/1/2 = cycles / cache misses /
    // branch misses). No-op unless `-Dkernel_profile=trace`. Counters
    // free-run; tracepoints snapshot them into each emitted record so
    // the post-processor can compute per-scope deltas.
    arch.pmu.kprofTraceCountersPerCoreInit();
}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Context switch to `ec` on the current core. Saves outgoing EC's
/// state to its `ctx`, swaps address space (if domain changed),
/// updates `current_ec`, applies lazy-FPU policy (arm/clear CR0.TS),
/// loads `ec.ctx` and returns to userspace via iretq/sysretq.
///
/// `current_ec` is written without the per-core lock — only this core
/// ever writes its own `current_ec`, and cross-core readers (FPU flush,
/// `coreRunning`) take an inherent snapshot semantics and re-check on
/// the target.
pub fn switchTo(ec: *ExecutionContext) void {
    // vCPU dispatch: spec-v3 §[create_vcpu] requires that every time the
    // vCPU EC becomes runnable (initial creation, reply-induced resume),
    // the kernel re-enters guest mode and on the subsequent guest exit
    // delivers a vm_exit event on its `exit_port`. Real VMX/SVM guest
    // re-entry (loadGuestState → VMLAUNCH/VMRESUME → exit decode) is
    // still a TODO in `arch/x64/hv/vcpu.zig` — until that lands, fire a
    // synthetic exit immediately so the recv/reply lifecycle remains
    // observable end-to-end. The vCPU re-suspends on its exit_port via
    // `fireVmExit` (which may rendezvous with a parked VMM receiver and
    // mark it ready) and we keep dispatching. We MUST NOT return here
    // with `current_ec == null` — the caller (yieldTo / dispatchInterrupt)
    // would iretq back to whatever interrupted-user RIP sits on the
    // kernel stack, and that EC has typically already been suspended
    // (e.g. fault path called fireThreadFault before yieldTo). The next
    // user fault on that stale RIP would re-enter `exceptionHandler`
    // with `currentEc() == null` and panic on the no-current-EC guard.
    // Loop instead: pick the next ready EC; if it's another vCPU, fire
    // its synthetic exit too; eventually we either dispatch a real EC
    // via `loadEcContextAndReturn` (noreturn) or run dry and fall
    // through to the empty-queue return path that leaves `current_ec`
    // null but is safe because `run()`'s outer `arch.cpu.idle()` and
    // `yieldTo`'s no-next branch are both designed for that.
    var current = ec;
    while (current.vm != null) {
        const core: u8 = @truncate(arch.smp.coreID());

        // Real VMX/SVM dispatch: load guest state, VMLAUNCH/VMRESUME,
        // save guest state on exit, decode the exit reason. Returns the
        // §[vm_exit_state] sub-code + 3-vreg payload for the event we
        // need to deliver. Falls back to a synthetic "unknown" exit on
        // platforms without hardware-virt support so the recv/reply
        // lifecycle still progresses.
        //
        // IRQs are disabled across the entry+exit window for two
        // reasons: (1) lockdep IRQ-mode consistency on the exit_port's
        // gen-lock (same class taken from async-IRQ context by
        // `expireTimedRecvWaiters`); (2) AMD VMRUN's required atomic
        // CLGI/STGI bracket — if a physical IRQ slipped in between
        // VMLOAD-host and VMRUN, host state would be inconsistent.
        clearCurrentEc(core);
        const irq = arch.cpu.saveAndDisableInterrupts();
        const delivery = arch.vm.enterGuest(current) orelse blk: {
            // Synthetic-exit fallback — covers two cases:
            //  (1) platforms without VMX/SVM at all
            //  (2) `arch_state.started == false` because the VMM has not
            //      yet supplied real initial guest state (spec §[reply]
            //      `initial_state` handshake)
            // Either way we re-deliver a vm_exit with sub-code
            // `initial_state` so the receiver observes the well-defined
            // not-yet-started condition rather than a synthetic cpuid /
            // unknown exit. Zero out ec.ctx.regs so the receiver sees a
            // clean "guest not running" GPR snapshot rather than the
            // prior `consumeReply`'s reply-time values.
            @memset(std.mem.asBytes(&current.ctx.regs), 0);
            break :blk arch.vm.VmExitDelivery{
                .subcode = zag.hv.virtual_machine.INITIAL_STATE_SUBCODE,
                .payload = .{ 0, 0, 0 },
            };
        };
        port_mod.fireVmExit(current, delivery.subcode, delivery.payload);
        arch.cpu.restoreInterrupts(irq);

        // The exit dispatch above may have rendezvoused with a parked
        // VMM receiver, putting it in this core's run queue. Pull it
        // (or anything else ready) and dispatch.
        const next = dequeueOrIdle() orelse return;
        current = next;
    }

    const core: u8 = @truncate(arch.smp.coreID());
    setCurrentEc(core, current);
    current.state = .running;
    kprof.point(.dispatch, @intFromPtr(current));
    arch.cpu.loadEcContextAndReturn(current);
}

/// Voluntary yield — current EC drops back into ready, scheduler
/// picks the next. If `target` is non-null and runnable, it runs next.
pub fn yieldTo(target: ?*ExecutionContext) void {
    kprof.enter(.yield);
    defer kprof.exit(.yield);

    const core: u8 = @truncate(arch.smp.coreID());
    const state = &core_states[core];
    const lock = &core_locks[core];

    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    if (state.current_ec) |cur_ref| {
        // caller-pinned: `current_ec` names the EC running on this core
        // — caller is in its syscall path so the slot is pinned.
        const cur = cur_ref.ptr;
        cur.state = .ready;
        state.run_queue.enqueue(cur);
    }
    const next = if (target) |t| blk: {
        if (t.state == .ready and state.run_queue.remove(t)) break :blk t;
        break :blk dequeueOrIdleLocked(core);
    } else dequeueOrIdleLocked(core);
    lock.unlockIrqRestore(irq);

    if (next) |n| {
        switchTo(n);
        return;
    }

    // Empty queue and no idle EC. Clear `current_ec` and return to the
    // caller — `dispatchInterrupt` then sends EOI and iretq's back to
    // the interrupted context. If that context was a halted
    // `scheduler.run`, control resumes past `hlt`, the loop iterates,
    // and `run` itself enters the top-level idle (outside any IRQ
    // handler) where halting won't strand the LAPIC's in-service
    // bit. Halting *here* would leave the timer IRQ never EOI'd —
    // any subsequent same-priority LAPIC tick would be blocked,
    // wedging the scheduler tick on this core.
    clearCurrentEc(core);
}

/// Preemption tick — invoked from the per-core timer interrupt when
/// the current EC's quantum expires. Re-enqueues current and dispatches.
pub fn preempt() void {
    yieldTo(null);
}

/// Main scheduler loop entry — called from `kMain` (BSP) and
/// `arch.x64.smp.coreInit` (APs) once their per-core state is ready.
/// Picks the highest-priority ready EC (or falls back to per-core idle
/// EC when set, otherwise `sti+hlt` until an IPI arrives), and
/// dispatches; never returns.
pub fn run() noreturn {
    while (true) {
        if (dequeueOrIdle()) |next| {
            switchTo(next);
        }
        // Either `dequeueOrIdle` found nothing and no idle EC was set
        // up for this core, or `switchTo` returned (it's `noreturn` on
        // the dispatch path, so this is the empty-queue case). Sleep
        // with interrupts enabled so a wake IPI breaks us out and the
        // loop re-runs `dequeueOrIdle`.
        arch.cpu.idle();
    }
}

/// Internal helper — dequeues the highest-priority EC, or returns the
/// per-core idle EC if the queue is empty. Returns null when both are
/// empty (caller drops to `sti+hlt` and waits for a wake IPI).
fn dequeueOrIdle() ?*ExecutionContext {
    const core: u8 = @truncate(arch.smp.coreID());
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    const result = dequeueOrIdleLocked(core);
    lock.unlockIrqRestore(irq);
    return result;
}

/// Lock-held variant of `dequeueOrIdle` — caller must hold
/// `core_locks[core]` with IRQs masked.
fn dequeueOrIdleLocked(core: u8) ?*ExecutionContext {
    const state = &core_states[core];
    while (state.run_queue.dequeue()) |ec| {
        // A cross-core terminate can flip an EC's state to .exited and
        // bump its slab gen between `enqueue` and `dequeue`. Drop those:
        // dispatching them would assert on the even gen in
        // `setCurrentEc`'s `SlabRef.init`, and the EC is reaped via the
        // pending_zombie path on its running core anyway.
        if (ec.state == .exited or ec._gen_lock.currentGen() % 2 == 0) continue;
        return ec;
    }
    if (state.idle_ec) |idle_ref| {
        // caller-pinned: per-core idle EC is allocated at perCoreInit and
        // never freed — it's the dispatch-of-last-resort target.
        return idle_ref.ptr;
    }
    return null;
}

// ── Enqueue / current accessors ──────────────────────────────────────

/// Enqueue `ec` on `core`'s run queue. Used by recv → ready transitions,
/// futex wake, timer fires, and the boot path.
///
/// Wake / preempt policy after queueing:
///   - target idle (no `current_ec`) and target != self: send wake IPI
///     so the parked `hlt` exits and `run` re-runs `dequeueOrIdle`.
///   - target current EC outranks `ec`: nothing to do — `ec` waits its
///     turn.
///   - `ec` outranks target's current EC: send a scheduler IPI to the
///     target. Self-IPI (when target == self) is LAPIC-ICR-based, so
///     it's IF-gated and fires once the caller exits its current IRQ /
///     spinlock-held window. We deliberately do NOT inline-yield: many
///     callers (e.g. `futex.wake`) hold a bucket lock across this call,
///     and a context-switch via `loadEcContextAndReturn` would strand
///     it.
pub fn enqueueOnCore(core: u8, ec: *ExecutionContext) void {
    ec.state = .ready;

    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    (&core_states[core]).run_queue.enqueue(ec);
    // Snapshot the target's current EC before deciding whether to
    // wake / preempt. Reading the remote core's `current_ec` is a racy
    // hint — the worst case if it changes after we decide is a spurious
    // wake or a missed preempt that the next preempt tick covers.
    const target_current = (&core_states[core]).current_ec;
    lock.unlockIrqRestore(irq);

    const self_core: u8 = @truncate(arch.smp.coreID());

    const target_current_ptr: ?*ExecutionContext = if (target_current) |r|
        // caller-pinned: read-only snapshot of target core's current_ec
        // for wake/preempt decision. Worst-case stale ptr just costs
        // a spurious IPI; real ptr deref is gated below.
        r.ptr
    else
        null;

    if (target_current_ptr == null) {
        // Idle target. Local self-wake is unnecessary — the caller is
        // running, not halted; the run loop will pick up `ec` on the
        // next dispatch.
        if (core != self_core) arch.smp.sendWakeIpi(core);
        return;
    }

    // Target is busy. Decide whether `ec` should preempt the running EC.
    // caller-pinned: snapshot ptr; race-tolerant priority compare.
    const cur = target_current_ptr.?;
    if (@intFromEnum(ec.priority) <= @intFromEnum(cur.priority)) return;

    // Same-core higher-pri: send a LAPIC self-IPI (deferred until the
    // caller exits the current critical section / IRQ handler and IF=1
    // is restored). We can't inline-yield here because callers like
    // `futex.wake` hold a bucket spinlock across `enqueueOnCore`, and
    // a context-switch via `loadEcContextAndReturn` would strand it.
    //
    // Cross-core higher-pri: same scheduler IPI. The receiver runs
    // `preempt()` which re-evaluates the queue and switches.
    arch.smp.triggerSchedulerInterrupt(core);
}

/// Enqueue `ec` on the kernel's choice of core, honoring `ec.affinity`.
pub fn enqueue(ec: *ExecutionContext) void {
    enqueueOnCore(pickCoreForAffinity(ec.affinity), ec);
}

/// Remove `ec` from whichever queue it currently occupies. Used by
/// terminate, priority change (reinsert), affinity change (migrate).
pub fn removeFromQueue(ec: *ExecutionContext) void {
    var i: u8 = 0;
    while (i < MAX_CORES) {
        const lock = &core_locks[i];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const removed = (&core_states[i]).run_queue.remove(ec);
        lock.unlockIrqRestore(irq);
        if (removed) return;
        i += 1;
    }
}

/// Currently dispatched EC on this core (the calling core).
///
/// IMPORTANT: indexes via `&core_states[i]` rather than the direct
/// `(&core_states[i]).field` form. In Debug builds Zig codegens the
/// latter as a `memcpy` of the entire `[MAX_CORES]PerCore` array onto
/// the caller's stack (≈ 6 KiB) followed by an index-of-the-copy
/// load — see `__zig_probe_stack` + `memcpy($0x1800, ...)` in the
/// disassembly. `currentEc` is on every page-fault, syscall, and
/// dispatch path, so unbounded 6 KiB-per-call stack blowups quickly
/// overflow the 48 KiB kernel stack and corrupt return addresses,
/// surfacing as `cpu.idle` returning to a `.bss` byte (#GP) or as
/// `pageFaultHandler` re-entering with `currentEc() == null` because
/// the stack-frame for the saved EC pointer was clobbered. Pointer
/// indexing avoids the per-call array snapshot.
pub fn currentEc() ?*ExecutionContext {
    const core: u8 = @truncate(arch.smp.coreID());
    const ref = (&core_states[core]).current_ec orelse return null;
    // caller-pinned: `current_ec` names the EC actually executing on this
    // very core; the slot can't be freed under us while this code runs.
    return ref.ptr;
}

/// True if this core's `current_ec` slot names `ec`. Identity-compare
/// helper used by suspend / terminate / fault paths to clear the
/// dispatch slot when the running EC parks itself.
pub inline fn coreCurrentIs(core: u8, ec: *ExecutionContext) bool {
    if ((&core_states[core]).current_ec) |ref| {
        // caller-pinned: identity compare on `current_ec` slot.
        return ref.ptr == ec;
    }
    return false;
}

/// Clear this core's `current_ec` slot. Called by suspend / terminate /
/// idle paths when the running EC stops being runnable.
pub inline fn clearCurrentEc(core: u8) void {
    if (comptime ec_log.enabled) {
        const prev: ?*ExecutionContext =
            if ((&core_states[core]).current_ec) |ref| ref.ptr else null;
        ec_log.mark(.clear_current_ec, prev, null);
    }
    (&core_states[core]).current_ec = null;
}

/// Set this core's `current_ec` to `ec`, capturing the gen at write time.
/// Also stamps `ec.last_dispatched_core` so cross-core `terminate` knows
/// where to post the deferred-finalize zombie — see the field doc on
/// `ExecutionContext.last_dispatched_core` for why this is necessary
/// (`current_ec` updates ahead of the actual kstack handoff in both
/// slow-path `switchTo` and FP step-14/R-14, so it can't be the
/// authority for "which core has the EC's kstack as rsp").
pub inline fn setCurrentEc(core: u8, ec: *ExecutionContext) void {
    if (comptime ec_log.enabled) {
        const prev: ?*ExecutionContext =
            if ((&core_states[core]).current_ec) |ref| ref.ptr else null;
        ec_log.mark(.set_current_ec, prev, ec);
    }
    (&core_states[core]).current_ec = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen());
    ec.last_dispatched_core = core;
}

/// True if this core's `current_ec` is null (idle).
pub inline fn coreIsIdle(core: u8) bool {
    return (&core_states[core]).current_ec == null;
}

/// Hand off `ec` to `core`'s pending_zombie slot. The next `switchTo`
/// on that core reaps it once the kstack swap moves execution off
/// `ec.kernel_stack`. Returns false if the slot already holds a
/// different zombie awaiting reap; the caller must spin until it
/// drains rather than overwrite (clobbering would leak the prior
/// zombie's kstack + slab slot).
/// `pre_bump_gen` is the EC's gen captured BEFORE `bumpDeadGenLocked`
/// flipped it to even — the SlabRef would otherwise assert on
/// `gen % 2 == 1` when constructed from the freed-parity gen. The
/// reap-side never calls `lockWithGen` against this ref (it's a
/// pointer-identity carrier; the slab is in its post-bump-pre-
/// destroyAlreadyMarked freed state), so the carried gen is just a
/// constructor-side parity placeholder.
pub fn postZombie(core: u8, ec: *ExecutionContext, pre_bump_gen: u63) bool {
    const pc = &core_states[core];
    // core_locks[core] serializes the read-modify-write of `pending_zombie`
    // against the target core's reap in arch.switchTo. Without this lock
    // the SlabRef (16 bytes — tag + ptr + gen) is read non-atomically by
    // the reader while another core writes it, producing torn reads:
    // .ptr from the new post combined with the old null tag, or vice
    // versa. The reaper would then `finalizeDestroyMarkedDead(garbage)`.
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    if (pc.pending_zombie) |existing| {
        if (existing.ptr != ec) return false;
        return true;
    }
    pc.pending_zombie = SlabRef(ExecutionContext).init(ec, pre_bump_gen);
    return true;
}

/// Self-help reaper: if THIS core has a pending zombie and we are not
/// standing on its kstack, finalize it inline. Called from terminate
/// before postZombie when target_core == self_core, to break the
/// self-deadlock where terminate's spin waits for switchTo to drain
/// the slot but switchTo never runs because terminate is spinning.
///
/// Returns the drained zombie's pointer for the caller to forward to
/// `finalizeDestroyMarkedDead` outside the lock-held section, or null
/// if nothing was reaped (slot empty, or rsp would have been on the
/// zombie's own kstack).
pub fn takeOwnPendingZombie() ?*ExecutionContext {
    const cid: u8 = @truncate(arch.smp.coreID());
    const lock = &core_locks[cid];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    const slot = &(&core_states[cid]).pending_zombie;
    const zr = slot.* orelse return null;
    const z = zr.ptr;
    const rsp_addr = arch.cpu.currentSp();
    const z_top = z.kernel_stack.top.addr;
    const z_base = z.kernel_stack.base.addr;
    const standing_on_zombie = rsp_addr >= z_base and rsp_addr < z_top;
    if (standing_on_zombie) return null;
    slot.* = null;
    return z;
}

// ── State transitions used by other subsystems ───────────────────────

/// Transition `ec` to ready and enqueue. Used by event delivery
/// resumes (reply, futex wake, timer fire, recv→ready, etc.).
pub fn markReady(ec: *ExecutionContext) void {
    ec.state = .ready;
    enqueue(ec);
}

/// Pick the right core for `ec` based on its affinity mask.
/// `affinity == 0` is the spec-defined "any core" sentinel; we fall
/// back to the calling core for cache locality.
fn pickCoreForAffinity(affinity: u64) u8 {
    if (affinity == 0) return @truncate(arch.smp.coreID());
    return @truncate(@as(u64, @ctz(affinity)));
}

// ── Lazy FPU coordination ────────────────────────────────────────────

/// Cross-core FPU flush — if `ec.last_fpu_core` points to a different
/// core than the calling core, IPI that core to FXSAVE its CPU regs
/// into `ec.fpu_state`, then clear `last_fpu_core`. Called before
/// the destination core arms its FPU trap so the trap handler can
/// safely FXRSTOR from a fresh buffer.
pub fn migrateFlush(ec: *ExecutionContext) void {
    _ = ec;
}

