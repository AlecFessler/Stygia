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
const execution_context = zag.sched.execution_context;
const kprof = zag.kprof.trace_id;
const port_mod = zag.sched.port;
const stack_mod = zag.memory.stack;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const Priority = zag.sched.execution_context.Priority;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Stack = zag.memory.stack.Stack;
const VAddr = zag.memory.address.VAddr;

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

    /// ECs handed off to this core for deferred destroy, indexed by
    /// POSTING core id. Each `terminate` on core P targeting an EC
    /// last-dispatched on core T writes `pending_zombie[P]` on core T's
    /// slab; the next `switchTo` / `parkAndAwaitIRQ` / `yieldTo`-empty
    /// on T walks all `MAX_CORES` columns and finalizes every non-null
    /// entry whose kstack isn't currently `rsp`.
    ///
    /// Per-poster slots eliminate the contention spin that the prior
    /// single-slot design hit when multiple cores simultaneously
    /// terminated ECs targeting the same core: each poster owns its
    /// column, so the only collision is same-poster-back-to-back which
    /// is rare in practice (terminate is single-syscall) and resolves
    /// in the next reap cycle.
    ///
    /// Stored as `SlabRef(ExecutionContext)` (rather than bare pointer)
    /// to satisfy the gen-lock-analyzer fat-pointer invariant — the gen
    /// captured at posting time is the *post-bump* even gen, and reap
    /// callers only use the `.ptr` for identity comparison +
    /// `finalizeDestroyMarkedDead` (which already operates on a `*EC`
    /// bypassing gen-lock checks because the slot is in its
    /// post-bump-pre-destroyAlreadyMarked state). No `lockWithGen`
    /// against these refs ever runs; the field type is a contract
    /// declaration only.
    pending_zombie: [MAX_CORES]?SlabRef(ExecutionContext) =
        [_]?SlabRef(ExecutionContext){null} ** MAX_CORES,

    /// Per-core "park" kstack — the kstack this core uses while no real
    /// EC is dispatched. Allocated at `perCoreInit`; sized like any
    /// other kernel stack (KERNEL_STACK_PAGES). When `run()` empties the
    /// queue and falls through the dispatch arm, `parkAndAwaitIRQ`
    /// swaps gs:0 / TSS.RSP0 / rsp to `park_stack.top` so subsequent
    /// kernel-mode IRQs and any future syscall entries land here
    /// instead of on the previously-suspended EC's kstack. Without
    /// this, multiple idle cores can hold stale `gs:0` pointing at the
    /// same suspended EC's kstack and concurrently push IRQ frames
    /// onto it from kernel mode — silent cross-core stack corruption
    /// that surfaces as iretq #GP / NO-EC PF when the corrupted slot
    /// is later popped.
    park_stack: Stack = .{
        .top = .{ .addr = 0 },
        .base = .{ .addr = 0 },
        .guard = .{ .addr = 0 },
        .slot = std.math.maxInt(u64),
    },

    /// EC whose `on_cpu` flag must be cleared after the next park-IRQ
    /// wake. Captured by `parkAndAwaitIRQ` from `current_ec` BEFORE the
    /// rsp swap so the post-wake landing pad knows which slab slot to
    /// clear without a stale-ref hazard. The wake's `scheduler_run_after_park`
    /// runs on the park kstack, with TSS.RSP0 already pointing at the
    /// park kstack — at that moment any kstack range comparison against
    /// the prev EC's kstack is safe (rsp no longer in range; TSS no
    /// longer references it), and clearing `on_cpu` lets the post-wake
    /// pending_zombie drain finally reap the EC. Without this clear, the
    /// only writer of prev's on_cpu is `switchTo`'s "current_ec → new"
    /// edge — but `parkAndAwaitIRQ` already cleared `current_ec` to null
    /// before sti+hlt, so that edge has nothing to read prev_ref from
    /// and the EC stays `on_cpu=true` forever (`takeOwnPendingZombie`
    /// keeps skipping it; the slab slot leaks).
    ///
    /// Stored as `SlabRef(ExecutionContext)` (rather than bare pointer)
    /// to satisfy the gen-lock-analyzer fat-pointer invariant. The
    /// post-wake reader takes `lock` → bumps `pop_gen`-style validation
    /// is not needed here: this slot is single-producer (the parking
    /// core writes it pre-park) / single-consumer (the same core reads
    /// it post-wake) and is consumed in the same task-context window
    /// during which the EC's slot cannot have been freed-and-realloced
    /// (`finalizeDestroyMarkedDead` skips ECs with `on_cpu=true`, which
    /// is exactly what this clear releases). The carried gen is a
    /// parity-correct placeholder for SlabRef constructor compatibility.
    post_park_clear_on_cpu: ?SlabRef(ExecutionContext) = null,
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
    // Allocate this core's park kstack. Used while the run queue is
    // empty AND no EC is dispatched — see `PerCore.park_stack` doc and
    // `parkAndAwaitIRQ`.
    const core: u8 = @truncate(arch.smp.coreID());
    const park = stack_mod.createKernel() catch @panic("park kstack alloc failed");
    var page_addr: u64 = park.base.addr;
    while (page_addr < park.top.addr) {
        const pmm_mgr = if (zag.memory.pmm.global_pmm) |*p| p else @panic("park kstack: pmm not ready");
        const page = pmm_mgr.create(zag.memory.paging.PageMem(.page4k)) catch @panic("park kstack: pmm OOM");
        const phys = zag.memory.address.PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        arch.paging.mapPage(
            zag.memory.init.kernel_addr_space_root,
            phys,
            VAddr.fromInt(page_addr),
            .{ .read = true, .write = true },
            .kernel_data,
        ) catch @panic("park kstack: map failed");
        page_addr += zag.memory.paging.PAGE4K;
    }
    (&core_states[core]).park_stack = park;

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
        const next = dequeueOrIdle() orelse {
            // Empty queue, no idle EC. Returning here unwinds to
            // run() (→ parkAndAwaitIRQ updates caches) or to yieldTo
            // (→ iretq back to the caller's user mode from the
            // current kstack). In either case `current_ec` is null
            // but the per-core caches (gs:0 kernel_rsp, TSS.RSP0,
            // gs:32/40/48/56/176 EC-identity slots) still name the
            // most-recently-dispatched EC's kstack. A peer-core
            // terminate of that EC can free its kstack at any time
            // after we drop the run-queue lock — the very next ring-3
            // → ring-0 entry on this core (timer IRQ, syscall, fault)
            // would push its iret frame onto freed memory, surfacing
            // as a silent triple-fault inside iret-frame setup OR a
            // re-entrant exception with `ctx` pointing into freed
            // slab (the XXXXFFFFXXXXX signature). Mirror yieldTo's
            // empty-queue cache park so any FUTURE entry uses this
            // core's park kstack. We do NOT swap rsp here — we still
            // need the current frame to return through the caller's
            // dispatch tail; the caller (run() or yieldTo) is on a
            // kstack that stays valid for the duration of its return.
            const park_top = (&core_states[core]).park_stack.top.addr;
            if (park_top != 0) {
                arch.cpu.parkPerCoreCaches(core, park_top);
            }
            return;
        };
        current = next;
    }

    const core: u8 = @truncate(arch.smp.coreID());
    // Clear the OUTGOING ec's on_cpu BEFORE setCurrentEc rewrites
    // current_ec to the new dispatch. The reaper inside
    // `interrupts.switchTo` reads `on_cpu` to decide whether a queued
    // zombie's kstack is still in use; without this clear, prev's
    // on_cpu stays `true` indefinitely (no later writer flips it
    // false) and the slot's pending_zombie post can never be reaped on
    // this core — the queue piles up and `postZombie` from cross-core
    // terminate spins.
    //
    // Clear prev's on_cpu only if prev still names US as its last
    // dispatched core. The `current_ec` slot can carry a STALE ref to
    // an EC that has since migrated to another core (the other core's
    // setCurrentEc bumps `last_dispatched_core` but doesn't reach back
    // to clear our slot). If we cleared on_cpu unconditionally on a
    // migrated EC, we'd flip its on_cpu false while it is actively
    // running on its new core; the reaper there sees on_cpu=false,
    // finalizes, unmaps the kstack mapped via TSS.RSP0 → next ring
    // transition triple-faults.
    if ((&core_states[core]).current_ec) |prev_ref| {
        if (prev_ref.ptr != current and prev_ref.ptr.last_dispatched_core == core) {
            prev_ref.ptr.on_cpu.store(false, .release);
        }
    }
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

    // Track an EC that needs cross-core enqueue after we drop the
    // local lock — see the affinity-aware branch below.
    var deferred_cross_core: ?*ExecutionContext = null;

    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    if (state.current_ec) |cur_ref| {
        // caller-pinned: `current_ec` names the EC running on this core
        // — caller is in its syscall path so the slot is pinned.
        const cur = cur_ref.ptr;
        // A peer-core terminate may have flipped state to .exited
        // before this preempt fired. Don't resurrect a terminated EC
        // by overwriting state and re-enqueueing — terminate already
        // removed it from every queue (`removeFromQueue`) and posted
        // its zombie; pulling it back into a run queue would dispatch
        // a freed slab next tick. Same gate covers the .suspended /
        // .idle_wait / .futex_wait cases where another path took
        // ownership of the EC's lifecycle and yieldTo musn't trample.
        if (cur.state == .running) {
            cur.state = .ready;
            // Honor affinity. If `cur` is no longer allowed on this
            // core (e.g. setAffinity excluded it mid-quantum) hand it
            // off to a satisfying core — but only when the local
            // queue has a replacement to dispatch. Without one, a
            // local re-enqueue is the safe fallback (the next preempt
            // with a non-empty queue migrates it; the explicit
            // `setAffinity`-side reposition also catches the case
            // when callers change affinity from off-core). `affinity
            // == 0` is the spec "any core" sentinel.
            const local_allowed = cur.affinity == 0 or
                (core < 64 and (cur.affinity & (@as(u64, 1) << @truncate(core))) != 0);
            if (local_allowed or state.run_queue.isEmpty()) {
                state.run_queue.enqueue(cur);
            } else {
                deferred_cross_core = cur;
            }
        }
    }
    const next = if (target) |t| blk: {
        if (t.state == .ready and state.run_queue.remove(t)) {
            // Same kstack-livesness rationale as dequeueOrIdleLocked's
            // stamp: we are committing `t` to dispatch on this core
            // under core_locks[core]. A cross-core terminate(t) that
            // races after we drop the lock must observe
            // `t.last_dispatched_core == core` to defer the reap to
            // this core's pending_zombie column rather than inline-
            // free t's kstack while we're about to land on it.
            t.last_dispatched_core = core;
            break :blk t;
        }
        break :blk dequeueOrIdleLocked(core);
    } else dequeueOrIdleLocked(core);
    lock.unlockIrqRestore(irq);

    // Cross-core enqueue runs unlocked: `enqueueOnCore` acquires the
    // target core's lock, and we mustn't hold two `core_locks`
    // simultaneously outside the registered ordered group. The EC's
    // state was stamped `.ready` under the local lock, so any racing
    // path that grabs it via `removeFromQueue` first sees no queue
    // residence and just falls through to its normal handling.
    if (deferred_cross_core) |cur| {
        enqueueOnCore(pickCoreForAffinity(cur.affinity), cur);
    }

    if (next) |n| {
        switchTo(n);
        return;
    }

    // Empty queue and no idle EC. Clear `current_ec` and re-point the
    // per-core caches (gs:0 kernel_rsp, TSS.RSP0) at this core's park
    // kstack BEFORE returning. Without this re-point, the caches still
    // name the previously-dispatched EC's kstack — and a peer-core
    // terminate of that EC can free its kstack at any time after we
    // unlock. The next ring-3→ring-0 entry on THIS core (timer IRQ /
    // syscall / fault) would then push its iret frame onto freed memory,
    // surfacing as a silent triple-fault inside iret-frame setup OR
    // re-entrant exception with `ctx` pointing into freed slab.
    //
    // We DO NOT swap rsp to the park kstack here — we still need the
    // current frame to return through `dispatchInterrupt`'s EOI + iretq
    // epilogue. The cache-only update is sufficient: rsp is preserved
    // for the in-flight return, and any FUTURE entry uses the park
    // kstack (or whatever EC subsequently dispatches on this core,
    // which `setCurrentEc` re-points at).
    //
    // Halting *here* would leave the IRQ never EOI'd — any subsequent
    // same-priority LAPIC tick would be blocked, wedging the scheduler
    // tick on this core.
    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top != 0) {
        arch.cpu.parkPerCoreCaches(core, park_top);
    }
    // Clear the previously-current EC's on_cpu flag now that TSS.RSP0
    // has been retargeted at the park kstack. Future ring transitions
    // on this core no longer push iret frames onto prev's kstack, so
    // a reap that unmaps it is safe. Without this clear, the only
    // writer of prev's on_cpu is `switchTo`'s "current_ec → new" edge,
    // but `clearCurrentEc(core)` below sets the slot to null, leaving
    // the next dispatch on this core with no `prev_ref` to drive the
    // clear from. The EC stays `on_cpu=true` forever — every reap pass
    // (`takeOwnPendingZombie`) skips it, the kstack stays mapped, and
    // the slab slot leaks. Same window as parkAndAwaitIRQ; same fix.
    if ((&core_states[core]).current_ec) |prev_ref| {
        if (prev_ref.ptr.last_dispatched_core == core) {
            prev_ref.ptr.on_cpu.store(false, .release);
        }
    }
    clearCurrentEc(core);

    // Drain any pending_zombie before returning — same rationale as
    // parkAndAwaitIRQ. yieldTo's empty branch returns through
    // dispatchInterrupt → iretq without going through `run()` /
    // `parkAndAwaitIRQ`, so without this drain a peer-core terminate
    // posting to this slot has no other reaper. takeOwnPendingZombie
    // skips when standing on the zombie's kstack so a same-EC pending
    // zombie is correctly deferred. Called from IRQ context (preempt
    // path); finalize takes port + CD locks via lockIrqSave which is
    // safe — both classes are already classified as IRQ-acquired by
    // expireTimedRecvWaiters.
    while (takeOwnPendingZombie()) |z| {
        execution_context.finalizeDestroyMarkedDead(z);
    }
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
        // Run queue empty and no idle_ec set up. Park this core on its
        // dedicated park kstack and sti+hlt until an IRQ wakes us.
        // `parkAndAwaitIRQ` swaps rsp / gs:0 / TSS.RSP0 / per-core
        // caches to park-state and tail-jumps back into `run()` on
        // wake — the outer call frame on the previously-dispatched
        // EC's kstack is abandoned. This eliminates the cross-core
        // kstack-sharing bug where multiple idle cores held stale
        // gs:0 pointing at the same suspended EC's kstack and
        // concurrently pushed IRQ frames onto it from kernel mode,
        // silently stomping each other's saved state and surfacing
        // as iretq #GP or NO-EC PF when the corrupted iret slot was
        // later popped.
        parkAndAwaitIRQ();
    }
}

/// Park this core on its per-core park kstack and idle until an IRQ
/// arrives. Updates the per-core caches (gs:0/32/40/48/56/176, TSS.RSP0,
/// PerCore.current_ec) to "no EC dispatched" state, swaps rsp to the
/// park kstack top, then sti+hlt. On IRQ-driven wake jumps back into
/// `run()` via the exported entry symbol — the original caller's call
/// frame is abandoned (we are noreturn). See `PerCore.park_stack`.
fn parkAndAwaitIRQ() noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top == 0) @panic("parkAndAwaitIRQ: park_stack not initialized");

    // Drain pending_zombie before parking: a peer-core terminate posted
    // a zombie to this core's slot expecting our next switchTo to reap.
    // But if our run_queue is empty we never enter switchTo — we go
    // straight from here to sti+hlt, leaving the zombie pinned forever.
    // A second peer-core terminate against the same target then spins
    // in postZombie waiting for us to drain, but we never will. With
    // reply FP enabled this scenario fires on smp=4 batches that
    // saturate the destroy machinery (terminate_05..08, yield_04, etc.).
    // takeOwnPendingZombie skips when standing-on-zombie (still on the
    // caller's kstack here, before the asm rsp swap), so a same-EC
    // pending zombie is correctly deferred to the next iteration.
    while (takeOwnPendingZombie()) |z| {
        execution_context.finalizeDestroyMarkedDead(z);
    }

    // Stash the previously-dispatched EC ref so the post-wake landing
    // pad can clear its `on_cpu` flag. Without this, an EC that was
    // dispatched on this core (e.g. a `dummyEntry` worker EC running
    // `hlt`) and then has its owning capability domain destroyed leaves
    // `on_cpu=true` indefinitely: the only writer that clears prev's
    // on_cpu is `switchTo`'s "current_ec → new" edge, but parkAndAwaitIRQ
    // sets `current_ec = null` here before any subsequent dispatch, so
    // that edge has nothing to clear from. The post-wake drain is what
    // actually catches the zombie now that its kstack is no longer in
    // use on this core.
    const prev_ec_to_clear: ?SlabRef(ExecutionContext) = blk: {
        if ((&core_states[core]).current_ec) |prev_ref| {
            // Match scheduler.switchTo's discipline: only clear when this
            // core was the EC's last_dispatched_core. The slot can carry
            // a stale ref to an EC that migrated; the other core owns
            // its on_cpu lifecycle in that case.
            if (prev_ref.ptr.last_dispatched_core == core) break :blk prev_ref;
        }
        break :blk null;
    };
    (&core_states[core]).post_park_clear_on_cpu = prev_ec_to_clear;

    // Update per-core caches FIRST while still on the caller's stack.
    // After the rsp swap below, locals on this stack frame go
    // unreferenced; the outer noreturn semantics make abandonment
    // safe.
    arch.cpu.parkPerCoreCaches(core, park_top);
    (&core_states[core]).current_ec = null;

    arch.cpu.parkAndAwaitIRQ(park_top);
}

/// Asm landing pad after `parkAndAwaitIRQ`'s wake: rsp is on the park
/// kstack, IRQs are masked. Re-enter `run()` to re-check the queue.
/// `run()` is noreturn so the call never returns; the pushed return
/// address sits unused on the park stack.
export fn scheduler_run_after_park() callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    // Clear the previously-dispatched EC's `on_cpu` flag now that we
    // are on the park kstack. TSS.RSP0 was repointed by parkPerCoreCaches
    // before sti+hlt, and the rsp swap moved us off the prev EC's kstack
    // entirely — neither hardware nor any code on this core references
    // the prev kstack. Clearing on_cpu unblocks `takeOwnPendingZombie`
    // for any zombie that pinned this slot during the park.
    const state_ptr = &core_states[core];
    if (state_ptr.post_park_clear_on_cpu) |prev_ref| {
        // caller-pinned: single-producer/single-consumer slot written by
        // this same core in `parkAndAwaitIRQ` immediately before sti+hlt.
        // The EC slab slot cannot have been freed in the park window
        // because `finalizeDestroyMarkedDead` skips ECs with on_cpu=true,
        // and that flag is exactly what this clear is about to release.
        prev_ref.ptr.on_cpu.store(false, .release);
        state_ptr.post_park_clear_on_cpu = null;
    }
    // Re-drain pending_zombie now that the prev EC's on_cpu is false.
    // The pre-park drain ran while the kstack was still in use (we were
    // standing on it) and skipped via the standing_on_zombie /
    // on_cpu=true gates. With both gates released we can reap.
    while (takeOwnPendingZombie()) |z| {
        execution_context.finalizeDestroyMarkedDead(z);
    }
    run();
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
        // Stamp `last_dispatched_core` here, while still holding
        // `core_locks[core]`, so a cross-core `terminate(ec)` that lands
        // AFTER our dequeue but BEFORE our `setCurrentEc` finds the
        // correct value rather than the stale `LAST_DISPATCHED_NEVER`
        // sentinel. See "kstack-livesness ordering" below.
        //
        // ── kstack-livesness ordering ──────────────────────────────────
        //
        // Without this stamp, the slow-path race is:
        //
        //   core A: dequeueOrIdle()       → takes core_locks[A]
        //   core A: state.run_queue.dequeue() → ec
        //   core A: drops core_locks[A]
        //   core A: <window — has not yet called setCurrentEc>
        //   core B: terminate(ec) runs:
        //     - removeFromQueue sweeps every core's queue under that
        //       core's lock; ec is in NONE (A already dequeued it).
        //     - state = .exited; second sweep — still nothing.
        //     - bumpDeadGenLocked flips gen to even.
        //     - reads ec.last_dispatched_core == LAST_DISPATCHED_NEVER
        //     - calls finalizeDestroyMarkedDead(ec) INLINE
        //         → stack.destroyKernel frees ec.kernel_stack pages.
        //   core A: setCurrentEc(A, ec) → loadEcContextAndReturn(ec)
        //            → arch.switchTo writes TSS.RSP0 = ec.kernel_stack.top,
        //              jmps to ec.ctx → iretq onto FREED kstack
        //              → iretq #GP at batch 168 (smp=4 reproducer).
        //
        // The fix: stamp last_dispatched_core under core_locks[core], so
        // that terminate's `removeFromQueue` sweep (which serializes
        // through that same lock) cannot read the stamp until after our
        // dequeue commit. Once stamped, terminate's last_dispatched_core
        // read in the post-bumpGen branch sees `core` and posts the
        // zombie to core A's pending_zombie column — A's next switchTo
        // (or park-drain) reaps it AFTER A has moved off the kstack.
        //
        // The terminate-path read of `last_dispatched_core` happens after
        // the `removeFromQueue` second sweep + bumpGen. Both halves are
        // synchronised against this stamp via core_locks[core]: the
        // removeFromQueue sweep takes core_locks[i] for every i in turn,
        // so by the time terminate gets to the post-bumpGen branch, every
        // core's lock has been acquired-and-released, publishing this
        // stamp via the lock release.
        //
        // Stamping here is a "floor" for last_dispatched_core: it may
        // be overwritten by setCurrentEc (slow path) or by FP step-14 /
        // R-14 (IPC fast path) when the EC actually lands on a different
        // core later. That's fine — last_dispatched_core has only one
        // monotone safety property: "names a core whose pending_zombie
        // column is a safe place to defer this EC's reap." Any core that
        // has held the EC's kstack alive (via dequeue or actual rsp use)
        // satisfies that.
        //
        // Note: the slow-path scheduler.switchTo's vCPU loop may dequeue
        // an EC, fire its synthetic vm_exit, re-suspend it on its
        // exit_port, and then dequeue another — never actually using the
        // first EC's kstack as rsp. The stamp on the first vCPU EC still
        // names this core; that's fine (false-positive zombie post → one
        // extra reap pass, no correctness impact).
        ec.last_dispatched_core = core;
        return ec;
    }
    if (state.idle_ec) |idle_ref| {
        // caller-pinned: per-core idle EC is allocated at perCoreInit and
        // never freed — it's the dispatch-of-last-resort target.
        idle_ref.ptr.last_dispatched_core = core;
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

/// Hand off `ec` to `core`'s pending_zombie array, in this poster's
/// own column. Reap on `core` walks the whole array each cycle and
/// finalizes every non-null entry whose kstack isn't currently `rsp`.
/// Returns false only on same-poster-back-to-back contention (this
/// poster's previous zombie hasn't been reaped on `core` yet);
/// caller spins until that drains rather than clobber.
/// `pre_bump_gen` is the EC's gen captured BEFORE `bumpDeadGenLocked`
/// flipped it to even — the SlabRef would otherwise assert on
/// `gen % 2 == 1` when constructed from the freed-parity gen. The
/// reap-side never calls `lockWithGen` against this ref (it's a
/// pointer-identity carrier; the slab is in its post-bump-pre-
/// destroyAlreadyMarked freed state), so the carried gen is just a
/// constructor-side parity placeholder.
pub fn postZombie(core: u8, ec: *ExecutionContext, pre_bump_gen: u63) bool {
    const self_core: u8 = @truncate(arch.smp.coreID());
    const pc = &core_states[core];
    // core_locks[core] serializes the read-modify-write of one
    // pending_zombie column against the target core's reap walk in
    // arch.switchTo. Without this lock the SlabRef (16 bytes — tag +
    // ptr + gen) is read non-atomically by the reader while another
    // core writes it, producing torn reads: .ptr from the new post
    // combined with the old null tag, or vice versa. The reaper would
    // then `finalizeDestroyMarkedDead(garbage)`. The lock is per-target
    // (not per-poster column) because the reaper walks all columns.
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    const slot = &pc.pending_zombie[self_core];
    if (slot.*) |existing| {
        if (existing.ptr == ec) return true;
        return false;
    }
    slot.* = SlabRef(ExecutionContext).init(ec, pre_bump_gen);
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
    const slots = &(&core_states[cid]).pending_zombie;
    const rsp_addr = arch.cpu.currentSp();
    var i: u8 = 0;
    while (i < MAX_CORES) : (i += 1) {
        const zr = slots[i] orelse continue;
        const z = zr.ptr;
        // `on_cpu` is the EC's "kstack is live somewhere" flag — set by
        // every dispatch path (suspend FP step 14, reply FP R14, slow
        // `switchTo`) before the swap that hands ring 3 control to the
        // EC, cleared on the next preempt away from it. Reaping under
        // on_cpu would unmap an in-use kstack: the reply FP race
        // sysretq's into a freshly-resumed sender whose terminate
        // posted a zombie to last_dispatched_core (= us); after the
        // sysretq the on-stack is the user-mode rsp, so the rsp-only
        // standing_on_zombie check below misses it, and finalize would
        // unmap the kstack mapped via TSS.RSP0 → next ring transition
        // pushes an iret frame at unmapped → #PF → #DF → triple-fault.
        const ec_on_cpu = z.on_cpu.load(.acquire);
        if (ec_on_cpu) continue;
        const z_top = z.kernel_stack.top.addr;
        const z_base = z.kernel_stack.base.addr;
        const standing_on_zombie = rsp_addr >= z_base and rsp_addr < z_top;
        if (standing_on_zombie) continue;
        slots[i] = null;
        return z;
    }
    return null;
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
/// safely FXRSTOR from a fresh buffer. Delegates to `sched.fpu` which
/// owns the per-arch mailbox protocol.
pub fn migrateFlush(ec: *ExecutionContext) void {
    zag.sched.fpu.migrateFlush(ec);
}

