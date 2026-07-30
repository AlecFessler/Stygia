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
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const ec_log = stygia.utils.ec_log;
const memory_init = stygia.memory.init;
const execution_context = stygia.sched.execution_context;
const kprof = stygia.kprof.trace_id;
const port_mod = stygia.sched.port;
const stack_mod = stygia.memory.stack;

const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const NOT_IN_RUN_QUEUE = stygia.sched.execution_context.NOT_IN_RUN_QUEUE;
const PerfmonState = stygia.sched.perfmon.PerfmonState;
const Priority = stygia.sched.execution_context.Priority;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const SpinLock = stygia.utils.sync.SpinLock;
const Stack = stygia.memory.stack.Stack;
const VAddr = stygia.memory.address.VAddr;

/// Intrusive priority queue of ECs, linked through the EC's `next`
/// field and ordered by `priority`. Shared by per-core run queues and
/// port wait queues. Futex buckets use a separate WaitNode-based queue
/// (see sched/futex.zig).
pub const EcQueue = stygia.sched.priority_queue.PriorityQueue(
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

    /// Physical address of the user translation root this core has
    /// LOADED (x86: CR3 root; aarch64: TTBR0), published with
    /// `.release` immediately AFTER each hardware root load. 0 = no
    /// user root (kernel root / parked / detached). This — not
    /// `on_cpu`, not `current_ec` — is the authoritative "may this
    /// core still walk translations of root R" signal that domain
    /// teardown must wait on before freeing R's tables (stygia-rs6):
    /// `on_cpu` stays stale-true across the migration boundary and
    /// its gated clears race, and `current_ec` flips BEFORE the
    /// dispatch path's root swap. Publishing after the load closes
    /// both windows.
    active_root: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Dispatch commitment, written UNDER `core_locks[core]` at the
    /// moment a dequeue (or yieldTo target-arm pick) commits an EC to
    /// this core, and cleared by the dispatch path once the EC's root
    /// is loaded+published (or by the park path). Exists because the
    /// window between the locked dequeue and `setCurrentEc` is
    /// unbounded under host vCPU preemption (KVM can deschedule this
    /// core mid-window for milliseconds), so domain teardown cannot
    /// rely on either `current_ec` or `active_root` becoming visible
    /// "soon" — instead the teardown barrier acquires each core lock
    /// once after the gen flips, which by lock ordering makes every
    /// pre-flip commitment visible here. Stale values are benign in
    /// the conservative direction only (the barrier waits longer);
    /// every path that abandons a commitment overwrites or clears it
    /// within one scheduler-loop iteration.
    /// caller-pinned: bare `*T` is deliberate — readers (the teardown
    /// barrier) perform identity-only compares of `.domain.ptr`
    /// against a raw CD key and never lock through this pointer. A
    /// committed EC's slab bytes cannot be recycled under the reader:
    /// the dequeue stamped `last_dispatched_core` under the same lock
    /// as this field, routing any concurrent terminate through the
    /// deferred-zombie path (bytes intact until this core's next
    /// switchTo reap, which cannot run while the commitment stands).
    committed_ec: ?*ExecutionContext = null,

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

    /// EC whose kstack this core is STILL EXECUTING ON even though the
    /// EC itself has already been published as claimable (recv/futex/
    /// suspend parked it, or a peer disowned it mid-quantum). The slot
    /// is the deferred half of the kstack-release protocol:
    ///
    ///   `ec.on_cpu == false  ⟹  no core is executing on ec's kstack`
    ///
    /// The old code cleared `on_cpu` at the park/suspend site itself —
    /// while the caller was still running on that very kstack, and kept
    /// running on it through `run()` → `switchTo` → the arch dispatch
    /// tail (reaper, CR3 swap, migrateFlush, EOI). A waker on another
    /// core would pass its `on_cpu` spin, enqueue, and dispatch the EC;
    /// the EC's next kernel entry then built frames down the same
    /// kstack the parking core was still using. Mutual frame stomp;
    /// observed as a runaway memcpy in `syscallDispatch` crossing the
    /// kstack guard ("Kernel stack overflow" panics) and as corrupted
    /// scheduler state wedges.
    ///
    /// Now the suspend sites STASH the EC here instead of clearing the
    /// flag, and the flag is cleared by `arch.cpu.hopToStackAndCall` /
    /// the park landing pad — i.e. at the exact instruction after which
    /// this core provably never touches the old kstack again. Written
    /// and consumed only by this core (single producer/consumer); the
    /// EC slab slot cannot be freed while `on_cpu` is true, which is
    /// precisely what the stash keeps set.
    pending_kstack_release: ?*ExecutionContext = null,

    /// EC that must be enqueued on a DIFFERENT core (affinity
    /// migration) but whose kstack this core is still executing on.
    /// `yieldTo`'s old code cross-enqueued immediately and then ran the
    /// whole dispatch tail on the migrating EC's kstack — the target
    /// core could dispatch it and reuse the kstack top while this
    /// core's frames were live on it. The migration arm now stashes the
    /// EC here and escapes to the park kstack; `scheduler_hop_run`
    /// consumes the slot AFTER the hop (clearing `on_cpu`, then
    /// enqueueing), so the target core can only ever see a fully
    /// released kstack. Single producer/consumer per core, same
    /// pinning argument as `pending_kstack_release`.
    pending_cross_enqueue: ?*ExecutionContext = null,

    /// True when this core's most recent dispatch decision — taken
    /// under `core_locks[core]` inside `dequeueOrIdleLocked` — found
    /// nothing to run, i.e. the core is heading for (or already
    /// sitting in) its idle park.
    ///
    /// This exists because `enqueueOnCore`'s wake decision cannot use
    /// `current_ec` alone. `current_ec` is cleared by the parking core
    /// AFTER it has dropped `core_locks[core]` (see `yieldTo`'s
    /// empty-queue arm and `run`'s park fall-through, both of which
    /// need the old value for their disowned-EC bookkeeping first), so
    /// there is a window in which the core has committed to parking but
    /// its slot still names the EC it was running. An `enqueueOnCore`
    /// landing in that window reads a non-null `current_ec`, concludes
    /// "target is busy, it will pick the EC up at its next reschedule",
    /// skips the wake IPI — and the target then parks forever with a
    /// `.ready` EC sitting in its queue. The EC is never dispatched and
    /// whatever was waiting on it (a test result, an IPC reply) never
    /// arrives. Nothing else necessarily disturbs that core: futex
    /// wakes and affinity-0 enqueues both prefer the *local* core, so
    /// an idle core can stay untargeted indefinitely.
    ///
    /// Publishing the parking decision under the same lock that guards
    /// the run queue closes the window in both directions:
    ///   - enqueuer wins the lock: it queues the EC before the parking
    ///     decision is made, so `dequeueOrIdleLocked` returns that EC
    ///     and the core never parks.
    ///   - parker wins the lock: `idle_parked` is already true when the
    ///     enqueuer reads it, so the wake IPI is sent. A wake that
    ///     arrives before the core reaches its `wfi`/`hlt` is not lost —
    ///     both arch park paths sleep with the IRQ masked-but-pending
    ///     wake semantics documented at `arch.cpu.parkAndAwaitIRQ`.
    ///
    /// Cleared at every dispatch commitment (both `dequeueOrIdleLocked`
    /// success returns and `yieldTo`'s explicit-target arm), all under
    /// `core_locks[core]`. A stale `true` would only cost a spurious
    /// wake IPI, never correctness.
    idle_parked: bool = false,
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
        const pmm_mgr = if (stygia.memory.pmm.global_pmm) |*p| p else @panic("park kstack: pmm not ready");
        const page = pmm_mgr.create(stygia.memory.paging.PageMem(.page4k)) catch @panic("park kstack: pmm OOM");
        const phys = stygia.memory.address.PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        arch.paging.mapPage(
            stygia.memory.init.kernel_addr_space_root,
            phys,
            VAddr.fromInt(page_addr),
            .{ .read = true, .write = true },
            .kernel_data,
        ) catch @panic("park kstack: map failed");
        page_addr += stygia.memory.paging.PAGE4K;
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

/// The EC's `PerfmonState` if perfmon is armed on it and the slab slot
/// still names the generation the EC's ref was minted against. Null
/// when perfmon was never started, was stopped, or the state has been
/// released underneath us (EC destroy).
inline fn livePerfmonState(ec: *ExecutionContext) ?*PerfmonState {
    const ref = ec.perfmon_state orelse return null;
    // caller-pinned: the gen compare below IS the liveness check — we
    // cannot take the gen-lock here because `pmuSwitch` runs in the
    // dispatch path with IRQs masked and no lock-order slot. A stale
    // gen means the slot was freed and we skip it entirely.
    if (ref.ptr._gen_lock.currentGen() != @as(u64, ref.gen)) return null;
    return ref.ptr;
}

/// Hand the per-core PMU counter file from the outgoing EC to `next`.
/// Called from `switchTo` while `current_ec` still names the outgoing
/// EC, i.e. before `setCurrentEc`.
///
/// The PMU register file is per-core hardware, but `perfmon_read`
/// reports counts per EC: it samples the live registers via `pmuSave`
/// and spec §[execution_context].perfmon_read requires each counter to
/// be "greater than or equal to the value returned by the prior
/// perfmon_read on that target". With no context-switch handoff, an EC
/// that migrates between two reads samples the DESTINATION core's
/// register file — another thread's counts, or zero on a core that
/// never programmed the PMU at all (PMCR_EL0.E clear on aarch64,
/// IA32_PERF_GLOBAL_CTRL clear on x86) — and the second read comes back
/// below the first. That is the `perfmon_read_06` aid=5 "cycles ran
/// backward" failure seen on Pi 5 KVM.
///
/// `pmuRestore` reprograms the event selectors and writes the EC's
/// saved values back into the hardware counters, so counts accumulate
/// across cores; `pmuSave` reads them back out and disables counting.
/// Pairing them here gives the invariant the spec wants: while an EC
/// with perfmon armed is running, its core's counters hold values >=
/// the EC's saved values, and the saved values only ever move forward.
///
/// `PerfmonState.hw_core` is the ownership token. It is needed because
/// `current_ec` can name an EC that has since migrated (see the
/// `on_cpu` clear in `switchTo`): saving that EC would capture THIS
/// core's unrelated counters into a state its new core is actively
/// driving, moving the saved values backwards — the very bug we are
/// closing. Only the core that last restored the EC may save it.
///
/// Not every switch-away runs through here: the escape-to-`run()` and
/// park paths clear `current_ec` without a `switchTo`, so an EC parked
/// that way leaves its counters enabled on the core until something
/// else restores over them. That loses the counts of the final quantum
/// but cannot violate monotonicity, because the EC's next dispatch
/// re-`pmuRestore`s from its own saved values on whatever core it
/// lands on.
fn pmuSwitch(core: u8, next: *ExecutionContext) void {
    const state = &core_states[core];

    const next_ps = livePerfmonState(next);
    var prev_ps: ?*PerfmonState = null;
    if (state.current_ec) |prev_ref| {
        // caller-pinned: identity read of this core's own `current_ec`
        // slot, gen-checked before the deref.
        if (prev_ref.ptr._gen_lock.currentGen() == @as(u64, prev_ref.gen)) {
            prev_ps = livePerfmonState(prev_ref.ptr);
        }
    }

    // Fast path: no perfmon anywhere near this dispatch. Every context
    // switch in a system that never called `perfmon_start` lands here,
    // so it must not touch the PMU registers (each is a trap-and-emulate
    // exit under KVM on aarch64).
    if (prev_ps == null and next_ps == null) return;

    if (prev_ps) |ps| {
        // `ps != next_ps` skips the pointless save/restore round trip
        // when the same EC is being re-dispatched on the same core.
        if (ps.hw_core == core and ps != next_ps) {
            arch.pmu.pmuSave(&ps.arch_state);
            ps.hw_core = null;
        }
    }
    if (next_ps) |ps| {
        if (ps.hw_core != core) {
            arch.pmu.pmuRestore(&ps.arch_state);
            ps.hw_core = core;
        }
    }
}

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
    // Dispatch-side half of the two-cores-one-frame fix. `on_cpu` means
    // "this EC's kstack is live on some core" — set by every dispatch
    // path before the SP/ring swap, cleared when that core switches
    // away. An EC can become CLAIMABLE (suspend publishes it, a waker's
    // tryClaimWake wins, it lands in a run queue) while the core that
    // suspended it is still unwinding kernel frames on its kstack.
    // Dispatching it here would resume the same stack on two cores —
    // measured on the Pi 5 rig as core 0 running lockdep bookkeeping on
    // slot 36 while core 1's current EC owned slot 36 with on_cpu=1.
    // Re-enqueue and let the previous core's next switch-away release
    // it; the wake is not lost, only deferred. `last == self` proceeds:
    // our own stale flag covers frames WE abandoned, and blocking on it
    // would deadlock the clear that only happens further down this very
    // function.
    {
        const self: u8 = @truncate(arch.smp.coreID());
        if (ec.last_dispatched_core != execution_context.LAST_DISPATCHED_NEVER and
            ec.last_dispatched_core != self and
            ec.on_cpu.load(.acquire))
        {
            enqueue(ec);
            return;
        }
    }
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
                .subcode = stygia.hv.virtual_machine.INITIAL_STATE_SUBCODE,
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
            // `dequeueOrIdle` above set `idle_parked` because it found
            // nothing to run — but this is the one exit from a dispatch
            // decision that does NOT lead to a park. We return into
            // `yieldTo`, which either escapes to `run()` (whose own
            // `dequeueOrIdle` re-establishes the flag correctly) or
            // iretqs back to the caller's user mode, leaving this core
            // busy. Clearing here is right for both: a stale `true` on
            // a running core makes every `enqueueOnCore` targeting it
            // send a wake IPI, and on x86 that vector IS the scheduler
            // vector (`IntVecs.sched` — see `arch.smp.sendWakeIpi`), so
            // the "wake" preempts an EC that was running fine. That
            // shows up as latency, e.g. `timer_rearm_09`'s 5 ms
            // arm-then-observe window closing late.
            (&core_states[core]).idle_parked = false;
            return;
        };
        current = next;
    }

    const core: u8 = @truncate(arch.smp.coreID());
    // ── kstack hop ───────────────────────────────────────────────────
    //
    // Everything from here to the iretq trampoline used to execute on
    // whatever kstack the caller happened to be standing on — usually
    // the OUTGOING EC's. That is fatal whenever the outgoing EC is
    // already claimable by another core (recv/futex/suspend published
    // its wait state; a preempt re-enqueued it): the other core
    // dispatches it, the EC's next kernel entry builds frames from its
    // kstack top downward, and both cores stomp each other's live
    // frames on one kstack. Autopsied as core 2's `syscallDispatch`
    // memcpy running away over the kstack guard (Kernel stack overflow
    // panic) with core 1's switchTo/loadEcContextAndReturn frames
    // interleaved on the same kstack.
    //
    // Hop to this core's park kstack FIRST, releasing the pending
    // kstack-release stash (if any) at the exact swap instruction, and
    // run the whole dispatch tail there. After the hop, no core ever
    // executes scheduler machinery on a claimable EC's kstack —
    // the collision is structurally impossible, independent of wake
    // ordering.
    //
    // The hop deliberately happens ONLY on the non-vCPU final dispatch:
    // the vCPU loop above must keep its "run dry and RETURN to the
    // caller" contract (yieldTo's empty-return / qn0f handling).
    //
    // Boot fallback: before `perCoreInit` allocates the park stacks the
    // first dispatches run single-core with nothing claimable — run the
    // tail in place.
    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top == 0) {
        dispatchTailBody(core, current);
    }
    const release_ptr = takePendingReleaseByte(core, current);
    arch.cpu.hopToStackAndCall(
        park_top,
        release_ptr,
        &scheduler_dispatch_tail,
        @intFromPtr(current),
    );
}

/// Dummy byte handed to `hopToStackAndCall` when a hop has no pending
/// kstack release — the primitive unconditionally stores 0 through the
/// pointer it is given.
var hop_release_dummy: u8 = 0;

/// Consume this core's `pending_kstack_release` stash into a byte
/// pointer for `hopToStackAndCall`'s post-swap release store.
///
/// `exclude` is the EC this core is about to dispatch (or null): if the
/// stashed EC IS the incoming dispatch, its `on_cpu` must stay true —
/// the flag is about to describe the new dispatch, and clearing it at
/// the hop would let a reaper free the kstack we are dispatching onto.
/// The slot is nulled either way (the pending release is resolved: by
/// the hop store, or by the EC being re-dispatched right here).
fn takePendingReleaseByte(core: u8, exclude: ?*ExecutionContext) *u8 {
    const st = &core_states[core];
    const pending = st.pending_kstack_release orelse return &hop_release_dummy;
    st.pending_kstack_release = null;
    if (exclude) |ex| {
        if (pending == ex) return &hop_release_dummy;
    }
    return @ptrCast(&pending.on_cpu);
}

/// Record that this core is still executing on `ec`'s kstack even
/// though `ec` has been published claimable (suspend/park sites) or
/// disowned (peer flipped its state mid-quantum). The flag release is
/// deferred to the next stack hop — the first point at which this core
/// provably stops touching the kstack. See
/// `PerCore.pending_kstack_release`.
pub fn stashKstackRelease(core: u8, ec: *ExecutionContext) void {
    const st = &core_states[core];
    // Single-producer discipline: a second stash before the first is
    // consumed would lose a release and strand `on_cpu` set forever
    // (wake-side spins would hang). By construction every stash is
    // followed by a hop before the next stash site can run.
    std.debug.assert(st.pending_kstack_release == null or
        st.pending_kstack_release == ec);
    st.pending_kstack_release = ec;
}

/// C-callconv landing target for `switchTo`'s kstack hop. Runs on the
/// per-core park kstack; must never return.
export fn scheduler_dispatch_tail(arg: u64) callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const current: *ExecutionContext = @ptrFromInt(arg);
    dispatchTailBody(core, current);
}

/// The dispatch tail: everything between the dispatch decision and the
/// context-load trampoline. Runs on the park kstack (or the boot stack
/// before `perCoreInit`). noreturn via `loadEcContextAndReturn`.
fn dispatchTailBody(core: u8, current: *ExecutionContext) noreturn {
    // Defensive: a cross-core migration stash should always have been
    // consumed by `scheduler_hop_run` before another dispatch commits,
    // but consuming it here too keeps the invariant "slots drain at
    // every hop" unconditional.
    consumePendingCrossEnqueue(core);
    // Clear the OUTGOING ec's on_cpu now that we are OFF its kstack
    // (the hop above moved us to the park kstack). The reaper inside
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
    // Same clear, for the case where `current_ec` was already nulled by a
    // park that a dispatching IRQ handler then escaped without reaching
    // `scheduler_run_after_park`. Without this the flag is stranded set
    // forever — see `consumePostParkClear` (stygia-7jm).
    consumePostParkClear(core, current);
    // Hand the per-core PMU counter file over before `current_ec` is
    // rewritten — `pmuSwitch` reads the slot to find the outgoing EC.
    pmuSwitch(core, current);
    setCurrentEc(core, current);
    current.state = .running;
    kprof.point(.dispatch, @intFromPtr(current));
    arch.cpu.loadEcContextAndReturn(current);
}

/// Consume this core's pending affinity-migration handoff: release the
/// migrating EC's `on_cpu` (we are off its kstack — every caller runs
/// on the park kstack, post-hop), then enqueue it on a core satisfying
/// its affinity mask. Enqueue-after-release is the load-bearing order:
/// the target core may dispatch the EC the instant it appears in its
/// queue, and it must only ever see a released kstack.
fn consumePendingCrossEnqueue(core: u8) void {
    const st = &core_states[core];
    const ec = st.pending_cross_enqueue orelse return;
    st.pending_cross_enqueue = null;
    ec.on_cpu.store(false, .release);
    // A cross-core terminate may have hit the EC while it sat in the
    // slot (it was in no run queue, so removeFromQueue missed it).
    // `enqueueOnCore` rejects `.exited` / even-gen ECs, so the stale
    // handoff drops harmlessly there.
    enqueueOnCore(pickCoreForAffinity(ec.affinity), ec);
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
            // core (e.g. `setAffinity` excluded it mid-quantum) hand it
            // off to a satisfying core unconditionally — even when the
            // local queue is empty. An empty-queue local re-enqueue is
            // a trap: `dequeueOrIdleLocked` below would re-pick `cur`
            // and `switchTo(cur)` would dispatch it on the same
            // excluded core, defeating the affinity mask (and there is
            // no other migration trigger — `setAffinity` writes the
            // mask without repositioning, and `preempt` re-enters this
            // same path). `affinity == 0` is the spec "any core"
            // sentinel.
            const local_allowed = cur.affinity == 0 or
                (core < 64 and (cur.affinity & (@as(u64, 1) << @truncate(core))) != 0);
            if (local_allowed) {
                state.run_queue.enqueue(cur);
                // Publish queue residency under `core_locks[core]` so
                // `removeFromQueue` can target this lock directly
                // instead of sweeping all 64 cores. `.release` pairs
                // with the `.acquire` load in `removeFromQueue`; the
                // queue link write above happens-before any reader
                // that observes a non-sentinel value here.
                cur.current_queue_core.store(core, .release);
            } else {
                // Affinity migration. The old code cross-enqueued `cur`
                // right after dropping the local lock and then ran the
                // dispatch machinery — ON `cur`'s KSTACK — while the
                // target core was free to dispatch `cur` and reuse that
                // same kstack (bd-qn0f / bd-20f7's whole two-cores-one-
                // frame family, plus the frame-stomp autopsy under
                // PerCore.pending_kstack_release). Instead: stash the
                // handoff, abandon this kstack via the park-kstack hop,
                // and let `scheduler_hop_run` release `cur.on_cpu` and
                // enqueue it AFTER the hop. The local queue is left
                // untouched — run() re-evaluates it from the park
                // kstack. Costs one extra dequeue pass per migration;
                // migrations are rare (explicit setAffinity exclusions).
                lock.unlockIrqRestore(irq);
                state.pending_cross_enqueue = cur;
                clearCurrentEc(core);
                escapeToRun();
            }
        }
    }
    const next = if (target) |t| blk: {
        // `domainRefAlive`: same dying-domain dispatch gate as the
        // dequeue filter — a yieldTo target whose CD was dead-marked
        // by destroyPhase1 must not be committed (its queue entry, if
        // any, is drained and dropped by dequeueOrIdleLocked instead).
        if (t.state == .ready and domainRefAlive(t) and state.run_queue.remove(t)) {
            // Same kstack-livesness rationale as dequeueOrIdleLocked's
            // stamp: we are committing `t` to dispatch on this core
            // under core_locks[core]. A cross-core terminate(t) that
            // races after we drop the lock must observe
            // `t.last_dispatched_core == core` to defer the reap to
            // this core's pending_zombie column rather than inline-
            // free t's kstack while we're about to land on it.
            t.last_dispatched_core = core;
            // Clear queue residency: `t` is leaving the run queue and
            // about to be dispatched. Without this clear a subsequent
            // `removeFromQueue(t)` could target the now-empty core's
            // lock and remove(t) would no-op — harmless, but wastes a
            // lock acquire. Mirrors the dequeueOrIdleLocked clear.
            t.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
            // Locked dispatch commitment — see PerCore.committed_ec.
            state.committed_ec = t;
            // This arm dispatches without consulting
            // `dequeueOrIdleLocked`, so clear the park flag here too —
            // see PerCore.idle_parked.
            state.idle_parked = false;
            break :blk t;
        }
        break :blk dequeueOrIdleLocked(core);
    } else dequeueOrIdleLocked(core);
    lock.unlockIrqRestore(irq);

    if (next) |n| {
        // `switchTo` is normally `noreturn` (the park-kstack hop into
        // `scheduler_dispatch_tail`), but for a vCPU target the vCPU
        // pre-loop can RETURN when the synthetic vm_exit fires and the
        // subsequent `dequeueOrIdle` runs dry. `current_ec` is null in
        // that case and the caller's iretq path handles it (the
        // affinity-migration arm above never reaches here — it escapes
        // via the hop before selecting `next`).
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
    // Record whether a disowned `cur` occupies the slot BEFORE the
    // clear below — it decides between returning through the caller's
    // iretq (safe only when this IRQ interrupted parked/idle context)
    // and the noreturn escape further down (mandatory when it
    // interrupted an EC a peer has since disowned).
    const disowned_cur = (&core_states[core]).current_ec != null;

    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top != 0) {
        arch.cpu.parkPerCoreCaches(core, park_top);
    }
    // Stash the previously-current EC for a deferred on_cpu release.
    // The old code CLEARED the flag right here — but this code is still
    // executing on prev's kstack (only TSS.RSP0/gs:0 were re-pointed;
    // rsp was not), and for a disowned `cur` the peer that suspended it
    // is gated on exactly this flag before re-enqueueing it. Clearing
    // here let the peer dispatch `cur` — and reuse this very kstack —
    // while the escape below was still running on it. The stash is
    // consumed (and the flag released) by the park-kstack hop inside
    // `escapeToRun`, the first point where this core is provably off
    // the kstack. Without any release the EC would stay `on_cpu=true`
    // forever — every reap pass (`takeOwnPendingZombie`) skips it, the
    // kstack stays mapped, and the slab slot leaks — hence the stash
    // rather than simply dropping the clear.
    if ((&core_states[core]).current_ec) |prev_ref| {
        if (prev_ref.ptr.last_dispatched_core == core) {
            stashKstackRelease(core, prev_ref.ptr);
        }
    }
    clearCurrentEc(core);

    // Disowned current: `cur` existed but was not re-enqueued locally
    // (a peer terminate/suspend/wait path flipped its state away from
    // `.running` mid-quantum; the affinity-migration arm escaped
    // earlier and never reaches here). Returning here would iretq back
    // into an EC this scheduler no longer tracks:
    //
    //   - a suspended `cur` that a peer then resumes gets dispatched
    //     on another core while THIS core is still executing it in
    //     user mode — bd-20f7's two-cores-one-frame catastrophe on
    //     the empty-queue branch;
    //   - an exited `cur` keeps running user code while destroyPhase2
    //     frees its domain's page tables under it. Once the CR3 root
    //     is recycled the CPU cannot even walk to the IDT: silent
    //     triple fault (stygia-rs6 autopsy: exited EC still current
    //     on core 0, on_cpu=1, teardown shootdown never acked).
    //
    // Escape into `run()` instead. `run()` parks (loading the kernel
    // root and publishing active_root=0) or dispatches another EC
    // (publishing that EC's root after the CR3/TTBR0 load) via the
    // existing machinery — either way `destroyPhase2`'s
    // `awaitNoActiveRoot` barrier observes this core off the dying
    // domain's translation root before any table is freed. The park
    // path also drains this core's pending zombies.
    if (disowned_cur) {
        escapeToRun();
    }

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
/// Shared exit for `yieldTo`'s noreturn escapes into `run()`. The
/// escapes abandon the caller's IRQ epilogue, so on x86 the in-service
/// sched vector (0xFE) must be EOI'd first: it outranks both the wake
/// IPI and tlb_shootdown vectors, so a core that parks with it still
/// in service goes deaf to cross-core wakes (stranded-RDY-EC hangs)
/// and shootdown IPIs (initiator spins forever on the missing ack).
/// Safe from syscall-context callers too — LAPIC EOI with an empty ISR
/// is a no-op. aarch64 EOIs before dispatching the handler (early-EOI),
/// so the dispatch helper is a no-op there.
fn escapeToRun() noreturn {
    arch.irq.schedulerEscapeEoi();
    hopParkRun();
}

/// Abandon the current kernel stack for this core's park kstack and
/// enter `run()` there. Releases the pending kstack-release stash at
/// the hop instruction (see `PerCore.pending_kstack_release`) and
/// consumes any pending affinity-migration handoff before re-entering
/// the scheduler loop. This is the mandatory route into `run()` for
/// every caller that may still be standing on a claimable EC's kstack
/// (post-suspend syscall epilogues, fault-park paths, yieldTo escapes):
/// entering `run()` in place would keep executing dequeue/park
/// machinery on a kstack another core may concurrently dispatch onto.
///
/// Boot fallback: before `perCoreInit` allocates the park stacks
/// nothing is claimable and there is no park kstack — enter `run()` in
/// place.
pub fn hopParkRun() noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top == 0) run();
    const release_ptr = takePendingReleaseByte(core, null);
    arch.cpu.hopToStackAndCall(park_top, release_ptr, &scheduler_hop_run, 0);
}

/// C-callconv landing target for `hopParkRun`. Runs on the park
/// kstack with the pending kstack release already published by the hop
/// primitive; drains the migration handoff, then enters the scheduler
/// loop. Never returns.
export fn scheduler_hop_run(arg: u64) callconv(.c) noreturn {
    _ = arg;
    const core: u8 = @truncate(arch.smp.coreID());
    consumePendingCrossEnqueue(core);
    run();
}

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
/// frame is abandoned. See `PerCore.park_stack`.
///
/// Returns early WITHOUT parking when a peer race-enqueued work between
/// `run()`'s queue check and our lock-protected re-check of the same
/// queue (see "lost-wake race" below). Caller (`run()`) loops and
/// re-runs `dequeueOrIdle`, which now sees the raced-in EC and
/// dispatches it via the normal path. Hence `void` rather than
/// `noreturn`.
fn parkAndAwaitIRQ() void {
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

    // ── lost-wake race window ────────────────────────────────────────
    //
    // Without the lock-protected re-check below, this sequence loses a
    // wakeup at smp=4 once per ~5-10 reps on terminate/affinity/yield
    // batches. The original signature is "core 0 has 2 RDY ECs in its
    // run_queue, current_ec=null, all 4 cores parked" with no further
    // LAPIC ticks for the rest of the run.
    //
    //   T0: this core's `dequeueOrIdle()` returned null (lock taken+dropped).
    //   T1: peer P calls `enqueueOnCore(this_core, ec)`:
    //         - takes core_locks[this_core]
    //         - run_queue.enqueue(ec)
    //         - reads `current_ec` slot — STILL the stale prev_ref
    //           (this core hasn't published null yet)
    //         - drops the lock
    //         - sees `target_current_ptr != null` → "busy" branch
    //         - if `ec.priority <= prev.priority` → no IPI sent
    //   T2: this core writes `current_ec = null` (no lock)
    //   T3: this core sti+hlt — never wakes because no IPI is coming
    //       and no prior caller re-armed our LAPIC for a near-future
    //       fire (the peer's enqueue path doesn't re-arm; only our
    //       own schedTimerHandler does, and we're parked).
    //
    // The fix: publish `current_ec = null` UNDER core_locks[this_core]
    // and re-check the run queue in the same critical section. If a
    // peer raced an enqueue in, signal "abandon park" to the caller
    // (`run()`) by returning early; the caller's loop re-runs
    // `dequeueOrIdle` and dispatches via the normal path. If we still
    // see an empty queue, the next enqueue will observe the published
    // null and send the wake IPI, which delivers when sti runs in the
    // arch trampoline below.
    //
    // The drain above runs OUTSIDE the lock (finalize takes its own
    // CD/port locks; nesting them under core_locks would seed an
    // out-of-class acquire). We re-drain post-wake in the asm landing
    // pad anyway, so any zombie posted between the pre-park drain and
    // the lock acquire below gets reaped on the next wake — what
    // matters at THIS instant is that the run-queue check and the
    // current_ec-null publish are atomic.
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    // Use `dequeueOrIdleLocked` rather than a raw `isEmpty` check: the
    // queue may contain `.exited` ECs that yieldTo's race-prone re-enqueue
    // window dropped in (a yieldTo that read `state == .running` from a
    // racing terminate's pre-flip can re-enqueue an EC after the second
    // sweep, leaving it dangling). dequeue filters those — if we bailed on
    // a queue containing only stale entries, `run()` would loop right back
    // through dequeueOrIdle, see only filterable junk, and re-park,
    // burning CPU on a tight cycle until the queue is cleaned out.
    if (dequeueOrIdleLocked(core)) |raced_in| {
        // Peer race: an EC landed in our queue between `run()`'s
        // `dequeueOrIdle()` and now. Bail park, dispatch directly under
        // the lock release. post_park_clear_on_cpu is consumed by the
        // asm landing pad which we're NOT going through, so reset it
        // — a future genuine park will overwrite it. We have NOT yet
        // mutated the per-core caches (parkPerCoreCaches hasn't run);
        // current_ec stays whatever it was, and the next switchTo's
        // prev clear will handle on_cpu correctly.
        (&core_states[core]).post_park_clear_on_cpu = null;
        lock.unlockIrqRestore(irq);
        switchTo(raced_in);
        // switchTo is conventionally noreturn (loadEcContextAndReturn);
        // it can return only via the vCPU-loop empty-queue exit, in
        // which case current_ec is null and the per-core caches are
        // already in the parked-stack state. Returning to our caller
        // (`run()`) then re-runs the queue check; if still empty the
        // next iteration calls back into us with a clean state.
        return;
    }

    // Update per-core caches FIRST while still on the caller's stack.
    // After the rsp swap below, locals on this stack frame go
    // unreferenced; the outer noreturn semantics make abandonment
    // safe.
    arch.cpu.parkPerCoreCaches(core, park_top);
    (&core_states[core]).current_ec = null;
    // Drop the lock but deliberately do NOT restore the caller's IRQ
    // state — everything from here to `arch.cpu.parkAndAwaitIRQ` is a
    // straight line into a noreturn primitive that requires IRQs MASKED
    // on entry and does its own controlled unmask (x86 `sti; hlt; cli`
    // relies on the STI interrupt shadow, which exists only if IF was 0;
    // aarch64 sleeps masked then unmasks for exactly one instruction —
    // 1bbcbbf7d mechanism 7).
    //
    // `irq` was captured by `lockIrqSaveOrdered`, so restoring it means
    // restoring whatever the caller had. Several callers reach `run()`
    // with IRQs already ENABLED — `arch/aarch64/exceptions.zig`'s EL0
    // `wfi` trap does a literal `cpu.enableInterrupts(); scheduler.run();`
    // (and the x86 #GP-on-`hlt` and port-IO paths do the same). Restoring
    // there reopens the exact lost-wake hole the masked-park idiom
    // closes: a wake IPI delivered between here and the halt is taken,
    // EOI'd and CONSUMED, after which the halt sleeps with `ec` sitting
    // `.ready` in this core's queue and nothing left to poke us.
    //
    // Discarding the saved state is sound precisely because this path
    // never returns: the park primitive tail-jumps to
    // `scheduler_run_after_park`, which re-enters `run()` under the same
    // masked contract.
    lock.unlock();

    // Detach from whatever user translation root the last dispatch
    // left loaded and publish "no user root" BEFORE halting. A parked
    // core otherwise keeps the previous domain's root live in CR3 —
    // if that domain is then destroyed, `freeUserAddrSpace` recycles
    // the tables this core's next IRQ entry walks through (stygia-rs6
    // family). The kernel half is shared across all roots, so the
    // swap is transparent to the park path itself; the publish order
    // (hardware load first, then store-release) keeps the teardown
    // barrier in `destroyPhase2` honest. Any stale dispatch
    // commitment is retired too — this core is committing to hlt.
    arch.paging.loadKernelRoot(memory_init.kernel_addr_space_root);
    publishActiveRoot(core, 0);
    (&core_states[core]).committed_ec = null;

    // Re-arm the preemption timer before sleeping — a parked core must
    // keep a heartbeat. The idle path's final timer tick was silenced
    // at the source (aarch64: silenceTimerLineIfFiring sets
    // CNTV_CTL.IMASK so the level-sensitive PPI de-asserts; the
    // matching unmask lives in armInterruptTimer, which only the
    // DISPATCH path reaches), so a parked core otherwise has no
    // periodic wake source at all and exactly one stale wake decision
    // in enqueueOnCore strands its run queue forever. Measured on the
    // .106 KVM reproducer as the persistent affinity_05/06 +
    // create_execution_context_14 MISS: pass 1 parks cores 1..3 with
    // silenced timers, and the first pinned enqueue that reads a stale
    // busy/parked snapshot never gets a second chance. With the
    // heartbeat, a missed wake costs one timeslice instead of the run.
    arch.time.getPreemptionTimer().armInterruptTimer(TIMESLICE_NS);

    arch.cpu.parkAndAwaitIRQ(park_top);
}

/// Consume this core's pending post-park `on_cpu` clear, if any.
///
/// `parkAndAwaitIRQ` stashes the previously dispatched EC here because it
/// nulls `current_ec` before halting, which leaves `switchTo`'s
/// "current_ec → new" prev-clear edge nothing to clear from.
///
/// The subtlety — and the bug this function exists to close (stygia-7jm)
/// — is that the asm landing pad `scheduler_run_after_park` is reached
/// ONLY IF the handler for the waking IRQ RETURNS. The park primitive is
/// a straight line (`sti; hlt; cli; jmp scheduler_run_after_park` on x86,
/// `wfi; daifclr; isb; daifset; b scheduler_run_after_park` on aarch64),
/// so any handler that dispatches instead of returning skips the trailing
/// branch entirely. Handlers that do exactly that:
///
///   * the x86 wake IPI, which IS `IntVecs.sched` (`arch.smp.sendWakeIpi`)
///     — its handler ends in `preempt()` → `switchTo` →
///     `loadEcContextAndReturn`, noreturn;
///   * the per-core timer tick on EITHER arch, which can land in the
///     unmask window and likewise end in `preempt()`.
///
/// So this is not specific to the wake vector, and not specific to x86.
/// When the branch is skipped, the previously dispatched EC keeps
/// `on_cpu = true` forever: `finalizeDestroyMarkedDead` skips ECs with
/// that flag set, so its zombie is never reaped, its slab slot leaks, and
/// a peer's `postZombie` spins waiting for a drain that will never
/// happen. Worse, the next park overwrites the slot, so the clear is lost
/// permanently rather than merely deferred.
///
/// Calling this from every dispatch-commitment point makes the invariant
/// independent of which return path the waking handler happens to take.
/// (The aarch64 wake was additionally given its own non-dispatching SGI —
/// see `arch.dispatch.smp` — but that only covers the wake, not the tick.)
///
/// Safe at any dispatch commit, for the same reason the landing pad is:
/// `parkPerCoreCaches` ran BEFORE the park primitive, so TSS.RSP0 already
/// names the park kstack, and the primitive's rsp swap moved us off the
/// prev EC's kstack — an IRQ taken in the halt window is therefore
/// already running on the park kstack, not on prev's.
///
/// `incoming` is the EC about to be dispatched, if any, so we never clear
/// the flag of the EC we are in the middle of scheduling.
fn consumePostParkClear(core: u8, incoming: ?*const ExecutionContext) void {
    const state_ptr = &core_states[core];
    const prev_ref = state_ptr.post_park_clear_on_cpu orelse return;
    state_ptr.post_park_clear_on_cpu = null;

    if (incoming) |inc| {
        if (prev_ref.ptr == inc) return;
    }
    // Same discipline as `switchTo`'s prev clear: only clear when this
    // core is still the EC's `last_dispatched_core`. The EC may have
    // migrated during the park (the new core's `setCurrentEc` bumps
    // `last_dispatched_core` but cannot reach back into our slot); that
    // core now owns its `on_cpu` lifecycle, and clearing it here would
    // let its reaper finalize an EC that is actively running — unmapping
    // a kstack still named by the live TSS.RSP0.
    if (prev_ref.ptr.last_dispatched_core != core) return;

    // caller-pinned: single-producer/single-consumer slot written by this
    // same core in `parkAndAwaitIRQ` immediately before the park
    // primitive. The EC slab slot cannot have been freed in the park
    // window because `finalizeDestroyMarkedDead` skips ECs with
    // on_cpu=true, and that flag is exactly what this clear releases.
    prev_ref.ptr.on_cpu.store(false, .release);
}

/// Asm landing pad after `parkAndAwaitIRQ`'s wake: rsp is on the park
/// kstack, IRQs are masked. Re-enter `run()` to re-check the queue.
/// `run()` is noreturn so the call never returns; the pushed return
/// address sits unused on the park stack.
export fn scheduler_run_after_park() callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    // Clear the previously-dispatched EC's `on_cpu` flag now that we
    // are on the park kstack. Clearing on_cpu unblocks
    // `takeOwnPendingZombie` for any zombie that pinned this slot during
    // the park. This is the normal consumer; see `consumePostParkClear`
    // for why it cannot be the only one.
    consumePostParkClear(core, null);
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
/// True while `ec`'s domain SlabRef still names the CD slot's live
/// gen. Turns false the instant `destroyPhase1` dead-marks the CD —
/// i.e. it covers the phase1→phase2 teardown gap in which the
/// domain's ECs are themselves still gen-live and `.ready` but their
/// domain (and imminently its translation root) is being destroyed.
/// Every dispatch-commitment site must refuse such ECs BEFORE the
/// `switchTo` domain deref; see the stygia-rs6 CR3=0 corpse notes at
/// the dequeue filter.
inline fn domainRefAlive(ec: *ExecutionContext) bool {
    const dref = ec.domain;
    return dref.ptr._gen_lock.currentGen() == @as(u64, dref.gen);
}

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
        // Clear queue residency on every popped EC, regardless of
        // whether we end up dispatching it or skipping it as stale —
        // either way it is no longer linked into any run queue.
        // Performed under `core_locks[core]` so a concurrent
        // `removeFromQueue` reader that observed a stale `core`
        // residency hint and is now waiting on this lock will see the
        // cleared sentinel after acquiring.
        ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        // A cross-core terminate can flip an EC's state to .exited and
        // bump its slab gen between `enqueue` and `dequeue`. Drop those:
        // dispatching them would assert on the even gen in
        // `setCurrentEc`'s `SlabRef.init`, and the EC is reaped via the
        // pending_zombie path on its running core anyway.
        //
        // Also drop ECs whose DOMAIN ref is stale (`!domainRefAlive`):
        // destroyPhase1 dead-marks the CD before phase 2 gen-bumps the
        // domain's ECs, so in that gap a dying-domain EC is still
        // gen-live and `.ready` — but dispatching it would deref the
        // dying CD slot for its translation root in `switchTo`
        // (stygia-rs6: a dispatch in this gap on the pre-fix code read
        // the freed slot's zeroed `addr_space_root` and loaded CR3=0;
        // the core wedged in an eternal page-fault loop until its TLB
        // evicted the fault handler's text, then triple-faulted with
        // no output).
        if (ec.state == .exited or
            ec._gen_lock.currentGen() % 2 == 0 or
            !domainRefAlive(ec)) continue;
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
        // Record the commitment while still under core_locks[core] —
        // the teardown barrier's lock-sweep keys on this (see
        // PerCore.committed_ec). The dispatch path clears it after
        // the root load+publish.
        state.committed_ec = ec;
        state.idle_parked = false;
        return ec;
    }
    if (state.idle_ec) |idle_ref| {
        // caller-pinned: per-core idle EC is allocated at perCoreInit and
        // never freed — it's the dispatch-of-last-resort target.
        idle_ref.ptr.last_dispatched_core = core;
        state.committed_ec = idle_ref.ptr;
        state.idle_parked = false;
        return idle_ref.ptr;
    }
    // Nothing to run: the caller parks this core. Publish that decision
    // under `core_locks[core]` so a concurrent `enqueueOnCore` knows to
    // send the wake IPI even though `current_ec` has not been cleared
    // yet. See `PerCore.idle_parked`.
    state.idle_parked = true;
    return null;
}

// ── Enqueue / current accessors ──────────────────────────────────────

/// Enqueue `ec` on `core`'s run queue. Used by recv → ready transitions,
/// futex wake, timer fires, and the boot path.
///
/// Wake / preempt policy after queueing:
///   - target idle (no `current_ec`) or parking (`idle_parked`, set
///     under this same lock) and target != self: send wake IPI so the
///     parked `hlt`/`wfi` exits and `run` re-runs `dequeueOrIdle`.
///   - target current EC outranks `ec`: nothing to do — `ec` waits its
///     turn. Only sound because `idle_parked` was checked first: a
///     target that has committed to parking still names its last EC in
///     `current_ec`, and trusting that alone strands `ec` forever.
///   - `ec` outranks target's current EC: send a scheduler IPI to the
///     target. Self-IPI (when target == self) is LAPIC-ICR-based, so
///     it's IF-gated and fires once the caller exits its current IRQ /
///     spinlock-held window. We deliberately do NOT inline-yield: many
///     callers (e.g. `futex.wake`) hold a bucket lock across this call,
///     and a context-switch via `loadEcContextAndReturn` would strand
///     it.
pub fn enqueueOnCore(core: u8, ec: *ExecutionContext) void {
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    // Validate, and perform the `.ready` transition, INSIDE the target
    // core's lock (stygia-qbx).
    //
    // This used to be an unconditional `ec.state = .ready;` as the
    // function's first statement — before the lock was even taken — so
    // every caller resurrected a terminated EC by construction. The
    // damage is not merely that a dead EC gets queued: it is that the
    // stamp DESTROYS THE EVIDENCE the dispatch-side filter keys on.
    // `dequeueOrIdleLocked` rejects on `state == .exited`, even gen, or a
    // dead domain ref; overwriting `.exited` with `.ready` means that in
    // the window after `terminate` sets `.exited` but before
    // `bumpDeadGenLocked` flips the gen, all three filter conditions read
    // healthy and a terminated EC is dispatched.
    //
    // Rejecting is safe for every caller: none legitimately enqueues an
    // `.exited` EC. Callers enqueue from `.futex_wait` (futex wake),
    // `.suspended_on_port` (port reply/resume), `.running` (yieldTo
    // re-enqueue), or a freshly created `.ready` EC.
    //
    // The even-gen check covers the case where the slot was already
    // released — the caller holds a bare `*ExecutionContext`, so this is
    // the only life-cycle signal available here.
    if (ec.state == .exited or ec._gen_lock.currentGen() % 2 == 0) {
        lock.unlockIrqRestore(irq);
        return;
    }
    ec.state = .ready;

    (&core_states[core]).run_queue.enqueue(ec);
    // Publish queue residency under the target core's lock so a
    // racing `removeFromQueue(ec)` from a third core can target the
    // right lock instead of sweeping all 64. `.release` pairs with
    // the `.acquire` load in `removeFromQueue`.
    ec.current_queue_core.store(core, .release);
    // Snapshot the target's current EC before deciding whether to
    // wake / preempt. Reading the remote core's `current_ec` is a racy
    // hint — the worst case if it changes after we decide is a spurious
    // wake or a missed preempt that the next preempt tick covers.
    const target_current = (&core_states[core]).current_ec;
    // Read the target's parking decision under the SAME lock that just
    // published `ec` into its queue. `current_ec` alone is not enough:
    // a core that has already committed to parking still names its last
    // EC there until after it drops this lock, and treating that as
    // "busy, it will pick `ec` up later" strands `ec` on a core that
    // never wakes. See `PerCore.idle_parked`.
    const target_parked = (&core_states[core]).idle_parked;
    lock.unlockIrqRestore(irq);

    const self_core: u8 = @truncate(arch.smp.coreID());

    const target_current_ptr: ?*ExecutionContext = if (target_current) |r|
        // caller-pinned: read-only snapshot of target core's current_ec
        // for wake/preempt decision. Worst-case stale ptr just costs
        // a spurious IPI; real ptr deref is gated below.
        r.ptr
    else
        null;

    // Wake and preempt are independent decisions; evaluate both.
    //
    // Wake: the target is idle, or has committed to parking and is
    // merely still carrying a stale `current_ec`. Either way the only
    // thing that will make it look at its queue again is a wake.
    //
    // Local self-wake is unnecessary — the caller is running, not
    // halted. That holds for the parked case too: an IRQ handler that
    // wakes a core out of its park (timer tick → `expireTimedWaiters`,
    // futex wake with affinity 0) runs on that core and returns through
    // the park loop, which re-runs `dequeueOrIdle` and finds `ec`.
    if (target_current_ptr == null or target_parked) {
        if (core != self_core) arch.smp.sendWakeIpi(core);
    }

    // Preempt: deliberately NOT an `else` on the wake above. A core can
    // resume without re-running `dequeueOrIdleLocked` (`switchTo`'s
    // vCPU-empty return unwinds through `yieldTo` back to user mode),
    // leaving `idle_parked` stale-true while it is genuinely busy.
    // Folding the preempt into the wake's `else` would swallow the
    // priority decision in exactly that case and delay a higher-
    // priority EC by up to a full quantum. A wake IPI to a running core
    // does not reschedule; only the scheduler IPI does.
    //
    // caller-pinned: snapshot ptr; race-tolerant priority compare.
    const cur = target_current_ptr orelse return;
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

/// Remove `ec` from whichever per-core run queue it currently occupies.
/// Used by terminate / suspendOnPort / destroyExecutionContextLocked.
///
/// Fast path (bd-mlpx / bd-vzdh): consult `ec.current_queue_core` —
/// the per-EC residency hint Zig enqueue/dequeue/remove sites maintain
/// under `core_locks[core]` — and target only that one core's lock
/// when the hint is non-sentinel. This drops the per-call cost from
/// `MAX_CORES = 64` lock acquires down to one for the EC-not-in-queue
/// case (terminate / paired post-`.exited` sweep / destroyPhase2 reap
/// on faulted ECs, the bd-vzdh contention scenario), eliminating the
/// O(MAX_CORES) cache-line bouncing that compounded into ~2.5 s of
/// LAPIC-tick suppression under SMP=4 concurrent CD destroys.
///
/// Fallback (`current_queue_core == NOT_IN_RUN_QUEUE`): sweep all 64
/// per-core locks. Required because the IPC fast-path asm in
/// `arch/x64/interrupts.zig` (R13 main + R13 fallback) enqueues a
/// freshly-replied receiver onto the local run queue without writing
/// `current_queue_core`. ECs in that window read the sentinel but
/// genuinely live in some queue — the legacy sweep finds them. The
/// bd-vzdh storm scenario does not enter this path: faulted ECs are
/// dispatched via the slow path, never the IPC fast path, so the
/// hint stays accurate for them.
pub fn removeFromQueue(ec: *ExecutionContext) void {
    const hint = ec.current_queue_core.load(.acquire);
    if (hint < MAX_CORES) {
        const lock = &core_locks[hint];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const removed = (&core_states[hint]).run_queue.remove(ec);
        if (removed) {
            ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        }
        lock.unlockIrqRestore(irq);
        if (removed) return;
        // Hint was stale (EC migrated between our load and our lock
        // acquire, or the asm fast-path put it in a different queue).
        // Fall through to the legacy sweep.
    }
    var i: u8 = 0;
    while (i < MAX_CORES) {
        const lock = &core_locks[i];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const removed = (&core_states[i]).run_queue.remove(ec);
        if (removed) {
            ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        }
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
/// Publish the user translation root this core has just LOADED (0 =
/// none / kernel root). Callers MUST issue the hardware root load
/// BEFORE this store — see the `PerCore.active_root` field doc.
pub inline fn publishActiveRoot(core: u8, root_addr: u64) void {
    (&core_states[core]).active_root.store(root_addr, .release);
}

/// Spin until no core can execute through the dying domain's
/// translation tables. Two per-core clauses, both required:
///
///   1. `active_root == root_addr` — the core has the dying root
///      LOADED (published with release-after-load; see
///      `PerCore.active_root`).
///   2. `current_ec` names an EC whose `domain.ptr == cd_ptr` — the
///      core has COMMITTED to dispatching a dying-domain EC but may
///      not have loaded (or published) its root yet. `current_ec`
///      flips at `setCurrentEc`, well before the dispatch path's
///      root swap, so it is the conservative early signal for
///      in-flight dispatches: a corpse showed a core dying INSIDE
///      `interrupts.switchTo` (post-`setCurrentEc`, pre-publish,
///      stalled in migrateFlush) when the teardown freed the root
///      it was about to load.
///
/// Domain teardown calls this after the destroy walk (zombies + wake
/// IPIs posted, gens bumped) and before freeing any table. Both
/// clauses converge: dying-domain ECs are gen-dead so no NEW dequeue
/// can dispatch them (dequeueOrIdleLocked filters even-gen), running
/// victims get evicted within one IRQ delivery, and an in-flight
/// dispatch either completes (publishing the root — clause 1 holds
/// it) or aborts. Residual window: the dequeue→setCurrentEc sliver
/// carries a committed EC in neither signal; it contains no spins
/// and its close (`setCurrentEc`'s SlabRef.init) asserts on the
/// bumped gen, so it cannot silently dispatch. Cross-core reads of
/// `ec.domain.ptr` are identity-only; slab memory persists after
/// reap (zeroed ⇒ ptr mismatch ⇒ clause exits).
///
/// The EXECUTING core is skipped: a self-destroying caller EC still
/// occupies its own core's `current_ec` slot through phase 2 (and is
/// standing on its kstack by design), so including self in clause 2
/// would deadlock — the destroyer core detached its root separately
/// and runs only kernel-mapped teardown code from here. All other 64
/// slots are scanned; never-started cores sit at the 0 / null
/// defaults.
///
/// Prologue: one acquire/release of every core's lock. Dispatch
/// commitments are written under `core_locks[core]`
/// (dequeueOrIdleLocked / yieldTo's target arm), and the gen flips
/// the caller performed before this barrier are what stop NEW
/// commitments (the dequeue filter drops even-gen ECs) — but a
/// commitment made just BEFORE a flip may sit in a core's store
/// buffer, or the committing core may be host-descheduled mid-window
/// for milliseconds (KVM vCPU preemption breaks every "visible soon"
/// argument). Taking each lock once forces the sweep to serialize
/// after any in-progress locked commit, making `committed_ec` (and
/// everything the committer wrote before its unlock) visible to the
/// clause scan below.
pub fn awaitDomainQuiesced(root_addr: u64, cd_ptr: *const anyopaque) void {
    const self_core: u8 = @truncate(arch.smp.coreID());
    for (&core_locks) |*lock| {
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        lock.unlockIrqRestore(irq);
    }
    for (&core_states, 0..) |*state, core_idx| {
        if (core_idx == self_core) continue;
        while (true) {
            if (state.active_root.load(.acquire) == root_addr) {
                std.atomic.spinLoopHint();
                continue;
            }
            if (state.current_ec) |ref| {
                // caller-pinned: identity-only compare of the raw
                // domain pointer against the dying CD's address — no
                // field of the CD is read through it. Slab bytes of a
                // current EC persist past its gen flip (deferred
                // finalize), and a zeroed domain field simply
                // mismatches and exits the clause.
                if (@intFromPtr(ref.ptr.domain.ptr) == @intFromPtr(cd_ptr)) {
                    std.atomic.spinLoopHint();
                    continue;
                }
            }
            if (state.committed_ec) |cec| {
                // caller-pinned: same identity-only compare as the
                // current_ec clause; see PerCore.committed_ec for why
                // the committed EC's bytes cannot recycle under us.
                if (@intFromPtr(cec.domain.ptr) == @intFromPtr(cd_ptr)) {
                    std.atomic.spinLoopHint();
                    continue;
                }
            }
            break;
        }
    }
}

/// Racy identity read of `core_states[core].current_ec.ptr` for
/// cross-core "has this EC left its core's dispatch slot" waits
/// (terminate's stops-executing barrier). Single-writer-per-core makes
/// the 8-byte ptr read tear-free on both arches; the gen word is
/// deliberately not read — pointer identity is all the caller compares.
pub inline fn currentEcPtrOn(core: u8) ?*ExecutionContext {
    if ((&core_states[core]).current_ec) |ref| return ref.ptr;
    return null;
}

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
        const zp_chk = @intFromPtr(z);
        const ka_chk = stygia.memory.address.KernelVA.KernelAllocators.range;
        if (zp_chk < ka_chk.start or zp_chk >= ka_chk.end) {
            stygia.arch.dispatch.boot.print(
                "[zombie] BUG: pending slot [{d}] holds non-slab 0x{x}; dropped\n",
                .{ i, zp_chk },
            );
            slots[i] = null;
            continue;
        }
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
        const z_top = z.kernel_stack.top.addr;
        const z_base = z.kernel_stack.base.addr;
        const standing_on_zombie = rsp_addr >= z_base and rsp_addr < z_top;
        if (standing_on_zombie) continue;

        // Bounded escape from a stranded `on_cpu` (stygia-7jm residual).
        //
        // `on_cpu` can be left set forever. `consumePostParkClear` nulls
        // `post_park_clear_on_cpu` BEFORE its `last_dispatched_core ==
        // core` guard can decline the clear, so a prev EC that migrated
        // between the park and the wake loses its clear permanently —
        // and nothing else writes the flag for an EC that will never be
        // dispatched again. The zombie then pins this column forever:
        // the gate below skips it, the column never frees, and the
        // poster spins in `postZombie` against a core that can never
        // drain. Observed as a wedged N=10 run with a parked core
        // holding `pending_zombies=1` and READY ECs — including the
        // root EC — stranded in its own run_queue.
        //
        // When WE are the EC's `last_dispatched_core`, a set `on_cpu` is
        // provably stale and we may clear it. The flag means "this EC's
        // kstack is live on its last-dispatched core". We are that core;
        // we are executing this reaper, not the EC; and the rsp check
        // above already proved we are not standing on its kstack. So the
        // kstack is not live here.
        //
        // Race-free against a re-dispatch: `postZombie`'s callers run
        // `bumpDeadGenLocked` first, so `z` is gen-dead by the time it
        // reaches this column, and `dequeueOrIdleLocked` filters
        // even-gen / `.exited` ECs. No core can commit to dispatching it
        // again. The only writer that could re-set `on_cpu` is a
        // dispatch of `z`, which can no longer happen. We also hold
        // `core_locks[cid]`, under which this core's own dispatch
        // commitments are made.
        //
        // Deliberately NOT extended to zombies owned by another core:
        // proving that remotely needs that core's lock, and taking a
        // second same-class core lock here is an AB-BA against a peer
        // doing the reverse. Those remain gated on the owner clearing
        // the flag, exactly as before.
        if (z.on_cpu.load(.acquire)) {
            if (z.last_dispatched_core != cid) continue;
            z.on_cpu.store(false, .release);
        }
        slots[i] = null;
        return z;
    }
    return null;
}

// ── State transitions used by other subsystems ───────────────────────

/// Transition `ec` to ready and enqueue. Used by event delivery
/// resumes (reply, futex wake, timer fire, recv→ready, etc.).
///
/// Routed through `tryClaimWake` so a resume that races a second waker
/// for the same wait — classically a recv/futex timeout expiring on the
/// timer core while the event it was waiting for arrives on another —
/// enqueues the EC exactly once. The loser returns silently; the winner
/// owns the wake. See `execution_context.tryClaimWake` for why a
/// per-core queue lock cannot serialize this.
pub fn markReady(ec: *ExecutionContext) void {
    // Racy read, then a cmpxchg from exactly that value — if it shifts
    // under us the claim fails and we correctly do nothing.
    const waiting_in = ec.state;
    switch (waiting_in) {
        // Genuine wakes.
        .suspended_on_port, .futex_wait, .idle_wait => {},
        // Not a wake but a legitimate re-enqueue: `resumeFromReply` can
        // reach here with the EC still `.running` (the reply landed on
        // the core that was executing it). Claiming from `.running` is
        // still single-writer, so it keeps the anti-double-enqueue
        // property while not stranding the EC.
        .running => {},
        // `.ready` means someone already claimed this wake and queued
        // the EC — enqueuing again is precisely the double-queue bug
        // this function exists to prevent. `.exited` must never be
        // resurrected: enqueueOnCore's dispatch filter keys on that
        // state, so stamping `.ready` over it destroys the evidence.
        else => return,
    }
    if (!execution_context.tryClaimWake(ec, waiting_in)) return;
    // Kstack-release barrier: the suspend/park sites no longer clear
    // `on_cpu` in place — the parking core keeps it set until it has
    // hopped off the EC's kstack (see PerCore.pending_kstack_release).
    // Enqueueing before that release lets the dispatching core reuse a
    // kstack whose previous core is still executing on it. Wait for the
    // release, exactly like the futex wake's phase-2 spin and
    // `deliverEvent`'s receiver spin. Bounded: the owner's path from
    // publishing the wait state to its hop is lock-bounded local work
    // (no IPI-ack waits), at worst one scheduler quantum when the EC
    // was suspended remotely mid-quantum.
    //
    // Skipped for the `.running` claim: that arm is same-core by
    // contract (`resumeFromReply` with the reply landing on the
    // executing core) — spinning there would wait on our own release.
    if (waiting_in != .running) {
        while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    }
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
    stygia.sched.fpu.migrateFlush(ec);
}

