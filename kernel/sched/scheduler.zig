//! Per-core scheduler — owns the run queues, dispatches Threads, handles
//! preemption + voluntary yield, tracks the current thread per core, and
//! coordinates lazy-FPU eviction across cores.
//!
//! Each core has a `PerCore` slot holding its run queue (priority-
//! ordered intrusive PQ over thread.next), the currently dispatched thread,
//! the last-FPU-owner thread, and a flag for whether CR0.TS is currently
//! armed. Cross-core enqueue is supported (the source core sends an
//! IPI to the destination if the destination is idle).

const builtin = @import("builtin");
const build_options = @import("build_options");
const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const spin_diag = stygia.utils.spin_diag;
const thread_log = stygia.utils.thread_log;
const memory_init = stygia.memory.init;
const thread_mod = stygia.sched.thread;
const lifecycle = stygia.sched.lifecycle;
const port_mod = stygia.sched.port;
const stack_mod = stygia.memory.stack;

const Process = stygia.caps.process.Process;
const Thread = stygia.sched.thread.Thread;
const NOT_IN_RUN_QUEUE = stygia.sched.thread.NOT_IN_RUN_QUEUE;
const Priority = stygia.sched.thread.Priority;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const SpinLock = stygia.utils.sync.SpinLock;
const Stack = stygia.memory.stack.Stack;
const VAddr = stygia.memory.address.VAddr;

const YIELD_SELECT_DIAG_BUDGET: u32 = 4096;
var yield_select_diag_prints: u32 = 0;

const YIELD_TARGET_PINNED_BIT: u64 = 1;
const YieldTarget = struct {
    // caller-pinned: every non-null target comes from yieldToPinned; the
    // lifecycle pin is carried across the park-stack hop and released here.
    thread: ?*Thread = null,
    pinned: bool = false,

    fn encodeForHop(self: YieldTarget) u64 {
        const target = self.thread orelse return 0;
        const raw = @intFromPtr(target);
        std.debug.assert(raw & YIELD_TARGET_PINNED_BIT == 0);
        return raw | if (self.pinned) YIELD_TARGET_PINNED_BIT else 0;
    }

    fn decodeFromHop(arg: u64) YieldTarget {
        if (arg == 0) return .{};
        const raw = arg & ~YIELD_TARGET_PINNED_BIT;
        return .{
            .thread = @as(*Thread, @ptrFromInt(raw)),
            .pinned = (arg & YIELD_TARGET_PINNED_BIT) != 0,
        };
    }

    fn release(self: *YieldTarget) void {
        if (self.pinned) {
            lifecycle.releasePin(self.thread.?);
            self.pinned = false;
        }
        self.thread = null;
    }
};

/// Intrusive priority queue of Threads, linked through the thread's `next`
/// field and ordered by `priority`. Shared by per-core run queues and
/// port wait queues. Futex buckets use a separate WaitNode-based queue
/// (see sched/futex.zig).
pub const ThreadQueue = stygia.sched.priority_queue.PriorityQueue(
    Thread,
    "next",
    "priority",
    @typeInfo(Priority).@"enum".fields.len,
);

pub const TeardownKind = enum(u8) { self_delete, unhandled_fault };

pub const TeardownRequest = struct {
    kind: TeardownKind,
    process: SlabRef(Process),
    caller_thread: ?SlabRef(Thread) = null,
};

/// Maximum cores the scheduler supports. Matches `affinity` mask width.
pub const MAX_CORES: u8 = 64;

var deferred_requeues: [MAX_CORES]ThreadQueue = [_]ThreadQueue{.{}} ** MAX_CORES;
var yield_handoff_targets: [MAX_CORES]?*Thread = [_]?*Thread{null} ** MAX_CORES;
var yield_handoff_preempt_guard: [MAX_CORES]bool = [_]bool{false} ** MAX_CORES;

const WORK_STEALING_ENABLED = switch (builtin.cpu.arch) {
    // aarch64 stays local-only until thread migration has FPU parity:
    // scheduler.migrateFlush, sched/fpu.migrateFlush via SGI, V0-V31 plus
    // FPCR/FPSR save/restore, and CPACR_EL1.FPEN trap-state handoff.
    .aarch64 => false,
    else => true,
};

/// Per-thief rotating victim cursor. Scheduler-local on purpose: `PerCore`
/// layout is referenced by x64 assembly and must not grow for policy state.
var steal_victim_cursors: [MAX_CORES]u8 = [_]u8{0} ** MAX_CORES;

/// Per-thread quantum between preemption ticks. Spec doesn't pin this.
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
/// low-priority thread (e.g. the W in `reply_05`'s `yieldThread(W)`) gets robbed
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
/// `?SlabRef(thread)` requires a tagged-union layout that's not extern-
/// compatible, so `PerCore` is a regular struct.
///
/// CAUTION — the x86-64 IPC fast path DOES reference field offsets in
/// here. `arch/x64/interrupts.zig` steps FP-S14 / R-14 open-code
/// `setCurrentThread` in asm using `@offsetOf(PerCore, "current_thread")` and
/// `@offsetOf(PerCore, "current_thread_gen")`. Any change to the shape of
/// those two fields must be mirrored there; the offsets are computed
/// with `@offsetOf` so a rename is a build error, but a change in
/// WIDTH or in the meaning of the bytes is not.
pub const PerCore = struct {
    /// Priority-ordered intrusive PQ over thread.next. Drained by
    /// `dequeue` on context switch / yield / preempt.
    run_queue: ThreadQueue = .{},

    /// thread currently dispatched on this core. `null` ⇒ core is idle.
    ///
    /// SINGLE-WORD BY CONSTRUCTION, and that is a correctness
    /// requirement, not a micro-optimisation. This slot is written
    /// without any lock by its owning core (`setCurrentThread` /
    /// `clearCurrentThread`) and read WITHOUT A LOCK by other cores —
    /// `awaitProcessQuiesced`'s teardown barrier, `markReady`'s
    /// wake/preempt decision, `currentThreadPtrOn`, the hang detector and
    /// the fatal-fault reporter all do it.
    ///
    /// It used to be `?SlabRef(Thread)`, i.e. a 24-byte
    /// `{ ptr, gen, is_non_null }` aggregate. Measured on the Pi 5
    /// (stygia-eu4): that layout tears. `state.current_thread = null`
    /// compiles to `stp xzr, xzr, [x]` + `str xzr, [x, #0x10]` — it
    /// ZEROES THE POINTER WORD — and `= SlabRef.init(...)` compiles to
    /// `str ptr` / `strb tag` / `str gen` with no release barrier, in
    /// that order. A remote reader loading the three words with no
    /// acquire barrier can therefore observe `is_non_null = 1`
    /// alongside `ptr = 0`, which is not a state any writer ever
    /// intends. `awaitProcessQuiesced` then dereferenced it and took
    /// `KERNEL PAGE FAULT at 0x488` — exactly
    /// `@offsetOf(Thread, "process")` — killing core 1 at
    /// pass 14 of a 100-pass bare-metal run.
    ///
    /// As a plain `?*Thread` the optional IS the pointer
    /// (Zig's null-pointer niche), so publication is one naturally
    /// aligned 8-byte store and observation is one 8-byte load. Neither
    /// can tear on either supported arch, and "non-null" now implies
    /// "dereferenceable" with no ordering argument required. The gen
    /// moved to `current_thread_gen`; it has exactly one consumer, and that
    /// consumer runs on the owning core.
    ///
    /// caller-pinned: bare `*T` is deliberate, matching `committed_thread`
    /// directly below. Cross-core readers perform identity-only
    /// compares (`== thread`, `.process.ptr == process_key`) and never lock
    /// through this pointer; a slab slot's bytes outlive its gen flip,
    /// so a stale-but-non-null value simply mismatches and the reader
    /// moves on.
    current_thread: ?*Thread = null,

    /// Slab generation of `current_thread`, captured at publication time.
    /// Split out of the old `SlabRef` so the pointer can stand alone as
    /// a tear-free word — see `current_thread`. Exactly one consumer, and
    /// it runs on this core (the x86 entry snapshot), so the pointer/gen pair
    /// never needs to be read atomically together.
    current_thread_gen: u32 = 0,

    /// thread whose FP/SIMD state currently lives in this core's CPU
    /// registers. May be a different thread than `current_thread` (lazy FPU —
    /// eviction happens on the next FP-disabled trap, not on context
    /// switch). `null` if no thread has used FP on this core since boot.
    last_fpu_owner: ?SlabRef(Thread) = null,

    /// Whether CR0.TS / FPEN is currently armed on this core. Tracked
    /// here so we don't issue redundant CR-writes (each one costs a
    /// vmexit under KVM).
    fpu_trap_armed: bool = false,

    /// Physical address of the user translation root this core has
    /// LOADED (x86: CR3 root; aarch64: TTBR0), published with
    /// `.release` immediately AFTER each hardware root load. 0 = no
    /// user root (kernel root / parked / detached). This — not
    /// `on_cpu`, not `current_thread` — is the authoritative "may this
    /// core still walk translations of root R" signal that process
    /// teardown must wait on before freeing R's tables (stygia-rs6):
    /// `on_cpu` stays stale-true across the migration boundary and
    /// its gated clears race, and `current_thread` flips BEFORE the
    /// dispatch path's root swap. Publishing after the load closes
    /// both windows.
    active_root: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Gen-dead thread whose final stack/slab cleanup must wait until this
    /// core is no longer executing on that thread's kernel stack. G16 records
    /// this as normative kernel behavior but keeps it out of the TLA model.
    teardown_pending: ?TeardownRequest = null,

    /// Per-core "park" kstack — the kstack this core uses while no real
    /// thread is dispatched. Allocated at `perCoreInit`; sized like any
    /// other kernel stack (KERNEL_STACK_PAGES). When `run()` empties the
    /// queue and falls through the dispatch arm, `parkAndAwaitIRQ`
    /// swaps gs:0 / TSS.RSP0 / rsp to `park_stack.top` so subsequent
    /// kernel-mode IRQs and any future syscall entries land here
    /// instead of on the previously-suspended thread's kstack. Without
    /// this, multiple idle cores can hold stale `gs:0` pointing at the
    /// same suspended thread's kstack and concurrently push IRQ frames
    /// onto it from kernel mode — silent cross-core stack corruption
    /// that surfaces as iretq #GP / NO-thread PF when the corrupted slot
    /// is later popped.
    park_stack: Stack = .{
        .top = .{ .addr = 0 },
        .base = .{ .addr = 0 },
        .guard = .{ .addr = 0 },
        .slot = std.math.maxInt(u64),
    },

    /// True when this core's most recent dispatch decision — taken
    /// under `core_locks[core]` inside `dequeueOrIdleLocked` — found
    /// nothing to run, i.e. the core is heading for (or already
    /// sitting in) its idle park.
    ///
    /// This exists because `enqueueOnCore`'s wake decision cannot use
    /// `current_thread` alone. `current_thread` is cleared by the parking core
    /// AFTER it has dropped `core_locks[core]` (see `yieldTo`'s
    /// empty-queue arm and `run`'s park fall-through, both of which
    /// need the old value for their disowned-thread bookkeeping first), so
    /// there is a window in which the core has committed to parking but
    /// its slot still names the thread it was running. An `enqueueOnCore`
    /// landing in that window reads a non-null `current_thread`, concludes
    /// "target is busy, it will pick the thread up at its next reschedule",
    /// skips the wake IPI — and the target then parks forever with a
    /// `.ready` thread sitting in its queue. The thread is never dispatched and
    /// whatever was waiting on it (a test result, an IPC reply) never
    /// arrives. Nothing else necessarily disturbs that core: futex
    /// wakes and affinity-0 enqueues both prefer the *local* core, so
    /// an idle core can stay untargeted indefinitely.
    ///
    /// Publishing the parking decision under the same lock that guards
    /// the run queue closes the window in both directions:
    ///   - enqueuer wins the lock: it queues the thread before the parking
    ///     decision is made, so `dequeueOrIdleLocked` returns that thread
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
/// `run_queue` and `current_thread`. Held only across queue ops and a
/// snapshot of `current_thread`; never held across `loadThreadContextAndReturn`.
/// Kept out of `PerCore` itself so the IPC fast-path's hardcoded field
/// offsets (72/80) inside `extern struct PerCore` stay pinned.
///
/// Lock order: `core_locks[i]` is its own class; cross-core enqueue may
/// acquire the target core's lock while holding the local core's lock,
/// so the class is registered as ordered to opt out of pair-edge
/// cycle detection. Callers must always release before invoking
/// scheduler dispatch (`switchTo` / `loadThreadContextAndReturn`).
pub var core_locks: [MAX_CORES]SpinLock = [_]SpinLock{.{ .class = "sched.core_lock" }} ** MAX_CORES;

/// Lockdep group tag for `core_locks`. Non-zero so that overlapping
/// per-core lock holds (e.g. cross-core enqueue grabbing target while
/// holding local) don't seed a phantom AB-BA cycle in the lock graph.
pub const SCHED_CORE_GROUP: u32 = 0x5C00; // arbitrary non-zero tag

/// Set true after `globalInit` returns. Read by the boot path before
/// enqueueing the root service's initial thread.
pub var initialized: bool = false;

// ── Init ─────────────────────────────────────────────────────────────

/// Boot-time global init — called once on the BSP before SMP brings
/// other cores up. Initializes `core_states[0]`'s idle thread and any
/// scheduler-wide state.
pub fn globalInit() !void {
    initialized = true;
}

/// Per-core init — called once per core during SMP bring-up after the
/// core's APIC / GIC is online. Arms the per-core preemption timer so
/// the scheduler tick fires every `TIMESLICE_NS` and round-robin
/// between equal-priority Threads is honored. Without this call no LAPIC
/// timer interrupt ever fires and a CPU-bound thread runs forever until
/// it voluntarily yields.
pub fn perCoreInit() void {
    // Allocate this core's park kstack. Used while the run queue is
    // empty AND no thread is dispatched — see `PerCore.park_stack` doc and
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
}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Context switch to `thread` on the current core. Saves outgoing thread's
/// state to its `ctx`, swaps address space (if process changed),
/// updates `current_thread`, applies lazy-FPU policy (arm/clear CR0.TS),
/// loads `thread.ctx` and returns to userspace via iretq/sysretq.
///
/// `current_thread` is written without the per-core lock — only this core
/// ever writes its own `current_thread`, and cross-core readers (FPU flush,
/// `coreRunning`) take an inherent snapshot semantics and re-check on
/// the target.
pub fn switchTo(thread: *Thread) void {
    // vCPU dispatch: spec-v3 §[create_vcpu] requires that every time the
    // vCPU thread becomes runnable (initial creation, reply-induced resume),
    // the kernel re-enters guest mode and on the subsequent guest exit
    // delivers a vm_exit event on its `exit_port`. Real VMX/SVM guest
    // re-entry (loadGuestState → VMLAUNCH/VMRESUME → exit decode) is
    // still a TODO in `arch/x64/hv/vcpu.zig` — until that lands, fire a
    // synthetic exit immediately so the recv/reply lifecycle remains
    // observable end-to-end. The vCPU re-suspends on its exit_port via
    // `fireVmExit` (which may rendezvous with a parked VMM receiver and
    // mark it ready) and we keep dispatching. We MUST NOT return here
    // with `current_thread == null` — the caller (yieldTo / dispatchInterrupt)
    // would iretq back to whatever interrupted-user RIP sits on the
    // kernel stack, and that thread has typically already been suspended
    // (e.g. fault path called fireThreadFault before yieldTo). The next
    // user fault on that stale RIP would re-enter `exceptionHandler`
    // with `currentThread() == null` and panic on the no-current-thread guard.
    // Loop instead: pick the next ready thread; if it's another vCPU, fire
    // its synthetic exit too; eventually we either dispatch a real thread
    // via `loadThreadContextAndReturn` (noreturn) or run dry and fall
    // through to the empty-queue return path that leaves `current_thread`
    // null but is safe because `run()`'s outer `arch.cpu.idle()` and
    // `yieldTo`'s no-next branch are both designed for that.
    var current = thread;
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
            // unknown exit. Zero out thread.ctx.regs so the receiver sees a
            // clean "guest not running" GPR snapshot rather than the
            // prior `consumeReply`'s reply-time values.
            @memset(std.mem.asBytes(&current.ctx.regs), 0);
            break :blk arch.vm.VmExitDelivery{
                .subcode = stygia.hv.virtual_machine.INITIAL_STATE_SUBCODE,
                .payload = .{ 0, 0, 0 },
            };
        };
        // stygia-8xl: a CANCELLED entry means another core retired this
        // vCPU while it was executing guest code, and the run loop left
        // guest mode to acknowledge that rather than exiting on a guest
        // event. There is no event to report and no live thread to suspend —
        // `fireVmExit` would publish a wait episode on a dead thread. Skip it
        // and fall straight through to `dischargeOwnedParking`, which is
        // the owner-side eviction the remote retire has been waiting for.
        if (!delivery.cancelled) {
            port_mod.fireVmExit(current, delivery.subcode, delivery.payload);
        }
        arch.cpu.restoreInterrupts(irq);

        // `fireVmExit` suspends the vCPU through the normal running
        // thread lifecycle. Keep `current_thread` naming the vCPU until that
        // call has published `.parking`, then complete the owner-side
        // handoff here on the scheduler's park stack before selecting
        // another thread. Clearing `current_thread` first makes
        // `suspendOnPort(.running)` reject the event as E_BUSY and
        // strands the VMM's follow-up recv.
        dischargeOwnedParking(core);

        // The exit dispatch above may have rendezvoused with a parked
        // VMM receiver, putting it in this core's run queue. Pull it
        // (or anything else ready) and dispatch.
        const next = dequeueOrIdle() orelse {
            // Empty queue, no idle thread. Returning here unwinds to
            // run() (→ parkAndAwaitIRQ updates caches) or to yieldTo
            // (→ iretq back to the caller's user mode from the
            // current kstack). In either case `current_thread` is null
            // but the per-core caches (gs:0 kernel_rsp, TSS.RSP0,
            // gs:32/40/48/56/176 thread-identity slots) still name the
            // most-recently-dispatched thread's kstack. A peer-core
            // terminate of that thread can free its kstack at any time
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
            // the "wake" preempts a thread that was running fine. That
            // shows up as latency, e.g. a 5 ms deadline
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
    // the OUTGOING thread's. That is fatal whenever the outgoing thread is
    // already claimable by another core (recv/futex/suspend published
    // its wait state; a preempt re-enqueued it): the other core
    // dispatches it, the thread's next kernel entry builds frames from its
    // kstack top downward, and both cores stomp each other's live
    // frames on one kstack. Autopsied as core 2's `syscallDispatch`
    // memcpy running away over the kstack guard (Kernel stack overflow
    // panic) with core 1's switchTo/loadThreadContextAndReturn frames
    // interleaved on the same kstack.
    //
    // Hop to this core's park kstack FIRST, releasing the pending
    // kstack-release stash (if any) at the exact swap instruction, and
    // run the whole dispatch tail there. After the hop, no core ever
    // executes scheduler machinery on a claimable thread's kstack —
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
    arch.cpu.hopToStackAndCall(
        park_top,
        &hop_release_dummy,
        &scheduler_dispatch_tail,
        @intFromPtr(current),
    );
}

/// Dummy byte handed to `hopToStackAndCall`; the primitive's release-store
/// operand is no longer a lifecycle authority.
var hop_release_dummy: u8 = 0;

/// C-callconv landing target for `switchTo`'s kstack hop. Runs on the
/// per-core park kstack; must never return.
export fn scheduler_dispatch_tail(arg: u64) callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const current: *Thread = @ptrFromInt(arg);
    dispatchTailBody(core, current);
}

/// The dispatch tail: everything between the dispatch decision and the
/// context-load trampoline. Runs on the park kstack (or the boot stack
/// before `perCoreInit`). noreturn via `loadThreadContextAndReturn`.
fn dispatchTailBody(core: u8, current: *Thread) noreturn {
    drainTeardown(core, current);
    if ((&core_states[core]).current_thread != current) {
        @panic("scheduler.dispatchTailBody: current_thread changed during teardown drain");
    }
    if (lifecycle.load(current) != .running) {
        dischargeOwnedParking(core);
        run();
    }
    yield_handoff_preempt_guard[core] = yield_handoff_targets[core] == current;
    yield_handoff_targets[core] = null;
    // Give the committed thread a fresh quantum at the dispatch boundary.
    // The old deadline belongs to the outgoing thread; carrying it across a
    // voluntary targeted yield can let an already-due tick preempt the
    // target before it executes one user instruction, which violates the
    // observable-progress contract of yield(target).
    arch.time.getPreemptionTimer().armInterruptTimer(TIMESLICE_NS);
    thread_mod.recordSpawnTrace(current, null, .dispatch_tail, core);
    arch.cpu.loadThreadContextAndReturn(current);
}

fn dischargeOwnedParking(core: u8) void {
    const thread = (&core_states[core]).current_thread orelse return;
    switch (lifecycle.load(thread)) {
        .parking => switch (thread.wait.kind) {
            .requeue => {
                clearCurrentThread(core);
                enqueueOnCore(pickCoreForAffinity(thread.affinity), thread);
            },
            else => {
                if (lifecycle.commitParkingWaiting(thread, NOT_IN_RUN_QUEUE)) {
                    clearCurrentThread(core);
                }
            },
        },
        .pended => {
            lifecycle.waitForPendedPayload(thread);
            clearCurrentThread(core);
            enqueueOnCore(pickCoreForAffinity(thread.affinity), thread);
        },
        .retired => {
            clearCurrentThread(core);
            if (thread._gen_lock.currentGen() % 2 == 0 and !stackContains(thread, arch.cpu.currentSp())) {
                thread_mod.finalizeDestroyMarkedDead(thread);
            }
        },
        else => {},
    }
}

fn drainDeferredRequeuesLocked(core: u8) void {
    const state = &core_states[core];
    while ((&deferred_requeues[core]).dequeue()) |thread| {
        if (lifecycle.load(thread) != .parking or thread.wait.kind != .requeue) continue;
        if (!canPublishReady(thread)) continue;
        if (!lifecycle.cas(thread, .parking, .ready)) continue;
        thread.owner_core = NOT_IN_RUN_QUEUE;
        thread.wait.clear();
        if (!canPublishReady(thread)) continue;
        state.run_queue.enqueue(thread);
        thread.current_queue_core.store(core, .release);
    }
}

pub fn deferLocalRunningRequeue(thread: *Thread) bool {
    const core: u8 = @truncate(arch.smp.coreID());
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);

    if (!lifecycle.prepareRunningPark(thread, core, .requeue)) return false;
    (&deferred_requeues[core]).enqueue(thread);
    return true;
}

fn stackContains(thread: *Thread, sp: u64) bool {
    return sp >= thread.kernel_stack.base.addr and sp < thread.kernel_stack.top.addr;
}

pub fn queueTeardown(core: u8, req: TeardownRequest) bool {
    if (core >= MAX_CORES) return false;
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    const slot = &(&core_states[core]).teardown_pending;
    if (slot.*) |existing| {
        if (existing.process.eql(req.process)) return true;
        return false;
    }
    slot.* = req;
    return true;
}

pub fn queueCurrentTeardown(req: TeardownRequest) void {
    const core: u8 = @truncate(arch.smp.coreID());
    while (!queueTeardown(core, req)) {
        spin_diag.note(.queue_teardown, @intFromPtr(req.process.ptr));
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        stygia.sched.fpu.serviceLocalFlushWhileSpinning();
        std.atomic.spinLoopHint();
    }
}

pub fn claimOwnTeardownInline(thread: *Thread) bool {
    const core: u8 = @truncate(arch.smp.coreID());
    if (thread.owner_core != core) return false;
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    if ((&core_states[core]).current_thread == thread) return false;
    if (stackContains(thread, arch.cpu.currentSp())) return false;
    return true;
}

fn runProcessTeardown(req: TeardownRequest) void {
    const tree_irq = stygia.caps.derivation.tree_mutex.lockIrqSaveOrdered(
        @src(),
        stygia.caps.derivation.TREE_MUTEX_GROUP,
    );
    const process_lr = req.process.lockOrderedIrqSave(
        stygia.caps.derivation.TREE_PROCESS_GROUP,
        @src(),
    ) catch {
        stygia.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);
        return;
    };
    const deferred = stygia.caps.process.destroyPhase1(
        process_lr.ptr,
        req.caller_thread,
    );
    arch.cpu.restoreInterrupts(process_lr.irq_state);
    stygia.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);

    switch (req.kind) {
        .self_delete, .unhandled_fault => stygia.caps.process.destroyPhase2(deferred),
    }
}

pub fn drainTeardown(core: u8, incoming: ?*Thread) void {
    while (true) {
        const req = blk: {
            const lock = &core_locks[core];
            const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
            defer lock.unlockIrqRestore(irq);
            const slot = &(&core_states[core]).teardown_pending;
            const req = slot.* orelse return;
            if (incoming) |thread| {
                const dref = thread.process;
                // `dispatchTailBody` calls this after committing
                // `current_thread` but before entering userspace. Phase-2
                // process teardown deliberately skips the executing
                // core in `awaitProcessQuiesced`; if this core drained
                // teardown for `incoming`'s own process here, it could
                // retire the thread after scheduler selection and before
                // the first user instruction. Leave it pending until
                // the core reaches a null-incoming park/yield drain.
                if (req.process.ptr == dref.ptr and req.process.gen == dref.gen) {
                    return;
                }
            }
            slot.* = null;
            break :blk req;
        };
        runProcessTeardown(req);
    }
}

/// Voluntary yield — current thread drops back into ready, scheduler
/// picks the next. If `target` is non-null and runnable, it runs next.
pub fn yieldTo(target: ?*Thread) void {
    yieldToTarget(.{ .thread = target });
}

/// Voluntary yield to a target whose lifecycle pin is already held by
/// the caller. Scheduler owns and releases the pin, including paths that
/// abandon the caller's kernel stack through a park-stack hop.
pub fn yieldToPinned(target: *Thread) void {
    yieldToTarget(.{ .thread = target, .pinned = true });
}

fn yieldToTarget(initial_target: YieldTarget) void {
    var target = initial_target;
    const core: u8 = @truncate(arch.smp.coreID());
    const state = &core_states[core];
    const lock = &core_locks[core];

    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    // TEMP DIAGNOSTIC (stygia-afo, REMOVE). A null `current_thread` here means
    // this frame has no thread to be re-enqueued under, so if we go on to
    // `switchTo` some other thread the C stack we are standing on is
    // ABANDONED — nothing will ever resume it. That is the exact
    // mechanism blamed for the leaked process teardowns; count the events
    // instead of inferring them from a counter gap.
    const disowned_at_entry = state.current_thread == null;
    if (state.current_thread) |cur| {
        switch (lifecycle.load(cur)) {
            .running => {
                if (lifecycle.prepareRunningPark(cur, core, .requeue)) {
                    lock.unlockIrqRestore(irq);
                    hopParkYield(target);
                }
            },
            .retired => {
                lock.unlockIrqRestore(irq);
                hopParkYield(target);
            },
            .parking, .pended => {
                lock.unlockIrqRestore(irq);
                hopParkYield(target);
            },
            else => {},
        }
    }
    const next = dequeueYieldTargetLocked(core, &target);
    lock.unlockIrqRestore(irq);

    if (next) |n| {
        // `switchTo` is normally `noreturn` (the park-kstack hop into
        // `scheduler_dispatch_tail`), but for a vCPU target the vCPU
        // pre-loop can RETURN when the synthetic vm_exit fires and the
        // subsequent `dequeueOrIdle` runs dry. `current_thread` is null in
        // that case and the caller's iretq path handles it (the
        // affinity-migration arm above never reaches here — it escapes
        // via the hop before selecting `next`).
        if (disowned_at_entry) {
            // TEMP DIAGNOSTIC (stygia-afo, REMOVE).
            stygia.caps.process.noteFrameAbandoned();
        }
        switchTo(n);
        return;
    }

    if ((&core_states[core]).current_thread != null) {
        escapeToRun();
    }

    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top != 0) arch.cpu.parkPerCoreCaches(core, park_top);
    drainTeardown(core, null);
}

/// Preemption tick — invoked from the per-core timer interrupt when
/// the current thread's quantum expires. Re-enqueues current and dispatches.
pub fn preempt() void {
    yieldTo(null);
}

/// Main scheduler loop entry — called from `kMain` (BSP) and
/// `arch.x64.smp.coreInit` (APs) once their per-core state is ready.
/// Picks the highest-priority ready thread (or falls back to per-core idle
/// thread when set, otherwise `sti+hlt` until an IPI arrives), and
/// dispatches; never returns.
/// Shared exit for `yieldTo`'s noreturn escapes into `run()`. The
/// escapes abandon the caller's IRQ epilogue, so on x86 the in-service
/// sched vector (0xFE) must be EOI'd first: it outranks both the wake
/// IPI and tlb_shootdown vectors, so a core that parks with it still
/// in service goes deaf to cross-core wakes (stranded-RDY-thread hangs)
/// and shootdown IPIs (initiator spins forever on the missing ack).
/// Safe from syscall-context callers too — LAPIC EOI with an empty ISR
/// is a no-op. aarch64 EOIs before dispatching the handler (early-EOI),
/// so the dispatch helper is a no-op there.
fn escapeToRun() noreturn {
    arch.irq.schedulerEscapeEoi();
    hopParkRun();
}

fn hopParkYield(target: YieldTarget) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const park_top = (&core_states[core]).park_stack.top.addr;
    arch.irq.schedulerEscapeEoi();
    if (park_top == 0) {
        dischargeOwnedParking(core);
        var local_target = target;
        const incoming = local_target.thread;
        drainTeardown(core, incoming);
        if (dequeueYieldTarget(core, &local_target)) |next| switchTo(next);
        run();
    }
    arch.cpu.hopToStackAndCall(
        park_top,
        &hop_release_dummy,
        &scheduler_hop_yield,
        target.encodeForHop(),
    );
}

export fn scheduler_hop_yield(arg: u64) callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    var target = YieldTarget.decodeFromHop(arg);
    dischargeOwnedParking(core);
    drainTeardown(core, target.thread);
    if (dequeueYieldTarget(core, &target)) |next| switchTo(next);
    run();
}

/// Abandon the current kernel stack for this core's park kstack and
/// enter `run()` there. The landing pad completes any owned
/// `parking`/`pended` episode after the hop, when the thread's stack is no
/// longer live on this core.
///
/// Boot fallback: before `perCoreInit` allocates the park stacks
/// nothing is claimable and there is no park kstack — enter `run()` in
/// place.
pub fn hopParkRun() noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top == 0) {
        dischargeOwnedParking(core);
        run();
    }
    arch.cpu.hopToStackAndCall(park_top, &hop_release_dummy, &scheduler_hop_run, 0);
}

/// C-callconv landing target for `hopParkRun`. Runs on the park
/// kstack with the pending kstack release already published by the hop
/// primitive; drains the migration handoff, then enters the scheduler
/// loop. Never returns.
export fn scheduler_hop_run(arg: u64) callconv(.c) noreturn {
    _ = arg;
    const core: u8 = @truncate(arch.smp.coreID());
    dischargeOwnedParking(core);
    drainTeardown(core, null);
    run();
}

pub fn run() noreturn {
    while (true) {
        if (dequeueOrIdle()) |next| {
            switchTo(next);
        }
        // Run queue empty and no idle_thread set up. Park this core on its
        // dedicated park kstack and sti+hlt until an IRQ wakes us.
        // `parkAndAwaitIRQ` swaps rsp / gs:0 / TSS.RSP0 / per-core
        // caches to park-state and tail-jumps back into `run()` on
        // wake — the outer call frame on the previously-dispatched
        // thread's kstack is abandoned. This eliminates the cross-core
        // kstack-sharing bug where multiple idle cores held stale
        // gs:0 pointing at the same suspended thread's kstack and
        // concurrently pushed IRQ frames onto it from kernel mode,
        // silently stomping each other's saved state and surfacing
        // as iretq #GP or NO-thread PF when the corrupted iret slot was
        // later popped.
        parkAndAwaitIRQ();
    }
}

/// Park this core on its per-core park kstack and idle until an IRQ
/// arrives. Updates the per-core caches (gs:0/32/40/48/56/176, TSS.RSP0,
/// PerCore.current_thread) to "no thread dispatched" state, swaps rsp to the
/// park kstack top, then sti+hlt. On IRQ-driven wake jumps back into
/// `run()` via the exported entry symbol — the original caller's call
/// frame is abandoned. See `PerCore.park_stack`.
///
/// Returns early WITHOUT parking when a peer race-enqueued work between
/// `run()`'s queue check and our lock-protected re-check of the same
/// queue (see "lost-wake race" below). Caller (`run()`) loops and
/// re-runs `dequeueOrIdle`, which now sees the raced-in thread and
/// dispatches it via the normal path. Hence `void` rather than
/// `noreturn`.
fn parkAndAwaitIRQ() void {
    const core: u8 = @truncate(arch.smp.coreID());
    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top == 0) @panic("parkAndAwaitIRQ: park_stack not initialized");

    drainTeardown(core, null);

    // ── lost-wake race window ────────────────────────────────────────
    //
    // Without the lock-protected re-check below, this sequence loses a
    // wakeup at smp=4 once per ~5-10 reps on terminate/affinity/yield
    // batches. The original signature is "core 0 has 2 RDY Threads in its
    // run_queue, current_thread=null, all 4 cores parked" with no further
    // LAPIC ticks for the rest of the run.
    //
    //   T0: this core's `dequeueOrIdle()` returned null (lock taken+dropped).
    //   T1: peer P calls `enqueueOnCore(this_core, thread)`:
    //         - takes core_locks[this_core]
    //         - run_queue.enqueue(thread)
    //         - reads `current_thread` slot — STILL the stale prev_ref
    //           (this core hasn't published null yet)
    //         - drops the lock
    //         - sees `target_current_ptr != null` → "busy" branch
    //         - if `thread.priority <= prev.priority` → no IPI sent
    //   T2: this core writes `current_thread = null` (no lock)
    //   T3: this core sti+hlt — never wakes because no IPI is coming
    //       and no prior caller re-armed our LAPIC for a near-future
    //       fire (the peer's enqueue path doesn't re-arm; only our
    //       own schedTimerHandler does, and we're parked).
    //
    // The fix: publish `current_thread = null` UNDER core_locks[this_core]
    // and re-check the run queue in the same critical section. If a
    // peer raced an enqueue in, signal "abandon park" to the caller
    // (`run()`) by returning early; the caller's loop re-runs
    // `dequeueOrIdle` and dispatches via the normal path. If we still
    // see an empty queue, the next enqueue will observe the published
    // null and send the wake IPI, which delivers when sti runs in the
    // arch trampoline below.
    //
    // The drain above runs OUTSIDE the lock (finalize takes its own
    // process/port locks; nesting them under core_locks would seed an
    // out-of-class acquire). We re-drain post-wake in the asm landing
    // pad anyway, so any zombie posted between the pre-park drain and
    // the lock acquire below gets reaped on the next wake — what
    // matters at THIS instant is that the run-queue check and the
    // current_thread-null publish are atomic.
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    // Use `dequeueOrIdleLocked` rather than a raw `isEmpty` check: the
    // queue may contain `.exited` Threads that yieldTo's race-prone re-enqueue
    // window dropped in (a yieldTo that read `state == .running` from a
    // racing terminate's pre-flip can re-enqueue a thread after the second
    // sweep, leaving it dangling). dequeue filters those — if we bailed on
    // a queue containing only stale entries, `run()` would loop right back
    // through dequeueOrIdle, see only filterable junk, and re-park,
    // burning CPU on a tight cycle until the queue is cleaned out.
    if (dequeueOrIdleLocked(core)) |raced_in| {
        // Peer race: a thread landed in our queue between `run()`'s
        // `dequeueOrIdle()` and now. Bail park, dispatch directly under
        lock.unlockIrqRestore(irq);
        switchTo(raced_in);
        // switchTo is conventionally noreturn (loadThreadContextAndReturn);
        // it can return only via the vCPU-loop empty-queue exit, in
        // which case current_thread is null and the per-core caches are
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
    (&core_states[core]).current_thread = null;
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
    // EOI'd and CONSUMED, after which the halt sleeps with `thread` sitting
    // `.ready` in this core's queue and nothing left to poke us.
    //
    // Discarding the saved state is sound precisely because this path
    // never returns: the park primitive tail-jumps to
    // `scheduler_run_after_park`, which re-enters `run()` under the same
    // masked contract.
    lock.unlock();

    // Detach from whatever user translation root the last dispatch
    // left loaded and publish "no user root" BEFORE halting. A parked
    // core otherwise keeps the previous process's root live in CR3 —
    // if that process is then destroyed, `freeUserAddrSpace` recycles
    // the tables this core's next IRQ entry walks through (stygia-rs6
    // family). The kernel half is shared across all roots, so the
    // swap is transparent to the park path itself; the publish order
    // (hardware load first, then store-release) keeps the teardown
    // barrier in `destroyPhase2` honest. Any stale dispatch
    // commitment is retired too — this core is committing to hlt.
    arch.paging.loadKernelRoot(memory_init.kernel_addr_space_root);
    publishActiveRoot(core, 0);

    // Re-arm the preemption timer before sleeping — a parked core must
    // keep a heartbeat. The idle path's final timer tick was silenced
    // at the source (aarch64: silenceTimerLineIfFiring sets
    // CNTV_CTL.IMASK so the level-sensitive PPI de-asserts; the
    // matching unmask lives in armInterruptTimer, which only the
    // DISPATCH path reaches), so a parked core otherwise has no
    // periodic wake source at all and exactly one stale wake decision
    // in enqueueOnCore strands its run queue forever. Measured on the
    // .106 KVM reproducer as the persistent affinity_05/06 +
    // create_thread_14 MISS: pass 1 parks cores 1..3 with
    // silenced timers, and the first pinned enqueue that reads a stale
    // busy/parked snapshot never gets a second chance. With the
    // heartbeat, a missed wake costs one timeslice instead of the run.
    arch.time.getPreemptionTimer().armInterruptTimer(TIMESLICE_NS);

    arch.cpu.parkAndAwaitIRQ(park_top);
}

/// Asm landing pad after `parkAndAwaitIRQ`'s wake: rsp is on the park
/// kstack, IRQs are masked. Re-enter `run()` to re-check the queue.
/// `run()` is noreturn so the call never returns; the pushed return
/// address sits unused on the park stack.
export fn scheduler_run_after_park() callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    drainTeardown(core, null);
    run();
}

/// Internal helper — dequeues the highest-priority thread, or returns the
/// per-core idle thread if the queue is empty. Returns null when both are
/// empty (caller drops to `sti+hlt` and waits for a wake IPI).
/// True while `thread`'s process SlabRef still names the process slot's live
/// gen. Turns false the instant `destroyPhase1` dead-marks the process —
/// i.e. it covers the phase1→phase2 teardown gap in which the
/// process's Threads are themselves still gen-live and `.ready` but their
/// process (and imminently its translation root) is being destroyed.
/// Every dispatch-commitment site must refuse such Threads BEFORE the
/// `switchTo` process deref; see the stygia-rs6 CR3=0 corpse notes at
/// the dequeue filter.
inline fn processRefAlive(thread: *Thread) bool {
    const dref = thread.process;
    return dref.ptr._gen_lock.currentGen() == @as(u64, dref.gen);
}

inline fn canPublishReady(thread: *Thread) bool {
    return thread._gen_lock.currentGen() % 2 == 1 and !lifecycle.isDestroyMarked(thread) and processRefAlive(thread);
}

fn diagTag(thread: *Thread) u64 {
    return thread.diag_test_tag;
}

fn logYieldSelectDiag(core: u8, target: *Thread, reason: []const u8, publishable: bool) void {
    if (!build_options.kernel_spawn_diag) return;
    const n = @atomicRmw(u32, &yield_select_diag_prints, .Add, 1, .monotonic);
    if (n >= YIELD_SELECT_DIAG_BUDGET) return;
    arch.boot.print(
        "[yseldbg] reason={s} tag=0x{x} core={d} target=0x{x} state={x} wait={x} owner={x} qcore={x} gen={x} mark={x} affinity=0x{x} publish={x}\n",
        .{
            reason,
            diagTag(target),
            core,
            @intFromPtr(target),
            @intFromEnum(lifecycle.load(target)),
            @intFromEnum(target.wait.kind),
            target.owner_core,
            target.current_queue_core.load(.acquire),
            target._gen_lock.currentGen(),
            target.mark_state.load(.acquire),
            target.affinity,
            @intFromBool(publishable),
        },
    );
}

fn dequeueOrIdle() ?*Thread {
    const core: u8 = @truncate(arch.smp.coreID());
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    const result = dequeueOrIdleLocked(core);
    lock.unlockIrqRestore(irq);
    return result;
}

/// Lock-held variant of `dequeueOrIdle` — caller must hold
/// `core_locks[core]` with IRQs masked.
fn dequeueOrIdleLocked(core: u8) ?*Thread {
    const state = &core_states[core];
    drainDeferredRequeuesLocked(core);
    if (dequeueLocalReadyLocked(core)) |thread| return thread;
    if (tryStealReadyLocked(core)) |thread| return thread;
    // Nothing to run: the caller parks this core. Publish that decision
    // under `core_locks[core]` so a concurrent `enqueueOnCore` knows to
    // send the wake IPI even though `current_thread` has not been cleared
    // yet. See `PerCore.idle_parked`.
    state.idle_parked = true;
    return null;
}

fn dequeueLocalReadyLocked(core: u8) ?*Thread {
    const state = &core_states[core];
    yield_handoff_targets[core] = null;
    while (state.run_queue.dequeue()) |thread| {
        // Clear queue residency on every popped thread, regardless of
        // whether we end up dispatching it or skipping it as stale —
        // either way it is no longer linked into any run queue.
        // Performed under `core_locks[core]` so a concurrent
        // `removeFromQueue` reader that observed a stale `core`
        // residency hint and is now waiting on this lock will see the
        // cleared sentinel after acquiring.
        thread.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        if (!canPublishReady(thread)) {
            thread_mod.recordSpawnTrace(thread, null, .dequeue_skip_not_publishable, core);
            continue;
        }
        if (!lifecycle.prepareDispatchLocked(thread, core, NOT_IN_RUN_QUEUE)) continue;
        setCurrentThread(core, thread);
        state.idle_parked = false;
        thread_mod.recordSpawnTrace(thread, null, .dequeue_select, core);
        return thread;
    }
    return null;
}

fn stealCandidateFromVictimLocked(thief: u8, victim: u8) ?*Thread {
    const state = &core_states[victim];
    var idx: usize = state.run_queue.levels.len;
    while (idx > 0) {
        idx -= 1;
        var cur = state.run_queue.levels[idx].head;
        while (cur) |thread| {
            cur = thread.next;
            if (!affinityAdmitsCore(thread.affinity, thief)) continue;
            if (!canPublishReady(thread)) continue;
            if (thread.owner_core != NOT_IN_RUN_QUEUE) continue;
            if (lifecycle.load(thread) != .ready) continue;

            const queue_core = thread.current_queue_core.load(.acquire);
            if (queue_core != victim and queue_core != NOT_IN_RUN_QUEUE) continue;
            if (!runQueueContains(&state.run_queue, thread)) continue;
            if (!lifecycle.beginReadyClaimPinned(thread)) continue;

            const removed = state.run_queue.remove(thread);
            std.debug.assert(removed);
            thread.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
            return thread;
        }
    }
    return null;
}

fn stealFromVictimsUnlocked(thief: u8) ?*Thread {
    if (!WORK_STEALING_ENABLED) return null;

    const core_count_u64 = @min(arch.smp.coreCount(), @as(u64, MAX_CORES));
    if (core_count_u64 <= 1) return null;
    const core_count: usize = @intCast(core_count_u64);

    var victim = @as(usize, steal_victim_cursors[thief]) % core_count;
    var checked: usize = 0;
    while (checked < core_count - 1) {
        if (victim == @as(usize, thief)) {
            victim = (victim + 1) % core_count;
            continue;
        }

        const victim_core: u8 = @intCast(victim);
        const lock = &core_locks[victim];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const stolen = stealCandidateFromVictimLocked(thief, victim_core);
        lock.unlockIrqRestore(irq);

        checked += 1;
        const next_victim = (victim + 1) % core_count;
        if (stolen) |thread| {
            steal_victim_cursors[thief] = @intCast(next_victim);
            return thread;
        }
        victim = next_victim;
    }

    steal_victim_cursors[thief] = @intCast(victim);
    return null;
}

fn abandonStolenReadyUnlocked(thread: *Thread) void {
    if (!canPublishReady(thread)) {
        thread_mod.dischargeClaimedHolderDead(thread);
        return;
    }
    switch (enqueuePinnedClaimed(thread)) {
        .published, .not_claimed => {},
        .not_publishable, .claimed_unpublishable => {
            thread_mod.dischargeClaimedHolderDead(thread);
            return;
        },
    }
    lifecycle.releasePin(thread);
}

fn commitStolenDispatchLocked(core: u8, thread: *Thread) bool {
    if (!canPublishReady(thread)) return false;
    if (!lifecycle.finishClaimedDispatch(thread, core, NOT_IN_RUN_QUEUE)) return false;
    setCurrentThread(core, thread);
    yield_handoff_targets[core] = null;
    (&core_states[core]).idle_parked = false;
    lifecycle.releasePin(thread);
    thread_mod.recordSpawnTrace(thread, null, .dequeue_select, core);
    return true;
}

fn tryStealReadyLocked(core: u8) ?*Thread {
    if (!WORK_STEALING_ENABLED) return null;

    const thief_lock = &core_locks[core];
    thief_lock.unlock();
    const stolen = stealFromVictimsUnlocked(core);
    const thief_irq = thief_lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    const thread = stolen orelse return null;
    if (dequeueLocalReadyLocked(core)) |local| {
        thief_lock.unlockIrqRestore(thief_irq);
        abandonStolenReadyUnlocked(thread);
        _ = thief_lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        return local;
    }
    if (commitStolenDispatchLocked(core, thread)) return thread;

    thief_lock.unlockIrqRestore(thief_irq);
    abandonStolenReadyUnlocked(thread);
    _ = thief_lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    return null;
}

fn affinityAdmitsCore(affinity: u64, core: u8) bool {
    return affinity == 0 or (core < 64 and (affinity & (@as(u64, 1) << @truncate(core))) != 0);
}

fn dequeueYieldTarget(core: u8, target: *YieldTarget) ?*Thread {
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    return dequeueYieldTargetLocked(core, target);
}

fn dequeueYieldTargetLocked(core: u8, target: *YieldTarget) ?*Thread {
    const state = &core_states[core];
    if (target.thread) |t| {
        defer target.release();

        // `processRefAlive`: same dying-process dispatch gate as the
        // dequeue filter — a yieldTo target whose process was dead-marked
        // by destroyPhase1 must not be committed (its queue entry, if
        // any, is drained and dropped by dequeueOrIdleLocked instead).
        if (!affinityAdmitsCore(t.affinity, core)) {
            logYieldSelectDiag(core, t, "affinity", false);
        } else if (lifecycle.load(t) != .ready) {
            logYieldSelectDiag(core, t, "not_ready", false);
        } else if (!canPublishReady(t)) {
            logYieldSelectDiag(core, t, "not_publishable", false);
        } else if (!state.run_queue.remove(t)) {
            logYieldSelectDiag(core, t, "not_in_run_queue", true);
        } else {
            if (!canPublishReady(t)) {
                logYieldSelectDiag(core, t, "post_remove_not_publishable", false);
                t.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
                return dequeueOrIdleLocked(core);
            }
            if (lifecycle.prepareDispatchLocked(t, core, NOT_IN_RUN_QUEUE)) {
                logYieldSelectDiag(core, t, "selected", true);
                setCurrentThread(core, t);
                yield_handoff_targets[core] = t;
                state.idle_parked = false;
                return t;
            }
            logYieldSelectDiag(core, t, "prepare_dispatch_failed", true);
        }
    }
    return dequeueOrIdleLocked(core);
}

// ── Enqueue / current accessors ──────────────────────────────────────

const EnqueuePinnedResult = enum {
    published,
    not_publishable,
    not_claimed,
    claimed_unpublishable,
};

fn finishEnqueuePublish(core: u8, thread: *Thread, irq: u64) void {
    const lock = &core_locks[core];
    (&core_states[core]).run_queue.enqueue(thread);
    // Publish queue residency under the target core's lock so a
    // racing `removeFromQueue(thread)` from a third core can target the
    // right lock instead of sweeping all 64. `.release` pairs with
    // the `.acquire` load in `removeFromQueue`.
    thread.current_queue_core.store(core, .release);
    // Snapshot the target's current thread before deciding whether to
    // wake / preempt. Reading the remote core's `current_thread` is a racy
    // hint — the worst case if it changes after we decide is a spurious
    // wake or a missed preempt that the next preempt tick covers.
    // caller-pinned: read-only snapshot of the target core's
    // `current_thread` for the wake/preempt decision. Worst-case stale ptr
    // just costs a spurious IPI; any real deref is gated below. Now a
    // single tear-free word — under the old `?SlabRef` layout a torn
    // read could yield a NON-NULL optional wrapping a ZERO pointer,
    // which reads as "target is busy" and silently suppresses the wake
    // IPI (see `PerCore.current_thread`).
    const target_current_ptr: ?*Thread = (&core_states[core]).current_thread;
    // Read the target's parking decision under the SAME lock that just
    // published `thread` into its queue. `current_thread` alone is not enough:
    // a core that has already committed to parking still names its last
    // thread there until after it drops this lock, and treating that as
    // "busy, it will pick `thread` up later" strands `thread` on a core that
    // never wakes. See `PerCore.idle_parked`.
    const target_parked = (&core_states[core]).idle_parked;
    const publish_aux: u64 =
        @as(u64, core) |
        (if (target_current_ptr != null) @as(u64, 1) << 8 else 0) |
        (if (target_parked) @as(u64, 1) << 9 else 0);
    thread_mod.recordSpawnTrace(thread, null, .enqueue_publish, publish_aux);
    lock.unlockIrqRestore(irq);

    const self_core: u8 = @truncate(arch.smp.coreID());

    // Wake and preempt are independent decisions; evaluate both.
    //
    // Wake: the target is idle, or has committed to parking and is
    // merely still carrying a stale `current_thread`. Either way the only
    // thing that will make it look at its queue again is a wake.
    //
    // Local self-wake is unnecessary — the caller is running, not
    // halted. That holds for the parked case too: an IRQ handler that
    // wakes a core out of its park (timer tick → `expireTimedWaiters`,
    // futex wake with affinity 0) runs on that core and returns through
    // the park loop, which re-runs `dequeueOrIdle` and finds `thread`.
    if (target_current_ptr == null or target_parked) {
        if (core != self_core) arch.smp.sendWakeIpi(core);
    }

    // Preempt: deliberately NOT an `else` on the wake above. A core can
    // resume without re-running `dequeueOrIdleLocked` (`switchTo`'s
    // vCPU-empty return unwinds through `yieldTo` back to user mode),
    // leaving `idle_parked` stale-true while it is genuinely busy.
    // Folding the preempt into the wake's `else` would swallow the
    // priority decision in exactly that case and delay a higher-
    // priority thread by up to a full quantum. A wake IPI to a running core
    // does not reschedule; only the scheduler IPI does.
    //
    // caller-pinned: snapshot ptr; race-tolerant priority compare.
    const cur = target_current_ptr orelse return;
    if (@intFromEnum(thread.priority) <= @intFromEnum(cur.priority)) return;

    // Same-core higher-pri: send a LAPIC self-IPI (deferred until the
    // caller exits the current critical section / IRQ handler and IF=1
    // is restored). We can't inline-yield here because callers like
    // `futex.wake` hold a bucket spinlock across `enqueueOnCore`, and
    // a context-switch via `loadThreadContextAndReturn` would strand it.
    //
    // Cross-core higher-pri: same scheduler IPI. The receiver runs
    // `preempt()` which re-evaluates the queue and switches.
    arch.smp.triggerSchedulerInterrupt(core);
}

fn enqueueClaimedOnCorePinned(core: u8, thread: *Thread) EnqueuePinnedResult {
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    if (!canPublishReady(thread)) {
        thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_not_publishable, core);
        lock.unlockIrqRestore(irq);
        return .not_publishable;
    }
    if (lifecycle.load(thread) != .claimed) {
        thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_state, @intFromEnum(lifecycle.load(thread)));
        lock.unlockIrqRestore(irq);
        return .not_claimed;
    }
    if (!lifecycle.finishClaimedReady(thread, NOT_IN_RUN_QUEUE)) {
        lock.unlockIrqRestore(irq);
        return .not_claimed;
    }

    if (!canPublishReady(thread)) {
        thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_not_publishable, core);
        std.debug.assert(thread.current_queue_core.load(.acquire) == NOT_IN_RUN_QUEUE);
        std.debug.assert(lifecycle.cas(thread, .ready, .claimed));
        lock.unlockIrqRestore(irq);
        return .claimed_unpublishable;
    }

    finishEnqueuePublish(core, thread, irq);
    return .published;
}

fn enqueuePinnedClaimed(thread: *Thread) EnqueuePinnedResult {
    return enqueueClaimedOnCorePinned(pickCoreForAffinity(thread.affinity), thread);
}

/// Enqueue `thread` on `core`'s run queue. Used by recv → ready transitions,
/// futex wake, timer fires, and the boot path.
///
/// Wake / preempt policy after queueing:
///   - target idle (no `current_thread`) or parking (`idle_parked`, set
///     under this same lock) and target != self: send wake IPI so the
///     parked `hlt`/`wfi` exits and `run` re-runs `dequeueOrIdle`.
///   - target current thread outranks `thread`: nothing to do — `thread` waits its
///     turn. Only sound because `idle_parked` was checked first: a
///     target that has committed to parking still names its last thread in
///     `current_thread`, and trusting that alone strands `thread` forever.
///   - `thread` outranks target's current thread: send a scheduler IPI to the
///     target. Self-IPI (when target == self) is LAPIC-ICR-based, so
///     it's IF-gated and fires once the caller exits its current IRQ /
///     spinlock-held window. We deliberately do NOT inline-yield: many
///     callers (e.g. `futex.wake`) hold a bucket lock across this call,
///     and a context-switch via `loadThreadContextAndReturn` would strand
///     it.
pub fn enqueueOnCore(core: u8, thread: *Thread) void {
    thread_mod.recordSpawnTrace(thread, null, .enqueue_attempt, core);
    if (!lifecycle.tryPinLive(thread)) {
        thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_not_live, core);
        return;
    }
    defer lifecycle.releasePin(thread);

    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    if (!canPublishReady(thread)) {
        thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_not_publishable, core);
        lock.unlockIrqRestore(irq);
        return;
    }
    switch (lifecycle.load(thread)) {
        .ready => {},
        .claimed => {
            if (!lifecycle.finishClaimedReady(thread, NOT_IN_RUN_QUEUE)) {
                lock.unlockIrqRestore(irq);
                return;
            }
        },
        .pended => {
            if (!lifecycle.finishPendedReady(thread, NOT_IN_RUN_QUEUE)) {
                lock.unlockIrqRestore(irq);
                return;
            }
        },
        .parking => {
            if (thread.wait.kind != .requeue or !lifecycle.cas(thread, .parking, .ready)) {
                lock.unlockIrqRestore(irq);
                return;
            }
            thread.owner_core = NOT_IN_RUN_QUEUE;
            thread.wait.clear();
        },
        else => {
            thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_state, @intFromEnum(lifecycle.load(thread)));
            lock.unlockIrqRestore(irq);
            return;
        },
    }

    if (!canPublishReady(thread)) {
        thread_mod.recordSpawnTrace(thread, null, .enqueue_skip_not_publishable, core);
        lock.unlockIrqRestore(irq);
        return;
    }

    finishEnqueuePublish(core, thread, irq);
}

/// Enqueue `thread` on the kernel's choice of core, honoring `thread.affinity`.
pub fn enqueue(thread: *Thread) void {
    enqueueOnCore(pickCoreForAffinity(thread.affinity), thread);
}

/// Remove `thread` from whichever per-core run queue it currently occupies.
/// Used by terminate / suspendOnPort / destroyThreadLocked.
///
/// Fast path (bd-mlpx / bd-vzdh): consult `thread.current_queue_core` —
/// the per-thread residency hint Zig enqueue/dequeue/remove sites maintain
/// under `core_locks[core]` — and target only that one core's lock
/// when the hint is non-sentinel. This drops the per-call cost from
/// `MAX_CORES = 64` lock acquires down to one for the thread-not-in-queue
/// case (terminate / paired post-`.exited` sweep / destroyPhase2 reap
/// on faulted Threads, the bd-vzdh contention scenario), eliminating the
/// O(MAX_CORES) cache-line bouncing that compounded into ~2.5 s of
/// LAPIC-tick suppression under SMP=4 concurrent process destroys.
///
/// Fallback (`current_queue_core == NOT_IN_RUN_QUEUE`): sweep all 64
/// per-core locks. Required for stale-hint races and for any thread that
/// was removed from one queue while the caller's hint snapshot was old;
/// the x64 IPC fast path now publishes this field in its ready-enqueue
/// branches, matching the Zig enqueue discipline.
pub fn removeFromQueue(thread: *Thread) void {
    const hint = thread.current_queue_core.load(.acquire);
    if (hint < MAX_CORES) {
        const lock = &core_locks[hint];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const removed = (&core_states[hint]).run_queue.remove(thread) or
            (&deferred_requeues[hint]).remove(thread);
        if (removed) {
            thread.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        }
        lock.unlockIrqRestore(irq);
        if (removed) return;
        // Hint was stale (thread migrated between our load and our lock
        // acquire, or the asm fast-path put it in a different queue).
        // Fall through to the legacy sweep.
    }
    var i: u8 = 0;
    while (i < MAX_CORES) {
        const lock = &core_locks[i];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const removed = (&core_states[i]).run_queue.remove(thread) or
            (&deferred_requeues[i]).remove(thread);
        if (removed) {
            thread.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        }
        lock.unlockIrqRestore(irq);
        if (removed) return;
        i += 1;
    }
}

fn runQueueContains(queue: *ThreadQueue, target: *Thread) bool {
    for (&queue.levels) |*level| {
        var cur = level.head;
        while (cur) |thread| {
            if (thread == target) return true;
            cur = thread.next;
        }
    }
    return false;
}

fn claimReadyFromLockedQueue(core: u8, thread: *Thread, expected_gen: ?u32) bool {
    const state = &core_states[core];
    const queue_core = thread.current_queue_core.load(.acquire);
    if (queue_core != core and queue_core != NOT_IN_RUN_QUEUE) return false;

    const thread_gen = thread._gen_lock.currentGen();
    if (expected_gen) |gen| {
        if (thread_gen != @as(u63, gen)) return false;
    }
    if (thread_gen % 2 == 0 or !processRefAlive(thread)) return false;
    if (thread.owner_core != NOT_IN_RUN_QUEUE) return false;
    if (lifecycle.load(thread) != .ready) return false;
    if (!runQueueContains(&state.run_queue, thread)) return false;
    if (!lifecycle.beginReadyClaimPinned(thread)) return false;

    const removed = state.run_queue.remove(thread);
    std.debug.assert(removed);
    thread.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
    return true;
}

/// Claim a ready thread under the run-queue lock that proves its membership,
/// then unlink it from that queue. On success, the returned thread is in
/// `.claimed`, no longer belongs to any run queue, and the caller owns a
/// lifecycle pin until it re-publishes or drops the claim.
pub fn claimReadyFromQueue(thread: *Thread, expected_gen: ?u32) bool {
    const hint = thread.current_queue_core.load(.acquire);
    if (hint < MAX_CORES) {
        const lock = &core_locks[hint];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const claimed = claimReadyFromLockedQueue(hint, thread, expected_gen);
        lock.unlockIrqRestore(irq);
        if (claimed) return true;
    }

    var i: u8 = 0;
    while (i < MAX_CORES) {
        if (i == hint) {
            i += 1;
            continue;
        }
        const lock = &core_locks[i];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const claimed = claimReadyFromLockedQueue(i, thread, expected_gen);
        lock.unlockIrqRestore(irq);
        if (claimed) return true;
        i += 1;
    }
    return false;
}

/// Currently dispatched thread on this core (the calling core).
///
/// IMPORTANT: indexes via `&core_states[i]` rather than the direct
/// `(&core_states[i]).field` form. In Debug builds Zig codegens the
/// latter as a `memcpy` of the entire `[MAX_CORES]PerCore` array onto
/// the caller's stack (≈ 6 KiB) followed by an index-of-the-copy
/// load — see `__zig_probe_stack` + `memcpy($0x1800, ...)` in the
/// disassembly. `currentThread` is on every page-fault, syscall, and
/// dispatch path, so unbounded 6 KiB-per-call stack blowups quickly
/// overflow the 48 KiB kernel stack and corrupt return addresses,
/// surfacing as `cpu.idle` returning to a `.bss` byte (#GP) or as
/// `pageFaultHandler` re-entering with `currentThread() == null` because
/// the stack-frame for the saved thread pointer was clobbered. Pointer
/// indexing avoids the per-call array snapshot.
pub fn currentThread() ?*Thread {
    const core: u8 = @truncate(arch.smp.coreID());
    // caller-pinned: `current_thread` names the thread actually executing on this
    // very core; the slot can't be freed under us while this code runs.
    return (&core_states[core]).current_thread;
}

/// True if this core's `current_thread` slot names `thread`. Identity-compare
/// helper used by suspend / terminate / fault paths to clear the
/// dispatch slot when the running thread parks itself.
pub inline fn coreCurrentIs(core: u8, thread: *Thread) bool {
    // caller-pinned: identity compare on `current_thread` slot.
    return (&core_states[core]).current_thread == thread;
}

pub inline fn coreCurrentIsRunning(core: u8, thread: *Thread) bool {
    return coreCurrentIs(core, thread) and lifecycle.load(thread) == .running;
}

/// Clear this core's `current_thread` slot. Called by suspend / terminate /
/// idle paths when the running thread stops being runnable.
/// Publish the user translation root this core has just LOADED (0 =
/// none / kernel root). Callers MUST issue the hardware root load
/// BEFORE this store — see the `PerCore.active_root` field doc.
pub inline fn publishActiveRoot(core: u8, root_addr: u64) void {
    (&core_states[core]).active_root.store(root_addr, .release);
}

/// Spin until no core can execute through the dying process's
/// translation tables. Two per-core clauses, both required:
///
///   1. `active_root == root_addr` — the core has the dying root
///      LOADED (published with release-after-load; see
///      `PerCore.active_root`).
///   2. `current_thread` names a thread whose `process.ptr == process_ptr` — the
///      core has COMMITTED to dispatching a dying-process thread but may
///      not have loaded (or published) its root yet. `current_thread`
///      flips at `setCurrentThread`, well before the dispatch path's
///      root swap, so it is the conservative early signal for
///      in-flight dispatches: a corpse showed a core dying INSIDE
///      `interrupts.switchTo` (post-`setCurrentThread`, pre-publish,
///      stalled in migrateFlush) when the teardown freed the root
///      it was about to load.
///
/// Process teardown calls this after the destroy walk (zombies + wake
/// IPIs posted, gens bumped) and before freeing any table. Both
/// clauses converge: dying-process Threads are gen-dead so no NEW dequeue
/// can dispatch them (dequeueOrIdleLocked filters even-gen), running
/// victims get evicted within one IRQ delivery, and an in-flight
/// dispatch either completes (publishing the root — clause 1 holds
/// it) or aborts. Residual window: the dequeue→setCurrentThread sliver
/// carries a committed thread in neither signal; it contains no spins
/// and its close (`setCurrentThread`'s SlabRef.init) asserts on the
/// bumped gen, so it cannot silently dispatch. Cross-core reads of
/// `thread.process.ptr` are identity-only; slab memory persists after
/// reap (zeroed ⇒ ptr mismatch ⇒ clause exits).
///
/// The EXECUTING core is skipped: a self-destroying caller thread still
/// occupies its own core's `current_thread` slot through phase 2 (and is
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
/// commitments (the dequeue filter drops even-gen Threads) — but a
/// commitment made just BEFORE a flip may sit in a core's store
/// buffer, or the committing core may be host-descheduled mid-window
/// for milliseconds (KVM vCPU preemption breaks every "visible soon"
/// argument). Taking each lock once forces the sweep to serialize
/// after any in-progress locked commit, making `committed_thread` (and
/// everything the committer wrote before its unlock) visible to the
/// clause scan below.
pub fn awaitProcessQuiesced(root_addr: u64, process_ptr: *const anyopaque) void {
    const self_core: u8 = @truncate(arch.smp.coreID());
    for (&core_locks) |*lock| {
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        lock.unlockIrqRestore(irq);
    }
    for (&core_states, 0..) |*state, core_idx| {
        if (core_idx == self_core) continue;
        while (true) {
            // Ack-while-spinning (stygia-rs6 mechanism 9): this barrier
            // is reachable with IRQs masked from the process-destroy
            // path, and a core deaf to the shootdown IPI while another
            // core sits in `waitForShootdownAcks` wedges the machine.
            spin_diag.note(.await_quiesced, core_idx);
            arch.paging.serviceTlbMaintenanceWhileSpinning();
            // stygia-8xl: same class as `routeRetiredFinalize`'s wait —
            // an IRQ-masked barrier whose target core may itself be
            // blocked in `migrateFlush` waiting on this core's mailbox.
            stygia.sched.fpu.serviceLocalFlushWhileSpinning();
            if (state.active_root.load(.acquire) == root_addr) {
                std.atomic.spinLoopHint();
                continue;
            }
            if (state.current_thread) |cur| {
                // caller-pinned: identity-only compare of the raw
                // process pointer against the dying process's address — no
                // field of the process is read through it. Slab bytes of a
                // current thread persist past its gen flip (deferred
                // finalize), and a zeroed process field simply
                // mismatches and exits the clause.
                //
                // The deref below is UNCONDITIONAL, so "non-null implies
                // dereferenceable" has to hold for a lock-free
                // cross-core read. It does now, and did not before:
                // `current_thread` is a single pointer word (see its field
                // doc), where the old `?SlabRef` aggregate let this
                // exact load fault at 0x488 == @offsetOf(thread, "process")
                // on a torn `{ is_non_null = 1, ptr = 0 }`.
                if (@intFromPtr(cur.process.ptr) == @intFromPtr(process_ptr)) {
                    std.atomic.spinLoopHint();
                    continue;
                }
            }
            break;
        }
    }
}

pub inline fn clearCurrentThread(core: u8) void {
    if (comptime thread_log.enabled) {
        thread_log.mark(.clear_current_thread, (&core_states[core]).current_thread, null);
    }
    (&core_states[core]).current_thread = null;
}

/// Set this core's `current_thread` to `thread`, capturing the gen at write time.
/// Dispatch callers do this under `core_locks[core]`, making
/// `current_thread` the sole dispatch-commitment signal for teardown
/// quiescence.
pub inline fn setCurrentThread(core: u8, thread: *Thread) void {
    if (comptime thread_log.enabled) {
        thread_log.mark(.set_current_thread, (&core_states[core]).current_thread, thread);
    }
    // Gen BEFORE pointer. A cross-core observer keys entirely off the
    // pointer word, so publishing it last means anyone who sees the new
    // occupant also sees a gen that belongs to it (the only reader of
    // the gen runs on this core anyway). The reverse order would
    // additionally expose the previous occupant's pointer paired with
    // the new gen.
    (&core_states[core]).current_thread_gen = @intCast(thread._gen_lock.currentGen());
    (&core_states[core]).current_thread = thread;
    thread.owner_core = core;
}

// ── State transitions used by other subsystems ───────────────────────

/// Transition `thread` to ready and enqueue. Used by event delivery
/// resumes (reply, futex wake, timer fire, recv→ready, etc.).
///
/// Routed through `tryClaimWake` so a resume that races a second waker
/// for the same wait — classically a recv/futex timeout expiring on the
/// timer core while the event it was waiting for arrives on another —
/// enqueues the thread exactly once. The loser returns silently; the winner
/// owns the wake. See `thread_mod.tryClaimWake` for why a
/// per-core queue lock cannot serialize this.
pub fn markReady(thread: *Thread) void {
    switch (lifecycle.beginWaitingClaimPinned(thread)) {
        .claimed => {
            enqueue(thread);
            lifecycle.releasePin(thread);
        },
        .pended => {
            lifecycle.publishPendedPayload(thread);
            lifecycle.releasePin(thread);
        },
        .none => {},
    }
}

pub fn clearYieldHandoffGuard(core: u8) void {
    if (core >= MAX_CORES) return;
    yield_handoff_preempt_guard[core] = false;
}

pub fn yieldHandoffGuardPtr(core: u8) *bool {
    return &yield_handoff_preempt_guard[core];
}

pub fn consumeYieldHandoffGuard(core: u8) bool {
    if (core >= MAX_CORES) return false;
    if (!yield_handoff_preempt_guard[core]) return false;
    yield_handoff_preempt_guard[core] = false;
    return true;
}

/// Pick the right core for `thread` based on its affinity mask.
/// `affinity == 0` is the spec-defined "any core" sentinel; we fall
/// back to the calling core for cache locality.
fn pickCoreForAffinity(affinity: u64) u8 {
    if (affinity == 0) return @truncate(arch.smp.coreID());
    return @truncate(@as(u64, @ctz(affinity)));
}

// ── Lazy FPU coordination ────────────────────────────────────────────

/// Cross-core FPU flush — if `thread.last_fpu_core` points to a different
/// core than the calling core, IPI that core to FXSAVE its CPU regs
/// into `thread.fpu_state`, then clear `last_fpu_core`. Called before
/// the destination core arms its FPU trap so the trap handler can
/// safely FXRSTOR from a fresh buffer. Delegates to `sched.fpu` which
/// owns the per-arch mailbox protocol.
pub fn migrateFlush(thread: *Thread) void {
    stygia.sched.fpu.migrateFlush(thread);
}
