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
const build_options = @import("build_options");
const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const spin_diag = stygia.utils.spin_diag;
const ec_log = stygia.utils.ec_log;
const memory_init = stygia.memory.init;
const execution_context = stygia.sched.execution_context;
const lifecycle = stygia.sched.lifecycle;
const port_mod = stygia.sched.port;
const stack_mod = stygia.memory.stack;

const CapabilityDomain = stygia.caps.capability_domain.CapabilityDomain;
const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const NOT_IN_RUN_QUEUE = stygia.sched.execution_context.NOT_IN_RUN_QUEUE;
const Priority = stygia.sched.execution_context.Priority;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const SpinLock = stygia.utils.sync.SpinLock;
const Stack = stygia.memory.stack.Stack;
const VAddr = stygia.memory.address.VAddr;

const YIELD_SELECT_DIAG_BUDGET: u32 = 4096;
var yield_select_diag_prints: u32 = 0;

const YIELD_TARGET_PINNED_BIT: u64 = 1;
const YieldTarget = struct {
    ec: ?*ExecutionContext = null,
    pinned: bool = false,

    fn encodeForHop(self: YieldTarget) u64 {
        const target = self.ec orelse return 0;
        const raw = @intFromPtr(target);
        std.debug.assert(raw & YIELD_TARGET_PINNED_BIT == 0);
        return raw | if (self.pinned) YIELD_TARGET_PINNED_BIT else 0;
    }

    fn decodeFromHop(arg: u64) YieldTarget {
        if (arg == 0) return .{};
        const raw = arg & ~YIELD_TARGET_PINNED_BIT;
        return .{
            .ec = @as(*ExecutionContext, @ptrFromInt(raw)),
            .pinned = (arg & YIELD_TARGET_PINNED_BIT) != 0,
        };
    }

    fn release(self: *YieldTarget) void {
        if (self.pinned) {
            lifecycle.releasePin(self.ec.?);
            self.pinned = false;
        }
        self.ec = null;
    }
};

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

pub const TeardownKind = enum(u8) { self_delete, unhandled_fault };

pub const TeardownRequest = struct {
    kind: TeardownKind,
    cd: SlabRef(CapabilityDomain),
    caller_ec: ?SlabRef(ExecutionContext) = null,
};

/// Maximum cores the scheduler supports. Matches `affinity` mask width.
pub const MAX_CORES: u8 = 64;

var deferred_requeues: [MAX_CORES]EcQueue = [_]EcQueue{.{}} ** MAX_CORES;
var yield_handoff_targets: [MAX_CORES]?*ExecutionContext = [_]?*ExecutionContext{null} ** MAX_CORES;
var yield_handoff_preempt_guard: [MAX_CORES]bool = [_]bool{false} ** MAX_CORES;

const WORK_STEALING_ENABLED = switch (builtin.cpu.arch) {
    // aarch64 stays local-only until EC migration has FPU parity:
    // scheduler.migrateFlush, sched/fpu.migrateFlush via SGI, V0-V31 plus
    // FPCR/FPSR save/restore, and CPACR_EL1.FPEN trap-state handoff.
    .aarch64 => false,
    else => true,
};

/// Per-thief rotating victim cursor. Scheduler-local on purpose: `PerCore`
/// layout is referenced by x64 assembly and must not grow for policy state.
var steal_victim_cursors: [MAX_CORES]u8 = [_]u8{0} ** MAX_CORES;

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
/// compatible, so `PerCore` is a regular struct.
///
/// CAUTION — the x86-64 IPC fast path DOES reference field offsets in
/// here. `arch/x64/interrupts.zig` steps FP-S14 / R-14 open-code
/// `setCurrentEc` in asm using `@offsetOf(PerCore, "current_ec")` and
/// `@offsetOf(PerCore, "current_ec_gen")`. Any change to the shape of
/// those two fields must be mirrored there; the offsets are computed
/// with `@offsetOf` so a rename is a build error, but a change in
/// WIDTH or in the meaning of the bytes is not.
pub const PerCore = struct {
    /// Priority-ordered intrusive PQ over EC.next. Drained by
    /// `dequeue` on context switch / yield / preempt.
    run_queue: EcQueue = .{},

    /// EC currently dispatched on this core. `null` ⇒ core is idle.
    ///
    /// SINGLE-WORD BY CONSTRUCTION, and that is a correctness
    /// requirement, not a micro-optimisation. This slot is written
    /// without any lock by its owning core (`setCurrentEc` /
    /// `clearCurrentEc`) and read WITHOUT A LOCK by other cores —
    /// `awaitDomainQuiesced`'s teardown barrier, `markReady`'s
    /// wake/preempt decision, `currentEcPtrOn`, the hang detector and
    /// the fatal-fault reporter all do it.
    ///
    /// It used to be `?SlabRef(ExecutionContext)`, i.e. a 24-byte
    /// `{ ptr, gen, is_non_null }` aggregate. Measured on the Pi 5
    /// (stygia-eu4): that layout tears. `state.current_ec = null`
    /// compiles to `stp xzr, xzr, [x]` + `str xzr, [x, #0x10]` — it
    /// ZEROES THE POINTER WORD — and `= SlabRef.init(...)` compiles to
    /// `str ptr` / `strb tag` / `str gen` with no release barrier, in
    /// that order. A remote reader loading the three words with no
    /// acquire barrier can therefore observe `is_non_null = 1`
    /// alongside `ptr = 0`, which is not a state any writer ever
    /// intends. `awaitDomainQuiesced` then dereferenced it and took
    /// `KERNEL PAGE FAULT at 0x488` — exactly
    /// `@offsetOf(ExecutionContext, "domain")` — killing core 1 at
    /// pass 14 of a 100-pass bare-metal run.
    ///
    /// As a plain `?*ExecutionContext` the optional IS the pointer
    /// (Zig's null-pointer niche), so publication is one naturally
    /// aligned 8-byte store and observation is one 8-byte load. Neither
    /// can tear on either supported arch, and "non-null" now implies
    /// "dereferenceable" with no ordering argument required. The gen
    /// moved to `current_ec_gen`; it has exactly one consumer, and that
    /// consumer runs on the owning core.
    ///
    /// caller-pinned: bare `*T` is deliberate, matching `committed_ec`
    /// directly below. Cross-core readers perform identity-only
    /// compares (`== ec`, `.domain.ptr == cd_key`) and never lock
    /// through this pointer; a slab slot's bytes outlive its gen flip,
    /// so a stale-but-non-null value simply mismatches and the reader
    /// moves on.
    current_ec: ?*ExecutionContext = null,

    /// Slab generation of `current_ec`, captured at publication time.
    /// Split out of the old `SlabRef` so the pointer can stand alone as
    /// a tear-free word — see `current_ec`. Exactly one consumer, and
    /// it runs on this core (the x86 entry snapshot), so the pointer/gen pair
    /// never needs to be read atomically together.
    current_ec_gen: u32 = 0,

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

    /// Gen-dead EC whose final stack/slab cleanup must wait until this
    /// core is no longer executing on that EC's kernel stack. G16 records
    /// this as normative kernel behavior but keeps it out of the TLA model.
    teardown_pending: ?TeardownRequest = null,

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
        // stygia-8xl: a CANCELLED entry means another core retired this
        // vCPU while it was executing guest code, and the run loop left
        // guest mode to acknowledge that rather than exiting on a guest
        // event. There is no event to report and no live EC to suspend —
        // `fireVmExit` would publish a wait episode on a dead EC. Skip it
        // and fall straight through to `dischargeOwnedParking`, which is
        // the owner-side eviction the remote retire has been waiting for.
        if (!delivery.cancelled) {
            port_mod.fireVmExit(current, delivery.subcode, delivery.payload);
        }
        arch.cpu.restoreInterrupts(irq);

        // `fireVmExit` suspends the vCPU through the normal running
        // EC lifecycle. Keep `current_ec` naming the vCPU until that
        // call has published `.parking`, then complete the owner-side
        // handoff here on the scheduler's park stack before selecting
        // another EC. Clearing `current_ec` first makes
        // `suspendOnPort(.running)` reject the event as E_BUSY and
        // strands the VMM's follow-up recv.
        dischargeOwnedParking(core);

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
    const current: *ExecutionContext = @ptrFromInt(arg);
    dispatchTailBody(core, current);
}

/// The dispatch tail: everything between the dispatch decision and the
/// context-load trampoline. Runs on the park kstack (or the boot stack
/// before `perCoreInit`). noreturn via `loadEcContextAndReturn`.
fn dispatchTailBody(core: u8, current: *ExecutionContext) noreturn {
    drainTeardown(core, current);
    if ((&core_states[core]).current_ec != current) {
        @panic("scheduler.dispatchTailBody: current_ec changed during teardown drain");
    }
    if (lifecycle.load(current) != .running) {
        dischargeOwnedParking(core);
        run();
    }
    yield_handoff_preempt_guard[core] = yield_handoff_targets[core] == current;
    yield_handoff_targets[core] = null;
    // Give the committed EC a fresh quantum at the dispatch boundary.
    // The old deadline belongs to the outgoing EC; carrying it across a
    // voluntary targeted yield can let an already-due tick preempt the
    // target before it executes one user instruction, which violates the
    // observable-progress contract of yield(target).
    arch.time.getPreemptionTimer().armInterruptTimer(TIMESLICE_NS);
    execution_context.recordSpawnTrace(current, null, .dispatch_tail, core);
    arch.cpu.loadEcContextAndReturn(current);
}

fn dischargeOwnedParking(core: u8) void {
    const ec = (&core_states[core]).current_ec orelse return;
    switch (lifecycle.load(ec)) {
        .parking => switch (ec.wait.kind) {
            .requeue => {
                clearCurrentEc(core);
                enqueueOnCore(pickCoreForAffinity(ec.affinity), ec);
            },
            else => {
                if (lifecycle.commitParkingWaiting(ec, NOT_IN_RUN_QUEUE)) {
                    clearCurrentEc(core);
                }
            },
        },
        .pended => {
            lifecycle.waitForPendedPayload(ec);
            clearCurrentEc(core);
            enqueueOnCore(pickCoreForAffinity(ec.affinity), ec);
        },
        .retired => {
            clearCurrentEc(core);
            if (ec._gen_lock.currentGen() % 2 == 0 and !stackContains(ec, arch.cpu.currentSp())) {
                execution_context.finalizeDestroyMarkedDead(ec);
            }
        },
        else => {},
    }
}

fn drainDeferredRequeuesLocked(core: u8) void {
    const state = &core_states[core];
    while ((&deferred_requeues[core]).dequeue()) |ec| {
        if (lifecycle.load(ec) != .parking or ec.wait.kind != .requeue) continue;
        if (!canPublishReady(ec)) continue;
        if (!lifecycle.cas(ec, .parking, .ready)) continue;
        ec.owner_core = NOT_IN_RUN_QUEUE;
        ec.wait.clear();
        if (!canPublishReady(ec)) continue;
        state.run_queue.enqueue(ec);
        ec.current_queue_core.store(core, .release);
    }
}

pub fn deferLocalRunningRequeue(ec: *ExecutionContext) bool {
    const core: u8 = @truncate(arch.smp.coreID());
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);

    if (!lifecycle.prepareRunningPark(ec, core, .requeue)) return false;
    (&deferred_requeues[core]).enqueue(ec);
    return true;
}

fn stackContains(ec: *ExecutionContext, sp: u64) bool {
    return sp >= ec.kernel_stack.base.addr and sp < ec.kernel_stack.top.addr;
}

pub fn queueTeardown(core: u8, req: TeardownRequest) bool {
    if (core >= MAX_CORES) return false;
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    const slot = &(&core_states[core]).teardown_pending;
    if (slot.*) |existing| {
        if (existing.cd.eql(req.cd)) return true;
        return false;
    }
    slot.* = req;
    return true;
}

pub fn queueCurrentTeardown(req: TeardownRequest) void {
    const core: u8 = @truncate(arch.smp.coreID());
    while (!queueTeardown(core, req)) {
        spin_diag.note(.queue_teardown, @intFromPtr(req.cd.ptr));
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        stygia.sched.fpu.serviceLocalFlushWhileSpinning();
        std.atomic.spinLoopHint();
    }
}

pub fn claimOwnTeardownInline(ec: *ExecutionContext) bool {
    const core: u8 = @truncate(arch.smp.coreID());
    if (ec.owner_core != core) return false;
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    if ((&core_states[core]).current_ec == ec) return false;
    if (stackContains(ec, arch.cpu.currentSp())) return false;
    return true;
}

fn runDomainTeardown(req: TeardownRequest) void {
    const tree_irq = stygia.caps.derivation.tree_mutex.lockIrqSaveOrdered(
        @src(),
        stygia.caps.derivation.TREE_MUTEX_GROUP,
    );
    const cd_lr = req.cd.lockOrderedIrqSave(
        stygia.caps.derivation.TREE_DOMAIN_GROUP,
        @src(),
    ) catch {
        stygia.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);
        return;
    };
    const deferred = stygia.caps.capability_domain.destroyPhase1(
        cd_lr.ptr,
        req.caller_ec,
    );
    arch.cpu.restoreInterrupts(cd_lr.irq_state);
    stygia.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);

    switch (req.kind) {
        .self_delete, .unhandled_fault => stygia.caps.capability_domain.destroyPhase2(deferred),
    }
}

pub fn drainTeardown(core: u8, incoming: ?*ExecutionContext) void {
    while (true) {
        const req = blk: {
            const lock = &core_locks[core];
            const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
            defer lock.unlockIrqRestore(irq);
            const slot = &(&core_states[core]).teardown_pending;
            const req = slot.* orelse return;
            if (incoming) |ec| {
                const dref = ec.domain;
                // `dispatchTailBody` calls this after committing
                // `current_ec` but before entering userspace. Phase-2
                // domain teardown deliberately skips the executing
                // core in `awaitDomainQuiesced`; if this core drained
                // teardown for `incoming`'s own domain here, it could
                // retire the EC after scheduler selection and before
                // the first user instruction. Leave it pending until
                // the core reaches a null-incoming park/yield drain.
                if (req.cd.ptr == dref.ptr and req.cd.gen == dref.gen) {
                    return;
                }
            }
            slot.* = null;
            break :blk req;
        };
        runDomainTeardown(req);
    }
}

/// Voluntary yield — current EC drops back into ready, scheduler
/// picks the next. If `target` is non-null and runnable, it runs next.
pub fn yieldTo(target: ?*ExecutionContext) void {
    yieldToTarget(.{ .ec = target });
}

/// Voluntary yield to a target whose lifecycle pin is already held by
/// the caller. Scheduler owns and releases the pin, including paths that
/// abandon the caller's kernel stack through a park-stack hop.
pub fn yieldToPinned(target: *ExecutionContext) void {
    yieldToTarget(.{ .ec = target, .pinned = true });
}

fn yieldToTarget(initial_target: YieldTarget) void {
    var target = initial_target;
    const core: u8 = @truncate(arch.smp.coreID());
    const state = &core_states[core];
    const lock = &core_locks[core];

    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    // TEMP DIAGNOSTIC (stygia-afo, REMOVE). A null `current_ec` here means
    // this frame has no EC to be re-enqueued under, so if we go on to
    // `switchTo` some other EC the C stack we are standing on is
    // ABANDONED — nothing will ever resume it. That is the exact
    // mechanism blamed for the leaked domain teardowns; count the events
    // instead of inferring them from a counter gap.
    const disowned_at_entry = state.current_ec == null;
    if (state.current_ec) |cur| {
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
        // subsequent `dequeueOrIdle` runs dry. `current_ec` is null in
        // that case and the caller's iretq path handles it (the
        // affinity-migration arm above never reaches here — it escapes
        // via the hop before selecting `next`).
        if (disowned_at_entry) {
            // TEMP DIAGNOSTIC (stygia-afo, REMOVE).
            stygia.caps.capability_domain.noteFrameAbandoned();
        }
        switchTo(n);
        return;
    }

    if ((&core_states[core]).current_ec != null) {
        escapeToRun();
    }

    const park_top = (&core_states[core]).park_stack.top.addr;
    if (park_top != 0) arch.cpu.parkPerCoreCaches(core, park_top);
    drainTeardown(core, null);
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

fn hopParkYield(target: YieldTarget) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    const park_top = (&core_states[core]).park_stack.top.addr;
    arch.irq.schedulerEscapeEoi();
    if (park_top == 0) {
        dischargeOwnedParking(core);
        var local_target = target;
        const incoming = local_target.ec;
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
    drainTeardown(core, target.ec);
    if (dequeueYieldTarget(core, &target)) |next| switchTo(next);
    run();
}

/// Abandon the current kernel stack for this core's park kstack and
/// enter `run()` there. The landing pad completes any owned
/// `parking`/`pended` episode after the hop, when the EC's stack is no
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

    drainTeardown(core, null);

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

/// Asm landing pad after `parkAndAwaitIRQ`'s wake: rsp is on the park
/// kstack, IRQs are masked. Re-enter `run()` to re-check the queue.
/// `run()` is noreturn so the call never returns; the pushed return
/// address sits unused on the park stack.
export fn scheduler_run_after_park() callconv(.c) noreturn {
    const core: u8 = @truncate(arch.smp.coreID());
    drainTeardown(core, null);
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

inline fn canPublishReady(ec: *ExecutionContext) bool {
    return ec._gen_lock.currentGen() % 2 == 1 and !lifecycle.isDestroyMarked(ec) and domainRefAlive(ec);
}

fn diagTag(ec: *ExecutionContext) u64 {
    if (ec.diag_test_tag != 0) return ec.diag_test_tag;
    return ec.domain.ptr.diag_test_tag;
}

fn logYieldSelectDiag(core: u8, target: *ExecutionContext, reason: []const u8, publishable: bool) void {
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
    drainDeferredRequeuesLocked(core);
    if (dequeueLocalReadyLocked(core)) |ec| return ec;
    if (tryStealReadyLocked(core)) |ec| return ec;
    // Nothing to run: the caller parks this core. Publish that decision
    // under `core_locks[core]` so a concurrent `enqueueOnCore` knows to
    // send the wake IPI even though `current_ec` has not been cleared
    // yet. See `PerCore.idle_parked`.
    state.idle_parked = true;
    return null;
}

fn dequeueLocalReadyLocked(core: u8) ?*ExecutionContext {
    const state = &core_states[core];
    yield_handoff_targets[core] = null;
    while (state.run_queue.dequeue()) |ec| {
        // Clear queue residency on every popped EC, regardless of
        // whether we end up dispatching it or skipping it as stale —
        // either way it is no longer linked into any run queue.
        // Performed under `core_locks[core]` so a concurrent
        // `removeFromQueue` reader that observed a stale `core`
        // residency hint and is now waiting on this lock will see the
        // cleared sentinel after acquiring.
        ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        if (!canPublishReady(ec)) {
            execution_context.recordSpawnTrace(ec, null, .dequeue_skip_not_publishable, core);
            continue;
        }
        if (!lifecycle.prepareDispatchLocked(ec, core, NOT_IN_RUN_QUEUE)) continue;
        setCurrentEc(core, ec);
        state.idle_parked = false;
        execution_context.recordSpawnTrace(ec, null, .dequeue_select, core);
        return ec;
    }
    return null;
}

fn stealCandidateFromVictimLocked(thief: u8, victim: u8) ?*ExecutionContext {
    const state = &core_states[victim];
    var idx: usize = state.run_queue.levels.len;
    while (idx > 0) {
        idx -= 1;
        var cur = state.run_queue.levels[idx].head;
        while (cur) |ec| {
            cur = ec.next;
            if (!affinityAdmitsCore(ec.affinity, thief)) continue;
            if (!canPublishReady(ec)) continue;
            if (ec.owner_core != NOT_IN_RUN_QUEUE) continue;
            if (lifecycle.load(ec) != .ready) continue;

            const queue_core = ec.current_queue_core.load(.acquire);
            if (queue_core != victim and queue_core != NOT_IN_RUN_QUEUE) continue;
            if (!runQueueContains(&state.run_queue, ec)) continue;
            if (!lifecycle.beginReadyClaimPinned(ec)) continue;

            const removed = state.run_queue.remove(ec);
            std.debug.assert(removed);
            ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
            return ec;
        }
    }
    return null;
}

fn stealFromVictimsUnlocked(thief: u8) ?*ExecutionContext {
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
        if (stolen) |ec| {
            steal_victim_cursors[thief] = @intCast(next_victim);
            return ec;
        }
        victim = next_victim;
    }

    steal_victim_cursors[thief] = @intCast(victim);
    return null;
}

fn abandonStolenReadyUnlocked(ec: *ExecutionContext) void {
    if (!canPublishReady(ec)) {
        execution_context.dischargeClaimedHolderDead(ec);
        return;
    }
    switch (enqueuePinnedClaimed(ec)) {
        .published, .not_claimed => {},
        .not_publishable, .claimed_unpublishable => {
            execution_context.dischargeClaimedHolderDead(ec);
            return;
        },
    }
    lifecycle.releasePin(ec);
}

fn commitStolenDispatchLocked(core: u8, ec: *ExecutionContext) bool {
    if (!canPublishReady(ec)) return false;
    if (!lifecycle.finishClaimedDispatch(ec, core, NOT_IN_RUN_QUEUE)) return false;
    setCurrentEc(core, ec);
    yield_handoff_targets[core] = null;
    (&core_states[core]).idle_parked = false;
    lifecycle.releasePin(ec);
    execution_context.recordSpawnTrace(ec, null, .dequeue_select, core);
    return true;
}

fn tryStealReadyLocked(core: u8) ?*ExecutionContext {
    if (!WORK_STEALING_ENABLED) return null;

    const thief_lock = &core_locks[core];
    thief_lock.unlock();
    const stolen = stealFromVictimsUnlocked(core);
    const thief_irq = thief_lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    const ec = stolen orelse return null;
    if (dequeueLocalReadyLocked(core)) |local| {
        thief_lock.unlockIrqRestore(thief_irq);
        abandonStolenReadyUnlocked(ec);
        _ = thief_lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        return local;
    }
    if (commitStolenDispatchLocked(core, ec)) return ec;

    thief_lock.unlockIrqRestore(thief_irq);
    abandonStolenReadyUnlocked(ec);
    _ = thief_lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    return null;
}

fn affinityAdmitsCore(affinity: u64, core: u8) bool {
    return affinity == 0 or (core < 64 and (affinity & (@as(u64, 1) << @truncate(core))) != 0);
}

fn dequeueYieldTarget(core: u8, target: *YieldTarget) ?*ExecutionContext {
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
    defer lock.unlockIrqRestore(irq);
    return dequeueYieldTargetLocked(core, target);
}

fn dequeueYieldTargetLocked(core: u8, target: *YieldTarget) ?*ExecutionContext {
    const state = &core_states[core];
    if (target.ec) |t| {
        defer target.release();

        // `domainRefAlive`: same dying-domain dispatch gate as the
        // dequeue filter — a yieldTo target whose CD was dead-marked
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
                setCurrentEc(core, t);
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

fn finishEnqueuePublish(core: u8, ec: *ExecutionContext, irq: u64) void {
    const lock = &core_locks[core];
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
    // caller-pinned: read-only snapshot of the target core's
    // `current_ec` for the wake/preempt decision. Worst-case stale ptr
    // just costs a spurious IPI; any real deref is gated below. Now a
    // single tear-free word — under the old `?SlabRef` layout a torn
    // read could yield a NON-NULL optional wrapping a ZERO pointer,
    // which reads as "target is busy" and silently suppresses the wake
    // IPI (see `PerCore.current_ec`).
    const target_current_ptr: ?*ExecutionContext = (&core_states[core]).current_ec;
    // Read the target's parking decision under the SAME lock that just
    // published `ec` into its queue. `current_ec` alone is not enough:
    // a core that has already committed to parking still names its last
    // EC there until after it drops this lock, and treating that as
    // "busy, it will pick `ec` up later" strands `ec` on a core that
    // never wakes. See `PerCore.idle_parked`.
    const target_parked = (&core_states[core]).idle_parked;
    const publish_aux: u64 =
        @as(u64, core) |
        (if (target_current_ptr != null) @as(u64, 1) << 8 else 0) |
        (if (target_parked) @as(u64, 1) << 9 else 0);
    execution_context.recordSpawnTrace(ec, null, .enqueue_publish, publish_aux);
    lock.unlockIrqRestore(irq);

    const self_core: u8 = @truncate(arch.smp.coreID());

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

fn enqueueClaimedOnCorePinned(core: u8, ec: *ExecutionContext) EnqueuePinnedResult {
    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    if (!canPublishReady(ec)) {
        execution_context.recordSpawnTrace(ec, null, .enqueue_skip_not_publishable, core);
        lock.unlockIrqRestore(irq);
        return .not_publishable;
    }
    if (lifecycle.load(ec) != .claimed) {
        execution_context.recordSpawnTrace(ec, null, .enqueue_skip_state, @intFromEnum(lifecycle.load(ec)));
        lock.unlockIrqRestore(irq);
        return .not_claimed;
    }
    if (!lifecycle.finishClaimedReady(ec, NOT_IN_RUN_QUEUE)) {
        lock.unlockIrqRestore(irq);
        return .not_claimed;
    }

    if (!canPublishReady(ec)) {
        execution_context.recordSpawnTrace(ec, null, .enqueue_skip_not_publishable, core);
        std.debug.assert(ec.current_queue_core.load(.acquire) == NOT_IN_RUN_QUEUE);
        std.debug.assert(lifecycle.cas(ec, .ready, .claimed));
        lock.unlockIrqRestore(irq);
        return .claimed_unpublishable;
    }

    finishEnqueuePublish(core, ec, irq);
    return .published;
}

fn enqueuePinnedClaimed(ec: *ExecutionContext) EnqueuePinnedResult {
    return enqueueClaimedOnCorePinned(pickCoreForAffinity(ec.affinity), ec);
}

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
    execution_context.recordSpawnTrace(ec, null, .enqueue_attempt, core);
    if (!lifecycle.tryPinLive(ec)) {
        execution_context.recordSpawnTrace(ec, null, .enqueue_skip_not_live, core);
        return;
    }
    defer lifecycle.releasePin(ec);

    const lock = &core_locks[core];
    const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);

    if (!canPublishReady(ec)) {
        execution_context.recordSpawnTrace(ec, null, .enqueue_skip_not_publishable, core);
        lock.unlockIrqRestore(irq);
        return;
    }
    switch (lifecycle.load(ec)) {
        .ready => {},
        .claimed => {
            if (!lifecycle.finishClaimedReady(ec, NOT_IN_RUN_QUEUE)) {
                lock.unlockIrqRestore(irq);
                return;
            }
        },
        .pended => {
            if (!lifecycle.finishPendedReady(ec, NOT_IN_RUN_QUEUE)) {
                lock.unlockIrqRestore(irq);
                return;
            }
        },
        .parking => {
            if (ec.wait.kind != .requeue or !lifecycle.cas(ec, .parking, .ready)) {
                lock.unlockIrqRestore(irq);
                return;
            }
            ec.owner_core = NOT_IN_RUN_QUEUE;
            ec.wait.clear();
        },
        else => {
            execution_context.recordSpawnTrace(ec, null, .enqueue_skip_state, @intFromEnum(lifecycle.load(ec)));
            lock.unlockIrqRestore(irq);
            return;
        },
    }

    if (!canPublishReady(ec)) {
        execution_context.recordSpawnTrace(ec, null, .enqueue_skip_not_publishable, core);
        lock.unlockIrqRestore(irq);
        return;
    }

    finishEnqueuePublish(core, ec, irq);
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
/// per-core locks. Required for stale-hint races and for any EC that
/// was removed from one queue while the caller's hint snapshot was old;
/// the x64 IPC fast path now publishes this field in its ready-enqueue
/// branches, matching the Zig enqueue discipline.
pub fn removeFromQueue(ec: *ExecutionContext) void {
    const hint = ec.current_queue_core.load(.acquire);
    if (hint < MAX_CORES) {
        const lock = &core_locks[hint];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const removed = (&core_states[hint]).run_queue.remove(ec) or
            (&deferred_requeues[hint]).remove(ec);
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
        const removed = (&core_states[i]).run_queue.remove(ec) or
            (&deferred_requeues[i]).remove(ec);
        if (removed) {
            ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
        }
        lock.unlockIrqRestore(irq);
        if (removed) return;
        i += 1;
    }
}

fn runQueueContains(queue: *EcQueue, target: *ExecutionContext) bool {
    for (&queue.levels) |*level| {
        var cur = level.head;
        while (cur) |ec| {
            if (ec == target) return true;
            cur = ec.next;
        }
    }
    return false;
}

fn claimReadyFromLockedQueue(core: u8, ec: *ExecutionContext, expected_gen: ?u32) bool {
    const state = &core_states[core];
    const queue_core = ec.current_queue_core.load(.acquire);
    if (queue_core != core and queue_core != NOT_IN_RUN_QUEUE) return false;

    const ec_gen = ec._gen_lock.currentGen();
    if (expected_gen) |gen| {
        if (ec_gen != @as(u63, gen)) return false;
    }
    if (ec_gen % 2 == 0 or !domainRefAlive(ec)) return false;
    if (ec.owner_core != NOT_IN_RUN_QUEUE) return false;
    if (lifecycle.load(ec) != .ready) return false;
    if (!runQueueContains(&state.run_queue, ec)) return false;
    if (!lifecycle.beginReadyClaimPinned(ec)) return false;

    const removed = state.run_queue.remove(ec);
    std.debug.assert(removed);
    ec.current_queue_core.store(NOT_IN_RUN_QUEUE, .release);
    return true;
}

/// Claim a ready EC under the run-queue lock that proves its membership,
/// then unlink it from that queue. On success, the returned EC is in
/// `.claimed`, no longer belongs to any run queue, and the caller owns a
/// lifecycle pin until it re-publishes or drops the claim.
pub fn claimReadyFromQueue(ec: *ExecutionContext, expected_gen: ?u32) bool {
    const hint = ec.current_queue_core.load(.acquire);
    if (hint < MAX_CORES) {
        const lock = &core_locks[hint];
        const irq = lock.lockIrqSaveOrdered(@src(), SCHED_CORE_GROUP);
        const claimed = claimReadyFromLockedQueue(hint, ec, expected_gen);
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
        const claimed = claimReadyFromLockedQueue(i, ec, expected_gen);
        lock.unlockIrqRestore(irq);
        if (claimed) return true;
        i += 1;
    }
    return false;
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
    // caller-pinned: `current_ec` names the EC actually executing on this
    // very core; the slot can't be freed under us while this code runs.
    return (&core_states[core]).current_ec;
}

/// True if this core's `current_ec` slot names `ec`. Identity-compare
/// helper used by suspend / terminate / fault paths to clear the
/// dispatch slot when the running EC parks itself.
pub inline fn coreCurrentIs(core: u8, ec: *ExecutionContext) bool {
    // caller-pinned: identity compare on `current_ec` slot.
    return (&core_states[core]).current_ec == ec;
}

pub inline fn coreCurrentIsRunning(core: u8, ec: *ExecutionContext) bool {
    return coreCurrentIs(core, ec) and lifecycle.load(ec) == .running;
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
            // Ack-while-spinning (stygia-rs6 mechanism 9): this barrier
            // is reachable with IRQs masked from the domain-destroy
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
            if (state.current_ec) |cur| {
                // caller-pinned: identity-only compare of the raw
                // domain pointer against the dying CD's address — no
                // field of the CD is read through it. Slab bytes of a
                // current EC persist past its gen flip (deferred
                // finalize), and a zeroed domain field simply
                // mismatches and exits the clause.
                //
                // The deref below is UNCONDITIONAL, so "non-null implies
                // dereferenceable" has to hold for a lock-free
                // cross-core read. It does now, and did not before:
                // `current_ec` is a single pointer word (see its field
                // doc), where the old `?SlabRef` aggregate let this
                // exact load fault at 0x488 == @offsetOf(EC, "domain")
                // on a torn `{ is_non_null = 1, ptr = 0 }`.
                if (@intFromPtr(cur.domain.ptr) == @intFromPtr(cd_ptr)) {
                    std.atomic.spinLoopHint();
                    continue;
                }
            }
            break;
        }
    }
}

pub inline fn clearCurrentEc(core: u8) void {
    if (comptime ec_log.enabled) {
        ec_log.mark(.clear_current_ec, (&core_states[core]).current_ec, null);
    }
    (&core_states[core]).current_ec = null;
}

/// Set this core's `current_ec` to `ec`, capturing the gen at write time.
/// Dispatch callers do this under `core_locks[core]`, making
/// `current_ec` the sole dispatch-commitment signal for teardown
/// quiescence.
pub inline fn setCurrentEc(core: u8, ec: *ExecutionContext) void {
    if (comptime ec_log.enabled) {
        ec_log.mark(.set_current_ec, (&core_states[core]).current_ec, ec);
    }
    // Gen BEFORE pointer. A cross-core observer keys entirely off the
    // pointer word, so publishing it last means anyone who sees the new
    // occupant also sees a gen that belongs to it (the only reader of
    // the gen runs on this core anyway). The reverse order would
    // additionally expose the previous occupant's pointer paired with
    // the new gen.
    (&core_states[core]).current_ec_gen = @intCast(ec._gen_lock.currentGen());
    (&core_states[core]).current_ec = ec;
    ec.owner_core = core;
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
    switch (lifecycle.beginWaitingClaimPinned(ec)) {
        .claimed => {
            enqueue(ec);
            lifecycle.releasePin(ec);
        },
        .pended => {
            lifecycle.publishPendedPayload(ec);
            lifecycle.releasePin(ec);
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
