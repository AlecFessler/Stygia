//! Execution context — schedulable unit of executable state bound to a
//! capability domain. See docs/kernel/specv3.md §[execution_context].

const std = @import("std");
const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;
const spin_diag = stygia.utils.spin_diag;
const capability = stygia.caps.capability;
const errors = stygia.syscall.errors;
const memory_init = stygia.memory.init;
const paging_consts = stygia.memory.paging;
const pmm = stygia.memory.pmm;
const scheduler = stygia.sched.scheduler;
const lifecycle = stygia.sched.lifecycle;
const stack = stygia.memory.stack;

const ArchCpuContext = arch.cpu.ArchCpuContext;
const CapabilityDomain = stygia.caps.capability_domain.CapabilityDomain;
const CapabilityType = stygia.caps.capability.CapabilityType;
const ErasedSlabRef = stygia.caps.capability.ErasedSlabRef;
const GenLock = stygia.memory.allocators.secure_slab.GenLock;
const KernelHandle = stygia.caps.capability.KernelHandle;
const PAddr = stygia.memory.address.PAddr;
const Port = stygia.sched.port.Port;
const SecureSlab = stygia.memory.allocators.secure_slab.SecureSlab;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const Stack = stygia.memory.stack.Stack;
const VAddr = stygia.memory.address.VAddr;
const VirtualMachine = stygia.hv.virtual_machine.VirtualMachine;
const WaitNode = stygia.sched.futex.WaitNode;

/// Upper bound on simultaneous futex wait addresses for a single EC.
/// Mirrors `futex.MAX_FUTEX_ADDRS` (the public spec ceiling) so each
/// EC's in-place wait-node / vaddr storage matches the kernel's
/// per-call cap.
pub const MAX_FUTEX_ADDRS_PER_EC: usize = 63;

/// Maximum handle attachments (pair entries) carried on a suspend.
/// Mirrors `syscall/port.zig::MAX_PAIR_COUNT`. Spec §[handle_attachments].
pub const MAX_PAIR_ENTRIES_PER_EC: usize = 63;

/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). How many `destroyExecutionContextLocked`
/// reaps had to fall back to the IRQ-enabling `postZombie` spin. The fix
/// for the abandoned-phase-2 frame rests on the claim that this is rare
/// and never happens for a same-core reap; if it climbs with the leak,
/// the claim is wrong and the window is still open.
///
/// ATOMIC, like the p2_* counters: a plain `+=` raced by four cores loses
/// increments, and cycle 1's residual claim ("every remaining abandoned
/// phase-2 frame is a contended post") rested on comparing this lossy
/// number against atomic ones. RMW so the comparison means something.
pub var slow_post_spins: u64 = 0;
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Incremented AFTER the contended
/// spin block returns. `slow_post_spins - slow_post_done` is the number of
/// frames that entered the IRQ-enabling window and never came out — i.e.
/// abandonments attributable to THIS site, measured rather than asserted.
pub var slow_post_done: u64 = 0;
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Contended posts whose target is
/// the posting core itself. The fast-path comment claims this is
/// impossible (the self-drain immediately above empties that very slot).
pub var slow_post_self: u64 = 0;
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Bracket around the per-victim
/// `destroyExecutionContextLocked` inside `destroyEcsInDomain`'s visitor.
/// `walk_visit_enter - walk_visit_done` is the number of abandonments that
/// happened anywhere inside the walk's per-victim destroy. If that equals
/// `p2_after_reap - p2_walk_done` the abandonment is in the victim destroy;
/// if it also equals `slow_post_spins - slow_post_done` it is specifically
/// the IRQ-enabling spin, which is the only `enableInterrupts()` call site
/// outside `kernel/arch/`.
pub var walk_visit_enter: u64 = 0;
pub var walk_visit_done: u64 = 0;
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Same-core posts that failed and
/// were resolved by finalizing inline instead, vs. the ones that still had
/// to take the IRQ-enabling spin. The fix's claim is that the second is
/// zero — the residual abandonments are ALL same-core and all inline-
/// finalizable — so a non-zero `inline_finalize_no` is the falsifier.
pub var inline_finalize_ok: u64 = 0;
pub var inline_finalize_no: u64 = 0;

/// TEMP DIAGNOSTIC (Rawls x86 MISS attribution, REMOVE). Bounded raw
/// serial budget for report-suspend entry markers. Focused x86 repros
/// stay below this; full-suite stress runs cannot flood the log forever.
var report_enter_prints: u32 = 0;
const REPORT_TAG_MAGIC: u64 = 0x8000;
const REPORT_PRINT_BUDGET: u32 = 4096;
const PRE_REPORT_TERMINAL_PRINT_BUDGET: u32 = 64;
var pre_report_terminal_prints: u32 = 0;
pub const PRE_REPORT_TERMINAL_RING_LEN: usize = if (build_options.kernel_spawn_diag) 32 else 0;
pub const SPAWN_TRACE_RING_LEN: usize = if (build_options.kernel_spawn_diag) 128 else 0;

pub const SpawnTraceEvent = enum(u8) {
    spawn_child,
    enqueue_attempt,
    enqueue_publish,
    enqueue_skip_not_live,
    enqueue_skip_not_publishable,
    enqueue_skip_state,
    dequeue_select,
    dequeue_skip_not_publishable,
    dispatch_tail,
    report_enter,
    terminal,
    retire,
    finalize,
};

pub const PreReportTerminalSample = struct {
    publish_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    seq: u64 = 0,
    tag: u64 = 0,
    cd: usize = 0,
    ec: usize = 0,
    reason: []const u8 = "",
};

pub const SpawnTraceSample = struct {
    publish_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    seq: u64 = 0,
    event: SpawnTraceEvent = .spawn_child,
    tag: u64 = 0,
    ec: usize = 0,
    cd: usize = 0,
    core: u8 = 0,
    state: u8 = 0,
    owner: u8 = NOT_IN_RUN_QUEUE,
    queue_core: u8 = NOT_IN_RUN_QUEUE,
    gen: u64 = 0,
    aux: u64 = 0,
};

pub var pre_report_terminal_seq: u64 = 0;
pub var pre_report_terminal_ring: [PRE_REPORT_TERMINAL_RING_LEN]PreReportTerminalSample =
    [_]PreReportTerminalSample{.{}} ** PRE_REPORT_TERMINAL_RING_LEN;
pub var spawn_trace_seq: u64 = 0;
pub var spawn_trace_ring: [SPAWN_TRACE_RING_LEN]SpawnTraceSample =
    [_]SpawnTraceSample{.{}} ** SPAWN_TRACE_RING_LEN;

/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Monotonic RMW bump helper.
pub fn dbump(counter: *u64) void {
    _ = @atomicRmw(u64, counter, .Add, 1, .monotonic);
}

fn maybePrintReportEntered(ec: *ExecutionContext) void {
    if (!build_options.kernel_spawn_diag) return;
    const tag = ec.event_state_gprs[4];
    if ((tag & REPORT_TAG_MAGIC) == 0) return;
    ec.diag_report_entered = true;
    if (ec.diag_test_tag == 0) ec.diag_test_tag = tag;
    recordSpawnTrace(ec, null, .report_enter, 0);
    const n = @atomicRmw(u32, &report_enter_prints, .Add, 1, .monotonic);
    if (n >= REPORT_PRINT_BUDGET) return;
    arch.boot.print(
        "[rpt-enter] ec=0x{x} cd=0x{x} tag=0x{x} code={x} aid={x}\n",
        .{
            @intFromPtr(ec),
            @intFromPtr(ec.domain.ptr),
            tag,
            ec.event_state_gprs[2],
            ec.event_state_gprs[3],
        },
    );
}

pub fn printPreReportTerminal(
    ec: ?*ExecutionContext,
    cd: ?*CapabilityDomain,
    reason: []const u8,
) void {
    if (!build_options.kernel_spawn_diag) return;
    if (ec) |e| {
        if (e.diag_report_entered) return;
    }
    const tag: u64 = blk: {
        if (ec) |e| if (e.diag_test_tag != 0) break :blk e.diag_test_tag;
        if (cd) |d| if (d.diag_test_tag != 0) break :blk d.diag_test_tag;
        break :blk 0;
    };
    if ((tag & REPORT_TAG_MAGIC) == 0) return;

    recordSpawnTrace(ec, cd, .terminal, 0);

    const n = @atomicRmw(u32, &pre_report_terminal_prints, .Add, 1, .monotonic);
    const seq = @atomicRmw(u64, &pre_report_terminal_seq, .Add, 1, .monotonic) + 1;
    const slot = &pre_report_terminal_ring[seq % PRE_REPORT_TERMINAL_RING_LEN];
    slot.publish_seq.store(0, .release);
    slot.seq = seq;
    slot.tag = tag;
    slot.cd = if (cd) |d| @intFromPtr(d) else @as(usize, 0);
    slot.ec = if (ec) |e| @intFromPtr(e) else @as(usize, 0);
    slot.reason = reason;
    slot.publish_seq.store(seq, .release);
    if (n >= PRE_REPORT_TERMINAL_PRINT_BUDGET) return;

    arch.boot.print(
        "[pre-report-terminal] tag=0x{x} index={x} cd=0x{x} ec=0x{x} reason={s}\n",
        .{
            tag,
            tag - REPORT_TAG_MAGIC,
            if (cd) |d| @intFromPtr(d) else @as(usize, 0),
            if (ec) |e| @intFromPtr(e) else @as(usize, 0),
            reason,
        },
    );
}

pub fn recordSpawnTrace(
    ec: ?*ExecutionContext,
    cd: ?*CapabilityDomain,
    event: SpawnTraceEvent,
    aux: u64,
) void {
    if (!build_options.kernel_spawn_diag) return;
    const tag: u64 = blk: {
        if (ec) |e| if (e.diag_test_tag != 0) break :blk e.diag_test_tag;
        if (cd) |d| if (d.diag_test_tag != 0) break :blk d.diag_test_tag;
        break :blk 0;
    };
    if ((tag & REPORT_TAG_MAGIC) == 0) return;

    const seq = @atomicRmw(u64, &spawn_trace_seq, .Add, 1, .monotonic) + 1;
    const state = if (ec) |e| @intFromEnum(lifecycle.load(e)) else @as(u8, 0xff);
    const owner = if (ec) |e| e.owner_core else NOT_IN_RUN_QUEUE;
    const queue_core = if (ec) |e| e.current_queue_core.load(.acquire) else NOT_IN_RUN_QUEUE;
    const gen = if (ec) |e| e._gen_lock.currentGen() else @as(u64, 0);

    const slot = &spawn_trace_ring[seq % SPAWN_TRACE_RING_LEN];
    slot.publish_seq.store(0, .release);
    slot.seq = seq;
    slot.event = event;
    slot.tag = tag;
    slot.ec = if (ec) |e| @intFromPtr(e) else @as(usize, 0);
    slot.cd = if (cd) |d| @intFromPtr(d) else if (ec) |e| @intFromPtr(e.domain.ptr) else @as(usize, 0);
    slot.core = @truncate(arch.smp.coreID());
    slot.state = state;
    slot.owner = owner;
    slot.queue_core = queue_core;
    slot.gen = gen;
    slot.aux = aux;
    slot.publish_seq.store(seq, .release);
}

/// Decoded pair entry stashed on the suspending EC at `validatePairEntries`
/// time and consumed at recv time in `port.deliverEvent`. Captures the
/// kernel-side `ErasedSlabRef` to the source object (lock-validated at
/// stash time so the gen baked here matches the live object), the
/// original holder domain and slot, the source caps captured for
/// expected-source revalidation, the internal caps used for the
/// pending lifetime ref, the type tag to install on the receiver, the
/// caps to install verbatim, and the move flag (drives the sender-side
/// slot clear at recv).
pub const PairEntryStashed = struct {
    obj_ref: ErasedSlabRef,
    source_domain: ErasedSlabRef,
    source_instance: u64,
    obj_type: CapabilityType,
    source_caps: u16,
    pending_ref_caps: u16,
    caps: u16,
    move: bool,
    src_slot: u12,
};

/// Cap bits in `Capability.word0[48..63]` for execution_context handles.
/// Spec §[execution_context] cap layout.
pub const EcCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    saff: bool = false,
    spri: bool = false,
    term: bool = false,
    susp: bool = false,
    read: bool = false,
    write: bool = false,
    restart_policy: u2 = 0,
    _reserved: u6 = 0,
};

/// Scheduling priority. Mirrors handle field0.pri (2 bits, 0..3).
pub const Priority = enum(u2) {
    idle = 0,
    normal = 1,
    high = 2,
    realtime = 3,
};

/// Sentinel for run-queue and owner-core caches. `0xFF` is outside the
/// scheduler's 0..63 core range.
pub const NOT_IN_RUN_QUEUE: u8 = 0xFF;

pub const State = lifecycle.State;
pub const WaitKind = lifecycle.WaitKind;

pub const Wait = struct {
    kind: WaitKind = .none,
    port: ?SlabRef(Port) = null,
    deadline_ns: u64 = 0,
    payload_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn begin(wait: *Wait, kind: WaitKind) void {
        wait.kind = kind;
        wait.port = null;
        wait.deadline_ns = 0;
        wait.payload_done.store(false, .release);
    }

    pub fn clear(wait: *Wait) void {
        wait.kind = .none;
        wait.port = null;
        wait.deadline_ns = 0;
        wait.payload_done.store(false, .release);
    }
};

/// Event type carried by a suspension. Matches spec §[event_type] values.
pub const EventType = enum(u5) {
    none = 0,
    suspension = 4,
    vm_exit = 5,
    _,
};

pub const ExecutionContext = struct {
    /// Slab generation lock. Protects every handle holding a
    /// `SlabRef(ExecutionContext)` to this EC against use after the slot
    /// is freed and reallocated.
    _gen_lock: GenLock = .{},

    /// Pointer to the topmost saved register frame. After exception or
    /// syscall entry this points at the user iret frame; after a
    /// scheduler yield it may be repointed at a kernel-mode frame
    /// produced by the IPI handler. Always safe to consume for the next
    /// dispatch — not safe for state writes that must reach userspace
    /// (use `iret_frame` for those).
    ctx: *ArchCpuContext,

    /// Snapshot of the user iret frame captured at exception entry, kept
    /// distinct from `ctx` so event reply paths can apply state writes
    /// back to userspace regardless of whether `ctx` has been retargeted
    /// by the scheduler. `null` outside an in-flight event.
    iret_frame: ?*ArchCpuContext = null,

    /// Kernel stack used by syscall and exception entry. Mapped in the
    /// kernel address space.
    kernel_stack: Stack,

    /// User stack reserved by `create_execution_context` in the bound
    /// domain's address space, with unmapped guard pages above and below.
    /// Optional to allow ECs without a user stack (e.g. per-core idle).
    user_stack: ?Stack,

    /// Bound capability domain. Set at create time; immutable.
    domain: SlabRef(CapabilityDomain),

    /// TEMP DIAGNOSTIC (Rawls x86 MISS attribution, REMOVE). Test-child
    /// identity copied from the owning CD at spawn time. Kernel-private:
    /// this does not affect any capability word or public ABI field.
    diag_test_tag: u64 = 0,
    diag_report_entered: bool = false,

    /// Forward link in whatever queue this EC currently inhabits.
    /// Mutually exclusive across {run queue, port wait queue, exited
    /// list}. Futex waits do NOT use this link — they use per-bucket
    /// WaitNodes (see `futex_wait_nodes`).
    ///
    /// caller-pinned: raw `?*EC`, not `?SlabRef`. Queue links are pinned
    /// by the enclosing structure's lock (port._gen_lock for port
    /// waiters; scheduler core_lock for run queues). Destroy paths
    /// must dequeue before freeing, and dequeue requires that same
    /// lock — so any pointer reachable from a held queue cannot be
    /// torn down. Slab type stability backs this up: the slot can
    /// only ever hold an EC. Mirror of futex's `WaitNode.next: ?*WaitNode`.
    next: ?*ExecutionContext = null,

    /// Backward link companion to `next`. Required by spec ops that
    /// arbitrarily remove or reposition an EC: `priority` (re-bucket on
    /// change), `affinity` (migration), `terminate` (drop from queue on
    /// destroy), `delete` on a reply (resolve sender with E_ABANDONED),
    /// and cross-EC `suspend`. O(1) instead of O(N) walk.
    ///
    /// caller-pinned: raw `?*EC`, same justification as `next` — pinned
    /// by the enclosing queue's lock.
    prev: ?*ExecutionContext = null,

    /// Current scheduling priority. Mirrors handle field0.pri.
    priority: Priority = .normal,

    /// Core affinity mask — bit N = 1 ⇒ may run on core N. `0` is the
    /// "any core" sentinel and matches the spec ABI exactly.
    affinity: u64 = 0,

    /// Lifecycle state. See `State` for the queue invariant.
    state: State = .ready,

    /// Owner core while `state` is running, parking, or pended. Sentinel
    /// means the EC is not currently owned by a CPU core.
    owner_core: u8 = NOT_IN_RUN_QUEUE,

    /// Short pin count for lifecycle operations that have claimed an EC
    /// but have not yet finished moving it between containers.
    pin_depth: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    /// Destruction marker separate from the slab generation word so
    /// lifecycle readers can observe retirement without resolving a handle.
    mark_state: std.atomic.Value(u8) =
        std.atomic.Value(u8).init(@intFromEnum(lifecycle.MarkState.clear)),

    /// Remote-suspend directive word. Packed as `{ state: u8, owner_slot: u24 }`.
    directive_state: std.atomic.Value(u32) =
        std.atomic.Value(u32).init(lifecycle.packDirective(.none, 0)),

    /// Result published when an owner core fails an armed remote-suspend
    /// directive. The waiter consumes it after observing `.failed`.
    directive_result: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    /// Port carried by an armed remote suspend directive.
    directive_port: ?SlabRef(Port) = null,

    /// Caller whose validated pair-entry stash should be handed to this
    /// EC if an armed remote suspend directive commits.
    directive_owner: ?*ExecutionContext = null,

    /// Current wait episode descriptor. Container-specific payload fields
    /// remain below; this descriptor is the lifecycle authority for where
    /// the EC is parked.
    wait: Wait = .{},

    /// Hint for `scheduler.removeFromQueue`: the core whose run queue
    /// currently holds this EC, or `NOT_IN_RUN_QUEUE` (`0xFF`) when the
    /// EC is not in any per-core run queue. Maintained at every Zig
    /// run-queue mutation site in `sched/scheduler.zig` under the
    /// matching `core_locks[core]`, and on the `removeFromQueue`
    /// success path itself.
    ///
    /// The x64 IPC fast-path asm in `arch/x64/interrupts.zig` mirrors
    /// this discipline in its R13 ready-enqueue branches: it writes the
    /// queue links first, then publishes this byte to the local core id
    /// before releasing that core's run-queue lock. Readers still treat
    /// it as a hint and revalidate actual queue membership under the
    /// named lock.
    ///
    /// Read with `.acquire`, written with `.release`, so the queue
    /// linkage written under `core_locks[core]` immediately before
    /// the field write is visible to any reader that observes a non-
    /// sentinel value.
    current_queue_core: std.atomic.Value(u8) =
        std.atomic.Value(u8).init(NOT_IN_RUN_QUEUE),

    // ── Futex wait state — meaningful iff state == .futex_wait ────────

    /// Absolute monotonic-clock deadline (ns). The scheduler tick checks
    /// it to wake a timed-out futex waiter. `0` = no deadline.
    futex_deadline_ns: u64 = 0,

    /// Index 0..N-1 into the original (addr, expected/target) pair list
    /// of the address whose bucket woke this EC. Stamped by
    /// `futex.wake` before transitioning to `.ready`; read after resume
    /// so the syscall's return `[1] = addr` names the right one.
    futex_wake_index: u8 = 0,

    /// In-place backing storage for the wait nodes the futex bucket
    /// chains link into while this EC is blocked. Must live on the
    /// EC, not the calling kernel stack: `futex_wait_val` returns a
    /// placeholder before the EC parks, so by the time wake/expiry
    /// runs, any waitVal-local stack frame has been reused. Sized to
    /// `MAX_FUTEX_ADDRS_PER_EC` (one node per watched address).
    futex_wait_nodes_storage: [MAX_FUTEX_ADDRS_PER_EC]WaitNode = undefined,

    /// In-place backing storage for the per-node user vaddrs the wake
    /// path needs to surface in vreg 1. Same lifetime concern as
    /// `futex_wait_nodes_storage`.
    futex_wait_vaddrs_storage: [MAX_FUTEX_ADDRS_PER_EC]u64 = undefined,

    /// Pointer to the prefix of `futex_wait_nodes_storage` actually in
    /// use this wait. One node per watched address; each node has its
    /// own `next` so the EC simultaneously occupies N independent
    /// bucket chains without aliasing a shared link. `null` outside
    /// `.futex_wait`.
    futex_wait_nodes: ?[*]WaitNode = null,

    /// N — number of valid entries in `futex_wait_nodes`. 1 for
    /// single-addr waits, up to MAX_FUTEX_ADDRS (63) for multi-addr.
    futex_bucket_count: u8 = 0,

    /// Pointer to an array of N caller-domain user vaddrs paired with
    /// `futex_wait_nodes` (entry i corresponds to wait-node i). The wake
    /// path reads `futex_wait_vaddrs[futex_wake_index]` to surface the
    /// matched user vaddr per spec §[futex_wait_val]/[futex_wait_change]
    /// vreg-1 contract. `null` outside `.futex_wait`.
    futex_wait_vaddrs: ?[*]const u64 = null,

    // ── Syscall-side scratch for futex_wait_val / futex_wait_change ───
    //
    // The syscall layer (`syscall.futex.futexWaitVal` /
    // `futexWaitChange`) decodes up to MAX_FUTEX_ADDRS_PER_EC pairs from
    // the user `pairs[]` slice into three parallel arrays before
    // handing them to `futex.waitVal/waitChange`. At 63 entries each
    // (3 × 504 B = ~1.5 KiB) those arrays do not fit safely on the
    // syscall kernel stack — combined with the rest of the syscall
    // chain they overran adjacent frames' saved-RIP slots and
    // manifested as `GPF at arch.x64.cpu.idle` on stress runs.
    //
    // Only the syscall-issuing EC ever reads/writes these. The
    // `futex.waitVal/waitChange` impl copies anything it needs to
    // outlive the syscall return into `futex_wait_nodes_storage` /
    // `futex_wait_vaddrs_storage`, so these scratch slots are dead
    // once the syscall returns and may be reused by the next syscall
    // on the same EC.

    /// Resolved page-aligned PAddr for each user vaddr in the call's
    /// pairs[] list. Built in `futexWait{Val,Change}`; consumed by
    /// `futex.waitVal/waitChange` for bucket selection and live-value
    /// loads.
    futex_syscall_addrs_storage: [MAX_FUTEX_ADDRS_PER_EC]PAddr = undefined,

    /// User-domain vaddrs from the call's pairs[] list, paired with
    /// `futex_syscall_addrs_storage`. Passed through to the futex impl
    /// which copies into `futex_wait_vaddrs_storage` for the wait.
    futex_syscall_vaddrs_storage: [MAX_FUTEX_ADDRS_PER_EC]u64 = undefined,

    /// `expected` (waitVal) or `target` (waitChange) values from the
    /// call's pairs[] list. Read-only in the futex impl; not retained
    /// across the wait.
    futex_syscall_values_storage: [MAX_FUTEX_ADDRS_PER_EC]u64 = undefined,

    // ── Event metadata — meaningful iff state == .suspended_on_port ───

    /// Type of event that triggered the suspension. `none` when the EC
    /// is not suspended.
    event_type: EventType = .none,

    /// Per-event-type sub-code (e.g. within memory_fault: read/write/
    /// execute/unmapped/protection). Carried into the event payload at
    /// recv time.
    event_subcode: u8 = 0,

    /// Faulting address (memory_fault) or other event-type-specific u64
    /// payload value.
    event_addr: u64 = 0,

    /// Spec §[event_state] vregs 1..13 = the suspending EC's GPRs at
    /// suspend time. Snapshotted in `suspendOnPort` from the EC's
    /// iret frame in canonical vreg order via
    /// `arch.syscall.getEventStateGprs`, and rewritten into the
    /// receiver's matching GPR slots in `port.deliverEvent` (gated by
    /// `originating_read_cap`) so the sender's payload is observable
    /// on recv per Spec §[suspend] test 10.
    /// x86-64 ordering: rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10,
    /// r12, r13, r14, r15. aarch64 ordering: x0..x12.
    event_state_gprs: [13]u64 = [_]u64{0} ** 13,

    /// Spec §[event_state] vreg 14 (x86-64 `[rsp+8]`) / vreg 32
    /// (aarch64 `[sp+8]`) — the suspending EC's saved instruction
    /// pointer. Snapshotted in `suspendOnPort` from the EC's saved
    /// context (entry point for ECs that never executed; saved RIP/PC
    /// for ones suspended mid-execution) and flushed onto the
    /// receiver's user stack at recv resume time.
    event_rip: u64 = 0,

    /// Number of valid entries in `pending_pair_entries`. Set by the
    /// suspend-side syscall layer from the syscall word's `pair_count`
    /// field after `validatePairEntries` has decoded each entry. Read
    /// at recv time in `port.deliverEvent` to drive contiguous handle
    /// installation in the receiver's domain. Spec §[handle_attachments].
    pending_pair_count: u8 = 0,

    /// Decoded pair entries stashed by the suspending EC's syscall
    /// path. Spec §[handle_attachments] mandates that the actual
    /// move/copy happens at recv time, so the entries ride the EC
    /// across the suspend → recv rendezvous. Each entry carries the
    /// captured `ErasedSlabRef` (gen-validated and object-ref pinned
    /// at stash time), original source domain/slot, source caps, the
    /// type tag and caps to install verbatim on the receiver, and the
    /// move flag (drives the source-slot clear at recv). Sized to
    /// `MAX_PAIR_ENTRIES_PER_EC` to match the spec ceiling.
    pending_pair_entries: [MAX_PAIR_ENTRIES_PER_EC]PairEntryStashed = undefined,

    /// Port we joined the wait queue on. Lets cleanup find us if the
    /// port closes while we are queued. `null` outside a suspension.
    suspend_port: ?SlabRef(Port) = null,

    /// Snapshot of the recv'ing port handle's `xfer` cap, taken under
    /// the receiver's CD lock when `recv` blocks. Spec §[reply]: the
    /// reply handle minted at recv resume inherits `xfer = 1` iff the
    /// recv'ing port carried `xfer`. The rendezvous-with-receiver path
    /// no longer has the receiver's CD locked when minting the reply,
    /// so we cache the bit here on the suspend side. Zero outside a
    /// suspended recv.
    recv_port_xfer: bool = false,

    /// Deadline for a timed `recv`. Zero outside a recv-with-timeout.
    /// Set when recv blocks with timeout_ns != 0; cleared by either the
    /// normal sender-wake path or `expireTimedRecvWaiters`.
    recv_deadline_ns: u64 = 0,

    /// Spec §[syscall_abi]: vreg 0 (the syscall word at `[rsp+0]`) is
    /// the recv-success return path — pair_count, tstart, reply_handle
    /// id, and event_type are packed here per §[event_state]. vreg 1
    /// (rax) carries error codes only and is 0 on success. The kernel
    /// stages the composed word here in `deliverEvent` and the
    /// per-arch resume path flushes it to user `[ctx.rsp + 0]` while
    /// running in this EC's address space, just before iretq.
    /// `pending_event_word_valid` discriminates "no pending write"
    /// from "pending write of value 0" since 0 is a legal return word.
    pending_event_word: u64 = 0,
    pending_event_word_valid: bool = false,

    /// Spec §[event_state] vreg 14 (x86-64 `[rsp+8]`) / vreg 32
    /// (aarch64 `[sp+8]`) — the suspending EC's RIP / PC, staged here
    /// in `deliverEvent` and flushed onto this EC's user stack at recv
    /// resume time. Like `pending_event_word`, the user-page write is
    /// only safe when running in this EC's address space, so the flush
    /// is deferred to the syscall epilogue (synchronous recv with a
    /// queued sender) or the rendezvous resume path (parked receiver
    /// woken by an arriving suspend). 0 is a legal value on freshly
    /// created ECs whose entry was zeroed, hence the explicit `_valid`
    /// flag.
    pending_event_rip: u64 = 0,
    pending_event_rip_valid: bool = false,

    /// Back-pointer to the receiver-side handle table entry that holds
    /// the outstanding reply against this EC. Set when we are dequeued
    /// by recv (the receiver's `recv` writes its handle entry pointing
    /// at this EC with type=reply, and stores the entry's address here
    /// so `terminate(this_ec)` can find it and mark it `E_ABANDONED`).
    /// Cleared when `reply` / `reply_transfer` / `delete` consumes the
    /// handle. `null` until recv dequeues us.
    ///
    /// No separate Reply slab object exists — the reply IS a handle
    /// table entry with type=reply pointing back at the suspended
    /// sender's EC, distinguished from a regular EC handle by the type
    /// tag in the parallel user `Capability.word0`. UAF safety on
    /// reply ops comes from this EC's own `_gen_lock`.
    pending_reply_holder: ?*KernelHandle = null,

    /// Receiver-side domain + slot for the outstanding reply handle —
    /// paired with `pending_reply_holder`. Stored separately so the
    /// `terminate` path can mark the user_table caps with the
    /// `abandoned` bit (the kernel_table entry alone has no caps
    /// field). Both are set/cleared together with `pending_reply_holder`.
    pending_reply_domain: ?SlabRef(CapabilityDomain) = null,
    pending_reply_slot: u12 = 0,

    /// Write-cap snapshot from the originating EC handle taken at the
    /// moment this EC was suspended (the suspending EC handle for
    /// explicit suspend, or the vCPU EC handle for vm_exit). Read at reply time
    /// so the receiver's vreg modifications are committed back to the
    /// sender's saved state iff the originating handle had `write`.
    /// Spec §[reply] tests 05/06.
    originating_write_cap: bool = false,

    /// Read-cap snapshot from the originating EC handle. Mirrors
    /// `originating_write_cap` but gates the recv-side projection of
    /// the suspended EC's §[event_state] vregs 1..13 onto the
    /// receiver's frame in `port.deliverEvent`: when set, the
    /// snapshotted GPRs are exposed; when clear, all 13 vregs land in
    /// the receiver as zero. Spec §[suspend] test 10.
    originating_read_cap: bool = false,

    // ── Restart ───────────────────────────────────────────────────────

    /// Original entry point recorded at create time. Used by
    /// `restart_policy = restart_at_entry` to re-launch the EC.
    entry_point: VAddr,

    // ── vCPU (null on regular ECs) ────────────────────────────────────

    /// VM this EC is a vCPU of, or `null` for a regular EC. Set at
    /// `create_vcpu`; immutable.
    vm: ?SlabRef(VirtualMachine) = null,

    /// Port where vm_exit events are delivered for this vCPU. Set at
    /// `create_vcpu` together with `vm`; nulled when the vCPU is
    /// destroyed or when the port's destruction cascades. The vCPU's
    /// existence increments `port.bind_refcount` per spec §[port]
    /// lifetime model; the matching dec runs in
    /// `destroyExecutionContextLocked`.
    exit_port: ?SlabRef(Port) = null,

    /// Singly-linked list link used by `Port.vcpu_list_head` to
    /// enumerate every vCPU pinning this port. Mutated under the
    /// port's `_gen_lock` (insert at create_vcpu, remove at vCPU
    /// destroy or cascade). `null` on regular ECs and on vCPUs whose
    /// exit_port has already been cleared. Reused by
    /// `port.cascadeDetachVcpus` as the chaining field for the
    /// post-lock-release destroy walk.
    /// The link carries the EC generation captured when the vCPU was
    /// published onto the port. A cascade finalize must pass that ref
    /// through the EC destroy helper so a recycled slot cannot be retired
    /// through a stale pointer.
    vcpu_list_next: ?SlabRef(ExecutionContext) = null,

    /// Per-vCPU arch state cell allocated by `allocVcpuArchState`. On
    /// x86-64 this points at a `vcpu.VcpuArchState` (GuestState + 16-byte-
    /// aligned FxsaveArea + last VmExitInfo); on aarch64 the analogous
    /// per-vCPU register bank. `null` on regular ECs and on vCPU ECs
    /// before `create_vcpu` finishes wiring. Freed on EC destruction.
    vcpu_arch_state: ?*anyopaque = null,

    // ── Lazy FPU ──────────────────────────────────────────────────────

    /// Save buffer for FP/SIMD state. The kernel itself never touches
    /// FP/SIMD, so userspace state survives across syscalls in registers.
    /// Eviction happens only when a different EC on the same core
    /// actually uses FP/SIMD, trapping the FPU-disabled bit. 576 bytes
    /// covers FXSAVE on x64 and V0..V31 + FPCR + FPSR on aarch64 (no
    /// SVE). Aligned 64 because XSAVE requires it on x64 and to fit a
    /// single cache line for the common case.
    fpu_state: [576]u8 align(64) = [_]u8{0} ** 576,

    /// Which core's `last_fpu_owner` slot currently points at this EC,
    /// or `null` if it has never used FPU since boot or has been evicted
    /// by another EC's trap. Read by the scheduler on cross-core
    /// migration to know whether the EC's regs need flushing from the
    /// source core before the destination core can safely restore.
    last_fpu_core: ?u8 = null,
};

pub const Allocator = SecureSlab(ExecutionContext, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: stygia.utils.range.Range,
    ptrs_range: stygia.utils.range.Range,
    links_range: stygia.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API (syscall handlers) ──────────────────────────────────

/// `self` syscall handler — returns the packed handle word for an EC
/// handle in the caller's domain that references the calling EC. Spec
/// §[execution_context].self.
///
/// Linear walk of the caller's kernel_table: an in-use slot
/// (`ref.ptr != null`) whose ptr equals `caller` and whose parallel
/// user_table entry is type-tagged `execution_context` is a self-handle.
/// By spec §[self]'s at-most-one invariant, at most one such slot
/// exists. Returns the packed Word0 (id | type<<12 | caps<<48) so the
/// type tag in bits 12..15 disambiguates the success word from the
/// `1..15` error range.
pub fn self(caller: *ExecutionContext) i64 {
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);

    var slot: u16 = 0;
    while (slot < capability.MAX_HANDLES_PER_DOMAIN) {
        const entry = &cd.kernel_table[slot];
        if (entry.ref.ptr == @as(*anyopaque, @ptrCast(caller))) {
            const user_word0 = cd.user_table[slot].word0;
            if (capability.Word0.typeTag(user_word0) == .execution_context) {
                const caps_word = capability.Word0.caps(user_word0);
                return @intCast(capability.Word0.pack(
                    @intCast(slot),
                    .execution_context,
                    caps_word,
                ));
            }
        }
        slot += 1;
    }
    return errors.E_NOENT;
}

/// `terminate` syscall handler. Spec §[execution_context].terminate.
///
/// Reserved-bit validation, handle resolution, and `term` cap check are
/// performed by the syscall-layer wrapper. By the time we get here the
/// target has been verified as an EC handle in `caller.domain` carrying
/// `term`. This stage performs the actual teardown:
///
///   1. Re-resolve the slot under the cd lock to recover the worker
///      EC's typed slab ref (pointer + gen).
///   2. Drop the cd lock, then fire `destroyExecutionContext`. The
///      destroy path locks the worker's domain itself to read the
///      addr-space root for kstack unmap, so it must run with the cd
///      lock released (worker.domain == caller.domain in the
///      target=self construction the spec tests use).
///
/// The caller's slot is intentionally NOT cleared here. Per spec
/// §[execution_context].terminate test 05, "syscalls invoked with any
/// handle to the terminated EC return E_TERM and remove that handle
/// from the caller's table on the same call." The kernel-table entry
/// is left pointing at the now-destroyed EC slab; the gen bump in
/// `destroyExecutionContext` flips its parity to "freed", so the next
/// syscall using this handle catches the gen mismatch via
/// `SlabRef.lock`, surfaces `E_TERM`, and lazily evicts the slot. The
/// same lazy eviction applies to stale handles in other capability
/// domains.
/// Park the calling EC out of every run queue with no possibility of
/// resuming. Used by unhandled fault teardown: the kernel must keep
/// the faulting EC from being re-dispatched. Otherwise
/// the EC re-iretq's onto the same instruction, faults again, and
/// (especially at higher-than-default priority) starves every other EC
/// in its domain. A full `destroyExecutionContext` from this path would
/// unmap the kernel stack the exception handler is currently running
/// on, so we instead clear the local core's `current_ec` slot and mark
/// the EC `.exited`. The EC's slab + stacks stay pinned until its
/// owning domain is torn down. After this returns the caller
/// (`exceptionHandler`) calls `scheduler.yieldTo(null)` — with
/// `current_ec` cleared, `yieldTo` skips the re-enqueue path and
/// dispatches the next runnable EC.
/// TEMP DIAGNOSTIC (stygia-2u0, REMOVE). Plain call counter only.
///
/// An earlier version of this probe also tried to classify each park by
/// whether the EC's domain was still alive, via `ec.domain.lockIrqSave`.
/// That DEADLOCKED the boot: SLOT_SELF teardown can call
/// `parkSelfFaulted` while already holding `cd._gen_lock` (the
/// `destroyPhase1` invariant), so the probe was a recursive gen-lock
/// acquire. Nothing in this function may take the domain lock.
pub var park_calls: u64 = 0;

pub fn parkSelfFaulted(ec: *ExecutionContext) void {
    // TEMP DIAGNOSTIC (stygia-2u0, REMOVE).
    park_calls +%= 1;
    _ = retireAndBumpCurrentGen(ec);
}

/// Park the calling EC into `.idle_wait` — used by the aarch64 wfi/wfe
/// trap path to deschedule a worker that issued a wait-for-event/interrupt
/// instruction in EL0. Distinct from `parkSelfFaulted` in that the EC
/// remains a valid `suspend` target: the suspend syscall accepts
/// `.idle_wait` alongside `.running`/`.ready`, transitions the EC into
/// `.suspended_on_port`, and delivers the suspension event normally. The
/// EC is removed from this core's `current_ec` slot so the scheduler
/// dispatches a different EC after this returns.
///
/// The state transition is serialized through `ec._gen_lock` so a
/// concurrent `suspend(target=ec, port)` from another core (which
/// snapshots state under the same gen lock) cannot interleave a
/// .running → .suspended_on_port transition with our .running →
/// .idle_wait write. The lock is held only across the field writes; we
/// drop it before yielding to the scheduler.
pub fn parkIdleWait(ec: *ExecutionContext) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    const gen = ec._gen_lock.currentGen();
    if (gen % 2 == 0) return;
    const ec_ref = SlabRef(ExecutionContext).init(ec, gen);
    if (ec_ref.lockIrqSave(@src())) |lr| {
        defer ec_ref.unlockIrqRestore(lr.irq_state);
        _ = lifecycle.prepareRunningPark(ec, core_id, .idle);
    } else |_| {
        // Slab gen flipped — EC was destroyed mid-trap. Nothing to do;
        // the trampoline will ERET into a freed slot, but the next
        // scheduler dispatch picks a different EC and the freed slot
        // gets recycled lazily.
    }
}

fn routeRetiredFinalize(
    ec: *ExecutionContext,
    pre_bump_gen: u63,
    retired_from: State,
    retired_owner: u8,
    caller: ?*ExecutionContext,
) void {
    _ = pre_bump_gen;
    const owned = switch (retired_from) {
        .running, .parking, .pended => retired_owner < scheduler.MAX_CORES,
        else => false,
    };
    if (!owned) {
        finalizeDestroyMarkedDead(ec);
        return;
    }

    const self_core: u8 = @truncate(arch.smp.coreID());
    if (retired_owner == self_core and scheduler.claimOwnTeardownInline(ec)) {
        finalizeDestroyMarkedDead(ec);
        return;
    }

    if (retired_owner != self_core) arch.smp.sendWakeIpi(retired_owner);

    if (caller) |c| {
        if (c != ec) {
            while (scheduler.coreCurrentIs(retired_owner, ec)) {
                spin_diag.note(.route_retired_wait, @intFromPtr(ec));
                arch.paging.serviceTlbMaintenanceWhileSpinning();
                // stygia-8xl. This wait runs from the `terminate`
                // syscall, i.e. with IF cleared by IA32_FMASK and never
                // re-enabled, so it is deaf to every IPI. That is fine
                // for the wake IPI we just sent (it only has to be
                // delivered to the OTHER core) but fatal for the lazy-FPU
                // flush protocol: `retired_owner` can be sitting in
                // `interrupts.switchTo` → `migrateFlush`, IRQs masked,
                // waiting for THIS core to save the very EC's FP regs —
                // and it published `current_ec` before it got there, so
                // our exit condition is exactly what it can no longer
                // reach. Service the mailbox here; see
                // `fpu.serviceLocalFlushWhileSpinning` for the full
                // argument, including why "the IPI could have fired
                // here anyway" is NOT the reason this is sound.
                stygia.sched.fpu.serviceLocalFlushWhileSpinning();
                std.atomic.spinLoopHint();
            }
        }
    }
}

const RetiredDeadGen = struct {
    from: State,
    owner: u8,
    gen: u63,
};

fn retireAndBumpDeadGen(
    ec_ref: SlabRef(ExecutionContext),
    ec: *ExecutionContext,
) ?RetiredDeadGen {
    const wlr = ec_ref.lockIrqSave(@src()) catch return null;
    const gen: u63 = @intCast(ec._gen_lock.currentGen());
    _ = lifecycle.markRetiring(ec);
    lifecycle.waitPinsDrained(ec);
    if (lifecycle.load(ec) == .ready) {
        scheduler.removeFromQueue(ec);
    }
    const retired_owner = ec.owner_core;
    const retired_from = lifecycle.retire(ec);
    recordSpawnTrace(ec, null, .retire, @intFromEnum(retired_from));
    slab_instance.bumpDeadGenLocked(ec, gen);
    // bumpDeadGenLocked clears the lock bit as part of the gen flip,
    // so we cannot use unlockIrqRestore (it would assert held). Just
    // restore IRQs.
    arch.cpu.restoreInterrupts(wlr.irq_state);
    return .{
        .from = retired_from,
        .owner = retired_owner,
        .gen = gen,
    };
}

fn retireAndBumpCurrentGen(ec: *ExecutionContext) ?RetiredDeadGen {
    const gen = ec._gen_lock.currentGen();
    if (gen % 2 == 0) return null;
    const ec_ref = SlabRef(ExecutionContext).init(ec, @intCast(gen));
    return retireAndBumpDeadGen(ec_ref, ec);
}

pub fn terminate(caller: *ExecutionContext, target: u64) i64 {
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const cd_irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    const entry = capability.resolveHandleOnDomain(cd, slot, .execution_context) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const worker_ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    // Verify the slot still references a live EC. If the gen lock
    // refuses (slot's referenced EC was already destroyed), evict
    // the stale entry and surface E_TERM (spec test 05/06).
    const wlr = worker_ref.lockIrqSave(@src()) catch {
        capability.clearAndFreeSlot(cd, slot, entry);
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_TERM;
    };
    worker_ref.unlockIrqRestore(wlr.irq_state);
    cd_ref.unlockIrqRestore(cd_irq_state);

    const ec = worker_ref.ptr;
    const retired = retireAndBumpDeadGen(worker_ref, ec) orelse return errors.OK;

    // Prepare phase — runs after the retire/dead-gen transition to keep
    // `.retired` fused with the slab generation flip. It still runs
    // WITHOUT the EC's gen lock held to avoid
    // EC→CD lock-order inversion (abandonPendingReply takes the
    // pending-reply holder's CD; CD→EC is the canonical order, so
    // holding EC across CD acquire would seed an AB-BA cycle in
    // lockdep). The fields touched here are stable for `.running`
    // ECs (queue/port linkage is empty while running) and for parked
    // ECs no other core is mutating them. Mirrors the pre-deferred-
    // destroy invariants of the old `destroyExecutionContext`.
    abandonPendingReply(ec);

    // Run all queue/waiter cleanups unconditionally rather than
    // branching on `ec.state`. State transitions on this EC happen
    // without holding the EC's gen-lock (e.g. `suspendOnPortLocked`
    // mutates `ec.state` under the Port's lock, not the EC's), so a
    // concurrent transition between the state-read and the matching
    // cleanup would leave a stale `*ec` on whichever queue the EC
    // moved into. Each cancel below is idempotent: a no-op when the
    // EC isn't in the targeted queue. Doing all of them drains
    // whichever the EC ends up in regardless of races.
    scheduler.removeFromQueue(ec);
    if (ec.suspend_port) |port_ref| {
        const portlr = port_ref.lockIrqSave(@src()) catch null;
        if (portlr) |plr| {
            const p = plr.ptr;
            _ = p.waiters.remove(ec);
            if (p.waiters.isEmpty()) p.waiter_kind = .none;
            port_ref.unlockIrqRestore(plr.irq_state);
        }
    }
    stygia.sched.port.releasePendingPairEntries(ec);
    // The EC's WaitNodes live on its kernel stack; later
    // `finalizeDestroyMarkedDead` unmaps the kstack pages, which
    // would leave the futex bucket queues holding pointers into
    // unmapped memory and fault the next `wake()` walk.
    stygia.sched.futex.cancelWait(ec);
    if (ec.recv_deadline_ns != 0) stygia.sched.port.cancelRecvDeadline(ec);

    // Clear any per-core `last_fpu_owner` slot still naming this EC —
    // otherwise the next FP-disabled trap on that core would
    // `fpuSave(&ec.fpu_state)` into a slab slot we're about to gen-
    // bump and (eventually) recycle to another EC.
    stygia.sched.fpu.clearFromLastFpuOwner(ec);

    if (ec.vm != null and ec.vcpu_arch_state != null) {
        arch.vm.freeVcpuArchState(ec);
    }

    scheduler.removeFromQueue(ec);
    routeRetiredFinalize(ec, retired.gen, retired.from, retired.owner, caller);
    return errors.OK;
}

/// Final teardown of an EC whose gen has already been rotated to its
/// freed parity via `slab_instance.bumpDeadGenLocked` and whose
/// prepare-phase cleanup was already done by `terminate`. Frees the
/// kernel stack and pushes the slab slot back onto the freelist.
/// Called from two sites: (1) `terminate` directly when the target
/// was not dispatched anywhere; (2) the per-core reap point in
/// `switchTo` for ECs that were running on this core when terminate
/// fired.
///
/// Includes defensive port detach: if the running EC re-suspended on
/// a port between terminate's prepare phase and the reap, it would
/// otherwise leave a stale `*ec` on the port wait queue. The pop-side
/// guards (`popHighestPriority{Sender,Receiver}`) reject the stale
/// pointer via the even-gen test, but removing it explicitly here
/// keeps the wait queue's count/size accurate.
pub fn finalizeDestroyMarkedDead(ec: *ExecutionContext) void {
    recordSpawnTrace(ec, null, .finalize, 0);
    lifecycle.markDirectiveDead(ec);
    if (ec.suspend_port) |port_ref| {
        if (port_ref.lockIrqSave(@src())) |plr| {
            const p = plr.ptr;
            _ = p.waiters.remove(ec);
            if (p.waiters.isEmpty()) p.waiter_kind = .none;
            port_ref.unlockIrqRestore(plr.irq_state);
        } else |_| {}
    }

    if (ec.user_stack) |us| {
        _ = us;
    }
    // Free the kstack unconditionally. This used to be gated on "the
    // owning domain is still alive" (inherited from when the old code
    // fetched the domain root under its lock), which leaked a
    // KERNEL_STACK_PAGES-page stack for every EC finalized after its
    // domain had been dead-marked. Since domain teardown dead-marks in
    // phase 1 and then destroys its ECs, that was very nearly every EC:
    // ~30 MB per full suite pass, exhausting the PMM around pass 11-16
    // of a repeat run on both bare metal and KVM (stygia-2u0).
    //
    // The gate was standing in for "no core is still live on this
    // kstack" — a real hazard (freeing a stack that is some core's
    // SP_EL1 / TSS.RSP0 target turns its next exception into a push onto
    // unmapped memory) but one this function is already protected from
    // by its callers, not by the domain's liveness. `on_cpu` is the
    // precise signal, and every path here honours it: the three
    // scheduler drains and both arch dispatch reap loops filter on
    // `on_cpu` and `standing_on_zombie` (see `takeOwnPendingZombie`),
    // and terminate's only ungated call is its `LAST_DISPATCHED_NEVER`
    // branch, where no core's rsp has ever pointed at these pages.
    //
    // What the gate WAS masking is aliasing, and both halves are now
    // closed in `destroyKernel`: frames are quarantined until their
    // invalidation epoch retires (they used to re-enter the PMM ahead
    // of it), and as of stygia-za7 the VA slot rides that same epoch
    // instead of being recycled immediately. Lifting the gate before
    // those two landed is what produced the suite-wide fault storms
    // recorded in the previous version of this comment.
    stack.destroyKernel(ec.kernel_stack);
    ec.wait.clear();

    slab_instance.destroyAlreadyMarked(ec);
}

/// `yield` syscall handler. Spec §[execution_context].yield.
///
/// Per spec: when `target` is non-zero and names a runnable EC handle
/// in the caller's table, the scheduler dispatches that EC next on
/// this core; otherwise (target == 0 or resolution fails) the call
/// still yields and the scheduler picks whatever's next.
///
/// Target-aware dispatch matters when caller's priority outranks the
/// target's: a plain `yieldTo(null)` re-dispatches the caller from
/// its own priority queue, starving the lower-pri target. Surfaces
/// in recv_14 (parent pri=3 yields to worker pri=0; worker must
/// self-suspend before the parent's blocking recv can complete).
/// `priority` syscall handler. Spec §[execution_context].priority.
///
/// The syscall layer has already validated reserved bits, resolved the
/// handle as an EC, and verified `spri` + `new_priority <= caller's
/// pri ceiling`. This handler updates the target EC's authoritative
/// priority and refreshes the handle's field0 snapshot (spec
/// §[execution_context] field0 bits 0-1 = pri).
///
/// If the target EC has been terminated, the slot still references the
/// destroyed slab but its gen has flipped to "freed". `lockWithGen`
/// catches the parity mismatch and we surface `E_TERM` while evicting
/// the slot from the caller's table — the spec line "syscalls invoked
/// with any handle to the terminated EC return E_TERM and remove that
/// handle from the caller's table on the same call" (test 05).
///
/// Re-bucketing the target if it is currently parked in a futex/port
/// wait queue (spec test 07) is not yet implemented; the priority
/// field is updated unconditionally so the next enqueue picks it up.
/// Same for the run-queue level-bucket case — a removeFromQueue +
/// enqueue would shift `.ready` ECs into the new priority bucket
/// immediately, but the run queues self-balance on the next preempt
/// cycle (cur EC's preempt re-enqueues with the new priority via
/// `state.run_queue.enqueue` which reads `ec.priority`), so deferring
/// is acceptable for the spec tests' observable behavior.
fn repairPriorityPlacement(ec: *ExecutionContext, expected_gen: u32) void {
    if (!lifecycle.tryPinLive(ec)) return;
    defer lifecycle.releasePin(ec);
    if (ec._gen_lock.currentGen() != @as(u63, expected_gen)) return;

    switch (lifecycle.load(ec)) {
        .ready => {
            if (!lifecycle.isReadyCacheValid(ec, NOT_IN_RUN_QUEUE)) return;
            if (!scheduler.claimReadyFromQueue(ec, expected_gen)) return;
            scheduler.enqueue(ec);
            lifecycle.releasePin(ec);
        },
        .waiting, .parking => switch (ec.wait.kind) {
            .port_sender, .port_receiver => {
                const port_ref = ec.suspend_port orelse return;
                const plr = port_ref.lockIrqSave(@src()) catch return;
                const p = plr.ptr;
                if (p.waiters.remove(ec)) p.waiters.enqueue(ec);
                port_ref.unlockIrqRestore(plr.irq_state);
            },
            .futex => stygia.sched.futex.repairPriority(ec),
            else => {},
        },
        else => {},
    }
}

fn repairAffinityPlacement(ec: *ExecutionContext, expected_gen: u32) void {
    if (!lifecycle.tryPinLive(ec)) return;
    defer lifecycle.releasePin(ec);
    if (ec._gen_lock.currentGen() != @as(u63, expected_gen)) return;

    if (lifecycle.load(ec) != .ready) return;
    if (!lifecycle.isReadyCacheValid(ec, NOT_IN_RUN_QUEUE)) return;
    if (!scheduler.claimReadyFromQueue(ec, expected_gen)) return;
    scheduler.enqueue(ec);
    lifecycle.releasePin(ec);
}

pub fn setPriority(caller: *ExecutionContext, target: u64, new_priority: u64) i64 {
    if (new_priority > 3) return errors.E_INVAL;

    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const cd_irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    const entry = capability.resolveHandleOnDomain(cd, slot, .execution_context) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const target_ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const tlr = target_ref.lockIrqSave(@src()) catch {
        // Stale handle — target EC was terminated. Evict the slot from
        // the caller's table and surface E_TERM (spec test 05).
        capability.clearAndFreeSlot(cd, slot, entry);
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_TERM;
    };
    const target_ec = tlr.ptr;
    const target_gen: u32 = @intCast(target_ec._gen_lock.currentGen());

    const new_pri: Priority = @enumFromInt(@as(u2, @intCast(new_priority)));
    target_ec.priority = new_pri;
    target_ref.unlockIrqRestore(tlr.irq_state);
    repairPriorityPlacement(target_ec, target_gen);

    // Refresh the handle's field0 snapshot (priority is bits 0-1).
    cd.user_table[slot].field0 = (cd.user_table[slot].field0 & ~@as(u64, 0x3)) | @intFromEnum(new_pri);

    cd_ref.unlockIrqRestore(cd_irq_state);
    return errors.OK;
}

/// `affinity` syscall handler. Spec §[execution_context].affinity.
///
/// The syscall layer has already validated reserved bits, the
/// new_affinity range, resolved the handle as an EC, and verified
/// `saff`. This handler updates the target EC's authoritative
/// affinity mask and refreshes the handle's field1 snapshot (spec
/// §[execution_context] field1 bits 0-63 = affinity mask).
///
/// If the target EC has been terminated, the slot still references the
/// destroyed slab but its gen has flipped to "freed". `lockWithGen`
/// catches the parity mismatch and we surface `E_TERM` while evicting
/// the slot from the caller's table — the spec line "syscalls invoked
/// with any handle to the terminated EC return E_TERM and remove that
/// handle from the caller's table on the same call" (test 05).
///
/// Re-enqueuing the target on a core that satisfies the new mask if
/// it is currently parked or running on an excluded core is not yet
/// implemented; the affinity field is updated unconditionally so the
/// next enqueue picks it up via `yieldTo`'s affinity-aware re-enqueue
/// branch (which always hands a `.running` EC off a forbidden core,
/// falling through to `run()` when the local queue has no
/// replacement so the local frame is not iretq'd through `cur`'s
/// saved frame while the remote core dispatches it).
pub fn setAffinity(caller: *ExecutionContext, target: u64, new_affinity: u64) i64 {
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const cd_irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    const entry = capability.resolveHandleOnDomain(cd, slot, .execution_context) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const target_ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    const tlr = target_ref.lockIrqSave(@src()) catch {
        // Stale handle — target EC was terminated. Evict the slot from
        // the caller's table and surface E_TERM (spec test 05).
        capability.clearAndFreeSlot(cd, slot, entry);
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_TERM;
    };
    const target_ec = tlr.ptr;
    const target_gen: u32 = @intCast(target_ec._gen_lock.currentGen());

    target_ec.affinity = new_affinity;
    target_ref.unlockIrqRestore(tlr.irq_state);
    repairAffinityPlacement(target_ec, target_gen);

    // Refresh the handle's field1 snapshot (affinity occupies bits
    // 0-63 of field1).
    cd.user_table[slot].field1 = new_affinity;

    cd_ref.unlockIrqRestore(cd_irq_state);
    return errors.OK;
}

/// Suspend `ec` on `port` with the given event metadata. Used by both
/// the explicit `suspend` syscall and vCPU exit delivery.
/// Rejects vCPUs with E_PERM (spec §[port].suspend test 06).
///
/// Slow-path mirror of arch/x64/interrupts.zig Phase 4: the observable
/// state after this call (current_ec→null, ec.state=suspended_on_port,
/// ec enqueued on port wait queue) must be identical to what the fast
/// path produces, so the two are interchangeable.
///
/// Lock contract: caller MUST hold `port._gen_lock` (acquired via
/// `lockIrqSave*`) on entry, passing the captured IRQ state through
/// `irq_state`. `suspendOnPort` ALWAYS releases that lock before
/// returning — either directly (no-receiver path) or transitively via
/// `rendezvousWithReceiver` (which drops Port before locking the
/// receiver's CD to honor the canonical CD → Port order). Both release
/// paths use `unlockIrqRestore(irq_state)`. Callers must NOT keep
/// their own `defer port_ref.unlockIrqRestore(...)`.
pub fn suspendOnPort(
    ec: *ExecutionContext,
    port: *Port,
    event: EventType,
    subcode: u8,
    addr: u64,
    originating_write_cap: bool,
    originating_read_cap: bool,
    irq_state: u64,
) i64 {
    return suspendOnPortInner(
        ec,
        port,
        event,
        subcode,
        addr,
        originating_write_cap,
        originating_read_cap,
        irq_state,
        null,
        null,
        null,
    );
}

pub fn suspendOnPortWithPairHandoffGen(
    ec: *ExecutionContext,
    handoff_from: *ExecutionContext,
    port: *Port,
    event: EventType,
    subcode: u8,
    addr: u64,
    originating_write_cap: bool,
    originating_read_cap: bool,
    irq_state: u64,
    expected_gen: u32,
) i64 {
    return suspendOnPortInner(
        ec,
        port,
        event,
        subcode,
        addr,
        originating_write_cap,
        originating_read_cap,
        irq_state,
        handoff_from,
        expected_gen,
        null,
    );
}

pub fn suspendOnPortWithPairHandoffDirectiveGen(
    ec: *ExecutionContext,
    handoff_from: *ExecutionContext,
    port: *Port,
    event: EventType,
    subcode: u8,
    addr: u64,
    originating_write_cap: bool,
    originating_read_cap: bool,
    irq_state: u64,
    expected_gen: u32,
    directive_word: u32,
) i64 {
    return suspendOnPortInner(
        ec,
        port,
        event,
        subcode,
        addr,
        originating_write_cap,
        originating_read_cap,
        irq_state,
        handoff_from,
        expected_gen,
        directive_word,
    );
}

fn clearSuspendDirectiveMetadata(ec: *ExecutionContext) void {
    ec.directive_port = null;
    ec.directive_owner = null;
}

fn clearFailedSuspendDirectiveMetadata(ec: *ExecutionContext) void {
    clearSuspendDirectiveMetadata(ec);
    ec.originating_write_cap = false;
    ec.originating_read_cap = false;
}

fn failSuspendDirective(ec: *ExecutionContext, word: u32, result: i64) void {
    if (lifecycle.failDirectiveWord(ec, word, result)) {
        clearFailedSuspendDirectiveMetadata(ec);
    }
}

fn suspendOnPortInner(
    ec: *ExecutionContext,
    port: *Port,
    event: EventType,
    subcode: u8,
    addr: u64,
    originating_write_cap: bool,
    originating_read_cap: bool,
    irq_state: u64,
    handoff_from: ?*ExecutionContext,
    expected_ready_gen: ?u32,
    directive_word: ?u32,
) i64 {
    if (ec.vm != null and event != .vm_exit) {
        port._gen_lock.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }
    const start_state = lifecycle.load(ec);
    var claimed_suspend = false;
    switch (start_state) {
        .running => {
            const current = scheduler.currentEc() orelse {
                port._gen_lock.unlockIrqRestore(irq_state);
                return errors.E_BUSY;
            };
            if (current != ec) {
                port._gen_lock.unlockIrqRestore(irq_state);
                return errors.E_BUSY;
            }
            if (!lifecycle.prepareRunningPark(ec, ec.owner_core, .port_sender)) {
                port._gen_lock.unlockIrqRestore(irq_state);
                return errors.E_INVAL;
            }
        },
        .ready => {
            if (!scheduler.claimReadyFromQueue(ec, expected_ready_gen)) {
                port._gen_lock.unlockIrqRestore(irq_state);
                return errors.E_INVAL;
            }
            claimed_suspend = true;
            ec.wait.begin(.port_sender);
        },
        .waiting => {
            if (ec.wait.kind != .idle) {
                port._gen_lock.unlockIrqRestore(irq_state);
                return errors.E_INVAL;
            }
            switch (lifecycle.beginWaitingClaimPinned(ec)) {
                .claimed => {},
                .pended => {
                    lifecycle.releasePin(ec);
                    port._gen_lock.unlockIrqRestore(irq_state);
                    return errors.E_INVAL;
                },
                .none => {
                    port._gen_lock.unlockIrqRestore(irq_state);
                    return errors.E_INVAL;
                },
            }
            claimed_suspend = true;
            ec.wait.begin(.port_sender);
        },
        else => {
            port._gen_lock.unlockIrqRestore(irq_state);
            return errors.E_INVAL;
        },
    }

    ec.event_type = event;
    ec.event_subcode = subcode;
    ec.event_addr = addr;
    // §[event_state] vregs 1..13 carry the suspending EC's GPRs to the
    // receiver. Snapshot them all in canonical vreg order from the
    // EC's user iret frame (where the syscall-entry GPRs were saved)
    // so they survive across the recv and ride into the receiver's
    // matching GPR slots in `port.deliverEvent`. `iret_frame` is the
    // canonical user-state pointer set on syscall/exception entry;
    // fall back to `ctx` for ECs that suspend outside an in-flight
    // syscall; ctx still references the most recent saved frame.
    const sender_ctx = ec.iret_frame orelse ec.ctx;
    ec.event_state_gprs = arch.syscall.getEventStateGprs(sender_ctx);
    ec.event_rip = arch.syscall.getEventRip(sender_ctx);
    if (event == .suspension) maybePrintReportEntered(ec);
    ec.suspend_port = SlabRef(Port).init(port, port._gen_lock.currentGen());
    ec.wait.port = ec.suspend_port;
    ec.pending_reply_holder = null;
    ec.pending_reply_domain = null;
    ec.pending_reply_slot = 0;
    ec.originating_write_cap = originating_write_cap;
    ec.originating_read_cap = originating_read_cap;
    var stash_moved = false;
    if (handoff_from) |src| {
        stash_moved = movePendingPairStash(ec, src);
    }
    if (start_state != .running and !lifecycle.commitClaimedWaiting(ec)) {
        if (stash_moved) {
            _ = movePendingPairStash(handoff_from.?, ec);
        }
        if (claimed_suspend) lifecycle.releasePin(ec);
        if (directive_word) |word| {
            failSuspendDirective(ec, word, errors.E_INVAL);
        }
        port._gen_lock.unlockIrqRestore(irq_state);
        return errors.E_INVAL;
    }
    // `on_cpu` handling is split by locality below (after the
    // rendezvous decision): when `ec` is THIS core's current EC we are
    // still executing on its kstack and must defer the release to the
    // park-kstack hop (PerCore.pending_kstack_release) — clearing it
    // here would let a resume enqueue+dispatch `ec` on another core
    // that then reuses this very kstack under our feet. When `ec` is
    // remote or queued, its previous core owns the release: touching
    // the flag from here would fake "kstack free" for an EC that may
    // still be running user code on its core (the remote-suspend
    // two-cores-one-frame hole).

    // Rendezvous with a waiting receiver if one is parked. Spec
    // §[recv]/§[suspend]: a send-side rendezvous must wake the
    // highest-priority receiver immediately rather than parking the
    // sender — otherwise a recv() that arrived first sleeps forever
    // because the matching suspend() only enqueues into the wait
    // queue without consulting `waiter_kind == .receivers`.
    //
    // `rendezvousWithReceiver` releases Port internally on the success
    // path so it can take the receiver's CD lock without inverting the
    // canonical CD → Port order. On `.no_receiver` it leaves Port held.
    if (port.waiter_kind == .receivers) {
        switch (stygia.sched.port.rendezvousWithReceiver(ec, port, event, subcode, addr, irq_state)) {
            .delivered => {
                if (stash_moved and ec.pending_pair_count != 0) {
                    _ = movePendingPairStash(handoff_from.?, ec);
                }
                ec.wait.kind = .reply;
                if (directive_word) |word| {
                    _ = lifecycle.disarmDirectiveWord(ec, word);
                    clearSuspendDirectiveMetadata(ec);
                }
                if (claimed_suspend) lifecycle.releasePin(ec);
                return 0;
            },
            .parked => {
                if (directive_word) |word| {
                    _ = lifecycle.disarmDirectiveWord(ec, word);
                    clearSuspendDirectiveMetadata(ec);
                }
                if (claimed_suspend) lifecycle.releasePin(ec);
                return 0;
            },
            .no_receiver => {},
        }
    }

    if (directive_word) |word| {
        _ = lifecycle.disarmDirectiveWord(ec, word);
        clearSuspendDirectiveMetadata(ec);
    }
    // No waiting receiver — park as a sender. WaiterKind tracks which
    // side owns the queue; transition .none → .senders here so a
    // subsequent recv() observing waiters knows what to dequeue.
    port.waiters.enqueue(ec);
    if (port.waiter_kind == .none) port.waiter_kind = .senders;
    port._gen_lock.unlockIrqRestore(irq_state);
    if (claimed_suspend) lifecycle.releasePin(ec);
    return 0;
}

fn movePendingPairStash(dst: *ExecutionContext, src: *ExecutionContext) bool {
    if (dst == src or src.pending_pair_count == 0) return false;
    std.debug.assert(dst.pending_pair_count == 0);
    dst.pending_pair_count = src.pending_pair_count;
    var k: usize = 0;
    while (k < src.pending_pair_count) {
        dst.pending_pair_entries[k] = src.pending_pair_entries[k];
        k += 1;
    }
    src.pending_pair_count = 0;
    return true;
}

pub fn consumeSuspendDirective(ec: *ExecutionContext, frame: *ArchCpuContext) bool {
    const word = ec.directive_state.load(.acquire);
    if (lifecycle.directiveTag(word) != .armed) return false;
    if (lifecycle.load(ec) != .running) {
        failSuspendDirective(ec, word, errors.E_INVAL);
        return false;
    }
    const port_ref = ec.directive_port orelse {
        failSuspendDirective(ec, word, errors.E_BADCAP);
        return false;
    };
    const directive_owner = ec.directive_owner;
    const plr = port_ref.lockIrqSave(@src()) catch {
        failSuspendDirective(ec, word, errors.E_BADCAP);
        return false;
    };
    // The directive traps on the target's owner core; this live frame is
    // the sender state reply must resume from even when writes are denied.
    ec.ctx = frame;
    ec.iret_frame = frame;
    const ret = suspendOnPortInner(
        ec,
        plr.ptr,
        .suspension,
        0,
        0,
        ec.originating_write_cap,
        ec.originating_read_cap,
        plr.irq_state,
        directive_owner,
        null,
        word,
    );
    if (ret != 0) {
        ec.iret_frame = null;
        failSuspendDirective(ec, word, ret);
        return false;
    }
    return true;
}

/// Resume `ec` from a reply. When `apply_writes` is true, the receiver
/// committed GPR modifications via the reply payload — they have
/// already been written into `ec.iret_frame` by the caller. Otherwise
/// `ec` resumes from its saved `ctx` unchanged.
pub fn resumeFromReply(ec: *ExecutionContext, apply_writes: bool) void {
    _ = apply_writes;
    std.debug.assert(lifecycle.isPortSuspended(ec));
    ec.event_type = .none;
    ec.event_subcode = 0;
    ec.event_addr = 0;
    ec.iret_frame = null;
    ec.suspend_port = null;
    ec.pending_reply_holder = null;
    ec.pending_reply_domain = null;
    ec.pending_reply_slot = 0;
    ec.originating_write_cap = false;
    ec.pending_pair_count = 0;
    ec.originating_read_cap = false;
    // No manual `.ready` stamp. `markReady` performs the wait->ready
    // transition itself via `tryClaimWake`, so a reply landing here at
    // the same moment the recv's timeout expires on the timer core
    // enqueues this EC exactly once. Pre-stamping `.ready` would hide
    // the wait state from that claim and let both wakers through — the
    // double-enqueue that resumes one saved frame on two cores.
    scheduler.markReady(ec);
}

/// Mark a pending reply against `ec` as abandoned — invoked when
/// `terminate` destroys a sender that's parked awaiting reply. Sets the
/// `abandoned` bit in the receiver-side reply handle's caps so a
/// subsequent `reply` / `reply_transfer` / `delete` on that slot returns
/// E_ABANDONED per spec §[terminate] test 07. The kernel_table entry
/// itself stays valid until the receiver consumes the slot — the gen
/// bump on `ec` would already make `reply` fail with E_TERM, but the
/// spec wants E_ABANDONED for the post-terminate window. Marking the
/// caps lets reply distinguish "abandoned via terminate" from "sender
/// died for other reasons".
pub fn abandonPendingReply(ec: *ExecutionContext) void {
    _ = ec.pending_reply_holder orelse return;
    if (ec.pending_reply_domain) |dom_ref| {
        // Re-validate the domain through the SlabRef before mutating
        // its user_table — terminate may race against destroy of the
        // receiver's domain.
        if (dom_ref.lockIrqSave(@src())) |domlr| {
            const dom = domlr.ptr;
            defer dom_ref.unlockIrqRestore(domlr.irq_state);
            const slot = ec.pending_reply_slot;
            const word0 = dom.user_table[slot].word0;
            const tag = stygia.caps.capability.Word0.typeTag(word0);
            if (tag == .reply) {
                const caps_u16 = stygia.caps.capability.Word0.caps(word0);
                var rc: stygia.sched.port.ReplyCaps = @bitCast(caps_u16);
                rc.abandoned = true;
                const new_caps: u16 = @bitCast(rc);
                dom.user_table[slot].word0 = stygia.caps.capability.Word0.pack(slot, .reply, new_caps);
            }
        } else |_| {}
    }
    ec.pending_reply_holder = null;
    ec.pending_reply_domain = null;
    ec.pending_reply_slot = 0;
}

/// Re-launch `ec` at its `entry_point` with a fresh user stack —
// ── Internal API ─────────────────────────────────────────────────────

/// Allocate an EC bound to `domain`: slab slot, kernel stack, user
/// stack with guard pages, sets `entry_point` and `affinity`. All
/// fields receive their spec defaults; the gen-lock has already been
/// initialized by the slab allocator.
pub fn allocExecutionContext(
    domain: *CapabilityDomain,
    entry: VAddr,
    stack_pages: u32,
    affinity: u64,
    priority: Priority,
    vm: ?*VirtualMachine,
    exit_port: ?*Port,
) !*ExecutionContext {
    const pending = try slab_instance.create();
    const ec = pending.ptr;

    const kstack = try stack.createKernel();
    errdefer stack.destroyKernel(kstack);

    // Back the kernel stack VA range with physical pages mapped into
    // the *kernel* address space root (the kernel half is shared
    // across all domain PML4s via copyKernelMappings). Without this
    // step the iret epilogue's stack pop and any subsequent kernel
    // execution on this stack page-fault into the void.
    var page_addr: u64 = kstack.base.addr;
    while (page_addr < kstack.top.addr) {
        const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
        const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        try arch.paging.mapPage(
            memory_init.kernel_addr_space_root,
            phys,
            VAddr.fromInt(page_addr),
            .{ .read = true, .write = true },
            .kernel_data,
        );
        page_addr += paging_consts.PAGE4K;
    }

    const ustack: ?Stack = if (vm != null) null else blk: {
        // VM vCPUs run guest code; no host user stack needed.
        // Otherwise reserve `stack_pages` pages in `domain`'s address
        // space using the domain's bump pointer. The full per-domain
        // VMM is still pending; this minimal allocator advances
        // `next_var_base` page-by-page so each new EC gets a fresh
        // non-overlapping stack range. Map the pages as user data so
        // userspace ring-3 entry can fetch from RSP and (under SMEP)
        // the iret_frame's user-mode CS lets the CPU execute the
        // entry point at all.
        const stack_bytes: u64 = @as(u64, stack_pages) * paging_consts.PAGE4K;
        // Leave a one-page guard below and above the populated range.
        const guard_below: u64 = paging_consts.PAGE4K;
        const guard_above: u64 = paging_consts.PAGE4K;
        const total: u64 = guard_below + stack_bytes + guard_above;
        const region_base: u64 = std.mem.alignForward(u64, domain.next_var_base, paging_consts.PAGE4K);
        domain.next_var_base = region_base + total;

        const stack_base: u64 = region_base + guard_below;
        const stack_top: u64 = stack_base + stack_bytes;

        var off: u64 = 0;
        while (off < stack_bytes) {
            const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
            const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
            const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
            try arch.paging.mapPage(
                domain.addr_space_root,
                phys,
                VAddr.fromInt(stack_base + off),
                .{ .read = true, .write = true },
                .user_data,
            );
            off += paging_consts.PAGE4K;
        }

        break :blk Stack{
            .top = VAddr.fromInt(stack_top),
            .base = VAddr.fromInt(stack_base),
            .guard = VAddr.fromInt(region_base),
            .slot = std.math.maxInt(u64),
        };
    };

    // Build the first-dispatch iret frame at the top of the kernel
    // stack. The arch helper writes RIP=entry, RFLAGS=0x202 (IF set),
    // CS/SS=user-mode selectors, RSP=user stack top (or null when no
    // user stack — currently the case for v0 ECs that have not had
    // their domain VMM allocate a stack VMAR yet). When ustack is null
    // the resulting frame still iret's, but to user RSP=0 — fine for
    // first-dispatch debugging since the panic shows up sooner than
    // an infinite hang.
    const ustack_top: ?VAddr = if (ustack) |us| us.top else null;
    const ctx_ptr = arch.cpu.prepareEcContext(kstack.top, ustack_top, entry, 0);

    // Slab zeroes every byte except `_gen_lock` on free, so any
    // field whose initial value is the zero-bit pattern (null, 0,
    // false, .none, default-constructed bool atomic, etc.) is
    // already correct on entry. Only set fields that need a non-
    // zero starting value or carry caller-supplied data.
    ec.ctx = ctx_ptr;
    ec.kernel_stack = kstack;
    ec.user_stack = ustack;
    ec.domain = SlabRef(CapabilityDomain).init(domain, domain._gen_lock.currentGen());
    ec.diag_test_tag = domain.diag_test_tag;
    ec.diag_report_entered = false;
    ec.priority = priority;
    ec.affinity = affinity;
    lifecycle.initNewEc(ec, NOT_IN_RUN_QUEUE);
    ec.entry_point = entry;
    if (vm) |v| ec.vm = SlabRef(VirtualMachine).init(v, v._gen_lock.currentGen());
    if (exit_port) |p| ec.exit_port = SlabRef(Port).init(p, p._gen_lock.currentGen());

    arch.cpu.fpuStateInit(&ec.fpu_state);
    // Reset lazy-FPU bookkeeping — slab slot may have inherited the
    // previous occupant's `last_fpu_core` if any prior teardown
    // skipped `clearFromLastFpuOwner` (e.g. via a non-graceful exit
    // path). `migrateFlush` reads this field and IPIs the named
    // core; a stale non-null value would send a flush IPI for an EC
    // that never actually used the FPU on that core.
    ec.last_fpu_core = null;
    _ = slab_instance.publish(pending);
    return ec;
}

/// Walk the EC slab and destroy every alive EC whose `domain` SlabRef
/// matches `(cd, cd_gen)`, skipping any EC named in `keep`. Used by
/// `destroyPhase2` to reap vCPU ECs and sub-domain helper ECs that
/// have no other release path. The caller-running EC (the one that
/// invoked `delete(SLOT_SELF)`) must be passed in `keep` — its kernel
/// stack is in active use and cannot be unmapped here.
///
/// We match BOTH `domain.ptr` and `domain.gen` to avoid grabbing leaked
/// ECs whose owning CD slot has since been recycled into a different
/// (currently-alive) CD: a bare-ptr aliasing match would let the new
/// CD's destroy walk free unrelated leaked ECs from earlier tests, and
/// while their slab slots can in principle be reclaimed that way, the
/// kstack unmap uses `cd_addr_space_root` and is only valid for ECs
/// genuinely bound to *this* CD.
///
/// `cd_addr_space_root` is read from the CD by `destroyPhase1` while it
/// holds `cd._gen_lock`; phase 2 runs after the lock has been released
/// (the slab slot is already destroyed-marked) so there is no recursive-
/// acquire risk here.
pub fn destroyEcsInDomain(cd_ref: SlabRef(CapabilityDomain), cd_addr_space_root: PAddr, keep_ref: ?SlabRef(ExecutionContext)) void {
    // Visitor packs the loop-invariant args. The CD ref carries a
    // verified gen so the visitor can reject ECs whose `domain` ptr
    // happens to alias a stale (since-recycled) slot. The keep ref
    // names the caller-running EC; its slot is `parkSelfFaulted`'d
    // (state .exited) and will be reaped lazily, and we identify it by
    // pointer identity to skip it during the walk. Both refs use
    // `SlabRef` to satisfy the fat-pointer invariant, but the visitor
    // never `.lock()`s them (we already hold cd._gen_lock and the keep
    // EC is the very EC executing this path) — the `.ptr` accesses on
    // the chains below are bracketed by that outer lock and are
    // explicitly caller-pinned.
    const Visitor = struct {
        cd_ref: SlabRef(CapabilityDomain),
        cd_addr_space_root: PAddr,
        keep_ref: ?SlabRef(ExecutionContext),
    };
    var ctx = Visitor{
        .cd_ref = cd_ref,
        .cd_addr_space_root = cd_addr_space_root,
        .keep_ref = keep_ref,
    };
    slab_instance.forEachAlive(
        &ctx,
        struct {
            fn visit(c: *Visitor, ec: *ExecutionContext, gen: u63) bool {
                if (c.keep_ref) |kr| {
                    // caller-pinned: keep_ref names the EC running this code
                    // path; pointer identity check, no deref.
                    if (ec == kr.ptr) return true;
                }
                // caller-pinned: cd_ref names the CD whose _gen_lock the
                // outer caller holds; checking ec.domain alignment
                // against it is pointer arithmetic only, no deref.
                if (ec.domain.ptr != c.cd_ref.ptr) return true;
                if (ec.domain.gen != c.cd_ref.gen) return true;
                // caller-pinned: same outer-locked CD, passed through to
                // the per-EC destroy helper which only uses the bare
                // pointer for caller_cd identity comparison.
                dbump(&walk_visit_enter); // TEMP DIAGNOSTIC (stygia-afo, REMOVE)
                destroyExecutionContextRefLocked(SlabRef(ExecutionContext).init(ec, gen), c.cd_ref.ptr); // caller-pinned: identity-only key, never dereferenced
                dbump(&walk_visit_done); // TEMP DIAGNOSTIC (stygia-afo, REMOVE)
                return true;
            }
        }.visit,
    );
    // NOTE: victim ECs of this walk may still be EXECUTING on remote
    // cores when this returns — the per-EC destroy only posts a zombie
    // + wake IPI for on-cpu targets. Translation safety is the
    // caller's job: destroyPhase2 runs `scheduler.awaitNoActiveRoot`
    // on the dying root before freeing any table. (`on_cpu` is NOT a
    // usable eviction signal here: it stays stale-true across the
    // cross-core migration boundary for queued ECs and its gated
    // clears race the dispatch path — see PerCore.active_root.)
}

/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Count alive ECs still matching
/// `cd_ref` — i.e. survivors of a `destroyEcsInDomain` walk that RAN TO
/// COMPLETION. Non-zero here means the walk itself misses ECs; zero with
/// a climbing orphan census means the walk never ran (abandoned frame)
/// or the ECs were created after it.
pub fn countEcsInDomain(cd_ref: SlabRef(CapabilityDomain)) u64 {
    var ctx = struct { cd_ref: SlabRef(CapabilityDomain), n: u64 }{ .cd_ref = cd_ref, .n = 0 };
    slab_instance.forEachAlive(&ctx, struct {
        fn visit(c: *@TypeOf(ctx), ec: *ExecutionContext, _: u63) bool {
            // caller-pinned: identity-only comparison, no deref of the
            // dead-marked CD slot.
            if (ec.domain.ptr == c.cd_ref.ptr and ec.domain.gen == c.cd_ref.gen) c.n += 1;
            return true;
        }
    }.visit);
    return ctx.n;
}

/// Same as `destroyExecutionContext`, but tailored for the
/// `destroyPhase2` walk: avoids the same-class recursive acquire on
/// `ec.domain._gen_lock` (the CD slab slot is already destroyed-marked
/// by phase 1, so locking would fail), and deliberately skips kstack
/// reclaim (see comment near the slab destroy at the bottom of this
/// fn for the rationale).
///
/// `dom_root` is reserved for a future kstack-reclaim path; today the
/// kstack is left mapped because tearing it down inline races against
/// the dying EC's last cross-core dispatch.
///
/// Caller passes its own CD pointer in `caller_cd` — any pending-reply
/// holder ref pointing at that CD is cleared without re-locking it.
/// For pending replies pointing at OTHER domains (cross-domain reply
/// pin), we run the normal `abandonPendingReply` path.
/// `caller_cd` is the domain whose teardown is driving this destroy, or
/// `null` when no domain is being torn down. It exists solely for the same-CD pending-reply shortcut below,
/// so `null` correctly forces the `abandonPendingReply` branch: nothing
/// is freeing the holder's `user_table`, and silently dropping the
/// back-pointer there would leak the holder slot.
///
/// The former `dom_root: PAddr` parameter was removed — it was never
/// read (`_ = dom_root`), and computing it at the new call sites would
/// mean dereferencing `ec.domain.ptr` for a domain that may already be
/// dead, which is exactly the case those call sites exist to handle.
pub fn destroyExecutionContextLocked(ec: *ExecutionContext, caller_cd: ?*CapabilityDomain) void {
    const gen = ec._gen_lock.currentGen();
    if (gen % 2 == 0) return;
    destroyExecutionContextRefLocked(SlabRef(ExecutionContext).init(ec, @intCast(gen)), caller_cd);
}

/// Discharge a run-queue steal claim whose EC became unpublishable while the
/// thief had dropped core locks. Caller owns the stolen holder pin.
pub fn dischargeClaimedHolderDead(ec: *ExecutionContext) void {
    const gen = ec._gen_lock.currentGen();
    if (gen % 2 == 0) {
        lifecycle.releasePin(ec);
        return;
    }

    const ec_ref = SlabRef(ExecutionContext).init(ec, @intCast(gen));
    lifecycle.releasePin(ec);
    destroyExecutionContextRefLocked(ec_ref, null);
}

pub fn destroyExecutionContextRefLocked(ec_ref: SlabRef(ExecutionContext), caller_cd: ?*CapabilityDomain) void {
    const ec = ec_ref.ptr;

    // Route the slab destroy through the deferred-finalize path
    // (`bumpDeadGenLocked` + `postZombie` / `finalizeDestroyMarkedDead`)
    // rather than the synchronous `slab_instance.destroy`. The
    // synchronous variant goes through `destroyLockedInner` which
    // zeroes T's bytes — at smp=4 that races with cross-core readers
    // (port `popHighest*` callers, futex wake's on_cpu spinner,
    // timer-async expiry path) that hold a bare `*EC` snapshot from
    // before the gen-flip. Routing through the deferred path leaves
    // those readers' dereferences valid (slab fields stay intact
    // until the next allocator pop re-inits them), and the kstack
    // unmap that `finalizeDestroyMarkedDead` does only fires once the
    // EC's `last_dispatched_core` has done a `switchTo` — i.e. the
    // running core is provably off the kstack.
    const retired = retireAndBumpDeadGen(ec_ref, ec) orelse return;

    if (ec.pending_reply_holder != null) {
        if (ec.pending_reply_domain) |dom_ref| {
            if (caller_cd != null and dom_ref.ptr == caller_cd.?) {
                // Same-CD reply pin — the user_table has already been
                // disarmed by the time we get here (the holder slot
                // referenced this caller_cd's table). Just drop the
                // back-pointer; user_table is about to be freed.
                ec.pending_reply_holder = null;
                ec.pending_reply_domain = null;
                ec.pending_reply_slot = 0;
            } else {
                abandonPendingReply(ec);
            }
        } else {
            ec.pending_reply_holder = null;
            ec.pending_reply_slot = 0;
        }
    }

    // Unconditional queue/waiter cleanup — see the matching block in
    // `terminate` for the state-race rationale. Each cancel is a no-op
    // when the EC isn't actually in the targeted queue.
    scheduler.removeFromQueue(ec);
    if (ec.suspend_port) |port_ref| {
        const portlr = port_ref.lockIrqSave(@src()) catch null;
        if (portlr) |plr| {
            const p = plr.ptr;
            _ = p.waiters.remove(ec);
            if (p.waiters.isEmpty()) p.waiter_kind = .none;
            port_ref.unlockIrqRestore(plr.irq_state);
        }
    }
    stygia.sched.port.releasePendingPairEntries(ec);
    stygia.sched.futex.cancelWait(ec);
    if (ec.recv_deadline_ns != 0) stygia.sched.port.cancelRecvDeadline(ec);
    stygia.sched.fpu.clearFromLastFpuOwner(ec);

    // Spec §[port] lifetime: a vCPU's exit_port is pinned for the
    // vCPU's lifetime. Unlink from the port's vcpu_list_head and
    // decrement the port's bind_refcount; teardown is independent —
    // the slab dies only when `recv_refcount` hits zero, which can
    // only happen via a separate recv-side handle release.
    if (ec.exit_port) |port_ref| {
        const port_lr_or_err = port_ref.lockIrqSave(@src());
        if (port_lr_or_err) |plr| {
            const p = plr.ptr;
            // Splice this EC out of the port's vcpu list.
            var cursor = &p.vcpu_list_head;
            while (cursor.*) |node_ref| {
                const node = node_ref.ptr;
                if (node == ec) {
                    cursor.* = ec.vcpu_list_next;
                    break;
                }
                cursor = &node.vcpu_list_next;
            }
            ec.vcpu_list_next = null;
            stygia.sched.port.decBindRef(p);
            port_ref.unlockIrqRestore(plr.irq_state);
        } else |_| {}
        ec.exit_port = null;
    }

    // vCPU EC: free per-vCPU arch state (GuestState + FxsaveArea page).
    // No-op for regular ECs (vcpu_arch_state stays null).
    if (ec.vm != null and ec.vcpu_arch_state != null) {
        arch.vm.freeVcpuArchState(ec);
    }

    scheduler.removeFromQueue(ec);

    routeRetiredFinalize(ec, retired.gen, retired.from, retired.owner, null);
}
