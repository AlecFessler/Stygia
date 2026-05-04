//! Execution context — schedulable unit of executable state bound to a
//! capability domain. See docs/kernel/specv3.md §[execution_context].

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const errors = zag.syscall.errors;
const memory_init = zag.memory.init;
const paging_consts = zag.memory.paging;
const perfmon_mod = zag.sched.perfmon;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;
const stack = zag.memory.stack;

const ArchCpuContext = arch.cpu.ArchCpuContext;
const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const PAddr = zag.memory.address.PAddr;
const PerfmonState = zag.sched.perfmon.PerfmonState;
const Port = zag.sched.port.Port;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const Stack = zag.memory.stack.Stack;
const VAddr = zag.memory.address.VAddr;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;
const WaitNode = zag.sched.futex.WaitNode;

/// Upper bound on simultaneous futex wait addresses for a single EC.
/// Mirrors `futex.MAX_FUTEX_ADDRS` (the public spec ceiling) so each
/// EC's in-place wait-node / vaddr storage matches the kernel's
/// per-call cap.
pub const MAX_FUTEX_ADDRS_PER_EC: usize = 63;

/// Maximum handle attachments (pair entries) carried on a suspend.
/// Mirrors `syscall/port.zig::MAX_PAIR_COUNT`. Spec §[handle_attachments].
pub const MAX_PAIR_ENTRIES_PER_EC: usize = 63;

/// Sentinel for `ExecutionContext.last_dispatched_core` — never dispatched.
/// `0xFF` is unreachable as a real core id (`scheduler.MAX_CORES` is 64,
/// so valid ids occupy 0..63), giving a single byte that doubles as the
/// "no core to defer-finalize to" signal.
pub const LAST_DISPATCHED_NEVER: u8 = 0xFF;

/// Decoded pair entry stashed on the suspending EC at `validatePairEntries`
/// time and consumed at recv time in `port.deliverEvent`. Captures the
/// kernel-side `ErasedSlabRef` to the source object (lock-validated at
/// stash time so the gen baked here matches the live object), the type
/// tag to install on the receiver, the caps to install verbatim, the
/// move flag (drives the sender-side slot-clear at recv), and the
/// source slot id in the sender's domain (used to clear the sender slot
/// when `move == true`).
pub const PairEntryStashed = struct {
    obj_ref: ErasedSlabRef,
    obj_type: CapabilityType,
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
    bind: bool = false,
    rebind: bool = false,
    unbind: bool = false,
    _reserved: u3 = 0,
};

/// Scheduling priority. Mirrors handle field0.pri (2 bits, 0..3).
pub const Priority = enum(u2) {
    idle = 0,
    normal = 1,
    high = 2,
    realtime = 3,
};

/// Lifecycle state. An EC is in at most one queue at a time; the state
/// names which one (or none, when running or exited).
pub const State = enum {
    /// Currently executing on a CPU.
    running,
    /// Enqueued on a per-core run queue, waiting to be dispatched.
    ready,
    /// Either parked in a port wait queue OR dequeued by a recv and
    /// awaiting reply. The flavor of suspension is in `event_type`; the
    /// two arms are distinguished by `pending_reply_holder` being null vs set.
    suspended_on_port,
    /// Blocked on one or more futex addresses. Wait state lives in the
    /// `futex_*` fields below.
    futex_wait,
    /// EC trapped on a hardware wait-for-interrupt-like instruction
    /// (aarch64 wfi, x86 hlt). Off every queue; consumes no CPU. Stays
    /// alive until its owning capability domain is destroyed, or until
    /// a sibling EC explicitly suspends it onto a port (treated like
    /// `.ready` by `suspend`'s pre-suspend state gate). Saved register
    /// state in `ctx` reflects the post-wait-instruction frame so
    /// `suspendOnPort` can snapshot vregs / event_rip without needing
    /// to re-execute anything.
    idle_wait,
    /// Terminated. Awaiting slab destroy.
    exited,
};

/// Event type carried by a suspension. Matches spec §[event_type] values.
pub const EventType = enum(u5) {
    none = 0,
    memory_fault = 1,
    thread_fault = 2,
    breakpoint = 3,
    suspension = 4,
    vm_exit = 5,
    pmu_overflow = 6,
};

/// Number of registerable event types — the subset bindable through
/// `bind_event_route` (memory_fault, thread_fault, breakpoint,
/// pmu_overflow). `suspension` and `vm_exit` are not registered through
/// these syscalls and so do not occupy an `event_routes` slot.
pub const REGISTERABLE_EVENT_COUNT = 4;

/// Index into `event_routes` for a given EventType. Returns `null` for
/// the unregisterable types (`none`, `suspension`, `vm_exit`).
pub fn eventRouteSlot(et: EventType) ?u8 {
    return switch (et) {
        .memory_fault => 0,
        .thread_fault => 1,
        .breakpoint => 2,
        .pmu_overflow => 3,
        else => null,
    };
}

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

    /// Cross-core context-switch barrier. Set true while actively
    /// executing on a CPU; cleared after the outgoing context has been
    /// fully saved. Remote cores attempting to migrate or destroy this
    /// EC spin on this until the saving core releases it.
    on_cpu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Core id of the most recent dispatch — set by `setCurrentEc` and by
    /// the FP step-14 / R-14 swap. Sentinel `LAST_DISPATCHED_NEVER` (0xFF)
    /// means the EC has never been dispatched. Cross-core `terminate` reads
    /// this to decide where to post the deferred-finalize zombie: posting
    /// to the last-dispatched core guarantees that core's NEXT `switchTo`
    /// runs the reap, by which point its asm rsp swap has moved off the
    /// EC's kstack — closing the kstack-still-in-use window that
    /// `runningCoreOf(current_ec.ptr == ec)` would otherwise miss
    /// (current_ec is updated BEFORE the asm rsp swap commits, so a
    /// cross-core terminate sees a misleading "not running" state).
    /// Never reset back to the sentinel — once dispatched, the kstack-in-
    /// use risk is owned by the most recent core indefinitely.
    last_dispatched_core: u8 = LAST_DISPATCHED_NEVER,

    // ── Futex wait state — meaningful iff state == .futex_wait ────────

    /// Absolute monotonic-clock deadline (ns). Timer wheel uses this to
    /// fire a wake when it expires. `0` = no deadline.
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
    /// captured `ErasedSlabRef` (gen-validated at stash time), the
    /// type tag and caps to install verbatim on the receiver, the
    /// move flag (drives the sender-slot-clear at recv), and the
    /// source slot id in the sender's domain. Sized to
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
    /// explicit suspend, the EC handle used at `bind_event_route` for
    /// fault events, the vCPU EC handle for vm_exit). Read at reply time
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

    /// Kernel-held event route bindings, one slot per registerable event
    /// type. Index follows `EventType` ordering minus the unregisterable
    /// ones: 0=memory_fault, 1=thread_fault, 2=breakpoint, 3=pmu_overflow.
    /// `null` ⇒ no route; firing falls back to the type-specific
    /// no-route handling per §[event_route].
    event_routes: [REGISTERABLE_EVENT_COUNT]?SlabRef(Port) = .{ null, null, null, null },

    // ── Restart ───────────────────────────────────────────────────────

    /// Original entry point recorded at create time. Used by
    /// `restart_policy = restart_at_entry` to re-launch the EC.
    entry_point: VAddr,

    // ── vCPU (null on regular ECs) ────────────────────────────────────

    /// VM this EC is a vCPU of, or `null` for a regular EC. Set at
    /// `create_vcpu`; immutable. `acquire_ecs` filters vCPUs out of its
    /// returned set by checking this field.
    vm: ?SlabRef(VirtualMachine) = null,

    /// Port where vm_exit events are delivered for this vCPU. Set at
    /// `create_vcpu` together with `vm`; immutable. `null` on regular
    /// ECs.
    exit_port: ?SlabRef(Port) = null,

    /// Per-vCPU arch state cell allocated by `allocVcpuArchState`. On
    /// x86-64 this points at a `vcpu.VcpuArchState` (GuestState + 16-byte-
    /// aligned FxsaveArea + last VmExitInfo); on aarch64 the analogous
    /// per-vCPU register bank. `null` on regular ECs and on vCPU ECs
    /// before `create_vcpu` finishes wiring. Freed on EC destruction.
    vcpu_arch_state: ?*anyopaque = null,

    // ── PMU ───────────────────────────────────────────────────────────

    /// Lazy-allocated PMU counter state. Allocated on first
    /// `perfmon_start` against this EC; freed on `perfmon_stop` or
    /// implicit release at EC destroy.
    perfmon_state: ?SlabRef(PerfmonState) = null,

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
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
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
/// resuming. Used by no-route fault fallbacks (§[event_route]): when an
/// exception fires and the EC has no thread_fault route bound, the
/// kernel must keep the faulting EC from being re-dispatched. Otherwise
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
pub fn parkSelfFaulted(ec: *ExecutionContext) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    if (scheduler.coreCurrentIs(core_id, ec)) {
        scheduler.clearCurrentEc(core_id);
    }
    // `.exited` is the closest existing state for "will never run again";
    // no `markReady`/`enqueue*` path observes it, and the EC stays in
    // the slab so outstanding handles still resolve (just to a parked
    // EC) until the owning domain is destroyed.
    ec.state = .exited;
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
    if (scheduler.coreCurrentIs(core_id, ec)) {
        scheduler.clearCurrentEc(core_id);
    }
    const ec_ref = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen());
    if (ec_ref.lockIrqSave(@src())) |lr| {
        defer ec_ref.unlockIrqRestore(lr.irq_state);
        // A racing suspend / terminate may have flipped state out of
        // .running already. Only commit .idle_wait if we still see the
        // .running we trapped from; otherwise the other path now owns
        // the lifecycle and our park would corrupt their queueing.
        if (ec.state == .running) {
            ec.state = .idle_wait;
            ec.on_cpu.store(false, .release);
        }
    } else |_| {
        // Slab gen flipped — EC was destroyed mid-trap. Nothing to do;
        // the trampoline will ERET into a freed slot, but the next
        // scheduler dispatch picks a different EC and the freed slot
        // gets recycled lazily.
    }
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
    const expected_gen: u63 = @intCast(worker_ref.gen);

    // Prepare phase — runs WITHOUT the EC's gen lock held to avoid
    // EC→CD lock-order inversion (abandonPendingReply takes the
    // pending-reply holder's CD; CD→EC is the canonical order, so
    // holding EC across CD acquire would seed an AB-BA cycle in
    // lockdep). The fields touched here are stable for `.running`
    // ECs (queue/port linkage is empty while running) and for parked
    // ECs no other core is mutating them. Mirrors the pre-deferred-
    // destroy invariants of the old `destroyExecutionContext`.
    abandonPendingReply(ec);

    if (ec.state == .ready) {
        scheduler.removeFromQueue(ec);
    } else if (ec.state == .suspended_on_port) {
        if (ec.suspend_port) |port_ref| {
            const portlr = port_ref.lockIrqSave(@src()) catch null;
            if (portlr) |plr| {
                const p = plr.ptr;
                _ = p.waiters.remove(ec);
                if (p.waiters.isEmpty()) p.waiter_kind = .none;
                port_ref.unlockIrqRestore(plr.irq_state);
            }
        }
    }

    for (&ec.event_routes) |*slot_ptr| slot_ptr.* = null;

    if (ec.perfmon_state != null) releasePerfmonState(ec);

    if (ec.vm != null and ec.vcpu_arch_state != null) {
        arch.vm.freeVcpuArchState(ec);
    }

    ec.state = .exited;

    // Re-acquire the EC's gen-lock briefly to atomically rotate gen to
    // the freed parity. After this point any concurrent handle
    // resolution (`lockWithGen`) on this slot fails with stale-handle.
    // The data bytes remain intact for the running core to keep
    // dereferencing until the reap path zeros + freelists. If the
    // re-acquire fails, another path already raced us through the
    // bump — the destroy is in progress, return OK and let the
    // winner finish.
    const wlr2 = worker_ref.lockIrqSave(@src()) catch return errors.OK;
    slab_instance.bumpDeadGenLocked(ec, expected_gen);
    // bumpDeadGenLocked clears the lock bit as part of the gen flip,
    // so we cannot use unlockIrqRestore (it would assert held). Just
    // restore IRQs.
    arch.cpu.restoreInterrupts(wlr2.irq_state);

    // Defer the finalize to whichever core most recently dispatched the
    // EC. The kstack-in-use window outlives `current_ec.ptr == ec` (slow-
    // path `switchTo` writes `current_ec` BEFORE the asm rsp swap; FP
    // step 14 / R-14 swap `current_ec` BEFORE sysretq) — so a
    // `runningCoreOf(ec)` check that compares `current_ec.ptr` would miss
    // the window and incorrectly inline-free the kstack while the running
    // core is still executing on it. Posting to `last_dispatched_core`
    // closes the window: that core's NEXT `switchTo` runs the reap, and
    // by then its asm rsp swap has committed onto whatever EC came next.
    // The existing `cur_is_zombie` skip in `switchTo` defers the reap
    // one more cycle if the target is *still* `current_ec` on that core.
    if (ec.last_dispatched_core != LAST_DISPATCHED_NEVER) {
        const core = ec.last_dispatched_core;
        while (!scheduler.postZombie(core, ec)) std.atomic.spinLoopHint();
    } else {
        // Never dispatched — kstack pages are mapped but no core's rsp
        // has ever pointed at them. Safe to finalize inline.
        finalizeDestroyMarkedDead(ec);
    }
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
    if (ec.suspend_port) |port_ref| {
        if (port_ref.lockIrqSave(@src())) |plr| {
            const p = plr.ptr;
            _ = p.waiters.remove(ec);
            if (p.waiters.isEmpty()) p.waiter_kind = .none;
            port_ref.unlockIrqRestore(plr.irq_state);
        } else |_| {}
    }

    const dom_root = blk: {
        const dlr = ec.domain.lockIrqSave(@src()) catch break :blk null;
        const d = dlr.ptr;
        defer ec.domain.unlockIrqRestore(dlr.irq_state);
        break :blk d.addr_space_root;
    };

    if (ec.user_stack) |us| {
        _ = us;
    }
    if (dom_root) |root| stack.destroyKernel(ec.kernel_stack, root);

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

    const new_pri: Priority = @enumFromInt(@as(u2, @intCast(new_priority)));
    target_ec.priority = new_pri;
    target_ref.unlockIrqRestore(tlr.irq_state);

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
/// Re-enqueuing the target on a core that satisfies the new mask if it
/// is currently parked or running on an excluded core is not yet
/// implemented; the affinity field is updated unconditionally so the
/// next enqueue picks it up.
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

    target_ec.affinity = new_affinity;
    target_ref.unlockIrqRestore(tlr.irq_state);

    // Refresh the handle's field1 snapshot (affinity occupies bits
    // 0-63 of field1).
    cd.user_table[slot].field1 = new_affinity;

    cd_ref.unlockIrqRestore(cd_irq_state);
    return errors.OK;
}

/// `perfmon_info` syscall handler. Spec §[execution_context].perfmon_info.
///
/// The syscall-layer wrapper has already verified the caller's
/// self-handle carries `pmu` (test 01 E_PERM gate). Here we pull the
/// authoritative PMU capabilities from `arch.pmu.pmuGetInfo()` and
/// pack them per the spec ABI:
///   vreg 1 — caps_word: bits 0-7 num_counters, bit 8 overflow_support
///   vreg 2 — supported_events bitmask
pub fn perfmonInfo(caller: *ExecutionContext) i64 {
    const info = arch.pmu.pmuGetInfo();
    const caps_word: u64 =
        @as(u64, info.num_counters) |
        (@as(u64, @intFromBool(info.overflow_support)) << 8);
    arch.syscall.setSyscallVreg2(caller.ctx, info.supported_events);
    return @bitCast(caps_word);
}

/// `perfmon_start` syscall handler. Spec §[execution_context].perfmon_start.
///
/// The syscall-layer wrapper has already verified `pmu` cap, target
/// handle resolves to an EC, and `num_configs` is in `1..num_counters`.
/// This handler performs the per-config validation (event index in
/// `supported_events`, has_threshold only when overflow supported,
/// no reserved bits set) and the running-state gate (E_BUSY when
/// target is not the calling EC and not currently suspended), then
/// programs the hardware via `arch.pmu` primitives.
pub fn perfmonStart(caller: *ExecutionContext, target: u64, num_configs: u8, configs: []const u64) i64 {
    const result = perfmonStartInner(caller, target, num_configs, configs);
    // Spec §[capabilities] / §[perfmon_start] test 09: the holder's
    // field0/field1 snapshot is refreshed from authoritative kernel
    // state regardless of return code. Best-effort — if the handle no
    // longer resolves (e.g. domain torn down), the refresh is a no-op.
    refreshHandleSnapshot(caller, target);
    return result;
}

fn perfmonStartInner(caller: *ExecutionContext, target: u64, num_configs: u8, configs: []const u64) i64 {
    // Validate per-config words against supported_events / overflow /
    // reserved bits per spec tests 04/05/06. The userspace ABI packs
    // each config as (config_event, config_threshold), so the args
    // slice carries 2*num_configs words. Configs above the runtime
    // ceiling (currently the args-slice cap) cannot fully validate, so
    // accept a shorter slice but validate every entry that arrived.
    const info = arch.pmu.pmuGetInfo();
    const provided = @min(@as(usize, num_configs) * 2, configs.len);
    if (provided % 2 != 0) return errors.E_INVAL;
    const pair_count = provided / 2;

    var i: usize = 0;
    while (i < pair_count) {
        const cfg_word = configs[2 * i];
        if (cfg_word & PERFMON_CONFIG_RESERVED_MASK != 0) return errors.E_INVAL;
        const event_idx: u8 = @truncate(cfg_word & PERFMON_CONFIG_EVENT_MASK);
        const has_threshold = (cfg_word & PERFMON_CONFIG_HAS_THRESHOLD_BIT) != 0;
        if (event_idx >= 64) return errors.E_INVAL;
        const event_bit = @as(u64, 1) << @intCast(event_idx);
        if (info.supported_events & event_bit == 0) return errors.E_INVAL;
        if (has_threshold and !info.overflow_support) return errors.E_INVAL;
        i += 1;
    }

    // Resolve the target EC. The syscall wrapper has already validated
    // that the slot is a valid EC handle.
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
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    const target_ec = tlr.ptr;
    const target_irq_state = tlr.irq_state;
    cd_ref.unlockIrqRestore(cd_irq_state);

    // Spec test 07: target must be the calling EC OR currently suspended.
    if (target_ec != caller and target_ec.state != .suspended_on_port) {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_BUSY;
    }

    // Lazy-allocate per-EC PerfmonState and program hardware.
    const ps = ensurePerfmonState(target_ec) catch {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_NOMEM;
    };

    var decoded: [perfmon_mod.MAX_COUNTERS]zag.syscall.pmu.PmuCounterConfig = undefined;
    var active_mask: u8 = 0;
    var threshold_mask: u8 = 0;

    var k: usize = 0;
    while (k < pair_count) {
        const cfg_word = configs[2 * k];
        const threshold = configs[2 * k + 1];
        const event_idx: u8 = @truncate(cfg_word & PERFMON_CONFIG_EVENT_MASK);
        const has_threshold = (cfg_word & PERFMON_CONFIG_HAS_THRESHOLD_BIT) != 0;
        decoded[k] = .{
            .event = @enumFromInt(event_idx),
            .has_threshold = has_threshold,
            .overflow_threshold = threshold,
        };
        const slot_bit: u8 = @as(u8, 1) << @intCast(k);
        active_mask |= slot_bit;
        if (has_threshold) threshold_mask |= slot_bit;
        ps.counter_events[k] = event_idx;
        ps.counter_thresholds[k] = threshold;
        k += 1;
    }

    // Zero trailing slots so a smaller-N reprogramming doesn't leave
    // stale entries visible.
    while (k < perfmon_mod.MAX_COUNTERS) {
        ps.counter_events[k] = 0;
        ps.counter_thresholds[k] = 0;
        k += 1;
    }

    ps.active_counters = active_mask;
    ps.has_threshold = threshold_mask;

    // For the calling EC the hardware MSRs are programmed live via
    // `pmuStart`; for a suspended sibling we stamp the state without
    // touching MSRs (the next `pmuRestore` reprograms when scheduled).
    var program_err: bool = false;
    if (target_ec == caller) {
        arch.pmu.pmuStart(&ps.arch_state, decoded[0..pair_count]) catch {
            program_err = true;
        };
    } else {
        arch.pmu.pmuConfigureState(&ps.arch_state, decoded[0..pair_count]);
    }
    target_ref.unlockIrqRestore(target_irq_state);
    if (program_err) return errors.E_INVAL;
    return errors.OK;
}

/// `perfmon_read` syscall handler. Spec §[execution_context].perfmon_read.
pub fn perfmonRead(caller: *ExecutionContext, target: u64) i64 {
    const result = perfmonReadInner(caller, target);
    refreshHandleSnapshot(caller, target);
    return result;
}

fn perfmonReadInner(caller: *ExecutionContext, target: u64) i64 {
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
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    const target_ec = tlr.ptr;
    const target_irq_state = tlr.irq_state;
    cd_ref.unlockIrqRestore(cd_irq_state);

    // Spec test 03: perfmon was not started on the target EC.
    const ps_ref = target_ec.perfmon_state orelse {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_INVAL;
    };

    // Spec test 04: target must be the calling EC OR currently suspended.
    if (target_ec != caller and target_ec.state != .suspended_on_port) {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_BUSY;
    }

    const pslr = ps_ref.lockIrqSave(@src()) catch {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_INVAL;
    };
    const ps = pslr.ptr;
    const ps_irq_state = pslr.irq_state;

    // For the calling EC the hardware counters are running live; the
    // cached `ps.arch_state.values` was last refreshed by the most
    // recent context switch out and is stale by the duration of the
    // current quantum. Snapshot the live MSRs into the state, read,
    // and restore so the counters keep accumulating after the read.
    if (target_ec == caller) {
        arch.pmu.pmuSave(&ps.arch_state);
    }
    var sample: zag.syscall.pmu.PmuSample = .{ .counters = [_]u64{0} ** perfmon_mod.MAX_COUNTERS };
    arch.pmu.pmuRead(&ps.arch_state, &sample);
    if (target_ec == caller) {
        arch.pmu.pmuRestore(&ps.arch_state);
    }

    // Spec ABI: vregs [1..num_counters] = counter values, [num_counters + 1] = ts.
    // `num_counters` is the system-wide hardware count from
    // `perfmon_info`. Counters that aren't currently configured read as
    // zero (pmuRead fills `sample.counters[0..arch_state.num_counters]`
    // and zeroes the rest). The timestamp lands in vreg num_counters + 1.
    const info = arch.pmu.pmuGetInfo();
    const hw_count: u8 = info.num_counters;
    const ts: u64 = arch.time.currentMonotonicNs();
    var gprs: [13]u64 = .{0} ** 13;
    var i: u8 = 0;
    while (i < hw_count and i < 13) {
        gprs[i] = sample.counters[i];
        i += 1;
    }
    if (hw_count < 13) {
        gprs[hw_count] = ts;
    }
    arch.syscall.setEventStateGprs(caller.ctx, gprs);

    ps_ref.unlockIrqRestore(ps_irq_state);
    target_ref.unlockIrqRestore(target_irq_state);
    // Return value sets vreg 1 (rax). gprs[0] above wrote vreg 1 too,
    // but the syscall epilogue overwrites rax with this return —
    // both paths agree on `sample.counters[0]`.
    return @bitCast(sample.counters[0]);
}

/// `perfmon_stop` syscall handler. Spec §[execution_context].perfmon_stop.
pub fn perfmonStop(caller: *ExecutionContext, target: u64) i64 {
    const result = perfmonStopInner(caller, target);
    refreshHandleSnapshot(caller, target);
    return result;
}

fn perfmonStopInner(caller: *ExecutionContext, target: u64) i64 {
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
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    const target_ec = tlr.ptr;
    const target_irq_state = tlr.irq_state;
    cd_ref.unlockIrqRestore(cd_irq_state);

    // Spec test 03: perfmon was not started on the target EC.
    if (target_ec.perfmon_state == null) {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_INVAL;
    }

    // Spec test 04: target must be the calling EC OR currently suspended.
    if (target_ec != caller and target_ec.state != .suspended_on_port) {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_BUSY;
    }

    const ps_ref = target_ec.perfmon_state.?;
    const pslr = ps_ref.lockIrqSave(@src()) catch {
        target_ref.unlockIrqRestore(target_irq_state);
        return errors.E_INVAL;
    };
    const ps = pslr.ptr;
    const ps_irq_state = pslr.irq_state;
    if (target_ec == caller) {
        arch.pmu.pmuStop(&ps.arch_state);
    } else {
        arch.pmu.pmuClearState(&ps.arch_state);
    }
    ps.active_counters = 0;
    ps.has_threshold = 0;
    ps_ref.unlockIrqRestore(ps_irq_state);
    releasePerfmonState(target_ec);
    target_ref.unlockIrqRestore(target_irq_state);
    return errors.OK;
}

/// Refresh the holder slot's `field0`/`field1` snapshot from
/// authoritative kernel state. Used by perfmon_start/read/stop to
/// implement the §[capabilities] implicit-sync side effect: every
/// syscall that takes a handle whose state can drift refreshes the
/// holder's snapshot regardless of return code. Best-effort — silently
/// no-ops if the handle has been freed or the domain is torn down.
fn refreshHandleSnapshot(caller: *ExecutionContext, target: u64) void {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return;
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);
    const slot: u12 = @truncate(target);
    const entry = capability.resolveHandleOnDomain(cd, slot, .execution_context) orelse return;
    capability.refreshSnapshot(cd, slot, entry);
}

/// Bit 8 of a `config_event` word is `has_threshold`. Spec §[execution_context].perfmon_start.
const PERFMON_CONFIG_HAS_THRESHOLD_BIT: u64 = 1 << 8;

/// Bits 0..7 of a `config_event` word hold the event index. Spec §[execution_context].perfmon_start.
const PERFMON_CONFIG_EVENT_MASK: u64 = 0xFF;

/// Reserved bits in a `config_event` word; any set bit returns E_INVAL. Spec test 06.
const PERFMON_CONFIG_RESERVED_MASK: u64 = ~(PERFMON_CONFIG_EVENT_MASK | PERFMON_CONFIG_HAS_THRESHOLD_BIT);

/// Suspend `ec` on `port` with the given event metadata. Used by both
/// the explicit `suspend` syscall and event-route fault delivery.
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
    if (ec.vm != null and event != .vm_exit) {
        port._gen_lock.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }
    std.debug.assert(ec.state == .running or ec.state == .ready or ec.state == .idle_wait);

    if (ec.state == .ready) {
        scheduler.removeFromQueue(ec);
    }
    // `.idle_wait` ECs are off every queue (parkIdleWait removes from
    // current_ec and never enqueues), so no removal is needed here.

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
    // syscall (e.g. event-route fault paths that suspend a
    // not-currently-executing EC; ctx still references the most
    // recent saved frame).
    const sender_ctx = ec.iret_frame orelse ec.ctx;
    ec.event_state_gprs = arch.syscall.getEventStateGprs(sender_ctx);
    ec.event_rip = arch.syscall.getEventRip(sender_ctx);
    ec.suspend_port = SlabRef(Port).init(port, port._gen_lock.currentGen());
    ec.state = .suspended_on_port;
    ec.pending_reply_holder = null;
    ec.pending_reply_domain = null;
    ec.pending_reply_slot = 0;
    ec.originating_write_cap = originating_write_cap;
    ec.originating_read_cap = originating_read_cap;
    ec.on_cpu.store(false, .release);

    // Rendezvous with a waiting receiver if one is parked. Spec
    // §[recv]/§[suspend]: a send-side rendezvous must wake the
    // highest-priority receiver immediately rather than parking the
    // sender — otherwise a recv() that arrived first sleeps forever
    // because the matching suspend() only enqueues into the wait
    // queue without consulting `waiter_kind == .receivers`.
    //
    // `rendezvousWithReceiver` releases Port internally on the success
    // path so it can take the receiver's CD lock without inverting the
    // canonical CD → Port order. On `false` it leaves Port held.
    if (port.waiter_kind == .receivers) {
        if (zag.sched.port.rendezvousWithReceiver(ec, port, event, subcode, addr, irq_state)) {
            const core_id: u8 = @truncate(arch.smp.coreID());
            if (scheduler.coreCurrentIs(core_id, ec)) {
                scheduler.clearCurrentEc(core_id);
            }
            return 0;
        }
    }

    // No waiting receiver — park as a sender. WaiterKind tracks which
    // side owns the queue; transition .none → .senders here so a
    // subsequent recv() observing waiters knows what to dequeue.
    port.waiters.enqueue(ec);
    if (port.waiter_kind == .none) port.waiter_kind = .senders;

    // Drop currency on the local core if `ec` is the running EC; the
    // caller's syscall return path will dispatch the next EC.
    const core_id: u8 = @truncate(arch.smp.coreID());
    if (scheduler.coreCurrentIs(core_id, ec)) {
        scheduler.clearCurrentEc(core_id);
    }
    port._gen_lock.unlockIrqRestore(irq_state);
    return 0;
}

/// Resume `ec` from a reply. When `apply_writes` is true, the receiver
/// committed GPR modifications via the reply payload — they have
/// already been written into `ec.iret_frame` by the caller. Otherwise
/// `ec` resumes from its saved `ctx` unchanged.
pub fn resumeFromReply(ec: *ExecutionContext, apply_writes: bool) void {
    _ = apply_writes;
    std.debug.assert(ec.state == .suspended_on_port);
    ec.event_type = .none;
    ec.event_subcode = 0;
    ec.event_addr = 0;
    ec.suspend_port = null;
    ec.pending_reply_holder = null;
    ec.pending_reply_domain = null;
    ec.pending_reply_slot = 0;
    ec.originating_write_cap = false;
    ec.pending_pair_count = 0;
    ec.originating_read_cap = false;
    ec.state = .ready;
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
            const tag = zag.caps.capability.Word0.typeTag(word0);
            if (tag == .reply) {
                const caps_u16 = zag.caps.capability.Word0.caps(word0);
                var rc: zag.sched.port.ReplyCaps = @bitCast(caps_u16);
                rc.abandoned = true;
                const new_caps: u16 = @bitCast(rc);
                dom.user_table[slot].word0 = zag.caps.capability.Word0.pack(slot, .reply, new_caps);
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
    const ref = try slab_instance.create();
    const ec = ref.ptr;

    const kstack = try stack.createKernel();
    errdefer stack.destroyKernel(kstack, domain.addr_space_root);

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

    // Field-by-field init rather than `ec.* = .{ ... }` so the slab's
    // already-set `_gen_lock` (live, gen=odd, lock=clear) is not
    // overwritten by an uninitialized GenLock default.
    ec.ctx = ctx_ptr;
    ec.iret_frame = null;
    ec.kernel_stack = kstack;
    ec.user_stack = ustack;
    ec.domain = SlabRef(CapabilityDomain).init(domain, domain._gen_lock.currentGen());
    ec.next = null;
    ec.prev = null;
    ec.priority = priority;
    ec.affinity = affinity;
    ec.state = .ready;
    ec.on_cpu = std.atomic.Value(bool).init(false);
    ec.last_dispatched_core = LAST_DISPATCHED_NEVER;
    ec.futex_deadline_ns = 0;
    ec.futex_wake_index = 0;
    ec.futex_wait_nodes = null;
    ec.futex_bucket_count = 0;
    ec.event_type = .none;
    ec.event_subcode = 0;
    ec.event_addr = 0;
    ec.suspend_port = null;
    ec.pending_reply_holder = null;
    ec.pending_reply_domain = null;
    ec.pending_reply_slot = 0;
    ec.originating_write_cap = false;
    ec.pending_pair_count = 0;
    ec.originating_read_cap = false;
    ec.event_routes = .{ null, null, null, null };
    ec.entry_point = entry;
    ec.vm = if (vm) |v| SlabRef(VirtualMachine).init(v, v._gen_lock.currentGen()) else null;
    ec.exit_port = if (exit_port) |p| SlabRef(Port).init(p, p._gen_lock.currentGen()) else null;
    ec.perfmon_state = null;
    ec.last_fpu_core = null;
    // Slab does NOT zero on alloc — every field a live EC reads must
    // be initialized here, else the new occupant inherits stale bytes
    // from the previous owner of this slot.
    ec.recv_port_xfer = false;
    ec.recv_deadline_ns = 0;
    ec.pending_event_word = 0;
    ec.pending_event_word_valid = false;
    ec.pending_event_rip = 0;
    ec.pending_event_rip_valid = false;
    ec.vcpu_arch_state = null;
    ec.event_state_gprs = [_]u64{0} ** 13;
    ec.event_rip = 0;
    ec.futex_wait_vaddrs = null;

    arch.cpu.fpuStateInit(&ec.fpu_state);
    return ec;
}

/// Walk the EC slab and destroy every alive EC whose `domain` SlabRef
/// matches `(cd, cd_gen)`, skipping any EC named in `keep`. Used by
/// `destroyCapabilityDomain` to reap vCPU ECs and sub-domain helper ECs
/// that have no other release path. The caller-running EC (the one that
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
/// `cd_addr_space_root` is read from the CD by the caller while it
/// holds `cd._gen_lock`. We MUST NOT re-lock `cd._gen_lock` here:
/// the caller (`destroyCapabilityDomain` invoked from `releaseSelf`)
/// already holds it, and SecureSlab gen-locks don't allow recursive
/// acquire on the same class.
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
            fn visit(c: *Visitor, ec: *ExecutionContext, _: u63) bool {
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
                destroyExecutionContextLocked(ec, c.cd_addr_space_root, c.cd_ref.ptr);
                return true;
            }
        }.visit,
    );
}

/// Same as `destroyExecutionContext`, but tailored for the
/// `destroyCapabilityDomain` walk: avoids the same-class recursive
/// acquire on `ec.domain._gen_lock` (the caller already holds that lock
/// and SecureSlab disallows recursive acquire on the same class), and
/// deliberately skips kstack reclaim (see comment near the slab destroy
/// at the bottom of this fn for the rationale).
///
/// `dom_root` is reserved for a future kstack-reclaim path; today the
/// kstack is left mapped because tearing it down inline races against
/// the dying EC's last cross-core dispatch.
///
/// Caller passes its own CD pointer in `caller_cd` — any pending-reply
/// holder ref pointing at that CD is cleared without re-locking it.
/// For pending replies pointing at OTHER domains (cross-domain reply
/// pin), we run the normal `abandonPendingReply` path.
pub fn destroyExecutionContextLocked(ec: *ExecutionContext, dom_root: PAddr, caller_cd: *CapabilityDomain) void {
    _ = dom_root;

    if (ec.pending_reply_holder != null) {
        if (ec.pending_reply_domain) |dom_ref| {
            if (dom_ref.ptr == caller_cd) {
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

    if (ec.state == .ready) {
        scheduler.removeFromQueue(ec);
    } else if (ec.state == .suspended_on_port) {
        if (ec.suspend_port) |port_ref| {
            const portlr = port_ref.lockIrqSave(@src()) catch null;
            if (portlr) |plr| {
                const p = plr.ptr;
                _ = p.waiters.remove(ec);
                if (p.waiters.isEmpty()) p.waiter_kind = .none;
                port_ref.unlockIrqRestore(plr.irq_state);
            }
        }
    }

    for (&ec.event_routes) |*slot| slot.* = null;

    if (ec.perfmon_state != null) releasePerfmonState(ec);

    // vCPU EC: free per-vCPU arch state (GuestState + FxsaveArea page).
    // No-op for regular ECs (vcpu_arch_state stays null).
    if (ec.vm != null and ec.vcpu_arch_state != null) {
        arch.vm.freeVcpuArchState(ec);
    }

    // Step-10 leak-budget tradeoff: kstack pages stay mapped (and the
    // backing PMM pages stay live) for the full kernel run. A future
    // patch can move kstack reclaim into a deferred per-core "to-free"
    // queue drained by the scheduler from a stack the EC does not own;
    // doing it inline here is racy with the EC's last cross-core
    // dispatch and was observed to corrupt the buddy allocator (its
    // last frame might still be in some other core's TLB / IRQ stack).
    // The slab slot freed below is the dominant pressure: it's what
    // gates a 256-test cumulative run, not the per-EC 48 KiB of stack.
    ec.state = .exited;
    const gen = ec._gen_lock.currentGen();
    slab_instance.destroy(ec, gen) catch {};
}

/// Final teardown — remove from any queue, clear event_routes, mark
/// outstanding reply as abandoned, release perfmon state, free stacks,
/// release slab.
pub fn destroyExecutionContext(ec: *ExecutionContext) void {
    abandonPendingReply(ec);

    if (ec.state == .ready) {
        scheduler.removeFromQueue(ec);
    } else if (ec.state == .suspended_on_port) {
        if (ec.suspend_port) |port_ref| {
            const portlr = port_ref.lockIrqSave(@src()) catch null;
            if (portlr) |plr| {
                const p = plr.ptr;
                _ = p.waiters.remove(ec);
                if (p.waiters.isEmpty()) p.waiter_kind = .none;
                port_ref.unlockIrqRestore(plr.irq_state);
            }
        }
    }

    for (&ec.event_routes) |*slot| slot.* = null;

    if (ec.perfmon_state != null) releasePerfmonState(ec);

    if (ec.vm != null and ec.vcpu_arch_state != null) {
        arch.vm.freeVcpuArchState(ec);
    }

    const dom_root = blk: {
        const dlr = ec.domain.lockIrqSave(@src()) catch break :blk null;
        const d = dlr.ptr;
        defer ec.domain.unlockIrqRestore(dlr.irq_state);
        break :blk d.addr_space_root;
    };

    if (ec.user_stack) |us| {
        // Free the user stack reservation back to the domain VMM.
        // Real impl: stack.destroyUser(us, &domain.vmm). Awaits the
        // per-domain VMM accessor.
        _ = us;
    }
    if (dom_root) |root| stack.destroyKernel(ec.kernel_stack, root);

    ec.state = .exited;
    const gen = ec._gen_lock.currentGen();
    slab_instance.destroy(ec, gen) catch {};
}

/// Lazy-allocate `perfmon_state` on first perfmon_start.
fn ensurePerfmonState(ec: *ExecutionContext) !*PerfmonState {
    if (ec.perfmon_state) |ref| {
        const reflr = ref.lockIrqSave(@src()) catch unreachable;
        ref.unlockIrqRestore(reflr.irq_state);
        return reflr.ptr;
    }
    const ref = try perfmon_mod.slab_instance.create();
    ec.perfmon_state = ref;
    return ref.ptr;
}

/// Free `perfmon_state` on perfmon_stop or implicit on EC destroy.
fn releasePerfmonState(ec: *ExecutionContext) void {
    const ref = ec.perfmon_state orelse return;
    ec.perfmon_state = null;
    perfmon_mod.slab_instance.destroy(ref.ptr, ref.gen) catch {};
}

