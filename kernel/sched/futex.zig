//! Futex — physical-address-keyed user-space synchronization primitive.
//! Spec §[futex].
//!
//! The kernel hashes the watched physical address into one of
//! `BUCKET_COUNT` buckets, each holding a priority-ordered intrusive
//! queue of `WaitNode`s. A multi-address wait allocates one `WaitNode`
//! per watched address on the EC's own kernel stack, so the EC
//! simultaneously occupies N independent bucket chains without aliasing
//! a shared link — the per-bucket queues cannot cross-pollute the way
//! they would if every bucket reached for the same EC link slot.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const arch_syscall = zag.arch.dispatch.syscall;
const errors = zag.syscall.errors;
const sched = zag.sched.scheduler;
const spin_diag = zag.utils.sync.spin_diag;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PAddr = zag.memory.address.PAddr;
const Priority = zag.sched.execution_context.Priority;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;

const BUCKET_COUNT = 256;
const MAX_TIMED_WAITERS = 64;
pub const MAX_FUTEX_ADDRS = 63;

// Internal sentinel stored in `EC.futex_deadline_ns` by the timer
// pass to mark "this EC was woken by deadline expiry, not by a peer
// `futex_wake`". `0` is reserved for "no wait active"; any real
// deadline is the wall clock at the time the wait was entered, so
// UINT64_MAX is far enough in the future to be unambiguous.
const FUTEX_TIMEOUT_SENTINEL: u64 = ~@as(u64, 0);

/// Per-(EC, bucket) wait entry. Allocated on the waiting EC's kernel
/// stack — one per address in a multi-address wait — and threaded into
/// bucket queues via its own `next` field. Each node carries its own
/// link slot so multi-address waits cannot cross-pollute the chains.
pub const WaitNode = struct {
    ec: SlabRef(ExecutionContext),
    paddr: PAddr,
    next: ?*WaitNode = null,
    priority: Priority,
};

const WaitNodePriorityQueue = zag.sched.priority_queue.PriorityQueue(
    WaitNode,
    "next",
    "priority",
    @typeInfo(Priority).@"enum".fields.len,
);

/// `Bucket.lock` ordered_group. Multi-bucket waits and the wake-side
/// cross-bucket cleanup both hold two `Bucket.lock` instances at once;
/// `sortByBucket` (waits) and the `except_idx` skip in
/// `removeNodesExcept` (wake) keep acquisition AB-BA-free.
const FUTEX_BUCKET_GROUP: u32 = 1;

const Bucket = struct {
    lock: SpinLock = .{ .class = "Bucket.lock" },
    pq: WaitNodePriorityQueue = .{},
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

var timed_lock: SpinLock = .{ .class = "futex.timed_lock" };
var timed_waiters: [MAX_TIMED_WAITERS]?*ExecutionContext = [_]?*ExecutionContext{null} ** MAX_TIMED_WAITERS;

/// Per-core BSS scratch for `expireTimedWaiters` Phase 1 → Phase 2
/// hand-off. At 64 × 16 = 1 KiB the snapshot used to live on the IRQ
/// timer-tick stack frame, sitting on top of whatever kernel/user stack
/// the tick interrupted. Combined with the recv-waiter snapshot
/// (`port.expire_recv_scratch`, 4 KiB) and the rest of the scheduler
/// chain, IRQ-context stack usage was clobbering adjacent frames'
/// saved-RIP slots (cf. d1948fbd lockdep visited[] fix). One scratch
/// per core is safe: `schedTimerHandler` runs to completion in IRQ
/// context with IRQs masked, never recurses, and each core has its
/// own timer.
const Snapshot = struct { ec: SlabRef(ExecutionContext), deadline: u64 };
var expire_timed_scratch: [sched.MAX_CORES][MAX_TIMED_WAITERS]Snapshot = undefined;

/// `timed_lock` ordered_group. The wait paths take a bucket.lock first
/// then call `addTimedWaiter` (which acquires `timed_lock`); the timer
/// IRQ path takes `timed_lock` then per-EC bucket.locks. Tagging the
/// timed_lock acquisition with a non-zero ordered_group opts out of
/// pair-edge cycle detection on the (bucket.lock, timed_lock) pair so
/// the two acquisition orders don't seed a phantom AB-BA cycle. Caller
/// discipline: timed_lock is always released before any bucket.lock is
/// re-acquired (phase split in `expireTimedWaiters`; release-then-undo
/// in `addTimedWaiter` failure path).
const FUTEX_TIMED_GROUP: u32 = 2;

fn bucketIdx(paddr: PAddr) usize {
    return @intCast((paddr.addr >> 3) % BUCKET_COUNT);
}

fn addTimedWaiter(ec: *ExecutionContext) bool {
    const irq = timed_lock.lockIrqSaveOrdered(@src(), FUTEX_TIMED_GROUP);
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = ec;
            return true;
        }
    }
    return false;
}

fn removeTimedWaiter(ec: *ExecutionContext) void {
    const irq = timed_lock.lockIrqSaveOrdered(@src(), FUTEX_TIMED_GROUP);
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == ec) {
            slot.* = null;
            return;
        }
    }
}

/// Cancel any futex wait `ec` is currently parked in: remove every
/// WaitNode owned by `ec` from its bucket queue(s) and drop the
/// timed_waiters slot if registered. Called from `terminate` /
/// `destroyExecutionContextLocked` when the dying EC is in
/// `.futex_wait` — the WaitNodes live on `ec`'s kernel stack, and
/// freeing the kstack later (via `stack.destroyKernel`) leaves the
/// bucket queues holding pointers into unmapped pages, faulting the
/// next `wake()` that walks the bucket.
///
/// Safe to call after `ec.state` is no longer `.futex_wait` — the loop
/// is bounded by `futex_bucket_count` and the per-bucket `pq.remove`
/// is idempotent on absent nodes.
pub fn cancelWait(ec: *ExecutionContext) void {
    const nodes = ec.futex_wait_nodes orelse return;
    const count: usize = ec.futex_bucket_count;
    var i: usize = 0;
    while (i < count) {
        const node = &nodes[i];
        const bucket = &buckets[bucketIdx(node.paddr)];
        const birq = bucket.lock.lockIrqSave(@src());
        _ = bucket.pq.remove(node);
        bucket.lock.unlockIrqRestore(birq);
        i += 1;
    }
    if (ec.futex_deadline_ns != 0) removeTimedWaiter(ec);
    ec.futex_bucket_count = 0;
    ec.futex_wait_nodes = null;
    ec.futex_wait_vaddrs = null;
    ec.futex_deadline_ns = 0;
}

/// Remove every node owned by `ec` from its bucket(s), without
/// touching the bucket whose lock the caller already holds (identified
/// by `held_idx`; pass an out-of-range value if none is held). Same-
/// bucket nodes other than `except_node` are removed under the held
/// lock without re-acquisition.
fn removeNodesExcept(ec: *ExecutionContext, except_node: *const WaitNode, held_idx: usize) void {
    const nodes = ec.futex_wait_nodes orelse return;
    const count: usize = ec.futex_bucket_count;
    var i: usize = 0;
    while (i < count) {
        const node = &nodes[i];
        if (node == except_node) {
            i += 1;
            continue;
        }
        const idx = bucketIdx(node.paddr);
        const bucket = &buckets[idx];
        if (idx == held_idx) {
            _ = bucket.pq.remove(node);
        } else {
            // Caller (wake) already holds buckets[held_idx].lock; this
            // is a second `Bucket.lock` acquisition in the same class.
            // The `idx == held_idx` skip above plus the strict
            // bucket-index ordering used by `acquireBucketLocks` keeps
            // the global acquisition graph AB-BA-free, so opt out of
            // the same-class overlap panic via FUTEX_BUCKET_GROUP.
            const birq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);
            _ = bucket.pq.remove(node);
            bucket.lock.unlockIrqRestore(birq);
        }
        i += 1;
    }
}

/// Pick the destination core for a wakeup, honoring `ec.affinity`.
/// `affinity == 0` is the spec-defined "any core" sentinel; we fall
/// back to the local core in that case to keep cache locality.
fn pickCoreForEc(ec: *ExecutionContext) u64 {
    if (ec.affinity == 0) return arch.smp.coreID();
    return @ctz(ec.affinity);
}

/// `futex_wake` — wake up to `count` ECs blocked on `paddr`.
/// Spec §[futex].futex_wake. Wake order is priority-ordered (highest
/// first; FIFO within a priority).
pub fn wake(paddr: PAddr, count: u32) u64 {
    const wake_idx = bucketIdx(paddr);
    const bucket = &buckets[wake_idx];
    var woken: u32 = 0;

    const irq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);

    // Multiple paddrs may hash to the same bucket, so a dequeued node
    // may not match the wake's paddr. Non-matching nodes are collected
    // and re-enqueued after the loop.
    var requeue: WaitNodePriorityQueue = .{};

    while (woken < count) {
        const node = bucket.pq.dequeue() orelse break;

        if (node.paddr.addr != paddr.addr) {
            requeue.enqueue(node);
            continue;
        }

        // caller-pinned: the node lives on the waiting EC's kernel stack
        // — the EC cannot have been freed while this node is still in
        // our bucket. The gen-locked SlabRef is for tooling uniformity
        // and the implicit liveness assertion.
        const ec_lr = node.ec.lockIrqSave(@src()) catch continue;
        const ec = ec_lr.ptr;
        node.ec.unlockIrqRestore(ec_lr.irq_state);

        // wake_index is the offset of this node in the EC's
        // wait_nodes array — the index of the address in the original
        // multi-address wait that matched.
        const nodes = ec.futex_wait_nodes.?;
        const node_idx: usize = (@intFromPtr(node) - @intFromPtr(nodes)) / @sizeOf(WaitNode);
        ec.futex_wake_index = @intCast(node_idx);

        // Drop this EC's other nodes from every bucket they live in
        // (skipping the just-dequeued node and using the held lock
        // for any same-bucket sibling).
        removeNodesExcept(ec, node, wake_idx);

        var on_cpu_spin: u64 = 0;
        while (ec.on_cpu.load(.acquire)) {
            std.atomic.spinLoopHint();
            spin_diag.tick(&on_cpu_spin, @src(), "on_cpu-futex-wake");
        }
        if (ec.futex_deadline_ns != 0) {
            ec.futex_deadline_ns = 0;
            removeTimedWaiter(ec);
        }
        // Spec §[futex_wait_val] / §[futex_wait_change]: on a wake the
        // syscall returns with vreg 1 set to the user vaddr that was
        // woken. The waiting EC is parked in user-mode space (its
        // syscall handler frame already returned a placeholder); the
        // resume path iretq's via `ec.ctx`, so write the real return
        // value into ctx.regs.rax (vreg 1) before marking it ready.
        if (ec.futex_wait_vaddrs) |vaddrs_ptr| {
            arch_syscall.setSyscallReturn(ec.ctx, vaddrs_ptr[node_idx]);
        }
        ec.futex_bucket_count = 0;
        ec.futex_wait_nodes = null;
        ec.futex_wait_vaddrs = null;
        ec.state = .ready;
        sched.enqueueOnCore(@intCast(pickCoreForEc(ec)), ec);
        woken += 1;
    }

    while (requeue.dequeue()) |n| bucket.pq.enqueue(n);

    bucket.lock.unlockIrqRestore(irq);
    return woken;
}

/// `futex_wait_val` — block while every `(addrs[i], expected[i])`
/// satisfies `*addr == expected`. Spec §[futex].futex_wait_val.
///
/// `vaddrs[i]` is the caller-domain virtual address corresponding to
/// `addrs[i]`. The success path returns the user vaddr that satisfied
/// the wait per spec §[futex_wait_val] vreg-1 contract; this avoids any
/// collision between an index (0..n-1) and a positive spec error code
/// (1..15) that the syscall layer would otherwise have to disambiguate.
///
/// Returns:
///   vaddrs[i]  = caller-domain vaddr of the first mismatched address
///                (immediate, no block) or the woken address (after
///                blocking).
///   E_TIMEOUT  if timeout expired, E_NOMEM if no timed waiter slot.
pub fn waitVal(addrs: []const PAddr, vaddrs: []const u64, expected: []const u64, count: usize, timeout_ns: u64, ec: *ExecutionContext) i64 {
    var sorted: [MAX_FUTEX_ADDRS]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

    for (0..count) |i| {
        const vaddr = VAddr.fromPAddr(addrs[i], null);
        const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);
        if (@atomicLoad(u64, value_ptr, .acquire) != expected[i]) {
            releaseBucketLocks(&lock_state);
            return @bitCast(vaddrs[i]);
        }
    }

    if (timeout_ns == 0) {
        releaseBucketLocks(&lock_state);
        return errors.E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        ec.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        ec.futex_deadline_ns = 0;
    }

    // Store WaitNodes and vaddrs in EC-resident storage rather than on
    // the caller's kernel stack: `waitVal` returns a placeholder to
    // `syscallDispatch` before the EC actually parks, so the stack
    // frame is reclaimed before wake/expiry runs. The bucket and
    // wake path both keep `&nodes[i]` / `vaddrs_ptr` references that
    // must remain valid until the wake completes.
    const nodes = &ec.futex_wait_nodes_storage;
    const vaddrs_storage = &ec.futex_wait_vaddrs_storage;
    const ec_ref = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .ec = ec_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = ec.priority,
        };
        vaddrs_storage[i] = vaddrs[i];
    }
    ec.futex_wait_nodes = nodes;
    ec.futex_wait_vaddrs = vaddrs_storage;
    ec.futex_bucket_count = @intCast(count);
    ec.state = .futex_wait;

    for (0..count) |i| {
        const idx = bucketIdx(addrs[i]);
        (&buckets[idx]).pq.enqueue(&nodes[i]);
    }

    if (ec.futex_deadline_ns != 0) {
        if (!addTimedWaiter(ec)) {
            for (0..count) |i| {
                _ = (&buckets[bucketIdx(addrs[i])]).pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            ec.state = .running;
            ec.futex_wait_nodes = null;
            ec.futex_wait_vaddrs = null;
            ec.futex_bucket_count = 0;
            ec.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    releaseBucketLocks(&lock_state);

    // Park the EC: drop currency on the local core. The syscall
    // dispatcher (`arch.x64.interrupts.syscallDispatch`) sees
    // `current_ec == null` and routes to `scheduler.run()` instead of
    // iretq'ing back to the now-parked user EC. The wake/timeout path
    // overwrites this EC's syscall-return slot with the real return
    // value (vaddr or E_TIMEOUT) before re-marking it ready, so the
    // placeholder returned here only needs to be a value the parked
    // EC will never observe.
    ec.on_cpu.store(false, .release);
    const core_id: u8 = @truncate(arch.smp.coreID());
    if (sched.coreCurrentIs(core_id, ec)) {
        sched.clearCurrentEc(core_id);
    }
    return 0;
}

/// `futex_wait_change` — block while every `(addrs[i], targets[i])`
/// satisfies `*addr != target`. Spec §[futex].futex_wait_change.
///
/// `vaddrs[i]` parallels `addrs[i]` and is the caller-domain user vaddr;
/// the success path returns one of these per spec §[futex_wait_change].
///
/// Returns:
///   vaddrs[i]  = caller-domain vaddr of the first matched address
///                (immediate, no block) or the woken address (after
///                blocking).
///   E_TIMEOUT  if timeout expired, E_NOMEM if no timed waiter slot.
pub fn waitChange(addrs: []const PAddr, vaddrs: []const u64, targets: []const u64, count: usize, timeout_ns: u64, ec: *ExecutionContext) i64 {
    var sorted: [MAX_FUTEX_ADDRS]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

    for (0..count) |i| {
        const vaddr = VAddr.fromPAddr(addrs[i], null);
        const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);
        if (@atomicLoad(u64, value_ptr, .acquire) == targets[i]) {
            releaseBucketLocks(&lock_state);
            return @bitCast(vaddrs[i]);
        }
    }

    if (timeout_ns == 0) {
        releaseBucketLocks(&lock_state);
        return errors.E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        ec.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        ec.futex_deadline_ns = 0;
    }

    // Same EC-resident storage discipline as `waitVal`.
    const nodes = &ec.futex_wait_nodes_storage;
    const vaddrs_storage = &ec.futex_wait_vaddrs_storage;
    const ec_ref = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .ec = ec_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = ec.priority,
        };
        vaddrs_storage[i] = vaddrs[i];
    }
    ec.futex_wait_nodes = nodes;
    ec.futex_wait_vaddrs = vaddrs_storage;
    ec.futex_bucket_count = @intCast(count);
    ec.state = .futex_wait;

    for (0..count) |i| {
        (&buckets[bucketIdx(addrs[i])]).pq.enqueue(&nodes[i]);
    }

    if (ec.futex_deadline_ns != 0) {
        if (!addTimedWaiter(ec)) {
            for (0..count) |i| {
                _ = (&buckets[bucketIdx(addrs[i])]).pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            ec.state = .running;
            ec.futex_wait_nodes = null;
            ec.futex_wait_vaddrs = null;
            ec.futex_bucket_count = 0;
            ec.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    releaseBucketLocks(&lock_state);

    // Park the EC: see `waitVal` for the full rationale.
    ec.on_cpu.store(false, .release);
    const core_id: u8 = @truncate(arch.smp.coreID());
    if (sched.coreCurrentIs(core_id, ec)) {
        sched.clearCurrentEc(core_id);
    }
    return 0;
}

/// Holds lock state for multi-bucket acquisition.
const BucketLockState = struct {
    /// Unique bucket indices in sorted order.
    unique_indices: [MAX_FUTEX_ADDRS]usize = undefined,
    /// Saved IRQ state per unique bucket.
    irq_states: [MAX_FUTEX_ADDRS]u64 = undefined,
    /// Number of unique buckets locked.
    count: usize = 0,
};

/// Sort indices by bucket index for consistent lock acquisition order.
fn sortByBucket(indices: []u8, addrs: []const PAddr) void {
    var i: usize = 1;
    while (i < indices.len) {
        var j = i;
        while (j > 0 and bucketIdx(addrs[indices[j]]) < bucketIdx(addrs[indices[j - 1]])) {
            const tmp = indices[j];
            indices[j] = indices[j - 1];
            indices[j - 1] = tmp;
            j -= 1;
        }
        i += 1;
    }
}

/// Acquire bucket locks in sorted order, skipping duplicates.
///
/// Pointer-index `buckets[]` to avoid Debug-mode codegen copying the
/// entire bucket array onto the multi-bucket lock-helper stack frame.
/// See the matching note in sched.scheduler on `core_states[]`.
fn acquireBucketLocks(sorted: []const u8, addrs: []const PAddr) BucketLockState {
    var state = BucketLockState{};
    var prev_idx: usize = std.math.maxInt(usize);
    for (sorted) |si| {
        const idx = bucketIdx(addrs[si]);
        if (idx == prev_idx) continue;
        const irq = (&buckets[idx]).lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);
        state.unique_indices[state.count] = idx;
        state.irq_states[state.count] = irq;
        state.count += 1;
        prev_idx = idx;
    }
    return state;
}

/// Release bucket locks in reverse order. Pointer-index `buckets[]`:
/// see the matching note in `acquireBucketLocks`.
fn releaseBucketLocks(lock_state: *const BucketLockState) void {
    var i: usize = lock_state.count;
    while (i > 0) {
        i -= 1;
        (&buckets[lock_state.unique_indices[i]]).lock.unlockIrqRestore(lock_state.irq_states[i]);
    }
}

/// Walk the timed-waiter list, wake each EC whose deadline has passed.
/// Called from the per-core timer tick.
pub fn expireTimedWaiters() void {
    const now_ns = arch.time.getMonotonicClock().now();

    // Phase 1: snapshot expired ECs + clear their slots, all under
    // timed_lock. Capturing the deadline lets phase 2 detect an EC
    // that was woken and re-registered as a fresh waiter between phases.
    //
    // The split is required by lock-order: wait() and wake() acquire
    // bucket.lock then timed_lock; if we held timed_lock here while
    // taking bucket.lock, that would form an AB-BA cycle.
    const core_id = arch.smp.coreID();
    const expired = &expire_timed_scratch[@intCast(core_id)];
    var expired_count: usize = 0;
    {
        const irq = timed_lock.lockIrqSaveOrdered(@src(), FUTEX_TIMED_GROUP);
        defer timed_lock.unlockIrqRestore(irq);
        for (&timed_waiters) |*slot| {
            const ec = slot.* orelse continue;
            // Cross-core terminate may have rotated this EC's slab gen to
            // even (freed) and left a stale entry here — `terminate` /
            // `destroyExecutionContextLocked` don't reach into this list.
            // Drop dead entries before SlabRef.init's `gen % 2 == 1`
            // assertion fires (the polymorphic source of every smp=4
            // panic in the futex_wait_change_* + futex_wake_* test
            // batch).
            const gen = ec._gen_lock.currentGen();
            if (gen % 2 == 0) {
                slot.* = null;
                continue;
            }
            if (ec.futex_deadline_ns == 0 or now_ns < ec.futex_deadline_ns) continue;
            // caller-pinned: `ec` is pinned by the `timed_waiters` slot we
            // just dequeued; capturing its current gen here gives the
            // phase-2 walk a stale-detector if the slot is freed and
            // reallocated between phases. The deadline re-check after
            // re-locking still rejects re-registered ECs.
            expired[expired_count] = .{
                .ec = SlabRef(ExecutionContext).init(ec, gen),
                .deadline = ec.futex_deadline_ns,
            };
            expired_count += 1;
            slot.* = null;
        }
    }

    // Phase 2: per-EC, take only bucket.lock (never timed_lock).
    for (expired[0..expired_count]) |entry| {
        // caller-pinned: `entry.ec` was captured under timed_lock above
        // and the EC's slot can only be freed after its bucket waiters
        // are unwound, which this very phase performs. The gen carried
        // by the SlabRef is the structural staleness backstop; the
        // deadline check below catches the wake/re-wait race.
        const ec = entry.ec.ptr;
        // Re-check deadline. If wake() ran between phases, deadline is
        // now 0; if the EC was woken and made a new wait, deadline
        // differs. In both cases this snapshot is stale — skip.
        if (ec.futex_deadline_ns != entry.deadline) continue;

        const nodes = ec.futex_wait_nodes orelse continue;
        const count: usize = ec.futex_bucket_count;
        var removed: bool = false;
        var i: usize = 0;
        while (i < count) {
            const node = &nodes[i];
            const bucket = &buckets[bucketIdx(node.paddr)];
            const birq = bucket.lock.lockIrqSave(@src());
            if (bucket.pq.remove(node)) removed = true;
            bucket.lock.unlockIrqRestore(birq);
            i += 1;
        }

        if (removed) {
            var on_cpu_spin: u64 = 0;
            while (ec.on_cpu.load(.acquire)) {
                std.atomic.spinLoopHint();
                spin_diag.tick(&on_cpu_spin, @src(), "on_cpu-futex-timeout");
            }
            ec.futex_deadline_ns = FUTEX_TIMEOUT_SENTINEL;
            // Spec §[futex_wait_val] [test 06] / §[futex_wait_change]
            // [test 06]: timeout returns E_TIMEOUT in vreg 1. The
            // waiting EC's syscall handler already returned a
            // placeholder, so we must overwrite ec.ctx.regs.rax with
            // the real timeout error before iretq resumes the EC.
            arch_syscall.setSyscallReturn(ec.ctx, @bitCast(@as(i64, errors.E_TIMEOUT)));
            ec.futex_bucket_count = 0;
            ec.futex_wait_nodes = null;
            ec.futex_wait_vaddrs = null;
            ec.state = .ready;
            sched.enqueueOnCore(@intCast(pickCoreForEc(ec)), ec);
        }
    }
}
