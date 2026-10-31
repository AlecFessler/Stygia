//! Futex — physical-address-keyed user-space synchronization primitive.
//! Spec §[futex].
//!
//! The kernel hashes the watched physical address into one of
//! `BUCKET_COUNT` buckets, each holding a priority-ordered intrusive
//! queue of `WaitNode`s. A multi-address wait allocates one `WaitNode`
//! per watched address out of the thread's own
//! `futex_wait_nodes_storage[MAX_FUTEX_ADDRS]` array, so the thread
//! simultaneously occupies N independent bucket chains without aliasing
//! a shared link — the per-bucket queues cannot cross-pollute the way
//! they would if every bucket reached for the same thread link slot.

const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const arch_syscall = stygia.arch.dispatch.syscall;
const errors = stygia.syscall.errors;
const sched = stygia.sched.scheduler;
const lifecycle = stygia.sched.lifecycle;

const Thread = stygia.sched.thread.Thread;
const PAddr = stygia.memory.address.PAddr;
const Priority = stygia.sched.thread.Priority;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const SpinLock = stygia.utils.sync.SpinLock;
const VAddr = stygia.memory.address.VAddr;

const BUCKET_COUNT = 256;
const MAX_TIMED_WAITERS = 64;
pub const MAX_FUTEX_ADDRS = 63;

// Internal sentinel stored in `thread.futex_deadline_ns` by the timer
// pass to mark "this thread was woken by deadline expiry, not by a peer
// `futex_wake`". `0` is reserved for "no wait active"; any real
// deadline is the wall clock at the time the wait was entered, so
// UINT64_MAX is far enough in the future to be unambiguous.
const FUTEX_TIMEOUT_SENTINEL: u64 = ~@as(u64, 0);

/// Per-(thread, bucket) wait entry. Allocated out of the waiting thread's
/// `futex_wait_nodes_storage[MAX_FUTEX_ADDRS]` array — one per address
/// in a multi-address wait — and threaded into bucket queues via its
/// own `next` field. Each node carries its own link slot so
/// multi-address waits cannot cross-pollute the chains.
pub const WaitNode = struct {
    thread: SlabRef(Thread),
    paddr: PAddr,
    next: ?*WaitNode = null,
    priority: Priority,
};

const WaitNodePriorityQueue = stygia.sched.priority_queue.PriorityQueue(
    WaitNode,
    "next",
    "priority",
    @typeInfo(Priority).@"enum".fields.len,
);

/// `Bucket.lock` ordered_group. Multi-bucket waits and the wake-side
/// cross-bucket cleanup both hold multiple `Bucket.lock` instances at
/// once; both paths sort their target bucket indices into ascending
/// order before acquiring (`sortByBucket` for the wait paths,
/// `removeNodesExcept` for the wake path), and the wake path skips the
/// `held_idx` slot it already owns. A single global ordering across all
/// futex `Bucket.lock` acquisitions keeps the graph AB-BA-free, which
/// is what this `ordered_group` tag asserts.
const FUTEX_BUCKET_GROUP: u32 = 1;

const Bucket = struct {
    lock: SpinLock = .{ .class = "Bucket.lock" },
    pq: WaitNodePriorityQueue = .{},
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

var timed_lock: SpinLock = .{ .class = "futex.timed_lock" };
var timed_waiters: [MAX_TIMED_WAITERS]?*Thread = [_]?*Thread{null} ** MAX_TIMED_WAITERS;

/// Per-core BSS scratch for `expireTimedWaiters` Phase 1 → Phase 2
/// hand-off. At 64 × 16 = 1 KiB the snapshot used to live on the IRQ
/// timer-tick stack frame, sitting on top of whatever kernel/user stack
/// the tick interrupted. Combined with the recv-waiter snapshot
/// (`port.expire_recv_scratch`, 4 KiB) and the rest of the scheduler
/// chain, IRQ-context stack usage was clobbering adjacent frames'
/// saved-RIP slots. One scratch
/// per core is safe: `schedTimerHandler` runs to completion in IRQ
/// context with IRQs masked, never recurses, and each core has its
/// own timer.
const Snapshot = struct { thread: SlabRef(Thread), deadline: u64 };
var expire_timed_scratch: [sched.MAX_CORES][MAX_TIMED_WAITERS]Snapshot = undefined;

/// `timed_lock` ordered_group. The wait paths take a bucket.lock first
/// then call `addTimedWaiter` (which acquires `timed_lock`); the timer
/// IRQ path takes `timed_lock` then per-thread bucket.locks. Tagging the
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

fn addTimedWaiter(thread: *Thread) bool {
    const irq = timed_lock.lockIrqSaveOrdered(@src(), FUTEX_TIMED_GROUP);
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = thread;
            return true;
        }
    }
    return false;
}

fn removeTimedWaiter(thread: *Thread) void {
    const irq = timed_lock.lockIrqSaveOrdered(@src(), FUTEX_TIMED_GROUP);
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == thread) {
            slot.* = null;
            return;
        }
    }
}

/// Cancel any futex wait `thread` is currently parked in: remove every
/// WaitNode owned by `thread` from its bucket queue(s) and drop the
/// timed_waiters slot if registered. Called from `terminate` /
/// `destroyThreadLocked` when the dying thread is in
/// `.futex_wait` — the WaitNodes live in `thread.futex_wait_nodes_storage`,
/// and freeing the thread slab later leaves the bucket queues holding
/// pointers into a recycled struct, faulting (or worse, mis-waking) the
/// next `wake()` that walks the bucket.
///
/// Safe to call after `thread.state` is no longer `.futex_wait` — the loop
/// is bounded by `futex_bucket_count` and the per-bucket `pq.remove`
/// is idempotent on absent nodes.
pub fn cancelWait(thread: *Thread) void {
    const nodes = thread.futex_wait_nodes orelse return;
    const count: usize = thread.futex_bucket_count;
    var i: usize = 0;
    while (i < count) {
        const node = &nodes[i];
        const bucket = &buckets[bucketIdx(node.paddr)];
        const birq = bucket.lock.lockIrqSave(@src());
        _ = bucket.pq.remove(node);
        bucket.lock.unlockIrqRestore(birq);
        i += 1;
    }
    if (thread.futex_deadline_ns != 0) removeTimedWaiter(thread);
    thread.futex_bucket_count = 0;
    thread.futex_wait_nodes = null;
    thread.futex_wait_vaddrs = null;
    thread.futex_deadline_ns = 0;
    thread.wait.clear();
}

pub fn repairPriority(thread: *Thread) void {
    const nodes = thread.futex_wait_nodes orelse return;
    const count: usize = thread.futex_bucket_count;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const node = &nodes[i];
        const bucket = &buckets[bucketIdx(node.paddr)];
        const birq = bucket.lock.lockIrqSave(@src());
        if (bucket.pq.remove(node)) {
            node.priority = thread.priority;
            bucket.pq.enqueue(node);
        } else {
            node.priority = thread.priority;
        }
        bucket.lock.unlockIrqRestore(birq);
    }
}

/// Remove every node owned by `thread` from its bucket(s), without
/// touching the bucket whose lock the caller already holds (identified
/// by `held_idx`; pass an out-of-range value if none is held). Same-
/// bucket nodes other than `except_node` are removed under the held
/// lock without re-acquisition.
///
/// Acquires sibling-bucket locks in strict ascending bucket-index
/// order to match the global ordering used by `acquireBucketLocks`.
/// This is required: two concurrent wakes on different paddrs (e.g.
/// IRQ-driven wakes on two cores) can each hold a different `held_idx`
/// while reaching across to clean up the same thread's other nodes; a
/// storage-order traversal would seed a classic AB-BA cycle. The skip
/// of `held_idx` plus ascending acquisition of the rest keeps the
/// wake-side acquisition graph identical to the wait-side one.
fn removeNodesExcept(thread: *Thread, except_node: *const WaitNode, held_idx: usize) void {
    const nodes = thread.futex_wait_nodes orelse return;
    const count: usize = thread.futex_bucket_count;

    // Insertion-sort the surviving nodes' storage indices by bucket
    // index ascending. `count <= MAX_FUTEX_ADDRS = 63`, so quadratic
    // sort is fine and keeps the routine allocation-free.
    var sorted: [MAX_FUTEX_ADDRS]u8 = undefined;
    var n: usize = 0;
    var k: usize = 0;
    while (k < count) : (k += 1) {
        if (&nodes[k] == except_node) continue;
        sorted[n] = @intCast(k);
        n += 1;
    }
    var i: usize = 1;
    while (i < n) : (i += 1) {
        var j = i;
        while (j > 0 and bucketIdx(nodes[sorted[j]].paddr) < bucketIdx(nodes[sorted[j - 1]].paddr)) {
            const tmp = sorted[j];
            sorted[j] = sorted[j - 1];
            sorted[j - 1] = tmp;
            j -= 1;
        }
    }

    // Walk the sorted list. Coalesce contiguous same-bucket entries
    // under one lock acquisition; skip the bucket the caller already
    // holds, removing those entries under the held lock.
    var p: usize = 0;
    while (p < n) {
        const idx = bucketIdx(nodes[sorted[p]].paddr);
        var q: usize = p + 1;
        while (q < n and bucketIdx(nodes[sorted[q]].paddr) == idx) q += 1;
        const bucket = &buckets[idx];
        if (idx == held_idx) {
            var r: usize = p;
            while (r < q) : (r += 1) _ = bucket.pq.remove(&nodes[sorted[r]]);
        } else {
            // Second `Bucket.lock` acquisition in the same class; the
            // ascending bucket-index ordering above (matching
            // `acquireBucketLocks`) keeps the global graph AB-BA-free,
            // so opt out of the same-class overlap panic via
            // FUTEX_BUCKET_GROUP.
            const birq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);
            var r: usize = p;
            while (r < q) : (r += 1) _ = bucket.pq.remove(&nodes[sorted[r]]);
            bucket.lock.unlockIrqRestore(birq);
        }
        p = q;
    }
}

/// Pick the destination core for a wakeup, honoring `thread.affinity`.
/// `affinity == 0` is the spec-defined "any core" sentinel; we fall
/// back to the local core in that case to keep cache locality.
fn pickCoreForThread(thread: *Thread) u64 {
    if (thread.affinity == 0) return arch.smp.coreID();
    return @ctz(thread.affinity);
}

fn peekFutexWaiter(bucket: *Bucket) ?*WaitNode {
    var idx: usize = bucket.pq.levels.len;
    while (idx > 0) {
        idx -= 1;
        if (bucket.pq.levels[idx].head) |head| return head;
    }
    return null;
}

fn peekMatchingWaiter(bucket: *Bucket, paddr: PAddr, requeue: *WaitNodePriorityQueue) ?*WaitNode {
    while (true) {
        const node = peekFutexWaiter(bucket) orelse return null;
        if (node.paddr.addr == paddr.addr) return node;
        _ = bucket.pq.dequeue();
        requeue.enqueue(node);
    }
}

/// `futex_wake` — wake up to `count` Threads blocked on `paddr`.
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
        const node = peekMatchingWaiter(bucket, paddr, &requeue) orelse break;

        // stygia-qbx: the thread behind this node can be destroyed by a
        // DOMAIN teardown running on another core at any point in this
        // iteration. The old comment here claimed the node's residence
        // in our bucket pinned the thread ("cannot have been freed"); that
        // is not true. `cancelWait` unlinks a victim's nodes under this
        // same bucket lock, so while we hold it a concurrent teardown
        // simply BLOCKS — the node stays visible to us — and the gen
        // has typically already been bumped dead by then. The first
        // acquire below catches an thread that is already dead; the danger
        // was everything after the old unconditional unlock.
        //
        // Phase 1 — validate under the thread's gen lock and claim the wait
        // episode before unlinking it. That keeps the lifecycle state word
        // as the single winner election: a racing timeout or teardown that
        // cannot CAS waiting/parking away knows this wake owns the payload.
        const wake_lr = node.thread.lockIrqSave(@src()) catch {
            _ = bucket.pq.dequeue();
            continue;
        };
        const thread = wake_lr.ptr;
        // wake_index is the offset of this node in the thread's
        // wait_nodes array — the index of the address in the original
        // multi-address wait that matched.
        const nodes = thread.futex_wait_nodes orelse {
            // Raced a cancel that already cleared the array; the node is
            // stale. Drop it and move on rather than deref a null.
            _ = bucket.pq.dequeue();
            node.thread.unlockIrqRestore(wake_lr.irq_state);
            continue;
        };
        const node_idx: usize = (@intFromPtr(node) - @intFromPtr(nodes)) / @sizeOf(WaitNode);
        if (node_idx >= thread.futex_bucket_count or &nodes[node_idx] != node) {
            _ = bucket.pq.dequeue();
            node.thread.unlockIrqRestore(wake_lr.irq_state);
            continue;
        }

        const claim = lifecycle.beginWaitingClaimPinned(thread);
        if (claim == .none) {
            _ = bucket.pq.dequeue();
            removeNodesExcept(thread, node, wake_idx);
            node.thread.unlockIrqRestore(wake_lr.irq_state);
            continue;
        }
        const dequeued = bucket.pq.dequeue() orelse unreachable;
        std.debug.assert(dequeued == node);
        // Drop this thread's other nodes from every bucket they live in
        // (skipping the just-dequeued node and using the held lock
        // for any same-bucket sibling).
        removeNodesExcept(thread, node, wake_idx);
        thread.futex_wake_index = @intCast(node_idx);
        if (thread.futex_deadline_ns != 0) {
            thread.futex_deadline_ns = 0;
            removeTimedWaiter(thread);
        }
        // Spec §[futex_wait_val] / §[futex_wait_change]: on a wake the
        // syscall returns with vreg 1 set to the user vaddr that was
        // woken. The waiting thread is parked in user-mode space (its
        // syscall handler frame already returned a placeholder); the
        // resume path iretq's via `thread.ctx`, so write the real return
        // value into ctx.regs.rax (vreg 1) before marking it ready.
        if (thread.futex_wait_vaddrs) |vaddrs_ptr| {
            arch_syscall.setSyscallReturn(thread.ctx, vaddrs_ptr[node_idx]);
        }
        thread.futex_bucket_count = 0;
        thread.futex_wait_nodes = null;
        thread.futex_wait_vaddrs = null;
        const dest_core: u8 = @intCast(pickCoreForThread(thread));
        node.thread.unlockIrqRestore(wake_lr.irq_state);

        // Phase 3 — enqueue OUTSIDE the gen lock. `enqueueOnCore` takes
        // `core_locks[]`, and nesting that under a gen lock is the
        // gen-lock→core-lock AB-BA edge qbx flagged. Keeping it out
        // here means this fix adds no new lock-order edge: the only
        // nesting is bucket→gen, which the original code already had.
        switch (claim) {
            .claimed => sched.enqueueOnCore(dest_core, thread),
            .pended => lifecycle.publishPendedPayload(thread),
            .none => unreachable,
        }
        lifecycle.releasePin(thread);
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
pub fn waitVal(addrs: []const PAddr, vaddrs: []const u64, expected: []const u64, count: usize, timeout_ns: u64, thread: *Thread) i64 {
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
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    // Store WaitNodes and vaddrs in thread-resident storage rather than on
    // the caller's kernel stack: `waitVal` returns a placeholder to
    // `syscallDispatch` before the thread actually parks, so the stack
    // frame is reclaimed before wake/expiry runs. The bucket and
    // wake path both keep `&nodes[i]` / `vaddrs_ptr` references that
    // must remain valid until the wake completes.
    const nodes = &thread.futex_wait_nodes_storage;
    const vaddrs_storage = &thread.futex_wait_vaddrs_storage;
    const thread_ref = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .thread = thread_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = thread.priority,
        };
        vaddrs_storage[i] = vaddrs[i];
    }
    thread.futex_wait_nodes = nodes;
    thread.futex_wait_vaddrs = vaddrs_storage;
    thread.futex_bucket_count = @intCast(count);
    const owner_core: u8 = @truncate(arch.smp.coreID());
    if (!lifecycle.prepareRunningPark(thread, owner_core, .futex)) {
        releaseBucketLocks(&lock_state);
        thread.futex_wait_nodes = null;
        thread.futex_wait_vaddrs = null;
        thread.futex_bucket_count = 0;
        thread.futex_deadline_ns = 0;
        return errors.E_INVAL;
    }

    for (0..count) |i| {
        const idx = bucketIdx(addrs[i]);
        (&buckets[idx]).pq.enqueue(&nodes[i]);
    }

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            for (0..count) |i| {
                _ = (&buckets[bucketIdx(addrs[i])]).pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            _ = lifecycle.cas(thread, .parking, .running);
            thread.owner_core = owner_core;
            thread.wait.clear();
            thread.futex_wait_nodes = null;
            thread.futex_wait_vaddrs = null;
            thread.futex_bucket_count = 0;
            thread.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    releaseBucketLocks(&lock_state);

    // Park the thread: drop currency on the local core. The syscall
    // dispatcher (`arch.x64.interrupts.syscallDispatch`) sees
    // `current_thread == null` and routes to `scheduler.hopParkRun()`
    // instead of iretq'ing back to the now-parked user thread. The
    // wake/timeout path overwrites this thread's syscall-return slot with
    // the real return value (vaddr or E_TIMEOUT) before re-marking it
    // ready, so the placeholder returned here only needs to be a value
    // the parked thread will never observe.
    //
    // `on_cpu` is NOT cleared here: this core keeps executing on the
    // thread's kstack until the park-kstack hop, and the wake side's
    // phase-2 spin gates its enqueue on exactly this flag. Stash the
    // release for the hop instead (see PerCore.pending_kstack_release).
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
pub fn waitChange(addrs: []const PAddr, vaddrs: []const u64, targets: []const u64, count: usize, timeout_ns: u64, thread: *Thread) i64 {
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
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    // Same thread-resident storage discipline as `waitVal`.
    const nodes = &thread.futex_wait_nodes_storage;
    const vaddrs_storage = &thread.futex_wait_vaddrs_storage;
    const thread_ref = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .thread = thread_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = thread.priority,
        };
        vaddrs_storage[i] = vaddrs[i];
    }
    thread.futex_wait_nodes = nodes;
    thread.futex_wait_vaddrs = vaddrs_storage;
    thread.futex_bucket_count = @intCast(count);
    const owner_core: u8 = @truncate(arch.smp.coreID());
    if (!lifecycle.prepareRunningPark(thread, owner_core, .futex)) {
        releaseBucketLocks(&lock_state);
        thread.futex_wait_nodes = null;
        thread.futex_wait_vaddrs = null;
        thread.futex_bucket_count = 0;
        thread.futex_deadline_ns = 0;
        return errors.E_INVAL;
    }

    for (0..count) |i| {
        (&buckets[bucketIdx(addrs[i])]).pq.enqueue(&nodes[i]);
    }

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            for (0..count) |i| {
                _ = (&buckets[bucketIdx(addrs[i])]).pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            _ = lifecycle.cas(thread, .parking, .running);
            thread.owner_core = owner_core;
            thread.wait.clear();
            thread.futex_wait_nodes = null;
            thread.futex_wait_vaddrs = null;
            thread.futex_bucket_count = 0;
            thread.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    releaseBucketLocks(&lock_state);

    // Park the thread: see `waitVal` for the full rationale, including why
    // the `on_cpu` release is stashed for the park-kstack hop rather
    // than performed here.
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

/// Walk the timed-waiter list, wake each thread whose deadline has passed.
/// Called from the per-core timer tick.
pub fn expireTimedWaiters() void {
    const now_ns = arch.time.getMonotonicClock().now();

    // Phase 1: snapshot expired Threads + clear their slots, all under
    // timed_lock. Capturing the deadline lets phase 2 detect an thread
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
            const thread = slot.* orelse continue;
            if (!lifecycle.tryPinLive(thread)) {
                slot.* = null;
                continue;
            }
            // Cross-core terminate may have rotated this thread's slab gen to
            // even (freed) and left a stale entry here — `terminate` /
            // `destroyThreadLocked` don't reach into this list.
            // Drop dead entries before SlabRef.init's `gen % 2 == 1`
            // assertion fires (the polymorphic source of every smp=4
            // panic in the futex_wait_change_* + futex_wake_* test
            // batch).
            const gen = thread._gen_lock.currentGen();
            if (gen % 2 == 0) {
                lifecycle.releasePin(thread);
                slot.* = null;
                continue;
            }
            const deadline = thread.futex_deadline_ns;
            if (deadline == 0 or now_ns < deadline) {
                lifecycle.releasePin(thread);
                continue;
            }
            // caller-pinned: `thread` is pinned by the `timed_waiters` slot we
            // just dequeued; capturing its current gen here gives the
            // phase-2 walk a stale-detector if the slot is freed and
            // reallocated between phases. The deadline re-check after
            // re-locking still rejects re-registered Threads.
            expired[expired_count] = .{
                .thread = SlabRef(Thread).init(thread, gen),
                .deadline = deadline,
            };
            lifecycle.releasePin(thread);
            expired_count += 1;
            slot.* = null;
        }
    }

    // Phase 2: per-thread, take only bucket.lock (never timed_lock).
    for (expired[0..expired_count]) |entry| {
        // caller-pinned: `entry.thread` was captured under timed_lock above
        // and the thread's slot can only be freed after its bucket waiters
        // are unwound, which this very phase performs. The gen carried
        // by the SlabRef is the structural staleness backstop; the
        // deadline check below catches the wake/re-wait race.
        const thread = entry.thread.ptr;
        if (!lifecycle.tryPinLive(thread)) continue;
        if (thread._gen_lock.currentGen() != @as(u63, entry.thread.gen)) {
            lifecycle.releasePin(thread);
            continue;
        }
        // Re-check deadline. If wake() ran between phases, deadline is
        // now 0; if the thread was woken and made a new wait, deadline
        // differs. In both cases this snapshot is stale — skip.
        if (thread.futex_deadline_ns != entry.deadline) {
            lifecycle.releasePin(thread);
            continue;
        }

        const nodes = thread.futex_wait_nodes orelse {
            lifecycle.releasePin(thread);
            continue;
        };
        const count: usize = thread.futex_bucket_count;
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
            const claim = lifecycle.beginWaitingClaimPinned(thread);
            if (claim == .none) {
                lifecycle.releasePin(thread);
                continue;
            }
            thread.futex_deadline_ns = FUTEX_TIMEOUT_SENTINEL;
            // Spec §[futex_wait_val] [test 06] / §[futex_wait_change]
            // [test 06]: timeout returns E_TIMEOUT in vreg 1. The
            // waiting thread's syscall handler already returned a
            // placeholder, so we must overwrite thread.ctx.regs.rax with
            // the real timeout error before iretq resumes the thread.
            arch_syscall.setSyscallReturn(thread.ctx, @bitCast(@as(i64, errors.E_TIMEOUT)));
            thread.futex_bucket_count = 0;
            thread.futex_wait_nodes = null;
            thread.futex_wait_vaddrs = null;
            switch (claim) {
                .claimed => sched.enqueueOnCore(@intCast(pickCoreForThread(thread)), thread),
                .pended => lifecycle.publishPendedPayload(thread),
                .none => unreachable,
            }
            lifecycle.releasePin(thread);
        }
        lifecycle.releasePin(thread);
    }
}
