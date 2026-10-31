const std = @import("std");
const stygia = @import("stygia");

const address = stygia.memory.address;
const arch = stygia.arch.dispatch;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const pmm = stygia.memory.pmm;

const PAddr = stygia.memory.address.PAddr;
const SpinLock = stygia.utils.sync.SpinLock;
const VAddr = stygia.memory.address.VAddr;

const STACK_RANGE_START: u64 = address.KernelVA.kernel_stacks.start;
const STACK_RANGE_END: u64 = address.KernelVA.kernel_stacks.end;
const SLOT_SIZE: u64 = address.KERNEL_STACK_SLOT_SIZE;
const MAX_SLOTS: u64 = (STACK_RANGE_END - STACK_RANGE_START) / SLOT_SIZE;

const FREELIST_CAP: usize = 512;

var next_slot = std.atomic.Value(u64).init(0);
var freelist_buf: [FREELIST_CAP]u64 = undefined;
var freelist_top: usize = 0;

/// Always taken with `lockIrqSave`, never plain `lock`.
///
/// This lock is reachable from an ASYNCHRONOUS interrupt: the timer
/// entry `arch.x64.irq.schedTimerHandler` → `scheduler.preempt` →
/// `scheduler.yieldTo` → `thread.finalizeDestroyMarkedDead`
/// → `destroyKernel`, which calls `quarantineSlot`/`recycleSlot` below.
/// It is also taken from thread-context teardown and from `allocSlot` on the
/// creation path. If a tick lands on a core that is already inside one
/// of those critical sections with IRQs enabled, the handler spins on a
/// lock its own core holds — an unbreakable single-core self-deadlock
/// (and `debug.checkIrqModeOn`'s `panic_irq_mode_mix`).
///
/// Every thread-context caller is *believed* to already run IRQs-masked, but
/// nothing enforces it — notably `destroyThreadLocked`'s
/// `else { finalizeDestroyMarkedDead(thread); }` arm sits outside that
/// function's `saveAndDisableInterrupts`/`restoreInterrupts` bracket.
/// Masking here makes the requirement local and self-enforcing instead
/// of caller-dependent and unchecked. The critical sections are a few
/// array writes, so the masked window stays tiny.
var freelist_lock: SpinLock = .{ .class = "stack.freelist_lock" };

pub const Stack = struct {
    top: VAddr,
    base: VAddr,
    guard: VAddr,
    slot: u64,
};

/// Frames whose kernel-stack PTEs have been cleared but which are not
/// yet safe to hand back to the PMM: some core may still hold a stale
/// TLB translation for the VA they were mapped at. Each entry carries
/// the invalidation epoch published right after its PTE was cleared;
/// `drainQuarantine` releases it once every core has honoured that
/// epoch. See `destroyKernel` for why this exists.
///
/// 1024 entries = 4 MiB of frames in flight at the absolute worst. An
/// epoch retires as soon as every core takes one IPI or spins on one
/// lock, so the steady-state depth is a handful of entries.
const QUARANTINE_CAP: usize = 1024;

const QuarantinedFrame = struct {
    paddr: PAddr,
    epoch: u64,
};

var quarantine: [QUARANTINE_CAP]QuarantinedFrame = undefined;
var quarantine_len: usize = 0;
var quarantine_lock: SpinLock = .{ .class = "stack.quarantine_lock" };

/// Slots whose stack was torn down but whose VA range is not yet safe to
/// hand to a new stack, for the same reason and on the same epoch as
/// `quarantine` above — a core holding a stale translation for this
/// slot's VAs would reach the OLD frames, which are sitting in that
/// quarantine precisely so they cannot be reused yet.
///
/// Recycling the slot early is subtly worse than recycling a frame
/// early, which is why this exists separately (stygia-za7). The frame
/// quarantine guarantees the physical pages are not handed to anyone
/// else; it says nothing about the VIRTUAL range. Recycle the slot
/// immediately and the next `createKernel` maps FRESH frames at those
/// same VAs, while a core with a stale TLB entry still translates them
/// to the quarantined originals. That core then runs on a kernel stack
/// whose stores land in a frame nobody will ever read: not a fault, not
/// a crash, just a stack whose writes silently disappear.
///
/// Sized to `FREELIST_CAP`: a slot that cannot be parked here is a slot
/// the freelist could not have absorbed either.
///
/// Guarded by `freelist_lock`, not a lock of its own. The quarantine is
/// the staging half of the freelist — every entry is destined for it and
/// nothing else reads either structure — so one lock keeps the drain
/// (which moves entries from here to there) a single critical section.
/// Two locks would have to nest, and `allocSlot` would want them in the
/// opposite order from the drain.
const SLOT_QUARANTINE_CAP: usize = FREELIST_CAP;

const QuarantinedSlot = struct {
    slot: u64,
    epoch: u64,
};

var slot_quarantine: [SLOT_QUARANTINE_CAP]QuarantinedSlot = undefined;
var slot_quarantine_len: usize = 0;

/// Return every quarantined frame whose invalidation epoch has retired.
/// Swap-removal, so the scan is O(live entries) and order does not
/// matter.
fn drainQuarantine() void {
    const irq = quarantine_lock.lockIrqSave(@src());
    defer quarantine_lock.unlockIrqRestore(irq);

    const pmm_mgr = &(pmm.global_pmm orelse return);
    var i: usize = 0;
    while (i < quarantine_len) {
        if (!arch.paging.kernelUnmapEpochRetired(quarantine[i].epoch)) {
            i += 1;
            continue;
        }
        const paddr = quarantine[i].paddr;
        quarantine_len -= 1;
        quarantine[i] = quarantine[quarantine_len];
        const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
        pmm_mgr.destroy(page);
    }
}

/// Park `paddr` until `epoch` retires. On overflow the frame is
/// deliberately LEAKED rather than freed early: freeing it is the
/// use-after-free this whole mechanism exists to prevent, and a bounded
/// leak is the strictly safer failure. Overflow requires >1024 frames
/// to be in flight with no core having taken a single interrupt or
/// touched a single lock, which is not a state this kernel reaches.
fn quarantineFrame(paddr: PAddr, epoch: u64) void {
    const irq = quarantine_lock.lockIrqSave(@src());
    defer quarantine_lock.unlockIrqRestore(irq);
    if (quarantine_len >= QUARANTINE_CAP) return;
    quarantine[quarantine_len] = .{ .paddr = paddr, .epoch = epoch };
    quarantine_len += 1;
}

pub const KernelStackPage = enum { usable, guard, not_stack };

pub fn isKernelStackPage(vaddr: VAddr) KernelStackPage {
    if (vaddr.addr < STACK_RANGE_START or vaddr.addr >= STACK_RANGE_END) return .not_stack;
    const slot_offset = (vaddr.addr - STACK_RANGE_START) % SLOT_SIZE;
    if (slot_offset == 0) return .guard;
    return .usable;
}

/// Move every slot whose invalidation epoch has retired from the
/// quarantine onto the freelist. Swap-removal, so the scan is O(live
/// entries). Caller must hold `freelist_lock`.
fn drainSlotQuarantineLocked() void {
    var i: usize = 0;
    while (i < slot_quarantine_len) {
        if (!arch.paging.kernelUnmapEpochRetired(slot_quarantine[i].epoch)) {
            i += 1;
            continue;
        }
        const slot = slot_quarantine[i].slot;
        slot_quarantine_len -= 1;
        slot_quarantine[i] = slot_quarantine[slot_quarantine_len];
        // No capacity test: the quarantine is capped at FREELIST_CAP and
        // every entry in it came out of the freelist's budget, so the
        // freelist always has room for what drains back.
        if (freelist_top < FREELIST_CAP) {
            freelist_buf[freelist_top] = slot;
            freelist_top += 1;
        }
    }
}

/// Park `slot` until `epoch` retires. On overflow the slot is
/// deliberately LEAKED rather than recycled early — same reasoning as
/// `quarantineFrame`, and a leaked slot is cheap: it costs one VA range
/// out of `MAX_SLOTS` and no physical memory.
fn quarantineSlot(slot: u64, epoch: u64) void {
    // IRQ-masked: reached from the async timer entry via
    // `schedTimerHandler → preempt → yieldTo →
    // finalizeDestroyMarkedDead → destroyKernel`. See `freelist_lock`.
    const irq = freelist_lock.lockIrqSave(@src());
    defer freelist_lock.unlockIrqRestore(irq);
    // Drain BEFORE testing capacity. Teardown is bursty — a domain
    // death destroys hundreds of stacks with nothing allocating in
    // between — so a quarantine that only drained from `allocSlot`
    // would fill during the burst and leak every slot past the cap,
    // which is worse than the freelist it replaced (that one was being
    // consumed continuously). Retired entries cost nothing to move.
    if (slot_quarantine_len >= SLOT_QUARANTINE_CAP) drainSlotQuarantineLocked();
    if (slot_quarantine_len >= SLOT_QUARANTINE_CAP) return;
    slot_quarantine[slot_quarantine_len] = .{ .slot = slot, .epoch = epoch };
    slot_quarantine_len += 1;
}

fn allocSlot() !u64 {
    // IRQ-masked for the same reason as `quarantineSlot`: the tick
    // handler reaches this lock class through `destroyKernel`, so a core
    // holding it with IRQs enabled would deadlock against itself. See
    // `freelist_lock`.
    const irq = freelist_lock.lockIrqSave(@src());
    // An empty freelist does NOT mean no slots are recoverable — it
    // usually means they are all sitting in quarantine waiting on an
    // epoch that has long since retired. Nothing else polls the
    // quarantine, so without this drain a burst of teardowns followed by
    // a burst of creates would march `next_slot` forward with a full
    // quarantine behind it and exhaust the range for no reason.
    if (freelist_top == 0) drainSlotQuarantineLocked();
    if (freelist_top > 0) {
        freelist_top -= 1;
        const slot = freelist_buf[freelist_top];
        freelist_lock.unlockIrqRestore(irq);
        return slot;
    }
    freelist_lock.unlockIrqRestore(irq);

    const slot = next_slot.fetchAdd(1, .monotonic);
    if (slot >= MAX_SLOTS) return error.OutOfKernelStacks;
    return slot;
}

/// Return a slot to the freelist immediately. Only correct when no core
/// can hold a stale translation for the slot's VA range — i.e. when
/// nothing was ever mapped there. Everything else must go through
/// `quarantineSlot`; see the `slot_quarantine` doc.
fn recycleSlot(slot: u64) void {
    // IRQ-masked: `destroyKernel`'s never-mapped arm calls this, and
    // `destroyKernel` is reachable from the async timer entry via
    // `schedTimerHandler → preempt → yieldTo →
    // finalizeDestroyMarkedDead`. See `freelist_lock`.
    const irq = freelist_lock.lockIrqSave(@src());
    defer freelist_lock.unlockIrqRestore(irq);
    if (freelist_top < FREELIST_CAP) {
        freelist_buf[freelist_top] = slot;
        freelist_top += 1;
    }
}

pub fn createKernel() !Stack {
    const slot = try allocSlot();
    const guard_addr = STACK_RANGE_START + slot * SLOT_SIZE;
    return .{
        .guard = VAddr.fromInt(guard_addr),
        .base = VAddr.fromInt(guard_addr + paging.PAGE4K),
        .top = VAddr.fromInt(guard_addr + SLOT_SIZE),
        .slot = slot,
    };
}

/// Unmap and free a kernel stack's pages, then recycle its slot.
///
/// **Ordering is load-bearing: clear every leaf PTE, publish a TLB
/// invalidation, and hand the physical frames back to the PMM only once
/// every core has honoured it.** The third step is deferred through
/// `quarantine` rather than waited on inline — see below.
///
/// The previous version interleaved those three steps per page, via
/// `arch.paging.unmapPage` → `flushRemoteTlb` → `pmm.destroy`, and
/// `flushRemoteTlb` is deliberately **fire-and-forget**: it publishes
/// ONE virtual address into the shared shootdown descriptor, fans out
/// IPIs and returns without waiting for a single ack (its own doc says
/// so, and notes the resulting UAF window). Sixteen back-to-back arms
/// therefore overwrite each other's descriptor, and same-vector IPIs
/// coalesce in the LAPIC IRR — one pending interrupt per vector — so a
/// remote core typically invalidates at most the LAST address of the
/// run. The design note on `shootdownTlbRange` in `arch/x64/paging.zig`
/// documents exactly this failure mode as the reason the synchronous
/// path exists.
///
/// Kernel stacks are mapped `.kernel_data`, which on x86-64 means
/// **global** PTEs. Global translations survive every CR3 write, so a
/// missed invalidation does not age out on the next context switch — it
/// persists until something explicitly flushes it. Meanwhile the frames
/// went straight back to the PMM, and `recycleSlot` handed the same VA
/// range to the next thread. A core still holding those stale global
/// translations then ran the new thread on a kernel stack that physically
/// aliased whatever the PMM had since allocated over it: silent
/// cross-core kernel-stack corruption, no fault, no diagnostic.
///
/// Captured live on x86-64 smp=4: `memory.page_frame.allocPageFrame`
/// faulted writing its return value through a stack-spilled pointer
/// that its own prologue had stored into two adjacent slots
/// (`[rbp-0xc8]` and `[rbp-0xc0]`, never rewritten afterwards). At fault
/// time those two slots held two DIFFERENT foreign values (`0xfff` and
/// `0x3296000`) and the saved return address at `[rbp+8]` had become
/// `0x7ea98000`. The wild `0xfff` became the
/// `[UNHANDLED] memory_fault subcode=2 payload=0xfff` that then wedged the
/// whole suite.
///
/// The reclaim is DEFERRED, not waited on. This function is reachable
/// with object gen-locks held and IRQs masked (`terminate` and
/// `destroyThreadLocked` both call it under the dying
/// domain's lock), and blocking for shootdown acks there deadlocks
/// against the IPC fast path: its gen-lock CAS spins are hand-written
/// assembly that runs IRQs-off and services no TLB arms, so a core
/// spinning on the lock this path holds can never ack, and this path
/// can never release. Measured as a fresh 3-cores-RUN wedge with an
/// inline ack-wait here. So: publish the invalidation, park the frames
/// with the epoch it was published at, and let `drainQuarantine` return
/// them once every core has caught up — which costs nothing and cannot
/// block.
///
/// Deliberately takes NO address-space root: kernel stacks are mapped
/// into `memory_init.kernel_addr_space_root` and nowhere else, so that
/// is the only root it can ever be correct to unmap them from. The
/// previous signature let callers pass a root, and the thread teardown path
/// passed the owning domain's — correct on x86-64, where the kernel
/// half is mirrored into every domain PML4, but wrong on aarch64, where
/// the domain root is the TTBR0 (user-only) tree: `unmapPage` walked
/// USER tables with indices derived from the kernel VA, so every thread
/// destroy either silently leaked the kstack (walk found nothing) or
/// unmapped and freed an unrelated LIVE USER PAGE at the aliased low VA
/// — a page whose physical frame the domain's wholesale teardown then
/// freed a second time, handing it to two owners at once. Measured on
/// the bare-metal Pi 5 as cross-core trampling of an active kernel
/// stack (stygia-723).
pub fn destroyKernel(stack: Stack) void {
    // Freeing a stack the calling core's own SP is inside is never
    // correct — the reap protocol (takeOwnPendingZombie) exists to
    // prevent exactly this. Scream rather than silently corrupt.
    const sp = arch.cpu.currentSp();
    if (sp >= stack.base.addr and sp < stack.top.addr) {
        arch.boot.print("[kstk] BUG: freeing own live stack, slot {d} core {d} ra 0x{x}\n", .{
            stack.slot, arch.smp.coreID(), @returnAddress(),
        });
    }

    // Phase 1 — clear every leaf, no per-page shootdown. Collecting the
    // frames instead of freeing them inline is the whole point: nothing
    // may re-enter the PMM before its translation is provably gone from
    // every core.
    var frames: [address.KERNEL_STACK_PAGES]?PAddr = @splat(null);
    var i: usize = 0;
    var any_unmapped = false;
    while (i < address.KERNEL_STACK_PAGES) : (i += 1) {
        const va = VAddr.fromInt(stack.base.addr + i * paging.PAGE4K);
        frames[i] = arch.paging.unmapPageNoShootdown(memory_init.kernel_addr_space_root, va);
        if (frames[i] != null) any_unmapped = true;
    }

    if (any_unmapped) {
        // Phase 2 — one globals-inclusive invalidation covering the whole
        // range, published (not waited on). Skipped when the stack was
        // never touched: no leaf was cleared, so no core can hold a
        // translation for it.
        const epoch = arch.paging.publishKernelUnmapEpoch();
        for (frames) |maybe_paddr| {
            const paddr = maybe_paddr orelse continue;
            quarantineFrame(paddr, epoch);
        }
        // Phase 3 — release everything (this batch included, if the
        // epoch has already retired) that every core has caught up on.
        drainQuarantine();

        // Phase 4 — the VA range rides the SAME epoch as its frames.
        // Handing the slot back now would let the next `createKernel`
        // map fresh frames at these VAs while a core still translates
        // them to the ones just quarantined (stygia-za7).
        quarantineSlot(stack.slot, epoch);
    } else {
        // Nothing was ever mapped here, so no core can hold a
        // translation for it and the slot is immediately reusable.
        recycleSlot(stack.slot);
    }
}
