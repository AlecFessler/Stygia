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

fn allocSlot() !u64 {
    freelist_lock.lock(@src());
    if (freelist_top > 0) {
        freelist_top -= 1;
        const slot = freelist_buf[freelist_top];
        freelist_lock.unlock();
        return slot;
    }
    freelist_lock.unlock();

    const slot = next_slot.fetchAdd(1, .monotonic);
    if (slot >= MAX_SLOTS) return error.OutOfKernelStacks;
    return slot;
}

fn recycleSlot(slot: u64) void {
    freelist_lock.lock(@src());
    defer freelist_lock.unlock();
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
/// range to the next EC. A core still holding those stale global
/// translations then ran the new EC on a kernel stack that physically
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
/// `[NOROUTE] memory_fault subcode=2 payload=0xfff` that then wedged the
/// whole suite.
///
/// The reclaim is DEFERRED, not waited on. This function is reachable
/// with object gen-locks held and IRQs masked (`terminate` and
/// `destroyExecutionContextLocked` both call it under the dying
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
/// previous signature let callers pass a root, and the EC teardown path
/// passed the owning domain's — correct on x86-64, where the kernel
/// half is mirrored into every domain PML4, but wrong on aarch64, where
/// the domain root is the TTBR0 (user-only) tree: `unmapPage` walked
/// USER tables with indices derived from the kernel VA, so every EC
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
    }

    recycleSlot(stack.slot);
}

