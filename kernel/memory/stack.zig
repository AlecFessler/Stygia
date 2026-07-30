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
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        if (arch.paging.unmapPage(memory_init.kernel_addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            const pmm_mgr = &pmm.global_pmm.?;
            const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
            pmm_mgr.destroy(page);
        }
        page_addr += paging.PAGE4K;
    }
    recycleSlot(stack.slot);
}

