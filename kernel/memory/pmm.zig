const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const paging = stygia.memory.paging;
const sched = stygia.sched.scheduler;

const BuddyAllocator = stygia.memory.allocators.buddy.BuddyAllocator;
const SpinLock = stygia.utils.sync.SpinLock;

const MAX_CORES = 64;
const CACHE_REFILL_ORDER: u4 = 4;
const CACHE_REFILL_PAGES: u32 = @as(u32, 1) << CACHE_REFILL_ORDER;
const CACHE_MAX_PAGES: u32 = 64;

const PageNode = struct {
    next: ?*PageNode,
};

const PerCorePageCache = struct {
    head: ?*PageNode = null,
    count: u32 = 0,

    fn push(self: *PerCorePageCache, ptr: [*]u8) void {
        const node: *PageNode = @ptrCast(@alignCast(ptr));
        node.next = self.head;
        self.head = node;
        self.count += 1;
    }

    fn pop(self: *PerCorePageCache) ?[*]u8 {
        const node = self.head orelse return null;
        self.head = node.next;
        self.count -= 1;
        // Push overwrote the first 8 bytes of the page with the intrusive
        // `next` pointer. Allocation callers expect a fully zeroed page
        // (§ PMM zero-on-free invariant), so null the one field we
        // mutated — re-zeroing the whole page would throw away the
        // cache-line-zero work the free path already paid for.
        node.next = null;
        return @ptrCast(node);
    }
};

var page_caches: [MAX_CORES]PerCorePageCache = [_]PerCorePageCache{.{}} ** MAX_CORES;

pub const PhysicalMemoryManager = struct {
    buddy: *BuddyAllocator,
    lock: SpinLock = .{ .class = "PhysicalMemoryManager.lock" },

    pub fn init(buddy: *BuddyAllocator) PhysicalMemoryManager {
        return .{
            .buddy = buddy,
        };
    }

    /// Allocate a single 4 KiB page. Uses the per-core page cache after
    /// the scheduler is up (so the common hot path avoids the buddy
    /// spinlock); falls back to a buddy allocation before that or on
    /// cache miss. Returns null on OOM.
    pub fn allocPage(self: *PhysicalMemoryManager) ?[*]u8 {
        if (sched.initialized) {
            const irq = arch.cpu.saveAndDisableInterrupts();
            const cache = &page_caches[arch.smp.coreID()];

            if (cache.pop()) |page| {
                arch.cpu.restoreInterrupts(irq);
                return page;
            }

            self.lock.lock(@src());
            const bulk = self.buddy.allocBlock(paging.PAGE4K * CACHE_REFILL_PAGES) orelse {
                const single = self.buddy.allocBlock(paging.PAGE4K);
                self.lock.unlock();
                arch.cpu.restoreInterrupts(irq);
                return single;
            };
            var batch = self.buddy.splitAllocation(@intFromPtr(bulk), 0);
            self.lock.unlock();

            while (batch.pop()) |page| {
                cache.push(@ptrCast(page));
            }

            const result = cache.pop().?;
            arch.cpu.restoreInterrupts(irq);
            return result;
        }

        const irq = self.lock.lockIrqSave(@src());
        defer self.lock.unlockIrqRestore(irq);
        return self.buddy.allocBlock(paging.PAGE4K);
    }

    /// Free a single 4 KiB page previously returned by `allocPage`.
    /// Zeroes the page before it rejoins the free pool (via the
    /// per-core cache or the buddy) so every alloc path observes a zero
    /// page without paying a read-for-ownership on bulk `@memset`.
    pub fn freePage(self: *PhysicalMemoryManager, page: [*]u8) void {
        arch.memory.zeroPage(@ptrCast(page));

        if (sched.initialized) {
            const irq = arch.cpu.saveAndDisableInterrupts();
            const cache = &page_caches[arch.smp.coreID()];

            if (cache.count < CACHE_MAX_PAGES) {
                cache.push(page);
                arch.cpu.restoreInterrupts(irq);
                return;
            }

            self.lock.lock(@src());
            var i: u32 = 0;
            while (i < CACHE_MAX_PAGES / 2) {
                const cached = cache.pop().?;
                self.buddy.freeBlock(cached[0..paging.PAGE4K]);
                i += 1;
            }
            self.lock.unlock();

            cache.push(page);
            arch.cpu.restoreInterrupts(irq);
            return;
        }

        const irq = self.lock.lockIrqSave(@src());
        defer self.lock.unlockIrqRestore(irq);
        self.buddy.freeBlock(page[0..paging.PAGE4K]);
    }

    /// Allocate a contiguous physical block sized `len` bytes (must be a
    /// power-of-two multiple of 4 KiB). Bypasses the per-core cache —
    /// the cache only holds single pages — and returns directly from
    /// the buddy allocator.
    pub fn allocBlock(self: *PhysicalMemoryManager, len: u64) ?[*]u8 {
        const irq = self.lock.lockIrqSave(@src());
        defer self.lock.unlockIrqRestore(irq);
        return self.buddy.allocBlock(len);
    }

    /// Free a contiguous physical block previously returned by
    /// `allocBlock`. Zeroes every page in the block before the buddy
    /// takes it back.
    pub fn freeBlock(self: *PhysicalMemoryManager, buf: []u8) void {
        std.debug.assert(buf.len % paging.PAGE4K == 0);
        var offset: u64 = 0;
        while (offset < buf.len) {
            arch.memory.zeroPage(@ptrCast(&buf[offset]));
            offset += paging.PAGE4K;
        }
        const irq = self.lock.lockIrqSave(@src());
        defer self.lock.unlockIrqRestore(irq);
        self.buddy.freeBlock(buf);
    }

    /// Typed convenience wrapper for the single-page path. The backing
    /// page is returned already zeroed (§ PMM zero-on-free invariant).
    pub fn create(self: *PhysicalMemoryManager, comptime T: type) !*T {
        comptime std.debug.assert(@sizeOf(T) == paging.PAGE4K);
        comptime std.debug.assert(@alignOf(T) == paging.PAGE4K);
        const page = self.allocPage() orelse return error.OutOfMemory;
        return @ptrCast(@alignCast(page));
    }

    pub fn destroy(self: *PhysicalMemoryManager, ptr: anytype) void {
        const bytes: [*]u8 = @ptrCast(ptr);
        self.freePage(bytes);
    }
};

pub var global_pmm: ?PhysicalMemoryManager = null;


/// Static total physical page count established by the buddy allocator
/// at `addRegion` time. Used by `sys_info` to populate `SysInfo.mem_total`
/// (§2.15.2, §21). Does not change at runtime.
pub fn totalPageCount() u64 {
    if (global_pmm == null) return 0;
    const pmm_ptr: *PhysicalMemoryManager = &global_pmm.?;
    const irq = pmm_ptr.lock.lockIrqSave(@src());
    defer pmm_ptr.lock.unlockIrqRestore(irq);
    return pmm_ptr.buddy.total_pages;
}

