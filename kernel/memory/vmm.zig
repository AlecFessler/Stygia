const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const secure_slab = zag.memory.allocators.secure_slab;

const GenLock = secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SlabRef = secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VmarCaps = zag.memory.vmar.VmarCaps;

/// Per-VMM reservation cap. Reservations live in a sorted inline
/// `[MAX_RESERVATIONS]SlabRef(VmNode)` array — lookups are
/// `std.sort.lowerBound` (O(log N) over cache-friendly contiguous
/// memory), insert/remove are `@memmove` of the tail (O(N) but N is
/// bounded and the compiler vectorizes the shift). VARs replaced the
/// SHM/MMIO/virtual-BAR variants in spec v3, so every node here is a
/// private demand-paged region or stack guard.
pub const MAX_RESERVATIONS: usize = 256;

/// Effective rwx for a private VMM node. Only the `r`/`w`/`x` bits of
/// `VmarCaps` are interpreted here — the rest of the VmarCaps fields
/// (move/copy/mmio/dma/restart_policy) have no meaning for an internal
/// VMM node and are kept zero.
pub const VmNode = extern struct {
    _gen_lock: GenLock = .{},
    start: VAddr,
    size: u64,
    rights: VmarCaps,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },

    pub fn end(self: *const VmNode) u64 {
        return self.start.addr + self.size;
    }

    /// Populate every non-`_gen_lock` field of a freshly allocated node.
    /// Use this instead of `node.* = .{...}` — a whole-struct assignment
    /// would clobber the gen-lock word that the allocator just set.
    pub fn init(self: *VmNode, start: VAddr, size: u64, rights: VmarCaps) void {
        self.start = start;
        self.size = size;
        self.rights = rights;
        self._pad = .{ 0, 0, 0, 0, 0, 0 };
    }
};

const VmNodeSlab = secure_slab.SecureSlab(VmNode, 256);
var vm_node_slab: VmNodeSlab = undefined;

pub fn initSlabs(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    vm_node_slab = VmNodeSlab.init(data_range, ptrs_range, links_range);
}

fn freeVmNode(node_ref: SlabRef(VmNode)) void {
    // caller-pinned: caller proves liveness by holding vmm.lock; the node
    // was just removed from `self.nodes[]` and no other context can
    // observe it after that point.
    // Use the carried gen (from the caller's SlabRef) rather than
    // reading `currentGen()` off the slot — the carried value is what
    // every prior handle to this node has been validated against, so
    // destroy targets that specific generation of the slot.
    vm_node_slab.destroy(node_ref.ptr, @intCast(node_ref.gen)) catch unreachable;
}

fn cmpAddrToNode(ctx_addr: u64, item: SlabRef(VmNode)) std.math.Order {
    // caller-pinned: sort comparator runs under vmm.lock; every item in
    // the slice is alive for the duration of the search.
    return std.math.order(ctx_addr, item.ptr.start.addr);
}

/// First index `i` into `slice` where `slice[i].start.addr >= addr`.
/// Matches `std.sort.lowerBound` semantics; returns `slice.len` when
/// `addr` is greater than every node's start.
fn lowerBoundIdx(slice: []SlabRef(VmNode), addr: u64) usize {
    return std.sort.lowerBound(SlabRef(VmNode), slice, addr, cmpAddrToNode);
}

pub const VirtualMemoryManager = struct {
    nodes: [MAX_RESERVATIONS]SlabRef(VmNode),
    count: u32,
    range_start: VAddr,
    range_end: VAddr,
    addr_space_root: PAddr,
    lock: SpinLock,

    pub fn init(start: VAddr, end_vaddr: VAddr, root: PAddr) VirtualMemoryManager {
        return .{
            .nodes = undefined,
            .count = 0,
            .range_start = start,
            .range_end = end_vaddr,
            .addr_space_root = root,
            .lock = .{ .class = "VirtualMemoryManager.lock" },
        };
    }

    /// Active slice view over the sorted reservation array.
    fn slice(self: *VirtualMemoryManager) []SlabRef(VmNode) {
        return self.nodes[0..self.count];
    }

    /// Returns the node whose range covers `vaddr`, or null. Each node
    /// occupies a disjoint half-open interval `[start, end)`, so the
    /// only candidate is the greatest-start-≤-vaddr neighbor.
    fn findNodeLocked(self: *VirtualMemoryManager, vaddr: VAddr) ?SlabRef(VmNode) {
        const idx = lowerBoundIdx(self.slice(), vaddr.addr +| 1);
        if (idx == 0) return null;
        const candidate = self.nodes[idx - 1];
        // caller-pinned: vmm.lock is held — the node is still in the array.
        if (vaddr.addr < candidate.ptr.end()) return candidate;
        return null;
    }

    pub fn deinit(self: *VirtualMemoryManager) void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node_ref = self.nodes[i];
            unmapNodePages(node_ref, self.addr_space_root, true);
            freeVmNode(node_ref);
        }
        self.count = 0;
    }

    pub fn findNode(self: *VirtualMemoryManager, vaddr: VAddr) ?SlabRef(VmNode) {
        const irq = self.lock.lockIrqSave(@src());
        defer self.lock.unlockIrqRestore(irq);
        return self.findNodeLocked(vaddr);
    }

};

fn unmapNodePages(node_ref: SlabRef(VmNode), addr_space_root: PAddr, free_phys: bool) void {
    // caller-pinned: callers hold vmm.lock; the node is stored in
    // self.nodes[] or was just removed by the same critical section.
    const node = node_ref.ptr;

    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = node.start.addr;
    while (page_addr < node.end()) {
        if (arch.paging.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            if (free_phys) {
                const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_mgr.destroy(page);
            }
        }
        page_addr += paging.PAGE4K;
    }
}

