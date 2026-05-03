const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const boot = zag.boot;
const capability_domain_mod = zag.caps.capability_domain;
const dev_region_mod = zag.devices.device_region;
const execution_context_mod = zag.sched.execution_context;
const KA = address.KernelVA.KernelAllocators;
const page_frame_mod = zag.memory.page_frame;
const paging = zag.memory.paging;
const perfmon_mod = zag.sched.perfmon;
const pmm = zag.memory.pmm;
const port_mod = zag.sched.port;
const timer_mod = zag.sched.timer;
const vmar_mod = zag.memory.vmar;
const virtual_machine_mod = zag.hv.virtual_machine;

const BuddyAllocator = zag.memory.allocators.buddy.BuddyAllocator;
const BumpAllocator = zag.memory.allocators.bump.BumpAllocator;
const MemoryPerms = zag.memory.address.MemoryPerms;
const MMap = zag.boot.protocol.MMap;
const MMapEntry = zag.boot.protocol.MMapEntry;
const PAddr = zag.memory.address.PAddr;
const PhysicalMemoryManager = zag.memory.pmm.PhysicalMemoryManager;
const Range = zag.utils.range.Range;
const VAddr = zag.memory.address.VAddr;

pub var kernel_addr_space_root: PAddr = undefined;

var bump_allocator: BumpAllocator = undefined;
var buddy_allocator: BuddyAllocator = undefined;



pub fn init(firmware_mmap: MMap) !void {
    var mmap_entries: [boot.protocol.MAX_MMAP_ENTRIES]MMapEntry = undefined;
    const mmap = boot.protocol.collapseMMap(&firmware_mmap, &mmap_entries);

    var smallest_addr_region: MMapEntry = .{ .start_paddr = std.math.maxInt(u64), .num_pages = 0, .type = .free };
    var largest_addr_free_region: MMapEntry = .{ .start_paddr = 0, .num_pages = 0, .type = .free };
    var largest_free_region: MMapEntry = .{ .start_paddr = 0, .num_pages = 0, .type = .free };
    for (mmap) |entry| {
        if (entry.start_paddr < smallest_addr_region.start_paddr) {
            smallest_addr_region = entry;
        }
        if (entry.type == .free and entry.start_paddr > largest_addr_free_region.start_paddr) {
            largest_addr_free_region = entry;
        }
        if (entry.type == .free and entry.num_pages > largest_free_region.num_pages) {
            largest_free_region = entry;
        }
    }

    const bump_alloc_start_phys = PAddr.fromInt(largest_free_region.start_paddr);
    const bump_alloc_end_phys = PAddr.fromInt(largest_free_region.start_paddr + largest_free_region.num_pages * paging.PAGE4K);
    bump_allocator = BumpAllocator.init(bump_alloc_start_phys.addr, bump_alloc_end_phys.addr);
    const bump_alloc_iface: std.mem.Allocator = bump_allocator.allocator();

    const addr_space_root_phys = arch.paging.getKernelAddrSpaceRoot();
    kernel_addr_space_root = addr_space_root_phys;
    const addr_space_root_id_virt = VAddr.fromPAddr(addr_space_root_phys, 0);

    var physmap_page_count: u64 = 0;
    for (mmap) |entry| {
        if (entry.type != .free and entry.type != .acpi) continue;

        const end_phys = PAddr.fromInt(entry.start_paddr + entry.num_pages * paging.PAGE4K);
        var current_phys = PAddr.fromInt(entry.start_paddr);
        while (current_phys.addr < end_phys.addr) {
            const physmap_virt = VAddr.fromPAddr(current_phys, null);
            const remaining = end_phys.addr - current_phys.addr;
            const chosen_size = blk: {
                if (std.mem.isAligned(current_phys.addr, paging.PAGE1G) and remaining >= paging.PAGE1G)
                    break :blk paging.PageSize.page1g;
                if (std.mem.isAligned(current_phys.addr, paging.PAGE2M) and remaining >= paging.PAGE2M)
                    break :blk paging.PageSize.page2m;
                break :blk paging.PageSize.page4k;
            };

            const physmap_perms: MemoryPerms = .{ .read = true, .write = true };

            try arch.paging.mapPageBoot(
                addr_space_root_id_virt,
                current_phys,
                physmap_virt,
                chosen_size,
                physmap_perms,
                .kernel_data,
                bump_alloc_iface,
            );

            current_phys.addr += @intFromEnum(chosen_size);
            physmap_page_count += 1;
        }
    }

    const bump_alloc_start_virt = VAddr.fromPAddr(bump_alloc_start_phys, null);
    const bump_alloc_free_phys = PAddr.fromInt(bump_allocator.free_addr);
    const bump_alloc_free_virt = VAddr.fromPAddr(bump_alloc_free_phys, null);
    const bump_alloc_end_virt = VAddr.fromPAddr(bump_alloc_end_phys, null);
    bump_allocator.start_addr = bump_alloc_start_virt.addr;
    bump_allocator.free_addr = bump_alloc_free_virt.addr;
    bump_allocator.end_addr = bump_alloc_end_virt.addr;

    arch.paging.dropIdentityMapping();
    const buddy_alloc_start_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignForward(u64, smallest_addr_region.start_paddr, paging.PAGE4K)),
        null,
    );
    const buddy_alloc_end_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignBackward(
            u64,
            largest_addr_free_region.start_paddr + largest_addr_free_region.num_pages * paging.PAGE4K,
            paging.PAGE4K,
        )),
        null,
    );
    buddy_allocator = try BuddyAllocator.init(
        buddy_alloc_start_virt.addr,
        buddy_alloc_end_virt.addr,
        bump_alloc_iface,
    );

    // Feature-detect CLZERO / DC ZVA once before anybody calls
    // `arch.memory.zeroPage`. The initial-pool pre-zero below and every
    // subsequent PMM free path rely on the cached flag.
    arch.cpu.initZeroPageFeatures();

    for (mmap) |entry| {
        if (entry.type != .free) continue;

        const entry_start_virt = VAddr.fromPAddr(PAddr.fromInt(entry.start_paddr), null);
        const entry_end_virt = VAddr.fromPAddr(
            PAddr.fromInt(entry.start_paddr + entry.num_pages * paging.PAGE4K),
            null,
        );
        const entry_range: Range = .{
            .start = entry_start_virt.addr,
            .end = entry_end_virt.addr,
        };

        const bump_alloc_range: Range = .{
            .start = bump_allocator.start_addr,
            .end = bump_allocator.free_addr,
        };
        const low_memory_range: Range = .{
            .start = VAddr.fromPAddr(PAddr.fromInt(0), null).addr,
            .end = VAddr.fromPAddr(PAddr.fromInt(0x100000), null).addr,
        };

        var useable_range: Range = entry_range;
        if (entry_range.overlapsWith(bump_alloc_range)) {
            useable_range = entry_range.removeOverlap(bump_alloc_range);
        } else if (entry_range.overlapsWith(low_memory_range)) {
            if (entry_range.start >= low_memory_range.start and entry_range.end <= low_memory_range.end) {
                continue;
            }
            useable_range = entry_range.removeOverlap(low_memory_range);
        }

        // Zero every 4 KiB page before handing it to the buddy. The PMM
        // free path zeroes on release, so alloc callers can rely on a
        // zero page without per-site @memset — but the very first
        // allocations come from this pool, which has never been freed.
        // Wiping it here extends the zero-on-free invariant backwards
        // to boot. Uses the same CLZERO/DC ZVA path the free path
        // uses, so cache traffic is identical.
        var zpage = std.mem.alignForward(u64, useable_range.start, paging.PAGE4K);
        const zend = std.mem.alignBackward(u64, useable_range.end, paging.PAGE4K);
        while (zpage < zend) {
            arch.memory.zeroPage(@ptrFromInt(zpage));
            zpage += paging.PAGE4K;
        }

        buddy_allocator.addRegion(useable_range.start, useable_range.end);
    }

    pmm.global_pmm = PhysicalMemoryManager.init(&buddy_allocator);

    dev_region_mod.initSlab(
        KA.dev_region_slab,
        KA.dev_region_slab_ptrs,
        KA.dev_region_slab_links,
    );
    capability_domain_mod.initSlab(
        KA.capability_domain_slab,
        KA.capability_domain_slab_ptrs,
        KA.capability_domain_slab_links,
    );
    execution_context_mod.initSlab(
        KA.execution_context_slab,
        KA.execution_context_slab_ptrs,
        KA.execution_context_slab_links,
    );
    vmar_mod.initSlab(
        KA.vmar_slab,
        KA.vmar_slab_ptrs,
        KA.vmar_slab_links,
    );
    port_mod.initSlab(
        KA.port_slab,
        KA.port_slab_ptrs,
        KA.port_slab_links,
    );
    page_frame_mod.initSlab(
        KA.page_frame_slab,
        KA.page_frame_slab_ptrs,
        KA.page_frame_slab_links,
    );
    timer_mod.initSlab(
        KA.timer_slab,
        KA.timer_slab_ptrs,
        KA.timer_slab_links,
    );
    virtual_machine_mod.initSlab(
        KA.virtual_machine_slab,
        KA.virtual_machine_slab_ptrs,
        KA.virtual_machine_slab_links,
    );
    perfmon_mod.initSlab(
        KA.pmu_state_slab,
        KA.pmu_state_slab_ptrs,
        KA.pmu_state_slab_links,
    );
}
