const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;

const Range = zag.utils.range.Range;

const PAGE4K: u64 = 0x1000;
const PAGE1G: u64 = 0x40000000;

const MAX_KERNEL_STACKS: u64 = 16384;
pub const KERNEL_STACK_PAGES: u64 = 12;
pub const KERNEL_STACK_SLOT_SIZE: u64 = (KERNEL_STACK_PAGES + 1) * PAGE4K;

const KERNEL_STACKS_RESERVATION: u64 = std.mem.alignForward(u64, MAX_KERNEL_STACKS * KERNEL_STACK_SLOT_SIZE, PAGE1G);
const SLAB_RESERVATION: u64 = 16 * 1024 * 1024;

pub const AddrSpacePartition = arch.paging.addr_space;

pub const UserVA = struct {
    pub const null_guard: Range = arch.paging.user_null_guard;
    pub const aslr: Range = arch.paging.user_aslr;
    pub const static: Range = arch.paging.user_static;
};

pub const KernelVA = struct {
    pub const kernel_stacks: Range = .{
        .start = AddrSpacePartition.kernel.start,
        .end = AddrSpacePartition.kernel.start + KERNEL_STACKS_RESERVATION,
    };

    pub const KernelAllocators = struct {
        pub const vm_node_slab: Range = .{
            .start = kernel_stacks.end,
            .end = kernel_stacks.end + SLAB_RESERVATION,
        };
        pub const shm_slab: Range = .{
            .start = vm_node_slab.end,
            .end = vm_node_slab.end + SLAB_RESERVATION,
        };
        pub const proc_slab: Range = .{
            .start = shm_slab.end,
            .end = shm_slab.end + SLAB_RESERVATION,
        };
        pub const thread_slab: Range = .{
            .start = proc_slab.end,
            .end = proc_slab.end + SLAB_RESERVATION,
        };
        pub const hv_vm_slab: Range = .{
            .start = thread_slab.end,
            .end = thread_slab.end + SLAB_RESERVATION,
        };
        pub const hv_vcpu_slab: Range = .{
            .start = hv_vm_slab.end,
            .end = hv_vm_slab.end + SLAB_RESERVATION,
        };
        pub const pmu_state_slab: Range = .{
            .start = hv_vcpu_slab.end,
            .end = hv_vcpu_slab.end + SLAB_RESERVATION,
        };

        // SecureSlab out-of-band metadata regions. Each gen-protected slab
        // class reserves two sibling regions alongside its data region:
        //   *_slab_ptrs  — dense array of `*T` (one per slot index)
        //   *_slab_links — prev/next u32 pairs backing the circular
        //                  doubly-linked free list
        // Separation is the security property: an OOB write from a T
        // instance cannot reach the address table or the freelist
        // topology from the same primitive.

        pub const shm_slab_ptrs: Range = .{
            .start = pmu_state_slab.end,
            .end = pmu_state_slab.end + SLAB_RESERVATION,
        };
        pub const shm_slab_links: Range = .{
            .start = shm_slab_ptrs.end,
            .end = shm_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const pmu_state_slab_ptrs: Range = .{
            .start = shm_slab_links.end,
            .end = shm_slab_links.end + SLAB_RESERVATION,
        };
        pub const pmu_state_slab_links: Range = .{
            .start = pmu_state_slab_ptrs.end,
            .end = pmu_state_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const thread_slab_ptrs: Range = .{
            .start = pmu_state_slab_links.end,
            .end = pmu_state_slab_links.end + SLAB_RESERVATION,
        };
        pub const thread_slab_links: Range = .{
            .start = thread_slab_ptrs.end,
            .end = thread_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const hv_vm_slab_ptrs: Range = .{
            .start = thread_slab_links.end,
            .end = thread_slab_links.end + SLAB_RESERVATION,
        };
        pub const hv_vm_slab_links: Range = .{
            .start = hv_vm_slab_ptrs.end,
            .end = hv_vm_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const hv_vcpu_slab_ptrs: Range = .{
            .start = hv_vm_slab_links.end,
            .end = hv_vm_slab_links.end + SLAB_RESERVATION,
        };
        pub const hv_vcpu_slab_links: Range = .{
            .start = hv_vcpu_slab_ptrs.end,
            .end = hv_vcpu_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const vm_node_slab_ptrs: Range = .{
            .start = hv_vcpu_slab_links.end,
            .end = hv_vcpu_slab_links.end + SLAB_RESERVATION,
        };
        pub const vm_node_slab_links: Range = .{
            .start = vm_node_slab_ptrs.end,
            .end = vm_node_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const proc_slab_ptrs: Range = .{
            .start = vm_node_slab_links.end,
            .end = vm_node_slab_links.end + SLAB_RESERVATION,
        };
        pub const proc_slab_links: Range = .{
            .start = proc_slab_ptrs.end,
            .end = proc_slab_ptrs.end + SLAB_RESERVATION,
        };

        pub const dev_region_slab: Range = .{
            .start = proc_slab_links.end,
            .end = proc_slab_links.end + SLAB_RESERVATION,
        };
        pub const dev_region_slab_ptrs: Range = .{
            .start = dev_region_slab.end,
            .end = dev_region_slab.end + SLAB_RESERVATION,
        };
        pub const dev_region_slab_links: Range = .{
            .start = dev_region_slab_ptrs.end,
            .end = dev_region_slab_ptrs.end + SLAB_RESERVATION,
        };

        // Spec-v3 SecureSlab regions for the new typed kernel objects.
        // Each typed slab needs a parallel data + ptrs + links region
        // (see SecureSlab init).
        pub const capability_domain_slab: Range = .{
            .start = dev_region_slab_links.end,
            .end = dev_region_slab_links.end + SLAB_RESERVATION,
        };
        pub const capability_domain_slab_ptrs: Range = .{
            .start = capability_domain_slab.end,
            .end = capability_domain_slab.end + SLAB_RESERVATION,
        };
        pub const capability_domain_slab_links: Range = .{
            .start = capability_domain_slab_ptrs.end,
            .end = capability_domain_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const execution_context_slab: Range = .{
            .start = capability_domain_slab_links.end,
            .end = capability_domain_slab_links.end + SLAB_RESERVATION,
        };
        pub const execution_context_slab_ptrs: Range = .{
            .start = execution_context_slab.end,
            .end = execution_context_slab.end + SLAB_RESERVATION,
        };
        pub const execution_context_slab_links: Range = .{
            .start = execution_context_slab_ptrs.end,
            .end = execution_context_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const vmar_slab: Range = .{
            .start = execution_context_slab_links.end,
            .end = execution_context_slab_links.end + SLAB_RESERVATION,
        };
        pub const vmar_slab_ptrs: Range = .{
            .start = vmar_slab.end,
            .end = vmar_slab.end + SLAB_RESERVATION,
        };
        pub const vmar_slab_links: Range = .{
            .start = vmar_slab_ptrs.end,
            .end = vmar_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const port_slab: Range = .{
            .start = vmar_slab_links.end,
            .end = vmar_slab_links.end + SLAB_RESERVATION,
        };
        pub const port_slab_ptrs: Range = .{
            .start = port_slab.end,
            .end = port_slab.end + SLAB_RESERVATION,
        };
        pub const port_slab_links: Range = .{
            .start = port_slab_ptrs.end,
            .end = port_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const page_frame_slab: Range = .{
            .start = port_slab_links.end,
            .end = port_slab_links.end + SLAB_RESERVATION,
        };
        pub const page_frame_slab_ptrs: Range = .{
            .start = page_frame_slab.end,
            .end = page_frame_slab.end + SLAB_RESERVATION,
        };
        pub const page_frame_slab_links: Range = .{
            .start = page_frame_slab_ptrs.end,
            .end = page_frame_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const timer_slab: Range = .{
            .start = page_frame_slab_links.end,
            .end = page_frame_slab_links.end + SLAB_RESERVATION,
        };
        pub const timer_slab_ptrs: Range = .{
            .start = timer_slab.end,
            .end = timer_slab.end + SLAB_RESERVATION,
        };
        pub const timer_slab_links: Range = .{
            .start = timer_slab_ptrs.end,
            .end = timer_slab_ptrs.end + SLAB_RESERVATION,
        };
        pub const virtual_machine_slab: Range = .{
            .start = timer_slab_links.end,
            .end = timer_slab_links.end + SLAB_RESERVATION,
        };
        pub const virtual_machine_slab_ptrs: Range = .{
            .start = virtual_machine_slab.end,
            .end = virtual_machine_slab.end + SLAB_RESERVATION,
        };
        pub const virtual_machine_slab_links: Range = .{
            .start = virtual_machine_slab_ptrs.end,
            .end = virtual_machine_slab_ptrs.end + SLAB_RESERVATION,
        };

        pub const range: Range = .{
            .start = vm_node_slab.start,
            .end = virtual_machine_slab_links.end,
        };
    };
};

comptime {
    @setEvalBranchQuota(20000);
    const T = AddrSpacePartition;
    const info = @typeInfo(T).@"struct";
    const decls = info.decls;
    for (decls, 0..) |decl_i, i| {
        const lhs = @field(T, decl_i.name);
        if (@TypeOf(lhs) != Range) continue;
        for (decls[(i + 1)..]) |decl_j| {
            const rhs = @field(T, decl_j.name);
            if (@TypeOf(rhs) != Range) continue;
            if (lhs.overlapsWith(rhs)) {
                @compileError(std.fmt.comptimePrint(
                    "AddrSpacePartition.{s} overlaps with .{s}",
                    .{ decl_i.name, decl_j.name },
                ));
            }
        }
    }

    const K = KernelVA.KernelAllocators;
    const k_info = @typeInfo(K).@"struct";
    const k_decls = k_info.decls;
    for (k_decls, 0..) |decl_i, i| {
        const lhs = @field(K, decl_i.name);
        if (@TypeOf(lhs) != Range) continue;
        if (std.mem.eql(u8, decl_i.name, "range")) continue;
        if (!AddrSpacePartition.kernel.containsRange(lhs)) {
            @compileError(std.fmt.comptimePrint(
                "KernelAllocators.{s} is outside AddrSpacePartition.kernel",
                .{decl_i.name},
            ));
        }
        for (k_decls[(i + 1)..]) |decl_j| {
            const rhs = @field(K, decl_j.name);
            if (@TypeOf(rhs) != Range) continue;
            if (std.mem.eql(u8, decl_j.name, "range")) continue;
            if (lhs.overlapsWith(rhs)) {
                @compileError(std.fmt.comptimePrint(
                    "KernelAllocators.{s} overlaps with .{s}",
                    .{ decl_i.name, decl_j.name },
                ));
            }
        }
    }

    if (!AddrSpacePartition.kernel.containsRange(KernelVA.kernel_stacks)) {
        @compileError("KernelVA.kernel_stacks is outside AddrSpacePartition.kernel");
    }
    if (!AddrSpacePartition.kernel.containsRange(KernelVA.KernelAllocators.range)) {
        @compileError("KernelVA.KernelAllocators.range is outside AddrSpacePartition.kernel");
    }
    if (KernelVA.kernel_stacks.overlapsWith(KernelVA.KernelAllocators.range)) {
        @compileError("KernelVA.kernel_stacks overlaps KernelVA.KernelAllocators");
    }
}

pub const MemoryPerms = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
    _: u5 = 0,
};

/// Classifies a page mapping site. The arch backend derives cache,
/// global, and privilege bits from the kind. Cache attributes follow
/// the same defaults Linux applies to its analogous mappings.
///
/// `kernel_data`: kernel RAM (heap, kernel ELF, physmap of free
///   memory). WB cache, global, supervisor-only.
/// `kernel_data_local`: kernel RAM that may be unmapped and recycled
///   during normal kernel operation (kernel stacks). Same as
///   `kernel_data` but non-global so cross-core TLB shootdown via the
///   IPI path can reliably invalidate stale entries; with PCIDE=1
///   global entries survive every CR3 reload, and INVLPG + INVPCID
///   type 2 must be free to evict them on remote cores.
///   Intel SDM Vol 3A §5.10 (CR4.PGE / global pages).
/// `kernel_mmio`: kernel-mapped device MMIO (IOMMU registers, ACPI
///   tables, LAPIC). UC cache, non-global, supervisor-only.
/// `user_data`: VMAR-installed RAM exposed to userspace. Cache attribute
///   comes from the VMAR's `cch` field via `mapPageSized`. Non-global,
///   user-accessible.
/// `user_mmio`: VMAR-installed MMIO exposed to userspace. UC cache,
///   non-global, user-accessible.
pub const MappingKind = enum {
    kernel_data,
    kernel_data_local,
    kernel_mmio,
    user_data,
    user_mmio,
};

pub const PAddr = extern struct {
    addr: u64,

    pub fn fromInt(addr: u64) PAddr {
        return .{ .addr = addr };
    }

    pub fn fromVAddr(vaddr: VAddr, addr_space_base: ?u64) PAddr {
        const base = addr_space_base orelse AddrSpacePartition.physmap.start;
        return .{ .addr = vaddr.addr - base };
    }

    pub fn getPtr(self: *const @This(), comptime t: anytype) t {
        return @ptrFromInt(self.addr);
    }
};

pub const VAddr = extern struct {
    addr: u64,

    pub fn fromInt(addr: u64) VAddr {
        return .{ .addr = addr };
    }

    pub fn fromPAddr(paddr: PAddr, addr_space_base: ?u64) VAddr {
        const base = addr_space_base orelse AddrSpacePartition.physmap.start;
        return .{ .addr = paddr.addr + base };
    }

    pub fn getPtr(self: *const @This(), comptime t: anytype) t {
        return @ptrFromInt(self.addr);
    }
};

pub const alignStack = arch.cpu.alignStack;
