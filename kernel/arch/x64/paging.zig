const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const interrupts = zag.arch.x64.interrupts;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const physmap = zag.memory.address.AddrSpacePartition.physmap;
const pmm = zag.memory.pmm;

const MappingKind = zag.memory.address.MappingKind;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VmarCacheType = zag.memory.vmar.CacheType;
const VmarPageSize = zag.memory.vmar.PageSize;

/// First user-mappable virtual address. The NULL guard `[0, 0x1000)` is
/// reserved by spec §[address_space] so that NULL dereferences always
/// fault; this is the upper bound of that guard. Mirrors the value in
/// `arch.dispatch.paging.user_null_guard.end` — repeated locally so the
/// arch backend doesn't reach upward through the dispatch boundary.
const FIRST_USER_PAGE: u64 = 0x1000;

/// Per-MappingKind page-attribute derivation. cache/global/user fields
/// are owned by the arch backend (Intel SDM Vol 3A §5.10, §11.11).
const KindAttrs = struct {
    user_accessible: bool,
    global: bool,
    not_cacheable: bool,
    write_through: bool,
    write_combining: bool,
};

fn kindAttrs(kind: MappingKind) KindAttrs {
    return switch (kind) {
        .kernel_data => .{
            .user_accessible = false,
            .global = true,
            .not_cacheable = false,
            .write_through = false,
            .write_combining = false,
        },
        .kernel_data_local => .{
            .user_accessible = false,
            .global = false,
            .not_cacheable = false,
            .write_through = false,
            .write_combining = false,
        },
        .kernel_mmio => .{
            .user_accessible = false,
            .global = false,
            .not_cacheable = true,
            .write_through = false,
            .write_combining = false,
        },
        .user_data => .{
            .user_accessible = true,
            .global = false,
            .not_cacheable = false,
            .write_through = false,
            .write_combining = false,
        },
        .user_mmio => .{
            .user_accessible = true,
            .global = false,
            .not_cacheable = true,
            .write_through = false,
            .write_combining = false,
        },
    };
}

/// TLB shootdown: serializes the broadcast and tracks per-core ACKs so
/// the initiator can wait for every remote core to invalidate before
/// the freed physical page is recycled.
///
/// Intel SDM Vol 3A §5.10.5 "Propagation of Paging-Structure Changes to
/// Multiple Processors" requires software to broadcast invalidations;
/// this is implemented via IPI + INVLPG on each remote core
/// (§5.10.4.1). The wait is required for kernel-half VAs (kstacks):
/// fire-and-forget would let a remote core's stale TLB entry outlive
/// the unmap and route writes through the recycled physical page,
/// which under §5.10 stays cached even across CR3 reloads (global
/// pages, or with CR4.PCIDE=1 any non-global entry under a PCID
/// re-entered via a no-flush CR3 load).
var shootdown_lock: SpinLock = .{ .class = "paging.shootdown_lock" };

/// Monotonically increasing shootdown sequence number. Initiator
/// fetches+1 under `shootdown_lock`; the remote IPI handler stores its
/// own latest seen value into `shootdown_seen[core]`. Initiator spins
/// on each remote core's `shootdown_seen[core] >= my_seq`. A coalesced
/// IPI that runs the handler once for two enqueued shootdowns is fine:
/// the handler invalidates everything any caller could have cared
/// about (see `tlbShootdownHandler`) and the seen counter advances
/// past both pending sequence numbers in one shot.
var shootdown_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var shootdown_seen: [scheduler_max_cores]std.atomic.Value(u64) =
    [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** scheduler_max_cores;

/// Mirror of `sched.scheduler.MAX_CORES`. Re-declared here to dodge a
/// circular import (sched.scheduler imports arch.dispatch which
/// resolves to this file).
const scheduler_max_cores: u8 = 64;

/// Bracket value advertised to the IPI handler so it knows the latest
/// global sequence number to acknowledge. Updated under
/// `shootdown_lock` before each broadcast.
var shootdown_pending_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// IPI handler for TLB shootdown. Runs on every remote core that
/// receives the broadcast, invalidates the kernel-half non-global TLB
/// entries that could be stale, and records the most-recent
/// `shootdown_pending_seq` it has serviced into the local
/// `shootdown_seen[core_id]` slot. The initiator polls that slot to
/// wait for completion (see `flushRemoteTlb`).
///
/// INVPCID type 2 ("all-context invalidation, retaining globals",
/// Intel SDM Vol 2A "INVPCID") evicts every non-global TLB entry
/// across every PCID, which is what's needed: a kstack VA cached
/// under PCID=A on a remote core that's currently running with
/// PCID=B would otherwise sit on the recycled physical page until
/// PCID=A is next entered via a no-flush CR3 load. Falls back to a
/// `mov %cr4, %cr4` PGE bounce on parts that lack INVPCID — same
/// effect (flushes all non-global entries) at higher cost.
pub fn tlbShootdownHandler(_: *cpu.Context) void {
    kprof.point(.tlb_shootdown, 0);

    if (cpu.invpcid_supported) {
        // INVPCID type 2: all-context invalidation, retaining globals.
        const desc: [2]u64 align(16) = .{ 0, 0 };
        asm volatile ("invpcid (%[desc]), %[type]"
            :
            : [desc] "r" (&desc),
              [type] "r" (@as(u64, 2)),
            : .{ .memory = true });
    } else {
        // CR4.PGE 1→0→1 bounces flush every TLB entry (Intel SDM Vol 3A
        // §5.10.4.1 "Operations that Invalidate TLBs and Paging-
        // Structure Caches" — "Software toggles CR4.PGE").
        var cr4 = asm ("mov %%cr4, %[cr4]"
            : [cr4] "=r" (-> u64),
        );
        const pge_bit: u64 = 1 << 7;
        asm volatile ("mov %[cr4], %%cr4"
            :
            : [cr4] "r" (cr4 & ~pge_bit),
        );
        asm volatile ("mov %[cr4], %%cr4"
            :
            : [cr4] "r" (cr4 | pge_bit),
        );
        _ = &cr4;
    }

    const core_id: u8 = @truncate(apic.coreID());
    const seq = shootdown_pending_seq.load(.acquire);
    shootdown_seen[core_id].store(seq, .release);
}

/// Flush a virtual address from all cores' TLBs and wait for every
/// remote core to acknowledge before returning.
///
/// Intel SDM Vol 3A §5.10.5: software must propagate paging-structure
/// invalidations to every processor that may have cached the old
/// translation. The wait is required because the caller (kstack free
/// path) is about to release the backing physical page back to the
/// PMM. If a remote core still cached the unmapped VA when PMM hands
/// the page out to a new allocation, writes through the stale
/// translation would scribble on the new owner.
///
/// `shootdown_lock` is held only across the broadcast (sequence
/// publish + sendIpi loop) and is dropped before the spin-wait. The
/// previous synchronous attempt held the lock across the wait, which
/// deadlocked when a remote core was spinning to acquire some
/// unrelated lock with IRQs disabled while the lock owner was queued
/// behind `shootdown_lock` to do its own shootdown — A waits for B's
/// IPI ACK, B can't ACK because IRQs are off, IRQs stay off because B
/// is waiting on a lock held by C, C is waiting for `shootdown_lock`,
/// `shootdown_lock` is held by A. Releasing the lock before the wait
/// breaks the cycle: the wait now only depends on remote cores
/// eventually re-enabling IRQs, which they all do as their syscall /
/// IRQ paths unwind.
fn flushRemoteTlb() void {
    const core_count = apic.coreCount();
    if (core_count <= 1) return;

    const self_id = apic.coreID();

    shootdown_lock.lock(@src());

    const my_seq = shootdown_seq.fetchAdd(1, .acq_rel) + 1;
    shootdown_pending_seq.store(my_seq, .release);

    const vec = @intFromEnum(interrupts.IntVecs.tlb_shootdown);
    for (apic.lapics.?, 0..) |la, i| {
        if (i == self_id) continue;
        apic.sendIpi(@intCast(la.apic_id), vec);
    }

    shootdown_lock.unlock();

    // Wait without holding any lock. Each remote core's ack monotonically
    // advances; once `shootdown_seen[i] >= my_seq`, that core has
    // serviced an IPI whose handler ran AFTER our pending_seq publish,
    // so its TLB no longer caches the unmapped VA.
    for (apic.lapics.?, 0..) |_, i| {
        if (i == self_id) continue;
        while (shootdown_seen[i].load(.acquire) < my_seq) std.atomic.spinLoopHint();
    }
}

/// Page-table entry for 4-level paging.
///
/// Intel SDM Vol 3A, Table 5-20 "Format of a Page-Table Entry that Maps a
/// 4-KByte Page". The same layout is used for non-leaf entries that reference
/// the next paging structure (Tables 5-15, 5-17, 5-19) with minor field
/// reinterpretation (e.g. bit 7 is PS instead of PAT in directory entries).
pub const PageEntry = packed struct(u64) {
    /// Bit 0 (P) -- Intel SDM Vol 3A, Table 5-20: must be 1 to map a page.
    present: bool = false,
    /// Bit 1 (R/W) -- Intel SDM Vol 3A, Table 5-20: if 0, writes are not allowed.
    writable: bool = false,
    /// Bit 2 (U/S) -- Intel SDM Vol 3A, Table 5-20: if 0, user-mode accesses are not allowed.
    user_accessible: bool = false,
    /// Bit 3 (PWT) -- Intel SDM Vol 3A, Table 5-20: page-level write-through.
    write_through: bool = false,
    /// Bit 4 (PCD) -- Intel SDM Vol 3A, Table 5-20: page-level cache disable.
    not_cacheable: bool = false,
    /// Bit 5 (A) -- Intel SDM Vol 3A, Table 5-20: set by hardware on access.
    accessed: bool = false,
    /// Bit 6 (D) -- Intel SDM Vol 3A, Table 5-20: set by hardware on write.
    dirty: bool = false,
    /// Bit 7 -- Intel SDM Vol 3A, Table 5-20: PAT bit for 4-KByte PTEs;
    /// Table 5-18: PS (page size) for PDEs that map 2-MByte pages.
    /// In leaf L1 entries this kernel uses it as the PAT index bit to select
    /// write-combining memory type (Section 5.9.2).
    huge_page: bool = false,
    /// Bit 8 (G) -- Intel SDM Vol 3A, Table 5-20: global; if CR4.PGE = 1,
    /// the translation is not invalidated on MOV to CR3 (Section 5.10).
    global: bool = false,
    /// Bits 10:9 -- ignored by hardware.
    ignored: u3 = 0,
    /// Bits M-1:12 -- Intel SDM Vol 3A, Table 5-20: physical address of the
    /// 4-KByte page (or next paging structure for non-leaf entries).
    addr: u40 = 0,
    _res: u11 = 0,
    /// Bit 63 (XD) -- Intel SDM Vol 3A, Table 5-20: execute-disable when
    /// IA32_EFER.NXE = 1; instruction fetches are not allowed from the page.
    not_executable: bool = false,

    pub fn setPAddr(self: *PageEntry, paddr: PAddr) void {
        std.debug.assert(std.mem.isAligned(paddr.addr, paging.PAGE4K));
        self.addr = @intCast(paddr.addr >> l1sh);
    }

    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << l1sh;
        return PAddr.fromInt(addr);
    }
};

const default_page_entry = PageEntry{};

const page_entry_table_size = 512;

/// Level shift constants for 4-level paging linear-address translation.
///
/// Intel SDM Vol 3A, Figure 5-8 "Linear-Address Translation to a 4-KByte
/// Page Using 4-Level Paging":
///   - Bits 47:39 index the PML4 table  (l4sh = 39)
///   - Bits 38:30 index the PDPT         (l3sh = 30)
///   - Bits 29:21 index the page directory (l2sh = 21)
///   - Bits 20:12 index the page table    (l1sh = 12)
///   - Bits 11:0  are the page offset
const l4sh: u6 = 39;
const l3sh: u6 = 30;
const l2sh: u6 = 21;
const l1sh: u6 = 12;

fn l4Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l4sh);
}

fn l3Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l3sh);
}

fn l2Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l2sh);
}

fn l1Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l1sh);
}

/// Return the physical address of the current PML4 table from CR3.
///
/// Intel SDM Vol 3A, Table 5-12 "Use of CR3 with 4-Level Paging and
/// 5-Level Paging and CR4.PCIDE = 0": bits M-1:12 hold the physical
/// address of the 4-KByte aligned PML4 table.
pub fn getAddrSpaceRoot() PAddr {
    const cr3 = cpu.readCr3();
    const mask: u64 = 0xFFF;
    return PAddr.fromInt(cr3 & ~mask);
}

/// Boot-time CR3 write used by the bootloader to install the kernel
/// page-table root before CR4.PCIDE has been enabled. With PCIDE=0 the
/// CR3 source operand's PCID/no-flush bits are reserved and must be
/// clear — `swapAddrSpace` cannot be used here. Always flushes the TLB.
pub fn setKernelAddrSpace(root: PAddr) void {
    cpu.writeCr3(root.addr);
}

/// Load a new PML4 table address into CR3, switching the active address space.
///
/// With CR4.PCIDE=1, CR3 carries the per-process PCID in bits[11:0] and a
/// "preserve TLB" hint in bit 63. Setting bit 63 tells the CPU not to
/// invalidate TLB entries on this CR3 write — entries from other PCIDs
/// stay cached and are simply ignored on lookup mismatch (Intel SDM Vol 3A
/// §5.10.4.1). Combined with CR4.PGE for global kernel pages, an
/// address-space switch costs effectively zero TLB work.
pub fn swapAddrSpace(root: PAddr, id: u16) void {
    if (!cpu.pcid_enabled) {
        cpu.writeCr3(root.addr);
        return;
    }
    const pcid: u64 = @as(u64, id) & 0xFFF;
    const no_flush: u64 = @as(u64, 1) << 63;
    cpu.writeCr3((root.addr & ~@as(u64, 0xFFF)) | pcid | no_flush);
}

/// Copy the upper-half (kernel) PML4 entries from the current address space
/// into a new PML4 table. Entries 256..511 cover the kernel's virtual
/// address range (bits 47:39 >= 256, i.e. canonical high-half addresses).
///
/// Intel SDM Vol 3A, Section 5.5.4, Figure 5-8 -- bits 47:39 of the linear
/// address select the PML4 entry; the upper 256 entries map the kernel half.
pub fn copyKernelMappings(root: VAddr) void {
    const src_root_phys = getAddrSpaceRoot();
    const src_root_virt = VAddr.fromPAddr(src_root_phys, null);
    const src = src_root_virt.getPtr([*]PageEntry);
    const dst = root.getPtr([*]PageEntry);

    for (256..page_entry_table_size) |i| {
        dst[i] = src[i];
    }
}

/// Clear the lower-half (user/identity) PML4 entries and flush the TLB
/// by reloading CR3.
///
/// Intel SDM Vol 3A, Section 5.10.4.1 -- MOV to CR3 invalidates all
/// non-global TLB entries for the current PCID.
pub fn dropIdentityMapping() void {
    const root_phys = getAddrSpaceRoot();
    const root_virt = VAddr.fromPAddr(root_phys, null);
    const root = root_virt.getPtr([*]PageEntry);

    for (0..256) |i| {
        root[i] = default_page_entry;
    }

    cpu.writeCr3(root_phys.addr);
}

/// Map a 4-KByte physical page at the given virtual address.
///
/// Intel SDM Vol 3A, Section 5.5.4 "Linear-Address Translation with 4-Level
/// Paging and 5-Level Paging" -- walks PML4 -> PDPT -> PD -> PT, allocating
/// intermediate tables as needed, then writes the leaf PTE (Table 5-20).
pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
    kind: MappingKind,
) !void {
    kprof.point(.map_page, virt.addr);
    std.debug.assert(std.mem.isAligned(phys.addr, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.PAGE4K));

    const pmm_mgr = &pmm.global_pmm.?;

    const attrs = kindAttrs(kind);
    if (attrs.user_accessible) {
        // Spec §[address_space]: NULL guard `[0, 0x1000)` must always
        // fault. No mapping path may install a leaf into the first page.
        std.debug.assert(virt.addr >= FIRST_USER_PAGE);
    }
    const writable = perms.write;
    const not_executable = !perms.exec;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = attrs.user_accessible,
    };

    // For L1 leaf entries, bit 7 (huge_page) is the PAT index bit
    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = attrs.user_accessible,
        .write_through = attrs.write_through or attrs.write_combining,
        .not_cacheable = attrs.not_cacheable,
        .huge_page = attrs.write_combining,
        .global = attrs.global,
        .not_executable = not_executable,
    };

    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            entry.* = parent_entry;
            entry.setPAddr(new_phys);
        }
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    l1_entry.* = leaf_entry;
    l1_entry.setPAddr(phys);
}

/// Boot-time page mapping supporting 4-KByte, 2-MByte, and 1-GByte pages.
///
/// Intel SDM Vol 3A, Section 5.5.4 -- walks the paging hierarchy, with
/// early termination for huge pages (Table 5-16 for 1-GByte PDPTE with
/// PS=1, Table 5-18 for 2-MByte PDE with PS=1).
pub fn mapPageBoot(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    kind: MappingKind,
    allocator: std.mem.Allocator,
) !void {
    std.debug.assert(std.mem.isAligned(phys.addr, paging.pageAlign(size).toByteUnits()));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.pageAlign(size).toByteUnits()));

    const attrs = kindAttrs(kind);
    const writable = perms.write;
    const not_executable = !perms.exec;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = attrs.user_accessible,
    };

    // For L1 leaf entries, bit 7 (huge_page) is the PAT index bit
    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = attrs.user_accessible,
        .write_through = attrs.write_through or attrs.write_combining,
        .not_cacheable = attrs.not_cacheable,
        .huge_page = attrs.write_combining,
        .global = attrs.global,
        .not_executable = not_executable,
    };

    const l4_idx = l4Idx(virt);
    const l3_idx = l3Idx(virt);
    const l2_idx = l2Idx(virt);
    const l1_idx = l1Idx(virt);

    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(addr_space_root.addr);
    var entry = &table[l4_idx];
    var level_entry_size: PageSize = .page1g;
    const use_physmap = physmap.contains(addr_space_root.addr);

    for (0..3) |i| {
        if (!entry.present) {
            const new_entry: []align(paging.PAGE4K) PageEntry = try allocator.alignedAlloc(
                PageEntry,
                paging.pageAlign(.page4k),
                page_entry_table_size,
            );
            @memset(new_entry, default_page_entry);
            entry.* = parent_entry;

            const new_entry_virt = VAddr.fromInt(@intFromPtr(new_entry.ptr));
            var new_entry_phys: PAddr = undefined;
            if (use_physmap) {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, null);
            } else {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, 0);
            }
            entry.setPAddr(new_entry_phys);
        }

        var entry_virt: VAddr = undefined;
        if (use_physmap) {
            entry_virt = VAddr.fromPAddr(entry.getPAddr(), null);
            std.debug.assert(physmap.contains(entry_virt.addr));
        } else {
            entry_virt = VAddr.fromPAddr(entry.getPAddr(), 0);
            std.debug.assert(!physmap.contains(entry_virt.addr));
        }

        table = @ptrFromInt(entry_virt.addr);
        const idx = switch (i) {
            0 => l3_idx,
            1 => l2_idx,
            2 => l1_idx,
            else => unreachable,
        };
        entry = &table[idx];

        if (size == level_entry_size) {
            entry.* = leaf_entry;
            if (level_entry_size != .page4k) entry.huge_page = true;
            entry.setPAddr(phys);
            return;
        }

        if (i == 0) {
            level_entry_size = .page2m;
        } else if (i == 1) {
            level_entry_size = .page4k;
        }
    }
}

/// Unmap a 4-KByte page and return its physical address, or null if not mapped.
///
/// Intel SDM Vol 3A, Section 5.5.4 -- walks PML4 -> PDPT -> PD -> PT to find
/// the leaf PTE, clears it, then invalidates the local TLB with INVLPG
/// (Section 5.10.4.1) and broadcasts a shootdown IPI to remote cores
/// (Section 5.10.5).
pub fn unmapPage(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    kprof.point(.unmap_page, virt.addr);
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return null;
        if (entry.huge_page) return null;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    const phys = l1_entry.getPAddr();
    l1_entry.* = default_page_entry;
    cpu.invlpg(virt.addr);

    // Shoot down remote TLBs on every unmap, user-space AND kernel-space.
    //
    // The earlier version only shot down for user addresses, on the
    // assumption that kernel mappings were identical across cores and
    // therefore couldn't go stale. That assumption is wrong: when
    // `thread_kill` tears down a kernel thread (`stack.destroyKernel`),
    // it unmaps the dying thread's kernel-stack pages from the killer
    // core and frees the physical pages back to the PMM. The physical
    // pages are immediately reusable — a subsequent allocation can
    // hand them out to a completely unrelated kernel data structure.
    // Meanwhile, any OTHER core that had those old kernel-stack VAs
    // cached in its TLB (because the dying thread last ran there)
    // still translates the old VA to the now-reused physical page. If
    // that remote core touches anything in that old VA range before
    // its TLB happens to evict the entry, it reads/writes a completely
    // unrelated kernel object — silent cross-core memory corruption.
    //
    // This is the root cause of the long-standing `s2_4_9` flake. The
    // test pins a spinning worker to core 1 via `set_affinity`,
    // suspends it (cross-core IPI), then `thread_kill`s it from core 0.
    // `thread_kill` runs `deinit -> destroyKernel -> unmapPage` on
    // core 0; the worker's kernel stack pages are unmapped locally on
    // core 0 but core 1's TLB still maps them. The freed pages land
    // wherever PMM's next allocation sends them, and the resulting
    // corruption manifests as a hang on the subsequent `serial.write`
    // path in ~60% of multi-core runs (see commit message for the
    // visible symptom on `[PASS] §2.4.9` truncation).
    //
    // Paying for a remote-TLB shootdown on every unmap is fine because
    // the kernel rarely unmaps pages outside of process teardown and
    // stack destruction — both are already slow-path operations. The
    // shootdown is synchronous: we don't return (and therefore don't
    // free the physical page in `destroyKernel`) until every remote
    // core has acknowledged the IPI. See `flushRemoteTlb`.
    flushRemoteTlb();

    return phys;
}

/// Recursively walk the 4-level paging hierarchy for the user half of the
/// address space (PML4 indices 0–255) and free all leaf pages and table pages.
/// Intel SDM Vol 3A, §4.5 "4-Level Paging and 5-Level Paging" — the hierarchy
/// is PML4 → PDPT → PD → PT; each table is a 4-KB page of 512 eight-byte
/// entries. Only PML4 entries 0–255 cover user space (canonical low half).
/// Walk the 4-level paging hierarchy and return the physical address mapped
/// at the given virtual address, or null if not mapped.
///
/// Intel SDM Vol 3A, Section 5.5.4 -- performs a software page-table walk
/// through PML4 -> PDPT -> PD -> PT (Tables 5-15, 5-17, 5-19, 5-20).
pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return null;
        if (entry.huge_page) return null;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    return l1_entry.getPAddr();
}

pub fn mapPageSized(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
    cch: VmarCacheType,
    perms: MemoryPerms,
) !void {
    _ = cch;
    // v0: only 4 KiB pages supported through the VMAR-side map path.
    // 2 MiB / 1 GiB landings go through `mapPageBoot` for the kernel
    // address space; userspace VARs are spec'd over 4 KiB throughout
    // the test runner so the simple fallback covers what the runner
    // exercises.
    std.debug.assert(sz == .sz_4k);
    return mapPage(addr_space_root, phys, virt, perms, .user_data);
}

pub fn unmapPageSized(
    addr_space_root: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
) ?PAddr {
    std.debug.assert(sz == .sz_4k);
    return unmapPage(addr_space_root, virt);
}

/// Allocate a fresh PML4 table for a new capability domain. Kernel
/// mappings (entries 256..511) are copied from the current address
/// space so kernel addresses translate identically; user-half entries
/// (0..255) come up empty for the caller to populate.
///
/// Intel SDM Vol 3A, Section 5.5.4: PML4 = 4 KiB-aligned table of 512
/// PageEntry slots. Section 5.10.4: kernel-shared mappings rely on
/// CR4.PGE = 1 and PageEntry.global = 1, but the PML4 entries themselves
/// (the table pointers) must be replicated into every address-space
/// root because the L4 walk indexes them by linear address bits 47:39.
pub fn allocAddrSpaceRoot() !PAddr {
    const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
    const new_table = try pmm_mgr.create(paging.PageMem(.page4k));
    const new_virt = VAddr.fromInt(@intFromPtr(new_table));
    copyKernelMappings(new_virt);
    return PAddr.fromVAddr(new_virt, null);
}

pub fn shootdownTlbRange(
    addr_space_id: u16,
    virt: VAddr,
    sz: VmarPageSize,
    page_count: u32,
) void {
    _ = addr_space_id;
    std.debug.assert(sz == .sz_4k);
    var i: u32 = 0;
    while (i < page_count) {
        const va = virt.addr + @as(u64, i) * paging.PAGE4K;
        cpu.invlpg(va);
        flushRemoteTlb();
        i += 1;
    }
}

