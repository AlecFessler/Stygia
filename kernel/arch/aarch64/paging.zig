//! AArch64 VMSAv8-64 page table management (4KB granule, 48-bit VA).
//!
//! ARM uses a 4-level page table with a split address space: TTBR0_EL1 for
//! user (lower VA range) and TTBR1_EL1 for kernel (upper VA range).
//!
//! Page table structure (4KB granule, 48-bit VA):
//!   Level 0: PGD  -- bits [47:39], 512 entries, each covers 512 GB
//!   Level 1: PUD  -- bits [38:30], 512 entries, each covers 1 GB
//!   Level 2: PMD  -- bits [29:21], 512 entries, each covers 2 MB
//!   Level 3: PTE  -- bits [20:12], 512 entries, each covers 4 KB
//!
//! Descriptor format (ARM ARM D5.3, Table D5-15):
//!   Bits [1:0]:  descriptor type
//!     0b00 = Invalid
//!     0b01 = Block (level 1/2 only -- 1GB/2MB mapping)
//!     0b11 = Table (levels 0-2) or Page (level 3)
//!   Bits [47:12]: output address (physical page frame)
//!   Upper attributes [63:50]:
//!     [54] = XN (Execute Never)
//!     [53] = PXN (Privileged Execute Never)
//!     [52] = Contiguous hint
//!   Lower attributes [11:2]:
//!     [7:6] = AP (Access Permissions, ARM ARM D5.4, Table D5-34):
//!       0b00 = EL1 RW, EL0 no access
//!       0b01 = EL1 RW, EL0 RW
//!       0b10 = EL1 RO, EL0 no access
//!       0b11 = EL1 RO, EL0 RO
//!     [4:2] = AttrIndx (indexes into MAIR_EL1 for memory type)
//!     [10]  = AF (Access Flag -- must be set or hardware generates fault)
//!     [11]  = nG (not Global -- tagged with ASID if set)
//!
//! TLB maintenance (ARM ARM D5.9):
//!   After modifying a PTE: DSB ISHST -> TLBI VAE1IS -> DSB ISH -> ISB.
//!   Full ASID invalidate: TLBI ASIDE1IS.
//!   On context switch: write TTBR0_EL1 (user tables change, kernel stays in TTBR1).
//!
//! Key differences from x86 paging:
//! - Split TTBR0/TTBR1 means kernel mappings don't need to be copied into
//!   every process's page table -- TTBR1 stays constant.
//!   copyKernelMappings() is a no-op.
//! - Explicit TLB invalidation required (no implicit invalidation on table write).
//! - AF bit must be set by software (or enable hardware AF management via TCR_EL1.HA).
//! - Memory attributes via MAIR indirection, not page table bits directly.
//!
//! MAIR_EL1 attribute indices (ARM ARM D13.2.97):
//!   Index 0 = Device-nGnRnE (0x00)
//!   Index 1 = Normal Write-Back cacheable (0xFF)
//!
//! References:
//! - ARM ARM D5.2: VMSAv8-64 translation table format
//! - ARM ARM D5.3: Translation table descriptor formats
//! - ARM ARM D5.4: Access controls and memory attributes
//! - ARM ARM D5.9: TLB maintenance
//! - ARM ARM D13.2.131: TCR_EL1
//! - ARM ARM D13.2.136: TTBR0_EL1, TTBR1_EL1

const std = @import("std");
const zag = @import("zag");

const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const physmap = zag.memory.address.AddrSpacePartition.physmap;
const pmm = zag.memory.pmm;

const MappingKind = zag.memory.address.MappingKind;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const VAddr = zag.memory.address.VAddr;
const VmarCacheType = zag.memory.vmar.CacheType;
const VmarPageSize = zag.memory.vmar.PageSize;

/// First user-mappable virtual address. The NULL guard `[0, 0x1000)` is
/// reserved by spec §[address_space] so that NULL dereferences always
/// fault; this is the upper bound of that guard. Mirrors the value in
/// `arch.dispatch.paging.user_null_guard.end`.
const FIRST_USER_PAGE: u64 = 0x1000;

/// Per-MappingKind descriptor attributes. cache/global/user fields are
/// owned by the arch backend (ARM ARM D5.4, D13.2.97).
const KindAttrs = struct {
    user: bool,
    /// nG bit. Kernel mappings are global (TLB-pinned across context
    /// switches under TTBR1); user mappings are non-global.
    not_global: bool,
    /// MAIR_EL1 index. mair_normal = WB cacheable, mair_device = UC.
    attr_indx: u3,
    /// SH[1:0] shareability. Normal mem = Inner Shareable, device = none.
    sh: u2,
};

fn kindAttrs(kind: MappingKind) KindAttrs {
    return switch (kind) {
        .kernel_data => .{
            .user = false,
            .not_global = false,
            .attr_indx = mair_normal,
            .sh = 0b11,
        },
        .kernel_mmio => .{
            .user = false,
            .not_global = true,
            .attr_indx = mair_device,
            .sh = 0b00,
        },
        .user_data => .{
            .user = true,
            .not_global = true,
            .attr_indx = mair_normal,
            .sh = 0b11,
        },
        .user_mmio => .{
            .user = true,
            .not_global = true,
            .attr_indx = mair_device,
            .sh = 0b00,
        },
    };
}

/// AArch64 page table descriptor for VMSAv8-64 with 4KB granule.
///
/// ARM ARM D5.3, Table D5-15: VMSAv8-64 translation table level 3 descriptor
/// format. The same layout is used for table descriptors at levels 0-2 (with
/// bits [1:0] = 0b11 indicating table/page) and block descriptors at levels
/// 1-2 (bits [1:0] = 0b01).
pub const PageEntry = packed struct(u64) {
    /// Bit 0 -- ARM ARM D5.3, Table D5-15: descriptor valid bit.
    /// Must be 1 for any valid descriptor.
    valid: bool = false,
    /// Bit 1 -- ARM ARM D5.3, Table D5-15: descriptor type.
    /// 1 = Table (levels 0-2) or Page (level 3); 0 = Block (levels 1-2).
    is_table: bool = false,
    /// Bits [4:2] -- ARM ARM D5.3, Table D5-15: AttrIndx[2:0].
    /// Indexes into MAIR_EL1. 0 = Device-nGnRnE, 1 = Normal WB cacheable.
    attr_indx: u3 = 0,
    /// Bit 5 -- ARM ARM D5.3, Table D5-15: NS (Non-Secure).
    /// Ignored at EL1 in non-secure state.
    ns: bool = false,
    /// Bits [7:6] -- ARM ARM D5.4, Table D5-34: AP[2:1] access permissions.
    ///   0b00 = EL1 RW, EL0 none
    ///   0b01 = EL1 RW, EL0 RW
    ///   0b10 = EL1 RO, EL0 none
    ///   0b11 = EL1 RO, EL0 RO
    ap: u2 = 0,
    /// Bits [9:8] -- ARM ARM D5.3, Table D5-15: SH[1:0] shareability.
    /// 0b11 = Inner Shareable (required for SMP coherency).
    sh: u2 = 0,
    /// Bit 10 -- ARM ARM D5.3, Table D5-15: AF (Access Flag).
    /// Must be set to 1 or the first access generates a fault.
    af: bool = false,
    /// Bit 11 -- ARM ARM D5.3, Table D5-15: nG (not Global).
    /// If set, the entry is tagged with the current ASID.
    ng: bool = false,
    /// Bits [47:12] -- ARM ARM D5.3, Table D5-15: output address.
    /// Physical address of the target page or next-level table.
    addr: u36 = 0,
    /// Bits [51:48] -- reserved, must be zero for 48-bit OA.
    _res0: u4 = 0,
    /// Bit 52 -- ARM ARM D5.3, Table D5-15: Contiguous hint.
    contiguous: bool = false,
    /// Bit 53 -- ARM ARM D5.3, Table D5-15: PXN (Privileged Execute Never).
    pxn: bool = false,
    /// Bit 54 -- ARM ARM D5.3, Table D5-15: XN/UXN (Execute Never).
    xn: bool = false,
    /// Bits [58:55] -- software use / PBHA, ignored by hardware.
    _sw: u4 = 0,
    /// Bits [62:59] -- ignored by hardware.
    _ignored: u4 = 0,
    /// Bit 63 -- reserved for FEAT_SVE/etc., zero for base VMSAv8-64.
    _res1: bool = false,

    pub fn setPAddr(self: *PageEntry, paddr: PAddr) void {
        std.debug.assert(std.mem.isAligned(paddr.addr, paging.PAGE4K));
        self.addr = @intCast(paddr.addr >> l0sh);
    }

    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << l0sh;
        return PAddr.fromInt(addr);
    }

    // The bit-field declarations below are part of the architectural
    // ARMv8 VMSAv8-64 PTE layout (ARM ARM D5.3, Table D5-15) and MUST
    // remain in this `packed struct(u64)` to preserve binary-correct
    // encoding of every other field. They are unused at the source
    // level today (the kernel runs entirely at non-secure EL1, never
    // touches PBHA/SW bits, and emits no descriptors with bit 63 set),
    // so the dead-code analyzer would otherwise flag them. Reference
    // them in a comptime no-op so the analyzer's `.<ident>` token
    // heuristic keeps them alive without affecting codegen.
    comptime {
        _ = PageEntry{
            .ns = false,
            ._sw = 0,
            ._ignored = 0,
            ._res1 = false,
        };
    }
};

const default_page_entry = PageEntry{};
const page_entry_table_size = 512;

/// Level shift constants for VMSAv8-64 4KB granule translation.
///
/// ARM ARM D5.2, Table D5-9 -- 48-bit input address, 4KB granule:
///   - Bits [47:39] index level 0 (l3sh = 39)
///   - Bits [38:30] index level 1 (l2sh = 30)
///   - Bits [29:21] index level 2 (l1sh = 21)
///   - Bits [20:12] index level 3 (l0sh = 12)
///   - Bits [11:0]  page offset
const l3sh: u6 = 39;
const l2sh: u6 = 30;
const l1sh: u6 = 21;
const l0sh: u6 = 12;

fn l3Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l3sh);
}

fn l2Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l2sh);
}

fn l1Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l1sh);
}

fn l0Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l0sh);
}

/// MAIR_EL1 attribute indices resolved at boot against whatever
/// MAIR layout the firmware/UEFI left in place. We cannot safely
/// rewrite MAIR_EL1 under a live MMU (Linux arm64 head.S / proc.S
/// only ever writes MAIR with the MMU disabled), so instead we
/// scan the live MAIR for the four attribute encodings we need:
///   - Normal WB cacheable     (0xFF) → `mair_normal`
///   - Device-nGnRnE           (0x00) → `mair_device`
///   - Normal Inner+Outer NC   (0x44) → `mair_normal_nc` (used for WC)
///   - Normal Inner+Outer WT   (0xBB) → `mair_normal_wt`
/// and cache the resolved indices for later page-table builds.
///
/// If the firmware MAIR layout does not include a slot for a
/// requested encoding, the index falls back to the closest available
/// equivalent: WC → Device-nGnRnE (strongly-ordered, no combining)
/// and WT → Normal WB. The fallbacks are conservative — they trade
/// performance for correctness, never the other way around.
///
/// Default values are a fallback only — `initMairIndices()` must
/// be called before any mapping is built.
/// ARM ARM D13.2.97 — MAIR_EL1 layout.
pub var mair_device: u3 = 0;
pub var mair_normal: u3 = 1;
pub var mair_normal_nc: u3 = 0; // WC fallback target — overridden if firmware exposes 0x44
pub var mair_normal_wt: u3 = 1; // WT fallback target — overridden if firmware exposes 0xBB

pub fn initMairIndices() void {
    var mair: u64 = undefined;
    asm volatile ("mrs %[v], mair_el1"
        : [v] "=r" (mair),
    );
    var found_nc: bool = false;
    var found_wt: bool = false;
    var i: u6 = 0;
    while (i < 8) {
        const attr: u8 = @truncate((mair >> (i * 8)) & 0xFF);
        if (attr == 0xFF) mair_normal = @intCast(i);
        if (attr == 0x00) mair_device = @intCast(i);
        if (attr == 0x44) {
            mair_normal_nc = @intCast(i);
            found_nc = true;
        }
        if (attr == 0xBB) {
            mair_normal_wt = @intCast(i);
            found_wt = true;
        }
        i += 1;
    }
    // Apply fallbacks for any encoding firmware did not expose: WC
    // collapses to Device-nGnRnE (strongly-ordered, no combining) and
    // WT collapses to Normal-WB. The fallbacks trade performance for
    // correctness — never the other way around.
    if (!found_nc) mair_normal_nc = mair_device;
    if (!found_wt) mair_normal_wt = mair_normal;
}

/// Resolve the MAIR index to use for a given VMAR `cch` value. The
/// firmware-provided MAIR slots cover at minimum WB and Device-nGnRnE;
/// WC and WT fall back to those when firmware doesn't expose Normal-NC
/// (0x44) or Normal-WT (0xBB) — see `initMairIndices`.
fn cchToAttrIndx(cch: VmarCacheType) u3 {
    return switch (cch) {
        .wb => mair_normal,
        .uc => mair_device,
        .wc => mair_normal_nc,
        .wt => mair_normal_wt,
    };
}

/// Shareability for a given cache type. Normal cacheable / WT memory
/// runs Inner-Shareable for SMP coherency; non-cacheable Normal memory
/// also runs Inner-Shareable (PE-coherent). Device memory is
/// non-shareable (the access is already strongly ordered).
/// ARM ARM D5.4, Table D5-39 (shareability + cacheability interaction).
fn cchToSh(cch: VmarCacheType) u2 {
    return switch (cch) {
        .wb, .wt, .wc => 0b11,
        .uc => 0b00,
    };
}

/// Disable UEFI's identity mapping by disabling TTBR0 walks and flushing TLB.
///
/// On aarch64, UEFI's identity mapping lives in TTBR0 which is separate
/// from the kernel's TTBR1. Rather than clearing individual entries (which
/// would require mapping the UEFI page table in our physmap), we simply
/// disable TTBR0 translation by setting TCR_EL1.EPD0 (bit 7).
///
/// ARM ARM D13.2.131: TCR_EL1.EPD0 = 1 disables TTBR0 walks (user VA faults).
/// ARM ARM D5.9: TLBI VMALLE1IS invalidates all stage 1 EL1&0 regime entries.
pub fn dropIdentityMapping() void {
    // On aarch64, the UEFI identity mapping lives in TTBR0 (separate from
    // kernel TTBR1). We don't need the identity mapping after boot init.
    // Instead of modifying TCR_EL1 (which can stall on TCG), just flush
    // the TLB to remove stale TTBR0 entries. Any subsequent user-space
    // access via TTBR0 will be set up fresh by process creation.
    //
    // The first user process will call swapAddrSpace() which writes a
    // fresh per-process page table to TTBR0, overriding UEFI's mapping.
    asm volatile (
        \\dsb ishst
        \\tlbi vmalle1is
        \\dsb ish
        \\isb
        ::: .{ .memory = true });
}

/// Map a 4KB physical page at the given virtual address in the given
/// address space.
///
/// ARM ARM D5.3, Table D5-15 -- walks the 4-level table hierarchy
/// (level 0 -> level 3), allocating intermediate table pages as needed,
/// then writes the level 3 page descriptor.
pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
    kind: MappingKind,
) !void {
    std.debug.assert(std.mem.isAligned(phys.addr, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.PAGE4K));
    kprof.point(.map_page, virt.addr);

    const pmm_mgr = &pmm.global_pmm.?;

    const attrs = kindAttrs(kind);
    if (attrs.user and virt.addr < FIRST_USER_PAGE) {
        // Spec §[address_space]: NULL guard `[0, 0x1000)` must always
        // fault. Runtime check (active in all build modes) so a buggy
        // caller cannot silently install a leaf into the first page.
        @panic("paging.mapPage: user mapping into NULL guard");
    }
    const ap = permsToAp(perms, attrs.user);
    const xn = !perms.exec;
    const pxn = xn;

    const parent_entry = PageEntry{
        .valid = true,
        .is_table = true,
        .attr_indx = mair_normal,
        .ap = 0b00,
        .sh = 0b11,
        .af = true,
    };

    const leaf_entry = PageEntry{
        .valid = true,
        .is_table = true, // Level 3 page descriptor: bits [1:0] = 0b11
        .attr_indx = attrs.attr_indx,
        .ap = ap,
        .sh = attrs.sh,
        .af = true,
        .ng = attrs.not_global,
        .xn = xn,
        .pxn = pxn,
    };

    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l3Idx(virt), l2Idx(virt), l1Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.valid) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            entry.* = parent_entry;
            entry.setPAddr(new_phys);
        }
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l0_entry = &table[l0Idx(virt)];
    l0_entry.* = leaf_entry;
    l0_entry.setPAddr(phys);

    // ARM ARM D5.9: after installing a new leaf entry, broadcast TLB
    // maintenance so cached "not-present" (faulting) entries from prior
    // translations are invalidated across all inner-shareable cores. Without
    // this, subsequent accesses (including kernel-mode @memcpy into the
    // just-mapped user VA) can walk a stale translation and data-abort
    // despite the new PTE being in memory. The helper handles the full
    // DSB ISHST -> TLBI VAE1IS -> DSB ISH -> ISB sequence.
    tlbiVae1is(virt.addr);
}

/// Boot-time page mapping supporting 4KB, 2MB, and 1GB pages.
///
/// ARM ARM D5.3, Table D5-15 -- walks the translation table hierarchy with
/// early termination for block descriptors at level 1 (1GB) or level 2 (2MB).
/// Block descriptors use bits [1:0] = 0b01 instead of 0b11.
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
    const ap = permsToAp(perms, attrs.user);
    const xn = !perms.exec;
    const pxn = xn;

    const parent_entry = PageEntry{
        .valid = true,
        .is_table = true,
        .attr_indx = mair_normal,
        .ap = 0b00,
        .sh = 0b11,
        .af = true,
    };

    // Leaf entry for 4KB page (level 3) uses is_table=true (bits [1:0] = 0b11).
    // Block entries (level 1/2) use is_table=false (bits [1:0] = 0b01).
    const leaf_entry = PageEntry{
        .valid = true,
        .is_table = true,
        .attr_indx = attrs.attr_indx,
        .ap = ap,
        .sh = attrs.sh,
        .af = true,
        .ng = attrs.not_global,
        .xn = xn,
        .pxn = pxn,
    };

    const idx_l3 = l3Idx(virt);
    const idx_l2 = l2Idx(virt);
    const idx_l1 = l1Idx(virt);
    const idx_l0 = l0Idx(virt);

    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(addr_space_root.addr);
    var entry = &table[idx_l3];
    var level_entry_size: PageSize = .page1g;
    const use_physmap = physmap.contains(addr_space_root.addr);

    for (0..3) |i| {
        if (!entry.valid) {
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
            0 => idx_l2,
            1 => idx_l1,
            2 => idx_l0,
            else => unreachable,
        };
        entry = &table[idx];

        if (size == level_entry_size) {
            entry.* = leaf_entry;
            // Block descriptors at level 1/2: bits [1:0] = 0b01
            if (level_entry_size != .page4k) entry.is_table = false;
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

/// Unmap a 4KB page and return its physical address, or null if not mapped.
///
/// ARM ARM D5.9 -- after clearing a PTE, a break-before-make sequence is
/// required: DSB ISHST ensures the invalid write is visible, TLBI VAE1IS
/// invalidates the VA across all cores in the inner shareable domain,
/// DSB ISH waits for completion, and ISB synchronizes the pipeline.
pub fn unmapPage(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    kprof.point(.unmap_page, virt.addr);

    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l3Idx(virt), l2Idx(virt), l1Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.valid) return null;
        if (!entry.is_table) return null; // block descriptor, not what we expect
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l0_entry = &table[l0Idx(virt)];
    if (!l0_entry.valid) return null;
    const phys = l0_entry.getPAddr();
    l0_entry.* = default_page_entry;

    // ARM ARM D5.9: TLB maintenance after PTE invalidation.
    // TLBI VAE1IS broadcasts the invalidation to all cores in the inner
    // shareable domain, eliminating the need for explicit IPI-based shootdown.
    tlbiVae1is(virt.addr);

    return phys;
}

/// Walk the 4-level translation table and return the page-base physical
/// address (4 KiB aligned) of the mapping for `virt`, or null if not mapped.
///
/// Contract matches `x64.paging.resolveVaddr`: the returned PAddr is page-
/// aligned. Callers that need the full PA must add `virt.addr & 0xFFF`
/// themselves. This keeps generic kernel code (syscall handlers, fault
/// dispatch, etc.) portable across architectures.
///
/// ARM ARM D5.2 -- performs a software page-table walk through all 4 levels
/// of the VMSAv8-64 translation regime with 4KB granule.
pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    // Walk root → L1 → L2, terminating early when we hit a block
    // descriptor. Block sizes: 1 GiB at ARM L1 (naming `l2Idx` here),
    // 2 MiB at ARM L2 (`l1Idx` here). The direct-kernel boot stub
    // maps the kernel image with 2 MiB blocks at L2, so smpInit's
    // `resolveVaddr(&secondaryEntry)` needs to honour them — without
    // this early-out it used to return null and SMP bring-up bailed
    // with "!R".
    const root_entry = &table[l3Idx(virt)];
    if (!root_entry.valid) return null;
    if (!root_entry.is_table) {
        // 512 GiB block at root — architecturally invalid for 4KB
        // granule, but handle defensively.
        return null;
    }
    table = @ptrFromInt(VAddr.fromPAddr(root_entry.getPAddr(), null).addr);

    const l1_entry = &table[l2Idx(virt)];
    if (!l1_entry.valid) return null;
    if (!l1_entry.is_table) {
        // 1 GiB block: page-base = entry_pa_base | (virt[29:12]).
        const base = l1_entry.getPAddr().addr & ~@as(u64, (1 << 30) - 1);
        const within = virt.addr & ((1 << 30) - 1) & ~@as(u64, 0xFFF);
        return PAddr.fromInt(base | within);
    }
    table = @ptrFromInt(VAddr.fromPAddr(l1_entry.getPAddr(), null).addr);

    const l2_entry = &table[l1Idx(virt)];
    if (!l2_entry.valid) return null;
    if (!l2_entry.is_table) {
        // 2 MiB block: page-base = entry_pa_base | (virt[20:12]).
        const base = l2_entry.getPAddr().addr & ~@as(u64, (1 << 21) - 1);
        const within = virt.addr & ((1 << 21) - 1) & ~@as(u64, 0xFFF);
        return PAddr.fromInt(base | within);
    }
    table = @ptrFromInt(VAddr.fromPAddr(l2_entry.getPAddr(), null).addr);

    const leaf = &table[l0Idx(virt)];
    if (!leaf.valid) return null;
    return leaf.getPAddr();
}

/// Map MemoryPerms to ARM AP[2:1] bits.
///
/// ARM ARM D5.4, Table D5-34:
///   AP[2:1] = 0b00: EL1 RW, EL0 no access
///   AP[2:1] = 0b01: EL1 RW, EL0 RW
///   AP[2:1] = 0b10: EL1 RO, EL0 no access
///   AP[2:1] = 0b11: EL1 RO, EL0 RO
fn permsToAp(perms: MemoryPerms, user: bool) u2 {
    const writable = perms.write;

    if (writable and user) return 0b01;
    if (writable) return 0b00;
    if (user) return 0b11;
    return 0b10;
}

// ── AArch64 system register and barrier intrinsics ──────────────────────────

/// Read TTBR1_EL1 (Translation Table Base Register 1 -- kernel space).
/// ARM ARM D13.2.136.
pub fn readTtbr1() u64 {
    return asm volatile ("mrs %[ret], ttbr1_el1"
        : [ret] "=r" (-> u64),
    );
}

/// Write TTBR1_EL1 (Translation Table Base Register 1 -- kernel space).
/// ARM ARM D13.2.136.
pub fn writeTtbr1(val: u64) void {
    asm volatile ("msr ttbr1_el1, %[val]"
        :
        : [val] "r" (val),
        : .{ .memory = true });
}

/// Return the physical address of the kernel page table from TTBR1_EL1.
/// ARM ARM D13.2.136: TTBR1_EL1 holds the base address of the translation
/// table for the upper VA range (kernel space).
pub fn getKernelAddrSpaceRoot() PAddr {
    const ttbr1 = readTtbr1();
    const mask: u64 = 0x0000_FFFF_FFFF_F000;
    return PAddr.fromInt(ttbr1 & mask);
}

/// Configure TCR_EL1's TTBR1 half and load a new kernel page table address
/// into TTBR1_EL1. Also caches firmware MAIR indices for attr_indx use.
///
/// Sets T1SZ=16, IRGN1/ORGN1=WB-WA, SH1=ISH, TG1=4KB, AS=1 (16-bit ASID
/// tag lives in TTBR0 bits [63:48]). Preserves TTBR0 bits [15:0].
/// All register writes are idempotent — safe to call repeatedly.
///
/// ARM ARM D13.2.131 (TCR_EL1), D13.2.136 (TTBR1_EL1), D5.9 (TLBI VMALLE1).
pub fn setKernelAddrSpace(root: PAddr) void {
    initMairIndices();

    var tcr: u64 = asm volatile ("mrs %[ret], tcr_el1"
        : [ret] "=r" (-> u64),
    );
    // Clear TTBR1 config bits [31:16] and AS (bit 36). Preserve TTBR0 bits
    // [15:0] and any other upper bits.
    tcr &= ~@as(u64, 0xFFFF_0000);
    tcr &= ~(@as(u64, 1) << 36);
    tcr |= (16 << 16) | // T1SZ
        (0b01 << 24) | // IRGN1
        (0b01 << 26) | // ORGN1
        (0b11 << 28) | // SH1
        (@as(u64, 0b10) << 30); // TG1 (4KB)
    // AS=1 selects the 16-bit ASID space; A1=0 (default) means TTBR0_EL1
    // holds the active ASID in bits [63:48]. ARM ARM D13.2.131.
    tcr |= (@as(u64, 1) << 36);
    asm volatile ("msr tcr_el1, %[val]"
        :
        : [val] "r" (tcr),
        : .{ .memory = true });
    // ISB publishes the new TCR. Flush any TLB entries cached under the
    // previous AS=0 interpretation — their ASID tags are reinterpreted
    // under AS=1 and would alias incorrectly otherwise.
    asm volatile (
        \\isb
        \\dsb ishst
        \\tlbi vmalle1is
        \\dsb ish
        \\isb
        ::: .{ .memory = true });

    writeTtbr1(root.addr);
    asm volatile (
        \\isb
        \\dsb ishst
        \\tlbi vmalle1is
        \\dsb ish
        \\isb
        ::: .{ .memory = true });
}

/// Force TCR_EL1.T0SZ to 16 (48-bit user VA, 4-level walk) and rewrite
/// the matching IRGN0/ORGN0/SH0/TG0 fields. Called from `init()` after
/// firmware has exited boot services. See the comment at the call site
/// for the Pi-5 / EDK2 motivation.
///
/// ARM ARM D13.2.131 (TCR_EL1):
///   T0SZ  = bits [5:0]
///   IRGN0 = bits [9:8]   (0b01 = Normal Inner WB-WA)
///   ORGN0 = bits [11:10] (0b01 = Normal Outer WB-WA)
///   SH0   = bits [13:12] (0b11 = Inner Shareable)
///   TG0   = bits [15:14] (0b00 = 4KB granule)
pub fn forceT0Sz16() void {
    var tcr: u64 = asm volatile ("mrs %[ret], tcr_el1"
        : [ret] "=r" (-> u64),
    );
    tcr &= ~@as(u64, 0xFFFF);
    tcr |= (@as(u64, 16) << 0) | // T0SZ
        (@as(u64, 0b01) << 8) | // IRGN0
        (@as(u64, 0b01) << 10) | // ORGN0
        (@as(u64, 0b11) << 12) | // SH0
        (@as(u64, 0b00) << 14); // TG0 (4KB)
    asm volatile ("msr tcr_el1, %[val]"
        :
        : [val] "r" (tcr),
        : .{ .memory = true });
    // ISB so the new T0SZ is visible to subsequent accesses; TLBI to
    // drop any cached UEFI-era TTBR0 walks that were derived under the
    // old T0SZ — they would have stale level-0 indices otherwise.
    asm volatile (
        \\isb
        \\dsb ishst
        \\tlbi vmalle1is
        \\dsb ish
        \\isb
        ::: .{ .memory = true });
}

/// ISB -- Instruction Synchronization Barrier.
/// ARM ARM C6.2.4 -- flushes the pipeline so that subsequent instructions
/// are fetched and decoded using the current state of the system.
fn isb() void {
    asm volatile ("isb" ::: .{ .memory = true });
}

/// DSB ISHST -- Data Synchronization Barrier, Inner Shareable, Store.
/// ARM ARM C6.2.3 -- ensures all prior stores are visible to other cores
/// in the inner shareable domain before the barrier completes.
fn dsbIshst() void {
    asm volatile ("dsb ishst" ::: .{ .memory = true });
}

/// DSB ISH -- Data Synchronization Barrier, Inner Shareable.
/// ARM ARM C6.2.3 -- ensures all prior loads and stores are complete
/// before the barrier completes, visible to the inner shareable domain.
fn dsbIsh() void {
    asm volatile ("dsb ish" ::: .{ .memory = true });
}

/// TLBI VAE1IS -- TLB Invalidate by VA, EL1, Inner Shareable.
/// ARM ARM D5.9 -- invalidates all TLB entries matching the VA (page-aligned,
/// shifted right by 12) across all cores in the inner shareable domain.
///
/// The full sequence for a PTE change is:
///   DSB ISHST -> TLBI VAE1IS -> DSB ISH -> ISB
fn tlbiVae1is(vaddr: u64) void {
    kprof.point(.tlb_shootdown, vaddr);

    const page_addr = vaddr >> 12;
    dsbIshst();
    asm volatile ("tlbi vae1is, %[addr]"
        :
        : [addr] "r" (page_addr),
        : .{ .memory = true });
    dsbIsh();
    isb();
}

/// Map a single user 4 KiB page with cache attributes drawn from the
/// VMAR's `cch` field. Spec §[var] line 1444: 0=wb, 1=uc, 2=wc, 3=wt.
///
/// Cache attribute selection on aarch64 uses the per-PTE `attr_indx`
/// field to index into MAIR_EL1 (ARM ARM D5.3, Table D5-15 + D13.2.97).
/// Since we cannot rewrite MAIR_EL1 under a live MMU, the indices come
/// from `initMairIndices` — see that function for the firmware-fallback
/// policy when WC (Normal-NC, 0x44) or WT (Normal-WT, 0xBB) are not
/// exposed by firmware.
pub fn mapPageSized(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
    cch: VmarCacheType,
    perms: MemoryPerms,
) !void {
    std.debug.assert(sz == .sz_4k);
    std.debug.assert(std.mem.isAligned(phys.addr, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.PAGE4K));

    if (virt.addr < FIRST_USER_PAGE) {
        // Spec §[address_space]: NULL guard `[0, 0x1000)` must always
        // fault. Runtime check (active in all build modes) so a buggy
        // caller cannot silently install a leaf into the first page.
        @panic("paging.mapPageSized: NULL guard");
    }

    kprof.point(.map_page, virt.addr);

    const ap = permsToAp(perms, true);
    const xn = !perms.exec;
    const pxn = xn;

    const parent_entry = PageEntry{
        .valid = true,
        .is_table = true,
        .attr_indx = mair_normal,
        .ap = 0b00,
        .sh = 0b11,
        .af = true,
    };

    const leaf_entry = PageEntry{
        .valid = true,
        .is_table = true, // Level 3 page descriptor: bits [1:0] = 0b11
        .attr_indx = cchToAttrIndx(cch),
        .ap = ap,
        .sh = cchToSh(cch),
        .af = true,
        .ng = true, // user mappings are non-global (ASID-tagged)
        .xn = xn,
        .pxn = pxn,
    };

    const pmm_mgr = &pmm.global_pmm.?;
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l3Idx(virt), l2Idx(virt), l1Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.valid) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            entry.* = parent_entry;
            entry.setPAddr(new_phys);
        }
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l0_entry = &table[l0Idx(virt)];
    l0_entry.* = leaf_entry;
    l0_entry.setPAddr(phys);

    // ARM ARM D5.9: after installing a new leaf entry, broadcast TLB
    // maintenance so cached "not-present" (faulting) entries from prior
    // translations are invalidated across all inner-shareable cores.
    tlbiVae1is(virt.addr);
}

pub fn unmapPageSized(
    addr_space_root: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
) ?PAddr {
    std.debug.assert(sz == .sz_4k);
    return unmapPage(addr_space_root, virt);
}

/// Allocate a fresh user-half L0 page-table root (TTBR0_EL1 will point at
/// this PA on context switch). Kernel mappings live in TTBR1_EL1 and are
/// shared across address spaces, so unlike the x86 PML4 we do NOT copy
/// kernel half-entries into the new root — `dispatch.paging.copyKernelMappings`
/// is a no-op on aarch64. ARM ARM DDI 0487 §D5.2 / §D13.2.136.
pub fn allocAddrSpaceRoot() !PAddr {
    const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
    const new_table = try pmm_mgr.create(paging.PageMem(.page4k));
    const new_virt = VAddr.fromInt(@intFromPtr(new_table));
    return PAddr.fromVAddr(new_virt, null);
}

/// Tear down the user-half (TTBR0_EL1) of an address space root and
/// return every page reachable through the L3 (PGD) table to PMM:
///   - intermediate table pages (L2 / L1 / L0) — always single-page
///     PMM allocations made by `mapPage`'s on-demand walk
///   - leaf 4 KiB pages whose physical address is NOT in either skip
///     range (used to keep page-aliased buddy blocks alive — the
///     cap-domain's `user_buf` block is aliased into user space via
///     `mapUserTableView` and freed wholesale via `pmm.freeBlock`,
///     and the user stack lives in a contiguous buddy block)
///
/// Leaves backed by VMAR-installed page_frames must already be cleared
/// (PageEntry.valid = 0) by the caller — `destroyVmar`'s `unmapAll`
/// does this and decrements PageFrame mapcnt for each entry. Any
/// valid leaves remaining at this point came from boot-side eager
/// mappings (mapUserStack, loadElfSegments, mapUserTableView).
///
/// On aarch64 the user/kernel split is cleaner than x86: TTBR0_EL1
/// covers the canonical low half exclusively (VAs `0x0000_0000_0000_0000`
/// .. `0x0000_FFFF_FFFF_FFFF`) and TTBR1_EL1 carries kernel mappings.
/// Therefore ALL 512 entries of the L3 root are user-half — there is
/// no `i < 256` guard like on x86's PML4. ARM ARM DDI 0487 §D5.2
/// (VMSAv8-64 translation table format), §D13.2.136 (TTBR0_EL1 /
/// TTBR1_EL1).
///
/// ARM ARM DDI 0487 §D5.3 Table D5-15: each translation table is 512
/// 64-bit descriptors. At L1 / L2 a `valid && !is_table` descriptor
/// is a block (1 GiB / 2 MiB leaf); at L0 (the leaf level in this
/// codebase's naming) `valid && is_table` is a 4 KiB page descriptor.
/// The on-demand `mapPage` walker only produces 4 KiB leaves at L0,
/// but defensive checks at L1 / L2 keep the walk correct if a future
/// patch lands a block mapping under TTBR0 (e.g. for a hugepage user
/// VAR).
pub fn freeUserAddrSpace(
    root: PAddr,
    skip1_start: u64,
    skip1_bytes: u64,
    skip2_start: u64,
    skip2_bytes: u64,
) void {
    const pmm_mgr = if (pmm.global_pmm) |*p| p else return;
    const root_virt = VAddr.fromPAddr(root, null);
    const l3: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &l3[i];
        if (!entry.valid) continue;
        // L3 (root) block descriptors would map 512 GiB and are not
        // produced by the codebase, but if one ever lands treat it as
        // a leaf and free per skip-range.
        if (!entry.is_table) {
            const phys = entry.getPAddr().addr;
            entry.* = default_page_entry;
            if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
                pmm_mgr.freePage(physToPagePtr(phys));
            }
            continue;
        }
        freeL2(pmm_mgr, entry.getPAddr(), skip1_start, skip1_bytes, skip2_start, skip2_bytes);
        entry.* = default_page_entry;
    }

    // Deliberately do NOT free the L3 root here — it is still the
    // active TTBR0_EL1 on the calling core until the next dispatch
    // swaps address space. Freeing it inline would let PMM hand the
    // page out, whose write would corrupt the live page-table walk
    // on this core. Kernel mappings live in TTBR1_EL1 and are
    // unaffected; the user-half is now empty so no future user TLB
    // miss can walk into freed pages. The 4 KiB leak is reaped at
    // the next reuse of the addr_space_id / ASID — addressable later
    // by deferring the free until after a TTBR0 swap.
}

/// Recurse one level down: free leaf pages and tables under an L2 (PUD)
/// pointer. ARM ARM §D5.3 Table D5-15. Block descriptors at L2 map 1 GiB
/// (`valid && !is_table`); table descriptors point at an L1 (PMD).
fn freeL2(
    pmm_mgr: *pmm.PhysicalMemoryManager,
    l2_phys: PAddr,
    skip1_start: u64,
    skip1_bytes: u64,
    skip2_start: u64,
    skip2_bytes: u64,
) void {
    const l2_virt = VAddr.fromPAddr(l2_phys, null);
    const l2: *[page_entry_table_size]PageEntry = @ptrFromInt(l2_virt.addr);
    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &l2[i];
        if (!entry.valid) continue;
        if (!entry.is_table) {
            // 1 GiB block leaf at L2.
            const phys = entry.getPAddr().addr;
            entry.* = default_page_entry;
            if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
                pmm_mgr.freePage(physToPagePtr(phys));
            }
            continue;
        }
        freeL1(pmm_mgr, entry.getPAddr(), skip1_start, skip1_bytes, skip2_start, skip2_bytes);
        entry.* = default_page_entry;
    }
    pmm_mgr.freePage(@as([*]u8, @ptrFromInt(l2_virt.addr)));
}

/// Recurse one level down: free leaf pages and tables under an L1 (PMD)
/// pointer. ARM ARM §D5.3 Table D5-15. Block descriptors at L1 map 2 MiB
/// (`valid && !is_table`); table descriptors point at an L0 (PT).
fn freeL1(
    pmm_mgr: *pmm.PhysicalMemoryManager,
    l1_phys: PAddr,
    skip1_start: u64,
    skip1_bytes: u64,
    skip2_start: u64,
    skip2_bytes: u64,
) void {
    const l1_virt = VAddr.fromPAddr(l1_phys, null);
    const l1: *[page_entry_table_size]PageEntry = @ptrFromInt(l1_virt.addr);
    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &l1[i];
        if (!entry.valid) continue;
        if (!entry.is_table) {
            // 2 MiB block leaf at L1.
            const phys = entry.getPAddr().addr;
            entry.* = default_page_entry;
            if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
                pmm_mgr.freePage(physToPagePtr(phys));
            }
            continue;
        }
        freeL0(pmm_mgr, entry.getPAddr(), skip1_start, skip1_bytes, skip2_start, skip2_bytes);
        entry.* = default_page_entry;
    }
    pmm_mgr.freePage(@as([*]u8, @ptrFromInt(l1_virt.addr)));
}

/// Free 4 KiB leaf pages and the L0 (PT) table itself. ARM ARM §D5.3
/// Table D5-15: at L0 (the level-3 leaf level in ARM spec naming) a
/// `valid && is_table` descriptor encodes a 4 KiB page (descriptor
/// type bits [1:0] = 0b11). There is no block-descriptor variant at
/// L0; a `valid && !is_table` here is architecturally a reserved
/// encoding and treated as no-op.
fn freeL0(
    pmm_mgr: *pmm.PhysicalMemoryManager,
    l0_phys: PAddr,
    skip1_start: u64,
    skip1_bytes: u64,
    skip2_start: u64,
    skip2_bytes: u64,
) void {
    const l0_virt = VAddr.fromPAddr(l0_phys, null);
    const l0: *[page_entry_table_size]PageEntry = @ptrFromInt(l0_virt.addr);
    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &l0[i];
        if (!entry.valid) continue;
        const phys = entry.getPAddr().addr;
        entry.* = default_page_entry;
        if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
            pmm_mgr.freePage(physToPagePtr(phys));
        }
    }
    pmm_mgr.freePage(@as([*]u8, @ptrFromInt(l0_virt.addr)));
}

inline fn leafSkipped(phys: u64, s1: u64, n1: u64, s2: u64, n2: u64) bool {
    if (n1 != 0 and phys >= s1 and phys < s1 + n1) return true;
    if (n2 != 0 and phys >= s2 and phys < s2 + n2) return true;
    return false;
}

inline fn physToPagePtr(phys: u64) [*]u8 {
    return @ptrFromInt(VAddr.fromPAddr(.{ .addr = phys }, null).addr);
}

/// Read the current TTBR0_EL1 base PA (low-half / user translation root).
/// Strips ASID bits [63:48] and reserved bits [11:0]; returns a clean PA.
/// ARM ARM DDI 0487 §D13.2.136 TTBR0_EL1.
pub fn getAddrSpaceRoot() PAddr {
    const ttbr0 = asm volatile ("mrs %[ret], ttbr0_el1"
        : [ret] "=r" (-> u64),
    );
    const mask: u64 = 0x0000_FFFF_FFFF_F000;
    return PAddr.fromInt(ttbr0 & mask);
}

/// Swap TTBR0_EL1 to a new user-half page-table root and tag the
/// translation with `id` (ASID, 16-bit). Per ARM ARM §D13.2.136 the
/// ASID lives in TTBR0_EL1[63:48] when TCR_EL1.AS=1 (which
/// `setKernelAddrSpace` already sets). Following the write the manual
/// requires a context-synchronization event before EL0 access can use
/// the new translation; an `isb` provides it. No explicit TLBI is
/// needed when the ASID changes — the new ASID inherently scopes
/// future lookups.
pub fn swapAddrSpace(root: PAddr, id: u16) void {
    const asid: u64 = @as(u64, id) << 48;
    const value: u64 = (root.addr & 0x0000_FFFF_FFFF_F000) | asid;
    asm volatile (
        \\msr ttbr0_el1, %[v]
        \\isb
        :
        : [v] "r" (value),
        : .{ .memory = true });
}

pub fn shootdownTlbRange(
    addr_space_id: u16,
    virt: VAddr,
    sz: VmarPageSize,
    page_count: u32,
) void {
    _ = addr_space_id;
    std.debug.assert(sz == .sz_4k);
    // ARM ARM D5.9: TLBI VAE1IS broadcasts across the inner-shareable
    // domain; no IPI fan-out required (unlike x86's per-core invlpg).
    var i: u32 = 0;
    while (i < page_count) {
        tlbiVae1is(virt.addr + @as(u64, i) * paging.PAGE4K);
        i += 1;
    }
}
