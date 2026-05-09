/// Intel VT-d (Virtualization Technology for Directed I/O) IOMMU driver.
///
/// Implements DMA remapping using legacy mode (root table + context table +
/// second-stage page tables) per the Intel VT-d Architecture Specification,
/// Rev 4.0, June 2022 (Order Number: D51397-015).
///
/// Translation flow (Section 3.4):
///   DMA request with BDF → Root Table[Bus] → Context Table[Dev:Fn]
///   → Second-Stage Page Tables (4-level, 48-bit) → Host Physical Address
///
/// Spec-v3 dispatch surface: per-page `mapPage` / `unmapPage` /
/// `invalidateIotlbRange` keyed by `*DeviceRegion`. The first call for a
/// device lazily provisions a root/context entry pair plus a fresh
/// second-stage PML4 and stashes that state on the DeviceRegion's
/// `iommu_state` slot.
const stygia = @import("stygia");

const arch_paging = stygia.arch.x64.paging;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const pmm = stygia.memory.pmm;

const DeviceRegion = stygia.devices.device_region.DeviceRegion;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;
const VmarPageSize = stygia.memory.vmar.PageSize;

const MMIO_PERMS: MemoryPerms = .{ .read = true, .write = true };

// ── Register offsets (Section 11.4, Table 1) ────────────────────────────

/// Extended Capability Register (Section 11.4.3, offset 010h).
/// Reports extended hardware capabilities. We read the IRO field
/// (bits 17:8) to locate the IOTLB registers.
const REG_ECAP = 0x10;

/// Global Command Register (Section 11.4.4.1, offset 018h).
/// **Write-only.** Controls translation enable, root table pointer
/// latching, write buffer flush, and other global commands.
/// Reading this register returns undefined values — software must
/// read GSTS to determine current state.
const REG_GCMD = 0x18;

/// Global Status Register (Section 11.4.4.2, offset 01Ch).
/// **Read-only.** Reports the status of commands issued via GCMD.
/// Bit positions mirror GCMD (e.g. bit 31 = TES mirrors TE).
const REG_GSTS = 0x1C;

/// Root Table Address Register (Section 11.4.5, offset 020h).
/// Bits 63:12 = 4KB-aligned root table physical address.
/// Bits 11:10 = TTM (Translation Table Mode): 00=legacy, 01=scalable.
/// Takes effect only after SRTP command via GCMD.
const REG_RTADDR = 0x20;

/// Context Command Register (Section 11.4.6.1, offset 028h).
/// 64-bit register for context-cache invalidation commands.
const REG_CCMD = 0x28;

// ── Command/status bit definitions (Section 11.4.4) ─────────────────────

/// GCMD bit 31: Translation Enable — write 1 to enable DMA remapping.
const GCMD_TE: u32 = 1 << 31;

/// GCMD bit 30: Set Root Table Pointer — one-shot command to latch
/// the value in RTADDR_REG. Cleared automatically; do not preserve.
const GCMD_SRTP: u32 = 1 << 30;

/// GSTS bit 31: Translation Enable Status — set when TE is active.
const GSTS_TES: u32 = 1 << 31;

/// GSTS bit 30: Root Table Pointer Status — set when SRTP completes.
const GSTS_RTPS: u32 = 1 << 30;

/// Mask to extract persistent command state from GSTS for GCMD writes.
/// Per Section 11.4.4.1, when writing GCMD software must:
///   1. Read GSTS_REG
///   2. AND with 0x96FFFFFF to clear one-shot bits (SRTP[30], WBF[27],
///      SIRTP[24], CFI[23]) and reserved bits [29:28]
///   3. OR in the desired command bit
///   4. Write to GCMD_REG
/// This preserves persistent enables (TE[31], QIE[26], IRE[25]) while
/// clearing one-shot command bits that must not be re-asserted.
const GSTS_CMD_MASK: u32 = 0x96FFFFFF;

/// Offset of the IOTLB registers, derived from ECAP.IRO at init time.
/// The IOTLB Invalidate Register is at this offset + 8 (Section 11.4.6.2).
var iotlb_offset: u32 = 0;

/// Legacy-mode Root Table Entry (Section 9.1, Table 3).
///
/// 128-bit entry, one per PCI bus (256 entries in root table).
/// The upper 64 bits are reserved in legacy mode (used only in
/// scalable mode for the upper context table pointer).
///
/// Layout:
///   Bits 127:64 — Reserved (must be 0)
///   Bits 63:12  — CTP: 4KB-aligned physical address of context table
///   Bits 11:1   — Reserved (must be 0)
///   Bit  0      — P: Present (1 = valid entry)
const RootEntry = packed struct(u128) {
    present: bool,
    _res0: u11 = 0,
    context_table_ptr: u52,
    _res1: u64 = 0,
};

/// Legacy-mode Context Table Entry (Section 9.3, Table 12).
///
/// 128-bit entry, 256 per context table (one per devfn on a PCI bus).
/// Maps a device to its second-stage page table and domain ID.
///
/// Layout:
///   Bits 127:88 — Reserved
///   Bits 87:72  — DID: 16-bit Domain Identifier
///   Bit  71     — Reserved
///   Bits 70:67  — Ignored
///   Bits 66:64  — AW: Address Width (001=39-bit/3-level, 010=48-bit/4-level, 011=57-bit/5-level)
///   Bits 63:12  — SLPTPTR: 4KB-aligned second-stage page table pointer
///   Bits 11:4   — Reserved
///   Bits 3:2    — TT: Translation Type (00=second-stage only, 10=pass-through)
///   Bit  1      — FPD: Fault Processing Disable (1=suppress fault logging)
///   Bit  0      — P: Present
const ContextEntry = packed struct(u128) {
    present: bool,
    fault_disable: bool,
    translation_type: u2,
    _res0: u8 = 0,
    slptptr: u52,
    address_width: u3,
    _ignored: u1 = 0,
    _avail: u3 = 0,
    _res1: u1 = 0,
    domain_id: u16,
    _res2: u40 = 0,
};

/// Per-device IOMMU side-state. Stashed via DeviceRegion.iommu_state on
/// first map; reused by subsequent map/unmap/invalidate. Statically
/// allocated from a small pool — DMA-capable PCI device count is bounded
/// by the platform and stays well below `MAX_PER_DEVICE` for QEMU's
/// virtual hardware set.
const PerDevice = struct {
    /// Second-stage page-table root (PML4) — physical address.
    sl_pt_root_phys: PAddr = PAddr.fromInt(0),
    /// Same root, kernel-virt for software walks.
    sl_pt_root_virt: VAddr = VAddr.fromInt(0),
    /// Domain identifier programmed into the context entry. Unique per
    /// device; we use the device's BDF.
    domain_id: u16 = 0,
    /// True once the context entry is present. Subsequent maps skip
    /// re-programming the root/context tables and only walk the SL-PT.
    provisioned: bool = false,
};

const MAX_PER_DEVICE: usize = stygia.devices.device_region.MAX_DEVICE_REGIONS;
var per_device_pool: [MAX_PER_DEVICE]PerDevice = [_]PerDevice{.{}} ** MAX_PER_DEVICE;
var per_device_used: usize = 0;

var iommu_base: u64 = 0;
var root_table_phys: PAddr = PAddr.fromInt(0);
var root_table_virt: VAddr = VAddr.fromInt(0);
var initialized: bool = false;
var translation_enabled: bool = false;

/// Read a 32-bit MMIO register at the given offset from the IOMMU base.
/// Per Section 11.2, software accesses 32-bit registers as aligned doublewords.
fn readReg32(offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(iommu_base + offset);
    return ptr.*;
}

/// Write a 32-bit MMIO register at the given offset from the IOMMU base.
fn writeReg32(offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(iommu_base + offset);
    ptr.* = value;
}

/// Write a 64-bit MMIO register at the given offset from the IOMMU base.
/// Per Section 11.2, hardware completes quadword writes in order
/// (lower doubleword first, upper doubleword second).
fn writeReg64(offset: u32, value: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(iommu_base + offset);
    ptr.* = value;
}

/// Allocate a zeroed 4KB page and return both its physical and virtual addresses.
/// Used for root tables, context tables, and page table levels — all of which
/// must be 4KB-aligned and zero-initialized (Section 9.1, 9.3, 9.8).
fn allocZeroedPage() !struct { phys: PAddr, virt: VAddr } {
    const pmm_mgr = &pmm.global_pmm.?;
    const page = try pmm_mgr.create(paging.PageMem(.page4k));
    const virt = VAddr.fromInt(@intFromPtr(page));
    const phys = PAddr.fromVAddr(virt, null);
    return .{ .phys = phys, .virt = virt };
}

/// Read current persistent GCMD state from GSTS and issue a command.
///
/// GCMD_REG is write-only (Section 11.4.4.1) — reads return undefined.
/// The spec prescribes this sequence for issuing commands:
///   1. Read GSTS_REG to get current state
///   2. Mask with 0x96FFFFFF to clear one-shot bits (SRTP, WBF, SIRTP, CFI)
///   3. OR in the desired command bit
///   4. Write to GCMD_REG
///   5. Poll GSTS_REG until the corresponding status bit confirms completion
fn issueGlobalCommand(cmd_bit: u32, status_bit: u32) void {
    const current = readReg32(REG_GSTS) & GSTS_CMD_MASK;
    writeReg32(REG_GCMD, current | cmd_bit);
    var timeout: u32 = 0;
    while (timeout < 1000000) {
        if (readReg32(REG_GSTS) & status_bit != 0) break;
        timeout += 1;
    }
}

/// Initialize the Intel VT-d remapping hardware unit.
///
/// Performs the following sequence per the spec:
///   1. Map the MMIO register page (implementation-specific base from ACPI DMAR)
///   2. Read ECAP.IRO (Section 11.4.3, bits 17:8) to locate IOTLB registers.
///      IRO is a 10-bit field giving the offset in 16-byte units.
///   3. Allocate and zero a 4KB root table (256 RootEntry, Section 9.1)
///   4. Write root table address to RTADDR_REG (Section 11.4.5).
///      Bits 63:12 = physical address, bits 11:10 = TTM = 00 (legacy mode).
///      Since the page is 4KB-aligned, bits 11:0 are 0, giving TTM=00.
///   5. Issue SRTP command (Section 11.4.4.1) to latch the root table pointer.
///      Hardware sets GSTS.RTPS when complete.
///
/// Translation enable (TE) is deferred to enableTranslation() so that
/// per-device provisioning can populate context entries first — if TE were
/// set now, the IOMMU would cache "not present" entries (Section 6.1, CM=0
/// still caches present/absent distinction for root and context entries).
pub fn init(reg_base_phys: PAddr) !void {
    const reg_base_virt = VAddr.fromPAddr(reg_base_phys, null);

    try arch_paging.mapPage(memory_init.kernel_addr_space_root, reg_base_phys, reg_base_virt, MMIO_PERMS, .kernel_mmio);
    iommu_base = reg_base_virt.addr;

    // ECAP.IRO (Section 11.4.3): bits 17:8 give the IOTLB register offset
    // in 16-byte (paragraph) units. Shift left by 4 to get byte offset.
    const ecap: u64 = @as(*const volatile u64, @ptrFromInt(iommu_base + REG_ECAP)).*;
    iotlb_offset = @truncate(((ecap >> 8) & 0x3FF) << 4);

    const root = try allocZeroedPage();
    root_table_phys = root.phys;
    root_table_virt = root.virt;

    // RTADDR_REG (Section 11.4.5): bits 63:12 = root table address.
    // Bits 11:10 = TTM = 00 (legacy mode). Page-aligned address ensures TTM=00.
    writeReg64(REG_RTADDR, root_table_phys.addr);

    // Issue SRTP command and wait for GSTS.RTPS (Section 11.4.4.1).
    issueGlobalCommand(GCMD_SRTP, GSTS_RTPS);

    initialized = true;
}

/// Enable DMA remapping by setting GCMD.TE (Section 11.4.4.1).
///
/// Called after all initial per-device provisioning so context entries are
/// populated before translation is active. Per Section 6.5, software must
/// invalidate context cache and IOTLB before enabling translation to
/// ensure the IOMMU does not use stale cached entries from a prior
/// translation-enabled session.
///
/// After writing TE=1, polls GSTS.TES until hardware confirms translation
/// is active. Hardware enables remapping at a deterministic transaction
/// boundary so in-flight DMA is fully remapped or not at all.
pub fn enableTranslation() void {
    if (!initialized or translation_enabled) return;
    invalidateContextCache();
    invalidateIotlbGlobal();
    issueGlobalCommand(GCMD_TE, GSTS_TES);
    translation_enabled = true;
}

/// Lazily provision the root/context entries and second-stage PML4 for a
/// device on its first map. Subsequent maps reuse the stashed PerDevice.
///
/// Root table (Section 9.1): 256 entries indexed by PCI bus number; each
/// entry points to a 4KB context table.
///
/// Context table (Section 9.3): 256 entries indexed by devfn (dev[4:0]
/// << 3 | func[2:0]). Each entry contains:
///   - SLPTPTR: second-stage page-table root (4KB-aligned phys)
///   - AW = 010b: 48-bit AGAW / 4-level page table (Section 9.3, Table 12)
///   - TT = 00b: untranslated requests, second-stage translation
///   - DID: domain identifier; we use the BDF for uniqueness.
fn ensureProvisioned(device: *DeviceRegion) !*PerDevice {
    if (device.iommu_state) |state| {
        return @ptrCast(@alignCast(state));
    }
    if (!device.pci.isValid()) return error.NotPci;
    if (per_device_used >= per_device_pool.len) return error.OutOfMemory;

    const slot_idx = per_device_used;
    per_device_used += 1;
    const pd = &per_device_pool[slot_idx];

    const root_entries: *[256]RootEntry = @ptrFromInt(root_table_virt.addr);
    const bus = device.pci.bus;

    if (!root_entries[bus].present) {
        const ctx = try allocZeroedPage();
        root_entries[bus] = .{
            .present = true,
            .context_table_ptr = @truncate(ctx.phys.addr >> 12),
        };
    }

    const ctx_phys = PAddr.fromInt(@as(u64, root_entries[bus].context_table_ptr) << 12);
    const ctx_virt = VAddr.fromPAddr(ctx_phys, null);
    const ctx_entries: *[256]ContextEntry = @ptrFromInt(ctx_virt.addr);
    const ctx_idx: u8 = device.pci.devfn;

    const pt = try allocZeroedPage();
    pd.sl_pt_root_phys = pt.phys;
    pd.sl_pt_root_virt = pt.virt;
    pd.domain_id = device.pci.bdf();
    pd.provisioned = true;

    ctx_entries[ctx_idx] = .{
        .present = true,
        .fault_disable = false,
        // TT = 00b: untranslated requests, second-stage translation (§9.3)
        .translation_type = 0,
        // AW = 010b: 48-bit AGAW, 4-level page table (§9.3, CAP.SAGAW)
        .address_width = 2,
        .slptptr = @truncate(pt.phys.addr >> 12),
        .domain_id = pd.domain_id,
    };

    // Per Section 6.5, context-cache invalidation must precede IOTLB
    // invalidation because context-cache info may tag IOTLB entries.
    invalidateContextCache();
    invalidateIotlbGlobal();

    device.iommu_state = @ptrCast(pd);
    return pd;
}

fn permsToBits(perms: MemoryPerms) u64 {
    var bits: u64 = 0;
    if (perms.read) bits |= 0x1; // Bit 0: R
    if (perms.write) bits |= 0x2; // Bit 1: W
    return bits;
}

fn pageSizeBytes(sz: VmarPageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0,
    };
}

/// Map a single page-sized IOVA in `device`'s second-stage page table.
///
/// Walks/allocates the 4-level page-table tree (PML4 → PDPT → PD → PT)
/// per Section 9.8-9.9, installing a leaf at the appropriate level for
/// 4KB / 2MB / 1GB pages. For 2MB and 1GB the leaf entry sets PS (bit 7,
/// "page size" — VT-d Table 42/40) so the IOMMU stops the walk.
///
/// Index extraction from the 48-bit DMA address:
///   PML4 index = bits 47:39 (Section 9.9, Table 24)
///   PDPT index = bits 38:30
///   PD index   = bits 29:21
///   PT index   = bits 20:12
pub fn mapPage(
    device: *DeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VmarPageSize,
    perms: MemoryPerms,
) !void {
    if (!initialized) return error.NotInitialized;
    const pd = try ensureProvisioned(device);

    const pml4: *[512]u64 = @ptrFromInt(pd.sl_pt_root_virt.addr);
    const pml4_idx: u9 = @truncate((iova >> 39) & 0x1FF);
    const pdpt_idx: u9 = @truncate((iova >> 30) & 0x1FF);
    const pd_idx: u9 = @truncate((iova >> 21) & 0x1FF);
    const pt_idx: u9 = @truncate((iova >> 12) & 0x1FF);

    const leaf_perms = permsToBits(perms);

    // PML4E → PDPT (Table 24): R=1, W=1 (intermediate, full perms).
    if (pml4[pml4_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pml4[pml4_idx] = page.phys.addr | 0x3;
    }
    if (sz == .sz_1g) {
        // 1GB leaf at PDPT level. PS (bit 7) selects page-size leaf.
        const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);
        pdpt[pdpt_idx] = (phys.addr & 0xFFFF_FFFF_C000_0000) | leaf_perms | 0x80;
        return;
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);

    // PDPTE → PD (Table 40)
    if (pdpt[pdpt_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pdpt[pdpt_idx] = page.phys.addr | 0x3;
    }
    if (sz == .sz_2m) {
        const pd_table: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);
        pd_table[pd_idx] = (phys.addr & 0xFFFF_FFFF_FFE0_0000) | leaf_perms | 0x80;
        return;
    }
    const pd_table: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);

    // PDE → PT (Table 42)
    if (pd_table[pd_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pd_table[pd_idx] = page.phys.addr | 0x3;
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd_table[pd_idx] & 0xFFFFFFFFF000), null).addr);

    // Leaf PTE (Table 43): perms in bits 1:0, address in bits (HAW-1):12
    pt[pt_idx] = (phys.addr & 0xFFFF_FFFF_FFFF_F000) | leaf_perms;
}

/// Remove a page mapping from `device`'s second-stage page table.
/// Returns the previously bound physical address, or null if the IOVA
/// was not mapped at the expected page size. Does not free intermediate
/// page-table pages — they remain available for re-map.
pub fn unmapPage(device: *DeviceRegion, iova: u64, sz: VmarPageSize) ?PAddr {
    if (!initialized) return null;
    const state = device.iommu_state orelse return null;
    const pd: *PerDevice = @ptrCast(@alignCast(state));
    if (!pd.provisioned) return null;

    const pml4: *[512]u64 = @ptrFromInt(pd.sl_pt_root_virt.addr);
    const pml4_idx: u9 = @truncate((iova >> 39) & 0x1FF);
    if (pml4[pml4_idx] & 1 == 0) return null;

    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);
    const pdpt_idx: u9 = @truncate((iova >> 30) & 0x1FF);

    if (sz == .sz_1g) {
        const entry = pdpt[pdpt_idx];
        if (entry & 1 == 0 or (entry & 0x80) == 0) return null;
        pdpt[pdpt_idx] = 0;
        return PAddr.fromInt(entry & 0xFFFF_FFFF_C000_0000);
    }
    if (pdpt[pdpt_idx] & 1 == 0) return null;

    const pd_table: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);
    const pd_idx: u9 = @truncate((iova >> 21) & 0x1FF);

    if (sz == .sz_2m) {
        const entry = pd_table[pd_idx];
        if (entry & 1 == 0 or (entry & 0x80) == 0) return null;
        pd_table[pd_idx] = 0;
        return PAddr.fromInt(entry & 0xFFFF_FFFF_FFE0_0000);
    }
    if (pd_table[pd_idx] & 1 == 0) return null;

    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd_table[pd_idx] & 0xFFFFFFFFF000), null).addr);
    const pt_idx: u9 = @truncate((iova >> 12) & 0x1FF);
    const entry = pt[pt_idx];
    if (entry & 1 == 0) return null;
    pt[pt_idx] = 0;
    return PAddr.fromInt(entry & 0xFFFF_FFFF_FFFF_F000);
}

/// Page-selective IOTLB invalidation per Section 11.4.6.4.
///
/// IOTLB Invalidate Register (offset IRO+8) layout:
///   Bit 63       = IVT — set to initiate; hardware clears on completion.
///   Bits 61:60   = IIRG — invalidation request granularity:
///                    01 = global, 10 = domain-selective, 11 = page-selective.
///   Bits 49:32   = DID — domain id (page-selective and domain-selective).
///
/// IOTLB Invalidate Address Register (offset IRO+0):
///   Bits 63:12   = ADDR — page-aligned IOVA.
///   Bits  5:0    = AM — invalidation address mask: 2^AM × 4KB pages.
///   Bit  6       = IH — hint (set to skip non-leaf invalidation for leaf-only
///                  changes; we leave 0 to invalidate the full walk).
///
/// We loop one command per affected page in the range. For unmap the caller
/// passes the freshly-cleared range; for remap-with-tighter-perms the caller
/// passes the touched window.
pub fn invalidatePageRange(
    device: *DeviceRegion,
    iova: u64,
    sz: VmarPageSize,
    page_count: u32,
) void {
    if (!initialized) return;
    const state = device.iommu_state orelse return;
    const pd: *PerDevice = @ptrCast(@alignCast(state));
    if (!pd.provisioned) return;

    const sz_bytes = pageSizeBytes(sz);
    if (sz_bytes == 0) return;
    // AM encoding: number of low-order bits to mask (4KB granularity).
    // For 4KB pages AM=0, for 2MB AM=9, for 1GB AM=18.
    const am: u64 = switch (sz) {
        .sz_4k => 0,
        .sz_2m => 9,
        .sz_1g => 18,
        ._reserved => return,
    };

    const iotlb_addr_reg: u32 = iotlb_offset;
    const iotlb_inv_reg: u32 = iotlb_offset + 8;

    var i: u32 = 0;
    while (i < page_count) {
        const page_iova = iova + @as(u64, i) * sz_bytes;
        // Address register: bits 63:12 = page IOVA, bits 5:0 = AM, bit 6 = IH=0.
        writeReg64(iotlb_addr_reg, (page_iova & 0xFFFF_FFFF_FFFF_F000) | (am & 0x3F));
        // Invalidate register: IVT=1 (bit 63), IIRG=11 (page-selective, bits 61:60),
        // DID = pd.domain_id (bits 49:32).
        const iirg_page: u64 = (@as(u64, 0b11) << 60);
        const ivt: u64 = @as(u64, 1) << 63;
        const did: u64 = @as(u64, pd.domain_id) << 32;
        writeReg64(iotlb_inv_reg, ivt | iirg_page | did);

        var timeout: u32 = 0;
        while (timeout < 1000000) {
            const val = @as(*const volatile u64, @ptrFromInt(iommu_base + iotlb_inv_reg)).*;
            if (val & (@as(u64, 1) << 63) == 0) break;
            timeout += 1;
        }
        i += 1;
    }
}

/// Perform a global context-cache invalidation (Section 11.4.6.1).
///
/// Writes to CCMD_REG (offset 028h) with:
///   Bit 63 = ICC (Invalidate Context-Cache): set to initiate invalidation.
///   Bits 62:61 = CIRG = 01b (Global Invalidation Request).
///
/// Polls ICC (bit 63) until hardware clears it, indicating completion.
/// Hardware may perform invalidation at a coarser granularity and reports
/// the actual granularity in CAIG (bits 60:59).
///
/// Per Section 11.4.6.1: "Since information from the context-cache may be
/// used by hardware to tag IOTLB entries, software must perform domain-
/// selective (or global) invalidation of IOTLB after the context-cache
/// invalidation has completed."
fn invalidateContextCache() void {
    // ICC=1 (bit 63), CIRG=01 (bit 61) = global invalidation
    writeReg64(REG_CCMD, (@as(u64, 1) << 63) | (@as(u64, 1) << 61));
    var timeout: u32 = 0;
    while (timeout < 1000000) {
        const val = @as(*const volatile u64, @ptrFromInt(iommu_base + REG_CCMD)).*;
        if (val & (@as(u64, 1) << 63) == 0) break;
        timeout += 1;
    }
}

/// Perform a global IOTLB invalidation (Section 11.4.6.3).
///
/// The IOTLB Invalidate Register is at offset IRO+8 (Section 11.4.6.2),
/// where IRO is read from ECAP.IRO during init(). Writes with:
///   Bit 63 = IVT (Invalidate IOTLB): set to initiate invalidation.
///   Bits 61:60 = IIRG = 01b (Global Invalidation Request).
///   Bit 62 is reserved and must be 0.
///
/// Polls IVT (bit 63) until hardware clears it, indicating completion.
/// Hardware reports actual granularity in IAIG (bits 58:57).
///
/// Must be called after context-cache invalidation (Section 11.4.6.1)
/// and after modifying root/context entries (Section 6.1, 6.5).
fn invalidateIotlbGlobal() void {
    // IOTLB_REG is at IRO + 8 (Section 11.4.6.2)
    const reg = iotlb_offset + 8;
    // IVT=1 (bit 63), IIRG=01 (bit 60) = global invalidation
    writeReg64(reg, @as(u64, 1) << 63 | @as(u64, 1) << 60);
    var timeout: u32 = 0;
    while (timeout < 1000000) {
        const val = @as(*const volatile u64, @ptrFromInt(iommu_base + reg)).*;
        if (val & (@as(u64, 1) << 63) == 0) break;
        timeout += 1;
    }
}
