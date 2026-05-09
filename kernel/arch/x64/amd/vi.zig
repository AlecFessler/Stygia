/// AMD I/O Virtualization Technology (AMD-Vi / IOMMU) driver.
///
/// Implements host-level DMA address translation per the AMD IOMMU specification
/// (AMD Publication #48882, Rev 3.05, January 2020). This driver programs the
/// IOMMU to enforce per-device I/O page tables so that each device can only DMA
/// to explicitly mapped physical pages.
///
/// Key spec references used throughout:
///   - Section 2.2.2: Device Table Entry (DTE) format (Figure 7, Table 7)
///   - Section 2.2.3: I/O Page Tables for Host Translations (Table 15, Figures 8-10)
///   - Section 2.3:   Starting the IOMMU / Data Structure Initialization
///   - Section 2.4:   Commands (generic format in Figure 40)
///   - Section 3.3.1: MMIO Control and Status Registers
///   - Section 3.3.13: Command and Event Log Pointer Registers
///
/// Spec-v3 dispatch surface: per-page `mapPage`/`unmapPage`/
/// `invalidatePageRange` keyed by `*DeviceRegion`. The DTE for a device is
/// lazily provisioned on first map and cached on the device's
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

// ---------------------------------------------------------------------------
// MMIO register offsets (spec Section 3.3.1, Section 3.3.13)
// ---------------------------------------------------------------------------

/// Device Table Base Address Register — spec MMIO Offset 0000h.
/// Bits [51:12] = DevTabBase, [8:0] = Size (n → (n+1)*4KB).
const MMIO_DEV_TABLE_BASE = 0x0000;

/// Command Buffer Base Address Register — spec MMIO Offset 0008h.
/// Bits [59:56] = ComLen (power-of-2), [51:12] = ComBase.
const MMIO_CMD_BUF_BASE = 0x0008;

/// Event Log Base Address Register — spec MMIO Offset 0010h.
/// Bits [59:56] = EventLen (power-of-2), [51:12] = EventBase.
const MMIO_EVT_LOG_BASE = 0x0010;

/// IOMMU Control Register — spec MMIO Offset 0018h.
/// Controls IOMMU enable, command buffer enable, event log enable, etc.
const MMIO_CONTROL = 0x0018;

/// Command Buffer Tail Pointer — spec MMIO Offset 2008h.
/// Bits [18:4] = CmdTailPtr (16-byte aligned offset from buffer base).
/// Written by software after enqueueing commands.
const MMIO_CMD_BUF_TAIL = 0x2008;

// ---------------------------------------------------------------------------
// IOMMU Control Register bit definitions (spec MMIO Offset 0018h)
// ---------------------------------------------------------------------------

/// IommuEn (bit 0): Master enable — all upstream transactions processed by IOMMU.
const CTRL_IOMMU_EN: u64 = 1 << 0;

/// EventLogEn (bit 2): Enable event logging to the Event Log buffer.
const CTRL_EVT_LOG_EN: u64 = 1 << 2;

/// CmdBufEn (bit 12): Start/restart command buffer processing.
const CTRL_CMD_BUF_EN: u64 = 1 << 12;

/// Coherent (bit 10): Device Table reads are snooped by the processor.
/// When set, IOMMU page table walks use coherent (snooped) accesses,
/// so software doesn't need explicit cache flushes after page table updates.
const CTRL_COHERENT_EN: u64 = 1 << 10;

// ---------------------------------------------------------------------------
// I/O Page Table Entry (PTE/PDE) bit definitions (spec Section 2.2.3, Figures 8-10)
// ---------------------------------------------------------------------------

/// IR (bit 61): I/O read permission. Set in both DTEs and page table entries.
/// Effective read permission is the AND of IR across the DTE and all walked entries.
const AMDVI_IR: u64 = 1 << 61;

/// IW (bit 62): I/O write permission. Set in both DTEs and page table entries.
/// Effective write permission is the AND of IW across the DTE and all walked entries.
const AMDVI_IW: u64 = 1 << 62;

/// Combined read+write permission bits for convenience.
const AMDVI_RW: u64 = AMDVI_IR | AMDVI_IW;

/// Mask for the page-aligned physical address field in page table entries.
/// Bits [51:12] hold the system physical address; bits [63:52] and [11:0] are
/// control/attribute fields (spec Table 17, Table 18).
const AMDVI_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// Command opcodes (spec Section 2.4, Figure 40)
//
// All IOMMU commands are 128 bits. The generic format places the 4-bit opcode
// at bits [31:28] of the +04 dword, which corresponds to bits [63:60] of the
// first 64-bit word when stored little-endian in memory.
// ---------------------------------------------------------------------------

/// COMPLETION_WAIT — spec Section 2.4.1, opcode 01h.
const CMD_COMPLETION_WAIT: u64 = @as(u64, 0x01) << 60;

/// INVALIDATE_DEVTAB_ENTRY — spec Section 2.4.2, opcode 02h.
const CMD_INVALIDATE_DEVTAB_ENTRY: u64 = @as(u64, 0x02) << 60;

/// INVALIDATE_IOMMU_PAGES — spec Section 2.4.3, opcode 03h.
const CMD_INVALIDATE_IOMMU_PAGES: u64 = @as(u64, 0x03) << 60;

const MAX_IOMMU_UNITS = 4;
const MAX_ALIASES = 128;

const IommuUnit = struct {
    base: u64 = 0,
    dev_table_phys: PAddr = PAddr.fromInt(0),
    dev_table_virt: VAddr = VAddr.fromInt(0),
    dev_table_size: u64 = 0,
    cmd_buf_phys: PAddr = PAddr.fromInt(0),
    cmd_buf_virt: VAddr = VAddr.fromInt(0),
    /// Command buffer length in bytes (minimum 4KB = 256 entries of 16 bytes).
    cmd_buf_len: u64 = 0,
    active: bool = false,

    /// Read a 64-bit MMIO register at the given offset from the unit's base.
    fn readReg64(self: *const IommuUnit, offset: u32) u64 {
        const ptr: *const volatile u64 = @ptrFromInt(self.base + offset);
        return ptr.*;
    }

    /// Write a 64-bit MMIO register at the given offset from the unit's base.
    fn writeReg64(self: *const IommuUnit, offset: u32, value: u64) void {
        const ptr: *volatile u64 = @ptrFromInt(self.base + offset);
        ptr.* = value;
    }

    /// Enqueue a 128-bit command into the circular command buffer and advance
    /// the tail pointer to notify the IOMMU.
    ///
    /// Spec Section 2.4 / Figure 39: Commands are 128 bits (16 bytes). Software
    /// writes the command at the current tail offset, then advances the tail
    /// pointer register. The IOMMU fetches commands between head and tail.
    ///
    /// Spec Section 3.3.13, MMIO Offset 2008h: CmdTailPtr is at bits [18:4],
    /// representing a 16-byte-aligned byte offset from the buffer base.
    fn issueCommand(self: *const IommuUnit, lo: u64, hi: u64) void {
        const tail = self.readReg64(MMIO_CMD_BUF_TAIL);
        const cmd_ptr: [*]volatile u64 = @ptrFromInt(self.cmd_buf_virt.addr + tail);
        cmd_ptr[0] = lo;
        cmd_ptr[1] = hi;
        // Advance tail by 16 bytes (one command entry), wrapping at buffer length.
        // For the minimum 4KB buffer this wraps at 0x1000.
        self.writeReg64(MMIO_CMD_BUF_TAIL, (tail + 16) % self.cmd_buf_len);
    }

    /// Issue INVALIDATE_DEVTAB_ENTRY for the given DeviceID.
    ///
    /// Spec Section 2.4.2, Figure 42:
    ///   lo[15:0]  = DeviceID
    ///   lo[31:16] = Reserved
    ///   lo[63:60] = Opcode 02h
    ///   hi        = Reserved (zero)
    ///
    /// Forces the IOMMU to discard its cached copy of this device's DTE so that
    /// subsequent DMA from the device triggers a fresh DTE fetch from memory.
    fn invalidateDeviceEntry(self: *const IommuUnit, device_id: u16) void {
        self.issueCommand(
            CMD_INVALIDATE_DEVTAB_ENTRY | @as(u64, device_id),
            0,
        );
    }

    /// Issue INVALIDATE_IOMMU_PAGES for all pages in the given domain.
    ///
    /// Spec Section 2.4.3, Figure 43:
    ///   lo[19:0]  = PASID (zero — no guest translation)
    ///   lo[31:20] = Reserved
    ///   lo[47:32] = DomainID
    ///   lo[59:48] = Reserved
    ///   lo[63:60] = Opcode 03h
    ///   hi[0]     = S (size: 1 = use address-encoded size)
    ///   hi[1]     = PDE (1 = also flush page directory entries)
    ///   hi[2]     = GN (0 = guest physical / nested)
    ///   hi[63:12] = Address[63:12]
    ///
    /// To invalidate ALL cached translations for the domain, set S=1, PDE=1,
    /// and Address[63:12] = 0x7_FFFF_FFFF_FFFF (spec software note in 2.4.3).
    fn invalidateAllPages(self: *const IommuUnit, domain_id: u16) void {
        const lo = CMD_INVALIDATE_IOMMU_PAGES | (@as(u64, domain_id) << 32);
        // S=1 (bit 0), PDE=1 (bit 1), Address[63:12] all 1s except bit 63
        // Address[31:12] = 0xFFFFF in hi[31:12], Address[63:32] = 0x7FFFFFFF in hi[63:32]
        const hi: u64 = 0x7FFF_FFFF_FFFF_F003;
        self.issueCommand(lo, hi);
    }

    /// Page-selective INVALIDATE_IOMMU_PAGES. Encodes a power-of-two-page
    /// invalidation window starting at `iova`. Spec §2.4.3 software note:
    /// Address bits below the encoded size are interpreted as 1, so the
    /// command flushes all translations for [iova_aligned, iova_aligned +
    /// size). When `pde` is true the IOMMU also flushes intermediate page
    /// directory entries (required after an unmap that may have removed
    /// non-leaf entries — we leave that to the bulk invalidator).
    fn invalidatePage(self: *const IommuUnit, domain_id: u16, iova: u64, size_log2: u6) void {
        const lo = CMD_INVALIDATE_IOMMU_PAGES | (@as(u64, domain_id) << 32);
        // S=1 (size encoded in address), PDE=0, GN=0.
        // Address[63:12] = iova[63:12] | low (size_log2-12) bits set to 1.
        const aligned = iova & ~((@as(u64, 1) << @as(u6, @intCast(size_log2))) - 1);
        var addr_field: u64 = aligned;
        if (size_log2 > 12) {
            // S=1 encodes size by setting bits below the page-aligned address
            // up to (size_log2 - 1) inclusive in the command's address field.
            const fill_mask: u64 = ((@as(u64, 1) << @as(u6, @intCast(size_log2))) - 1) & ~@as(u64, 0xFFF);
            addr_field |= fill_mask;
        }
        const hi: u64 = (addr_field & ~@as(u64, 0xFFF)) | 0x1; // S=1
        self.issueCommand(lo, hi);
    }

    /// Issue COMPLETION_WAIT to synchronize with the IOMMU command stream.
    ///
    /// Spec Section 2.4.1, Figure 41:
    ///   lo[0]     = s (store): 0 = no store
    ///   lo[1]     = i (interrupt): 0 = no interrupt
    ///   lo[2]     = f (flush queue): 1 = strict ordering, subsequent commands
    ///               wait until this completes
    ///   lo[63:60] = Opcode 01h
    ///   hi        = Store data (unused when s=0)
    ///
    /// This command does not finish until all older commands have completed.
    /// Software must issue this after invalidation sequences before allowing
    /// device DMA to ensure no stale translations persist (spec Section 2.4.9).
    fn completionWait(self: *const IommuUnit) void {
        // f=1 (flush queue), s=0, i=0
        self.issueCommand(CMD_COMPLETION_WAIT | 0x4, 0);
    }
};

const AliasEntry = struct {
    source: u16 = 0,
    alias: u16 = 0,
};

/// Per-device IOMMU side-state. Stashed via DeviceRegion.iommu_state on
/// first map; reused by subsequent map/unmap/invalidate. Bounded pool;
/// DMA-capable PCI device count fits comfortably in MAX_DEVICE_REGIONS.
const PerDevice = struct {
    /// Level-4 (PML4) page-table root — physical address.
    pt_root_phys: PAddr = PAddr.fromInt(0),
    /// Same root, kernel-virt for software walks.
    pt_root_virt: VAddr = VAddr.fromInt(0),
    /// Device id used as both BDF requester and DomainID (spec Table 7).
    device_id: u16 = 0,
    provisioned: bool = false,
};

const MAX_PER_DEVICE: usize = stygia.devices.device_region.MAX_DEVICE_REGIONS;
var per_device_pool: [MAX_PER_DEVICE]PerDevice = [_]PerDevice{.{}} ** MAX_PER_DEVICE;
var per_device_used: usize = 0;

var units: [MAX_IOMMU_UNITS]IommuUnit = .{IommuUnit{}} ** MAX_IOMMU_UNITS;
var unit_count: u32 = 0;
var aliases: [MAX_ALIASES]AliasEntry = .{AliasEntry{}} ** MAX_ALIASES;
var alias_count: u32 = 0;
var translation_enabled: bool = false;

fn allocZeroedPage() !struct { phys: PAddr, virt: VAddr } {
    const pmm_mgr = &pmm.global_pmm.?;
    const page = try pmm_mgr.create(paging.PageMem(.page4k));
    const virt = VAddr.fromInt(@intFromPtr(page));
    const phys = PAddr.fromVAddr(virt, null);
    return .{ .phys = phys, .virt = virt };
}

/// Register an alias mapping from IVRS device entries.
/// When the IOMMU sees DMA from `source`, it uses `alias` to index the Device Table.
pub fn addAlias(source: u16, alias: u16) void {
    if (alias_count < MAX_ALIASES) {
        aliases[alias_count] = .{ .source = source, .alias = alias };
        alias_count += 1;
    }
}

/// Look up whether a device BDF has an alias (e.g., from IVRS ACPI table).
/// Returns the alias DeviceID if found, otherwise the original BDF.
fn lookupAlias(bdf: u16) u16 {
    for (aliases[0..alias_count]) |entry| {
        if (entry.source == bdf) return entry.alias;
    }
    return bdf;
}

/// Initialize one IOMMU unit given its MMIO register base physical address.
///
/// This follows the startup sequence from spec Section 2.3.1:
///   1. Allocate and zero the Device Table; program MMIO Offset 0000h.
///   2. Allocate and zero the Command Buffer; program MMIO Offset 0008h.
///   3. Allocate and zero the Event Log; program MMIO Offset 0010h.
///   4. Initialize head/tail pointers to 0 (reset default).
///   5. Enable the IOMMU via the Control Register (MMIO Offset 0018h).
pub fn init(reg_base_phys: PAddr) !void {
    if (unit_count >= MAX_IOMMU_UNITS) return;

    var unit = &units[unit_count];

    // Map the IOMMU's MMIO register space (16KB = 4 pages) into kernel VA space.
    // The register space extends from the base through at least offset 0x2048
    // (command/event pointer registers), so 4 pages covers it.
    const num_mmio_pages: u32 = 4;
    var i: u32 = 0;
    while (i < num_mmio_pages) {
        const page_phys = PAddr.fromInt(reg_base_phys.addr + @as(u64, i) * paging.PAGE4K);
        const page_virt = VAddr.fromPAddr(page_phys, null);
        arch_paging.mapPage(memory_init.kernel_addr_space_root, page_phys, page_virt, MMIO_PERMS, .kernel_mmio) catch {
            i += 1;
            continue;
        };
        i += 1;
    }
    unit.base = VAddr.fromPAddr(reg_base_phys, null).addr;

    // -----------------------------------------------------------------------
    // Device Table: 65536 entries × 32 bytes = 2MB (512 pages).
    //
    // Spec Section 2.2.2: The Device Table is an array of 256-bit (32-byte)
    // entries indexed by the 16-bit DeviceID. Must be 4KB-aligned and a
    // multiple of 4KB in size.
    // -----------------------------------------------------------------------
    const dt_pages: u32 = 512;
    const dt_size = @as(u64, dt_pages) * paging.PAGE4K;
    const pmm_mgr = &pmm.global_pmm.?;
    const dt_mem = pmm_mgr.allocBlock(dt_size) orelse return error.OutOfMemory;

    // Initialize all DTEs to block DMA by default.
    //
    // Spec Table 8, V=1/TV=1/GV=0: "All fields in bits [127:2] are valid and
    // GPA-to-SPA translation is active." With Mode=000b, translation is
    // disabled and access is controlled by IR and IW (spec Table 7, Mode field).
    // Since IR=0 and IW=0, all device-initiated DMA reads and writes are
    // target-aborted by the IOMMU.
    {
        var dte_idx: u64 = 0;
        while (dte_idx < 65536) {
            const dte: *volatile u64 = @ptrFromInt(@intFromPtr(dt_mem) + dte_idx * 32);
            // V=1 (bit 0), TV=1 (bit 1) — blocks all DMA with IR=0, IW=0.
            dte.* = 0x3;
            dte_idx += 1;
        }
    }
    const dt_virt = VAddr.fromInt(@intFromPtr(dt_mem));
    unit.dev_table_phys = PAddr.fromVAddr(dt_virt, null);
    unit.dev_table_virt = dt_virt;
    unit.dev_table_size = dt_size;

    // Program the Device Table Base Address Register (MMIO Offset 0000h).
    //
    // Spec Section 3.3.1, MMIO Offset 0000h:
    //   Bits [51:12] = DevTabBase (4KB-aligned physical address)
    //   Bits [8:0]   = Size: unsigned n where table size = (n + 1) * 4KB
    //
    // For the full 2MB table: n = (2MB / 4KB) - 1 = 511 = 0x1FF.
    const dt_size_field: u64 = (dt_size / paging.PAGE4K) - 1;
    unit.writeReg64(MMIO_DEV_TABLE_BASE, unit.dev_table_phys.addr | (dt_size_field & 0x1FF));

    // -----------------------------------------------------------------------
    // Command Buffer: 4KB = 256 entries of 16 bytes each.
    //
    // Spec Section 3.3.1, MMIO Offset 0008h:
    //   Bits [59:56] = ComLen: power-of-2 length (min 1000b = 256 entries = 4KB)
    //   Bits [51:12] = ComBase: 4KB-aligned physical address
    //   Bits [11:0]  = Reserved
    //
    // ComLen = 8 (1000b) → 2^8 = 256 entries → 256 * 16 = 4096 bytes.
    // -----------------------------------------------------------------------
    const cmd = try allocZeroedPage();
    unit.cmd_buf_phys = cmd.phys;
    unit.cmd_buf_virt = cmd.virt;
    unit.cmd_buf_len = paging.PAGE4K;
    const cmd_len_bits: u64 = 8;
    unit.writeReg64(MMIO_CMD_BUF_BASE, unit.cmd_buf_phys.addr | (cmd_len_bits << 56));

    // -----------------------------------------------------------------------
    // Event Log: 4KB = 256 entries of 16 bytes each.
    //
    // Spec Section 3.3.1, MMIO Offset 0010h: same layout as Command Buffer.
    // EventLen = 8 → 256 entries (4KB).
    // -----------------------------------------------------------------------
    const evt = try allocZeroedPage();
    const evt_len_bits: u64 = 8;
    unit.writeReg64(MMIO_EVT_LOG_BASE, evt.phys.addr | (evt_len_bits << 56));

    // -----------------------------------------------------------------------
    // Prepare the IOMMU Control Register (MMIO Offset 0018h).
    //
    // Enable the command buffer, event log, and coherent mode now so that
    // first-map provisioning can issue invalidation commands. IommuEn is
    // deferred to enableTranslation() — enabling now with empty page tables
    // would fault any early device DMA (same deferral strategy as Intel VT-d).
    //
    // Spec Section 3.3.1, MMIO Offset 0018h:
    //   Bit  0: IommuEn    — master enable (deferred)
    //   Bit  2: EventLogEn — events written to the Event Log
    //   Bit 10: Coherent   — DTE reads are snooped (coherent with CPU caches)
    //   Bit 12: CmdBufEn   — start fetching commands from the command buffer
    // -----------------------------------------------------------------------
    var ctrl = unit.readReg64(MMIO_CONTROL);
    ctrl |= CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN | CTRL_COHERENT_EN;
    unit.writeReg64(MMIO_CONTROL, ctrl);

    unit.active = true;
    unit_count += 1;
}

/// Configure a device's DTE on first map. Allocates a fresh level-4 root
/// page table for the device and programs the DTE for 4-level host
/// translation (Mode=100b → 48-bit DMA address space, spec Table 7 Mode
/// field / Table 15).
///
/// Spec Section 2.2.2.2 (Making Device Table Entry Changes):
///   When V=1 before the change, the DTE must be updated carefully. We
///   clear V first to mark the entry invalid, write all fields, then set
///   V=1 as the final step, followed by INVALIDATE_DEVTAB_ENTRY.
fn ensureProvisioned(device: *DeviceRegion) !*PerDevice {
    if (device.iommu_state) |state| {
        return @ptrCast(@alignCast(state));
    }
    if (unit_count == 0) return error.NotInitialized;
    if (!device.pci.isValid()) return error.NotPci;
    if (per_device_used >= per_device_pool.len) return error.OutOfMemory;

    const pd = &per_device_pool[per_device_used];
    per_device_used += 1;

    const bdf = device.pci.bdf();
    const device_id = lookupAlias(bdf);

    const pt = try allocZeroedPage();
    pd.pt_root_phys = pt.phys;
    pd.pt_root_virt = pt.virt;
    pd.device_id = device_id;
    pd.provisioned = true;

    // Build the DTE quadwords (spec Figure 7, Table 7).
    //   QW0:
    //     Bit  0:      V  = 1 (entry valid)
    //     Bit  1:      TV = 1 (translation info valid)
    //     Bits [11:9]: Mode = 100b (4-level page table → 48-bit GPA space)
    //     Bits [51:12]: Host Page Table Root Pointer
    //     Bit  61:     IR = 1 (DMA reads allowed)
    //     Bit  62:     IW = 1 (DMA writes allowed)
    //   QW1:
    //     Bits [79:64]: DomainID — the IOMMU uses this to tag IOTLB entries.
    //                  We use the aliased DeviceID for natural uniqueness.
    const mode: u64 = 4;
    const qw0 = 0x3 | (mode << 9) | (pt.phys.addr & AMDVI_ADDR_MASK) | AMDVI_RW;
    const qw1 = @as(u64, device_id);

    for (units[0..unit_count]) |*unit| {
        if (!unit.active) continue;

        const entry_offset = @as(u64, device_id) * 32;
        if (entry_offset + 32 > unit.dev_table_size) continue;
        const entry_base: [*]volatile u64 = @ptrFromInt(unit.dev_table_virt.addr + entry_offset);

        // Spec Section 2.2.2.2: When V=1 before the change, clear V first
        // to prevent the IOMMU from seeing a partially-updated DTE.
        entry_base[0] = 0;
        entry_base[3] = 0;
        entry_base[2] = 0;
        entry_base[1] = qw1;
        // Write qw0 last — this sets V=1, making the entry live.
        entry_base[0] = qw0;

        unit.invalidateDeviceEntry(device_id);
        unit.invalidateAllPages(device_id);
        unit.completionWait();

        // If this device has an alias, also program the DTE at the original
        // BDF so the IOMMU handles both the aliased and original requester
        // IDs.
        if (device_id == bdf) continue;
        const bdf_offset = @as(u64, bdf) * 32;
        if (bdf_offset + 32 <= unit.dev_table_size) {
            const bdf_entry: [*]volatile u64 = @ptrFromInt(unit.dev_table_virt.addr + bdf_offset);
            bdf_entry[0] = 0;
            bdf_entry[3] = 0;
            bdf_entry[2] = 0;
            bdf_entry[1] = qw1;
            bdf_entry[0] = qw0;

            unit.invalidateDeviceEntry(bdf);
            unit.invalidateAllPages(bdf);
            unit.completionWait();
        }
    }

    device.iommu_state = @ptrCast(pd);
    return pd;
}

/// Construct a non-leaf (Page Directory Entry) I/O page table entry.
///
/// Spec Section 2.2.3, Figure 10, Table 18 (PDE fields, PR=1):
///   Bit  0:      PR = 1 (present)
///   Bits [11:9]: NextLevel (level of the page table this entry points to;
///                must not be 000b or 111b for a PDE)
///   Bits [51:12]: Next Table Address (SPA of the child page table)
///   Bit  61:     IR = 1 (read permission — ANDed into cumulative perms)
///   Bit  62:     IW = 1 (write permission — ANDed into cumulative perms)
fn amdviNonLeaf(phys_addr: u64, next_level: u64) u64 {
    return (phys_addr & AMDVI_ADDR_MASK) | (next_level << 9) | AMDVI_RW | 0x1;
}

/// Construct a leaf (Page Translation Entry) I/O page table entry for a 4KB page.
///
/// Spec Section 2.2.3, Figure 9, Table 17 (PTE fields, PR=1):
///   Bit  0:      PR = 1 (present)
///   Bits [11:9]: NextLevel = 000b (page translation entry, not a directory)
///   Bits [51:12]: Page Address (SPA of the 4KB physical page)
///   Bit  61:     IR set per `perms.read`
///   Bit  62:     IW set per `perms.write`
fn amdviLeaf(phys_addr: u64, perms: MemoryPerms) u64 {
    var entry: u64 = (phys_addr & AMDVI_ADDR_MASK) | 0x1;
    if (perms.read) entry |= AMDVI_IR;
    if (perms.write) entry |= AMDVI_IW;
    return entry;
}

/// Construct a leaf for a larger (2MB / 1GB) page. Spec Table 17:
/// NextLevel = 7 selects a "default page" leaf at the entry's level —
/// the IOMMU stops the walk at this level. The spec encodes the level
/// in NextLevel; for a 2MB leaf placed in the level-2 table NextLevel=7,
/// for a 1GB leaf placed in level-3 NextLevel=7 also (the entry's host
/// table position determines the page size).
fn amdviLargeLeaf(phys_addr: u64, perms: MemoryPerms) u64 {
    var entry: u64 = (phys_addr & AMDVI_ADDR_MASK) | (@as(u64, 7) << 9) | 0x1;
    if (perms.read) entry |= AMDVI_IR;
    if (perms.write) entry |= AMDVI_IW;
    return entry;
}

/// Check the Present bit (bit 0) of a page table entry.
/// Spec Table 16: PR=0 means the entry is not present; remaining bits are ignored.
fn amdviPresent(entry: u64) bool {
    return (entry & 0x1) != 0;
}

fn pageSizeBytes(sz: VmarPageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0,
    };
}

fn pageSizeLog2(sz: VmarPageSize) u6 {
    return switch (sz) {
        .sz_4k => 12,
        .sz_2m => 21,
        .sz_1g => 30,
        ._reserved => 0,
    };
}

/// Map a single IOVA → phys at the requested page size in `device`'s I/O
/// page table. Walks (and lazily allocates) the 4-level tree rooted at the
/// device's `pt_root_virt`, creating intermediate PDEs as needed and
/// installing a leaf PTE.
///
/// Spec Section 2.2.3, Table 15 (level parameters for 4-level mode):
///   Level 4: indexes bits [47:39] of the IOVA
///   Level 3: indexes bits [38:30]
///   Level 2: indexes bits [29:21]
///   Level 1: indexes bits [20:12]
pub fn mapPage(
    device: *DeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VmarPageSize,
    perms: MemoryPerms,
) !void {
    if (unit_count == 0) return error.NotInitialized;
    const pd = try ensureProvisioned(device);

    const pml4: *[512]u64 = @ptrFromInt(pd.pt_root_virt.addr);
    const pml4_idx: u9 = @truncate((iova >> 39) & 0x1FF);
    const pdpt_idx: u9 = @truncate((iova >> 30) & 0x1FF);
    const pd_idx: u9 = @truncate((iova >> 21) & 0x1FF);
    const pt_idx: u9 = @truncate((iova >> 12) & 0x1FF);

    // Level 4 → Level 3
    if (!amdviPresent(pml4[pml4_idx])) {
        const page = try allocZeroedPage();
        pml4[pml4_idx] = amdviNonLeaf(page.phys.addr, 3);
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & AMDVI_ADDR_MASK), null).addr);

    if (sz == .sz_1g) {
        // 1GB leaf at level 3.
        pdpt[pdpt_idx] = amdviLargeLeaf(phys.addr & 0xFFFF_FFFF_C000_0000, perms);
        return;
    }

    // Level 3 → Level 2
    if (!amdviPresent(pdpt[pdpt_idx])) {
        const page = try allocZeroedPage();
        pdpt[pdpt_idx] = amdviNonLeaf(page.phys.addr, 2);
    }
    const pd_table: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & AMDVI_ADDR_MASK), null).addr);

    if (sz == .sz_2m) {
        pd_table[pd_idx] = amdviLargeLeaf(phys.addr & 0xFFFF_FFFF_FFE0_0000, perms);
        return;
    }

    // Level 2 → Level 1
    if (!amdviPresent(pd_table[pd_idx])) {
        const page = try allocZeroedPage();
        pd_table[pd_idx] = amdviNonLeaf(page.phys.addr, 1);
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd_table[pd_idx] & AMDVI_ADDR_MASK), null).addr);

    // Level 1 leaf
    pt[pt_idx] = amdviLeaf(phys.addr, perms);
}

/// Remove the mapping for a single IOVA from `device`'s I/O page table at
/// the given page size. Returns the previously bound physical address, or
/// null if the IOVA was not mapped at that size.
pub fn unmapPage(device: *DeviceRegion, iova: u64, sz: VmarPageSize) ?PAddr {
    if (unit_count == 0) return null;
    const state = device.iommu_state orelse return null;
    const pd: *PerDevice = @ptrCast(@alignCast(state));
    if (!pd.provisioned) return null;

    const pml4: *[512]u64 = @ptrFromInt(pd.pt_root_virt.addr);
    const pml4_idx: u9 = @truncate((iova >> 39) & 0x1FF);
    if (!amdviPresent(pml4[pml4_idx])) return null;

    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & AMDVI_ADDR_MASK), null).addr);
    const pdpt_idx: u9 = @truncate((iova >> 30) & 0x1FF);

    if (sz == .sz_1g) {
        const entry = pdpt[pdpt_idx];
        if (!amdviPresent(entry)) return null;
        // Large-page leaves carry NextLevel=7 in bits [11:9].
        if (((entry >> 9) & 0x7) != 7) return null;
        pdpt[pdpt_idx] = 0;
        return PAddr.fromInt(entry & 0xFFFF_FFFF_C000_0000);
    }
    if (!amdviPresent(pdpt[pdpt_idx])) return null;

    const pd_table: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & AMDVI_ADDR_MASK), null).addr);
    const pd_idx: u9 = @truncate((iova >> 21) & 0x1FF);

    if (sz == .sz_2m) {
        const entry = pd_table[pd_idx];
        if (!amdviPresent(entry)) return null;
        if (((entry >> 9) & 0x7) != 7) return null;
        pd_table[pd_idx] = 0;
        return PAddr.fromInt(entry & 0xFFFF_FFFF_FFE0_0000);
    }
    if (!amdviPresent(pd_table[pd_idx])) return null;

    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd_table[pd_idx] & AMDVI_ADDR_MASK), null).addr);
    const pt_idx: u9 = @truncate((iova >> 12) & 0x1FF);
    const entry = pt[pt_idx];
    if (!amdviPresent(entry)) return null;
    pt[pt_idx] = 0;
    return PAddr.fromInt(entry & AMDVI_ADDR_MASK);
}

/// Page-selective IOTLB invalidation for `[iova, iova + page_count*sz)`.
/// Issues one INVALIDATE_IOMMU_PAGES per page and a trailing
/// COMPLETION_WAIT so the caller observes the flush before resuming.
pub fn invalidatePageRange(
    device: *DeviceRegion,
    iova: u64,
    sz: VmarPageSize,
    page_count: u32,
) void {
    if (unit_count == 0) return;
    const state = device.iommu_state orelse return;
    const pd: *PerDevice = @ptrCast(@alignCast(state));
    if (!pd.provisioned) return;

    const sz_bytes = pageSizeBytes(sz);
    if (sz_bytes == 0) return;
    const log2 = pageSizeLog2(sz);

    for (units[0..unit_count]) |*unit| {
        if (!unit.active) continue;
        var i: u32 = 0;
        while (i < page_count) {
            const page_iova = iova + @as(u64, i) * sz_bytes;
            unit.invalidatePage(pd.device_id, page_iova, log2);
            i += 1;
        }
        unit.completionWait();
    }
}

/// Enable DMA translation by setting IommuEn on all active units.
///
/// Called after first-map provisioning has populated each device's DTE.
/// Without this deferral, early device DMA would fault against empty page
/// tables (same pattern as Intel VT-d's deferred TE).
pub fn enableTranslation() void {
    if (translation_enabled) return;
    for (units[0..unit_count]) |*unit| {
        if (unit.active) {
            var ctrl = unit.readReg64(MMIO_CONTROL);
            ctrl |= CTRL_IOMMU_EN;
            unit.writeReg64(MMIO_CONTROL, ctrl);
        }
    }
    translation_enabled = true;
}
