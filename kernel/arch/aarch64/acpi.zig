//! AArch64 ACPI table parsing.
//!
//! Parses the same ACPI tables as x64 (XSDT, MADT, SPCR) but extracts
//! ARM-specific interrupt controller information instead of APIC structures.
//!
//! Key differences from x64:
//! - MADT contains GIC CPU Interface (type 0x0B), GIC Distributor (type 0x0C),
//!   GIC MSI Frame (type 0x0D), and GIC Redistributor (type 0x0E) structures
//!   instead of Local APIC / IO APIC entries.
//! - SPCR (Serial Port Console Redirection) provides the PL011 UART base address.
//! - GTDT (Generic Timer Description Table) provides timer interrupt numbers
//!   and flags for the ARM Generic Timer.
//! - IORT (IO Remapping Table) describes SMMU topology for DMA remapping.
//!
//! References:
//! - ACPI 6.5, Section 5.2.12: Multiple APIC Description Table (MADT)
//! - ACPI 6.5, Table 5-45: GIC CPU Interface (GICC, type 0x0B)
//! - ACPI 6.5, Table 5-47: GIC Distributor (GICD, type 0x0C)
//! - ACPI 6.5, Table 5-49: GIC Redistributor (GICR, type 0x0E)
//! - ACPI 6.5, Section 5.2.32: SPCR

const std = @import("std");
const stygia = @import("stygia");

const aarch64_paging = stygia.arch.aarch64.paging;
const gic = stygia.arch.aarch64.gic;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const power = stygia.arch.aarch64.power;
const rtc = stygia.arch.aarch64.rtc;
const serial = stygia.arch.aarch64.serial;
const smp = stygia.arch.aarch64.smp;

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;

/// Map an MMIO region as Device memory into the kernel's physmap range
/// (TTBR1). Returns the physmap VA that corresponds to `phys_start`.
///
/// The initial physmap built in memory.init() only covers RAM regions
/// reported as free/ACPI in the UEFI memory map, so low MMIO like the
/// GIC distributor at PA 0x08000000 has no valid translation in TTBR1
/// until we add one here. We map Device memory (not_cacheable) because
/// the regions are peripheral MMIO.
fn mapDeviceRange(phys_start: u64, length: u64) !u64 {
    const perms: MemoryPerms = .{ .read = true, .write = true };
    const page = paging.PAGE4K;
    const start_aligned = std.mem.alignBackward(u64, phys_start, page);
    const end_aligned = std.mem.alignForward(u64, phys_start + length, page);
    var pa: u64 = start_aligned;
    while (pa < end_aligned) {
        try aarch64_paging.mapPage(
            memory_init.kernel_addr_space_root,
            PAddr.fromInt(pa),
            VAddr.fromPAddr(PAddr.fromInt(pa), null),
            perms,
            .kernel_mmio,
        );
        pa += page;
    }
    return VAddr.fromPAddr(PAddr.fromInt(phys_start), null).addr;
}

const ValidationError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

/// ACPI 6.5, Section 5.2.12, Table 5-45 — MADT GICC (type 0x0B).
const Gicc = struct {
    cpu_interface_number: u32,
    acpi_processor_uid: u32,
    flags: u32,
    /// Physical base address of the GICv2 CPU interface registers (GICC).
    /// Zero on GICv3 systems (where the CPU interface is accessed via
    /// system registers rather than MMIO). ACPI 6.5 Table 5-45 offset 32.
    physical_base_address: u64,
    mpidr: u64,
};

/// ACPI 6.5, Section 5.2.12, Table 5-47 — MADT GICD (type 0x0C).
const Gicd = struct {
    physical_base_address: u64,
};

/// ACPI 6.5, Section 5.2.12, Table 5-49 — MADT GICR (type 0x0E).
const Gicr = struct {
    discovery_range_base: u64,
    discovery_range_length: u32,
};

/// MADT interrupt controller structure types for AArch64.
/// ACPI 6.5, Section 5.2.12, Table 5-44.
pub const MadtType = enum(u8) {
    gicc = 0x0B,
    gicd = 0x0C,
    gic_msi_frame = 0x0D,
    gicr = 0x0E,
    gic_its = 0x0F,
};

pub const AnyMadt = union(MadtType) {
    gicc: Gicc,
    gicd: Gicd,
    gic_msi_frame: []const u8,
    gicr: Gicr,
    gic_its: []const u8,
};

/// ACPI 6.5, Section 5.2.32 — Generic Address Structure.
pub const GenericAddressStruct = packed struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

/// ACPI 6.5, Section 5.2.32 — Serial Port Console Redirection Table (SPCR).
pub const SpcrTable = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    interface_type: u8,
    reserved: u24,
    base_address: GenericAddressStruct,

    pub fn fromVAddr(v: VAddr) *SpcrTable {
        @setRuntimeSafety(false);
        return @ptrFromInt(v.addr);
    }

    pub fn validate(self: *const SpcrTable) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "SPCR")) {
            return ValidationError.InvalidSignature;
        }
        var sum: u8 = 0;
        const bytes = @as([*]const u8, @ptrCast(self))[0..self.length];
        for (bytes) |b| {
            sum +%= b;
        }
        if (sum != 0) {
            return ValidationError.InvalidChecksum;
        }
    }
};

/// ACPI 6.5, Section 5.2.12 — Multiple APIC Description Table (MADT).
pub const Madt = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
    lapic_addr: u32,
    flags: u32,

    pub fn fromVAddr(madt_virt: VAddr) *Madt {
        @setRuntimeSafety(false);
        return @ptrFromInt(madt_virt.addr);
    }

    pub fn validate(self: *const Madt) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "APIC")) {
            return ValidationError.InvalidSignature;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| {
            sum +%= b;
        }
        if (sum != 0) {
            return ValidationError.InvalidChecksum;
        }
    }

    pub const EntryHeader = packed struct {
        kind: u8,
        length: u8,
    };

    pub const Entry = struct {
        header: EntryHeader,
        bytes: []const u8,
    };

    pub const Iterator = struct {
        madt: *const Madt,
        off: u64,

        pub fn init(m: *const Madt) Iterator {
            return .{
                .madt = m,
                .off = 36 + 8,
            };
        }

        pub fn next(self: *Iterator) ?Entry {
            if (self.off >= self.madt.length) return null;
            const bytes = self.madt.asBytes(self.madt.length);
            const hdr: *align(1) const EntryHeader = @ptrCast(bytes.ptr + self.off);
            const start = self.off;
            const len = hdr.length;
            if (len < 2 or start + len > self.madt.length) return null;
            self.off += len;
            return .{
                .header = hdr.*,
                .bytes = bytes[start .. start + len],
            };
        }
    };

    pub fn iter(self: *const Madt) Iterator {
        return Iterator.init(self);
    }

    fn asBytes(self: *const Madt, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

pub const Sdt = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    pub fn fromVAddr(sdt_virt: VAddr) *const Sdt {
        @setRuntimeSafety(false);
        return @ptrFromInt(sdt_virt.addr);
    }
};

/// ACPI 6.5, Section 5.2.5.3 — Extended System Description Pointer (XSDP).
pub const Xsdp = packed struct {
    signature: u64,
    checksum20: u8,
    oem_id: u48,
    revision: u8,
    rsdt_paddr: u32,
    length: u32,
    xsdt_paddr: u64,
    checksum_ext: u8,
    reserved: u24,

    pub fn fromVAddr(xsdp_virt: VAddr) *Xsdp {
        @setRuntimeSafety(false);
        return @ptrFromInt(xsdp_virt.addr);
    }

    pub fn validate(self: *const Xsdp) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "RSD PTR ")) {
            return ValidationError.InvalidSignature;
        }

        if (self.length < 36) {
            return ValidationError.InvalidSize;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| {
            sum +%= b;
        }
        if (sum != 0) {
            return ValidationError.InvalidChecksum;
        }
    }

    fn asBytes(self: *const Xsdp, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

/// ACPI 6.5, Section 5.2.8 — Extended System Description Table (XSDT).
pub const Xsdt = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
    entries_base: u64,

    pub fn fromVAddr(xsdt_virt: VAddr) *Xsdt {
        @setRuntimeSafety(false);
        return @ptrFromInt(xsdt_virt.addr);
    }

    pub fn validate(self: *const Xsdt) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "XSDT")) {
            return ValidationError.InvalidSignature;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| sum +%= b;
        if (sum != 0) return ValidationError.InvalidChecksum;
    }

    pub const Iterator = struct {
        xsdt: *const Xsdt,
        off: u64,

        pub fn init(x: *const Xsdt) Iterator {
            return .{
                .xsdt = x,
                .off = 36,
            };
        }

        pub fn next(self: *Iterator) ?u64 {
            if (self.off + 8 > self.xsdt.length) return null;
            const bytes = self.xsdt.asBytes(self.xsdt.length);
            const paddr = std.mem.readInt(u64, @ptrCast(bytes.ptr + self.off), .little);
            self.off += 8;
            return paddr;
        }
    };

    pub fn iter(self: *const Xsdt) Iterator {
        return Iterator.init(self);
    }

    fn asBytes(self: *const Xsdt, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

/// Decode a MADT entry into a typed AArch64 GIC structure.
///
/// p = e.bytes[2..] skips the 2-byte header (type + length), so p[0] = struct offset 2.
///
/// MADT GICC (type 0x0B, 80 bytes): ACPI 6.5, Table 5-45.
///   - offset 4:  u32 CPU Interface Number  (p + 2)
///   - offset 8:  u32 ACPI Processor UID    (p + 6)
///   - offset 12: u32 Flags (bit 0 = enabled) (p + 10)
///   - offset 32: u64 Physical Base Address (GICv2 GICC MMIO) (p + 30)
///   - offset 68: u64 MPIDR                 (p + 66)
///
/// MADT GICD (type 0x0C, 24 bytes): ACPI 6.5, Table 5-47.
///   - offset 8:  u64 Physical Base Address (p + 6, after 4-byte GIC ID)
///
/// MADT GICR (type 0x0E, 16 bytes): ACPI 6.5, Table 5-49.
///   - offset 4:  u64 Discovery Range Base Address (p + 2)
///   - offset 12: u32 Discovery Range Length       (p + 10)
pub fn decodeMadt(e: Madt.Entry) ?AnyMadt {
    const p = e.bytes[2..];
    return switch (e.header.kind) {
        @intFromEnum(MadtType.gicc) => .{
            .gicc = .{
                .cpu_interface_number = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
                .acpi_processor_uid = std.mem.readInt(u32, @ptrCast(p.ptr + 6), .little),
                .flags = std.mem.readInt(u32, @ptrCast(p.ptr + 10), .little),
                .physical_base_address = std.mem.readInt(u64, @ptrCast(p.ptr + 30), .little),
                .mpidr = std.mem.readInt(u64, @ptrCast(p.ptr + 66), .little),
            },
        },
        @intFromEnum(MadtType.gicd) => .{
            .gicd = .{
                .physical_base_address = std.mem.readInt(u64, @ptrCast(p.ptr + 6), .little),
            },
        },
        @intFromEnum(MadtType.gicr) => .{
            .gicr = .{
                .discovery_range_base = std.mem.readInt(u64, @ptrCast(p.ptr + 2), .little),
                .discovery_range_length = std.mem.readInt(u32, @ptrCast(p.ptr + 10), .little),
            },
        },
        @intFromEnum(MadtType.gic_msi_frame) => .{ .gic_msi_frame = e.bytes },
        @intFromEnum(MadtType.gic_its) => .{ .gic_its = e.bytes },
        else => null,
    };
}

/// Parse ACPI tables starting from the XSDP physical address.
///
/// Walks the XSDT to find:
/// - MADT ("APIC"): GIC distributor, redistributor, and CPU interface discovery.
/// - SPCR: PL011 UART base address for serial output.
/// - FADT ("FACP"): ARM Boot Architecture Flags → PSCI conduit (SMC vs HVC).
pub fn parseAcpi(xsdp_phys: PAddr) !void {
    // Direct-kernel boot has no ACPI at all — QEMU `virt -kernel` hands
    // us a DTB in x0 which we currently ignore. Skip the XSDP/XSDT walk
    // entirely when the bootloader passes a zero XSDP and fall through
    // to the PL011/RTC fallback block so the serial upper-half and the
    // wall-clock still get wired up.
    var saw_spcr = false;
    var gic_discovery: gic.GicDiscovery = .{};
    if (xsdp_phys.addr == 0) {
        saw_spcr = false;
    } else {
        const xsdp_virt = VAddr.fromPAddr(xsdp_phys, null);
        const xsdp = Xsdp.fromVAddr(xsdp_virt);
        try xsdp.validate();

        const xsdt_phys = PAddr.fromInt(xsdp.xsdt_paddr);
        const xsdt_virt = VAddr.fromPAddr(xsdt_phys, null);
        const xsdt = Xsdt.fromVAddr(xsdt_virt);
        try xsdt.validate();

        var xsdt_iter = xsdt.iter();
        while (xsdt_iter.next()) |sdt_paddr| {
            const sdt_phys = PAddr.fromInt(sdt_paddr);
            const sdt_virt = VAddr.fromPAddr(sdt_phys, null);
            const sdt = Sdt.fromVAddr(sdt_virt);

            if (std.mem.eql(u8, @ptrCast(&sdt.signature), "APIC")) {
                gic_discovery = try parseMadt(sdt_virt);
            }

            if (std.mem.eql(u8, @ptrCast(&sdt.signature), "SPCR")) {
                parseSpcr(sdt_virt);
                saw_spcr = true;
            }

            if (std.mem.eql(u8, @ptrCast(&sdt.signature), "FACP")) {
                parseFadt(sdt_virt);
            }
        }
    }

    // If SPCR was absent (some firmware omits it), fall back to the QEMU
    // virt PL011 at PA 0x09000000 and map it into physmap so the serial
    // driver's upper-half VA is translatable. serial.init() already set
    // base_addr to physmap+0x09000000 as a placeholder, but that VA is
    // not mapped until we do it here: memory.init() skips MMIO pages
    // when populating the physmap.
    if (!saw_spcr) {
        const pl011_phys: u64 = 0x09000000;
        const uart_vaddr = mapDeviceRange(pl011_phys, 0x1000) catch 0;
        if (uart_vaddr != 0) serial.setBase(uart_vaddr);
    }

    // QEMU `virt` exposes a PL031 RTC at PA 0x09010000 but does not
    // advertise it through any ACPI table we currently parse. Map the
    // MMIO page as Device memory and install its physmap VA so
    // `arch.time.readRtc()` returns a real wall-clock value. Physical
    // ARM platforms typically describe the RTC via the device tree or
    // SSDT; this hardcoded fallback targets the QEMU virt layout used
    // by the kernel test suite.
    const pl031_phys: u64 = 0x09010000;
    const rtc_vaddr = mapDeviceRange(pl031_phys, 0x1000) catch 0;
    if (rtc_vaddr != 0) rtc.setBase(rtc_vaddr);

    // GIC init must happen after MADT parsing so that the distributor,
    // CPU-interface, and redistributor bases are known. init.zig runs
    // before ACPI parsing, so it cannot do this itself. The discovery
    // state is an explicit argument rather than module globals — if the
    // MADT pass is skipped (e.g. direct-kernel boot with XSDP == 0), the
    // default-initialized `gic_discovery` simply leaves the driver with
    // zeroed state and the internal guards bail out safely.
    gic.init(gic_discovery);
}

// FADT (ACPI 6.5, Section 5.2.9, Table 5-34) — ARM Boot Architecture Flags.
// Located at offset 129 (decimal) into the FADT, length 2 bytes (u16).
// Bit 0: PSCI_COMPLIANT — firmware implements PSCI.
// Bit 1: PSCI_USE_HVC   — when set, PSCI calls must use HVC; otherwise SMC.
const FADT_ARM_BOOT_FLAGS_OFFSET: usize = 129;
const FADT_ARM_BOOT_FLAG_PSCI_COMPLIANT: u16 = 1 << 0;
const FADT_ARM_BOOT_FLAG_PSCI_USE_HVC: u16 = 1 << 1;

/// Parse FADT ARM Boot Architecture Flags to determine the PSCI conduit.
///
/// ACPI 6.5, Section 5.2.9, Table 5-34:
///   - offset 129, u16: ARM Boot Architecture Flags
///       bit 0 = PSCI_COMPLIANT
///       bit 1 = PSCI_USE_HVC (set → HVC, clear → SMC)
///
/// Behaviour:
///   - PSCI_COMPLIANT && PSCI_USE_HVC  → conduit = HVC
///   - PSCI_COMPLIANT && !PSCI_USE_HVC → conduit = SMC
///   - !PSCI_COMPLIANT                  → leave conduit at its default (SMC);
///     the caller has no PSCI to talk to anyway.
///
/// Older FADT revisions predating ACPI 5.1 do not have this field; guard on
/// table length so we never read past the end of the FADT.
fn parseFadt(fadt_virt: VAddr) void {
    const sdt = Sdt.fromVAddr(fadt_virt);
    const length = sdt.length;
    if (length < FADT_ARM_BOOT_FLAGS_OFFSET + @sizeOf(u16)) return;

    const base: [*]const u8 = @ptrFromInt(fadt_virt.addr);
    const flags = std.mem.readInt(u16, @ptrCast(base + FADT_ARM_BOOT_FLAGS_OFFSET), .little);

    if ((flags & FADT_ARM_BOOT_FLAG_PSCI_COMPLIANT) == 0) return;

    if ((flags & FADT_ARM_BOOT_FLAG_PSCI_USE_HVC) != 0) {
        power.setConduit(.hvc);
    } else {
        power.setConduit(.smc);
    }
}

/// Parse MADT to discover GIC components and core count.
///
/// Iterates all MADT entries to find:
/// - GICC entries (type 0x0B): count enabled cores.
/// - GICD entries (type 0x0C): extract distributor base address.
/// - GICR entries (type 0x0E): extract redistributor region base addresses.
///
/// Returns a `GicDiscovery` populated with the virtual-address topology
/// so that `gic.init(discovery)` receives its inputs through an explicit
/// argument rather than side-channel globals.
///
/// ACPI 6.5, Section 5.2.12.
fn parseMadt(madt_virt: VAddr) !gic.GicDiscovery {
    const madt = Madt.fromVAddr(madt_virt);
    try madt.validate();

    var discovery: gic.GicDiscovery = .{};

    // First pass: count enabled cores, store MPIDR values, and capture
    // the GICv2 GICC CPU-interface MMIO base if present. On GICv3 the
    // per-GICC physical_base_address field is zero because the CPU
    // interface is accessed via system registers, so we only record it
    // when non-zero.
    var madt_iter = madt.iter();
    var core_count: u64 = 0;
    var gicc_mmio_phys: u64 = 0;

    while (madt_iter.next()) |e| {
        const entry = decodeMadt(e) orelse continue;
        switch (entry) {
            .gicc => |gicc_entry| {
                if (gicc_entry.flags & 0x1 == 0) continue;
                smp.setMpidr(@intCast(core_count), gicc_entry.mpidr);
                core_count += 1;
                if (gicc_mmio_phys == 0 and gicc_entry.physical_base_address != 0) {
                    gicc_mmio_phys = gicc_entry.physical_base_address;
                }
            },
            else => {},
        }
    }

    if (gicc_mmio_phys != 0) {
        // GICv2 CPU interface is spec'd as an 8KB region (IHI 0048B §5.3).
        discovery.gicc_base = try mapDeviceRange(gicc_mmio_phys, 8 * 1024);
    }

    // Second pass: extract distributor and redistributor base addresses.
    // The redistributor slots populate `discovery.gicr_bases`, leaving
    // `core_count` (from the GICC pass above) independent so the two
    // counters can't clobber each other regardless of MADT entry order.
    madt_iter = madt.iter();

    while (madt_iter.next()) |e| {
        const entry = decodeMadt(e) orelse continue;
        switch (entry) {
            .gicd => |gicd_entry| {
                // GICv3 distributor occupies 64KB. Map into the physmap
                // range as Device memory so MMIO reads/writes translate.
                // The physmap built in memory.init() only covers RAM
                // regions, so low [0, 1GB) MMIO on QEMU virt needs an
                // explicit mapping here.
                // IHI 0069H, Section 8.1.
                const gicd_va = try mapDeviceRange(gicd_entry.physical_base_address, 64 * 1024);
                discovery.gicd_base = gicd_va;
            },
            .gicr => |gicr_entry| {
                // A GICR discovery range covers one or more redistributors
                // back-to-back. Each GICv3 redistributor occupies two 64KB
                // frames (RD_base + SGI_base) for a total 128KB stride.
                // IHI 0069H, Section 9.1.1 and Section 10.1.
                const stride: u64 = 128 * 1024;
                // Each GICv3 redistributor occupies two 64KB frames
                // (RD_base + SGI_base) for a total 128KB stride. Use
                // the ACPI-reported discovery-range length (rounded
                // up to a whole frame) as the source of truth, and
                // fall back to `core_count * stride` when ACPI leaves
                // the field unpopulated — some firmware/emulators
                // report 0 here.
                const reported_len: u64 = gicr_entry.discovery_range_length;
                const cores_for_redist: u64 = @max(@as(u64, 1), core_count);
                const range_len: u64 = if (reported_len >= stride)
                    std.mem.alignForward(u64, reported_len, stride)
                else
                    cores_for_redist * stride;
                // Map the entire discovery range into the physmap as
                // Device memory and hand back the physmap VA per frame.
                const gicr_va_base = try mapDeviceRange(gicr_entry.discovery_range_base, range_len);
                var offset: u64 = 0;
                while (offset + stride <= range_len) {
                    const idx: usize = @intCast(discovery.redist_count);
                    if (idx >= discovery.gicr_bases.len) break;
                    discovery.gicr_bases[idx] = gicr_va_base + offset;
                    discovery.redist_count += 1;
                    offset += stride;
                }
            },
            else => {},
        }
    }

    discovery.core_count = core_count;
    return discovery;
}

/// Parse SPCR to discover the PL011 UART base address.
///
/// ACPI 6.5, Section 5.2.32 — SPCR layout:
///   - offset 36: u8 Interface Type
///   - offset 40: GenericAddressStruct (12 bytes) containing UART base address.
///
/// The PL011 MMIO page is not included in the physmap built by memory.init()
/// (the physmap only covers RAM reported as free/ACPI in the UEFI memory map),
/// so we must explicitly map it as Device memory into the kernel address
/// space root before handing its physmap VA to the serial driver. Without
/// this, the first `arch.boot.print` from a syscall (e.g. sysWrite) translation
/// faults on the upper-half VA and the kernel hangs in a nested exception
/// loop.
fn parseSpcr(spcr_virt: VAddr) void {
    const spcr = SpcrTable.fromVAddr(spcr_virt);
    spcr.validate() catch return;

    const uart_paddr = spcr.base_address.address;
    if (uart_paddr == 0) return;

    const uart_vaddr_base = mapDeviceRange(uart_paddr, 0x1000) catch return;
    serial.setBase(uart_vaddr_base);
}
