const std = @import("std");
const stygia = @import("stygia");

const apic = stygia.arch.x64.apic;
const arch_paging = stygia.arch.x64.paging;
const cpu = stygia.arch.x64.cpu;
const device_region = stygia.devices.device_region;
const iommu = stygia.arch.x64.iommu;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const timers = stygia.arch.x64.timers;

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;

const ValidationError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

pub const MadtType = enum(u8) {
    local_apic = 0,
    ioapic = 1,
    int_src_override = 2,
    lapic_nmi = 4,
    lapic_addr_override = 5,
};

pub const AnyMadt = union(MadtType) {
    local_apic: LocalApic,
    ioapic: IoApic,
    int_src_override: IntSrcOverride,
    lapic_nmi: []const u8,
    lapic_addr_override: LapicAddrOverride,
};

pub const GenericAddressStruct = packed struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

/// IA-PC HPET Specification §3.2.4 — HPET Description Table layout.
pub const HpetTable = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    event_timer_block_id: u32,
    base_address: GenericAddressStruct,
    hpet_number: u8,
    min_tick: u16,
    page_protection: u8,

    pub fn fromVAddr(v: VAddr) *HpetTable {
        @setRuntimeSafety(false);
        return @ptrFromInt(v.addr);
    }

    pub fn validate(self: *const HpetTable) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "HPET")) {
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
        if (self.base_address.address_space_id != 0) {
            return ValidationError.InvalidSize;
        }
    }
};

pub const IoApic = packed struct {
    ioapic_id: u8,
    _rsvd: u8 = 0,
    ioapic_addr: u32,
    gsi_base: u32,
};

pub const IntSrcOverride = packed struct {
    bus: u8,
    src: u8,
    gsi: u32,
    flags: u16,
};

pub const LapicAddrOverride = packed struct {
    _rsvd: u16 = 0,
    addr: u64,
};

pub const LocalApic = packed struct {
    processor_uid: u8,
    apic_id: u8,
    flags: u32,
};

/// ACPI Specification §5.2.12 — Multiple APIC Description Table (MADT).
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

/// ACPI Specification §5.2.5.3 — Extended System Description Pointer (XSDP).
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

/// ACPI Specification §5.2.8 — Extended System Description Table (XSDT).
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

pub fn decodeMadt(e: Madt.Entry) AnyMadt {
    const p = e.bytes[2..];
    return switch (@as(MadtType, @enumFromInt(e.header.kind))) {
        .local_apic => .{
            .local_apic = .{
                .processor_uid = p[0],
                .apic_id = p[1],
                .flags = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
            },
        },
        .ioapic => .{
            .ioapic = .{
                .ioapic_id = p[0],
                .ioapic_addr = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
                .gsi_base = std.mem.readInt(u32, @ptrCast(p.ptr + 6), .little),
            },
        },
        .int_src_override => .{
            .int_src_override = .{
                .bus = p[0],
                .src = p[1],
                .gsi = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
                .flags = std.mem.readInt(u16, @ptrCast(p.ptr + 6), .little),
            },
        },
        .lapic_nmi => .{
            .lapic_nmi = e.bytes,
        },
        .lapic_addr_override => .{
            .lapic_addr_override = .{
                .addr = std.mem.readInt(u64, @ptrCast(p.ptr + 2), .little),
            },
        },
    };
}

pub fn parseAcpi(xsdp_phys: PAddr) !void {
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
        const sdt_virt_x = VAddr.fromPAddr(sdt_phys, null);
        const sdt = Sdt.fromVAddr(sdt_virt_x);

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "APIC")) {
            const madt = Madt.fromVAddr(sdt_virt_x);
            try madt.validate();

            var lapic_base: u64 = @intCast(madt.lapic_addr);
            var madt_iter = madt.iter();
            var lapics_count: u32 = 0;
            while (madt_iter.next()) |e| {
                const entry = decodeMadt(e);
                switch (entry) {
                    .local_apic => |la| {
                        if (la.flags & 0x1 == 0) continue;
                        // Firmware MADTs are untrusted input: a corrupt or
                        // oversized table enumerating > MAX_CORES enabled
                        // local APICs would otherwise overflow the static
                        // lapics_array and corrupt the next file-scope
                        // global. Clamp silently — apic.lapics is the only
                        // surface other subsystems read, and truncation is
                        // strictly safer than the alternative of bringing
                        // up cores whose per-cpu state doesn't exist.
                        if (lapics_count >= MAX_CORES) continue;
                        lapics_array[lapics_count] = la;
                        lapics_count += 1;
                    },
                    .ioapic => |io| {
                        // Map IOAPIC MMIO and stash its virtual base for
                        // any subsequent IOAPIC redirection programming
                        // (currently used by the HPET-NMI hang watchdog
                        // when FSB delivery isn't available).
                        const ioapic_phys = PAddr.fromInt(std.mem.alignBackward(u64, io.ioapic_addr, paging.PAGE4K));
                        const ioapic_virt = VAddr.fromPAddr(ioapic_phys, null);
                        const ioapic_perms: MemoryPerms = .{ .read = true, .write = true };
                        try arch_paging.mapPage(
                            memory_init.kernel_addr_space_root,
                            ioapic_phys,
                            ioapic_virt,
                            ioapic_perms,
                            .kernel_mmio,
                        );
                        stygia.arch.x64.irq.setIoapicBase(ioapic_virt.addr);
                    },
                    .int_src_override => |_| {},
                    .lapic_nmi => |_| {},
                    .lapic_addr_override => |x| {
                        lapic_base = x.addr;
                    },
                }
            }

            apic.lapics = lapics_array[0..lapics_count];

            const lapic_phys = PAddr.fromInt(std.mem.alignBackward(u64, lapic_base, paging.PAGE4K));
            const lapic_virt = VAddr.fromPAddr(lapic_phys, null);

            const mmio_perms: MemoryPerms = .{ .read = true, .write = true };

            try arch_paging.mapPage(
                memory_init.kernel_addr_space_root,
                lapic_phys,
                lapic_virt,
                mmio_perms,
                .kernel_mmio,
            );

            apic.init(lapic_virt);
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "HPET")) {
            const hpet_table = HpetTable.fromVAddr(sdt_virt_x);
            try hpet_table.validate();

            const hpet_phys = PAddr.fromInt(hpet_table.base_address.address);
            const hpet_virt = VAddr.fromPAddr(hpet_phys, null);

            const mmio_perms: MemoryPerms = .{ .read = true, .write = true };

            try arch_paging.mapPage(
                memory_init.kernel_addr_space_root,
                hpet_phys,
                hpet_virt,
                mmio_perms,
                .kernel_mmio,
            );

            timers.hpet_timer = timers.Hpet.init(hpet_virt);
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "MCFG")) {
            parseMcfg(sdt_virt_x, sdt.length) catch {};
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "DMAR")) {
            parseDmar(sdt_virt_x, sdt.length) catch {};
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "IVRS")) {
            parseIvrs(sdt_virt_x, sdt.length) catch {};
        }
    }

    if (enumerated_device_count == 0) {
        enumeratePciLegacy();
    }

    probeSerialPorts();
    initIommuDevices();
}

/// Count of device_regions allocated by boot-time PCI / serial enumerators.
/// Drives the MCFG-vs-legacy fallback in `parseAcpi`: only fall back to
/// CF8/CFC legacy probing if MCFG produced nothing. Spec-v3 §[device_region]
/// hands the allocated regions off to the root service.
var enumerated_device_count: u32 = 0;

const MMIO_PERMS: MemoryPerms = .{ .read = true, .write = true };

/// PCI Firmware Specification §4.1.2 — MCFG table; maps ECAM base addresses per segment/bus range.
fn parseMcfg(mcfg_vaddr: VAddr, length: u32) !void {
    const header_size: u32 = 44;
    const entry_size: u32 = 16;
    if (length <= header_size) return;

    const num_entries = (length - header_size) / entry_size;
    var i: u32 = 0;
    while (i < num_entries) {
        const entry_addr = mcfg_vaddr.addr + header_size + @as(u64, i) * entry_size;
        const bytes: [*]const u8 = @ptrFromInt(entry_addr);
        const base_address = std.mem.readInt(u64, bytes[0..8], .little);
        const start_bus = bytes[10];
        const end_bus = bytes[11];

        if (base_address == 0) {
            i += 1;
            continue;
        }

        const ecam_phys = PAddr.fromInt(base_address);
        const ecam_size = (@as(u64, end_bus) - @as(u64, start_bus) + 1) << 20;

        var offset: u64 = 0;
        while (offset < ecam_size) {
            const page_phys = PAddr.fromInt(base_address + offset);
            const page_virt = VAddr.fromPAddr(page_phys, null);
            arch_paging.mapPage(memory_init.kernel_addr_space_root, page_phys, page_virt, MMIO_PERMS, .kernel_mmio) catch {
                offset += paging.PAGE4K;
                continue;
            };
            offset += paging.PAGE4K;
        }

        enumeratePci(VAddr.fromPAddr(ecam_phys, null), start_bus, end_bus);
        i += 1;
    }
}

/// PCI Express Base Specification §7.2.2 — ECAM config space read (32-bit).
fn pciConfigRead32(ecam_base: VAddr, bus: u8, dev: u5, func: u3, offset: u12) u32 {
    const addr = ecam_base.addr +
        (@as(u64, bus) << 20) |
        (@as(u64, dev) << 15) |
        (@as(u64, func) << 12) |
        @as(u64, offset);
    return @as(*const volatile u32, @ptrFromInt(addr)).*;
}

/// PCI Express Base Specification §7.2.2 — ECAM config space write (32-bit).
fn pciConfigWrite32(ecam_base: VAddr, bus: u8, dev: u5, func: u3, offset: u12, value: u32) void {
    const addr = ecam_base.addr +
        (@as(u64, bus) << 20) |
        (@as(u64, dev) << 15) |
        (@as(u64, func) << 12) |
        @as(u64, offset);
    @as(*volatile u32, @ptrFromInt(addr)).* = value;
}

/// PCI Local Bus Specification §6.2.5.1 — BAR sizing via all-ones write/readback.
fn pciEcamProbeBarSize(ecam_base: VAddr, bus: u8, dev: u5, func: u3, bar_offset: u12) u64 {
    const original = pciConfigRead32(ecam_base, bus, dev, func, bar_offset);
    pciConfigWrite32(ecam_base, bus, dev, func, bar_offset, 0xFFFFFFFF);
    const sized = pciConfigRead32(ecam_base, bus, dev, func, bar_offset);
    pciConfigWrite32(ecam_base, bus, dev, func, bar_offset, original);

    if (original & 1 != 0) {
        const mask = sized & 0xFFFC;
        if (mask == 0) return 0;
        return (~mask + 1) & 0xFFFF;
    } else {
        const mask = sized & 0xFFFFFFF0;
        if (mask == 0) return 0;
        return ~mask + 1;
    }
}

fn enumeratePci(ecam_base: VAddr, start_bus: u8, end_bus: u8) void {
    var bus: u16 = start_bus;
    while (bus <= end_bus) {
        var dev: u8 = 0;
        while (dev < 32) {
            const vendor_device = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), 0, 0);
            const vendor: u16 = @truncate(vendor_device);
            if (vendor == 0xFFFF) {
                dev += 1;
                continue;
            }

            const header_type = @as(u8, @truncate(pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), 0, 0x0C) >> 16));
            const max_func: u8 = if (header_type & 0x80 != 0) 8 else 1;

            var func: u8 = 0;
            while (func < max_func) {
                const func_vendor: u16 = @truncate(pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), 0));
                if (func_vendor == 0xFFFF) {
                    func += 1;
                    continue;
                }

                const class_code: u8 = @truncate(pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), 0x08) >> 24);

                if (class_code == 0x06) {
                    func += 1;
                    continue;
                }

                if (header_type & 0x7F != 0) {
                    func += 1;
                    continue;
                }

                // Enable bus mastering and memory space for all devices
                const cmd_reg = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), 0x04);
                pciConfigWrite32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), 0x04, cmd_reg | 0x06);

                var bar_idx: u12 = 0;
                while (bar_idx < 6) {
                    const bar_offset: u12 = 0x10 + bar_idx * 4;
                    const bar_val = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset);

                    if (bar_val == 0) {
                        bar_idx += 1;
                        continue;
                    }

                    if (bar_val & 1 != 0) {
                        const port_base: u16 = @truncate(bar_val & 0xFFFC);
                        if (port_base == 0) {
                            bar_idx += 1;
                            continue;
                        }
                        const port_size = pciEcamProbeBarSize(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                        const port_count: u16 = if (port_size > 0) @truncate(port_size) else 32;
                        const pci_addr = device_region.PciAddress.make(@intCast(bus), @intCast(dev), @intCast(func));
                        const dr = device_region.registerPortIoPci(port_base, port_count, pci_addr) catch {
                            bar_idx += 1;
                            continue;
                        };
                        device_region.appendBootGrant(dr);
                        enumerated_device_count += 1;
                        bar_idx += 1;
                        continue;
                    }

                    const bar_type = (bar_val >> 1) & 0x3;
                    var phys_addr: u64 = bar_val & 0xFFFFFFF0;

                    if (bar_type == 2 and bar_idx < 5) {
                        const bar_high = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset + 4);
                        phys_addr |= @as(u64, bar_high) << 32;
                        bar_idx += 1;
                    }

                    if (phys_addr == 0) {
                        bar_idx += 1;
                        continue;
                    }

                    const bar_size = pciEcamProbeBarSize(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                    const aligned_size = if (bar_size >= paging.PAGE4K)
                        std.mem.alignForward(u64, bar_size, paging.PAGE4K)
                    else
                        paging.PAGE4K;

                    const pci_addr = device_region.PciAddress.make(@intCast(bus), @intCast(dev), @intCast(func));
                    const dr = device_region.registerMmioPci(
                        PAddr.fromInt(phys_addr),
                        aligned_size,
                        pci_addr,
                    ) catch {
                        bar_idx += 1;
                        continue;
                    };
                    device_region.appendBootGrant(dr);
                    enumerated_device_count += 1;

                    // Only register the first MMIO BAR per PCI function.
                    break;
                }
                func += 1;
            }
            dev += 1;
        }
        bus += 1;
    }
}

/// PCI Local Bus Specification §3.2.2.3.2 — Configuration Mechanism #1; ports 0xCF8/0xCFC write.
fn pciLegacyWrite32(bus: u8, dev: u5, func: u3, offset: u8, value: u32) void {
    const addr: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, dev) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    cpu.outd(addr, 0xCF8);
    cpu.outd(value, 0xCFC);
}

/// PCI Local Bus Specification §6.2.5.1 — BAR sizing via all-ones write/readback.
fn pciProbeBarSize(bus: u8, dev: u5, func: u3, bar_offset: u8) u64 {
    const original = pciLegacyRead32(bus, dev, func, bar_offset);
    pciLegacyWrite32(bus, dev, func, bar_offset, 0xFFFFFFFF);
    const sized = pciLegacyRead32(bus, dev, func, bar_offset);
    pciLegacyWrite32(bus, dev, func, bar_offset, original);

    if (original & 1 != 0) {
        const mask = sized & 0xFFFC;
        if (mask == 0) return 0;
        return (~mask + 1) & 0xFFFF;
    } else {
        const mask = sized & 0xFFFFFFF0;
        if (mask == 0) return 0;
        return ~mask + 1;
    }
}

/// PCI Local Bus Specification §3.2.2.3.2 — Configuration Mechanism #1; ports 0xCF8/0xCFC read.
fn pciLegacyRead32(bus: u8, dev: u5, func: u3, offset: u8) u32 {
    const addr: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, dev) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    cpu.outd(addr, 0xCF8);
    return cpu.ind(0xCFC);
}

fn enumeratePciLegacy() void {
    var bus: u16 = 0;
    while (bus < 256) {
        var dev: u8 = 0;
        while (dev < 32) {
            const vendor_device = pciLegacyRead32(@intCast(bus), @intCast(dev), 0, 0);
            const vendor: u16 = @truncate(vendor_device);
            if (vendor == 0xFFFF) {
                dev += 1;
                continue;
            }

            const header_type = @as(u8, @truncate(pciLegacyRead32(@intCast(bus), @intCast(dev), 0, 0x0C) >> 16));
            const max_func: u8 = if (header_type & 0x80 != 0) 8 else 1;

            var func: u8 = 0;
            while (func < max_func) {
                const func_vendor: u16 = @truncate(pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), 0));
                if (func_vendor == 0xFFFF) {
                    func += 1;
                    continue;
                }

                const class_code: u8 = @truncate(pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), 0x08) >> 24);

                if (class_code == 0x06) {
                    func += 1;
                    continue;
                }

                if (header_type & 0x7F != 0) {
                    func += 1;
                    continue;
                }

                // Enable bus mastering and memory space for all devices
                const cmd_reg = pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), 0x04);
                pciLegacyWrite32(@intCast(bus), @intCast(dev), @intCast(func), 0x04, cmd_reg | 0x06);

                var bar_idx: u8 = 0;
                while (bar_idx < 6) {
                    const bar_offset: u8 = 0x10 + bar_idx * 4;
                    const bar_val = pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), bar_offset);

                    if (bar_val == 0) {
                        bar_idx += 1;
                        continue;
                    }

                    if (bar_val & 1 != 0) {
                        const port_base: u16 = @truncate(bar_val & 0xFFFC);
                        if (port_base == 0) {
                            bar_idx += 1;
                            continue;
                        }
                        const port_size = pciProbeBarSize(@intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                        const port_count: u16 = if (port_size > 0) @truncate(port_size) else 32;
                        const pci_addr = device_region.PciAddress.make(@intCast(bus), @intCast(dev), @intCast(func));
                        const dr = device_region.registerPortIoPci(port_base, port_count, pci_addr) catch {
                            bar_idx += 1;
                            continue;
                        };
                        device_region.appendBootGrant(dr);
                        enumerated_device_count += 1;
                        bar_idx += 1;
                        continue;
                    }

                    const phys_addr: u64 = bar_val & 0xFFFFFFF0;
                    if (phys_addr == 0) {
                        bar_idx += 1;
                        continue;
                    }
                    const bar_size = pciProbeBarSize(@intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                    const aligned_size = if (bar_size >= paging.PAGE4K)
                        std.mem.alignForward(u64, bar_size, paging.PAGE4K)
                    else
                        paging.PAGE4K;

                    const pci_addr = device_region.PciAddress.make(@intCast(bus), @intCast(dev), @intCast(func));
                    const dr = device_region.registerMmioPci(
                        PAddr.fromInt(phys_addr),
                        aligned_size,
                        pci_addr,
                    ) catch {
                        bar_idx += 1;
                        continue;
                    };
                    device_region.appendBootGrant(dr);
                    enumerated_device_count += 1;

                    // Only register the first MMIO BAR per PCI function.
                    break;
                }
                func += 1;
            }
            dev += 1;
        }
        bus += 1;
    }
}

fn probeSerialPorts() void {
    const com_ports = [_]u16{ 0x3F8, 0x2F8, 0x3E8, 0x2E8 };
    for (com_ports) |port| {
        cpu.outb(0xA5, port + 7);
        const readback = cpu.inb(port + 7);
        if (readback == 0xA5) {
            cpu.outb(0x00, port + 7);
            const dr = device_region.registerPortIo(port, 8) catch continue;
            device_region.appendBootGrant(dr);
            enumerated_device_count += 1;
        }
    }
}

/// Intel VT-d Specification §8.1 — DMA Remapping Reporting (DMAR) structure; finds DRHD unit.
fn parseDmar(dmar_vaddr: VAddr, length: u32) !void {
    const header_size: u32 = 48;
    if (length <= header_size) return;

    var offset: u32 = header_size;
    while (offset + 4 <= length) {
        const entry_type = @as(*const volatile u16, @ptrFromInt(dmar_vaddr.addr + offset)).*;
        const entry_len = @as(*const volatile u16, @ptrFromInt(dmar_vaddr.addr + offset + 2)).*;
        if (entry_len == 0) break;

        if (entry_type != 0 or entry_len < 16) {
            offset += entry_len;
            continue;
        }

        const reg_base = @as(*const volatile u64, @ptrFromInt(dmar_vaddr.addr + offset + 8)).*;
        if (reg_base == 0) {
            offset += entry_len;
            continue;
        }

        iommu.initIntel(PAddr.fromInt(reg_base)) catch {};
        break;
    }
}

/// AMD I/O Virtualization Technology Specification §5.2 — I/O Virtualization Reporting Structure (IVRS).
fn parseIvrs(ivrs_vaddr: VAddr, length: u32) !void {
    // IVRS header is 48 bytes (standard ACPI header + IVinfo + reserved).
    const header_size: u32 = 48;
    if (length <= header_size) return;

    var offset: u32 = header_size;
    while (offset + 4 <= length) {
        const entry_type = @as(*const volatile u8, @ptrFromInt(ivrs_vaddr.addr + offset)).*;
        const entry_len = @as(*const volatile u16, @ptrFromInt(ivrs_vaddr.addr + offset + 2)).*;
        if (entry_len == 0 or offset + entry_len > length) break;

        // IVHD types: 0x10 (basic), 0x11 (extended), 0x40 (ACPI 6.0 extended).
        // All share the same base layout with IOMMU base address at offset +8.
        if ((entry_type == 0x10 or entry_type == 0x11 or entry_type == 0x40) and entry_len >= 24) {
            const iommu_base = @as(*const volatile u64, @ptrFromInt(ivrs_vaddr.addr + offset + 8)).*;

            if (iommu_base != 0) {
                // Parse device entries within this IVHD block for alias mappings.
                // Device entries start at offset +24 within the IVHD.
                const dev_start: u32 = offset + 24;
                var dev_off: u32 = dev_start;
                while (dev_off < offset + entry_len) {
                    const dev_type = @as(*const volatile u8, @ptrFromInt(ivrs_vaddr.addr + dev_off)).*;
                    switch (dev_type) {
                        // 4-byte device entries: all, select, range start/end
                        1, 2, 3, 4 => dev_off += 4,
                        // 8-byte alias entries: alias select (66), alias range start (67)
                        66, 67 => {
                            if (dev_off + 8 <= offset + entry_len) {
                                const source = @as(*align(1) const u16, @ptrFromInt(ivrs_vaddr.addr + dev_off + 2)).*;
                                const alias = @as(*align(1) const u16, @ptrFromInt(ivrs_vaddr.addr + dev_off + 4)).*;
                                if (source != alias) {
                                    iommu.addAmdAlias(source, alias);
                                }
                            }
                            dev_off += 8;
                        },
                        // 8-byte special device entry (type 72)
                        72 => dev_off += 8,
                        // Variable-length extended entries (type 70, 71, 74, 75)
                        70, 71, 74, 75 => {
                            if (entry_type == 0x10) {
                                dev_off += 4;
                            } else {
                                dev_off += 8;
                            }
                        },
                        // Padding or unknown — skip 4 bytes
                        0 => dev_off += 4,
                        else => dev_off += 4,
                    }
                }

                iommu.initAmd(PAddr.fromInt(iommu_base)) catch {};
                break;
            }
        }

        offset += entry_len;
    }
}

fn initIommuDevices() void {
    if (!iommu.isAvailable()) return;

    // Per-device root/context entries are installed lazily on first
    // mapPage call (the IOMMU subsystem keys per-device state on
    // *DeviceRegion). What we *do* need to do here is flip the global
    // translation-enable bit so subsequent DMA actually walks the
    // page tables. Enabling with empty per-device tables is the
    // documented path (see vtd.enableTranslation / vi.enableTranslation
    // comments) — until a driver maps something, transactions for that
    // device hit "context entry not present" and fault, which is what
    // we want.
    iommu.enableTranslation();
}

const MAX_CORES = 64;
var lapics_array: [MAX_CORES]LocalApic = undefined;
