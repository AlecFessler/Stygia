const std = @import("std");
const stygia = @import("stygia");

const vi = stygia.arch.x64.amd.vi;
const vtd = stygia.arch.x64.intel.vtd;

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const SpecDeviceRegion = stygia.devices.device_region.DeviceRegion;
const VmarPageSize = stygia.memory.vmar.PageSize;

const IommuType = enum {
    none,
    intel_vtd,
    amd_vi,
};

var active_type: IommuType = .none;

pub fn initIntel(reg_base: PAddr) !void {
    // Invariant: at most one IOMMU flavor per platform; ACPI calls this
    // serially during boot, so no lock is required.
    std.debug.assert(active_type == .none);
    try vtd.init(reg_base);
    active_type = .intel_vtd;
}

pub fn initAmd(reg_base: PAddr) !void {
    // Invariant: at most one IOMMU flavor per platform; ACPI calls this
    // serially during boot, so no lock is required.
    std.debug.assert(active_type == .none);
    try vi.init(reg_base);
    active_type = .amd_vi;
}

pub fn addAmdAlias(source: u16, alias: u16) void {
    vi.addAlias(source, alias);
}

/// Call after the first wave of `iommuMapPage` to flip translation on.
/// Both VT-d (TE) and AMD-Vi (IommuEn) defer master enable from init so
/// provisioning runs against an inert IOMMU; once devices' page tables
/// hold real mappings, this latches translation live. No-op if already
/// enabled, or if no IOMMU was discovered.
pub fn enableTranslation() void {
    switch (active_type) {
        .intel_vtd => vtd.enableTranslation(),
        .amd_vi => vi.enableTranslation(),
        .none => {},
    }
}

pub fn isAvailable() bool {
    return active_type != .none;
}

pub fn iommuMapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VmarPageSize,
    perms: MemoryPerms,
) !void {
    switch (active_type) {
        .intel_vtd => return vtd.mapPage(device, iova, phys, sz, perms),
        .amd_vi => return vi.mapPage(device, iova, phys, sz, perms),
        .none => return,
    }
}

pub fn iommuUnmapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VmarPageSize,
) ?PAddr {
    switch (active_type) {
        .intel_vtd => return vtd.unmapPage(device, iova, sz),
        .amd_vi => return vi.unmapPage(device, iova, sz),
        .none => return null,
    }
}

pub fn invalidateIotlbRange(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VmarPageSize,
    page_count: u32,
) void {
    switch (active_type) {
        .intel_vtd => vtd.invalidatePageRange(device, iova, sz, page_count),
        .amd_vi => vi.invalidatePageRange(device, iova, sz, page_count),
        .none => {},
    }
}
