const std = @import("std");
const zag = @import("zag");

const vi = zag.arch.x64.amd.vi;
const vtd = zag.arch.x64.intel.vtd;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const SpecDeviceRegion = zag.devices.device_region.DeviceRegion;
const VmarPageSize = zag.memory.vmar.PageSize;

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
    _ = device;
    _ = iova;
    _ = phys;
    _ = sz;
    _ = perms;
    @panic("not implemented");
}

pub fn iommuUnmapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VmarPageSize,
) ?PAddr {
    _ = device;
    _ = iova;
    _ = sz;
    @panic("not implemented");
}

pub fn invalidateIotlbRange(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VmarPageSize,
    page_count: u32,
) void {
    _ = device;
    _ = iova;
    _ = sz;
    _ = page_count;
    @panic("not implemented");
}
