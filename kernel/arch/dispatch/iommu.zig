const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const DeviceRegion = zag.devices.device_region.DeviceRegion;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VarPageSize = zag.memory.var_range.PageSize;

/// Map a single page-sized IOVA in `device`'s domain to `phys` with
/// `perms`. Spec §[var].map_pf (caps.dma=1).
pub fn iommuMapPage(
    device: *DeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.iommu.iommuMapPage(device, iova, phys, sz, perms),
        .aarch64 => return aarch64.iommu.iommuMapPage(device, iova, phys, sz, perms),
        else => unreachable,
    }
}

/// Unmap a single page-sized IOVA from `device`'s domain. Returns the
/// previously bound physical address if any.
pub fn iommuUnmapPage(
    device: *DeviceRegion,
    iova: u64,
    sz: VarPageSize,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.iommu.iommuUnmapPage(device, iova, sz),
        .aarch64 => return aarch64.iommu.iommuUnmapPage(device, iova, sz),
        else => unreachable,
    }
}

/// Invalidate IOTLB entries covering `page_count` pages starting at
/// `iova` in `device`'s domain. Required after any unmap or
/// permission downgrade so the device cannot continue to DMA against
/// stale translations.
pub fn invalidateIotlbRange(
    device: *DeviceRegion,
    iova: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.invalidateIotlbRange(device, iova, sz, page_count),
        .aarch64 => aarch64.iommu.invalidateIotlbRange(device, iova, sz, page_count),
        else => unreachable,
    }
}
