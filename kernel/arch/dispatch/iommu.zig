const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

const DeviceRegion = stygia.devices.device_region.DeviceRegion;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VmarPageSize = stygia.memory.vmar.PageSize;

pub const InspectedLeaf = struct { phys: PAddr, read: bool, write: bool };

/// Test-profile diagnostic. Returns null when no hardware IOMMU is active.
pub fn inspectLeaf(device: *DeviceRegion, iova: u64, sz: VmarPageSize) ?InspectedLeaf {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const leaf = x64.iommu.inspectLeaf(device, iova, sz) orelse return null;
            return .{ .phys = leaf.phys, .read = leaf.read, .write = leaf.write };
        },
        .aarch64 => return null,
        else => unreachable,
    }
}

pub fn isAvailable() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.isAvailable(),
        .aarch64 => false,
        else => unreachable,
    };
}

/// Map a single page-sized IOVA in `device`'s domain to `phys` with
/// `perms`. Spec §[var].map_pf (caps.dma=1).
pub fn iommuMapPage(
    device: *DeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VmarPageSize,
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
    sz: VmarPageSize,
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
    sz: VmarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.invalidateIotlbRange(device, iova, sz, page_count),
        .aarch64 => aarch64.iommu.invalidateIotlbRange(device, iova, sz, page_count),
        else => unreachable,
    }
}
