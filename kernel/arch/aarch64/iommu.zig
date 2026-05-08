//! aarch64 IOMMU dispatch — fail-closed stub.
//!
//! No SMMU driver exists yet. QEMU `virt` does not emit an IORT SMMU
//! node by default and Pi 5 (BCM2712) exposes no architecturally
//! standard SMMUv2/v3 instance, so there is no live IOMMU on any
//! aarch64 platform we currently boot. `iommuMapPage` therefore fails
//! every call closed; `iommuUnmapPage` and `invalidateIotlbRange` are
//! unreachable in invariant — they panic if invoked. When a real
//! SMMUv2/v3 driver lands, replace this with an `active_type`-style
//! switch matching `arch/x64/iommu.zig`.

const zag = @import("zag");

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const SpecDeviceRegion = zag.devices.device_region.DeviceRegion;
const VmarPageSize = zag.memory.vmar.PageSize;

/// No SMMU driver on aarch64 — refuse the map. The caller in
/// `memory/vmar.zig:mappingInstall` translates this to `E_NOMEM`,
/// aborts the install, and leaves `v.map` at `.unmapped`. This keeps
/// every caps.dma=1 device from hitting unmediated DRAM on a kernel
/// that has no DMA isolation to enforce.
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
    return error.NotSupported;
}

/// Unreachable in invariant: every caps.dma=1 install fails at
/// `iommuMapPage` above, so no DMA mapping is ever recorded in
/// `installed_pfs[]`, so `mappingRemove`'s DMA branch never matches an
/// installed entry. A `caps.dma=1` VMAR stays at `v.map == .unmapped`
/// forever; `unmap` short-circuits with `E_INVAL` before reaching this
/// path, and `destroyVmar` only walks the iommu unmap helpers via
/// `unmapAll`'s `.page_frame`/`.demand` branches — neither state is
/// reachable for a DMA VMAR on this arch.
pub fn iommuUnmapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VmarPageSize,
) ?PAddr {
    _ = device;
    _ = iova;
    _ = sz;
    @panic("aarch64 iommuUnmapPage reached without a successful prior map");
}

/// Same invariant as `iommuUnmapPage` — reachable only after a
/// successful map, which aarch64 cannot produce.
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
    @panic("aarch64 invalidateIotlbRange reached without a successful prior map");
}
