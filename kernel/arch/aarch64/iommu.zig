//! aarch64 IOMMU dispatch — no-SMMU passthrough.
//!
//! No SMMU driver exists yet. QEMU `virt` does not emit an IORT SMMU
//! node by default and Pi 5 (BCM2712) exposes no architecturally
//! standard SMMUv2/v3 instance, so there is no live IOMMU on any
//! aarch64 platform we currently boot. The dispatch surface mirrors
//! `arch/x64/iommu.zig`'s `.none` arm: `iommuMapPage` is a successful
//! no-op (no IOMMU translation is installed because there is no IOMMU
//! to install one on), `iommuUnmapPage` returns null (no recorded
//! mapping to retire), `invalidateIotlbRange` is a no-op. When a real
//! SMMUv2/v3 driver lands, replace this with an `active_type`-style
//! switch matching `arch/x64/iommu.zig`.

const stygia = @import("stygia");

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const SpecDeviceRegion = stygia.devices.device_region.DeviceRegion;
const VmarPageSize = stygia.memory.vmar.PageSize;

/// No SMMU active — no-op success. Matches the x64 `.none` arm's
/// behavior when neither VT-d nor AMD-Vi is present: the dma path
/// records a VMAR mapping in the kernel's bookkeeping (so structural
/// state per Spec §[map_pf] / §[var] is consistent) but no IOMMU PTE
/// is installed because there is no IOMMU to install one on. DMA
/// isolation cannot be enforced on a platform without an IOMMU.
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
}

/// No SMMU active — no-op. The mapping was never installed in
/// hardware (see `iommuMapPage`), so there is nothing to retire.
/// Returns null to signal "no recorded mapping" matching the x64
/// `.none` arm.
pub fn iommuUnmapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VmarPageSize,
) ?PAddr {
    _ = device;
    _ = iova;
    _ = sz;
    return null;
}

/// No SMMU active — no IOTLB to invalidate. Mirrors the x64 `.none`
/// arm.
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
}
