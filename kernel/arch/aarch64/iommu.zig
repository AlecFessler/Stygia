//! ARM SMMU (System MMU) driver — aarch64 equivalent of x86 IOMMU (VT-d / AMD-Vi).
//!
//! The SMMU provides DMA remapping: it translates device-initiated memory
//! accesses through a set of page tables, isolating devices from each other
//! and from physical memory they shouldn't access.
//!
//! SMMU versions:
//! - SMMUv2 (ARM IHI 0062): two-stage translation, stream ID based.
//! - SMMUv3 (ARM IHI 0070): command queue / event queue model, IOPMP support.
//!
//! Discovery: SMMU base addresses come from the ACPI IORT (IO Remapping Table),
//! ACPI 6.5 Section 5.2.29. Each IORT SMMU node describes one SMMU instance
//! and its stream ID mappings.
//!
//! Key concepts:
//!   Stream ID:     Identifies the device (like x86 BDF for VT-d).
//!   Stream Table:  Maps stream IDs → Stream Table Entries (STEs).
//!   STE:           Points to a stage-1 and/or stage-2 translation table.
//!   Command Queue: (SMMUv3) software → SMMU commands (invalidate, sync, etc.).
//!   Event Queue:   (SMMUv3) SMMU → software fault/error reports.
//!
//! Dispatch interface mapping:
//!   isAvailable()          → true if IORT contains an SMMU node
//!   mapDmaPages(dev, frame) → create stage-2 mapping for device's stream ID
//!   unmapDmaPages(...)     → remove stage-2 mapping, invalidate IOTLB
//!   enableTranslation()    → set SMMU_CR0.SMMUEN (SMMUv3) or SMMU_sCR0 (SMMUv2)
//!
//! References:
//! - ARM IHI 0070F: SMMUv3 Architecture Specification
//! - ARM IHI 0062E: SMMUv2 Architecture Specification
//! - ACPI 6.5, Section 5.2.29: IORT

const zag = @import("zag");

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const SpecDeviceRegion = zag.devices.device_region.DeviceRegion;
const VarPageSize = zag.memory.var_range.PageSize;

// SMMU driver is not yet implemented. QEMU `virt` does not expose an IORT
// SMMU node by default, and the kernel test rig does not need real stage-2
// isolation — tests only observe that `mem_dma_map` returns a positive base
// and that subsequent unmap/remap cycles behave consistently.
//
// Until a real SMMUv3 driver lands, run in a "passthrough identity" mode:
// the syscall path still bumps per-device `dma_cursor` under the per-device
// lock so §2.4.33 (positive return), concurrent map/unmap accounting, and
// the cursor-race patches stay observable. No hardware page tables are
// touched, so this is equivalent to the x86 "iommu=off" path that x86
// routerOS uses under QEMU without VT-d.
pub fn iommuMapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VarPageSize,
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
    sz: VarPageSize,
) ?PAddr {
    _ = device;
    _ = iova;
    _ = sz;
    @panic("not implemented");
}

pub fn invalidateIotlbRange(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    _ = device;
    _ = iova;
    _ = sz;
    _ = page_count;
    @panic("not implemented");
}
