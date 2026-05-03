//! Disk loader — NVMe path.
//!
//! Spec-v3 stub: NVMe device discovery and the controller driver
//! ride on a PCI passthrough device_region with bound DMA VARs (see
//! §[device_region] and §[create_var] caps.dma path). Both pieces
//! exist in the prior-ABI form (see git history before the spec-v3
//! port), but the device-discovery + DMA mapping migration is
//! deferred — the NVMe blob is large and the embedded-asset path in
//! main.zig (`bootLinuxEmbedded`) covers boot for QEMU.
//!
//! For now `init` always reports "no controller found", which steers
//! main.zig into the embedded path. When NVMe support comes back we
//! restore the controller wiring on top of `caps.readCap` for the PCI
//! device_region and `createVar` with `caps.dma = 1` for the prp lists.

const log = @import("log.zig");

pub const DiskImage = struct {
    bzimage_offset: u64,
    bzimage_size: u64,
    initramfs_offset: u64,
    initramfs_size: u64,
};

pub fn init(cap_table_base: u64) bool {
    _ = cap_table_base;
    log.print("disk: NVMe deferred — using embedded assets\n");
    return false;
}

pub fn readHeader() ?DiskImage {
    return null;
}

pub fn loadToGuest(disk_offset: u64, size: u64, guest_phys: u64) bool {
    _ = disk_offset;
    _ = size;
    _ = guest_phys;
    return false;
}
