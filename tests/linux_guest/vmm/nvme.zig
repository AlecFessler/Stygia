//! NVMe controller — spec-v3 stub.
//!
//! The pre-port driver lives in git history. Restoring it on the new
//! ABI requires:
//!   1. PCI device_region discovery via `caps.readCap` (currently
//!      only port_io device_regions are exposed; PCI MMIO discovery
//!      goes through the bootloader's cap-table seeding).
//!   2. DMA VARs for the prp lists and data buffer, using
//!      `createVar` with `caps.dma = 1` and the device_region as
//!      `[5] device_region` per §[create_var].
//!   3. Doorbell writes through an `mmio` VAR mapped over the
//!      controller's BAR0.
//!
//! Until that lands, `disk.init` always returns false and the
//! VMM falls back to embedded assets.

pub fn dataBuffer(ctrl: *const Controller) [*]const u8 {
    _ = ctrl;
    return undefined;
}

pub const InitError = enum {
    none,
    not_implemented,
};

pub const Controller = struct {
    lba_size: u32 = 0,

    pub fn initFromHandle(self: *Controller, device_handle: u64, mmio_size: u32) InitError {
        _ = self;
        _ = device_handle;
        _ = mmio_size;
        return .not_implemented;
    }

    pub fn readSectors(self: *Controller, nsid: u32, lba: u64, count: u16) bool {
        _ = self;
        _ = nsid;
        _ = lba;
        _ = count;
        return false;
    }

    pub fn flush(self: *Controller, nsid: u32) bool {
        _ = self;
        _ = nsid;
        return false;
    }
};
