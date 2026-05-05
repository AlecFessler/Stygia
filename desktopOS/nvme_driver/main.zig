// NVMe driver service.
//
// Cap-table layout the root service hands us (passed_handles, in
// order, starting at SLOT_FIRST_PASSED = 3):
//   [3]      — COM1 port_io device_region (for direct serial logging)
//   [4..N+4] — every PCI MMIO device_region the kernel enumerated
//
// Phase 1 boot:
//   1. log.init — finds COM1 by base_port.
//   2. scanDeviceRegions — walk the cap table, collect MMIO handles.
//   3. For each MMIO, map it once with MMIO perms and read VS at
//      offset 0x08. NVMe reports VS as MJR.MNR.TER (NVMe 1.x has
//      MJR=1). The first BAR that responds as NVMe is the controller.
//   4. Run the full controller init sequence (see nvme.zig — port of
//      desktopOS commit 1f0b273ec hardware logic, adapted to the v3
//      vreg ABI).
//   5. Park.

const lib = @import("lib");
const log = @import("log");
const nvme = @import("nvme.zig");

const builtin = @import("builtin");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const PAGE_4K: u64 = 4096;
const MAX_MMIO: usize = 32;

const MmioEntry = struct {
    handle: HandleId,
    base_paddr: u64,
    size_pages: u64,
};

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[nvme_driver] starting\n");

    var mmios: [MAX_MMIO]MmioEntry = undefined;
    const n = scanMmioDeviceRegions(cap_table_base, &mmios);
    log.print("[nvme_driver] scanning ");
    log.dec(n);
    log.print(" MMIO device_region(s) for NVMe\n");

    var nvme_dev: ?HandleId = null;
    var nvme_size_pages: u64 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const m = mmios[i];
        log.print("[nvme_driver]   MMIO #");
        log.dec(i);
        log.print(" handle=");
        log.dec(m.handle);
        log.print(" paddr=0x");
        log.hex64(m.base_paddr);
        log.print(" size=");
        log.dec(m.size_pages * PAGE_4K);
        log.print("B");

        const is_nvme = probeNvme(m);
        if (is_nvme) {
            log.print("  <-- NVMe\n");
            if (nvme_dev == null) {
                nvme_dev = m.handle;
                nvme_size_pages = m.size_pages;
            }
        } else {
            log.print("\n");
        }
    }

    if (nvme_dev == null) {
        log.print("[nvme_driver] no NVMe controller found; idling\n");
        park();
    }

    log.print("[nvme_driver] initializing controller (handle=");
    log.dec(nvme_dev.?);
    log.print(")\n");

    var controller: nvme.Controller = .{};
    const init_err = controller.initFromHandle(nvme_dev.?, nvme_size_pages * PAGE_4K);
    if (init_err != .none) {
        log.print("[nvme_driver] init FAILED: ");
        log.print(@tagName(init_err));
        log.print("\n");
        park();
    }
    log.print("[nvme_driver] controller ready (lba_size=");
    log.dec(controller.lba_size);
    log.print(", ns_size=");
    log.dec(controller.ns_size);
    log.print(")\n");

    park();
}

fn scanMmioDeviceRegions(cap_table_base: u64, out: []MmioEntry) usize {
    var n: usize = 0;
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX and n < out.len) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() != .device_region) continue;
        const dev_type: u4 = @truncate(c.field0 & 0xF);
        if (dev_type != 0) continue; // not MMIO
        // §[device_region] mmio field0:
        //   bits 4-51 paddr>>12, bits 52-63 size_pages
        const paddr: u64 = ((c.field0 >> 4) & ((@as(u64, 1) << 48) - 1)) << 12;
        const size_pages: u64 = (c.field0 >> 52) & 0xFFF;
        if (size_pages == 0) continue;
        out[n] = .{
            .handle = @truncate(slot),
            .base_paddr = paddr,
            .size_pages = size_pages,
        };
        n += 1;
    }
    return n;
}

/// Map the MMIO BAR temporarily, read VS (offset 0x08), tear down.
/// Returns true iff this looks like an NVMe controller (VS reports
/// MJR=1 with sensible MNR).
fn probeNvme(m: MmioEntry) bool {
    const var_caps_word = caps.VmarCap{
        .r = true,
        .w = false, // probe is read-only
        .mmio = true,
    };
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (0 << 3) | // sz = 0 (4 KiB)
        0b001; // cur_rwx = r
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        m.size_pages,
        0,
        0,
    );
    if (cvar.v1 < 16) return false;
    const vmar_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const vmar_base: u64 = cvar.v2;

    const mm = syscall.mapMmio(vmar_handle, m.handle);
    if (mm.v1 != 0) {
        _ = syscall.delete(vmar_handle);
        return false;
    }

    const vs_ptr: *const volatile u32 = @ptrFromInt(vmar_base + 0x08);
    const vs = vs_ptr.*;

    _ = syscall.delete(vmar_handle);

    if (vs == 0 or vs == 0xFFFF_FFFF) return false;
    const mjr: u32 = (vs >> 16) & 0xFFFF;
    const mnr: u32 = (vs >> 8) & 0xFF;
    return mjr == 1 and mnr <= 10;
}

fn park() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}
