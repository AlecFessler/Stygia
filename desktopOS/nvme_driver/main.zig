// NVMe driver service.
//
// Phase-4 path: serves the same blockdev port protocol the interim
// `block_device` did (op/lba/count/buf_off in vregs, scratch page_frame
// for data), but backed by real NVMe queue submissions. With the
// VT-d / AMD-Vi restoration in place the NVMe driver's DMA-VMAR setup
// (`createVmar(caps.dma=1, [5]=device)` + `mapPf`) actually programs
// the IOMMU page tables for the controller's BDF, so the device-side
// IOVA == VMAR base and writes from the NVMe SQ's PRP1 land on real
// memory.
//
// Cap-table layout the root service hands us (in order, starting at
// SLOT_FIRST_PASSED = 3):
//   [3]      — COM1 port_io device_region (logging)
//   [4]      — port (recv)
//   [5]      — scratch page_frame (r+w; same pf fs maps; CPU-only,
//                                   not IOMMU-bound)
//   [6..]    — every PCI MMIO device_region the kernel enumerated;
//              the NVMe controller's BAR0 is one of them.

const lib = @import("lib");
const log = @import("log");
const nvme = @import("nvme.zig");
const blockdev = @import("blockdev");

const builtin = @import("builtin");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const PAGE_4K: u64 = 4096;
const SCRATCH_PAGES: u64 = 1;
const MAX_MMIO: usize = 32;

// Spec §[recv] [2]: 0 = block indefinitely. Anything large enough to
// deadline-overflow the kernel's u64 timer panics; stay at 0.
const RECV_TIMEOUT_NS: u64 = 0;

const MmioEntry = struct {
    handle: HandleId,
    base_paddr: u64,
    size_pages: u64,
};

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[nvme_driver] starting\n");

    // ── Locate port + scratch page_frame ─────────────────────────
    const port_handle = findPort(cap_table_base) orelse {
        log.print("[nvme_driver] FATAL: no port handle in cap table\n");
        park();
    };
    const scratch_pf = findFirstPageFrame(cap_table_base) orelse {
        log.print("[nvme_driver] FATAL: no scratch page_frame in cap table\n");
        park();
    };
    const scratch_va = mapPfRw(scratch_pf, SCRATCH_PAGES) orelse {
        log.print("[nvme_driver] FATAL: mapPf(scratch) failed\n");
        park();
    };

    // ── Probe MMIO BARs for the NVMe controller ──────────────────
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
        if (probeNvme(m)) {
            log.print("[nvme_driver]   NVMe at handle=");
            log.dec(m.handle);
            log.print(" paddr=0x");
            log.hex64(m.base_paddr);
            log.print("\n");
            nvme_dev = m.handle;
            nvme_size_pages = m.size_pages;
            break;
        }
    }
    if (nvme_dev == null) {
        log.print("[nvme_driver] FATAL: no NVMe controller found\n");
        park();
    }

    // ── Init controller (DMA setup + admin queues + identify + I/O queues) ─
    var controller: nvme.Controller = .{};
    const init_err = controller.initFromHandle(nvme_dev.?, nvme_size_pages * PAGE_4K);
    if (init_err != .none) {
        log.print("[nvme_driver] FATAL: init err=");
        log.print(@tagName(init_err));
        log.print("\n");
        park();
    }
    log.print("[nvme_driver] controller ready (lba_size=");
    log.dec(controller.lba_size);
    log.print(", ns_size=");
    log.dec(controller.ns_size);
    log.print(")\n");

    if (controller.lba_size != blockdev.BLOCK_SIZE) {
        log.print("[nvme_driver] WARNING: controller lba_size != ");
        log.dec(blockdev.BLOCK_SIZE);
        log.print("; clients expect 512B sectors\n");
    }

    serveLoop(&controller, port_handle, scratch_va);
}

fn findPort(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .port) return @truncate(slot);
    }
    return null;
}

fn findFirstPageFrame(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .page_frame) return @truncate(slot);
    }
    return null;
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
        .w = false,
        .mmio = true,
    };
    const props: u64 = (1 << 5) | // cch=1 (uc)
        (0 << 3) | // sz=0 (4 KiB)
        0b001; // cur_rwx=r
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

fn mapPfRw(pf_handle: HandleId, pages: u64) ?u64 {
    const var_caps_word = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011;
    const cv = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        pages,
        0,
        0,
    );
    if (cv.v1 < 16) return null;
    const vmar_handle: HandleId = @truncate(cv.v1 & 0xFFF);
    const vmar_base: u64 = cv.v2;

    const pairs = [_]u64{ 0, pf_handle };
    const mp = syscall.mapPf(vmar_handle, pairs[0..]);
    if (mp.v1 != 0) return null;
    return vmar_base;
}

fn serveLoop(controller: *nvme.Controller, port: HandleId, scratch_va: u64) noreturn {
    log.print("[nvme_driver] entering serve loop\n");
    const scratch: [*]u8 = @ptrFromInt(scratch_va);
    while (true) {
        const got = syscall.recv(port, RECV_TIMEOUT_NS);
        if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) continue;

        const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);

        // Suspend payload at v3..v6 (matches block_device + fs).
        const op_raw = got.regs.v3;
        const lba = got.regs.v4;
        const count = got.regs.v5;
        const buf_off = got.regs.v6;

        const status = serveOne(controller, scratch, op_raw, lba, count, buf_off);

        _ = syscall.issueReg(
            .reply,
            syscall.extraReplyHandle(reply_handle),
            .{ .v1 = @intFromEnum(status) },
        );
    }
}

fn serveOne(
    controller: *nvme.Controller,
    scratch: [*]u8,
    op_raw: u64,
    lba: u64,
    count: u64,
    buf_off: u64,
) blockdev.Status {
    const op: blockdev.Op = @enumFromInt(op_raw);
    if (count == 0 or count > 8) return .out_of_range;
    const bytes = count * blockdev.BLOCK_SIZE;
    if (buf_off + bytes > SCRATCH_PAGES * PAGE_4K) return .out_of_range;
    if (lba + count > controller.ns_size) return .out_of_range;

    const nsid: u32 = 1;
    switch (op) {
        .read => {
            if (!controller.readSectors(nsid, lba, @intCast(count))) return .fail;
            const dma = controller.getReadBuf();
            var i: u64 = 0;
            while (i < bytes) : (i += 1) scratch[buf_off + i] = dma[i];
        },
        .write => {
            const dma = controller.getWriteBuf();
            var i: u64 = 0;
            while (i < bytes) : (i += 1) dma[i] = scratch[buf_off + i];
            if (!controller.writeSectors(nsid, lba, @intCast(count))) return .fail;
        },
        else => return .bad_op,
    }
    return .ok;
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
