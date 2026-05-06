// desktopOS root service.
//
// Boot path:
//   1. log.init via the kernel-issued COM1 device_region.
//   2. Discover device_regions in the cap table (boot grant list).
//   3. Mint two ports — `blockdev_port` (fs ↔ nvme_driver) and
//      `fs_port` (verify_fs/anything ↔ fs).
//   4. Allocate two page_frames — `blockdev_scratch` (1 page; shared
//      between fs and nvme_driver) and `io_scratch` (fs_ops.SCRATCH_PAGES;
//      shared between fs and FS clients).
//   5. Stage nvme_driver.elf, fs.elf, verify_fs.elf into page_frames.
//   6. Spawn nvme_driver with [COM1, blockdev_port (recv|bind),
//        blockdev_scratch (r+w), <each MMIO device_region>].
//   7. Spawn fs with [COM1, blockdev_port (xfer|bind), blockdev_scratch (r+w),
//        fs_port (recv|bind), io_scratch (r+w)].
//   8. Spawn verify_fs with [COM1, fs_port (xfer|bind), io_scratch (r+w)].
//   9. Park.

const lib = @import("lib");
const log = @import("log");
const services = @import("services");

const builtin = @import("builtin");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const PAGE_4K: u64 = 4096;
const BLOCKDEV_SCRATCH_PAGES: u64 = 1;
const IO_SCRATCH_PAGES: u64 = 16; // fs_ops.SCRATCH_PAGES; kept literal to avoid module dep.
const MAX_PASSED: usize = 32;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[desktopOS] root service starting\n");

    const com1 = findCom1(cap_table_base) orelse {
        log.print("[desktopOS] FATAL: no COM1 in cap table\n");
        powerShutdown();
    };

    if (findFramebuffer(cap_table_base)) |fb_slot| {
        const fb = caps.framebufferFields(caps.readCap(cap_table_base, fb_slot));
        log.print("[desktopOS] framebuffer slot=");
        log.dec(fb_slot);
        log.print(" ");
        log.dec(fb.width);
        log.print("x");
        log.dec(fb.height);
        log.print(" stride=");
        log.dec(fb.stride);
        log.print(" fmt=");
        log.dec(@intFromEnum(fb.pixel_format));
        log.print("\n");
    } else {
        log.print("[desktopOS] no framebuffer in cap table\n");
    }

    // Mint the two ports. Both come up with full caps so we can pass
    // restricted views down to each child.
    const port_full = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const blockdev_port = createPort(port_full) orelse powerShutdown();
    const fs_port = createPort(port_full) orelse powerShutdown();

    // Shared page_frames.
    const blockdev_scratch = createPf(BLOCKDEV_SCRATCH_PAGES) orelse {
        log.print("[desktopOS] FATAL: blockdev_scratch alloc failed\n");
        powerShutdown();
    };
    const io_scratch = createPf(IO_SCRATCH_PAGES) orelse {
        log.print("[desktopOS] FATAL: io_scratch alloc failed\n");
        powerShutdown();
    };

    // Stage child ELFs.
    const nvme_driver_pf = stageElfPageFrame(services.nvme_driver_elf) orelse powerShutdown();
    const fs_pf = stageElfPageFrame(services.fs_elf) orelse powerShutdown();
    const verify_pf = stageElfPageFrame(services.verify_fs_elf) orelse powerShutdown();

    // Collect MMIO device_regions to forward to the NVMe driver.
    var mmio_devs: [16]HandleId = undefined;
    const mmio_count = collectMmioDeviceRegions(cap_table_base, &mmio_devs);
    log.print("[desktopOS] forwarding ");
    log.dec(mmio_count);
    log.print(" MMIO device_region(s) to nvme_driver\n");

    // ── Spawn nvme_driver ───────────────────────────────────────────
    {
        var passed: [MAX_PASSED]u64 = undefined;
        var n: usize = 0;
        appendDevice(&passed, &n, com1, .{}); // COM1 (caps don't gate map_mmio)
        appendPort(&passed, &n, blockdev_port, .{ .recv = true, .bind = true });
        appendPf(&passed, &n, blockdev_scratch, .{ .r = true, .w = true });
        var i: usize = 0;
        while (i < mmio_count) : (i += 1) {
            appendDevice(&passed, &n, mmio_devs[i], .{ .dma = true, .irq = true });
        }
        _ = spawnService("nvme_driver", nvme_driver_pf, passed[0..n]) orelse powerShutdown();
    }

    // ── Spawn fs ────────────────────────────────────────────────────
    {
        var passed: [MAX_PASSED]u64 = undefined;
        var n: usize = 0;
        appendDevice(&passed, &n, com1, .{});
        appendPort(&passed, &n, blockdev_port, .{ .xfer = true, .bind = true });
        appendPf(&passed, &n, blockdev_scratch, .{ .r = true, .w = true });
        appendPort(&passed, &n, fs_port, .{ .recv = true, .bind = true });
        appendPf(&passed, &n, io_scratch, .{ .r = true, .w = true });
        _ = spawnService("fs", fs_pf, passed[0..n]) orelse powerShutdown();
    }

    // ── Spawn verify_fs ─────────────────────────────────────────────
    {
        var passed: [MAX_PASSED]u64 = undefined;
        var n: usize = 0;
        appendDevice(&passed, &n, com1, .{});
        appendPort(&passed, &n, fs_port, .{ .xfer = true, .bind = true });
        appendPf(&passed, &n, io_scratch, .{ .r = true, .w = true });
        _ = spawnService("verify_fs", verify_pf, passed[0..n]) orelse powerShutdown();
    }

    log.print("[desktopOS] services spawned; root parking\n");
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

fn appendPort(buf: []u64, n: *usize, handle: HandleId, port_caps: caps.PortCap) void {
    buf[n.*] = (caps.PassedHandle{
        .id = handle,
        .caps = port_caps.toU16(),
        .move = false,
    }).toU64();
    n.* += 1;
}

fn appendPf(buf: []u64, n: *usize, handle: HandleId, pf_caps: caps.PfCap) void {
    buf[n.*] = (caps.PassedHandle{
        .id = handle,
        .caps = pf_caps.toU16(),
        .move = false,
    }).toU64();
    n.* += 1;
}

fn appendDevice(buf: []u64, n: *usize, handle: HandleId, dev_caps: caps.DeviceCap) void {
    buf[n.*] = (caps.PassedHandle{
        .id = handle,
        .caps = dev_caps.toU16(),
        .move = false,
    }).toU64();
    n.* += 1;
}

fn collectMmioDeviceRegions(cap_table_base: u64, out: []HandleId) usize {
    var n: usize = 0;
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX and n < out.len) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() != .device_region) continue;
        const dev_type: u4 = @truncate(c.field0 & 0xF);
        if (dev_type != 0) continue; // not MMIO
        const size_pages: u64 = (c.field0 >> 52) & 0xFFF;
        if (size_pages == 0) continue;
        out[n] = @truncate(slot);
        n += 1;
    }
    return n;
}

fn findFramebuffer(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() != .device_region) continue;
        const dev_type: u4 = @truncate(c.field0 & 0xF);
        if (dev_type != @intFromEnum(caps.DevType.framebuffer)) continue;
        return @truncate(slot);
    }
    return null;
}

fn findCom1(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() != .device_region) continue;
        const dr = caps.deviceRegionFields(c);
        if (dr.dev_type == .port_io and dr.base_port == 0x3F8 and dr.port_count == 8) {
            return @truncate(slot);
        }
    }
    return null;
}

fn createPort(port_caps: caps.PortCap) ?HandleId {
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (cp.v1 < 16) return null;
    return @truncate(cp.v1 & 0xFFF);
}

fn createPf(pages: u64) ?HandleId {
    const pf_caps = caps.PfCap{ .move = true, .copy = true, .r = true, .w = true };
    const c = syscall.createPageFrame(@as(u64, pf_caps.toU16()), 0, pages);
    if (c.v1 < 16) return null;
    return @truncate(c.v1 & 0xFFF);
}

fn spawnService(name: []const u8, elf_pf: HandleId, passed: []const u64) ?HandleId {
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    const child_self = caps.SelfCap{
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crpt = true,
        .fut_wake = true,
        .timer = true,
        .pri = 2,
    };

    const r = syscall.createCapabilityDomain(
        @as(u64, child_self.toU16()),
        ceilings_inner,
        ceilings_outer,
        elf_pf,
        0,
        passed,
    );
    if (r.v1 < 16) {
        log.print("[desktopOS] FATAL: createCapabilityDomain(");
        log.print(name);
        log.print(") err=");
        log.dec(r.v1);
        log.print("\n");
        return null;
    }
    const idc: HandleId = @truncate(r.v1 & 0xFFF);
    log.print("[desktopOS] spawned ");
    log.print(name);
    log.print(" (idc=");
    log.dec(idc);
    log.print(", passed=");
    log.dec(passed.len);
    log.print(")\n");
    return idc;
}

fn stageElfPageFrame(elf_bytes: []const u8) ?HandleId {
    const pages = (elf_bytes.len + PAGE_4K - 1) / PAGE_4K;
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true, .x = true };
    const cpf = syscall.createPageFrame(@as(u64, pf_caps.toU16()), 0, pages);
    if (cpf.v1 < 16) return null;
    const pf_handle: HandleId = @truncate(cpf.v1 & 0xFFF);

    const var_caps_word = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011;
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        pages,
        0,
        0,
    );
    if (cvar.v1 < 16) return null;
    const vmar_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const vmar_base: u64 = cvar.v2;

    const pairs = [_]u64{ 0, pf_handle };
    const mp = syscall.mapPf(vmar_handle, pairs[0..]);
    if (mp.v1 != 0) return null;

    const dst: [*]u8 = @ptrFromInt(vmar_base);
    var i: usize = 0;
    while (i < elf_bytes.len) : (i += 1) dst[i] = elf_bytes[i];

    _ = syscall.delete(vmar_handle);
    return pf_handle;
}

fn powerShutdown() noreturn {
    _ = syscall.powerShutdown();
    while (true) asm volatile ("hlt");
}
