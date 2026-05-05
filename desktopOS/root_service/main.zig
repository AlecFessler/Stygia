// desktopOS root service.
//
// Phase-1 boot path:
//   1. log.init via the kernel-issued COM1 device_region.
//   2. Discover device_regions in the cap table (boot grant list).
//   3. createPort + createPageFrame for the shared block scratch.
//   4. createPageFrame for the block_device's "disk" backing.
//   5. Stage block_device.elf and fs.elf into page_frames.
//   6. Spawn block_device with passed handles =
//        [COM1, port (recv), scratch_pf (r+w), disk_pf (r+w)]
//   7. Spawn fs with passed handles =
//        [COM1, port (xfer), scratch_pf (r+w)]
//   8. Park.
//
// Once the IOMMU restoration agent lands and the real NVMe driver
// is functional, the disk_pf gets replaced by an NVMe device_region
// passed to a third service that speaks the same blockdev wire
// protocol — fs is the same code in either case.

const lib = @import("lib");
const log = @import("log");
const services = @import("services");

const builtin = @import("builtin");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const PAGE_4K: u64 = 4096;
const SCRATCH_PAGES: u64 = 1;
const DISK_PAGES: u64 = 4096; // 16 MiB
const MAX_PASSED: usize = 16;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[desktopOS] root service starting\n");

    const com1 = findCom1(cap_table_base) orelse {
        log.print("[desktopOS] FATAL: no COM1 in cap table\n");
        powerShutdown();
    };

    // Mint the IPC port that fs and block_device share.
    const port_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (cp.v1 < 16) {
        log.print("[desktopOS] FATAL: createPort err=");
        log.dec(cp.v1);
        log.print("\n");
        powerShutdown();
    }
    const port_handle: HandleId = @truncate(cp.v1 & 0xFFF);

    // Allocate the shared scratch buffer (block transfer area).
    const scratch_pf = createPf(SCRATCH_PAGES) orelse {
        log.print("[desktopOS] FATAL: scratch_pf alloc failed\n");
        powerShutdown();
    };

    // Allocate the block_device's "disk" backing.
    const disk_pf = createPf(DISK_PAGES) orelse {
        log.print("[desktopOS] FATAL: disk_pf alloc failed\n");
        powerShutdown();
    };

    // Stage child ELFs.
    const block_device_pf = stageElfPageFrame(services.block_device_elf) orelse {
        log.print("[desktopOS] FATAL: stage(block_device.elf) failed\n");
        powerShutdown();
    };
    const fs_pf = stageElfPageFrame(services.fs_elf) orelse {
        log.print("[desktopOS] FATAL: stage(fs.elf) failed\n");
        powerShutdown();
    };

    // Spawn block_device.
    _ = spawnService(
        "block_device",
        block_device_pf,
        com1,
        port_handle,
        true, // recv side
        &.{ scratch_pf, disk_pf },
    ) orelse powerShutdown();

    // Spawn fs.
    _ = spawnService(
        "fs",
        fs_pf,
        com1,
        port_handle,
        false, // xfer side
        &.{scratch_pf},
    ) orelse powerShutdown();

    log.print("[desktopOS] both services spawned; root parking\n");

    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
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

fn createPf(pages: u64) ?HandleId {
    const pf_caps = caps.PfCap{
        .move = true,
        .copy = true,
        .r = true,
        .w = true,
    };
    const c = syscall.createPageFrame(@as(u64, pf_caps.toU16()), 0, pages);
    if (c.v1 < 16) return null;
    return @truncate(c.v1 & 0xFFF);
}

/// Spawn a child capability domain running `elf_pf`. Passes COM1 by
/// copy, the IPC port (with caps tailored to recv vs xfer side),
/// then any extra page_frame handles.
fn spawnService(
    name: []const u8,
    elf_pf: HandleId,
    com1: HandleId,
    port_handle: HandleId,
    is_recv_side: bool,
    extra_pfs: []const HandleId,
) ?HandleId {
    var passed: [MAX_PASSED]u64 = undefined;
    var n: usize = 0;

    // [0] COM1 (port_io device_region; map_mmio doesn't gate on caps)
    passed[n] = (caps.PassedHandle{
        .id = com1,
        .caps = 0,
        .move = false,
    }).toU64();
    n += 1;

    // [1] port — recv for server, xfer for client.
    // Both sides also get `bind` — suspend's perm check on the port
    // handle requires it (matches the runner's port-grant pattern).
    const port_passed_caps = if (is_recv_side)
        caps.PortCap{ .recv = true, .bind = true }
    else
        caps.PortCap{ .xfer = true, .bind = true };
    passed[n] = (caps.PassedHandle{
        .id = port_handle,
        .caps = port_passed_caps.toU16(),
        .move = false,
    }).toU64();
    n += 1;

    // [2..] page_frames (r+w; recipient maps them into its own VMARs)
    const pf_passed_caps = caps.PfCap{ .r = true, .w = true };
    var i: usize = 0;
    while (i < extra_pfs.len and n < MAX_PASSED) : (i += 1) {
        passed[n] = (caps.PassedHandle{
            .id = extra_pfs[i],
            .caps = pf_passed_caps.toU16(),
            .move = false,
        }).toU64();
        n += 1;
    }

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
        passed[0..n],
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
    log.dec(n);
    log.print(")\n");
    return idc;
}

/// Allocate a page_frame, map R+W locally, copy `elf_bytes` in,
/// drop the temp VMAR. Returns the page_frame handle id.
fn stageElfPageFrame(elf_bytes: []const u8) ?HandleId {
    const pages = (elf_bytes.len + PAGE_4K - 1) / PAGE_4K;
    const pf_caps = caps.PfCap{
        .move = true,
        .r = true,
        .w = true,
        .x = true,
    };
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

    // Spec §[map_pf] pair order: (offset_bytes, page_frame_handle).
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
