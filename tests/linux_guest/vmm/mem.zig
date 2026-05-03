//! Guest physical memory management — spec-v3 port.
//!
//! Layout:
//!   1. Allocate a page_frame for the VmPolicy struct (small, 1 page),
//!      map it locally so we can write the policy bytes before
//!      createVirtualMachine consumes it.
//!   2. Allocate a single contiguous page_frame covering all guest RAM.
//!   3. map_guest the guest RAM page_frame into the VM at gpa 0.
//!   4. createVmar + map_pf locally so the VMM can read/write guest
//!      memory by host VA (used for bzImage / initramfs / boot_params).

const lib = @import("lib");

const log = @import("log.zig");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;
const PfCap = caps.PfCap;
const VmarCap = caps.VmarCap;

const PAGE_SIZE: u64 = 4096;

// Guest RAM is allocated in fixed-size chunks to fit the kernel's
// buddy MAX_ORDER (currently 14 = 64 MiB). For 128 MiB we need 2
// chunks; we leave headroom for up to 16 (1 GiB) so larger guests
// don't immediately overflow this scaffolding.
// Buddy allocator caps each block at MAX_ORDER = 14 → 64 MiB at 4 KiB.
// Use 4 MiB chunks (order 10) for headroom and bounded allocator
// fragmentation. 128 MiB guest RAM = 32 chunks.
const CHUNK_PAGES: u64 = 1 << 10; // 1024 pages = 4 MiB per chunk
const CHUNK_BYTES: u64 = CHUNK_PAGES * PAGE_SIZE;
const MAX_CHUNKS: usize = 64;

var guest_ram_pfs: [MAX_CHUNKS]HandleId = .{0} ** MAX_CHUNKS;
var guest_ram_chunk_count: usize = 0;
var guest_ram_var: HandleId = 0;
var host_base: u64 = 0;
var mapped_size: u64 = 0;

/// Allocate the VmPolicy page_frame and map it locally so the caller
/// can zero-init / seed the policy before `createVirtualMachine`
/// consumes it. Returns the page_frame handle, or null on failure.
///
/// Spec test 05: createVirtualMachine returns E_INVAL if the policy
/// page_frame is smaller than sizeof(VmPolicy). One 4 KiB page covers
/// the x86-64 VmPolicy (≈ 1 KiB) comfortably.
pub fn allocPolicyPageFrame() ?HandleId {
    const pf_caps_word: u64 = @as(u64, (PfCap{
        .r = true,
        .w = true,
        .max_sz = 0, // 4 KiB
    }).toU16());
    const pf_props_word: u64 = 0; // sz = 0 (4 KiB)
    const pf_r = syscall.createPageFrame(pf_caps_word, pf_props_word, 1);
    if (pf_r.v1 < 16) {
        log.print("policy: createPageFrame failed: ");
        log.dec(pf_r.v1);
        log.print("\n");
        return null;
    }
    const pf_handle: HandleId = @truncate(pf_r.v1 & 0xFFF);

    // Map locally to zero the frame. The VMAR is a regular (non-mmio,
    // non-dma) range; we install one page_frame at offset 0.
    const var_caps_word: u64 = @as(u64, (VmarCap{
        .r = true,
        .w = true,
    }).toU16());
    const var_props: u64 = 0b011; // cur_rwx = r|w
    const var_r = syscall.createVmar(var_caps_word, var_props, 1, 0, 0);
    if (var_r.v1 < 16) {
        log.print("policy: createVmar failed: ");
        log.dec(var_r.v1);
        log.print("\n");
        return null;
    }
    const vmar_handle: HandleId = @truncate(var_r.v1 & 0xFFF);
    const var_base: u64 = var_r.v2;

    const map_pairs = [_]u64{ 0, @as(u64, pf_handle) };
    const map_r = syscall.mapPf(vmar_handle, &map_pairs);
    if (map_r.v1 != 0) {
        log.print("policy: mapPf failed: ");
        log.dec(map_r.v1);
        log.print("\n");
        return null;
    }

    // Zero the policy page so num_cpuid_responses / num_cr_policies
    // start at 0 (the kernel rejects values exceeding MAX_*).
    const policy_ptr: [*]u8 = @ptrFromInt(var_base);
    @memset(policy_ptr[0..PAGE_SIZE], 0);

    return pf_handle;
}

/// Allocate guest RAM as a sequence of buddy-sized page_frames (each
/// up to MAX_ORDER pages = 64 MiB at 4 KiB), install them contiguously
/// at gpa 0..size in the VM, and map a single local VMAR over them so
/// VMM-side @memcpy etc. see one flat host VA range.
pub fn setupGuestMemory(size: u64) bool {
    const num_pages = size / PAGE_SIZE;
    const chunks_needed: usize = @intCast((num_pages + CHUNK_PAGES - 1) / CHUNK_PAGES);
    if (chunks_needed > MAX_CHUNKS) {
        log.print("guest_ram: size exceeds MAX_CHUNKS\n");
        return false;
    }

    // 1) Allocate chunks_needed page_frames.
    const pf_caps_word: u64 = @as(u64, (PfCap{
        .r = true,
        .w = true,
        .x = true, // guest executes its own code
        .max_sz = 0,
    }).toU16());
    const pf_props_word: u64 = 0; // sz = 0 (4 KiB)

    log.print("guest_ram: allocating ");
    log.dec(chunks_needed);
    log.print(" chunks of ");
    log.dec(CHUNK_PAGES);
    log.print(" pages each\n");

    var i: usize = 0;
    while (i < chunks_needed) {
        log.print("  chunk[");
        log.dec(i);
        log.print("] createPageFrame...");
        const pf_r = syscall.createPageFrame(pf_caps_word, pf_props_word, CHUNK_PAGES);
        log.print(" ret=");
        log.hex64(pf_r.v1);
        log.print("\n");
        if (pf_r.v1 < 16) {
            log.print("guest_ram: createPageFrame[");
            log.dec(i);
            log.print("] failed: ");
            log.dec(pf_r.v1);
            log.print("\n");
            return false;
        }
        guest_ram_pfs[i] = @truncate(pf_r.v1 & 0xFFF);
        i += 1;
    }
    guest_ram_chunk_count = chunks_needed;

    // 2) map_guest each chunk at its corresponding gpa.
    const main_mod = @import("main.zig");
    i = 0;
    while (i < chunks_needed) {
        const map_pairs = [_]u64{ i * CHUNK_BYTES, @as(u64, guest_ram_pfs[i]) };
        const mg_r = syscall.mapGuest(main_mod.vm_handle, &map_pairs);
        if (mg_r.v1 != 0) {
            log.print("guest_ram: mapGuest[");
            log.dec(i);
            log.print("] failed: ");
            log.dec(mg_r.v1);
            log.print("\n");
            return false;
        }
        i += 1;
    }

    // 3) Allocate a local VMAR sized to all chunks_needed * CHUNK_PAGES,
    //    then map_pf each chunk at the corresponding offset so VMM-side
    //    code sees one flat host VA range.
    const total_local_pages = chunks_needed * CHUNK_PAGES;
    const var_caps_word: u64 = @as(u64, (VmarCap{
        .r = true,
        .w = true,
    }).toU16());
    const var_props: u64 = 0b011; // cur_rwx = r|w
    const var_r = syscall.createVmar(var_caps_word, var_props, total_local_pages, 0, 0);
    if (var_r.v1 < 16) {
        log.print("guest_ram: createVmar failed: ");
        log.dec(var_r.v1);
        log.print("\n");
        return false;
    }
    guest_ram_var = @truncate(var_r.v1 & 0xFFF);
    host_base = var_r.v2;

    i = 0;
    while (i < chunks_needed) {
        const local_pairs = [_]u64{ i * CHUNK_BYTES, @as(u64, guest_ram_pfs[i]) };
        const mp_r = syscall.mapPf(guest_ram_var, &local_pairs);
        if (mp_r.v1 != 0) {
            log.print("guest_ram: mapPf[");
            log.dec(i);
            log.print("] (local) failed: ");
            log.dec(mp_r.v1);
            log.print("\n");
            return false;
        }
        i += 1;
    }

    mapped_size = size;
    log.print("mem: ");
    log.dec(size / (1024 * 1024));
    log.print(" MB guest RAM (");
    log.dec(chunks_needed);
    log.print(" chunks) at host 0x");
    log.hex64(host_base);
    log.print("\n");
    return true;
}

/// MMIO stub pages. Old linux_guest mapped a couple of all-0 pages at
/// device addresses Linux probes briefly (HPET, TPM). On the new ABI
/// each stub takes its own page_frame + map_guest call.
pub noinline fn mapMmioStubs() void {
    const mmio_addrs = [_]u64{
        0xFED00000, // HPET
        0xFED80000, // Intel TPM / platform devices
    };

    for (mmio_addrs) |addr| {
        const pf_caps_word: u64 = @as(u64, (PfCap{
            .r = true,
            .w = true,
        }).toU16());
        const pf_r = syscall.createPageFrame(pf_caps_word, 0, 1);
        if (pf_r.v1 < 16) continue;
        const pf_handle: HandleId = @truncate(pf_r.v1 & 0xFFF);

        const main_mod = @import("main.zig");
        const map_pairs = [_]u64{ addr, @as(u64, pf_handle) };
        const mg_r = syscall.mapGuest(main_mod.vm_handle, &map_pairs);
        if (mg_r.v1 == 0) {
            log.print("mem: MMIO stub at 0x");
            log.hex64(addr);
            log.print("\n");
        }
    }
}

/// Allocate a single 4 KiB page_frame, map it at `guest_phys` in the
/// VM, AND map it locally; return the host VA (caller can read / write
/// the page directly to keep guest-visible state in sync).
pub noinline fn mapDevicePage(guest_phys: u64) ?[*]volatile u8 {
    const pf_caps_word: u64 = @as(u64, (PfCap{
        .r = true,
        .w = true,
    }).toU16());
    const pf_r = syscall.createPageFrame(pf_caps_word, 0, 1);
    if (pf_r.v1 < 16) return null;
    const pf_handle: HandleId = @truncate(pf_r.v1 & 0xFFF);

    const main_mod = @import("main.zig");
    const map_pairs = [_]u64{ guest_phys, @as(u64, pf_handle) };
    const mg_r = syscall.mapGuest(main_mod.vm_handle, &map_pairs);
    if (mg_r.v1 != 0) return null;

    const var_caps_word: u64 = @as(u64, (VmarCap{
        .r = true,
        .w = true,
    }).toU16());
    const var_props: u64 = 0b011;
    const var_r = syscall.createVmar(var_caps_word, var_props, 1, 0, 0);
    if (var_r.v1 < 16) return null;
    const vmar_handle: HandleId = @truncate(var_r.v1 & 0xFFF);
    const var_base: u64 = var_r.v2;

    const local_pairs = [_]u64{ 0, @as(u64, pf_handle) };
    const mp_r = syscall.mapPf(vmar_handle, &local_pairs);
    if (mp_r.v1 != 0) return null;

    const ptr: [*]u8 = @ptrFromInt(var_base);
    @memset(ptr[0..PAGE_SIZE], 0);

    log.print("mem: device page at 0x");
    log.hex64(guest_phys);
    log.print(" -> host 0x");
    log.hex64(var_base);
    log.print("\n");
    return @ptrFromInt(var_base);
}

pub fn writeGuest(guest_phys: u64, data: []const u8) void {
    if (guest_phys + data.len > mapped_size) {
        log.print("mem: writeGuest out of bounds at 0x");
        log.hex64(guest_phys);
        log.print("\n");
        return;
    }
    const dst: [*]u8 = @ptrFromInt(host_base + guest_phys);
    @memcpy(dst[0..data.len], data);
}

pub fn readGuestByte(guest_phys: u64) u8 {
    if (guest_phys >= mapped_size) return 0;
    const ptr: *const u8 = @ptrFromInt(host_base + guest_phys);
    return ptr.*;
}

pub fn readGuestSlice(guest_phys: u64, len: usize) []const u8 {
    const ptr: [*]const u8 = @ptrFromInt(host_base + guest_phys);
    return ptr[0..len];
}

pub fn copyGuest(dst_phys: u64, src_phys: u64, len: u64) void {
    if (dst_phys + len > mapped_size or src_phys + len > mapped_size) return;
    const dst: [*]u8 = @ptrFromInt(host_base + dst_phys);
    const src: [*]const u8 = @ptrFromInt(host_base + src_phys);
    @memcpy(dst[0..@intCast(len)], src[0..@intCast(len)]);
}
