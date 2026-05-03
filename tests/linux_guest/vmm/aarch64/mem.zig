//! aarch64 guest physical memory management — spec-v3 port.
//!
//! Mirror of `vmm/mem.zig` for the aarch64 boot path. Differences:
//!   * Guest RAM is staged at `GUEST_RAM_BASE = 0x10000000` (256 MiB)
//!     to fit inside the kernel's 1 GiB stage-2 IPA window (T0SZ=34 in
//!     `kernel/arch/aarch64/stage2.zig`).
//!   * Guest RAM size defaults to 128 MiB so a single buddy chunk
//!     covers it; `setupGuestMemory(size)` accepts arbitrary sizes
//!     up to `MAX_CHUNKS * CHUNK_BYTES`.

const lib = @import("lib");

const log = @import("log.zig");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;
const PfCap = caps.PfCap;
const VmarCap = caps.VmarCap;

pub const PAGE_SIZE: u64 = 4096;

pub const GUEST_RAM_BASE: u64 = 0x1000_0000; // 256 MiB

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
pub fn allocPolicyPageFrame() ?HandleId {
    const pf_caps_word: u64 = @as(u64, (PfCap{
        .r = true,
        .w = true,
        .max_sz = 0,
    }).toU16());
    const pf_props_word: u64 = 0;
    const pf_r = syscall.createPageFrame(pf_caps_word, pf_props_word, 1);
    if (pf_r.v1 < 16) return null;
    const pf_handle: HandleId = @truncate(pf_r.v1 & 0xFFF);

    const var_caps_word: u64 = @as(u64, (VmarCap{
        .r = true,
        .w = true,
    }).toU16());
    const var_props: u64 = 0b011;
    const var_r = syscall.createVmar(var_caps_word, var_props, 1, 0, 0);
    if (var_r.v1 < 16) return null;
    const vmar_handle: HandleId = @truncate(var_r.v1 & 0xFFF);
    const var_base: u64 = var_r.v2;

    const map_pairs = [_]u64{ 0, @as(u64, pf_handle) };
    const map_r = syscall.mapPf(vmar_handle, &map_pairs);
    if (map_r.v1 != 0) return null;

    const policy_ptr: [*]u8 = @ptrFromInt(var_base);
    @memset(policy_ptr[0..PAGE_SIZE], 0);

    return pf_handle;
}

/// Allocate guest RAM as a sequence of buddy-sized page_frames, install
/// them contiguously at gpa GUEST_RAM_BASE..GUEST_RAM_BASE+size in the
/// VM, and map a single local VMAR over them so VMM-side @memcpy etc.
/// see one flat host VA range.
pub fn setupGuestMemory(size: u64) bool {
    const num_pages = size / PAGE_SIZE;
    const chunks_needed: usize = @intCast((num_pages + CHUNK_PAGES - 1) / CHUNK_PAGES);
    if (chunks_needed > MAX_CHUNKS) return false;

    const pf_caps_word: u64 = @as(u64, (PfCap{
        .r = true,
        .w = true,
        .x = true,
        .max_sz = 0,
    }).toU16());
    const pf_props_word: u64 = 0;

    var i: usize = 0;
    while (i < chunks_needed) {
        const pf_r = syscall.createPageFrame(pf_caps_word, pf_props_word, CHUNK_PAGES);
        if (pf_r.v1 < 16) return false;
        guest_ram_pfs[i] = @truncate(pf_r.v1 & 0xFFF);
        i += 1;
    }
    guest_ram_chunk_count = chunks_needed;

    const main_mod = @import("main.zig");
    i = 0;
    while (i < chunks_needed) {
        const map_pairs = [_]u64{ GUEST_RAM_BASE + i * CHUNK_BYTES, @as(u64, guest_ram_pfs[i]) };
        const mg_r = syscall.mapGuest(main_mod.vm_handle, &map_pairs);
        if (mg_r.v1 != 0) return false;
        i += 1;
    }

    const total_local_pages = chunks_needed * CHUNK_PAGES;
    const var_caps_word: u64 = @as(u64, (VmarCap{
        .r = true,
        .w = true,
    }).toU16());
    const var_props: u64 = 0b011;
    const var_r = syscall.createVmar(var_caps_word, var_props, total_local_pages, 0, 0);
    if (var_r.v1 < 16) return false;
    guest_ram_var = @truncate(var_r.v1 & 0xFFF);
    host_base = var_r.v2;

    i = 0;
    while (i < chunks_needed) {
        const local_pairs = [_]u64{ i * CHUNK_BYTES, @as(u64, guest_ram_pfs[i]) };
        const mp_r = syscall.mapPf(guest_ram_var, &local_pairs);
        if (mp_r.v1 != 0) return false;
        i += 1;
    }

    mapped_size = size;
    log.print("");
    return true;
}

pub fn writeGuest(guest_phys: u64, data: []const u8) void {
    if (guest_phys < GUEST_RAM_BASE) return;
    const offset = guest_phys - GUEST_RAM_BASE;
    if (offset + data.len > mapped_size) return;
    const dst: [*]u8 = @ptrFromInt(host_base + offset);
    @memcpy(dst[0..data.len], data);
}

pub fn zeroGuest(guest_phys: u64, len: u64) void {
    if (guest_phys < GUEST_RAM_BASE) return;
    const offset = guest_phys - GUEST_RAM_BASE;
    if (offset + len > mapped_size) return;
    const dst: [*]u8 = @ptrFromInt(host_base + offset);
    @memset(dst[0..@intCast(len)], 0);
}

pub fn guestToHost(guest_phys: u64) ?[*]u8 {
    if (guest_phys < GUEST_RAM_BASE) return null;
    const offset = guest_phys - GUEST_RAM_BASE;
    if (offset >= mapped_size) return null;
    return @ptrFromInt(host_base + offset);
}
