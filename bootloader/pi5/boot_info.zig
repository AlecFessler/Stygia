//! Synthesize a `BootInfo` for the Raspberry Pi 5 native boot path.
//!
//! `BootInfo` is UEFI-shaped — `mmap` is an array of `uefi.tables.MemoryDescriptor`
//! — because until now the only thing that produced one was the UEFI loader. Rather
//! than add a second map format to the kernel (and a second code path in
//! `memory.init` to consume it), this builds descriptors in the existing shape.
//! The kernel then cannot tell the difference, which is the whole point: the seam
//! stays `kEntry(*BootInfo)` and no kernel code changes for bare metal.
//!
//! The real work is subtraction. The DTB says which physical ranges are RAM, but
//! several regions inside that RAM must never reach the page allocator:
//!
//!   * ATF at 0x0-0x7FFFF, which provides PSCI. Allocating over it breaks SMP
//!     bring-up and SYSTEM_RESET — and it breaks them later, somewhere else,
//!     long after the actual mistake.
//!   * This loader's own image and stack, which are still executing.
//!   * The DTB blob, which we are still reading.
//!   * The early log at 0xF9000000, or the kernel silently overwrites the only
//!     record of what went wrong.
//!   * The root_service blob the kernel is about to load.
//!
//! `collapseMMap` in kernel/boot/protocol.zig merges adjacent descriptors only
//! when `physical_start == prev_end`, so descriptors must come out **sorted and
//! non-overlapping** or the map it builds is wrong. It also asserts
//! `num_descriptors <= MAX_MMAP_ENTRIES` (256).

const std = @import("std");
const stygia = @import("stygia");

const dtb = @import("dtb.zig");
const log = @import("early_log.zig");

const uefi = std.os.uefi;
const protocol = stygia.boot.protocol;

pub const BootInfo = protocol.BootInfo;
pub const MMap = protocol.MMap;

pub const PAGE: u64 = 4096;

/// Bounded by `collapseMMap`'s MAX_MMAP_ENTRIES (256). Splitting 2 RAM ranges by
/// ~a dozen reservations cannot approach this, but the cap is asserted rather
/// than assumed because overflowing it silently corrupts the map.
pub const MAX_DESCRIPTORS = 64;

pub const Error = error{
    TooManyDescriptors,
    TooManyReservations,
    NoUsableMemory,
};

const MAX_RESERVATIONS = dtb.MAX_RANGES * 2 + 8;

/// A carve-out of RAM, with the descriptor type it must be published as.
///
/// The type matters more than it looks. `kernel/boot/protocol.zig:87-96` folds
/// UEFI types into three kernel-visible classes, and `kernel/memory/init.zig`
/// then treats them very differently:
///
///   * `.conventional_memory` -> `.free`: physmapped AND handed to the physical
///     allocator (init.zig:67 and :132).
///   * `.acpi_reclaim_memory` -> `.acpi`: physmapped, NOT handed to the
///     allocator. Visible but not reusable.
///   * anything else -> `.reserved`: neither. Invisible to the kernel.
///
/// So "reserved" is not a synonym for "safe". Anything the kernel must still be
/// able to READ after handoff — page tables, the root_service blob — has to be
/// `.acpi_reclaim_memory`, or `VAddr.fromPAddr(phys, null)` produces a physmap VA
/// that was never mapped. This is the same type the UEFI loader allocates its
/// page tables from (`PageAllocator.init(boot_services, .acpi_reclaim_memory)`),
/// for the same reason.
const Reservation = struct {
    base: u64,
    size: u64,
    mem_type: uefi.tables.MemoryType,

    fn end(self: Reservation) u64 {
        return self.base + self.size;
    }
};

/// Storage for the descriptor array handed to the kernel. It must outlive this
/// loader — the kernel reads it after we have branched away — so it lives in
/// .bss inside the loader image, and the loader image is itself marked reserved
/// in the very map it builds. That circularity is deliberate.
var descriptors: [MAX_DESCRIPTORS]uefi.tables.MemoryDescriptor = undefined;
var descriptor_count: usize = 0;

var reservations: [MAX_RESERVATIONS]Reservation = undefined;
var reservation_count: usize = 0;

fn pageDown(v: u64) u64 {
    return v & ~(PAGE - 1);
}

fn pageUp(v: u64) u64 {
    return (v + PAGE - 1) & ~(PAGE - 1);
}

/// Add a reservation, rounded OUTWARD to page boundaries.
///
/// Outward is the only safe direction: rounding a reservation inward would leave
/// a partial page of protected memory inside a "free" descriptor, and the
/// allocator would hand out a page that overlaps something live.
fn reserve(base: u64, size: u64, mem_type: uefi.tables.MemoryType) Error!void {
    if (size == 0) return;
    if (reservation_count >= MAX_RESERVATIONS) return Error.TooManyReservations;
    reservations[reservation_count] = .{
        .base = pageDown(base),
        .size = pageUp(base + size) - pageDown(base),
        .mem_type = mem_type,
    };
    reservation_count += 1;
}

/// Sort reservations by base and merge any that overlap or abut.
///
/// Insertion sort: n is at most ~70 and this runs once, with no allocator
/// available. The merge is what lets the emit loop below assume the reservation
/// list is a clean, ordered partition.
///
/// Only merges reservations of the SAME type. Merging across types would silently
/// relabel memory — folding an `.acpi_reclaim_memory` page table into an abutting
/// `.reserved_memory_type` range would make the kernel stop physmapping it, and
/// the failure would surface as a fault on a physmap VA thousands of instructions
/// later. Differing types are left as separate descriptors, which `collapseMMap`
/// handles correctly (it also refuses to merge unlike types).
fn normalizeReservations() void {
    var i: usize = 1;
    while (i < reservation_count) : (i += 1) {
        const key = reservations[i];
        var j: usize = i;
        while (j > 0 and reservations[j - 1].base > key.base) : (j -= 1) {
            reservations[j] = reservations[j - 1];
        }
        reservations[j] = key;
    }

    if (reservation_count == 0) return;
    var w: usize = 0;
    var r: usize = 1;
    while (r < reservation_count) : (r += 1) {
        const cur = reservations[r];
        const acc_end = reservations[w].end();
        if (cur.base <= acc_end and cur.mem_type == reservations[w].mem_type) {
            if (cur.end() > acc_end) {
                reservations[w].size = cur.end() - reservations[w].base;
            }
        } else {
            w += 1;
            reservations[w] = cur;
        }
    }
    reservation_count = w + 1;
}

fn emit(mem_type: uefi.tables.MemoryType, base: u64, size: u64) Error!void {
    if (size < PAGE) return;
    if (descriptor_count >= MAX_DESCRIPTORS) return Error.TooManyDescriptors;
    descriptors[descriptor_count] = .{
        .type = mem_type,
        .physical_start = base,
        .virtual_start = 0,
        .number_of_pages = size / PAGE,
        .attribute = std.mem.zeroes(uefi.tables.MemoryDescriptorAttribute),
    };
    descriptor_count += 1;
}

pub const LoaderExtents = struct {
    /// The loader image, from its link base through __image_end.
    image_base: u64,
    image_end: u64,
    /// Stack region. Grows DOWN from stack_top, so the reserved span is
    /// [stack_top - stack_size, stack_top).
    stack_top: u64,
    stack_size: u64,
    /// The DTB firmware handed us, still being read.
    dtb_base: u64,
    dtb_size: u64,
    /// The embedded root_service blob, if any.
    root_service_base: u64,
    root_service_size: u64,
    /// Pages handed out by the bump allocator: page tables, the loaded kernel
    /// image, the kernel stack. Zero on the preliminary pass, which is the pass
    /// that CHOOSES the arena and therefore cannot know it yet. See
    /// page_allocator.zig for why the map has to be built twice.
    arena_base: u64 = 0,
    arena_size: u64 = 0,
};

/// Build the descriptor array. Returns an `MMap` pointing at static storage.
pub fn buildMMap(map: *const dtb.MemoryMap, ext: LoaderExtents) Error!MMap {
    descriptor_count = 0;
    reservation_count = 0;

    // ATF and anything else the DTB declares off-limits. Fully opaque to the
    // kernel: it must neither allocate nor read these.
    for (map.reservedSlice()) |r| try reserve(r.base, r.size, .reserved_memory_type);

    // The loader image and its stack. Fully opaque: the embedded blobs live in
    // here, but the kernel never reads them at these addresses. Both are copied
    // into the arena first, because the kernel resolves BOTH blob pointers as
    // PHYSICAL addresses through the physmap — `elf_blob` via
    // `debug_info.init`'s `elf_phys_ptr` (utils/debug_info.zig:47-49) and
    // `root_service` at kernel/main.zig:119-121, both doing
    // `VAddr.fromPAddr(PAddr.fromInt(@intFromPtr(ptr)), null)`. A pointer into
    // this reserved image would resolve to a physmap VA that was never mapped.
    try reserve(ext.image_base, ext.image_end - ext.image_base, .reserved_memory_type);
    try reserve(ext.stack_top - ext.stack_size, ext.stack_size, .reserved_memory_type);
    // The DTB blob. Reserved, not reclaimable: the kernel's devicetree discovery
    // maps this range itself rather than reaching it through the physmap.
    try reserve(ext.dtb_base, ext.dtb_size, .reserved_memory_type);
    // The root_service blob's arena copy. `.acpi_reclaim_memory` for the physmap
    // reason above, and specifically NOT `.conventional_memory`: that would make
    // it `.free`, which `memory/init.zig:132` hands to the physical allocator, so
    // the allocator could reuse the blob before main.zig:122 reads it. This
    // normally falls inside the arena range below and merges with it — same type,
    // so `normalizeReservations` folds them.
    if (ext.root_service_size != 0) {
        try reserve(ext.root_service_base, ext.root_service_size, .acpi_reclaim_memory);
    }
    // The bump arena: page tables the kernel keeps walking after handoff, plus
    // the loaded kernel image and stack. Must stay physmap-visible for the same
    // reason, and must never be reallocated.
    if (ext.arena_size != 0) {
        try reserve(ext.arena_base, ext.arena_size, .acpi_reclaim_memory);
    }
    // The early log. Reserving it is what keeps a postmortem readable after the
    // kernel has been running for a while. Left opaque rather than reclaimable
    // because nothing kernel-side writes to it yet; flip it to
    // `.acpi_reclaim_memory` when a bare-metal console needs it as a fallback.
    try reserve(log.REGION, log.REGION_SIZE, .reserved_memory_type);

    normalizeReservations();

    // Walk each RAM range, cutting out reservations as we go. Both lists are
    // sorted, so this is a single merge pass and the output is sorted too —
    // which is exactly what collapseMMap needs to merge correctly.
    for (map.ramSlice()) |ram| {
        // Round RAM inward: a partial page at either end is not usable and
        // claiming it would hand the allocator a page that runs off the end.
        var cursor = pageUp(ram.base);
        const limit = pageDown(ram.end());
        if (cursor >= limit) continue;

        for (reservations[0..reservation_count]) |res| {
            if (res.end() <= cursor) continue;
            if (res.base >= limit) break;

            if (res.base > cursor) {
                try emit(.conventional_memory, cursor, res.base - cursor);
            }
            const res_start = @max(res.base, cursor);
            const res_end = @min(res.end(), limit);
            if (res_end > res_start) {
                try emit(res.mem_type, res_start, res_end - res_start);
            }
            cursor = res_end;
            if (cursor >= limit) break;
        }

        if (cursor < limit) {
            try emit(.conventional_memory, cursor, limit - cursor);
        }
    }

    var free_pages: u64 = 0;
    for (descriptors[0..descriptor_count]) |d| {
        if (d.type == .conventional_memory) free_pages += d.number_of_pages;
    }
    if (free_pages == 0) return Error.NoUsableMemory;

    return .{
        .key = @enumFromInt(0),
        .mmap = &descriptors,
        .mmap_size = descriptor_count * @sizeOf(uefi.tables.MemoryDescriptor),
        .descriptor_size = @sizeOf(uefi.tables.MemoryDescriptor),
        .num_descriptors = descriptor_count,
    };
}

/// The largest free span in the map built by the most recent `buildMMap`.
///
/// This is how the page arena gets sited, which is why `buildMMap` runs once
/// before any allocation: the loader needs a picture of free memory in order to
/// carve its own working set out of it. Ties go to the lower address purely for
/// determinism — a boot-to-boot difference in arena placement would make two
/// otherwise identical failures look unrelated.
pub fn largestFreeSpan() ?dtb.Range {
    var best: ?dtb.Range = null;
    for (descriptors[0..descriptor_count]) |d| {
        if (d.type != .conventional_memory) continue;
        const size = d.number_of_pages * PAGE;
        if (best == null or size > best.?.size) {
            best = .{ .base = d.physical_start, .size = size };
        }
    }
    return best;
}

/// Dump the synthesized map to the early log. This is the only way to see
/// whether the map is right before the kernel consumes it, and a wrong map
/// manifests as a fault thousands of instructions later in the allocator.
pub fn dumpMMap() void {
    log.str("  synthesized memory map (");
    log.dec(descriptor_count);
    log.str(" descriptors):\n");
    var free_pages: u64 = 0;
    for (descriptors[0..descriptor_count]) |d| {
        const kind = switch (d.type) {
            .conventional_memory => "free    ",
            .reserved_memory_type => "reserved",
            // Physmapped but not allocatable. Shown distinctly because confusing
            // it with "reserved" hides exactly the bug this typing prevents.
            .acpi_reclaim_memory => "reclaim ",
            else => "other   ",
        };
        log.str("    ");
        log.str(kind);
        log.byte(' ');
        log.hex(d.physical_start);
        log.str(" .. ");
        log.hex(d.physical_start + d.number_of_pages * PAGE);
        log.str("  ");
        log.size(d.number_of_pages * PAGE);
        log.byte('\n');
        if (d.type == .conventional_memory) free_pages += d.number_of_pages;
    }
    log.str("  usable total: ");
    log.size(free_pages * PAGE);
    log.byte('\n');
}

pub fn dumpReservations() void {
    log.str("  reservations after merge (");
    log.dec(reservation_count);
    log.str("):\n");
    for (reservations[0..reservation_count]) |r| {
        log.str("    ");
        log.str(switch (r.mem_type) {
            .acpi_reclaim_memory => "reclaim ",
            else => "opaque  ",
        });
        log.hex(r.base);
        log.str(" .. ");
        log.hex(r.end());
        log.str("  ");
        log.size(r.size);
        log.byte('\n');
    }
}
