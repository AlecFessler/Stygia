//! Load the embedded kernel ELF into the arena and map it into the kernel table.
//!
//! This mirrors `bootloader/main.zig:289-352` deliberately closely. That path
//! reads `kernel.elf` off a FAT volume and allocates through UEFI; this one reads
//! it out of the loader image and allocates from the bump arena. Everything
//! between — section walk, per-page copy, permissions, cache maintenance — is the
//! same sequence, because any divergence would mean the bare-metal kernel is
//! handed a subtly different address space than the one every test boots on.
//!
//! Both blobs get COPIED into the arena rather than mapped where they sit. That
//! is not about mutability alone; it is the physmap contract. The kernel resolves
//! `BootInfo.elf_blob.ptr` and `BootInfo.root_service.ptr` as PHYSICAL addresses
//! and reads them through the physmap:
//!
//!   * `utils/debug_info.zig:47-49` — `elf_phys_ptr` -> `PAddr.fromInt` ->
//!     `VAddr.fromPAddr(.., null)`.
//!   * `kernel/main.zig:119-121` — the identical dance for root_service.
//!
//! The loader image is published as `.reserved_memory_type`, which the kernel
//! never physmaps, so a pointer into the image would resolve to an unmapped
//! physmap VA. The arena is `.acpi_reclaim_memory`: physmapped, and not handed to
//! the physical allocator. Hence the copy.

const std = @import("std");
const stygia = @import("stygia");

const log = @import("early_log.zig");
const page_allocator = @import("page_allocator.zig");

const arch = stygia.arch.dispatch;
const address = stygia.memory.address;
const paging = stygia.memory.paging;
const elf = stygia.utils.elf;

const ElfSection = elf.ElfSection;
const MemoryPerms = address.MemoryPerms;
const PAddr = address.PAddr;
const ParsedElf = elf.ParsedElf;
const VAddr = address.VAddr;

const kernel_code = address.AddrSpacePartition.kernel_code;

pub const Error = error{
    OutOfArena,
    NoSections,
};

/// Where a blob ended up after being copied into the arena.
pub const Blob = struct {
    /// Physical address. Page-aligned, and inside `.acpi_reclaim_memory`, so the
    /// kernel's `VAddr.fromPAddr(.., null)` resolves it through the physmap.
    phys: u64,
    len: u64,
};

pub const LoadedKernel = struct {
    /// The mutable ELF copy, handed to the kernel as `BootInfo.elf_blob` for DWARF.
    elf: Blob,
    /// Entry point VA, KASLR slide already applied.
    entry: VAddr,
    kaslr_slide: u64,
    /// Lowest and highest kernel VA actually mapped, for logging and for the
    /// sanity check that the image landed inside the kernel_code partition.
    va_low: u64,
    va_high: u64,
    pages_mapped: u64,
};

/// `ParsedElf` is ~large and this loader has no heap. One static instance is
/// enough: the kernel ELF is parsed exactly once.
var parsed: ParsedElf = undefined;

/// Copy a blob into freshly allocated arena pages.
///
/// Returns a mutable slice because `elf.parseElf` takes `[]u8` — it stores the
/// slice in `ParsedElf.bytes`, and `applyKaslrRelocations` writes through it when
/// the slide is non-zero.
pub fn copyIntoArena(alloc: std.mem.Allocator, src: []const u8) Error!Blob {
    const pages = alloc.alignedAlloc(u8, paging.pageAlign(.page4k), src.len) catch
        return Error.OutOfArena;
    // Byte-granular copy. @memcpy is fine here: both ends are page-aligned at the
    // start, and with FP/NEON subtracted from this target the compiler cannot
    // widen it into the unaligned 16-byte Device accesses that fault MMU-off.
    @memcpy(pages[0..src.len], src);
    return .{ .phys = @intFromPtr(pages.ptr), .len = src.len };
}

/// Mirror of `bootloader/main.zig:26-70`.
///
/// Returns 0 today, exactly as the UEFI path does — `computeKaslrSlide` there
/// discards `slide_pages` and returns 0, so KASLR is inert tree-wide. The
/// structure is kept rather than hardcoding 0 so that whenever that changes, the
/// bare-metal path picks it up instead of silently staying unrandomised. The
/// window checks are real and worth keeping regardless: they are what turns "the
/// kernel outgrew the KASLR window" from a Debug-mode integer-overflow panic into
/// a diagnosable message.
fn computeKaslrSlide(pe: *const ParsedElf) u64 {
    const link_base = kernel_code.start;
    const window = kernel_code.end - link_base;

    var image_end: u64 = 0;
    const num_sections = @intFromEnum(ElfSection.num_sections);
    for (0..num_sections) |i| {
        const end = pe.sections[i].vaddr + pe.sections[i].size;
        if (end > image_end) image_end = end;
    }

    if (image_end <= link_base) {
        log.str("    *** highest section is below the kernel_code base; slide=0\n");
        return 0;
    }
    const image_size = std.mem.alignForward(u64, image_end - link_base, paging.PAGE4K);
    if (image_size >= window) {
        log.str("    *** kernel does not fit the KASLR window; slide=0\n");
        return 0;
    }
    return 0;
}

/// Parse the embedded kernel ELF, copy it into the arena, and map every section
/// into `ttbr1_root`.
///
/// `ttbr1_root` is the PHYSICAL address of the kernel table root. With the MMU off
/// that doubles as its virtual address, which is the identity case mapPageBoot
/// already handles (`use_physmap` false, since a physical address is never inside
/// the physmap partition).
pub fn loadKernel(
    alloc: std.mem.Allocator,
    ttbr1_root: u64,
    blob: []const u8,
) !LoadedKernel {
    // The ELF copy must be mutable and physmap-reachable; see the module comment.
    const elf_copy = try copyIntoArena(alloc, blob);
    const bytes: []u8 = @as([*]u8, @ptrFromInt(@as(usize, @intCast(elf_copy.phys))))[0..elf_copy.len];

    try elf.parseElf(&parsed, bytes);

    const slide = computeKaslrSlide(&parsed);
    // Relocations are a no-op while the slide is 0, and applying them would write
    // through `bytes` — which is why the copy above had to be mutable.
    if (slide != 0) return error.KaslrNotSupportedYet;

    log.str("    e_type = ");
    log.hex(parsed.e_type);
    log.str(", entry = ");
    log.hex(parsed.entry.addr);
    log.str(", slide = ");
    log.hex(slide);
    log.byte('\n');

    var va_low: u64 = ~@as(u64, 0);
    var va_high: u64 = 0;
    var pages_mapped: u64 = 0;

    const num_sections = @intFromEnum(ElfSection.num_sections);
    for (0..num_sections) |i| {
        const section_idx: ElfSection = @enumFromInt(i);
        const perms: MemoryPerms = switch (section_idx) {
            .text => .{ .read = true, .exec = true },
            .rodata => .{ .read = true },
            .data, .bss => .{ .read = true, .write = true },
            else => unreachable,
        };

        const section = parsed.sections[i];
        if (section.size == 0) continue;

        const start_vaddr = section.vaddr + slide;
        const end_vaddr = section.vaddr + section.size + slide;
        var current_vaddr = start_vaddr;
        var file_offset = section.offset;

        while (current_vaddr < end_vaddr) {
            const page = alloc.alignedAlloc(u8, paging.pageAlign(.page4k), paging.PAGE4K) catch
                return Error.OutOfArena;

            if (section_idx == .bss) {
                // .bss has no file bytes. The arena already zeroes on allocation,
                // but be explicit: this is the one section whose correctness
                // depends on zeroing, and DRAM here survives resets.
                @memset(page, 0);
            } else {
                // Clamp to the blob. The last page of a section is usually
                // partial, and `file_bytes[off..off+PAGE4K]` would run past the
                // end — the UEFI path gets away with it because its file buffer is
                // a whole number of pages, which an @embedFile is not.
                const remaining = if (file_offset < bytes.len) bytes.len - file_offset else 0;
                const n = @min(paging.PAGE4K, remaining);
                if (n != 0) @memcpy(page[0..n], bytes[file_offset..][0..n]);
                if (n < paging.PAGE4K) @memset(page[n..], 0);
                file_offset += n;
            }

            // Clean this page to the point of coherency before it can be fetched
            // as instructions. Same reason as main.zig:325-335: the bytes we just
            // wrote may sit in the D-cache while the I-cache fill goes to RAM.
            arch.cpu.cleanInvalidateDcacheRange(@intFromPtr(page.ptr), paging.PAGE4K);

            try arch.paging.mapPageBoot(
                VAddr.fromInt(ttbr1_root),
                PAddr.fromInt(@intFromPtr(page.ptr)),
                VAddr.fromInt(current_vaddr),
                .page4k,
                perms,
                .kernel_data,
                alloc,
            );

            if (current_vaddr < va_low) va_low = current_vaddr;
            if (current_vaddr + paging.PAGE4K > va_high) va_high = current_vaddr + paging.PAGE4K;
            pages_mapped += 1;
            current_vaddr += paging.PAGE4K;
        }
    }

    if (pages_mapped == 0) return Error.NoSections;
    arch.cpu.syncInstructionCache();

    return .{
        .elf = elf_copy,
        .entry = VAddr.fromInt(parsed.entry.addr + slide),
        .kaslr_slide = slide,
        .va_low = va_low,
        .va_high = va_high,
        .pages_mapped = pages_mapped,
    };
}

pub fn dump(k: *const LoadedKernel) void {
    log.str("    mapped ");
    log.dec(k.pages_mapped);
    log.str(" pages, ");
    log.hex(k.va_low);
    log.str(" .. ");
    log.hex(k.va_high);
    log.str("  ");
    log.size(k.va_high - k.va_low);
    log.byte('\n');
    log.str("    elf copy at ");
    log.hex(k.elf.phys);
    log.str("  ");
    log.size(k.elf.len);
    log.byte('\n');
    // The kernel is linked for this partition; landing outside it means every
    // absolute address in the image is wrong, which is worth catching here rather
    // than as a translation fault after the MMU comes on.
    if (k.va_low < kernel_code.start or k.va_high > kernel_code.end) {
        log.str("    *** image lies outside the kernel_code partition ");
        log.hex(kernel_code.start);
        log.str(" .. ");
        log.hex(kernel_code.end);
        log.byte('\n');
    }
}
