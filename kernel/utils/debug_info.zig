const std = @import("std");
const stygia = @import("stygia");

const elf = stygia.utils.elf;

const PAddr = stygia.memory.address.PAddr;
const ParsedElf = stygia.utils.elf.ParsedElf;
const VAddr = stygia.memory.address.VAddr;

pub var global_ptr: ?*std.debug.Dwarf = null;
pub var kaslr_slide: u64 = 0;

/// Dedicated BSS region backing the dwarf parse.
///
/// `std.debug.Dwarf.open` builds per-section index structures whose
/// total footprint is proportional to the `.debug_*` section sizes in
/// the kernel ELF. We give it a `FixedBufferAllocator` over this
/// region so the dwarf parse has no runtime allocator dependency —
/// the kernel heap is gone.
///
/// Size is a tuned constant: dwarf indexes for the current Stygia kernel
/// fit comfortably under 2 MiB. If the kernel grows past the budget,
/// `Dwarf.open` returns OutOfMemory and `init()` returns without
/// setting `global_ptr`, degrading panic output to raw addresses
/// without taking down the boot.
const DEBUG_INFO_BSS_SIZE: usize = 2 * 1024 * 1024;
var debug_info_buffer: [DEBUG_INFO_BSS_SIZE]u8 align(16) = undefined;
var debug_info_fba: std.heap.FixedBufferAllocator = undefined;
var parsed_elf_storage: ParsedElf = undefined;

pub fn init(
    elf_phys_ptr: [*]u8,
    elf_len: u64,
    slide: u64,
) void {
    kaslr_slide = slide;
    // Direct-kernel boot doesn't load the kernel ELF into RAM as a
    // separately addressable blob (it's baked into the loaded image
    // itself). Skip parsing when the bootloader passes a zero-length
    // blob so debug_info stays uninitialised instead of walking a
    // bogus physmap pointer.
    if (elf_len == 0) return;

    debug_info_fba = std.heap.FixedBufferAllocator.init(&debug_info_buffer);
    const allocator = debug_info_fba.allocator();

    const elf_ptr_phys = PAddr.fromInt(@intFromPtr(elf_phys_ptr));
    const elf_ptr_virt = VAddr.fromPAddr(elf_ptr_phys, null);
    const elf_ptr: [*]u8 = @ptrFromInt(elf_ptr_virt.addr);
    const elf_bytes = elf_ptr[0..elf_len];
    elf.parseElf(&parsed_elf_storage, elf_bytes) catch return;
    parsed_elf_storage.dwarf.open(allocator) catch return;
    global_ptr = &parsed_elf_storage.dwarf;
}
