const std = @import("std");
const stygia = @import("stygia");

const elf = std.elf;
const paging = stygia.memory.paging;

const Dwarf = std.debug.Dwarf;
const VAddr = stygia.memory.address.VAddr;

pub const ElfSection = enum {
    text,
    rodata,
    data,
    bss,
    num_sections,
};

pub const Section = struct {
    vaddr: u64,
    size: u64,
    offset: u64,
};

pub const ParsedElf = struct {
    bytes: []u8,
    entry: VAddr,
    /// ELF `e_type` field (ET_DYN, ET_EXEC, etc.). Spec
    /// §[create_capability_domain] requires PIE images (ET_DYN).
    e_type: u16,
    sections: [@intFromEnum(ElfSection.num_sections)]Section,
    dwarf: Dwarf,
};

pub fn parseElf(result: *ParsedElf, bytes: []u8) !void {
    result.bytes = bytes;

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    // Spec §[create_capability_domain]: a malformed ELF (zero-sized
    // page frame, truncated file, missing magic) must surface as
    // E_INVAL at the syscall boundary. parseElf is the entry point
    // most likely to be reached with attacker-controlled bytes —
    // abort before reading past the buffer to keep it from panicking
    // the kernel for any test that hands it a degenerate page frame.
    if (bytes.len < hdr_sz) return error.InvalidElfMagic;
    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    result.entry = VAddr.fromInt(elf_hdr.entry);
    result.e_type = @intFromEnum(elf_hdr.type);
    result.dwarf = .{
        .endian = elf_hdr.endian,
        .is_macho = false,
    };

    // Bounds-check the program header table before iteration. The
    // stdlib iterator slices `bytes[phoff + i*phentsize..]` without
    // validating against `bytes.len`, so a malformed phoff/phnum would
    // panic the kernel inside the slice op. Mirror the shoff guard at
    // the section-header table below; use overflow-safe arithmetic
    // because phoff is u64 and phentsize*phnum is attacker-controlled.
    const phtbl_size_mul = @mulWithOverflow(@as(u64, elf_hdr.phentsize), @as(u64, elf_hdr.phnum));
    if (phtbl_size_mul[1] != 0) return error.InvalidElfMagic;
    const phtbl_end = @addWithOverflow(elf_hdr.phoff, phtbl_size_mul[0]);
    if (phtbl_end[1] != 0 or phtbl_end[0] > bytes.len) return error.InvalidElfMagic;

    var phdr_itr = elf_hdr.iterateProgramHeadersBuffer(bytes);

    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != elf.PT_LOAD) continue;
        // Validate the segment file extent against `bytes.len`. The
        // resulting Section is consumed by capability_domain's segment-
        // copy loop and boot.userspace_init's ELF mapper, both of which
        // slice `bytes[offset .. offset + size]` directly; an unchecked
        // p_offset/p_filesz from a hostile phdr would slice past the
        // buffer. p_filesz == 0 is legal (e.g. pure-bss segments).
        const seg_end = @addWithOverflow(phdr.p_offset, phdr.p_filesz);
        if (seg_end[1] != 0 or seg_end[0] > bytes.len) return error.InvalidElfMagic;

        const writable = (phdr.p_flags & elf.PF_W) != 0;
        const executable = (phdr.p_flags & elf.PF_X) != 0;
        if (!writable and executable) {
            result.sections[@intFromEnum(ElfSection.text)] = .{
                .vaddr = phdr.p_vaddr,
                .size = phdr.p_filesz,
                .offset = phdr.p_offset,
            };
        } else if (!writable and !executable) {
            result.sections[@intFromEnum(ElfSection.rodata)] = .{
                .vaddr = phdr.p_vaddr,
                .size = phdr.p_filesz,
                .offset = phdr.p_offset,
            };
        } else if (writable and !executable) {
            // bss derivation needs three guards beyond seg_end above:
            //   1. p_vaddr + p_filesz overflow before alignForward.
            //   2. alignForward overflow on the (vaddr + filesz) sum.
            //   3. p_memsz >= p_filesz, otherwise the size subtraction
            //      underflows into a multi-EB Section.
            const bss_vaddr_raw = @addWithOverflow(phdr.p_vaddr, phdr.p_filesz);
            if (bss_vaddr_raw[1] != 0) return error.InvalidElfMagic;
            const align_mask = paging.PAGE4K - 1;
            const bss_align_raw = @addWithOverflow(bss_vaddr_raw[0], align_mask);
            if (bss_align_raw[1] != 0) return error.InvalidElfMagic;
            if (phdr.p_memsz < phdr.p_filesz) return error.InvalidElfMagic;

            result.sections[@intFromEnum(ElfSection.data)] = .{
                .vaddr = phdr.p_vaddr,
                .size = phdr.p_filesz,
                .offset = phdr.p_offset,
            };
            result.sections[@intFromEnum(ElfSection.bss)] = .{
                .vaddr = std.mem.alignForward(
                    u64,
                    bss_vaddr_raw[0],
                    paging.PAGE4K,
                ),
                .size = phdr.p_memsz - phdr.p_filesz,
                .offset = 0,
            };
        }
    }

    // Section headers are optional per the ELF spec — a runtime image
    // with no debug info / no symbol table can legitimately have
    // e_shnum=0 and e_shoff=0. The DWARF walk below only adds debug
    // info, never anything load-bearing for execution, so a section-
    // table-less ELF is fine; bail out before touching the table.
    if (elf_hdr.shnum == 0) return;

    var shdr_itr = elf_hdr.iterateSectionHeadersBuffer(bytes);

    // Bounds-check the section header table before slicing. A truncated
    // ELF (e.g. user-staged page frame whose size doesn't cover shoff)
    // would otherwise panic the kernel inside `bytes[shoff..end]`.
    const shtbl_size = @as(u64, elf_hdr.shentsize) * @as(u64, elf_hdr.shnum);
    if (elf_hdr.shoff + shtbl_size > bytes.len) return error.InvalidElfMagic;

    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        bytes[elf_hdr.shoff .. elf_hdr.shoff + elf_hdr.shentsize * elf_hdr.shnum],
    );

    if (elf_hdr.shstrndx >= shdrs.len) return error.InvalidElfMagic;
    const shstr_shdr = shdrs[elf_hdr.shstrndx];
    const shstr_end = shstr_shdr.sh_offset + shstr_shdr.sh_size;
    if (shstr_end > bytes.len) return error.InvalidElfMagic;
    const shstr = bytes[shstr_shdr.sh_offset..shstr_end];

    while (try shdr_itr.next()) |shdr| {
        const name = getCStrAt(shstr, @intCast(shdr.sh_name)) orelse "<bad name>";

        const dwarf_idx = blk: {
            if (std.mem.eql(u8, name, ".debug_info")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_info);
            } else if (std.mem.eql(u8, name, ".debug_abbrev")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_abbrev);
            } else if (std.mem.eql(u8, name, ".debug_str")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_str);
            } else if (std.mem.eql(u8, name, ".debug_str_offsets")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_str_offsets);
            } else if (std.mem.eql(u8, name, ".debug_line")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_line);
            } else if (std.mem.eql(u8, name, ".debug_line_str")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_line_str);
            } else if (std.mem.eql(u8, name, ".debug_ranges")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_ranges);
            } else if (std.mem.eql(u8, name, ".debug_loclists")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_loclists);
            } else if (std.mem.eql(u8, name, ".debug_rnglists")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_rnglists);
            } else if (std.mem.eql(u8, name, ".debug_addr")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_addr);
            } else if (std.mem.eql(u8, name, ".debug_names")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_names);
            } else if (std.mem.eql(u8, name, ".eh_frame")) {
                break :blk @intFromEnum(Dwarf.Section.Id.eh_frame);
            } else if (std.mem.eql(u8, name, ".eh_frame_hdr")) {
                break :blk @intFromEnum(Dwarf.Section.Id.eh_frame_hdr);
            } else {
                break :blk null;
            }
        };
        if (dwarf_idx) |i| {
            // Bounds-check the DWARF section against `bytes.len` per
            // shdr. shstrndx is already validated above, but every
            // other shdr offset comes straight from the (potentially
            // malformed) section table; an unchecked sh_offset/sh_size
            // would panic the kernel in the slice op below.
            const sec_end = @addWithOverflow(shdr.sh_offset, shdr.sh_size);
            if (sec_end[1] != 0 or sec_end[0] > bytes.len) return error.InvalidElfMagic;
            result.dwarf.sections[i] = .{
                .data = bytes[shdr.sh_offset..sec_end[0]],
                .owned = false,
            };
        }
    }
}

fn getCStrAt(bytes: []const u8, offset: u64) ?[]const u8 {
    if (offset >= bytes.len) return null;
    const tail = bytes[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}
