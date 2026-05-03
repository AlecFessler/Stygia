// libz_loader: minimal userspace runtime linker bits for the libz_c
// shared library.
//
// Two surfaces, used at very different times:
//
//   * Runner-side (`computeImageSize`, `layoutAndPrelink`): the test
//     runner statically links libz, embeds libz_c.elf as a build-time
//     blob, and at startup measures + lays out the libz_c PT_LOADs
//     into one writable page_frame, then applies R_*_RELATIVE relocs
//     against `LIBZ_SLIDE`. The result is a position-frozen image: any
//     child can mapPf the pf at exactly `LIBZ_SLIDE` and the image's
//     internal pointers (GOT, data.rel.ro slots, vtables) already
//     point at the right runtime addresses.
//
//   * Child-side (`relocateSelf`): each spawned test ELF wakes up at
//     its own kernel-applied slide with `R_*_GLOB_DAT` and
//     `R_*_JUMP_SLOT` slots that still reference unresolved libz_c
//     symbols (the kernel ELF loader silently skips non-RELATIVE
//     reloc types — see kernel/boot/userspace_init.zig). After the
//     child's `_start` maps the libz pf at `LIBZ_SLIDE`, it calls
//     `relocateSelf`, which walks its own .rela.dyn / .rela.plt and
//     patches each missing slot with `LIBZ_SLIDE + libz_sym.st_value`
//     looked up by name in the libz image's .dynsym / .dynstr.
//
// Both surfaces are pure ELF-walking — no syscalls, no allocations.
// The runner-side functions consume libz_c.elf as `[]const u8`; the
// child-side function operates entirely on already-mapped runtime
// addresses (its own ELF base + the libz image base).

const std = @import("std");
const builtin = @import("builtin");
const elf = std.elf;

// Constants shared between the libz_image builder (runner-side) and the
// libz_loader runtime hook (child-side).
//
// The runner stages libz_c.elf into a single page_frame at startup,
// applies its R_*_RELATIVE relocations against `LIBZ_SLIDE`, then hands
// that pf out to every spawned test domain. Each child mapPfs the pf
// at exactly `LIBZ_SLIDE` so the prelinked addresses inside the libz
// image (its own GOT, its data.rel.ro pointers, etc.) are valid at
// runtime without re-relocating per-child.
//
// The slot constant pins where the runner stages the libz pf in the
// child's installed cap-table view. The runner already passes:
//   slot 3 = result port handle    (SLOT_FIRST_PASSED + 0)
//   slot 4 = test ELF page_frame   (SLOT_FIRST_PASSED + 1, for tests
//                                    that need to re-spawn themselves)
// Add libz at slot 5 so existing tests that never look at slot 5 don't
// notice. The runner passes 3 handles in its passed_handles array; the
// child's _start reaches into slot 5 via a self-handle issuance to
// resolve the libz pf id.
// LIBZ_SLIDE pins where every dynamic libz consumer maps libz.elf in
// its own address space. Must be in the §[address_space] static zone
// (x86_64: [0x1000_0000_0000, 0x8000_0000_0000); aarch64 has the same
// lower bound). 0x7000_0000_0000 (112 TiB) is high in the static zone
// — well clear of common probe addresses spec tests reach for when
// they want a "deep-unmapped" sentinel (futex_wait_change_05 picks
// 0x4000_0000_0000 for exactly that reason). 1 MiB of libz fits with
// 16 TiB of static-zone headroom above; future tests probing high
// static-zone addresses should avoid 0x7000_0000_0000.
pub const LIBZ_SLIDE: u64 = 0x7000_0000_0000;
pub const LIBZ_PF_SLOT: u8 = 5;

const PAGE_SIZE: u64 = 0x1000;

const RELATIVE_TYPE: u32 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(elf.R_X86_64.RELATIVE),
    .aarch64 => @intFromEnum(elf.R_AARCH64.RELATIVE),
    else => @compileError("unsupported target arch for libz_loader"),
};

const GLOB_DAT_TYPE: u32 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(elf.R_X86_64.GLOB_DAT),
    .aarch64 => @intFromEnum(elf.R_AARCH64.GLOB_DAT),
    else => @compileError("unsupported target arch for libz_loader"),
};

const JUMP_SLOT_TYPE: u32 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(elf.R_X86_64.JUMP_SLOT),
    .aarch64 => @intFromEnum(elf.R_AARCH64.JUMP_SLOT),
    else => @compileError("unsupported target arch for libz_loader"),
};

// ---------------------------------------------------------------
// Runner side: layout + RELATIVE prelink.
// ---------------------------------------------------------------

/// Returns the page-aligned byte count needed to hold every PT_LOAD
/// segment of the supplied libz_c.elf image, where segment i sits at
/// `image[phdr.p_vaddr .. phdr.p_vaddr + phdr.p_memsz]`. Used to size
/// the pf the runner allocates for libz.
pub fn computeImageSize(libz_bytes: []const u8) u64 {
    const ehdr: *const elf.Elf64_Ehdr = @ptrCast(@alignCast(libz_bytes.ptr));
    var max_end: u64 = 0;
    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const off = ehdr.e_phoff + @as(u64, pi) * ehdr.e_phentsize;
        const phdr: *const elf.Elf64_Phdr = @ptrCast(@alignCast(libz_bytes.ptr + off));
        if (phdr.p_type != elf.PT_LOAD) continue;
        const end = phdr.p_vaddr + phdr.p_memsz;
        if (end > max_end) max_end = end;
    }
    return (max_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/// Lay out libz_bytes' PT_LOADs into `image_writable` at
/// `image_writable[phdr.p_vaddr ..]`, then apply every R_*_RELATIVE
/// relocation listed in the .rela.dyn section against the laid-out
/// image. The relocation target's runtime address is treated as
/// `image_runtime_base + r_offset`; the patched value is
/// `r_addend + image_runtime_base`.
///
/// `image_writable.len` must be at least `computeImageSize(libz_bytes)`.
/// `image_runtime_base` is the VA at which children will mapPf this
/// image (i.e. `LIBZ_SLIDE`).
pub fn layoutAndPrelink(
    libz_bytes: []const u8,
    image_writable: []u8,
    image_runtime_base: u64,
) void {
    const ehdr: *const elf.Elf64_Ehdr = @ptrCast(@alignCast(libz_bytes.ptr));

    // Phase 1: copy each PT_LOAD's filesz from elf bytes into image at
    // p_vaddr; zero the trailing memsz-filesz (BSS).
    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const phoff = ehdr.e_phoff + @as(u64, pi) * ehdr.e_phentsize;
        const phdr: *const elf.Elf64_Phdr = @ptrCast(@alignCast(libz_bytes.ptr + phoff));
        if (phdr.p_type != elf.PT_LOAD) continue;
        const dst_off = phdr.p_vaddr;
        const fsz = phdr.p_filesz;
        const msz = phdr.p_memsz;
        const src = libz_bytes[phdr.p_offset .. phdr.p_offset + fsz];
        @memcpy(image_writable[dst_off .. dst_off + fsz], src);
        if (msz > fsz) {
            @memset(image_writable[dst_off + fsz .. dst_off + msz], 0);
        }
    }

    // Phase 2: walk SHT_RELA sections and apply R_*_RELATIVE.
    // libz_c.elf has its full section header table available because
    // it's emitted with debug info / not stripped — same shape the
    // kernel ELF loader (kernel/boot/userspace_init.zig) relies on.
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;
    const shdr_total = @as(u64, ehdr.e_shnum) * ehdr.e_shentsize;
    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        libz_bytes[ehdr.e_shoff .. ehdr.e_shoff + shdr_total],
    );
    for (shdrs) |shdr| {
        if (shdr.sh_type != elf.SHT_RELA) continue;
        const ne = shdr.sh_size / @sizeOf(elf.Elf64_Rela);
        const rela_total = ne * @sizeOf(elf.Elf64_Rela);
        const relas = std.mem.bytesAsSlice(
            elf.Elf64_Rela,
            libz_bytes[shdr.sh_offset .. shdr.sh_offset + rela_total],
        );
        for (relas) |r| {
            const rtype: u32 = @truncate(r.r_info);
            if (rtype != RELATIVE_TYPE) continue;
            const slot: *align(1) u64 = @ptrCast(@alignCast(image_writable.ptr + r.r_offset));
            slot.* = @as(u64, @bitCast(r.r_addend)) +% image_runtime_base;
        }
    }
}

// ---------------------------------------------------------------
// Child side: walk PT_DYNAMIC, look up libz symbols, patch own
// GLOB_DAT / JUMP_SLOT slots.
// ---------------------------------------------------------------

const Dynamic = struct {
    /// Runtime address of .dynsym (image_base + DT_SYMTAB).
    sym_ptr: [*]const elf.Elf64_Sym = undefined,
    sym_count: usize = 0,

    /// Runtime address of .dynstr (image_base + DT_STRTAB), with size.
    str_ptr: [*]const u8 = undefined,
    str_sz: usize = 0,

    /// Runtime address + byte length of .rela.dyn (DT_RELA / DT_RELASZ).
    rela_ptr: ?[*]const elf.Elf64_Rela = null,
    rela_count: usize = 0,

    /// Runtime address + byte length of .rela.plt (DT_JMPREL /
    /// DT_PLTRELSZ). DT_PLTRELSZ is in *bytes*, not entries.
    plt_ptr: ?[*]const elf.Elf64_Rela = null,
    plt_count: usize = 0,
};

/// Walk PT_DYNAMIC starting from the runtime ELF base and resolve the
/// dynsym / dynstr / rela / rela.plt windows. The image must already
/// be in the running address space (kernel-loaded for the child's own
/// ELF; mapPf'd for the libz image).
fn parseDynamic(image_base: u64) ?Dynamic {
    const ehdr: *const elf.Elf64_Ehdr = @ptrFromInt(image_base);
    var dyn_vaddr: u64 = 0;
    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const phoff = ehdr.e_phoff + @as(u64, pi) * ehdr.e_phentsize;
        const phdr: *const elf.Elf64_Phdr = @ptrFromInt(image_base + phoff);
        if (phdr.p_type == elf.PT_DYNAMIC) {
            dyn_vaddr = phdr.p_vaddr;
            break;
        }
    }
    if (dyn_vaddr == 0) return null;

    var sym_addr: u64 = 0;
    var str_addr: u64 = 0;
    var str_sz: u64 = 0;
    var rela_addr: u64 = 0;
    var rela_sz: u64 = 0;
    var plt_addr: u64 = 0;
    var plt_sz: u64 = 0;
    var hash_addr: u64 = 0;
    var gnu_hash_addr: u64 = 0;

    var i: usize = 0;
    while (true) : (i += 1) {
        const dyn: *const elf.Elf64_Dyn =
            @ptrFromInt(image_base + dyn_vaddr + i * @sizeOf(elf.Elf64_Dyn));
        const tag: i64 = dyn.d_tag;
        if (tag == elf.DT_NULL) break;
        switch (tag) {
            elf.DT_SYMTAB => sym_addr = dyn.d_val,
            elf.DT_STRTAB => str_addr = dyn.d_val,
            elf.DT_STRSZ => str_sz = dyn.d_val,
            elf.DT_RELA => rela_addr = dyn.d_val,
            elf.DT_RELASZ => rela_sz = dyn.d_val,
            elf.DT_JMPREL => plt_addr = dyn.d_val,
            elf.DT_PLTRELSZ => plt_sz = dyn.d_val,
            elf.DT_HASH => hash_addr = dyn.d_val,
            elf.DT_GNU_HASH => gnu_hash_addr = dyn.d_val,
            else => {},
        }
    }

    if (sym_addr == 0 or str_addr == 0) return null;

    // The DT_SYMTAB tag carries the runtime VA of the .dynsym table
    // but no count. SysV DT_HASH starts with `nbuckets`, `nchain`,
    // where `nchain` equals the dynsym entry count; we use it when
    // available because it's the only spec-clean way to bound the
    // table without parsing section headers (which the libz image's
    // ehdr still has, but the running test ELF's may have been
    // stripped). libz_c.elf currently emits both DT_HASH and
    // DT_GNU_HASH; either suffices.
    var sym_count: u64 = 0;
    if (hash_addr != 0) {
        const hdr: *const [2]u32 = @ptrFromInt(image_base + hash_addr);
        sym_count = hdr[1];
    } else if (gnu_hash_addr != 0) {
        // GNU hash header: nbuckets, symoffset, bloom_size, bloom_shift.
        const ghdr: *const [4]u32 = @ptrFromInt(image_base + gnu_hash_addr);
        const nbuckets = ghdr[0];
        const symoffset = ghdr[1];
        const bloom_size = ghdr[2];
        const buckets_off = 16 + bloom_size * @sizeOf(u64);
        const buckets: [*]const u32 = @ptrFromInt(image_base + gnu_hash_addr + buckets_off);
        var max_sym: u32 = symoffset;
        var b: u32 = 0;
        while (b < nbuckets) : (b += 1) {
            if (buckets[b] > max_sym) max_sym = buckets[b];
        }
        // Walk chain from max_sym until terminator (low bit set).
        const chain_off = buckets_off + nbuckets * @sizeOf(u32);
        const chain: [*]const u32 = @ptrFromInt(image_base + gnu_hash_addr + chain_off);
        if (max_sym >= symoffset) {
            var c: u32 = max_sym;
            while ((chain[c - symoffset] & 1) == 0) : (c += 1) {}
            sym_count = c + 1;
        } else {
            sym_count = symoffset;
        }
    }

    return Dynamic{
        .sym_ptr = @ptrFromInt(image_base + sym_addr),
        .sym_count = sym_count,
        .str_ptr = @ptrFromInt(image_base + str_addr),
        .str_sz = str_sz,
        .rela_ptr = if (rela_addr != 0)
            @ptrFromInt(image_base + rela_addr)
        else
            null,
        .rela_count = rela_sz / @sizeOf(elf.Elf64_Rela),
        .plt_ptr = if (plt_addr != 0)
            @ptrFromInt(image_base + plt_addr)
        else
            null,
        .plt_count = plt_sz / @sizeOf(elf.Elf64_Rela),
    };
}

fn cstrEql(p: [*]const u8, max: usize, name: []const u8) bool {
    if (name.len + 1 > max) return false;
    var i: usize = 0;
    while (i < name.len) : (i += 1) {
        if (p[i] != name[i]) return false;
    }
    return p[name.len] == 0;
}

/// Linear scan of `lib.sym_ptr[0 .. lib.sym_count]` for an exported
/// symbol named `name`. Returns the symbol's runtime address (i.e.
/// `image_runtime_base + sym.st_value`) or null if not found / hidden
/// / undefined.
///
/// libz_c.elf has ~88 dynamic symbols and each test ELF triggers ~30
/// lookups, so the linear scan is fine in practice. Adding a hash
/// lookup would buy us ~10× on the constant factor but doesn't change
/// the order of the runner's per-spawn cost (kernel-side
/// createCapabilityDomain dwarfs it).
fn lookupSymbol(lib: Dynamic, image_runtime_base: u64, name: []const u8) ?u64 {
    var i: usize = 1; // index 0 is the reserved STN_UNDEF entry
    while (i < lib.sym_count) : (i += 1) {
        const sym = lib.sym_ptr[i];
        if (sym.st_shndx == 0) continue; // undefined
        if (sym.st_value == 0 and sym.st_size == 0) continue;
        if (sym.st_name >= lib.str_sz) continue;
        const cname: [*]const u8 = lib.str_ptr + sym.st_name;
        if (!cstrEql(cname, lib.str_sz - sym.st_name, name)) continue;
        return image_runtime_base + sym.st_value;
    }
    return null;
}

/// Patch every R_*_GLOB_DAT and R_*_JUMP_SLOT relocation in this ELF's
/// own .rela.dyn / .rela.plt against the libz_c image already mapped
/// at `libz_runtime_base` (= LIBZ_SLIDE). `self_runtime_base` is this
/// ELF's runtime base — i.e. `&__ehdr_start`.
///
/// Returns the number of slots successfully patched. A return less
/// than the expected count means at least one libz symbol was missing
/// from the staged image, which is a build-time mismatch between the
/// ELF and the libz_c.elf shipped in the runner.
pub fn relocateSelf(self_runtime_base: u64, libz_runtime_base: u64) usize {
    const lib = parseDynamic(libz_runtime_base) orelse return 0;
    const me = parseDynamic(self_runtime_base) orelse return 0;

    var patched: usize = 0;

    // Walk this ELF's .dynsym to map its symbol-index → name. Each
    // GLOB_DAT/JUMP_SLOT relocation references a symbol by its index
    // in *our own* dynsym, whose name string we resolve against our
    // own dynstr, and then look up in the libz image.
    if (me.rela_ptr) |rp| {
        var i: usize = 0;
        while (i < me.rela_count) : (i += 1) {
            const r = rp[i];
            const rtype: u32 = @truncate(r.r_info);
            if (rtype != GLOB_DAT_TYPE) continue;
            const sym_idx: u32 = @truncate(r.r_info >> 32);
            if (sym_idx >= me.sym_count) continue;
            const sym = me.sym_ptr[sym_idx];
            if (sym.st_name >= me.str_sz) continue;
            const cname: [*]const u8 = me.str_ptr + sym.st_name;
            const name = sliceFromCstr(cname, me.str_sz - sym.st_name);
            const target_va = lookupSymbol(lib, libz_runtime_base, name) orelse continue;
            const slot: *align(1) u64 = @ptrFromInt(self_runtime_base + r.r_offset);
            slot.* = target_va +% @as(u64, @bitCast(r.r_addend));
            patched += 1;
        }
    }

    if (me.plt_ptr) |pp| {
        var i: usize = 0;
        while (i < me.plt_count) : (i += 1) {
            const r = pp[i];
            const rtype: u32 = @truncate(r.r_info);
            if (rtype != JUMP_SLOT_TYPE) continue;
            const sym_idx: u32 = @truncate(r.r_info >> 32);
            if (sym_idx >= me.sym_count) continue;
            const sym = me.sym_ptr[sym_idx];
            if (sym.st_name >= me.str_sz) continue;
            const cname: [*]const u8 = me.str_ptr + sym.st_name;
            const name = sliceFromCstr(cname, me.str_sz - sym.st_name);
            const target_va = lookupSymbol(lib, libz_runtime_base, name) orelse continue;
            const slot: *align(1) u64 = @ptrFromInt(self_runtime_base + r.r_offset);
            slot.* = target_va +% @as(u64, @bitCast(r.r_addend));
            patched += 1;
        }
    }

    return patched;
}

fn sliceFromCstr(p: [*]const u8, max: usize) []const u8 {
    var n: usize = 0;
    while (n < max and p[n] != 0) : (n += 1) {}
    return p[0..n];
}
