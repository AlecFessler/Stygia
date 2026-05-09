const builtin = @import("builtin");
const el2_drop = @import("aarch64_el2_drop.zig");
const fs_mod = @import("fs.zig");
const page_allocator = @import("page_allocator.zig");
const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const address = stygia.memory.address;
const boot_protocol = stygia.boot.protocol;
const elf = stygia.utils.elf;
const paging = stygia.memory.paging;
const std_elf = std.elf;
const uefi = std.os.uefi;

const BootInfo = boot_protocol.BootInfo;
const ElfSection = elf.ElfSection;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const PageAllocator = page_allocator.PageAllocator;
const ParsedElf = stygia.utils.elf.ParsedElf;
const VAddr = stygia.memory.address.VAddr;

const KEntryType = fn (*BootInfo) callconv(stygia.arch.dispatch.cpu.cc()) noreturn;

fn computeKaslrSlide(parsed_elf: *const ParsedElf) u64 {
    const link_base = address.AddrSpacePartition.kernel_code.start;
    const kaslr_end = address.AddrSpacePartition.kernel_code.end;

    var image_end: u64 = 0;
    const num_sections = @intFromEnum(ElfSection.num_sections);
    for (0..num_sections) |i| {
        const section = parsed_elf.sections[i];
        const section_end = section.vaddr + section.size;
        if (section_end > image_end) image_end = section_end;
    }
    const image_size = std.mem.alignForward(u64, image_end - link_base, paging.PAGE4K);
    const max_slide = kaslr_end - link_base - image_size;
    const slide_pages = max_slide / paging.PAGE4K;

    _ = slide_pages;
    _ = arch.time.readTimestamp(true);
    return 0;
}

fn applyKaslrRelocations(file_bytes: []u8, slide: u64) !void {
    if (slide == 0) return;
    if (file_bytes.len < @sizeOf(std_elf.Elf64_Ehdr)) return error.InvalidElf;

    const ehdr = std.mem.bytesAsValue(
        std_elf.Elf64_Ehdr,
        file_bytes[0..@sizeOf(std_elf.Elf64_Ehdr)],
    );
    const shdr_size: u64 = ehdr.e_shentsize;
    const shdr_count: u64 = ehdr.e_shnum;

    if (ehdr.e_shoff == 0 or shdr_count == 0) return;
    if (shdr_size < @sizeOf(std_elf.Elf64_Shdr)) return;

    var s: u64 = 0;
    while (s < shdr_count) : (s += 1) {
        const off = ehdr.e_shoff + s * shdr_size;
        const shdr = std.mem.bytesAsValue(
            std_elf.Elf64_Shdr,
            file_bytes[off..][0..@sizeOf(std_elf.Elf64_Shdr)],
        );
        if (shdr.sh_type != std_elf.SHT_RELA) continue;

        const target_idx: u64 = shdr.sh_info;
        if (target_idx == 0 or target_idx >= shdr_count) continue;

        const target_off = ehdr.e_shoff + target_idx * shdr_size;
        const target_shdr = std.mem.bytesAsValue(
            std_elf.Elf64_Shdr,
            file_bytes[target_off..][0..@sizeOf(std_elf.Elf64_Shdr)],
        );

        if ((target_shdr.sh_flags & std_elf.SHF_ALLOC) == 0) continue;

        const target_base_addr = target_shdr.sh_addr;
        const target_base_file_offset = target_shdr.sh_offset;

        const entry_size: u64 = @sizeOf(std_elf.Elf64_Rela);
        const num_entries = shdr.sh_size / entry_size;

        var r: u64 = 0;
        while (r < num_entries) : (r += 1) {
            const rela_off = shdr.sh_offset + r * entry_size;
            const rela = std.mem.bytesAsValue(
                std_elf.Elf64_Rela,
                file_bytes[rela_off..][0..entry_size],
            );
            const rtype: u32 = @truncate(rela.r_info);

            if (rela.r_offset < target_base_addr) return error.InvalidElf;
            const file_off = target_base_file_offset + (rela.r_offset - target_base_addr);

            switch (arch.paging.classifyRelocation(rtype)) {
                .skip => continue,
                .abs64 => {
                    if (file_off + 8 > file_bytes.len) return error.InvalidElf;
                    const slot: *align(1) u64 = @ptrCast(file_bytes.ptr + file_off);
                    slot.* +%= slide;
                },
                .abs32 => {
                    if (file_off + 4 > file_bytes.len) return error.InvalidElf;
                    const slot: *align(1) i32 = @ptrCast(file_bytes.ptr + file_off);
                    const new_val: i64 = @as(i64, slot.*) +% @as(i64, @bitCast(slide));
                    slot.* = @truncate(new_val);
                },
                .unsupported => return error.InvalidElf,
            }
        }
    }
}

fn puts(msg: [*:0]const u16) void {
    if (uefi.system_table.con_out) |out| {
        _ = out.outputString(msg) catch {};
    }
}

const dbg = struct {
    const boot_start = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] boot start\r\n");
    const page_tables = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] page tables\r\n");
    const physmap = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] physmap\r\n");
    const loading = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] loading files\r\n");
    const kernel_elf = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] kernel.elf\r\n");
    const rs_elf = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] root_service\r\n");
    const elf_parsed = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] ELF parsed\r\n");
    const kaslr1 = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] KASLR slide\r\n");
    const kaslr2 = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] KASLR reloc\r\n");
    const sections = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] sections\r\n");
    const sections_done = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] mapped\r\n");
    const stack = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] stack\r\n");
    const exit_bs = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] exit BS\r\n");
    const jump = std.unicode.utf8ToUtf16LeStringLiteral("[STYGIA] jump\r\n");
};

pub fn main() uefi.Status {
    // On aarch64 + `-M virt,virtualization=on`, AAVMF hands off to us
    // at EL2. The bootloader (and kernel) are written against EL1
    // semantics. Drop to EL1 NOW so every subsequent TTBR/TCR/SCTLR
    // write lands on the active regime. `dropToEl1` mirrors the EL2
    // MMU state into the corresponding EL1 sysregs and ERETs back to
    // the same C frame via SP_EL1 so the drop is transparent.
    //
    // At this point we do NOT yet know the kernel's __hyp_vectors PA
    // (the ELF isn't loaded yet). `dropToEl1` therefore writes VBAR_EL2
    // to a temporary bootloader-owned stub — but that stub is allocated
    // in a fresh RuntimeServicesCode page (not linked into the
    // bootloader PE's .text) so its EL2 execute permission survives
    // ExitBootServices. The kernel later overwrites VBAR_EL2 via an
    // HVC that the stub honours; see aarch64_el2_drop.zig for the
    // vector layout and HVC imm dispatch.
    const boot_services: *uefi.tables.BootServices = uefi.system_table.boot_services orelse return .aborted;

    const arrived_at_el2: bool = blk: {
        if (builtin.cpu.arch != .aarch64) break :blk false;
        if (el2_drop.currentEl() != 2) break :blk false;
        const stub_pa = el2_drop.allocateHypVectorStub(boot_services) catch return .aborted;
        el2_drop.dropToEl1(stub_pa);
        break :blk true;
    };
    uefi.system_table.con_out.?.clearScreen() catch return .aborted;
    puts(dbg.boot_start);

    var page_alloc = PageAllocator.init(boot_services, .acpi_reclaim_memory);
    const page_alloc_iface = page_alloc.allocator();

    // Separate allocator for pages that must stay executable at EL2
    // after ExitBootServices. On aarch64 + AAVMF the firmware's EL2
    // page tables mark generic reclaim/loader-data pages as NX; kernel
    // `.text` pages we copy into those fault as IFSC=0xF permission
    // faults the moment an HVC from EL1 tries to fetch from them
    // (most notably `__hyp_vectors`). `runtime_services_code` memory
    // is preserved and remains executable at EL2 across the drop.
    var code_page_alloc = PageAllocator.init(boot_services, .runtime_services_code);
    const code_page_alloc_iface = code_page_alloc.allocator();

    puts(dbg.page_tables);

    // Copy or allocate the kernel page table root. On x86-64, the UEFI
    // identity-mapped CR3 covers both halves so we copy it and keep using it.
    // On aarch64 (split TTBR0/TTBR1) TTBR1 may be uninitialized — allocate a
    // fresh table, then setKernelAddrSpace programs TCR_EL1 + writes TTBR1.
    const kernel_table_root_phys: PAddr = blk: {
        const fresh = page_alloc_iface.alignedAlloc(
            u8,
            paging.pageAlign(.page4k),
            paging.PAGE4K,
        ) catch return .aborted;

        // On x86-64 (shared CR3): copy UEFI's identity-mapped table so the
        // bootloader keeps running from the same mappings.
        // On aarch64 (split TTBR0/TTBR1): start with a clean kernel table.
        if (arch.paging.kernel_shares_user_table) {
            const current = arch.paging.getKernelAddrSpaceRoot();
            const src = current.getPtr([*]u8);
            @memcpy(fresh, src[0..paging.PAGE4K]);
        } else {
            @memset(fresh, 0);
        }

        const phys = PAddr.fromInt(@intFromPtr(fresh.ptr));
        arch.paging.setKernelAddrSpace(phys);
        break :blk phys;
    };

    puts(dbg.physmap);
    const identity_mapping = 0;
    const new_addr_space_root_virt = VAddr.fromPAddr(kernel_table_root_phys, identity_mapping);

    const new_addr_space_root_virt_physmapped = VAddr.fromPAddr(kernel_table_root_phys, null);
    const addr_space_root_perms: MemoryPerms = .{ .read = true, .write = true };
    arch.paging.mapPageBoot(
        new_addr_space_root_virt,
        kernel_table_root_phys,
        new_addr_space_root_virt_physmapped,
        .page4k,
        addr_space_root_perms,
        .kernel_data,
        page_alloc_iface,
    ) catch return .aborted;

    puts(dbg.loading);
    const loaded_image = boot_services.handleProtocol(
        uefi.protocol.LoadedImage,
        uefi.handle,
    ) catch {
        return .aborted;
    } orelse return .aborted;

    const fs: *uefi.protocol.SimpleFileSystem = boot_services.handleProtocol(
        uefi.protocol.SimpleFileSystem,
        loaded_image.device_handle.?,
    ) catch {
        return .aborted;
    } orelse return .aborted;

    const root_dir: *uefi.protocol.File = fs.openVolume() catch return .aborted;
    const kernel_file = fs_mod.openFile(root_dir, "kernel.elf") catch return .aborted;
    const file_bytes = fs_mod.readFile(kernel_file, boot_services) catch return .aborted;
    puts(dbg.kernel_elf);

    const rs_file = fs_mod.openFile(root_dir, "root_service.elf") catch return .aborted;
    const rs_bytes = fs_mod.readFile(rs_file, boot_services) catch return .aborted;
    puts(dbg.rs_elf);

    const parsed_elf_mem = boot_services.allocatePool(.loader_data, @sizeOf(ParsedElf)) catch return .aborted;
    const parsed_elf: *ParsedElf = @ptrCast(parsed_elf_mem.ptr);
    elf.parseElf(parsed_elf, file_bytes) catch return .aborted;
    puts(dbg.elf_parsed);

    const kaslr_slide = computeKaslrSlide(parsed_elf);
    puts(dbg.kaslr1);
    applyKaslrRelocations(file_bytes, kaslr_slide) catch return .aborted;
    puts(dbg.kaslr2);
    puts(dbg.sections);

    const num_sections = @intFromEnum(ElfSection.num_sections);
    for (0..num_sections) |i| {
        const section_idx: ElfSection = @enumFromInt(i);
        const perms: MemoryPerms = switch (section_idx) {
            .text => .{ .read = true, .exec = true },
            .rodata => .{ .read = true },
            .data, .bss => .{ .read = true, .write = true },
            else => unreachable,
        };

        const section = parsed_elf.sections[i];
        const start_vaddr = section.vaddr + kaslr_slide;
        const end_vaddr = section.vaddr + section.size + kaslr_slide;
        var current_vaddr = start_vaddr;
        var file_offset = section.offset;
        while (current_vaddr < end_vaddr) {
            // Use RuntimeServicesCode memory for executable sections
            // so AAVMF's EL2 page tables keep them executable across
            // ExitBootServices. See the comment near `code_page_alloc`.
            const section_alloc = if (section_idx == .text)
                code_page_alloc_iface
            else
                page_alloc_iface;
            const page = section_alloc.alignedAlloc(
                u8,
                paging.pageAlign(.page4k),
                paging.PAGE4K,
            ) catch return .aborted;
            if (section_idx == .bss) {
                @memset(page, 0);
            } else {
                const bytes = file_bytes[file_offset .. file_offset + paging.PAGE4K];
                @memcpy(page, bytes);
                file_offset += paging.PAGE4K;
            }

            // Clean the D-cache over this freshly written page to the
            // point of coherency. Without this the kernel's first fetch
            // after the handoff can read stale data (the bytes we just
            // wrote may still be in the D-cache while the I-cache fill
            // goes to RAM). Linux arm64 does the same in head.S as
            // `dcache_clean_poc` over the loaded image. Pair this with
            // `syncInstructionCache` after the loop.
            arch.cpu.cleanInvalidateDcacheRange(
                @intFromPtr(page.ptr),
                paging.PAGE4K,
            );

            const page_phys = PAddr.fromInt(@intFromPtr(page.ptr));
            const page_virt = VAddr.fromInt(current_vaddr);

            arch.paging.mapPageBoot(
                new_addr_space_root_virt,
                page_phys,
                page_virt,
                .page4k,
                perms,
                .kernel_data,
                page_alloc_iface,
            ) catch return .aborted;

            current_vaddr += paging.PAGE4K;
        }
    }

    // Synchronize the instruction cache with the freshly copied kernel
    // code. On architectures with split I/D caches this is required
    // before branching into any newly written instructions — without
    // it the first fetch can decode stale cache bytes as garbage.
    arch.cpu.syncInstructionCache();

    puts(dbg.sections_done);
    const xsdp_addr = boot_protocol.findXSDP() catch return .aborted;
    const xsdp_phys = PAddr.fromInt(xsdp_addr);

    const gop = boot_services.locateProtocol(uefi.protocol.GraphicsOutput, null) catch null;
    const framebuffer: boot_protocol.Framebuffer = if (gop) |g| .{
        .base = PAddr.fromInt(g.mode.frame_buffer_base),
        .size = g.mode.frame_buffer_size,
        .width = g.mode.info.horizontal_resolution,
        .height = g.mode.info.vertical_resolution,
        .stride = g.mode.info.pixels_per_scan_line,
        .pixel_format = switch (g.mode.info.pixel_format) {
            .red_green_blue_reserved_8_bit_per_color => .rgb8,
            .blue_green_red_reserved_8_bit_per_color => .bgr8,
            .bit_mask => .bitmask,
            .blt_only => .blt_only,
        },
    } else .{
        .base = PAddr.fromInt(0),
        .size = 0,
        .width = 0,
        .height = 0,
        .stride = 0,
        .pixel_format = .none,
    };

    puts(dbg.stack);
    const stack_pages = page_alloc_iface.alignedAlloc(
        u8,
        paging.pageAlign(.page4k),
        boot_protocol.STACK_SIZE,
    ) catch return .aborted;

    const num_pages = boot_protocol.STACK_SIZE / paging.PAGE4K;
    var current_page_phys = PAddr.fromInt(@intFromPtr(stack_pages.ptr));
    for (0..num_pages) |_| {
        const current_page_virt = VAddr.fromPAddr(current_page_phys, null);
        const perms: MemoryPerms = .{ .read = true, .write = true };

        arch.paging.mapPageBoot(
            new_addr_space_root_virt,
            current_page_phys,
            current_page_virt,
            .page4k,
            perms,
            .kernel_data,
            page_alloc_iface,
        ) catch return .aborted;

        current_page_phys = PAddr.fromInt(current_page_phys.addr + paging.PAGE4K);
    }

    const stack_top_virt = VAddr.fromPAddr(current_page_phys, null);
    const boot_info_virt = VAddr.fromInt(stack_top_virt.addr - @sizeOf(BootInfo));
    const aligned_stack_top_virt = address.alignStack(boot_info_virt);
    const boot_info: *BootInfo = @ptrFromInt(boot_info_virt.addr);

    boot_info.elf_blob.ptr = parsed_elf.bytes.ptr;
    boot_info.elf_blob.len = parsed_elf.bytes.len;
    boot_info.root_service.ptr = rs_bytes.ptr;
    boot_info.root_service.len = rs_bytes.len;
    boot_info.xsdp_phys = xsdp_phys;
    boot_info.stack_top = aligned_stack_top_virt;
    boot_info.framebuffer = framebuffer;
    boot_info.kaslr_slide = kaslr_slide;
    boot_info.arrived_at_el2 = if (arrived_at_el2) 1 else 0;

    // Clean boot_info (and the surrounding stack page that holds it)
    // to the Point of Coherency. After the handoff the kernel reads
    // boot_info through a TTBR1 physmap VA with attr_indx=1, and any
    // stale cache line at this physical address — left over from
    // firmware activity that mapped the same page as Write-Back —
    // otherwise shadows the writes we just performed. Linux does the
    // same with `dcache_clean_poc` over the boot arguments in head.S.
    arch.cpu.cleanInvalidateDcacheRange(
        @intFromPtr(boot_info),
        @sizeOf(BootInfo),
    );

    puts(dbg.exit_bs);
    boot_info.mmap = boot_protocol.getMmap(boot_services) orelse return .aborted;
    boot_services.exitBootServices(
        uefi.handle,
        boot_info.mmap.key,
    ) catch {
        boot_info.mmap = boot_protocol.getMmap(boot_services) orelse return .aborted;
        boot_services.exitBootServices(
            uefi.handle,
            boot_info.mmap.key,
        ) catch return .aborted;
    };

    // Clean boot_info again after the mmap field has been populated.
    arch.cpu.cleanInvalidateDcacheRange(
        @intFromPtr(boot_info),
        @sizeOf(BootInfo),
    );

    // Final TLB flush after exitBootServices ensures all TTBR1 page table
    // entries are visible to the hardware walker before jumping to the kernel.
    arch.paging.setKernelAddrSpace(kernel_table_root_phys);

    // Switch SP to kernel stack before calling kEntry. After exitBootServices,
    // the UEFI stack (loader_data) may be reclaimed — writing to it would
    // fault on KVM where memory is real hardware.
    arch.cpu.switchStackAndCall(
        aligned_stack_top_virt,
        @intFromPtr(boot_info),
        parsed_elf.entry.addr + kaslr_slide,
    );
}
