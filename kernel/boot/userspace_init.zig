const build_options = @import("build_options");
const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const capdom = zag.caps.capability_domain;
const elf_util = zag.utils.elf;
const execution_context = zag.sched.execution_context;
const paging_consts = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const EcCaps = zag.sched.execution_context.EcCaps;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PAddr = zag.memory.address.PAddr;
const ParsedElf = zag.utils.elf.ParsedElf;
const Priority = zag.sched.execution_context.Priority;
const VAddr = zag.memory.address.VAddr;

/// Cap word minted on the root capability domain's slot-0 self-handle.
/// Spec §[capability_domain] self-handle cap layout — every privilege the
/// root service is permitted to delegate downward must be set here.
const ROOT_SELF_CAPS = capdom.CapabilityDomainCaps{
    .crcd = true,
    .crec = true,
    .crvr = true,
    .crpf = true,
    .crvm = true,
    .crpt = true,
    .pmu = true,
    .setwall = true,
    .power = true,
    .restart = true,
    .reply_policy = true,
    .fut_wake = true,
    .timer = true,
    .pri = @intFromEnum(Priority.realtime),
};

/// Cap word minted on the root EC's slot-1 handle. Spec §[execution_context]
/// cap layout — full local-EC privileges so the root service can manage its
/// own thread.
const ROOT_EC_CAPS = EcCaps{
    .move = true,
    .copy = true,
    .saff = true,
    .spri = true,
    .term = true,
    .susp = true,
    .read = true,
    .write = true,
    .restart_policy = 1,
    .bind = true,
    .rebind = true,
    .unbind = true,
};

/// Pages reserved for the per-EC user stack created by
/// create_capability_domain. 16 pages (64 KiB) is the spec default
/// and the right size for nearly every userspace task. The in-Zag
/// self-hosted Zig compiler's recursive AstGen / Sema descent for
/// std-sized files needs more headroom — that's a per-process opt-in
/// (TODO: surface via a `create_capability_domain` argument or via
/// demand-paged stack growth) rather than a global bump that would
/// 64× every spawn's PMM footprint and starve the test runner past
/// ~rep 2 of an N=500 boot.
pub const USER_STACK_PAGES: u64 = 16;
pub const USER_STACK_BYTES: u64 = USER_STACK_PAGES * paging_consts.PAGE4K;

/// Bytes reserved for the read-only cap-table view mapped into a new
/// domain. MAX_HANDLES_PER_DOMAIN * sizeof(Capability) = 4096 * 24 =
/// 96 KiB, rounded up to the next page.
pub const ROOT_USER_TABLE_BYTES: u64 = 96 * 1024;

/// Resolved per-domain layout in the ASLR zone: where the ELF image
/// loads, where its user stack tops out, and where the read-only
/// cap-table view is mapped. All three live inside the ASLR zone (spec
/// §[address_space]) and are picked so they cannot overlap each other.
pub const DomainLayout = struct {
    elf_slide: u64,
    stack_top: u64,
    table_base: u64,
};

/// Compute the maximum `p_vaddr + p_memsz` across the ELF's PT_LOAD
/// segments. Used to size the slide-target window so segments stay
/// inside the ASLR zone after applying the slide.
fn elfImageSpan(elf_bytes: []const u8) !u64 {
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(elf_bytes[0..hdr_sz]);
    const hdr = try std.elf.Header.read(&rd);

    var max_end: u64 = 0;
    var phdr_itr = hdr.iterateProgramHeadersBuffer(@constCast(elf_bytes));
    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != std.elf.PT_LOAD) continue;
        // Spec §[create_capability_domain] [test 16]: any PT_LOAD that
        // declares more file bytes than the staged page frame can
        // supply (`p_offset + p_filesz > elf_bytes.len`) is an INVAL —
        // userspace lied about the staged image. Surface this here so
        // the syscall short-circuits with E_INVAL instead of trying to
        // copy past the end of the staged buffer in `loadElfSegments`.
        if (phdr.p_offset > elf_bytes.len) return error.ElfPhdrFileSizeExceeds;
        if (phdr.p_filesz > elf_bytes.len - phdr.p_offset) return error.ElfPhdrFileSizeExceeds;
        const end = std.mem.alignForward(u64, phdr.p_vaddr + phdr.p_memsz, paging_consts.PAGE4K);
        if (end > max_end) max_end = end;
    }
    return max_end;
}

/// Sample one 64-bit value of randomness for ASLR placement. Uses the
/// hardware RNG (RDRAND/RNDR) when available, with a TSC-mixed
/// fallback so back-to-back calls remain distinct under entropy
/// stalls.
fn aslrRandom() u64 {
    if (arch.cpu.getRandom()) |hw| return hw;
    const ts = arch.time.readTimestamp(false);
    aslr_fallback_counter +%= 1;
    return ts ^ (aslr_fallback_counter *% 0x9E3779B97F4A7C15);
}

var aslr_fallback_counter: u64 = 0;

/// Pick a page-aligned base inside `[lo, hi - bytes]` for a region of
/// `bytes` bytes. Returns null if the requested span doesn't fit.
fn pickAslrBase(lo: u64, hi: u64, bytes: u64) ?u64 {
    if (bytes == 0 or hi <= lo or bytes > hi - lo) return null;
    const max_base = hi - bytes;
    if (max_base < lo) return null;
    const span = max_base - lo + paging_consts.PAGE4K;
    const off = aslrRandom() % span;
    const candidate = lo + std.mem.alignBackward(u64, off, paging_consts.PAGE4K);
    if (candidate < lo or candidate > max_base) return null;
    return candidate;
}

/// Resolve a non-overlapping (elf, stack, table) layout in the ASLR
/// zone. Each region is picked uniformly within the zone; collisions
/// are retried up to RETRY_LIMIT times before falling back to a tiled
/// layout that places the regions adjacent to one another in zone
/// order. Spec §[address_space].
pub fn resolveDomainLayout(elf_bytes: []const u8) !DomainLayout {
    const aslr = arch.paging.user_aslr;
    const elf_span = try elfImageSpan(elf_bytes);
    if (elf_span == 0) return error.ElfHasNoLoadableSegments;

    const RETRY_LIMIT = 16;
    var attempt: u8 = 0;
    while (attempt < RETRY_LIMIT) {
        const elf_base = pickAslrBase(aslr.start, aslr.end, elf_span) orelse
            return error.OutOfMemory;
        const stack_base = pickAslrBase(aslr.start, aslr.end, USER_STACK_BYTES) orelse
            return error.OutOfMemory;
        const table_base = pickAslrBase(aslr.start, aslr.end, ROOT_USER_TABLE_BYTES) orelse
            return error.OutOfMemory;

        const elf_end = elf_base + elf_span;
        const stack_end = stack_base + USER_STACK_BYTES;
        const table_end = table_base + ROOT_USER_TABLE_BYTES;

        const overlap_es = elf_base < stack_end and stack_base < elf_end;
        const overlap_et = elf_base < table_end and table_base < elf_end;
        const overlap_st = stack_base < table_end and table_base < stack_end;
        if (!overlap_es and !overlap_et and !overlap_st) {
            return .{
                .elf_slide = elf_base,
                .stack_top = stack_end,
                .table_base = table_base,
            };
        }
        attempt += 1;
    }

    // Fallback: tile sequentially from a randomized origin so jitter
    // is preserved while collisions are impossible by construction.
    const total = elf_span + USER_STACK_BYTES + ROOT_USER_TABLE_BYTES;
    const origin = pickAslrBase(aslr.start, aslr.end, total) orelse
        return error.OutOfMemory;
    return .{
        .elf_slide = origin,
        .stack_top = origin + elf_span + USER_STACK_BYTES,
        .table_base = origin + elf_span + USER_STACK_BYTES,
    };
}

pub fn init(root_service_elf: []const u8) !void {
    var parsed: ParsedElf = undefined;
    try elf_util.parseElf(&parsed, @constCast(root_service_elf));

    // Spec §[create_capability_domain] test 16a: the ELF must be PIE
    // (e_type == ET_DYN). Even at boot we enforce this so the loader
    // path is the single source of truth for the rule.
    if (parsed.e_type != @intFromEnum(std.elf.ET.DYN)) {
        return error.NotPositionIndependent;
    }

    const layout = try resolveDomainLayout(root_service_elf);
    const slid_entry = VAddr.fromInt(parsed.entry.addr + layout.elf_slide);

    // Spec §[capability_domain] root domain: ceilings_inner / ceilings_outer
    // are absolute upper bounds — root must be allowed to mint handles
    // with full caps in every type, otherwise the runner's own
    // createPageFrame / createVmar / createCapabilityDomain calls fail
    // E_PERM against zero ceilings before the first test ever runs.
    //
    // Self-handle field0 layout per §[capability_domain] Self handle:
    //   bits  0-7   ec_inner_ceiling          = 0xFF
    //   bits  8-23  vmar_inner_ceiling         = 0xFFFF
    //   bits 24-31  cridc_ceiling             = 0xFF
    //   bits 32-39  idc_rx                    = 0xFF
    //   bits 40-47  pf_ceiling                = 0x1F  (max_rwx=7, max_sz=3)
    //   bits 48-55  vm_ceiling                = 0x01  (policy=1)
    //   bits 56-63  port_ceiling              = 0x5C  (xfer|recv|bind|suspend)
    const root_field0_ceilings: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0xFFFF) << 8) |
        (@as(u64, 0xFF) << 24) |
        (@as(u64, 0xFF) << 32) |
        (@as(u64, 0x1F) << 40) |
        (@as(u64, 0x01) << 48) |
        (@as(u64, 0x5C) << 56);
    // ceilings_outer (field1):
    //   bits  0-7   ec_outer_ceiling           = 0xFF
    //   bits  8-15  vmar_outer_ceiling          = 0xFF
    //   bits 16-31  restart_policy_ceiling     = 0xFFFF
    //   bits 32-37  fut_wait_max               = 63
    const root_field1_ceilings: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0xFF) << 8) |
        (@as(u64, 0xFFFF) << 16) |
        (@as(u64, 63) << 32);

    const root_cd = try capdom.allocCapabilityDomain(
        @bitCast(ROOT_SELF_CAPS),
        root_field0_ceilings,
        root_field1_ceilings,
        slid_entry,
    );

    // Re-mirror kernel-half PML4 entries from the kernel root into the
    // new domain's PML4. Fresh L3/L2/L1 paging structures created
    // between allocCapabilityDomain (which copies entries 256..511 once
    // up front) and now — most notably the EC's kernel stack PTEs
    // installed in allocExecutionContext — only landed in the kernel
    // address space root. Without this re-copy, swapAddrSpace into the
    // new domain leaves the kernel-stack VAs unmapped and the iret
    // epilogue's stack pop / writethrough faults.
    const root_virt = VAddr.fromPAddr(root_cd.addr_space_root, null);
    arch.paging.copyKernelMappings(root_virt);

    try loadElfSegments(root_cd, root_service_elf, &parsed, layout.elf_slide);
    try mapUserStack(root_cd, layout.stack_top);
    try mapUserTableView(root_cd, layout.table_base);

    const root_ec = try resolveOrSpawnRootEc(root_cd, slid_entry, layout);

    grantDevices(root_cd);

    // Re-mirror once more — the user mappings we just installed live in
    // user-half PML4 entries (0..255), which copyKernelMappings does
    // not touch. They went into root_cd's PML4 directly via mapPage.
    arch.paging.copyKernelMappings(root_virt);

    arch.boot.print("[boot] root EC ready: entry=0x{x} stack_top=0x{x} ut=0x{x}\n", .{ slid_entry.addr, layout.stack_top, layout.table_base });

    sched.enqueueOnCore(@intCast(arch.smp.coreID()), root_ec);
}

/// Walk PT_LOAD headers in `elf_bytes`, allocate user pages from PMM,
/// copy bytes from the bootloader-loaded ELF blob (in physmap), and
/// map into the new domain's PML4 with per-segment R/W/X perms,
/// shifted by `slide` (spec §[address_space] — PIE images load at a
/// kernel-chosen randomized base in the ASLR zone).
///
/// PIE ELFs (linker origin = 0) frequently pack two segments onto one
/// 4 KiB page — e.g. .text ending mid-page and .rodata starting later
/// in the same page. The loader handles this by:
///   1. First segment that touches a page allocates a fresh PMM page,
///      fills it with the matching slice of file bytes, maps it.
///   2. Later segments that touch that same page resolve the existing
///      physical page through the partially-populated PML4, copy
///      their bytes into the kernel-half view of that physical page,
///      and leave the original PTE perms intact (the most permissive
///      perms — text/exec — must not be stripped by a subsequent
///      rodata mapping).
pub fn loadElfSegments(
    root_cd: *CapabilityDomain,
    elf_bytes: []const u8,
    parsed: *const ParsedElf,
    slide: u64,
) !void {
    _ = parsed;
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(elf_bytes[0..hdr_sz]);
    const hdr = try std.elf.Header.read(&rd);

    var phdr_itr = hdr.iterateProgramHeadersBuffer(@constCast(elf_bytes));
    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != std.elf.PT_LOAD) continue;
        const writable = (phdr.p_flags & std.elf.PF_W) != 0;
        const executable = (phdr.p_flags & std.elf.PF_X) != 0;

        const slid_vaddr = phdr.p_vaddr + slide;
        const seg_start = std.mem.alignBackward(u64, slid_vaddr, paging_consts.PAGE4K);
        const seg_end = std.mem.alignForward(u64, slid_vaddr + phdr.p_memsz, paging_consts.PAGE4K);
        const skip_head = slid_vaddr - seg_start;
        const file_bytes = phdr.p_filesz;

        var off: u64 = 0;
        while (seg_start + off < seg_end) {
            const target_vaddr = VAddr.fromInt(seg_start + off);
            const existing_phys = arch.paging.resolveVaddr(root_cd.addr_space_root, target_vaddr);

            // Compute the union of perms across every PT_LOAD that
            // touches this 4 KiB page. Test ELFs commonly split a
            // single page into a R-only header PT_LOAD (bytes 0..0x10)
            // followed by a R+E PT_LOAD (entry at 0x10); if the first
            // segment maps the page R-only and the second skips the
            // remap on `existing_phys`, instruction fetch at the
            // entry point faults. Walk every segment's per-page span
            // and OR the perms here so the eventual mapPage call
            // installs the merged perms.
            const page_perms = unionPagePerms(elf_bytes, target_vaddr.addr, slide) catch zag.memory.address.MemoryPerms{
                .read = true,
                .write = writable,
                .exec = executable,
            };

            const page_phys: PAddr = if (existing_phys) |p| p else blk: {
                const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
                const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
                const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
                // Zero on first allocation; subsequent segment overlays
                // preserve previously-installed bytes.
                const dst: [*]u8 = @ptrCast(page);
                @memset(dst[0..paging_consts.PAGE4K], 0);
                try arch.paging.mapPage(
                    root_cd.addr_space_root,
                    phys,
                    target_vaddr,
                    page_perms,
                    .user_data,
                );
                break :blk phys;
            };

            // Copy this segment's file bytes into the page (whether
            // freshly allocated or pre-existing from an earlier segment).
            if (off + paging_consts.PAGE4K > skip_head) {
                const dst_start = if (off >= skip_head) @as(usize, 0) else @as(usize, @intCast(skip_head - off));
                const src_start = if (off >= skip_head) @as(usize, @intCast(off - skip_head)) else 0;
                if (src_start < file_bytes) {
                    var copy_len = paging_consts.PAGE4K - dst_start;
                    if (src_start + copy_len > file_bytes) copy_len = file_bytes - src_start;
                    const src_off = phdr.p_offset + src_start;
                    const src: [*]const u8 = elf_bytes.ptr + src_off;
                    const dst_kernel_va = VAddr.fromPAddr(page_phys, null).addr;
                    const dst: [*]u8 = @ptrFromInt(dst_kernel_va);
                    @memcpy(dst[dst_start .. dst_start + copy_len], src[0..copy_len]);
                }
            }

            off += paging_consts.PAGE4K;
        }
    }

    // Apply R_X86_64_RELATIVE dynamic relocations. The runner is built
    // PIE; any pointer in initialized .data (notably the embedded test
    // ELF manifest's `bytes.ptr` slots) is encoded as a RELATIVE
    // relocation in `.rela.dyn` whose addend is the unslided VA. The
    // patched value is `addend + slide`; the relocation target's VA is
    // also slid before the kernel walks the page tables to find the
    // backing physical page.
    try applyRelativeRelocations(root_cd, elf_bytes, slide);
}

/// Walk PT_LOADs and return the union of perms across every segment
/// that overlaps the given page-aligned VA. Page-granularity perms
/// must be OR'd because two PT_LOADs can share a 4 KiB page (e.g. a
/// 16-byte R-only header followed by a R+E entry segment) and the
/// stricter perms would otherwise win and break instruction fetch.
fn unionPagePerms(
    elf_bytes: []const u8,
    page_va: u64,
    slide: u64,
) !zag.memory.address.MemoryPerms {
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(elf_bytes[0..hdr_sz]);
    const hdr = try std.elf.Header.read(&rd);

    var perms = zag.memory.address.MemoryPerms{ .read = true };
    var phdr_itr = hdr.iterateProgramHeadersBuffer(@constCast(elf_bytes));
    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != std.elf.PT_LOAD) continue;
        const slid = phdr.p_vaddr + slide;
        const seg_start = std.mem.alignBackward(u64, slid, paging_consts.PAGE4K);
        const seg_end = std.mem.alignForward(u64, slid + phdr.p_memsz, paging_consts.PAGE4K);
        if (page_va < seg_start or page_va >= seg_end) continue;
        if ((phdr.p_flags & std.elf.PF_W) != 0) perms.write = true;
        if ((phdr.p_flags & std.elf.PF_X) != 0) perms.exec = true;
    }
    return perms;
}

/// Walk SHT_RELA sections and apply R_X86_64_RELATIVE entries against
/// the user address space. The patched value is `addend + slide`; the
/// relocation target's runtime VA (`r_offset + slide`) is translated
/// to a PA via `resolveVaddr` and written through the kernel physmap
/// rather than touching the file bytes — the file bytes live in
/// either the bootloader's `loader_data` blob (root service path) or
/// a page frame's physmap (createCapabilityDomain path), and patching
/// them in place would corrupt the original ELF the caller still
/// holds a reference to.
fn applyRelativeRelocations(
    root_cd: *CapabilityDomain,
    elf_bytes: []const u8,
    slide: u64,
) !void {
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    if (elf_bytes.len < hdr_sz) return;
    const ehdr: *const std.elf.Elf64_Ehdr = @ptrCast(@alignCast(elf_bytes.ptr));
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    const shdrs = std.mem.bytesAsSlice(
        std.elf.Elf64_Shdr,
        elf_bytes[ehdr.e_shoff .. ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize],
    );

    for (shdrs) |shdr| {
        if (shdr.sh_type != std.elf.SHT_RELA) continue;

        const entry_size: u64 = @sizeOf(std.elf.Elf64_Rela);
        const num_entries = shdr.sh_size / entry_size;
        const relas = std.mem.bytesAsSlice(
            std.elf.Elf64_Rela,
            elf_bytes[shdr.sh_offset .. shdr.sh_offset + num_entries * entry_size],
        );

        for (relas) |rela| {
            const rtype: u32 = @truncate(rela.r_info);
            // R_X86_64.RELATIVE (= 8) / R_AARCH64.RELATIVE (= 1027) only.
            // Other types (e.g. ABS64) require a symbol table walk, which
            // the runner does not emit — its dynamic linker is the
            // kernel and the runner is statically linked, so all live
            // relocations are RELATIVE.
            const relative_type: u32 = comptime switch (builtin.cpu.arch) {
                .x86_64 => @intFromEnum(std.elf.R_X86_64.RELATIVE),
                .aarch64 => @intFromEnum(std.elf.R_AARCH64.RELATIVE),
                else => @compileError("unsupported arch"),
            };
            if (rtype != relative_type) continue;

            const slid_target = rela.r_offset + slide;
            const target_va = VAddr.fromInt(slid_target);
            const target_pa = arch.paging.resolveVaddr(
                root_cd.addr_space_root,
                target_va,
            ) orelse return error.RelocationTargetUnmapped;

            const page_off: u64 = slid_target & (paging_consts.PAGE4K - 1);
            const km_va = VAddr.fromPAddr(target_pa, null).addr + page_off;

            const new_val: u64 = @as(u64, @bitCast(rela.r_addend)) +% slide;
            const slot: *align(1) u64 = @ptrFromInt(km_va);
            slot.* = new_val;
        }
    }
}

/// Allocate USER_STACK_BYTES of user pages and map them ending at
/// `stack_top`. The EC's iret frame uses `stack_top` as the initial
/// RSP. Spec §[create_execution_context] / §[create_capability_domain]
/// — stack lives at a kernel-chosen randomized base in the ASLR zone.
pub fn mapUserStack(root_cd: *CapabilityDomain, stack_top: u64) !void {
    const base: u64 = stack_top - USER_STACK_BYTES;
    var off: u64 = 0;
    while (off < USER_STACK_BYTES) {
        const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
        const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        try arch.paging.mapPage(
            root_cd.addr_space_root,
            phys,
            VAddr.fromInt(base + off),
            .{ .read = true, .write = true },
            .user_data,
        );
        off += paging_consts.PAGE4K;
    }
}

/// Map the user_table backing pages read-only into the new domain's
/// user half at `table_base`. The kernel writes to the table via its
/// own kernel-half pointer (root_cd.user_table); user code reads
/// through this view.
pub fn mapUserTableView(root_cd: *CapabilityDomain, table_base: u64) !void {
    const ut_kernel_va: u64 = @intFromPtr(root_cd.user_table);
    var off: u64 = 0;
    while (off < ROOT_USER_TABLE_BYTES) {
        const kernel_page_va = VAddr.fromInt(ut_kernel_va + off);
        const phys = PAddr.fromVAddr(kernel_page_va, null);
        try arch.paging.mapPage(
            root_cd.addr_space_root,
            phys,
            VAddr.fromInt(table_base + off),
            .{ .read = true },
            .user_data,
        );
        off += paging_consts.PAGE4K;
    }
}

fn resolveOrSpawnRootEc(
    root_cd: *CapabilityDomain,
    entry: VAddr,
    layout: DomainLayout,
) !*ExecutionContext {
    const existing = capability.typedRef(ExecutionContext, root_cd.kernel_table[1]);
    if (existing) |ref| return ref.ptr;

    const ec = try execution_context.allocExecutionContext(
        root_cd,
        entry,
        1,
        0,
        .normal,
        null,
        null,
    );

    // allocExecutionContext built an iret frame in kernel-mode (no user
    // stack was wired through allocVmar yet). Patch it for user mode.
    arch.cpu.patchUserModeIretFrame(
        ec.ctx,
        entry,
        VAddr.fromInt(layout.stack_top),
        layout.table_base,
    );

    const obj_ref: ErasedSlabRef = .{
        .ptr = ec,
        .gen = @intCast(ec._gen_lock.currentGen()),
    };
    // Pin the root EC to slot 1 (= caps.SLOT_INITIAL_EC). Child CDs
    // get their initial EC at slot 1 via the explicit `user_table[1] =
    // ...` block in create_capability_domain; the root CD's existing
    // path used `mintHandle` (which pops `free_head` starting at 3),
    // so the root EC silently landed at slot 3 and the root service's
    // `priority(SLOT_INITIAL_EC, ...)` syscall returned E_BADCAP. Slots
    // 0, 1, 2 are reserved (not on the free list), so `mintHandleAt`
    // can drop a handle there without unlinking.
    capdom.mintHandleAt(
        root_cd,
        1,
        obj_ref,
        .execution_context,
        @bitCast(ROOT_EC_CAPS),
        0,
        0,
    );
    return ec;
}

fn grantDevices(root_cd: *CapabilityDomain) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            // x86 enumerators (`enumeratePci`, `probeSerialPorts`) stage
            // every discovered device_region onto `device_region`'s boot
            // grant list. Drain it here so the root service's cap table
            // is the single source of truth for platform hardware —
            // COM1 included.
            grantBootDevices(root_cd);
        },
        .aarch64 => {
            // aarch64 has no PCI enumerator yet. Mint the platform
            // devices the runner / linux_guest VMM expect: the MMIO
            // PL011 region (0x09000000) and the virtualized port_io
            // 0x3F8 the runner serial sink scans for.
            grantPl011(root_cd);
            grantCom1(root_cd);
            // Plus anything kMain staged on the boot grant list
            // (currently the framebuffer; future arch-portable
            // platform devices will land here too).
            grantBootDevices(root_cd);
        },
        else => {},
    }

    // Test-only fixture device_regions. Gated on `tests_fixture_devices`
    // build option (auto-on under -Dprofile=test). Two synthetic MMIO
    // regions are minted into the root service's cap table so spec
    // tests targeting `device_region` / IRQ / DMA surfaces have
    // something to scan for. The runner forwards them to test
    // children via `passed_handles` (see tests/suite/runner/primary.zig).
    // Spec §[device_region] does not constrain how device_regions are
    // sourced at boot — kernel is free to mint synthetic ones for test
    // purposes — and userspace cannot tell a fixture from real
    // hardware (no introspection on `phys_base` validity).
    if (build_options.tests_fixture_devices) {
        grantTestFixtureDevices(root_cd);
    }
}

/// Mint two synthetic test-only device_regions:
///   - `caps={move,copy,dma,irq}` — exercises `caps.dma=1` and
///     `caps.irq=1` paths in §[create_vmar] / §[ack] / §[device_irq].
///     Stamped with a synthetic-but-valid PCI BDF (bus=0xCA, dev=0x1F,
///     func=0x7) so the IOMMU drivers (`arch/x64/intel/vtd.zig`,
///     `arch/x64/amd/vi.zig`) can lazily provision a per-device
///     translation domain on the first `iommuMapPage`. The BDF is
///     chosen far outside any real ACPI-discovered range — bus 0xCA
///     is well above QEMU q35's PCI topology (which lives on bus 0
///     and a handful of bridge-allocated busses) and the
///     `dev=0x1F,func=0x7` slot is rarely populated in real hardware
///     either. Neither IOMMU driver cross-checks BDFs against ACPI
///     tables; both allocate context/DTE entries lazily on first use,
///     so a synthetic BDF behaves identically to a real one as long
///     as it is unique.
///   - `caps={move,copy}` — bare device_region with neither dma nor
///     irq. Used by §[create_vmar] tests that need a valid handle whose
///     caps subset check fails (test 15: `caps.dma=1` and [5] without
///     `dma` cap → E_PERM). Left with `pci.valid=0` since no IOMMU
///     translation is ever attempted through it.
///
/// Both fixtures use sentinel `phys_base` addresses (0xCAFE_0000 /
/// 0xBABE_0000) chosen to be far outside any real PCI/MMIO BAR; tests
/// only use the handle metadata, not the backing memory. `irq_source`
/// stays `IRQ_SOURCE_NONE` for both — no IOAPIC line is bound, so
/// `onIrq → maskIrq` and `ack → unmaskIrq` short-circuit on the
/// IRQ_SOURCE_NONE guard inside `device_region.zig`. Triggering an
/// actual hardware IRQ for these fixtures requires kernel-side
/// IRQ-injection infrastructure that this branch does not provide;
/// see the spec test files (device_irq_*.zig, ack_07.zig) for the
/// outstanding harness gap.
fn grantTestFixtureDevices(root_cd: *CapabilityDomain) void {
    const TEST_DMA_IRQ_BASE: u64 = 0xCAFE_0000;
    const TEST_DMA_IRQ_SIZE: u64 = 0x1000;
    const TEST_PLAIN_BASE: u64 = 0xBABE_0000;
    const TEST_PLAIN_SIZE: u64 = 0x1000;

    mintTestFixtureMmio(
        root_cd,
        PAddr.fromInt(TEST_DMA_IRQ_BASE),
        TEST_DMA_IRQ_SIZE,
        zag.devices.device_region.DeviceRegionCaps{
            .move = true,
            .copy = true,
            .dma = true,
            .irq = true,
        },
        zag.devices.device_region.PciAddress.make(0xCA, 0x1F, 0x7),
    );
    mintTestFixtureMmio(
        root_cd,
        PAddr.fromInt(TEST_PLAIN_BASE),
        TEST_PLAIN_SIZE,
        zag.devices.device_region.DeviceRegionCaps{
            .move = true,
            .copy = true,
        },
        .{},
    );
}

fn mintTestFixtureMmio(
    root_cd: *CapabilityDomain,
    phys_base: PAddr,
    size: u64,
    dr_caps: zag.devices.device_region.DeviceRegionCaps,
    pci: zag.devices.device_region.PciAddress,
) void {
    const dr = zag.devices.device_region.registerMmioPci(phys_base, size, pci) catch {
        arch.boot.print("[boot] WARNING: test-fixture MMIO registerMmio failed\n", .{});
        return;
    };
    // Spec §[device_region] field0 layout (mmio):
    //   bits  0-3   dev_type (0 = mmio)
    //   bits  4-51  base_paddr >> 12
    //   bits 52-63  size_pages
    const field0: u64 = 0 |
        ((phys_base.addr >> 12) << 4) |
        ((size >> 12) << 52);

    const erased: ErasedSlabRef = .{
        .ptr = @ptrCast(dr),
        .gen = @intCast(dr._gen_lock.currentGen()),
    };
    _ = capdom.mintHandle(
        root_cd,
        erased,
        zag.caps.capability.CapabilityType.device_region,
        @bitCast(dr_caps),
        field0,
        0,
    ) catch {
        arch.boot.print("[boot] WARNING: test-fixture device_region handle mint failed\n", .{});
    };
}

fn grantBootDevices(root_cd: *CapabilityDomain) void {
    zag.devices.device_region.forEachBootGrant(root_cd, mintBootDevice);
}

fn mintBootDevice(root_cd: *CapabilityDomain, dr: *zag.devices.device_region.DeviceRegion) void {
    // field0 layout per spec §[device_region]:
    //   port_io:     bits 0-3 dev_type=1, bits 4-19 base_port, bits 20-35 port_count
    //   mmio:        bits 0-3 dev_type=0, bits 4-51 paddr>>12, bits 52-63 size_pages
    //   framebuffer: bits 0-3 dev_type=2, bits 4-51 paddr>>12, bits 52-63 size_pages
    //                field1: width(16) | height(16) | stride(16) | pixel_format(8) | reserved(8)
    var field0: u64 = @intFromEnum(dr.device_type);
    var field1: u64 = 0;
    switch (dr.device_type) {
        .mmio => {
            const m = dr.access.mmio;
            field0 |= ((m.phys_base.addr >> 12) << 4) |
                ((m.size >> 12) << 52);
        },
        .port_io => {
            const p = dr.access.port_io;
            field0 |= (@as(u64, p.base_port) << 4) |
                (@as(u64, p.port_count) << 20);
        },
        .framebuffer => {
            const fb = dr.access.framebuffer;
            field0 |= ((fb.phys_base.addr >> 12) << 4) |
                ((fb.size >> 12) << 52);
            field1 =
                @as(u64, fb.width) |
                (@as(u64, fb.height) << 16) |
                (@as(u64, fb.stride) << 32) |
                (@as(u64, @intFromEnum(fb.pixel_format)) << 48);
        },
    }
    // Grant move/copy/dma/irq so the root service can delegate freely
    // to drivers and create DMA VMARs for them.
    const dr_caps = zag.devices.device_region.DeviceRegionCaps{
        .move = true,
        .copy = true,
        .dma = true,
        .irq = true,
    };
    const erased: ErasedSlabRef = .{
        .ptr = @ptrCast(dr),
        .gen = @intCast(dr._gen_lock.currentGen()),
    };
    _ = capdom.mintHandle(
        root_cd,
        erased,
        zag.caps.capability.CapabilityType.device_region,
        @bitCast(dr_caps),
        field0,
        field1,
    ) catch {
        arch.boot.print("[boot] WARNING: device_region grant failed (boot list overflow)\n", .{});
    };
}

fn grantCom1(root_cd: *CapabilityDomain) void {
    // Surface a port_io device_region for COM1 (0x3F8/8) so the runner's
    // serial sink can find it via slot scan + `caps.deviceRegionFields`.
    // Without this the runner's `[runner] *` print stream is silent —
    // `findCom1` returns null, the `Serial` defaults to `DISABLED`, and
    // every subsequent `[runner] result: code=X aid=Y` line that the
    // primary tries to emit is dropped on the floor. Spec §[device_region]
    // does not pin where boot mints the early platform device handles;
    // we put COM1 here so it's available before sched.run() picks up
    // the root EC.
    //
    // Spec §[device_region] field0 layout (port_io):
    //   bits  0-3  dev_type (1 = port_io)
    //   bits  4-19 base_port (16-bit)
    //   bits 20-35 port_count (16-bit)
    const COM1_BASE: u16 = 0x3F8;
    const COM1_COUNT: u16 = 8;
    const dr = zag.devices.device_region.registerPortIo(COM1_BASE, COM1_COUNT) catch {
        arch.boot.print("[boot] WARNING: COM1 registerPortIo failed; serial disabled\n", .{});
        return;
    };

    const field0: u64 = 1 |
        (@as(u64, COM1_BASE) << 4) |
        (@as(u64, COM1_COUNT) << 20);
    const dr_caps: u16 = 0; // No move/copy/dma/irq required; runner only
                             //   needs the slot to exist for map_mmio.

    const erased: zag.caps.capability.ErasedSlabRef = .{
        .ptr = @ptrCast(dr),
        .gen = @intCast(dr._gen_lock.currentGen()),
    };
    _ = capdom.mintHandle(
        root_cd,
        erased,
        zag.caps.capability.CapabilityType.device_region,
        dr_caps,
        field0,
        0,
    ) catch {
        arch.boot.print("[boot] WARNING: COM1 device_region handle mint failed\n", .{});
    };
}

fn grantPl011(root_cd: *CapabilityDomain) void {
    // QEMU virt PL011 UART0 sits at 0x09000000/4 KiB. The aarch64
    // root_service VMMs (linux_guest, suite runner) discover it by
    // scanning their cap table for a device_region whose mmio fields
    // match this base. Spec §[device_region] field0 layout (mmio):
    //   bits  0-3   dev_type (0 = mmio)
    //   bits  4-51  base_paddr >> 12
    //   bits 52-63  size_pages
    const PL011_BASE: u64 = 0x0900_0000;
    const PL011_SIZE: u64 = 0x1000;
    const dr = zag.devices.device_region.registerMmio(PAddr.fromInt(PL011_BASE), PL011_SIZE) catch {
        arch.boot.print("[boot] WARNING: PL011 registerMmio failed; serial disabled\n", .{});
        return;
    };

    const field0: u64 = 0 |
        ((PL011_BASE >> 12) << 4) |
        ((PL011_SIZE >> 12) << 52);
    const dr_caps: u16 = 0;

    const erased: zag.caps.capability.ErasedSlabRef = .{
        .ptr = @ptrCast(dr),
        .gen = @intCast(dr._gen_lock.currentGen()),
    };
    _ = capdom.mintHandle(
        root_cd,
        erased,
        zag.caps.capability.CapabilityType.device_region,
        dr_caps,
        field0,
        0,
    ) catch {
        arch.boot.print("[boot] WARNING: PL011 device_region handle mint failed\n", .{});
    };
}
