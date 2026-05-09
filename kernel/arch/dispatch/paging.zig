const builtin = @import("builtin");
const std = @import("std");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

const MappingKind = stygia.memory.address.MappingKind;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const PageSize = stygia.memory.paging.PageSize;
const Range = stygia.utils.range.Range;
const VAddr = stygia.memory.address.VAddr;
const VmarPageSize = stygia.memory.vmar.PageSize;
const VmarCacheType = stygia.memory.vmar.CacheType;

// ── Address Space Layout ────────────────────────────────────────────────
// Architecture-specific virtual address space boundaries. These define
// the user/kernel split, physmap location, and kernel code range.

pub const addr_space = switch (builtin.cpu.arch) {
    .x86_64 => struct {
        pub const user: Range = .{
            .start = 0x0000_0000_0000_0000,
            .end = 0xFFFF_8000_0000_0000,
        };
        pub const kernel: Range = .{
            .start = 0xFFFF_8000_0000_0000,
            .end = 0xFFFF_8400_0000_0000,
        };
        pub const physmap: Range = .{
            .start = 0xFFFF_FF80_0000_0000,
            .end = 0xFFFF_FF88_0000_0000,
        };
        pub const kernel_code: Range = .{
            .start = 0xFFFF_FFFF_8000_0000,
            .end = 0xFFFF_FFFF_C000_0000,
        };
    },
    .aarch64 => struct {
        pub const user: Range = .{
            .start = 0x0000_0000_0000_0000,
            .end = 0x0001_0000_0000_0000,
        };
        // Kernel heap/data (above kernel_code).
        pub const kernel: Range = .{
            .start = 0xFFFF_0000_4000_0000,
            .end = 0xFFFF_0400_0000_0000,
        };
        pub const physmap: Range = .{
            .start = 0xFFFF_FF80_0000_0000,
            .end = 0xFFFF_FF88_0000_0000,
        };
        // Kernel text/rodata (bottom of TTBR1 range).
        pub const kernel_code: Range = .{
            .start = 0xFFFF_0000_0000_0000,
            .end = 0xFFFF_0000_4000_0000,
        };
    },
    else => unreachable,
};

/// NULL guard at the bottom of every user address space. The first
/// page must always fault — no mapping path may install a leaf into
/// `[0, 0x1000)`. Spec §[address_space].
pub const user_null_guard: Range = .{
    .start = 0x0000_0000_0000_0000,
    .end = 0x0000_0000_0000_1000,
};

/// ASLR zone — kernel-chosen base, randomized at placement time. Used
/// for ELF segments, EC stacks, and `create_vmar(preferred_base = 0)`.
/// Spec §[address_space].
pub const user_aslr: Range = switch (builtin.cpu.arch) {
    .x86_64 => .{
        .start = 0x0000_0000_0000_1000,
        .end = 0x0000_1000_0000_0000,
    },
    .aarch64 => .{
        .start = 0x0000_0000_0000_1000,
        .end = 0x0000_1000_0000_0000,
    },
    else => unreachable,
};

/// Static zone — userspace-chosen base via `create_vmar(preferred_base
/// != 0)`. Placement is deterministic. Spec §[address_space].
pub const user_static: Range = switch (builtin.cpu.arch) {
    .x86_64 => .{
        .start = 0x0000_1000_0000_0000,
        .end = 0x0000_8000_0000_0000,
    },
    .aarch64 => .{
        .start = 0x0000_1000_0000_0000,
        .end = 0x0001_0000_0000_0000,
    },
    else => unreachable,
};

pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
    kind: MappingKind,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPage(addr_space_root, phys, virt, perms, kind),
        .aarch64 => try aarch64.paging.mapPage(addr_space_root, phys, virt, perms, kind),
        else => unreachable,
    }
}

pub fn mapPageBoot(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    kind: MappingKind,
    allocator: std.mem.Allocator,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPageBoot(addr_space_root, phys, virt, size, perms, kind, allocator),
        .aarch64 => try aarch64.paging.mapPageBoot(addr_space_root, phys, virt, size, perms, kind, allocator),
        else => unreachable,
    }
}

pub fn unmapPage(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.unmapPage(addr_space_root, virt),
        .aarch64 => return aarch64.paging.unmapPage(addr_space_root, virt),
        else => unreachable,
    }
}

pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.resolveVaddr(addr_space_root, virt),
        .aarch64 => return aarch64.paging.resolveVaddr(addr_space_root, virt),
        else => unreachable,
    }
}

/// Allocate a per-process address-space identifier for TLB tagging
/// (PCID on x86-64, ASID on aarch64). Returns null on exhaustion.
pub fn allocAddrSpaceId() ?u16 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.pcid.allocate(),
        .aarch64 => aarch64.asid.allocate(),
        else => unreachable,
    };
}

/// Release an address-space identifier previously returned by
/// `allocAddrSpaceId`. The allocator invalidates every TLB entry tagged
/// with `id` before returning the slot so a future re-allocation does not
/// inherit stale mappings from the previous owner. Releasing id 0 is a
/// programming error.
pub fn freeAddrSpaceId(id: u16) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pcid.free(id),
        .aarch64 => aarch64.asid.free(id),
        else => unreachable,
    }
}

/// Whether the kernel page table root is the same as the user table.
/// On x86-64 (single CR3) the bootloader must copy the UEFI identity map
/// into the new kernel table. On aarch64 (split TTBR0/TTBR1) the kernel
/// table is independent and should start clean.
pub const kernel_shares_user_table: bool = switch (builtin.cpu.arch) {
    .x86_64 => true,
    .aarch64 => false,
    else => unreachable,
};

/// Return the physical address of the kernel page table root.
/// On x86-64 this is the same as getAddrSpaceRoot() since CR3 covers both
/// halves. On aarch64 this reads TTBR1_EL1 (upper/kernel VA range).
pub fn getKernelAddrSpaceRoot() PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.getAddrSpaceRoot(),
        .aarch64 => aarch64.paging.getKernelAddrSpaceRoot(),
        else => unreachable,
    };
}

/// Set the kernel page table root. Bootloader-only — runs before
/// CR4.PCIDE is enabled, so on x86-64 the CR3 source operand cannot
/// carry the PCID/no-flush bits that runtime swapAddrSpace uses.
/// On aarch64 this writes TTBR1_EL1 (upper/kernel VA range).
pub fn setKernelAddrSpace(root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.setKernelAddrSpace(root),
        .aarch64 => aarch64.paging.setKernelAddrSpace(root),
        else => unreachable,
    }
}

pub fn dropIdentityMapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.dropIdentityMapping(),
        .aarch64 => aarch64.paging.dropIdentityMapping(),
        else => unreachable,
    }
}

/// Classification of ELF relocation types for KASLR slide application.
pub const RelocAction = enum { skip, abs64, abs32, unsupported };

/// Classify a relocation type for KASLR processing.
pub fn classifyRelocation(rtype: u32) RelocAction {
    return switch (builtin.cpu.arch) {
        .x86_64 => {
            if (rtype == @intFromEnum(std.elf.R_X86_64.PC32) or
                rtype == @intFromEnum(std.elf.R_X86_64.PLT32) or
                rtype == @intFromEnum(std.elf.R_X86_64.NONE)) return .skip;
            if (rtype == @intFromEnum(std.elf.R_X86_64.@"64")) return .abs64;
            if (rtype == @intFromEnum(std.elf.R_X86_64.@"32S")) return .abs32;
            return .unsupported;
        },
        .aarch64 => {
            const R = std.elf.R_AARCH64;
            // PC-relative: no adjustment needed (both sides move by slide).
            // LO12: low 12 bits unchanged with page-aligned slide.
            if (rtype == @intFromEnum(R.NONE) or
                rtype == @intFromEnum(R.PREL32) or
                rtype == @intFromEnum(R.PREL64) or
                rtype == @intFromEnum(R.ADR_PREL_PG_HI21) or
                rtype == @intFromEnum(R.ADR_PREL_PG_HI21_NC) or
                rtype == @intFromEnum(R.ADR_PREL_LO21) or
                rtype == @intFromEnum(R.ADD_ABS_LO12_NC) or
                rtype == @intFromEnum(R.CALL26) or
                rtype == @intFromEnum(R.JUMP26) or
                rtype == @intFromEnum(R.LDST8_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST16_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST32_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST64_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST128_ABS_LO12_NC)) return .skip;
            if (rtype == @intFromEnum(R.ABS64) or
                rtype == @intFromEnum(R.RELATIVE)) return .abs64;
            if (rtype == @intFromEnum(R.ABS32)) return .abs32;
            return .unsupported;
        },
        else => unreachable,
    };
}

// ── Spec v3 paging primitives ────────────────────────────────────────
// Fine-grained per-page mapping/invalidation surface used by VMAR
// install/unmap, page_frame mapcnt updates, and shootdown coordination.

/// Map a single page of size `sz` at `virt → phys` with `cch` cache
/// attributes and `perms`. Spec §[var].map_pf.
pub fn mapPageSized(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
    cch: VmarCacheType,
    perms: MemoryPerms,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPageSized(addr_space_root, phys, virt, sz, cch, perms),
        .aarch64 => try aarch64.paging.mapPageSized(addr_space_root, phys, virt, sz, cch, perms),
        else => unreachable,
    }
}

/// Unmap a single page of size `sz` at `virt`. Returns the previously
/// mapped physical page if any. Spec §[var].unmap.
pub fn unmapPageSized(
    addr_space_root: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
) ?PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.unmapPageSized(addr_space_root, virt, sz),
        .aarch64 => aarch64.paging.unmapPageSized(addr_space_root, virt, sz),
        else => unreachable,
    };
}

/// Allocate a fresh empty top-level address space (PML4 root on x86-64,
/// stage-1 TTBR0 root on aarch64). Bumps the per-arch ASID/PCID
/// allocator implicitly is the caller's responsibility — this only
/// hands back the page-table root. Spec §[capability_domain].
/// Mirror the kernel half (upper) of the current address-space root into
/// a freshly-allocated child root. On x86_64 this copies PML4 entries
/// 256..511; on aarch64 the kernel half lives in TTBR1 and is shared by
/// hardware so this is a no-op.
pub fn copyKernelMappings(root: VAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.copyKernelMappings(root),
        .aarch64 => {},
        else => unreachable,
    }
}

pub fn allocAddrSpaceRoot() !PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.allocAddrSpaceRoot(),
        .aarch64 => aarch64.paging.allocAddrSpaceRoot(),
        else => unreachable,
    };
}

/// Free the user-half of an address space root and every page reachable
/// through it back to PMM. See per-arch implementations for the walk
/// strategy. Two `(skip_phys_start, skip_phys_bytes)` ranges define
/// physical extents whose leaves are NOT freed individually — the
/// caller is freeing them via a wholesale `pmm.freeBlock`. Pass
/// `skipN_bytes = 0` to disable a range. Used by capability-domain
/// teardown to reclaim the eagerly-mapped user stack, ELF segments,
/// and page-table pages that accumulate per-spawn under the test
/// runner; the user_table view aliases the cap-domain's user_buf
/// block (skip range 1) and the user stack lives in a contiguous
/// buddy block freed wholesale (skip range 2).
pub fn freeUserAddrSpace(
    root: PAddr,
    skip1_start: u64,
    skip1_bytes: u64,
    skip2_start: u64,
    skip2_bytes: u64,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.freeUserAddrSpace(root, skip1_start, skip1_bytes, skip2_start, skip2_bytes),
        .aarch64 => aarch64.paging.freeUserAddrSpace(root, skip1_start, skip1_bytes, skip2_start, skip2_bytes),
        else => unreachable,
    }
}

/// Clear a leaf PTE in `addr_space_root` for `virt` without issuing
/// local INVLPG or remote TLB shootdown. Used by VMAR destroy in the
/// capability-domain teardown path — no core has the dying CD's CR3
/// active by the time `freeUserAddrSpace` returns, so the shootdown is
/// unnecessary. Returns the leaf physical address that was cleared
/// (caller may freePage it) or null if no leaf was installed.
pub fn unmapPageNoShootdown(addr_space_root: PAddr, virt: VAddr) ?PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.unmapPageNoShootdown(addr_space_root, virt),
        .aarch64 => aarch64.paging.unmapPage(addr_space_root, virt),
        else => unreachable,
    };
}

/// Cross-core TLB shootdown over the same page range, addressed by
/// `addr_space_id` so remote cores can filter quickly. Issues a
/// shootdown IPI and waits for ack from every core that may hold a
/// stale entry.
pub fn shootdownTlbRange(
    addr_space_id: u16,
    virt: VAddr,
    sz: VmarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.shootdownTlbRange(addr_space_id, virt, sz, page_count),
        .aarch64 => aarch64.paging.shootdownTlbRange(addr_space_id, virt, sz, page_count),
        else => unreachable,
    }
}
