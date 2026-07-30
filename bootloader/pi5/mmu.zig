//! Bring the MMU up at EL2, so the rest of the loader runs on Normal memory.
//!
//! WHY this exists, and why it has to happen early:
//!
//! With `SCTLR_EL2.M = 0` every access is Device-nGnRnE, and Device memory
//! requires natural alignment for *every* access regardless of `SCTLR_EL2.A`.
//! That makes ordinary compiled code unsafe in ways no build flag can fix. Two
//! distinct instances were hit on hardware here:
//!
//!   1. LLVM turning 16-byte struct copies into `ldr q`/`str q` against 8-byte
//!      aligned data. Fixed by subtracting `fp_armv8`+`neon` from the target.
//!   2. `std.mem.eql` / `memcmp` on a short slice, which compiles to OVERLAPPING
//!      unaligned 4-byte loads (`ldr w12, [x2, x12]`). Hit while comparing the
//!      ELF magic against a `.rodata` literal at 0xa0f505 — an odd address.
//!      EC=0x25, DFSC=0x21.
//!
//! The second one cannot be fixed with target flags: it is integer code, and it
//! is emitted by the standard library. Any stdlib call is a potential unaligned
//! access. So rather than audit the whole transitive callee set, turn translation
//! on: Normal memory permits unaligned accesses when `SCTLR.A == 0`, which is the
//! state every other loader (and Linux's head.S) arranges early for exactly this
//! reason. It also makes the ~10 MB of blob copying cached instead of
//! uncached-non-gathering.
//!
//! Ordering consequence worth stating plainly: the DTB parse, the memory-map
//! synthesis and the page-arena setup all run BEFORE this, and all three are
//! hand-written with volatile loads and explicit widths precisely so they are
//! alignment-safe. Everything after this point may use the standard library.

const std = @import("std");
const stygia = @import("stygia");

const boot_info = @import("boot_info.zig");
const dtb = @import("dtb.zig");
const early_log = @import("early_log.zig");
const log = early_log;
const pi5_paging = @import("paging.zig");

const arch = stygia.arch.dispatch;
const address = stygia.memory.address;
const paging = stygia.memory.paging;

const MemoryPerms = address.MemoryPerms;
const PAddr = address.PAddr;
const VAddr = address.VAddr;

/// MAIR layout this loader installs, low byte = index 0.
///
///   index 0 = 0x00  Device-nGnRnE
///   index 1 = 0xFF  Normal, Inner+Outer Write-Back cacheable
///   index 2 = 0x44  Normal, Inner+Outer Non-Cacheable  (Write-Combining)
///   index 3 = 0xBB  Normal, Inner+Outer Write-Through
///
/// The two low indices are not arbitrary. `kernel/arch/aarch64/paging.zig`
/// declares `mair_device = 0` and `mair_normal = 1` as its compile-time defaults,
/// and `mapPageBoot` stamps those into every descriptor it writes — including the
/// ones this loader creates, before `initMairIndices()` has ever run. Choosing any
/// other order would make the loader's own tables describe the wrong memory type.
///
/// Indices 2 and 3 exist for the kernel's benefit. `initMairIndices()` SCANS the
/// live MAIR_EL1 rather than programming it (it cannot: MAIR must not be rewritten
/// under a live MMU), and falls back to Device for WC and WB for WT when it finds
/// no 0x44/0xBB slot. On a UEFI boot firmware supplies those. Bare metal has no
/// firmware MAIR at all, so if this loader omitted them every write-combining
/// mapping in the system would silently degrade to strongly-ordered Device.
pub const MAIR_VALUE: u64 = 0x0000_0000_BB44_FF00;

/// TCR_EL2, non-VHE (`HCR_EL2.E2H == 0`) layout — ARM ARM D13.2.132.
///
/// T0SZ = 16 gives a 48-bit VA space, matching what the kernel's TCR_EL1 uses and
/// what `mapPageBoot`'s four-level index extraction assumes.
const TCR_EL2_T0SZ: u64 = 16;
/// IRGN0/ORGN0 = 0b01: table walks are Write-Back Read/Write-Allocate cacheable.
const TCR_EL2_IRGN0: u64 = 0b01 << 8;
const TCR_EL2_ORGN0: u64 = 0b01 << 10;
/// SH0 = 0b11: Inner Shareable. Required for the walker to see other cores'
/// writes once SMP comes up.
const TCR_EL2_SH0: u64 = 0b11 << 12;
/// TG0 = 0b00: 4 KiB granule.
const TCR_EL2_TG0: u64 = 0b00 << 14;
/// PS = 0b010: 40-bit (1 TiB) output. Must cover more than RAM — the BCM2712 SoC
/// window sits at PA 0x10_xxxx_xxxx and RP1 at 0x1F_xxxx_xxxx, both above 32 bits.
/// Sizing this to RAM alone would make every MMIO mapping untranslatable.
const TCR_EL2_PS: u64 = 0b010 << 16;
/// Bits 23 and 31 are RES1 in TCR_EL2 when E2H == 0.
const TCR_EL2_RES1: u64 = (1 << 23) | (1 << 31);

const TCR_EL2_VALUE: u64 = TCR_EL2_T0SZ | TCR_EL2_IRGN0 | TCR_EL2_ORGN0 |
    TCR_EL2_SH0 | TCR_EL2_TG0 | TCR_EL2_PS | TCR_EL2_RES1;

const SCTLR_M: u64 = 1 << 0;
const SCTLR_C: u64 = 1 << 2;
const SCTLR_I: u64 = 1 << 12;

pub const Error = error{
    UnexpectedE2H,
    IdentityMapFailed,
    VerifyFailed,
};

fn readSysreg(comptime name: []const u8) u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], " ++ name
        : [v] "=r" (v),
    );
    return v;
}

pub fn hcrE2H() u64 {
    return (readSysreg("hcr_el2") >> 34) & 1;
}

/// Identity-map every RAM range as Normal Write-Back cacheable.
///
/// UNIFORM granularity on purpose. An earlier version mapped RAM in 1 GiB blocks
/// and then re-mapped the 64 KiB early-log window inside one of them as Device, to
/// keep log writes out of the cache. That corrupts the tables, and it does so
/// silently: `mapPageBoot` tests only `entry.valid` and cannot tell a BLOCK from a
/// TABLE, so descending toward the 4 KiB leaf it found the enclosing 1 GiB block
/// valid, took its output address (0xC0000000) as the next-level table, and read
/// uninitialized DRAM as descriptors. Measured on hardware: DFSC=0x0 address size
/// fault, FAR=0xFFFF_FFFF_F000 — which is `(u36 max) << 12`, i.e. a garbage
/// descriptor's address field. Same hazard the two-root self-test documents.
///
/// So no finer mapping may be layered inside a coarser one. The log's durability
/// is handled where it belongs instead — `early_log.commit()` cleans the written
/// range to the point of coherency, so Normal WB is safe for it. `mapRange` also
/// now refuses to create an overlap rather than corrupting the table, which is
/// what makes this constraint enforced rather than merely documented.
pub fn buildIdentity(
    alloc: std.mem.Allocator,
    ttbr0_root: u64,
    map: *const dtb.MemoryMap,
) Error!void {
    const root = VAddr.fromInt(ttbr0_root);
    // Executable: the loader is running out of this mapping.
    const rwx: MemoryPerms = .{ .read = true, .write = true, .exec = true };

    for (map.ramSlice()) |r| {
        mapRange(alloc, root, r.base, r.size, rwx, .kernel_data) catch
            return Error.IdentityMapFailed;
    }
}

/// Identity-map an MMIO window as Device memory.
///
/// `.kernel_mmio` resolves to MAIR index 0 (Device-nGnRnE). Mapping MMIO cacheable
/// would let stores sit in the D-cache and reorder, which for a UART means garbage
/// on the wire and for a controller means writes that never land.
///
/// Callers must pass a window outside RAM. That is not a style preference: RAM is
/// mapped with 1 GiB and 2 MiB blocks, and layering a 4 KiB mapping inside one
/// corrupts the tables (see `buildIdentity`). `mapRange`'s guard enforces it.
pub fn mapMmio(
    alloc: std.mem.Allocator,
    ttbr0_root: u64,
    base: u64,
    size: u64,
) !void {
    try mapRange(
        alloc,
        VAddr.fromInt(ttbr0_root),
        base,
        size,
        .{ .read = true, .write = true },
        .kernel_mmio,
    );
}

/// Map [base, base+size) identity, choosing the largest granule that fits.
fn mapRange(
    alloc: std.mem.Allocator,
    root: VAddr,
    base: u64,
    size: u64,
    perms: MemoryPerms,
    kind: address.MappingKind,
) !void {
    var cursor = base & ~(paging.PAGE4K - 1);
    const limit = (base + size + paging.PAGE4K - 1) & ~(paging.PAGE4K - 1);

    while (cursor < limit) {
        const remaining = limit - cursor;
        const chosen: paging.PageSize = blk: {
            if (std.mem.isAligned(cursor, paging.PAGE1G) and remaining >= paging.PAGE1G)
                break :blk .page1g;
            if (std.mem.isAligned(cursor, paging.PAGE2M) and remaining >= paging.PAGE2M)
                break :blk .page2m;
            break :blk .page4k;
        };
        const step: u64 = switch (chosen) {
            .page1g => paging.PAGE1G,
            .page2m => paging.PAGE2M,
            .page4k => paging.PAGE4K,
        };

        // Refuse to map inside an existing coarser mapping. `mapPageBoot` would
        // happily descend INTO the enclosing block descriptor, treating its output
        // address as a page table and scribbling on whatever lives there — the
        // failure that cost a boot cycle and showed up as an address size fault
        // far from its cause. Cheap to check (one walk per mapping) and it turns a
        // silent table corruption into a message naming the exact VA.
        if (pi5_paging.walk(root.addr, cursor)) |existing| {
            const existing_bytes: u64 = switch (existing.kind) {
                .block_1g => paging.PAGE1G,
                .block_2m => paging.PAGE2M,
                .page_4k => paging.PAGE4K,
            };
            if (existing_bytes > step) {
                log.str("      *** ");
                log.hex(cursor);
                log.str(" already covered by a coarser mapping (");
                log.size(existing_bytes);
                log.str("); refusing to split it\n");
                return error.OverlappingGranularity;
            }
        }

        try arch.paging.mapPageBoot(
            root,
            PAddr.fromInt(cursor),
            VAddr.fromInt(cursor),
            chosen,
            perms,
            kind,
            alloc,
        );
        cursor += step;
    }
    syncTables();
}

/// Make freshly written descriptors visible to the hardware table walker.
///
/// `mapPageBoot` installs descriptors with a plain store and no trailing barrier.
/// That is sufficient everywhere the UEFI loader uses it, because there it only
/// ever populates a table that is not yet live — TTBR1 before `setKernelAddrSpace`
/// installs it. The moment a mapping is added to the CURRENTLY ACTIVE table and
/// dereferenced, the store must be ordered against the walker's reads or the
/// walker may still see the old invalid entry.
///
/// Measured: mapping the SoC PL011 into the live TTBR0_EL2 and immediately reading
/// its CR register faulted with DFSC=0x6 (translation fault) at exactly the address
/// just mapped. Every prior mapping in this loader went into the inactive TTBR1
/// root or was read back by the software walker as ordinary data, which is why this
/// only surfaced once a live-table mapping was dereferenced.
///
/// `tlbi alle2` rather than per-VA invalidation: this is boot-time, it runs a
/// handful of times, and a broad invalidate removes any question about cached
/// intermediate walk results for the new tables' parents.
pub fn syncTables() void {
    asm volatile (
        \\ dsb ishst
        \\ tlbi alle2
        \\ dsb ish
        \\ isb
        ::: .{ .memory = true });
}

/// Check, with translation still OFF, that the addresses this loader must keep
/// executing from actually translate identically.
///
/// This is the last chance to catch a bad table. After `enable()` a wrong mapping
/// faults on the very next instruction fetch, with translation broken and the
/// early log unreachable — indistinguishable from a hang, and a hang on this board
/// costs a physical power cycle plus the log.
pub fn verifyIdentity(ttbr0_root: u64, probes: []const u64) bool {
    var ok = true;
    for (probes) |va| {
        if (!pi5_paging.expect(ttbr0_root, va, va, "identity")) ok = false;
    }
    return ok;
}

/// Program MAIR/TCR/TTBR0 and set SCTLR_EL2.{M,C,I}.
///
/// The barrier discipline matters and follows Linux arm64's `__enable_mmu`:
/// system-register writes must be visible before the TLB is touched, the TLB must
/// be clean before translation starts, and the SCTLR write needs an `isb` after it
/// or the next instruction may still be fetched under the old regime.
pub fn enable(ttbr0_root: u64) void {
    // MAIR before anything can be translated through it. This is the only legal
    // window to write MAIR at all — see MAIR_VALUE's comment.
    //
    // MAIR_EL1 is programmed here too, even though nothing runs at EL1 yet,
    // because the kernel's `initMairIndices()` READS MAIR_EL1 and there will be no
    // other opportunity to establish it with the MMU off.
    asm volatile (
        \\ msr mair_el2, %[mair]
        \\ msr mair_el1, %[mair]
        \\ msr tcr_el2,  %[tcr]
        \\ msr ttbr0_el2, %[ttbr0]
        \\ isb
        :
        : [mair] "r" (MAIR_VALUE),
          [tcr] "r" (TCR_EL2_VALUE),
          [ttbr0] "r" (ttbr0_root),
        : .{ .memory = true });

    // Invalidate everything: firmware ran with the MMU off but may have left
    // stale entries, and this core's caches may hold clean lines for addresses
    // whose attributes just changed.
    asm volatile (
        \\ dsb sy
        \\ tlbi alle2
        \\ dsb sy
        \\ ic  iallu
        \\ dsb sy
        \\ isb
        ::: .{ .memory = true });

    const sctlr = readSysreg("sctlr_el2") | SCTLR_M | SCTLR_C | SCTLR_I;
    asm volatile (
        \\ msr sctlr_el2, %[v]
        \\ isb
        :
        : [v] "r" (sctlr),
        : .{ .memory = true });
}

pub fn dumpState(label: []const u8) void {
    log.str("    ");
    log.str(label);
    log.str(": SCTLR_EL2 = ");
    log.hex(readSysreg("sctlr_el2"));
    log.str(", TCR_EL2 = ");
    log.hex(readSysreg("tcr_el2"));
    log.str(", MAIR_EL2 = ");
    log.hex(readSysreg("mair_el2"));
    log.byte('\n');
}
