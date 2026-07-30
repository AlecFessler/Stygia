//! Translation-table construction and verification for the Pi 5 native path.
//!
//! Table construction itself is NOT reimplemented here. `mapPageBoot` in
//! kernel/arch/aarch64/paging.zig already builds VMSAv8-64 tables, it is
//! reachable from this tier through `stygia.arch.dispatch`, and it carries fixes
//! this loader would otherwise have to rediscover — notably the single-store
//! descriptor install (stygia-rs6 mechanism 8), where computing a descriptor's
//! address after marking it valid left a window in which the walker could cache
//! a table entry pointing at physical 0. Reimplementing that would mean
//! reintroducing the bug.
//!
//! What this file adds is the part the UEFI path never needed: a way to check
//! the tables BEFORE trusting them. UEFI hands off with the MMU on and a working
//! identity map, so the loader edits a live, already-correct configuration. Here
//! the MMU is off and every table is built from nothing, so the first `msr
//! sctlr_el2` is a cliff — if the tables are wrong the core faults on the
//! instruction after it, with translation broken, and cannot even reach the
//! early log to say so. That failure is indistinguishable from a hang, and a
//! hang on this board costs a physical power cycle plus the log itself.
//!
//! So: walk the tables in software first, with the MMU still off, and compare
//! against what we intended to map. A wrong table then costs a log line.

const std = @import("std");
const stygia = @import("stygia");

const log = @import("early_log.zig");

/// VA bit positions of each translation level's index, top level first.
///
/// 4 KiB granule, T0SZ/T1SZ = 16 (48-bit VA), so all four levels are in play.
/// Note the kernel's paging module names these in the opposite order — its
/// `l3Idx` is the TOP level (shift 39) and `l0Idx` the bottom (shift 12) — so
/// this array is deliberately indexed by depth-from-root instead of borrowing
/// that naming, which reads backwards everywhere it is used.
const LEVEL_SHIFT = [4]u6{ 39, 30, 21, 12 };

/// Bits [47:12] of a descriptor: the output address.
const OA_MASK: u64 = 0x0000_FFFF_FFFF_F000;

pub const Descriptor = enum {
    /// Level 1 block: 1 GiB.
    block_1g,
    /// Level 2 block: 2 MiB.
    block_2m,
    /// Level 3 page: 4 KiB.
    page_4k,
};

pub const Translation = struct {
    /// Physical address the VA resolves to, offset within the block included.
    phys: u64,
    /// Granularity the walk terminated at.
    kind: Descriptor,
    /// The raw terminating descriptor, for attribute inspection.
    raw: u64,
    /// Depth the walk terminated at, 0 = root.
    depth: u8,
};

/// Resolve a VA through a table hierarchy by reading memory directly.
///
/// Physical addressing throughout, which is only correct because the MMU is off
/// — that is the whole point, and it is why this must run before SCTLR is
/// touched. Reads are volatile: these are freshly written descriptors in Device
/// memory, and the compiler has no idea the MMU is about to consume them.
///
/// Returns null if the walk hits an invalid descriptor, i.e. the VA is not
/// mapped. Note that this deliberately does NOT interpret TTBR0-vs-TTBR1
/// selection — the caller passes whichever root it means, because at this stage
/// neither TTBR is programmed yet.
pub fn walk(root_phys: u64, va: u64) ?Translation {
    var table_phys = root_phys;
    for (LEVEL_SHIFT, 0..) |shift, depth| {
        const idx: u64 = (va >> shift) & 0x1FF;
        const slot: *volatile u64 = @ptrFromInt(@as(usize, @intCast(table_phys + idx * 8)));
        const raw = slot.*;

        if ((raw & 1) == 0) return null;
        const is_table = (raw & 2) != 0;
        const oa = raw & OA_MASK;

        if (depth == 3) {
            // Level 3: bit 1 set means "page". A level 3 descriptor with bit 1
            // clear is architecturally reserved, not a block.
            if (!is_table) return null;
            return .{
                .phys = oa | (va & 0xFFF),
                .kind = .page_4k,
                .raw = raw,
                .depth = @intCast(depth),
            };
        }

        if (!is_table) {
            // Block descriptor. Only levels 1 and 2 may have one at 4 KiB
            // granule; a "block" at level 0 is reserved and means the table is
            // malformed, which is exactly the kind of thing this walk exists to
            // catch rather than let the hardware discover.
            if (depth == 0) return null;
            const size_mask = (@as(u64, 1) << shift) - 1;
            return .{
                .phys = oa | (va & size_mask),
                .kind = if (depth == 1) .block_1g else .block_2m,
                .raw = raw,
                .depth = @intCast(depth),
            };
        }

        table_phys = oa;
    }
    unreachable;
}

/// Check that `va` maps to `expect_phys`, logging either way.
///
/// Returns false on mismatch so the caller can accumulate a verdict rather than
/// stopping at the first problem: when a table is wrong it is usually wrong in a
/// pattern, and seeing all of the failures at once identifies the pattern in one
/// boot instead of one boot per mapping.
pub fn expect(root_phys: u64, va: u64, expect_phys: u64, what: []const u8) bool {
    log.str("    ");
    log.str(what);
    log.str(": ");
    log.hex(va);
    log.str(" -> ");
    if (walk(root_phys, va)) |t| {
        log.hex(t.phys);
        const kind = switch (t.kind) {
            .block_1g => " [1G]",
            .block_2m => " [2M]",
            .page_4k => " [4K]",
        };
        log.str(kind);
        if (t.phys == expect_phys) {
            log.str(" ok\n");
            return true;
        }
        log.str(" *** MISMATCH, expected ");
        log.hex(expect_phys);
        log.byte('\n');
        return false;
    }
    log.str("*** UNMAPPED, expected ");
    log.hex(expect_phys);
    log.byte('\n');
    return false;
}
