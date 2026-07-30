//! Bare-metal page allocator for the Raspberry Pi 5 native boot path.
//!
//! The UEFI loader gets pages from `bs.allocatePages` and gets a memory map
//! that already accounts for them, because UEFI tracks every allocation and
//! `getMemoryMap` runs LAST — after the page tables, the kernel image and the
//! stack have all been claimed. Neither half of that exists here. There is no
//! firmware allocator, and the map is something this loader synthesizes itself,
//! so the same ordering has to be arranged by hand:
//!
//!   1. Parse the DTB and build a PRELIMINARY map (reservations known so far:
//!      ATF, loader image, DTB blob, early log).
//!   2. Pick the largest free span in that map as the arena and bump through it.
//!   3. Allocate page tables, kernel image pages, stack.
//!   4. Rebuild the map with `usedRange()` reserved. THAT map goes to the kernel.
//!
//! Step 4 is not optional and its absence would not be obvious: the kernel would
//! boot, run for a while on a map that calls its own page tables free memory,
//! and then corrupt itself from the physical allocator at some unrelated later
//! moment. The preliminary map from step 1 must be treated as scratch — it
//! shares static storage with the final one and is overwritten by step 4.
//!
//! Bump-only, no reclaim. `resize`/`remap`/`free` are `unreachable`, matching
//! the UEFI allocator's contract: nothing on the boot path frees, and a silent
//! no-op free would be worse than a crash if that ever changed.

const std = @import("std");
const stygia = @import("stygia");

const dtb = @import("dtb.zig");
const log = @import("early_log.zig");

const paging = stygia.memory.paging;

pub const PAGE: u64 = paging.PAGE4K;

pub const Error = error{
    /// No free span in the preliminary map was large enough to be worth using.
    NoArena,
};

/// Smallest arena worth proceeding with.
///
/// Not a computed requirement — the real floor is "kernel image + stack + page
/// tables", which is not known until the ELF is parsed. This is a sanity bound
/// that fails loudly and early if the map synthesis produced something absurd,
/// rather than letting the allocator starve halfway through mapping the kernel
/// where the symptom is a half-built page table.
pub const MIN_ARENA: u64 = 16 * 1024 * 1024;

/// A contiguous run of physical pages, handed out low to high.
///
/// Deliberately not a global: the arena's extent has to be threaded into the
/// final `buildMMap` call, and a global invites a code path that allocates
/// before the arena is chosen — which would silently hand out whatever `next`
/// happened to be, i.e. physical address 0, i.e. ATF.
pub const Arena = struct {
    base: u64,
    next: u64,
    limit: u64,
    /// Pages successfully handed out. Only for the log; `next` is the truth.
    pages: u64,
    /// Latched on the first failed request. `alloc` can only return null — it
    /// cannot say why — so the reason is recorded here and logged at the point
    /// of failure, because `error.OutOfMemory` surfacing out of `mapPageBoot`
    /// several frames up is indistinguishable from a dozen other failures.
    starved: bool,

    pub fn init(span: dtb.Range) Error!Arena {
        if (span.size < MIN_ARENA) return Error.NoArena;
        // The span comes from a descriptor, so it is already page aligned. Align
        // anyway: this is the one invariant every allocation below inherits, and
        // asserting it here is cheaper than debugging a misaligned page table.
        const base = (span.base + PAGE - 1) & ~(PAGE - 1);
        const limit = span.end() & ~(PAGE - 1);
        if (limit <= base or limit - base < MIN_ARENA) return Error.NoArena;
        return .{
            .base = base,
            .next = base,
            .limit = limit,
            .pages = 0,
            .starved = false,
        };
    }

    /// The span to reserve in the final map: everything handed out so far.
    ///
    /// Returns the USED extent, not the whole arena, so the kernel gets the
    /// hundreds of megabytes this loader did not touch.
    pub fn usedRange(self: *const Arena) dtb.Range {
        return .{ .base = self.base, .size = self.next - self.base };
    }

    pub fn usedBytes(self: *const Arena) u64 {
        return self.next - self.base;
    }

    pub fn allocator(self: *Arena) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: u64,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *Arena = @ptrCast(@alignCast(ptr));
        const align_bytes = alignment.toByteUnits();

        std.debug.assert(len > 0);
        // Same bound the UEFI allocator asserts. Everything on this path wants
        // page alignment or less; honouring more would need a search, and
        // silently under-aligning a page table is unrecoverable.
        std.debug.assert(align_bytes <= PAGE);

        const size = (len + PAGE - 1) & ~(PAGE - 1);
        if (size > self.limit - self.next) {
            if (!self.starved) {
                self.starved = true;
                log.str("  *** page arena exhausted: wanted ");
                log.size(size);
                log.str(", ");
                log.size(self.limit - self.next);
                log.str(" left of ");
                log.size(self.limit - self.base);
                log.byte('\n');
                log.commit();
            }
            return null;
        }

        const addr = self.next;
        self.next += size;
        self.pages += size / PAGE;

        // Zero before handing out. DRAM on this board demonstrably survives a
        // warm reset, so arena pages come up holding the PREVIOUS boot's page
        // tables — stale valid-looking descriptors, which is the worst possible
        // garbage to leave in a table that only partially gets overwritten.
        // `mapPageBoot` memsets its own tables, but the kernel-image and stack
        // pages have no such guarantee, and a partially-copied final page of a
        // section would otherwise carry last boot's bytes into the kernel.
        const p: [*]u8 = @ptrFromInt(@as(usize, @intCast(addr)));
        @memset(p[0..@intCast(size)], 0);
        return p;
    }

    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) void {
        _ = ptr;
        _ = buf;
        _ = alignment;
        _ = ret_addr;
        unreachable;
    }

    pub fn dump(self: *const Arena) void {
        log.str("  page arena ");
        log.hex(self.base);
        log.str(" .. ");
        log.hex(self.limit);
        log.str("  (");
        log.size(self.limit - self.base);
        log.str(" available)\n");
        log.str("    used ");
        log.size(self.usedBytes());
        log.str(" in ");
        log.dec(self.pages);
        log.str(" pages, next = ");
        log.hex(self.next);
        log.byte('\n');
        if (self.starved) log.str("    *** STARVED\n");
    }
};
