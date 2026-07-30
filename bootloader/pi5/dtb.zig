//! Minimal flattened-devicetree reader for the Raspberry Pi 5 native loader.
//!
//! Scope is deliberately narrow: find the physical RAM ranges and the ranges we
//! must NOT hand to the kernel. That is everything needed to synthesize a
//! `BootInfo.mmap`, and nothing more. This is not a general FDT library and
//! should not grow into one — the UEFI path gets its map from firmware, so this
//! code exists solely because bare-metal boot has no other source of truth.
//!
//! Two traps on this board, both of which produce plausible-looking garbage
//! rather than an error if you get them wrong:
//!
//!   1. `/memory@0` is `#address-cells=2, #size-cells=1`, so its `reg` is
//!      **24 bytes, not 32**. Assuming the conventional 2/2 misparses it into
//!      nonsense ranges. Cell counts are read from the parent node, never
//!      assumed.
//!   2. ATF owns 0x0-0x7FFFF and provides PSCI. Handing that to the kernel's
//!      allocator means PSCI (and therefore SMP bring-up and SYSTEM_RESET)
//!      breaks the moment something allocates there. Reserved ranges come from
//!      both the FDT memory-reservation block and `/reserved-memory`.
//!
//! Spec: Devicetree Specification v0.4, §5 (Flattened Devicetree format).

const std = @import("std");

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TooManyRanges,
    NoMemoryNode,
    BadCellCount,
};

/// FDT header field offsets (DT spec §5.2). All big-endian u32.
const H_MAGIC = 0x00;
const H_TOTALSIZE = 0x04;
const H_OFF_DT_STRUCT = 0x08;
const H_OFF_DT_STRINGS = 0x0C;
const H_OFF_MEM_RSVMAP = 0x10;
const H_VERSION = 0x14;
const H_LAST_COMP_VERSION = 0x18;
const H_SIZE_DT_STRUCT = 0x24;

const FDT_MAGIC: u32 = 0xd00d_feed;

/// Structure-block tokens (DT spec §5.4.1).
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// Generous for this board (2 RAM ranges, a handful of reservations) while
/// staying small enough to live comfortably in .bss on a loader stack.
pub const MAX_RANGES = 32;

pub const Range = struct {
    base: u64,
    size: u64,

    pub fn end(self: Range) u64 {
        return self.base + self.size;
    }
};

pub const MemoryMap = struct {
    ram: [MAX_RANGES]Range = undefined,
    ram_len: usize = 0,
    reserved: [MAX_RANGES]Range = undefined,
    reserved_len: usize = 0,
    /// Count of `reg` properties we declined to parse because their length was
    /// not a whole multiple of the node's cell stride. Surfaced in the log rather
    /// than swallowed: a nonzero value means we may be missing a reservation,
    /// which is a correctness risk worth seeing even though it is not fatal.
    skipped_reg: usize = 0,

    fn addRam(self: *MemoryMap, r: Range) Error!void {
        if (self.ram_len >= MAX_RANGES) return Error.TooManyRanges;
        self.ram[self.ram_len] = r;
        self.ram_len += 1;
    }

    fn addReserved(self: *MemoryMap, r: Range) Error!void {
        if (self.reserved_len >= MAX_RANGES) return Error.TooManyRanges;
        self.reserved[self.reserved_len] = r;
        self.reserved_len += 1;
    }

    pub fn ramSlice(self: *const MemoryMap) []const Range {
        return self.ram[0..self.ram_len];
    }

    pub fn reservedSlice(self: *const MemoryMap) []const Range {
        return self.reserved[0..self.reserved_len];
    }
};

/// Big-endian reads. The DTB is big-endian regardless of CPU endianness, and
/// these go through volatile byte loads because the blob lives in memory the
/// MMU is not translating yet.
fn be32(addr: usize) u32 {
    const p: *volatile [4]u8 = @ptrFromInt(addr);
    const b = p.*;
    return (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) |
        (@as(u32, b[2]) << 8) | @as(u32, b[3]);
}

fn be64(addr: usize) u64 {
    return (@as(u64, be32(addr)) << 32) | @as(u64, be32(addr + 4));
}

/// Read a `cells`-wide big-endian integer. DT allows 1 or 2 cells for the
/// address/size fields we care about; anything else on this platform means we
/// have misidentified the node and should fail loudly rather than guess.
fn readCells(addr: usize, cells: u32) Error!u64 {
    return switch (cells) {
        1 => @as(u64, be32(addr)),
        2 => be64(addr),
        else => Error.BadCellCount,
    };
}

fn strEqlAt(addr: usize, want: []const u8) bool {
    for (want, 0..) |c, i| {
        const p: *volatile u8 = @ptrFromInt(addr + i);
        if (p.* != c) return false;
    }
    const term: *volatile u8 = @ptrFromInt(addr + want.len);
    return term.* == 0;
}

fn strStartsWithAt(addr: usize, prefix: []const u8) bool {
    for (prefix, 0..) |c, i| {
        const p: *volatile u8 = @ptrFromInt(addr + i);
        if (p.* != c) return false;
    }
    return true;
}

fn cstrLen(addr: usize) usize {
    var i: usize = 0;
    while (true) : (i += 1) {
        const p: *volatile u8 = @ptrFromInt(addr + i);
        if (p.* == 0) return i;
        // A missing terminator would otherwise walk off into unmapped memory.
        if (i > 4096) return i;
    }
}

fn align4(v: usize) usize {
    return (v + 3) & ~@as(usize, 3);
}

/// Per-node state the walker needs. Cell counts are inherited from the parent,
/// which is exactly why they cannot be assumed: `/` and `/reserved-memory`
/// advertise different values on this board.
const Frame = struct {
    address_cells: u32,
    size_cells: u32,
    /// True when this node (or an ancestor) is `/reserved-memory`, so `reg` on
    /// its children means "do not touch" rather than "usable RAM".
    in_reserved_memory: bool,
    /// True when this node is a `/memory` node whose `reg` is usable RAM.
    is_memory: bool,
};

/// Walk the FDT and collect RAM plus reserved ranges.
///
/// `dtb_phys` is the value firmware left in x0. Validate it before trusting it —
/// a bogus pointer here otherwise produces a memory map that looks structurally
/// fine and is entirely fictional.
pub fn parseMemory(dtb_phys: u64) Error!MemoryMap {
    const base: usize = @intCast(dtb_phys);

    if (be32(base + H_MAGIC) != FDT_MAGIC) return Error.BadMagic;

    // v16 introduced the current structure-block encoding; every real DTB is
    // >= 16. Checking last_comp_version rather than version is the spec's
    // intent: it states the oldest version this blob is compatible with.
    const last_comp = be32(base + H_LAST_COMP_VERSION);
    if (last_comp > 17) return Error.UnsupportedVersion;

    const totalsize = be32(base + H_TOTALSIZE);
    const off_struct = be32(base + H_OFF_DT_STRUCT);
    const off_strings = be32(base + H_OFF_DT_STRINGS);
    const size_struct = be32(base + H_SIZE_DT_STRUCT);
    if (off_struct + size_struct > totalsize) return Error.Truncated;

    var map: MemoryMap = .{};

    // ---- FDT memory reservation block (DT spec §5.3) --------------------
    // A null-terminated list of (address, size) 64-bit pairs. Separate from
    // /reserved-memory and easy to forget; both must be honoured.
    {
        var p: usize = base + be32(base + H_OFF_MEM_RSVMAP);
        while (true) {
            const addr = be64(p);
            const sz = be64(p + 8);
            if (addr == 0 and sz == 0) break;
            try map.addReserved(.{ .base = addr, .size = sz });
            p += 16;
            if (p > base + totalsize) return Error.Truncated;
        }
    }

    // ---- Structure block ------------------------------------------------
    const struct_begin = base + off_struct;
    const struct_end = struct_begin + size_struct;
    const strings_begin = base + off_strings;

    // Root defaults per DT spec §2.3.5 when the properties are absent. The real
    // values are read from the root node's own properties below.
    var stack: [16]Frame = undefined;
    var depth: usize = 0;
    stack[0] = .{
        .address_cells = 2,
        .size_cells = 1,
        .in_reserved_memory = false,
        .is_memory = false,
    };

    var p: usize = struct_begin;
    while (p < struct_end) {
        const token = be32(p);
        p += 4;

        switch (token) {
            FDT_NOP => {},

            FDT_BEGIN_NODE => {
                const name_addr = p;
                const name_len = cstrLen(name_addr);
                p = align4(p + name_len + 1);

                if (depth + 1 >= stack.len) return Error.Truncated;
                const parent = stack[depth];
                depth += 1;

                // A child inherits the parent's cell counts until it overrides
                // them with its own #address-cells/#size-cells properties.
                stack[depth] = .{
                    .address_cells = parent.address_cells,
                    .size_cells = parent.size_cells,
                    // Inherited so that direct children (depth 3) still see it,
                    // but only ever ORIGINATED at depth 2 — `/reserved-memory` is
                    // a child of root, and a same-named node elsewhere in the
                    // tree means something different.
                    .in_reserved_memory = parent.in_reserved_memory or
                        (depth == 2 and strEqlAt(name_addr, "reserved-memory")),
                    // Matches both "memory" and the unit-address form "memory@0".
                    //
                    // depth == 2, NOT 1: the root node is itself an FDT_BEGIN_NODE
                    // with an empty name, so it consumes depth 1 and its children
                    // land at depth 2. Getting this wrong made is_memory never
                    // fire, which is how the first parse attempt failed.
                    .is_memory = depth == 2 and strStartsWithAt(name_addr, "memory") and
                        (name_len == 6 or blk: {
                            const at: *volatile u8 = @ptrFromInt(name_addr + 6);
                            break :blk at.* == '@';
                        }),
                };
            },

            FDT_END_NODE => {
                if (depth == 0) return Error.Truncated;
                depth -= 1;
            },

            FDT_PROP => {
                const prop_len = be32(p);
                const nameoff = be32(p + 4);
                const prop_data = p + 8;
                p = align4(prop_data + prop_len);

                const prop_name = strings_begin + nameoff;

                if (strEqlAt(prop_name, "#address-cells") and prop_len == 4) {
                    stack[depth].address_cells = be32(prop_data);
                } else if (strEqlAt(prop_name, "#size-cells") and prop_len == 4) {
                    stack[depth].size_cells = be32(prop_data);
                } else if (strEqlAt(prop_name, "reg")) {
                    const frame = stack[depth];
                    const want_ram = frame.is_memory and !frame.in_reserved_memory;
                    // Only DIRECT children of /reserved-memory. Deeper descendants
                    // are device sub-nodes whose `reg` means something else
                    // entirely, and parsing those as reservations both wastes
                    // slots and can abort the walk.
                    const want_rsv = frame.in_reserved_memory and depth == 3;
                    if (want_ram or want_rsv) {
                        const ac = frame.address_cells;
                        const sc = frame.size_cells;
                        const stride = (ac + sc) * 4;

                        // A `reg` whose length is not a whole number of entries
                        // means our inherited cell counts do not describe this
                        // node. SKIP it rather than failing the whole parse:
                        // aborting here would leave the kernel with no memory map
                        // at all, which is strictly worse than possibly missing
                        // one reservation. The count is reported in the log so a
                        // miss is visible rather than silent.
                        //
                        // Deliberately not fatal even for a /memory node — if the
                        // RAM list ends up empty we fail later with NoMemoryNode,
                        // which is a far more specific diagnosis than
                        // BadCellCount from somewhere in a 2000-node tree.
                        if (stride == 0 or prop_len % stride != 0 or
                            (ac != 1 and ac != 2) or (sc != 1 and sc != 2))
                        {
                            map.skipped_reg += 1;
                        } else {
                            var i: u32 = 0;
                            while (i < prop_len / stride) : (i += 1) {
                                const entry = prop_data + i * stride;
                                const addr = try readCells(entry, ac);
                                const sz = try readCells(entry + ac * 4, sc);
                                if (sz == 0) continue;
                                if (want_ram) {
                                    try map.addRam(.{ .base = addr, .size = sz });
                                } else {
                                    // Running out of reservation slots is not
                                    // fatal on its own, but it does mean we might
                                    // hand the kernel memory it must not touch,
                                    // so let it propagate.
                                    try map.addReserved(.{ .base = addr, .size = sz });
                                }
                            }
                        }
                    }
                }
            },

            FDT_END => break,

            // An unrecognized token means we have lost sync with the structure
            // block. Continuing would emit fabricated ranges.
            else => return Error.Truncated,
        }
    }

    if (map.ram_len == 0) return Error.NoMemoryNode;
    return map;
}
