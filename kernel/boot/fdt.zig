//! Flattened-devicetree reader for kernel-side device discovery.
//!
//! This is the kernel's answer to "where is my GIC, where is my UART" on
//! boards that ship no ACPI — the Raspberry Pi 5 above all. The ACPI path
//! (`arch/aarch64/acpi.zig`) reads MADT/SPCR and is untouched by this
//! file; together with `arch/aarch64/dt_discovery.zig` this provides the
//! parallel route, and `arch/dispatch/boot.zig` picks between them.
//!
//! Deliberately `std`-only: no `@import("stygia")` anywhere in this file.
//! Two reasons.
//!   1. It classifies as `generic` for the arch-layering analyzer, so any
//!      future arch or loader can share it without violating the tier
//!      rules.
//!   2. It is directly testable on the host against a real DTB. The
//!      `ranges` translation below is the most error-prone piece of this
//!      subsystem and the target hardware cannot yet run the kernel, so
//!      exercising it under `zig test` against a byte-for-byte copy of the
//!      board's own blob is the only real check that exists.
//!
//! Traps this parser is built around, all of which yield plausible-looking
//! garbage rather than an error if you get them wrong:
//!
//!   - **Cell counts are per-parent, never global.** The Pi 5 root is
//!     `#address-cells=2, #size-cells=1`, `/soc` is 1/1 and `/axi` is 2/2.
//!     `/memory@0`'s `reg` is therefore 24 bytes (2 entries × 12), not 32.
//!     Assuming the conventional 2/2 misparses it silently.
//!   - **`reg` addresses are bus-local.** `/soc/serial@7d001000` declares
//!     `reg = <0x7d001000 0x200>`, but the CPU must access it at
//!     `0x10_7d001000`; the delta comes from `/soc`'s `ranges`. Skipping
//!     translation yields an address that looks entirely reasonable and
//!     either faults or, worse, hits a different peripheral.
//!   - **The root node consumes a depth level.** It is an `FDT_BEGIN_NODE`
//!     with an empty name, so `/soc` lives at depth 2, not depth 1.
//!   - **Property order within a node is not guaranteed.** `compatible`
//!     may follow `reg`. Properties do all precede subnodes (DT spec
//!     §5.4.2), so a node's full property set is known by the time its
//!     first child opens — which is where matching is evaluated.
//!
//! Spec: Devicetree Specification v0.4 — §2.3 (standard properties),
//! §2.3.8 (`ranges`), §3.8 (`/cpus`), §5 (flattened format).
//!
//! There is a second, narrower FDT reader in `bootloader/pi5/dtb.zig`;
//! see the note at the bottom of this file for why.

const std = @import("std");

pub const Error = error{
    /// Header magic was not 0xd00dfeed — the pointer is not a DTB.
    BadMagic,
    /// `last_comp_version` is newer than this reader understands.
    UnsupportedVersion,
    /// Header offsets/sizes point outside the blob, or the structure
    /// block ran off its end mid-token.
    Truncated,
    /// A cell count outside {1, 2} appeared somewhere that must be
    /// decoded (e.g. a PCI bus's 3-cell child addresses), or a property
    /// length was not a whole multiple of its entry stride.
    BadCells,
    /// The structure block nests deeper than `MAX_DEPTH`.
    TooDeep,
    /// No node matched the requested compatible strings.
    NoMatch,
    /// A matched node's `reg` address falls outside every `ranges` entry
    /// of one of its ancestor buses, so it has no CPU-physical address.
    NoTranslation,
};

/// FDT header field offsets (DT spec §5.2). All big-endian u32.
const H_MAGIC = 0x00;
const H_TOTALSIZE = 0x04;
const H_OFF_DT_STRUCT = 0x08;
const H_OFF_DT_STRINGS = 0x0C;
const H_LAST_COMP_VERSION = 0x18;
const H_SIZE_DT_STRUCT = 0x24;
const HEADER_SIZE = 0x28;

const FDT_MAGIC: u32 = 0xd00d_feed;

/// Structure-block tokens (DT spec §5.4.1).
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// Maximum node nesting the walker tracks. The Pi 5 blob's deepest path
/// (`/axi/pcie@120000/rp1/<bus>/<device>`) sits at depth 6; 16 leaves
/// plenty of headroom while keeping the frame stack a fixed few-hundred-
/// byte stack object — this runs on the kernel's boot stack.
pub const MAX_DEPTH: usize = 16;

/// A `reg` entry whose address has been translated to CPU-physical.
pub const Region = struct {
    base: u64,
    size: u64,
};

/// PSCI conduit, from `/psci`'s `method` property (DT binding
/// `arm/psci.yaml`).
pub const PsciMethod = enum { smc, hvc };

/// Read a `cells`-wide big-endian integer from the front of `bytes`.
///
/// DT permits 1 or 2 cells for every address/size field this reader
/// decodes; 3-cell PCI addresses and the 0-cell form (`#size-cells = 0`,
/// used by `/cpus` for sizes) are rejected rather than guessed at.
fn readCells(bytes: []const u8, cells: u32) Error!u64 {
    return switch (cells) {
        1 => if (bytes.len < 4)
            Error.Truncated
        else
            @as(u64, std.mem.readInt(u32, bytes[0..4], .big)),
        2 => if (bytes.len < 8)
            Error.Truncated
        else
            std.mem.readInt(u64, bytes[0..8], .big),
        else => Error.BadCells,
    };
}

fn be32(bytes: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, bytes[off..][0..4], .big);
}

fn align4(v: u64) u64 {
    return (v + 3) & ~@as(u64, 3);
}

/// The bus context a node inherits from its parent. `frames[1]` is the
/// root node; `frames[0]` holds the DT spec §2.3.5 defaults the root
/// inherits when it declares neither property.
const Frame = struct {
    address_cells: u32,
    size_cells: u32,
    /// The node's own `ranges` property bytes, or null when absent.
    /// Absent and empty are different: empty means identity, absent
    /// means the child address space is not mapped into the parent's at
    /// all (DT spec §2.3.8).
    ranges: ?[]const u8,
};

fn checkHeader(bytes: []const u8) Error!void {
    if (be32(bytes, H_MAGIC) != FDT_MAGIC) return Error.BadMagic;
    // Checking `last_comp_version` rather than `version` is the spec's
    // intent (§5.2): it states the oldest version this blob is
    // backward-compatible with. v16 introduced the current structure
    // encoding and v17 added the size fields; every real DTB reports 16.
    if (be32(bytes, H_LAST_COMP_VERSION) > 17) return Error.UnsupportedVersion;
}

/// Validate a DTB header and return its `totalsize`.
///
/// Split out from `Fdt.init` for the chicken-and-egg the kernel glue
/// faces: the blob's length lives inside the blob, so one page must be
/// mapped and inspected before the caller knows how much to map. Accepts
/// whatever prefix the caller has; only the first 40 bytes are touched.
pub fn totalSize(header: []const u8) Error!u32 {
    if (header.len < HEADER_SIZE) return Error.Truncated;
    try checkHeader(header);
    const totalsize = be32(header, H_TOTALSIZE);
    if (totalsize < HEADER_SIZE) return Error.Truncated;
    return totalsize;
}

pub const Fdt = struct {
    bytes: []const u8,
    off_struct: u32,
    size_struct: u32,
    off_strings: u32,

    /// Validate the header and bind a reader to the blob.
    ///
    /// Every offset is checked against the slice the caller actually
    /// mapped, not merely against the blob's self-reported `totalsize`:
    /// a short mapping with a large `totalsize` would otherwise walk off
    /// the end of the physmap window and fault in early boot.
    pub fn init(bytes: []const u8) Error!Fdt {
        if (bytes.len < HEADER_SIZE) return Error.Truncated;
        try checkHeader(bytes);

        const totalsize: u64 = be32(bytes, H_TOTALSIZE);
        const off_struct: u64 = be32(bytes, H_OFF_DT_STRUCT);
        const size_struct: u64 = be32(bytes, H_SIZE_DT_STRUCT);
        const off_strings: u64 = be32(bytes, H_OFF_DT_STRINGS);

        if (totalsize > bytes.len) return Error.Truncated;
        // u64 arithmetic throughout: both operands are attacker-supplied
        // u32s and their sum overflows u32 on a crafted blob.
        if (off_struct + size_struct > totalsize) return Error.Truncated;
        if (off_strings > totalsize) return Error.Truncated;

        return .{
            .bytes = bytes,
            .off_struct = @intCast(off_struct),
            .size_struct = @intCast(size_struct),
            .off_strings = @intCast(off_strings),
        };
    }

    /// A NUL-terminated string from the strings block.
    fn stringAt(self: *const Fdt, nameoff: u32) []const u8 {
        const start: u64 = @as(u64, self.off_strings) + nameoff;
        if (start >= self.bytes.len) return "";
        const rest = self.bytes[@intCast(start)..];
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
        return rest[0..end];
    }
};

// ── Structure-block walker ──────────────────────────────────────────────

/// One structure-block event. Slices borrow from the blob; there are no
/// copies and no allocation anywhere in this file.
pub const Event = union(enum) {
    node_begin: struct { name: []const u8, depth: usize },
    prop: struct { name: []const u8, data: []const u8, depth: usize },
    node_end: struct { depth: usize },
};

/// Streaming walker over the structure block, maintaining the
/// parent-cells / `ranges` frame stack that address translation needs.
///
/// The walker owns the two pieces of bookkeeping every query would
/// otherwise get wrong independently: depth (the root is a real node, so
/// its children sit at depth 2) and inherited cell counts. Queries below
/// consume events and never touch raw tokens.
pub const Walker = struct {
    fdt: *const Fdt,
    pos: u64,
    end: u64,
    depth: usize = 0,
    frames: [MAX_DEPTH + 1]Frame = undefined,

    pub fn init(fdt: *const Fdt) Walker {
        var w: Walker = .{
            .fdt = fdt,
            .pos = fdt.off_struct,
            .end = @as(u64, fdt.off_struct) + fdt.size_struct,
        };
        // DT spec §2.3.5 defaults, inherited by the root when it declares
        // neither property. The Pi 5 root really is 2/1, so this must not
        // be hardcoded to the more common 2/2 anywhere.
        w.frames[0] = .{ .address_cells = 2, .size_cells = 1, .ranges = null };
        return w;
    }

    /// Advance to the next event, or null at FDT_END / end of block.
    pub fn next(self: *Walker) Error!?Event {
        while (true) {
            if (self.pos + 4 > self.end) return null;
            const token = be32(self.fdt.bytes, @intCast(self.pos));
            self.pos += 4;

            switch (token) {
                FDT_NOP => continue,
                FDT_END => return null,

                FDT_BEGIN_NODE => {
                    if (self.pos >= self.end) return Error.Truncated;
                    const rest = self.fdt.bytes[@intCast(self.pos)..];
                    const name_len = std.mem.indexOfScalar(u8, rest, 0) orelse
                        return Error.Truncated;
                    const name = rest[0..name_len];
                    self.pos = align4(self.pos + name_len + 1);
                    if (self.pos > self.end) return Error.Truncated;

                    if (self.depth + 1 > MAX_DEPTH) return Error.TooDeep;
                    const parent = self.frames[self.depth];
                    self.depth += 1;
                    // Cells are inherited until the child overrides them
                    // with its own properties; `ranges` is never inherited.
                    self.frames[self.depth] = .{
                        .address_cells = parent.address_cells,
                        .size_cells = parent.size_cells,
                        .ranges = null,
                    };
                    return .{ .node_begin = .{ .name = name, .depth = self.depth } };
                },

                FDT_END_NODE => {
                    if (self.depth == 0) return Error.Truncated;
                    const d = self.depth;
                    self.depth -= 1;
                    return .{ .node_end = .{ .depth = d } };
                },

                FDT_PROP => {
                    if (self.pos + 8 > self.end) return Error.Truncated;
                    const prop_len: u64 = be32(self.fdt.bytes, @intCast(self.pos));
                    const nameoff = be32(self.fdt.bytes, @intCast(self.pos + 4));
                    const data_off = self.pos + 8;
                    if (data_off + prop_len > self.fdt.bytes.len) return Error.Truncated;
                    self.pos = align4(data_off + prop_len);
                    if (self.pos > self.end) return Error.Truncated;
                    // A property outside any node is malformed; the frame
                    // stack has nowhere to put it.
                    if (self.depth == 0) return Error.Truncated;

                    const data = self.fdt.bytes[@intCast(data_off)..][0..@intCast(prop_len)];
                    const name = self.fdt.stringAt(nameoff);

                    // Standard properties that shape the frame stack are
                    // applied here so every query sees them for free.
                    if (prop_len == 4 and std.mem.eql(u8, name, "#address-cells")) {
                        self.frames[self.depth].address_cells =
                            std.mem.readInt(u32, data[0..4], .big);
                    } else if (prop_len == 4 and std.mem.eql(u8, name, "#size-cells")) {
                        self.frames[self.depth].size_cells =
                            std.mem.readInt(u32, data[0..4], .big);
                    } else if (std.mem.eql(u8, name, "ranges")) {
                        self.frames[self.depth].ranges = data;
                    }

                    return .{ .prop = .{ .name = name, .data = data, .depth = self.depth } };
                },

                // An unrecognized token means we lost sync with the
                // structure block; anything decoded from here on would be
                // fabricated.
                else => return Error.Truncated,
            }
        }
    }
};

// ── Address translation ─────────────────────────────────────────────────

/// Outcome of walking a bus-local address up to CPU-physical.
const Translation = struct {
    addr: u64,
    /// Ancestor bus levels crossed as identity because they declared no
    /// `ranges` at all. Per DT spec §2.3.8 that formally means the child
    /// address space is *not* mapped into the parent's; treating it as
    /// identity is the pragmatic choice every OS makes, but the caller
    /// should say so out loud, since it is a guess rather than a reading.
    identity_levels: usize,
};

/// Translate a bus-local `reg` address to CPU-physical by walking the
/// `ranges` of every ancestor bus.
///
/// `depth` is the matched node's own depth; its addresses live in
/// `frames[depth - 1]`'s address space (the *parent bus*, never the
/// node's own cells). The walk stops at the root, whose address space IS
/// CPU-physical — the root's own `ranges` is never consulted. A node that
/// is a direct child of the root (depth 2) therefore needs no work.
///
/// `size` participates only in the containment check; sizes are never
/// translated (DT spec §2.3.8).
fn translateUp(
    frames: []const Frame,
    depth: usize,
    addr_in: u64,
    size: u64,
) Error!Translation {
    var addr = addr_in;
    var identity_levels: usize = 0;

    // `i - 1` is the bus level being crossed and `i - 2` its parent, so
    // the loop runs from the node's parent bus down to (but excluding)
    // the root. Phrased in terms of `i >= 3` to keep the two indices
    // non-negative without a signed counter.
    var i: usize = depth;
    while (i >= 3) : (i -= 1) {
        const bus = frames[i - 1];
        const parent = frames[i - 2];

        const ranges = bus.ranges orelse {
            identity_levels += 1;
            continue;
        };
        // An empty `ranges` is the explicit identity mapping.
        if (ranges.len == 0) continue;

        const ac_child = bus.address_cells;
        const ac_parent = parent.address_cells;
        const sc_child = bus.size_cells;
        // Rejects PCI's 3-cell child addresses, among other things. A
        // device behind such a bus is skipped by the caller rather than
        // mistranslated.
        if (ac_child == 0 or ac_child > 2) return Error.BadCells;
        if (ac_parent == 0 or ac_parent > 2) return Error.BadCells;
        if (sc_child == 0 or sc_child > 2) return Error.BadCells;

        // Note the asymmetry: the parent-address width comes from the
        // GRANDPARENT frame. `/soc` is 1/1 under a 2-cell root, so its
        // entries are 1 + 2 + 1 = 4 cells (16 bytes), not 12.
        const stride: usize = 4 * @as(usize, ac_child + ac_parent + sc_child);
        if (ranges.len % stride != 0) return Error.BadCells;

        var off: usize = 0;
        var matched = false;
        while (off + stride <= ranges.len) : (off += stride) {
            const e = ranges[off..][0..stride];
            const child_base = try readCells(e, ac_child);
            const parent_base = try readCells(e[4 * ac_child ..], ac_parent);
            const window = try readCells(e[4 * (ac_child + ac_parent) ..], sc_child);

            if (addr < child_base) continue;
            const rel = addr - child_base;
            // Contain the whole `reg` entry, not just its base: a region
            // straddling the end of a `ranges` window is not translatable.
            if (rel > window) continue;
            if (window - rel < size) continue;

            addr = parent_base + rel;
            matched = true;
            break;
        }
        if (!matched) return Error.NoTranslation;
    }

    return .{ .addr = addr, .identity_levels = identity_levels };
}

// ── Queries ─────────────────────────────────────────────────────────────

/// Result of a successful `findCompatible`.
pub const Match = struct {
    /// Number of `reg` entries written to the caller's buffer. Capped by
    /// the buffer length: a GIC node listing GICD/GICC/GICH/GICV fills
    /// only as many as the caller asked for.
    regs: usize,
    /// See `Translation.identity_levels`. Non-zero means at least one
    /// address was assumed rather than translated — worth logging.
    identity_levels: usize,
};

/// Does a NUL-separated `compatible` stringlist contain an exact match
/// for any of `wanted`?
///
/// Exact, never prefix: the Pi 5's RP1 UARTs are `"arm,pl011-axi"` and
/// must NOT be selected by a search for `"arm,pl011"`. They sit behind
/// PCIe (3-cell addresses, untranslatable here) and are not the debug
/// console.
fn compatibleMatches(list: []const u8, wanted: []const []const u8) bool {
    var rest = list;
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
        const entry = rest[0..end];
        for (wanted) |w| {
            if (std.mem.eql(u8, entry, w)) return true;
        }
        if (end == rest.len) break;
        rest = rest[end + 1 ..];
    }
    return false;
}

/// Is this `status` value usable? Absent counts as usable (DT spec
/// §2.3.4 default). The Pi 5's two spare PL011s say `"disabled"` and must
/// be skipped, or the kernel prints into a UART with no clock and no pins.
fn statusEnabled(status: ?[]const u8) bool {
    const s = status orelse return true;
    const end = std.mem.indexOfScalar(u8, s, 0) orelse s.len;
    const v = s[0..end];
    return std.mem.eql(u8, v, "okay") or std.mem.eql(u8, v, "ok");
}

/// The subset of a node's properties `findCompatible` needs, captured
/// while its property region is being scanned and evaluated once that
/// region closes.
const Candidate = struct {
    depth: usize = 0,
    compatible: ?[]const u8 = null,
    reg: ?[]const u8 = null,
    status: ?[]const u8 = null,

    /// Evaluate this node. Returns null when it is not a match, or when
    /// it matches but its `reg` cannot be decoded or translated — in
    /// which case the caller keeps walking. That policy is deliberate: a
    /// single malformed node in a 3000-node vendor blob must not cost the
    /// kernel its console.
    fn evaluate(
        self: Candidate,
        frames: []const Frame,
        compatibles: []const []const u8,
        require_enabled: bool,
        regs_out: []Region,
    ) ?Match {
        const compatible = self.compatible orelse return null;
        if (!compatibleMatches(compatible, compatibles)) return null;
        if (require_enabled and !statusEnabled(self.status)) return null;
        const reg = self.reg orelse return null;
        if (self.depth < 2) return null;

        // `reg` is expressed in the PARENT bus's cells, never the node's
        // own — the single most common way to misparse a DTB.
        const ac = frames[self.depth - 1].address_cells;
        const sc = frames[self.depth - 1].size_cells;
        if (ac == 0 or ac > 2 or sc == 0 or sc > 2) return null;
        const stride: usize = 4 * @as(usize, ac + sc);
        if (reg.len == 0 or reg.len % stride != 0) return null;

        var count: usize = 0;
        var identity_levels: usize = 0;
        var off: usize = 0;
        while (off + stride <= reg.len and count < regs_out.len) : (off += stride) {
            const e = reg[off..][0..stride];
            const raw_base = readCells(e, ac) catch return null;
            const size = readCells(e[4 * ac ..], sc) catch return null;
            const t = translateUp(frames, self.depth, raw_base, size) catch return null;
            identity_levels += t.identity_levels;
            regs_out[count] = .{ .base = t.addr, .size = size };
            count += 1;
        }
        if (count == 0) return null;

        return .{ .regs = count, .identity_levels = identity_levels };
    }
};

/// Find the first node whose `compatible` list contains any of
/// `compatibles`, and write its `reg` entries — translated to
/// CPU-physical — into `regs_out`.
///
/// `require_enabled` gates on `status` (see `statusEnabled`).
pub fn findCompatible(
    fdt: *const Fdt,
    compatibles: []const []const u8,
    require_enabled: bool,
    regs_out: []Region,
) Error!Match {
    var w = Walker.init(fdt);

    // Properties all precede subnodes, so only the innermost open node
    // can still be accumulating them and one slot suffices. The node's
    // property region closes at its first child's FDT_BEGIN_NODE or at
    // its own FDT_END_NODE, whichever comes first; evaluation happens
    // there, BEFORE the event is allowed to mutate `cur`.
    var open = false;
    var cur: Candidate = .{};

    while (try w.next()) |ev| {
        const closes = open and switch (ev) {
            .node_begin => |n| n.depth > cur.depth,
            .node_end => |n| n.depth <= cur.depth,
            .prop => false,
        };
        if (closes) {
            open = false;
            // `w.frames[0 .. cur.depth]` is what `evaluate` reads; a
            // child's FDT_BEGIN_NODE has already pushed frames[depth+1]
            // by now, which is above everything consulted.
            if (cur.evaluate(&w.frames, compatibles, require_enabled, regs_out)) |m| {
                return m;
            }
        }

        switch (ev) {
            .node_begin => |n| {
                open = true;
                cur = .{ .depth = n.depth };
            },
            .prop => |p| {
                if (std.mem.eql(u8, p.name, "compatible")) {
                    cur.compatible = p.data;
                } else if (std.mem.eql(u8, p.name, "reg")) {
                    cur.reg = p.data;
                } else if (std.mem.eql(u8, p.name, "status")) {
                    cur.status = p.data;
                }
            },
            .node_end => {},
        }
    }

    return Error.NoMatch;
}

/// Collect MPIDR values from `/cpus/cpu@N` `reg` properties. Returns how
/// many were written.
///
/// A CPU node's `reg` is its MPIDR-derived ID expressed in `/cpus`'s
/// `#address-cells`, and is explicitly NOT subject to `ranges`
/// translation: `/cpus` has no `ranges` and the value is an identifier,
/// not an address (DT spec §3.8).
///
/// Malformed entries are skipped rather than fatal — a short core list is
/// recoverable, a failed parse of the whole tree is not.
pub fn cpuMpidrs(fdt: *const Fdt, out: []u64) usize {
    var w = Walker.init(fdt);
    var count: usize = 0;
    var cpus_depth: ?usize = null;
    var cpu_node_depth: ?usize = null;

    while (w.next() catch null) |ev| {
        switch (ev) {
            .node_begin => |n| {
                if (cpus_depth) |cd| {
                    // Only direct children of /cpus. Deeper descendants
                    // (e.g. per-core `l2-cache` nodes) have `reg`
                    // properties that mean something else entirely.
                    cpu_node_depth = if (n.depth == cd + 1 and isCpuNodeName(n.name))
                        n.depth
                    else
                        null;
                } else if (n.depth == 2 and std.mem.eql(u8, n.name, "cpus")) {
                    // `/cpus` is a child of the root, hence depth 2.
                    cpus_depth = n.depth;
                }
            },
            .node_end => |n| {
                if (cpus_depth) |cd| {
                    if (n.depth <= cd) cpus_depth = null;
                }
                if (cpu_node_depth) |cnd| {
                    if (n.depth <= cnd) cpu_node_depth = null;
                }
            },
            .prop => |p| {
                const cnd = cpu_node_depth orelse continue;
                if (p.depth != cnd) continue;
                if (!std.mem.eql(u8, p.name, "reg")) continue;
                if (count >= out.len) continue;
                const v = readCells(p.data, w.frames[p.depth - 1].address_cells) catch
                    continue;
                out[count] = v;
                count += 1;
            },
        }
    }
    return count;
}

/// Matches both the bare `cpu` form and the conventional `cpu@N`.
/// Deliberately not a bare `startsWith("cpu")`, which would also swallow
/// `cpu-map` and `cpus`-adjacent vendor nodes.
fn isCpuNodeName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "cpu")) return true;
    return std.mem.startsWith(u8, name, "cpu@");
}

/// Read the PSCI conduit from `/psci`'s `method` property.
///
/// Null when there is no `/psci` node or its `method` is unrecognized;
/// the caller should then leave the conduit at its default rather than
/// guess, matching how `acpi.parseFadt` treats a non-PSCI-compliant FADT.
pub fn psciMethod(fdt: *const Fdt) ?PsciMethod {
    var w = Walker.init(fdt);
    var psci_depth: ?usize = null;

    while (w.next() catch null) |ev| {
        switch (ev) {
            .node_begin => |n| {
                // Matched by name at depth 2 rather than by compatible:
                // the node is `/psci` on every platform that has one
                // (Pi 5, QEMU virt), while the compatible string varies
                // across PSCI revisions ("arm,psci-1.0", "arm,psci-0.2",
                // "arm,psci") in ways the conduit does not depend on.
                if (psci_depth == null and n.depth == 2 and
                    std.mem.eql(u8, n.name, "psci"))
                {
                    psci_depth = n.depth;
                }
            },
            .node_end => |n| {
                const pd = psci_depth orelse continue;
                // Left `/psci` without finding a usable `method`.
                if (n.depth <= pd) return null;
            },
            .prop => |p| {
                const pd = psci_depth orelse continue;
                if (p.depth != pd) continue;
                if (!std.mem.eql(u8, p.name, "method")) continue;
                const end = std.mem.indexOfScalar(u8, p.data, 0) orelse p.data.len;
                const v = p.data[0..end];
                if (std.mem.eql(u8, v, "smc")) return .smc;
                if (std.mem.eql(u8, v, "hvc")) return .hvc;
                return null;
            },
        }
    }
    return null;
}

// ── Why there are two FDT readers in this tree ──────────────────────────
//
// `bootloader/pi5/dtb.zig` parses the same blob for a different purpose
// (synthesizing `BootInfo.mmap` from `/memory` and the reservation lists)
// under a fundamentally different access model: the loader runs with the
// MMU OFF, where every access is Device-nGnRnE and must be a volatile
// load from a physical address. This file reads through a mapped physmap
// VA as ordinary Normal memory, using `std.mem.readInt` over a
// `[]const u8` slice.
//
// A single parser would have to abstract over the access method — a
// comptime-parameterized reader threaded through every helper — which
// costs more complexity than the ~80-line token walk it would save. The
// two are kept in sync by hand, and the split is arranged so only the
// walk is duplicated: the risky logic (exact-match `compatible`, `status`
// gating, and `ranges` translation) exists only here, where it is
// host-testable against the real blob.
