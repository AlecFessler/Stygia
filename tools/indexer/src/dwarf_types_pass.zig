//! DWARF type / struct-field ingest. Walks the `.debug_info` section of the
//! kernel ELF and emits:
//!
//!   * one `type` row per type DIE (struct/union/enum/array/pointer/base/etc.)
//!   * one `type_field` row per DW_TAG_member (with the constant byte offset
//!     pulled from `DW_AT_data_member_location`)
//!   * one `dwarf_die` row per ingested DIE, keyed on its byte offset in
//!     `.debug_info`, mapping that offset to an entity_id when we managed to
//!     match the DIE's qualified `DW_AT_name` against the entity table
//!
//! This is the bridge that lets a downstream tool resolve, e.g.,
//! `sched.scheduler.core_states[0].current_ec` purely via SQL: variable
//! address from `bin_symbol`, element stride from the array's element type
//! `size`, field offset from `type_field.offset`.
//!
//! Intentional scope:
//!   * DWARF v4 only (the kernel build emits v4). We don't try to support v5
//!     `strx`/`addrx`/`loclistx` indirection.
//!   * `data_member_location` is read only when the form is a constant
//!     (data1/data2/data4/data8/udata/sdata/implicit_const). Members whose
//!     location is a DWARF expression (rare for non-bitfield struct
//!     members) get NULL offset.
//!   * Unions: members are emitted with their DWARF data_member_location
//!     (typically 0 across the board); offset semantics are union-correct.
//!   * Bitfields (DW_AT_bit_offset / DW_AT_data_bit_offset / DW_AT_bit_size):
//!     not modeled separately. The byte offset is still emitted; bit-level
//!     consumers will need to revisit if/when that matters.

const std = @import("std");
const types = @import("types.zig");
const dwarf = std.dwarf;
const elf = std.elf;

const TypeRow = types.TypeRow;
const TypeFieldRow = types.TypeFieldRow;
const DwarfDieRow = types.DwarfDieRow;

pub const PassResult = struct {
    types: []TypeRow,
    type_fields: []TypeFieldRow,
    dwarf_dies: []DwarfDieRow,
};

pub fn pass(
    palloc: std.mem.Allocator,
    elf_path: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) !PassResult {
    const file_bytes = try readFile(palloc, elf_path);

    const sections = try findDwarfSections(file_bytes);

    var ingest: Ingest = .{
        .palloc = palloc,
        .debug_info = sections.debug_info orelse return error.MissingDebugInfo,
        .debug_abbrev = sections.debug_abbrev orelse return error.MissingDebugAbbrev,
        .debug_str = sections.debug_str orelse "",
        .debug_line_str = sections.debug_line_str orelse "",
        .entity_by_qname = entity_by_qname,
    };
    try ingest.run();

    return .{
        .types = try ingest.type_rows.toOwnedSlice(palloc),
        .type_fields = try ingest.field_rows.toOwnedSlice(palloc),
        .dwarf_dies = try ingest.die_rows.toOwnedSlice(palloc),
    };
}

fn readFile(palloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const stat = try f.stat();
    const buf = try palloc.alloc(u8, @intCast(stat.size));
    const n = try f.readAll(buf);
    if (n != buf.len) return error.ShortRead;
    return buf;
}

const DwarfSections = struct {
    debug_info: ?[]const u8,
    debug_abbrev: ?[]const u8,
    debug_str: ?[]const u8,
    debug_line_str: ?[]const u8,
};

fn findDwarfSections(bytes: []const u8) !DwarfSections {
    var out: DwarfSections = .{
        .debug_info = null,
        .debug_abbrev = null,
        .debug_str = null,
        .debug_line_str = null,
    };

    var fbs = std.io.fixedBufferStream(bytes);
    var reader_buf: [@sizeOf(elf.Elf64_Ehdr)]u8 = undefined;
    var io_reader = fbs.reader().adaptToNewApi(&reader_buf);
    const hdr = try elf.Header.read(&io_reader.new_interface);

    if (!hdr.is_64) return error.UnsupportedElfClass;

    // Section headers are at hdr.shoff, hdr.shnum entries of hdr.shentsize.
    if (hdr.shoff + @as(u64, hdr.shnum) * hdr.shentsize > bytes.len) return error.TruncatedElf;

    // Find the section name string table (`.shstrtab`).
    if (hdr.shstrndx == elf.SHN_UNDEF) return error.MissingSectionNames;
    const shstr_off = hdr.shoff + @as(u64, hdr.shstrndx) * hdr.shentsize;
    const shstr_shdr = try readShdr(bytes, shstr_off, hdr.endian);
    const shstrtab = bytes[@intCast(shstr_shdr.sh_offset)..][0..@intCast(shstr_shdr.sh_size)];

    var i: u16 = 0;
    while (i < hdr.shnum) {
        const off = hdr.shoff + @as(u64, i) * hdr.shentsize;
        const shdr = try readShdr(bytes, off, hdr.endian);

        // Skip SHT_NOBITS (no payload in the file).
        if (shdr.sh_type == elf.SHT_NOBITS) {
            i += 1;
            continue;
        }
        if (shdr.sh_offset + shdr.sh_size > bytes.len) {
            i += 1;
            continue;
        }

        const name = readCString(shstrtab, shdr.sh_name);
        const data = bytes[@intCast(shdr.sh_offset)..][0..@intCast(shdr.sh_size)];

        if (std.mem.eql(u8, name, ".debug_info")) out.debug_info = data;
        if (std.mem.eql(u8, name, ".debug_abbrev")) out.debug_abbrev = data;
        if (std.mem.eql(u8, name, ".debug_str")) out.debug_str = data;
        if (std.mem.eql(u8, name, ".debug_line_str")) out.debug_line_str = data;

        i += 1;
    }
    return out;
}

fn readShdr(bytes: []const u8, off: u64, endian: std.builtin.Endian) !elf.Elf64_Shdr {
    const sz = @sizeOf(elf.Elf64_Shdr);
    if (off + sz > bytes.len) return error.TruncatedElf;
    const raw = bytes[@intCast(off)..][0..sz];
    var shdr: elf.Elf64_Shdr = undefined;
    @memcpy(std.mem.asBytes(&shdr), raw);
    if (endian != @import("builtin").cpu.arch.endian()) {
        std.mem.byteSwapAllFields(elf.Elf64_Shdr, &shdr);
    }
    return shdr;
}

fn readCString(table: []const u8, off: u32) []const u8 {
    if (off >= table.len) return "";
    const start = off;
    var end = start;
    while (end < table.len and table[end] != 0) : (end += 1) {}
    return table[start..end];
}

// ── Ingest core ──────────────────────────────────────────────────────────

const Abbrev = struct {
    code: u64,
    tag: u64,
    has_children: bool,
    attrs: []AttrSpec,
};

const AttrSpec = struct {
    id: u64,
    form: u64,
    /// Only valid when form == FORM.implicit_const.
    payload: i64 = 0,
};

/// Decoded form value. Only the variants we actually use are populated.
const Value = union(enum) {
    none: void,
    addr: u64,
    udata: u64,
    sdata: i64,
    /// String slice into `.debug_str`, `.debug_line_str`, or inline.
    string: []const u8,
    /// Block bytes (DW_FORM_block*, DW_FORM_exprloc).
    block: []const u8,
    /// CU-relative DIE offset (DW_FORM_ref*).
    ref_cu: u64,
    /// .debug_info-absolute DIE offset (DW_FORM_ref_addr).
    ref_abs: u64,
    flag: bool,
    sec_offset: u64,
};

const Ingest = struct {
    palloc: std.mem.Allocator,
    debug_info: []const u8,
    debug_abbrev: []const u8,
    debug_str: []const u8,
    debug_line_str: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),

    type_rows: std.ArrayList(TypeRow) = .empty,
    field_rows: std.ArrayList(TypeFieldRow) = .empty,
    die_rows: std.ArrayList(DwarfDieRow) = .empty,
    /// Maps DIE byte offset (in `.debug_info`) → type_id assigned by us.
    /// Allows DW_AT_type back-references to resolve to a type_ref.
    die_to_type: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    next_type_id: u32 = 1,

    fn run(self: *Ingest) !void {
        var pos: usize = 0;
        while (pos < self.debug_info.len) {
            const cu_start = pos;
            const len32 = readU32(self.debug_info, &pos);
            var unit_len: u64 = len32;
            var is_dwarf64 = false;
            if (len32 == 0xffffffff) {
                unit_len = readU64(self.debug_info, &pos);
                is_dwarf64 = true;
            } else if (len32 == 0) {
                // Padding / end of section.
                break;
            }
            const header_size: usize = if (is_dwarf64) 12 else 4;
            const cu_end = cu_start + header_size + unit_len;
            if (cu_end > self.debug_info.len) return error.TruncatedDebugInfo;

            // CU header (DWARF v4): version u16, debug_abbrev_offset (u32 / u64), addr_size u8.
            const version = readU16(self.debug_info, &pos);
            const abbrev_off: u64 = if (is_dwarf64)
                readU64(self.debug_info, &pos)
            else
                @as(u64, readU32(self.debug_info, &pos));
            const addr_size = self.debug_info[pos];
            pos += 1;

            // DWARF v5 has an extra unit_type byte before abbrev_off; we don't
            // expect it (kernel build emits v4) but skip the CU if we hit it.
            if (version > 4) {
                pos = cu_end;
                continue;
            }

            const abbrev_table = try self.parseAbbrevTable(abbrev_off);
            defer self.palloc.free(abbrev_table);

            try self.walkDies(&pos, cu_start, cu_end, abbrev_table, addr_size, is_dwarf64, null, null);

            pos = cu_end;
        }
    }

    fn parseAbbrevTable(self: *Ingest, off: u64) ![]Abbrev {
        var list: std.ArrayList(Abbrev) = .empty;
        var pos: usize = @intCast(off);
        while (pos < self.debug_abbrev.len) {
            const code = readUleb128(self.debug_abbrev, &pos);
            if (code == 0) break;
            const tag = readUleb128(self.debug_abbrev, &pos);
            if (pos >= self.debug_abbrev.len) return error.TruncatedAbbrev;
            const has_children = self.debug_abbrev[pos] != 0;
            pos += 1;

            var attrs: std.ArrayList(AttrSpec) = .empty;
            while (true) {
                const id = readUleb128(self.debug_abbrev, &pos);
                const form = readUleb128(self.debug_abbrev, &pos);
                if (id == 0 and form == 0) break;
                var payload: i64 = 0;
                if (form == dwarf.FORM.implicit_const) {
                    payload = readSleb128(self.debug_abbrev, &pos);
                }
                try attrs.append(self.palloc, .{ .id = id, .form = form, .payload = payload });
            }
            try list.append(self.palloc, .{
                .code = code,
                .tag = tag,
                .has_children = has_children,
                .attrs = try attrs.toOwnedSlice(self.palloc),
            });
        }
        return try list.toOwnedSlice(self.palloc);
    }

    fn findAbbrev(table: []const Abbrev, code: u64) ?*const Abbrev {
        for (table) |*a| {
            if (a.code == code) return a;
        }
        return null;
    }

    /// Walk DIE tree at `pos`. Recurses into children. `parent_die_offset` is
    /// the .debug_info offset of the enclosing DIE (null for the CU itself's
    /// children). `parent_type_id`, when non-null, is the type_id of the
    /// enclosing container (struct/union/enum) — DW_TAG_member children of
    /// such a parent emit `type_field` rows linked to it.
    ///
    /// Returns when it consumes the terminating null entry that closes the
    /// current sibling list.
    fn walkDies(
        self: *Ingest,
        pos: *usize,
        cu_start: usize,
        cu_end: usize,
        abbrev_table: []const Abbrev,
        addr_size: u8,
        is_dwarf64: bool,
        parent_die_offset: ?u64,
        parent_type_id: ?u32,
    ) !void {
        // Field index counter for member emission within a container parent.
        var ctx_field_idx: u32 = 0;

        while (pos.* < cu_end) {
            const die_off: u64 = pos.*;
            const code = readUleb128(self.debug_info, pos);
            if (code == 0) {
                // End of sibling list.
                return;
            }
            const abbrev = findAbbrev(abbrev_table, code) orelse return error.UnknownAbbrev;

            // Decode all attributes into a small fixed-size attr map keyed on
            // AT id; we look up only the ones we care about.
            var name_val: ?[]const u8 = null;
            var linkage_name_val: ?[]const u8 = null;
            var byte_size_val: ?u64 = null;
            var alignment_val: ?u64 = null;
            var data_member_loc_val: ?u64 = null;
            var data_member_loc_ok: bool = true;
            var type_ref_val: ?u64 = null; // resolved to absolute .debug_info offset

            for (abbrev.attrs) |attr| {
                const v = try self.readForm(pos, attr.form, attr.payload, addr_size, is_dwarf64);
                switch (attr.id) {
                    dwarf.AT.name => name_val = takeString(v),
                    dwarf.AT.linkage_name => linkage_name_val = takeString(v),
                    dwarf.AT.byte_size => byte_size_val = takeUnsigned(v),
                    dwarf.AT.alignment => alignment_val = takeUnsigned(v),
                    dwarf.AT.data_member_location => {
                        if (takeUnsignedOnly(v)) |u| {
                            data_member_loc_val = u;
                        } else if (takeBlock(v)) |_| {
                            // A DWARF expression — we don't evaluate it.
                            data_member_loc_ok = false;
                        } else {
                            data_member_loc_ok = false;
                        }
                    },
                    dwarf.AT.@"type" => {
                        switch (v) {
                            .ref_cu => |off| type_ref_val = cu_start + off,
                            .ref_abs => |off| type_ref_val = off,
                            else => {},
                        }
                    },
                    else => {},
                }
            }

            // Emit type / member / die rows depending on tag.
            const tag = abbrev.tag;

            // Determine if this DIE is a "type" we want to emit.
            const is_type_kind: ?[]const u8 = switch (tag) {
                dwarf.TAG.structure_type => "struct",
                dwarf.TAG.union_type => "union",
                dwarf.TAG.enumeration_type => "enum",
                dwarf.TAG.array_type => "array",
                dwarf.TAG.pointer_type => "pointer",
                dwarf.TAG.base_type => "primitive",
                dwarf.TAG.typedef => "typedef",
                dwarf.TAG.const_type => "const",
                dwarf.TAG.subroutine_type => "subroutine",
                else => null,
            };

            var assigned_type_id: ?u32 = null;
            if (is_type_kind) |kind_str| {
                const tid = self.next_type_id;
                self.next_type_id += 1;

                // Match DWARF qualified name against entity table.
                const qname: ?[]const u8 = name_val;
                const eid: ?u32 = if (qname) |n| self.entity_by_qname.get(n) else null;

                try self.type_rows.append(self.palloc, .{
                    .id = tid,
                    .entity_id = eid,
                    .kind = kind_str,
                    .size = byte_size_val,
                    .alignment = if (alignment_val) |a| @intCast(a) else null,
                });
                try self.die_to_type.put(self.palloc, die_off, tid);
                assigned_type_id = tid;

                if (eid) |entity_id| {
                    try self.die_rows.append(self.palloc, .{
                        .offset = die_off,
                        .entity_id = entity_id,
                        .tag = tagName(tag),
                        .parent_offset = parent_die_offset,
                    });
                }
            }

            // Variables / subprograms: emit dwarf_die row matching by linkage_name.
            if (tag == dwarf.TAG.variable or tag == dwarf.TAG.subprogram) {
                const lookup_name: ?[]const u8 = linkage_name_val orelse name_val;
                if (lookup_name) |n| {
                    if (self.entity_by_qname.get(n)) |entity_id| {
                        try self.die_rows.append(self.palloc, .{
                            .offset = die_off,
                            .entity_id = entity_id,
                            .tag = tagName(tag),
                            .parent_offset = parent_die_offset,
                        });
                    }
                }
            }

            // For DW_TAG_member inside a struct/union, emit a type_field row.
            if (tag == dwarf.TAG.member and parent_type_id != null) {
                const fname = if (name_val) |n| try self.palloc.dupe(u8, n) else "";
                const offset_to_store: ?u64 = if (data_member_loc_ok) data_member_loc_val else null;
                const ref_to_store: ?u32 = blk: {
                    if (type_ref_val) |off| {
                        if (self.die_to_type.get(off)) |tid| break :blk tid;
                    }
                    break :blk null;
                };
                try self.field_rows.append(self.palloc, .{
                    .type_id = parent_type_id.?,
                    .idx = ctx_field_idx,
                    .name = fname,
                    .offset = offset_to_store,
                    .type_ref = ref_to_store,
                });
                ctx_field_idx += 1;
            }

            // DW_TAG_subrange_type carries the array element count via
            // DW_AT_count or DW_AT_upper_bound. Zig's DWARF emitter doesn't
            // populate DW_AT_byte_size on the parent array_type, so the
            // array's `size` row stays NULL. Consumers who need the array's
            // total byte size compute element_size * count themselves
            // (subrange counts can be read out of `.debug_info` if needed).

            // Recurse into children. Pass `assigned_type_id` as parent_type_id
            // when the current DIE is a container/array — this is the
            // critical link that lets the child sibling list see its parent.
            if (abbrev.has_children) {
                const child_parent_type_id: ?u32 = blk: {
                    if (assigned_type_id) |tid| {
                        if (tag == dwarf.TAG.structure_type or
                            tag == dwarf.TAG.union_type or
                            tag == dwarf.TAG.enumeration_type or
                            tag == dwarf.TAG.array_type)
                        {
                            break :blk tid;
                        }
                    }
                    break :blk null;
                };
                try self.walkDies(pos, cu_start, cu_end, abbrev_table, addr_size, is_dwarf64, die_off, child_parent_type_id);
            }
        }
    }


    /// Read one form value. Mutates `pos`. Many forms we don't fully decode
    /// but we still need to advance past them.
    fn readForm(
        self: *Ingest,
        pos: *usize,
        form: u64,
        implicit_const: i64,
        addr_size: u8,
        is_dwarf64: bool,
    ) !Value {
        switch (form) {
            dwarf.FORM.addr => {
                const v: u64 = switch (addr_size) {
                    4 => @as(u64, readU32(self.debug_info, pos)),
                    8 => readU64(self.debug_info, pos),
                    else => return error.UnsupportedAddrSize,
                };
                return .{ .addr = v };
            },
            dwarf.FORM.data1 => return .{ .udata = self.debug_info[advance(pos, 1)] },
            dwarf.FORM.data2 => return .{ .udata = readU16(self.debug_info, pos) },
            dwarf.FORM.data4 => return .{ .udata = readU32(self.debug_info, pos) },
            dwarf.FORM.data8 => return .{ .udata = readU64(self.debug_info, pos) },
            dwarf.FORM.data16 => {
                pos.* += 16;
                return .{ .none = {} };
            },
            dwarf.FORM.udata => return .{ .udata = readUleb128(self.debug_info, pos) },
            dwarf.FORM.sdata => return .{ .sdata = readSleb128(self.debug_info, pos) },
            dwarf.FORM.implicit_const => return .{ .sdata = implicit_const },
            dwarf.FORM.flag => return .{ .flag = self.debug_info[advance(pos, 1)] != 0 },
            dwarf.FORM.flag_present => return .{ .flag = true },
            dwarf.FORM.string => {
                const start = pos.*;
                while (pos.* < self.debug_info.len and self.debug_info[pos.*] != 0) : (pos.* += 1) {}
                const s = self.debug_info[start..pos.*];
                pos.* += 1; // skip nul
                return .{ .string = s };
            },
            dwarf.FORM.strp => {
                const off = if (is_dwarf64) readU64(self.debug_info, pos) else @as(u64, readU32(self.debug_info, pos));
                return .{ .string = readCStrAt(self.debug_str, off) };
            },
            dwarf.FORM.line_strp => {
                const off = if (is_dwarf64) readU64(self.debug_info, pos) else @as(u64, readU32(self.debug_info, pos));
                return .{ .string = readCStrAt(self.debug_line_str, off) };
            },
            dwarf.FORM.ref1 => return .{ .ref_cu = self.debug_info[advance(pos, 1)] },
            dwarf.FORM.ref2 => return .{ .ref_cu = readU16(self.debug_info, pos) },
            dwarf.FORM.ref4 => return .{ .ref_cu = readU32(self.debug_info, pos) },
            dwarf.FORM.ref8 => return .{ .ref_cu = readU64(self.debug_info, pos) },
            dwarf.FORM.ref_udata => return .{ .ref_cu = readUleb128(self.debug_info, pos) },
            dwarf.FORM.ref_addr => {
                const off = if (is_dwarf64) readU64(self.debug_info, pos) else @as(u64, readU32(self.debug_info, pos));
                return .{ .ref_abs = off };
            },
            dwarf.FORM.sec_offset => {
                const off = if (is_dwarf64) readU64(self.debug_info, pos) else @as(u64, readU32(self.debug_info, pos));
                return .{ .sec_offset = off };
            },
            dwarf.FORM.block1 => {
                const len: usize = self.debug_info[advance(pos, 1)];
                const start = pos.*;
                pos.* += len;
                return .{ .block = self.debug_info[start .. start + len] };
            },
            dwarf.FORM.block2 => {
                const len: usize = readU16(self.debug_info, pos);
                const start = pos.*;
                pos.* += len;
                return .{ .block = self.debug_info[start .. start + len] };
            },
            dwarf.FORM.block4 => {
                const len: usize = readU32(self.debug_info, pos);
                const start = pos.*;
                pos.* += len;
                return .{ .block = self.debug_info[start .. start + len] };
            },
            dwarf.FORM.block, dwarf.FORM.exprloc => {
                const len: usize = @intCast(readUleb128(self.debug_info, pos));
                const start = pos.*;
                pos.* += len;
                return .{ .block = self.debug_info[start .. start + len] };
            },
            dwarf.FORM.indirect => {
                const real_form = readUleb128(self.debug_info, pos);
                return self.readForm(pos, real_form, implicit_const, addr_size, is_dwarf64);
            },
            // DWARF v5 forms — addr/strx/loclistx/rnglistx. Our build is v4 so
            // these shouldn't appear, but skip them gracefully if they do.
            dwarf.FORM.strx, dwarf.FORM.addrx, dwarf.FORM.loclistx, dwarf.FORM.rnglistx => {
                _ = readUleb128(self.debug_info, pos);
                return .{ .none = {} };
            },
            dwarf.FORM.strx1, dwarf.FORM.addrx1 => {
                pos.* += 1;
                return .{ .none = {} };
            },
            dwarf.FORM.strx2, dwarf.FORM.addrx2 => {
                pos.* += 2;
                return .{ .none = {} };
            },
            dwarf.FORM.strx3, dwarf.FORM.addrx3 => {
                pos.* += 3;
                return .{ .none = {} };
            },
            dwarf.FORM.strx4, dwarf.FORM.addrx4 => {
                pos.* += 4;
                return .{ .none = {} };
            },
            dwarf.FORM.ref_sig8 => {
                pos.* += 8;
                return .{ .none = {} };
            },
            else => return error.UnknownDwarfForm,
        }
    }
};

// ── Helper readers ──────────────────────────────────────────────────────

fn advance(pos: *usize, n: usize) usize {
    const cur = pos.*;
    pos.* += n;
    return cur;
}

fn readU16(buf: []const u8, pos: *usize) u16 {
    const v = std.mem.readInt(u16, buf[pos.*..][0..2], .little);
    pos.* += 2;
    return v;
}

fn readU32(buf: []const u8, pos: *usize) u32 {
    const v = std.mem.readInt(u32, buf[pos.*..][0..4], .little);
    pos.* += 4;
    return v;
}

fn readU64(buf: []const u8, pos: *usize) u64 {
    const v = std.mem.readInt(u64, buf[pos.*..][0..8], .little);
    pos.* += 8;
    return v;
}

fn readUleb128(buf: []const u8, pos: *usize) u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < buf.len) {
        const b = buf[pos.*];
        pos.* += 1;
        result |= @as(u64, b & 0x7f) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift >= 64) break;
    }
    return result;
}

fn readSleb128(buf: []const u8, pos: *usize) i64 {
    var result: i64 = 0;
    var shift: u6 = 0;
    var b: u8 = 0;
    while (pos.* < buf.len) {
        b = buf[pos.*];
        pos.* += 1;
        result |= @as(i64, b & 0x7f) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
        if (shift >= 64) break;
    }
    if (shift < 64 and (b & 0x40) != 0) {
        result |= @as(i64, -1) << shift;
    }
    return result;
}

fn readCStrAt(table: []const u8, off: u64) []const u8 {
    if (off >= table.len) return "";
    const start: usize = @intCast(off);
    var end = start;
    while (end < table.len and table[end] != 0) : (end += 1) {}
    return table[start..end];
}

// ── Value extractors ──────────────────────────────────────────────────────

fn takeString(v: Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn takeUnsigned(v: Value) ?u64 {
    return switch (v) {
        .udata => |u| u,
        .sdata => |s| if (s >= 0) @intCast(s) else null,
        .sec_offset => |o| o,
        else => null,
    };
}

/// Strict — doesn't accept block/exprloc.
fn takeUnsignedOnly(v: Value) ?u64 {
    return switch (v) {
        .udata => |u| u,
        .sdata => |s| if (s >= 0) @intCast(s) else null,
        else => null,
    };
}

fn takeBlock(v: Value) ?[]const u8 {
    return switch (v) {
        .block => |b| b,
        else => null,
    };
}

fn tagName(tag: u64) []const u8 {
    return switch (tag) {
        dwarf.TAG.structure_type => "structure_type",
        dwarf.TAG.union_type => "union_type",
        dwarf.TAG.enumeration_type => "enumeration_type",
        dwarf.TAG.array_type => "array_type",
        dwarf.TAG.pointer_type => "pointer_type",
        dwarf.TAG.base_type => "base_type",
        dwarf.TAG.typedef => "typedef",
        dwarf.TAG.const_type => "const_type",
        dwarf.TAG.subroutine_type => "subroutine_type",
        dwarf.TAG.variable => "variable",
        dwarf.TAG.subprogram => "subprogram",
        dwarf.TAG.member => "member",
        dwarf.TAG.subrange_type => "subrange_type",
        dwarf.TAG.enumerator => "enumerator",
        dwarf.TAG.compile_unit => "compile_unit",
        dwarf.TAG.namespace => "namespace",
        else => "other",
    };
}
