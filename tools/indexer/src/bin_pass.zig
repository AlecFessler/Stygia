const std = @import("std");
const types = @import("types.zig");

const BinSymbolRow = types.BinSymbolRow;
const BinInstRow = types.BinInstRow;
const DwarfLineRow = types.DwarfLineRow;

pub const PassResult = struct {
    bin_symbols: []BinSymbolRow,
    bin_insts: []BinInstRow,
    dwarf_lines: []DwarfLineRow,
};

/// Runs objdump three times against `elf_path` and produces bin_symbol,
/// bin_inst, and dwarf_line (coalesced) rows.
pub fn pass(
    palloc: std.mem.Allocator,
    elf_path: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
    file_by_basename: *const std.StringHashMapUnmanaged(u32),
) !PassResult {
    const sym_out = try runCmd(palloc, &.{ "objdump", "--syms", elf_path });
    const dis_out = try runCmd(palloc, &.{ "objdump", "-d", "-M", "intel", elf_path });
    const line_out = try runCmd(palloc, &.{ "objdump", "--dwarf=decodedline", elf_path });

    return .{
        .bin_symbols = try parseSymbols(palloc, sym_out, entity_by_qname),
        .bin_insts = try parseDisasm(palloc, dis_out),
        .dwarf_lines = try parseLines(palloc, line_out, file_by_basename),
    };
}

fn runCmd(palloc: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = palloc,
        .argv = argv,
        .max_output_bytes = 200 * 1024 * 1024,
    });
    if (result.term != .Exited or result.term.Exited != 0) {
        // Non-zero exit usually means an arch mismatch (e.g. an ARM ELF
        // passed to an x86 indexer run) which produces empty disasm /
        // symbol tables silently. Log the stderr so the cause is visible
        // and surface the failure as a hard error.
        std.log.err("{s} exited with non-zero status; stderr:\n{s}", .{ argv[0], result.stderr });
        return error.ObjdumpFailed;
    }
    return result.stdout;
}

// ── objdump --syms ────────────────────────────────────────────────────────

fn parseSymbols(
    palloc: std.mem.Allocator,
    text: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) ![]BinSymbolRow {
    var rows: std.ArrayList(BinSymbolRow) = .empty;
    var line_iter = std.mem.splitScalar(u8, text, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        if (line.len < 20) continue;

        // Format: "<addr> <flags...> <type> <section>\t<size> <name>"
        // The flags region carries a single-letter type indicator:
        //   'F' = function (in .text)
        //   'O' = object   (in .bss / .data / .rodata / .tdata / .tbss)
        const tab_idx = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        const head = line[0..tab_idx];
        const tail = line[tab_idx + 1 ..];

        // Address: first whitespace-separated token of head.
        const addr_end = std.mem.indexOfScalar(u8, head, ' ') orelse continue;
        const addr = std.fmt.parseInt(u64, head[0..addr_end], 16) catch continue;
        if (addr == 0) continue;

        // Section: last whitespace-separated token of head.
        const section_idx = std.mem.lastIndexOfScalar(u8, head, ' ') orelse continue;
        const section = head[section_idx + 1 ..];

        const is_fn = std.mem.indexOf(u8, head, " F ") != null and std.mem.eql(u8, section, ".text");
        const is_obj = std.mem.indexOf(u8, head, " O ") != null and isDataSection(section);
        if (!is_fn and !is_obj) continue;

        // Tail: "<size_hex> <name>"
        const size_end = std.mem.indexOfScalar(u8, tail, ' ') orelse continue;
        const size = std.fmt.parseInt(u64, tail[0..size_end], 16) catch continue;
        const name = std.mem.trimLeft(u8, tail[size_end + 1 ..], " \t");
        if (name.len == 0 or size == 0) continue;

        // Skip LLVM-internal builtins and Zig-internal anonymous globals.
        if (std.mem.startsWith(u8, name, "llvm.")) continue;
        if (std.mem.startsWith(u8, name, "__anon_")) continue;

        const stripped = stripMonoSuffix(name);
        const entity_id = entity_by_qname.get(stripped) orelse continue;

        try rows.append(palloc, .{
            .addr = addr,
            .entity_id = entity_id,
            .size = size,
            .section = try palloc.dupe(u8, section),
        });
    }
    return try rows.toOwnedSlice(palloc);
}

fn isDataSection(section: []const u8) bool {
    const data_sections = [_][]const u8{ ".bss", ".data", ".rodata", ".tdata", ".tbss" };
    for (data_sections) |s| {
        if (std.mem.eql(u8, section, s)) return true;
    }
    // Match `.rodata.cst*`, `.data.rel.ro`, etc. — common compiler-generated
    // data subsections.
    for (data_sections) |s| {
        if (std.mem.startsWith(u8, section, s) and section.len > s.len and section[s.len] == '.') return true;
    }
    return false;
}

// ── objdump -d -M intel ───────────────────────────────────────────────────

fn parseDisasm(palloc: std.mem.Allocator, text: []const u8) ![]BinInstRow {
    var rows: std.ArrayList(BinInstRow) = .empty;
    var line_iter = std.mem.splitScalar(u8, text, '\n');

    while (line_iter.next()) |raw_line| {
        // Instruction lines have format: "<hexaddr>:\t<bytes>\t<mnem> <ops>"
        // (tabs separating). Function header lines like "<addr> <name>:" have
        // a colon at the end with no tab — skip them.
        if (raw_line.len == 0) continue;
        if (!std.ascii.isHex(raw_line[0])) continue;

        const colon_idx = std.mem.indexOfScalar(u8, raw_line, ':') orelse continue;
        const addr_str = raw_line[0..colon_idx];
        const addr = std.fmt.parseInt(u64, addr_str, 16) catch continue;

        const after_colon = raw_line[colon_idx + 1 ..];
        // Format: \t<bytes>\t<mnemonic_and_operands>
        if (after_colon.len < 2 or after_colon[0] != '\t') continue;
        const after_tab = after_colon[1..];
        const second_tab = std.mem.indexOfScalar(u8, after_tab, '\t') orelse continue;

        const bytes_text = std.mem.trim(u8, after_tab[0..second_tab], " ");
        const insn_text = std.mem.trim(u8, after_tab[second_tab + 1 ..], " ");

        // Bytes are space-separated hex pairs. Pack them.
        const bytes = try parseHexBytes(palloc, bytes_text);

        // Split mnemonic and operands on first whitespace.
        const space_idx = std.mem.indexOfAny(u8, insn_text, " \t");
        const mnemonic = if (space_idx) |s| insn_text[0..s] else insn_text;
        const operands = if (space_idx) |s| std.mem.trimLeft(u8, insn_text[s..], " \t") else "";

        try rows.append(palloc, .{
            .addr = addr,
            .bytes = bytes,
            .mnemonic = try palloc.dupe(u8, mnemonic),
            .operands = try palloc.dupe(u8, operands),
        });
    }
    return try rows.toOwnedSlice(palloc);
}

fn parseHexBytes(palloc: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i + 1 < text.len) {
        // Skip whitespace.
        if (text[i] == ' ' or text[i] == '\t') {
            i += 1;
            continue;
        }
        if (!std.ascii.isHex(text[i]) or !std.ascii.isHex(text[i + 1])) break;
        const byte = std.fmt.parseInt(u8, text[i .. i + 2], 16) catch break;
        try out.append(palloc, byte);
        i += 2;
    }
    return try out.toOwnedSlice(palloc);
}

// ── objdump --dwarf=decodedline ───────────────────────────────────────────

fn parseLines(
    palloc: std.mem.Allocator,
    text: []const u8,
    file_by_basename: *const std.StringHashMapUnmanaged(u32),
) ![]DwarfLineRow {
    // First pass: parse raw entries (file, line, addr) sorted by addr.
    const RawEntry = struct {
        file_id: u32,
        line: u32,
        addr: u64,
    };
    var raw: std.ArrayList(RawEntry) = .empty;

    var line_iter = std.mem.splitScalar(u8, text, '\n');
    while (line_iter.next()) |raw_line| {
        if (raw_line.len == 0) continue;
        // Skip CU headers (lines ending with `:`) and section headers.
        if (raw_line[0] != ' ' and raw_line[0] != '\t') {
            // Most entry lines start with a non-space basename (e.g. "ubsan_rt.zig").
            // Only accept lines containing ".zig" or ".c" and a hex address.
        }

        // Tokenize on whitespace.
        var tok_iter = std.mem.tokenizeAny(u8, raw_line, " \t");
        const fname = tok_iter.next() orelse continue;
        const line_str = tok_iter.next() orelse continue;
        const addr_str = tok_iter.next() orelse continue;
        // Skip view + stmt flag tokens — we don't need them.

        if (!std.mem.endsWith(u8, fname, ".zig") and !std.mem.endsWith(u8, fname, ".c")) continue;
        const line_no = std.fmt.parseInt(u32, line_str, 10) catch continue;
        if (line_no == 0) continue; // end-of-statement markers
        if (!std.mem.startsWith(u8, addr_str, "0x")) continue;
        const addr = std.fmt.parseInt(u64, addr_str[2..], 16) catch continue;

        const file_id = file_by_basename.get(fname) orelse continue;
        try raw.append(palloc, .{ .file_id = file_id, .line = line_no, .addr = addr });
    }
    if (raw.items.len == 0) return &.{};

    // Sort by addr for coalescing. The line table is already mostly in order,
    // but multi-CU output can interleave.
    const Ctx = struct {
        fn lessThan(_: void, a: RawEntry, b: RawEntry) bool {
            return a.addr < b.addr;
        }
    };
    std.mem.sort(RawEntry, raw.items, {}, Ctx.lessThan);

    // Coalesce consecutive same-(file, line) into ranges.
    var rows: std.ArrayList(DwarfLineRow) = .empty;
    var cur_file: u32 = raw.items[0].file_id;
    var cur_line: u32 = raw.items[0].line;
    var cur_lo: u64 = raw.items[0].addr;
    var cur_hi: u64 = raw.items[0].addr;

    for (raw.items[1..]) |e| {
        if (e.file_id == cur_file and e.line == cur_line) {
            cur_hi = e.addr;
            continue;
        }
        // Close current range. addr_hi = e.addr - 1 since the new entry begins
        // at e.addr.
        try rows.append(palloc, .{
            .addr_lo = cur_lo,
            .addr_hi = e.addr -| 1,
            .file_id = cur_file,
            .line = cur_line,
            .col = null,
        });
        cur_file = e.file_id;
        cur_line = e.line;
        cur_lo = e.addr;
        cur_hi = e.addr;
    }
    // Final range — addr_hi unknown; use cur_hi (last seen addr) as placeholder.
    try rows.append(palloc, .{
        .addr_lo = cur_lo,
        .addr_hi = cur_hi,
        .file_id = cur_file,
        .line = cur_line,
        .col = null,
    });

    return try rows.toOwnedSlice(palloc);
}

fn stripMonoSuffix(name: []const u8) []const u8 {
    const SUFFIX_PREFIXES = [_][]const u8{ "__anon_", "__struct_", "__enum_", "__union_" };
    for (SUFFIX_PREFIXES) |pref| {
        if (std.mem.lastIndexOf(u8, name, pref)) |pos| {
            return name[0..pos];
        }
    }
    return name;
}
