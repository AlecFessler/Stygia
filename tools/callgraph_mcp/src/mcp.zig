//! MCP (Model Context Protocol) stdio transport.
//!
//! Speaks JSON-RPC 2.0, line-delimited, over stdin/stdout — the wire
//! format Claude Code's MCP transport expects. Each tool call
//! dispatches into the local SQLite-backed handlers (see tools.zig)
//! against the per-(arch, commit_sha) DB built by tools/indexer.
//! This is the production callgraph MCP server; the in-memory daemon
//! at tools/callgraph/ that this replaces is gone.

const std = @import("std");

const tools = @import("tools.zig");

const PROTOCOL_VERSION = "2024-11-05";

const SERVER_INFO_JSON = "{\"name\":\"callgraph-mcp\",\"version\":\"0.1.0\"}";
const CAPABILITIES_JSON = "{\"tools\":{\"listChanged\":false},\"logging\":{}}";

const INSTRUCTIONS =
    "Callgraph index for the Zag kernel — SQLite-backed view over " ++
    "the per-(arch, commit_sha) DB built by tools/indexer. Provides " ++
    "structured queries over entities, ir_calls, entry points, AST, " ++
    "binaries, DWARF lines, and analyzer findings (lint_finding). " ++
    "Use these tools instead of Read/Grep/Glob when investigating " ++
    "kernel code; typically 5-20× cheaper in tokens.";

const TOOLS_JSON =
    \\[
    \\  {"name":"callgraph_arches","description":"List (arch, commit_sha) for every loaded callgraph DB.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"callgraph_find","description":"FTS5 substring search over entity.qualified_name. Returns name + kind + file:line.","inputSchema":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer"}},"required":["q"],"additionalProperties":false}},
    \\  {"name":"callgraph_loc","description":"Definition location for one function: path:def_line:def_col, with [inlined] when is_ast_only=1.","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"callgraph_src","description":"Function body sliced from file.source via def_byte_start..def_byte_end.","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"callgraph_callers","description":"Reverse callers from ir_call. Aggregates across generic_parent_id instantiations.","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"callgraph_reaches","description":"Recursive CTE on ir_call (direct/dispatch_x64/dispatch_aarch64). Returns yes/no + shortest path.","inputSchema":{"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"},"max_depth":{"type":"integer"}},"required":["from","to"],"additionalProperties":false}},
    \\  {"name":"callgraph_entries","description":"Entry points grouped by kind. Optional kind filter.","inputSchema":{"type":"object","properties":{"kind":{"type":"string"}},"additionalProperties":false}},
    \\  {"name":"callgraph_modules","description":"Cross-module call counts. min_edges threshold; direction = out|in|both.","inputSchema":{"type":"object","properties":{"level":{"type":"integer"},"min_edges":{"type":"integer"},"direction":{"type":"string"}},"additionalProperties":false}},
    \\  {"name":"callgraph_trace","description":"Recursive CTE on ir_call rooted at one fn; per-callsite ast_edge ancestor walk reveals enclosing if/else/while/for/switch_prong/block. Renders an indented tree with control-flow markers.","inputSchema":{"type":"object","properties":{"entry":{"type":"string"},"depth":{"type":"integer"},"hide_debug":{"type":"boolean"},"hide_library":{"type":"boolean"},"hide_assertions":{"type":"boolean"}},"required":["entry"],"additionalProperties":false}},
    \\  {"name":"callgraph_type","description":"Type definition: type table for the entity, plus alias chain (depth ≤4 via const_alias).","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"callgraph_src_bin","description":"Disassembly for a function — bin_inst over the symbol's address range, interleaved with `; file:line` markers when entering a new dwarf_line range.","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"callgraph_src_bin_at","description":"Source line → emitted instructions. file basename match against dwarf_line, then bin_inst over the joined ranges.","inputSchema":{"type":"object","properties":{"at":{"type":"string"}},"required":["at"],"additionalProperties":false}},
    \\  {"name":"callgraph_bin_dataflow_reg","description":"Linear scan of bin_inst over a fn's address range; regex over operands extracts register tokens. stop_at_call defaults true.","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"reg":{"type":"string"},"stop_at_call":{"type":"boolean"}},"required":["name","reg"],"additionalProperties":false}},
    \\  {"name":"callgraph_bin_addr2line","description":"Floor lookup — dwarf_line WHERE addr_lo <= ? ORDER BY addr_lo DESC LIMIT 1; symbol via bin_symbol.","inputSchema":{"type":"object","properties":{"addr":{"type":"string"}},"required":["addr"],"additionalProperties":false}},
    \\  {"name":"callgraph_commits","description":"Recent commits in the Zag repo. One commit per line: `<short_sha>  <iso8601_date>  <subject>` with a trailing `  [stale]` marker on commits older than the `-Demit_ir` build option. Limit defaults to 30 (max 500). Shells out to `git log` against the daemon's repo root.","inputSchema":{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}},
    \\  {"name":"callgraph_findings","description":"Query the lint_finding table populated by analyzer passes (genlock, dead_code). Filters: analyzer / rule / severity / file (path GLOB). One line per finding: `<analyzer>  [<severity>]  <rule>  <file>:<line>  <message>`. Useful for asking 'what dead code does X module have?' without re-running the analyzer.","inputSchema":{"type":"object","properties":{"analyzer":{"type":"string"},"rule":{"type":"string"},"severity":{"type":"string"},"file":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":2000}},"additionalProperties":false}}
    \\]
;

fn stripNewlines(comptime s: []const u8) []const u8 {
    @setEvalBranchQuota(s.len * 4);
    comptime var n: usize = 0;
    inline for (s) |c| if (c != '\n') {
        n += 1;
    };
    var buf: [n]u8 = undefined;
    comptime var i: usize = 0;
    inline for (s) |c| if (c != '\n') {
        buf[i] = c;
        i += 1;
    };
    const final = buf;
    return &final;
}

const TOOLS_JSON_FLAT: []const u8 = stripNewlines(TOOLS_JSON);

pub fn run(gpa: std.mem.Allocator, registry: *tools.Registry) !void {
    const stdin_handle = std.fs.File.stdin().handle;
    var stdout_buf: [16 * 1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const out = &stdout_writer.interface;

    var line_buf = std.ArrayList(u8){};
    defer line_buf.deinit(gpa);

    while (true) {
        line_buf.clearRetainingCapacity();
        const got = readLine(gpa, stdin_handle, &line_buf) catch return;
        if (!got) return;
        const line = std.mem.trim(u8, line_buf.items, " \t\r\n");
        if (line.len == 0) continue;

        handleMessage(gpa, registry, out, line) catch |err| {
            std.debug.print("callgraph mcp handler error: {s}\n", .{@errorName(err)});
        };
        try out.flush();
    }
}

fn handleMessage(
    gpa: std.mem.Allocator,
    registry: *tools.Registry,
    out: *std.io.Writer,
    line: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const al = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, al, line, .{}) catch |err| {
        std.debug.print("callgraph mcp parse error: {s}: {s}\n", .{ @errorName(err), line });
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return;
    const obj = root.object;

    const id_val: ?std.json.Value = if (obj.get("id")) |v| v else null;
    const method = (obj.get("method") orelse return).string;

    if (std.mem.eql(u8, method, "initialize")) {
        try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
        try writeIdJson(out, id_val);
        try out.writeAll(",\"result\":{\"protocolVersion\":\"" ++ PROTOCOL_VERSION ++
            "\",\"capabilities\":" ++ CAPABILITIES_JSON ++
            ",\"serverInfo\":" ++ SERVER_INFO_JSON ++ ",\"instructions\":");
        try writeJsonString(out, INSTRUCTIONS);
        try out.writeAll("}}\n");
        return;
    }
    if (std.mem.eql(u8, method, "notifications/initialized")) return;
    if (std.mem.eql(u8, method, "ping")) {
        try writeResultRaw(out, id_val, "{}");
        return;
    }
    if (std.mem.eql(u8, method, "shutdown")) {
        try writeResultRaw(out, id_val, "{}");
        return;
    }
    if (std.mem.eql(u8, method, "tools/list")) {
        try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
        try writeIdJson(out, id_val);
        try out.writeAll(",\"result\":{\"tools\":");
        try out.writeAll(TOOLS_JSON_FLAT);
        try out.writeAll("}}\n");
        return;
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        try handleToolCall(al, registry, out, id_val, obj.get("params"));
        return;
    }
    try writeError(out, id_val, -32601, "method not found");
}

fn handleToolCall(
    al: std.mem.Allocator,
    registry: *tools.Registry,
    out: *std.io.Writer,
    id_val: ?std.json.Value,
    params_opt: ?std.json.Value,
) !void {
    const params = params_opt orelse return writeError(out, id_val, -32602, "missing params");
    if (params != .object) return writeError(out, id_val, -32602, "params must be object");
    const name_v = params.object.get("name") orelse return writeError(out, id_val, -32602, "missing tool name");
    if (name_v != .string) return writeError(out, id_val, -32602, "name must be string");
    const tool_name = name_v.string;
    const tool_args = if (params.object.get("arguments")) |v| v else std.json.Value{ .null = {} };

    var body = std.ArrayList(u8){};
    defer body.deinit(al);

    const dispatched = registry.dispatch(al, tool_name, tool_args, &body) catch |err| {
        const msg = try std.fmt.allocPrint(al, "tool failed: {s}", .{@errorName(err)});
        return writeError(out, id_val, -32000, msg);
    };
    if (!dispatched) return writeError(out, id_val, -32601, "unknown tool");

    try writeToolText(out, id_val, body.items);
}

// ---------------------------------------------------------- JSON-RPC out

fn writeResultRaw(out: *std.io.Writer, id_val: ?std.json.Value, raw_result: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeIdJson(out, id_val);
    try out.writeAll(",\"result\":");
    try out.writeAll(raw_result);
    try out.writeAll("}\n");
}

fn writeError(out: *std.io.Writer, id_val: ?std.json.Value, code: i32, message: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeIdJson(out, id_val);
    try out.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
    try writeJsonString(out, message);
    try out.writeAll("}}\n");
}

fn writeToolText(out: *std.io.Writer, id_val: ?std.json.Value, body: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeIdJson(out, id_val);
    try out.writeAll(",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try writeJsonString(out, body);
    try out.writeAll("}]}}\n");
}

fn writeIdJson(out: *std.io.Writer, id_val: ?std.json.Value) !void {
    const v = id_val orelse {
        try out.writeAll("null");
        return;
    };
    switch (v) {
        .integer => |i| try out.print("{d}", .{i}),
        .string => |s| try writeJsonString(out, s),
        .null => try out.writeAll("null"),
        else => try out.writeAll("null"),
    }
}

fn writeJsonString(out: *std.io.Writer, s: []const u8) !void {
    try out.writeAll("\"");
    for (s) |ch| {
        switch (ch) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            0...0x07, 0x0b, 0x0e...0x1f => try out.print("\\u{x:0>4}", .{ch}),
            else => try out.writeAll(&[_]u8{ch}),
        }
    }
    try out.writeAll("\"");
}

fn readLine(
    gpa: std.mem.Allocator,
    fd: std.posix.fd_t,
    buf: *std.ArrayList(u8),
) !bool {
    var byte: [1]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &byte);
        if (n == 0) return buf.items.len > 0;
        if (byte[0] == '\n') return true;
        try buf.append(gpa, byte[0]);
    }
}
