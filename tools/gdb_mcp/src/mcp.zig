//! MCP (Model Context Protocol) stdio transport for gdb_mcp.
//!
//! Speaks JSON-RPC 2.0, line-delimited, over stdin/stdout — same wire format
//! the callgraph MCP uses; this module is a near-copy of that one with the
//! gdb tool surface and dispatch.

const std = @import("std");

const tools = @import("tools.zig");

const PROTOCOL_VERSION = "2024-11-05";

const SERVER_INFO_JSON = "{\"name\":\"gdb-mcp\",\"version\":\"0.1.0\"}";
const CAPABILITIES_JSON = "{\"tools\":{\"listChanged\":false},\"logging\":{}}";

const INSTRUCTIONS =
    "Persistent gdb session for the Stygia kernel under qemu's gdb stub. " ++
    "Symbol/field resolution is backed by the callgraph DB (tools/indexer), " ++
    "so qualified Zig names like `sched.scheduler.core_states` resolve " ++
    "directly to (addr, size) without fighting gdb's namespace handling. " ++
    "Workflow: gdb_start → gdb_break / gdb_continue / gdb_step_instruction " ++
    "/ gdb_read_mem / gdb_read_var → gdb_end. Use gdb_raw for commands the " ++
    "high-level tools don't cover.";

const TOOLS_JSON =
    \\[
    \\  {"name":"gdb_status","description":"Report whether a gdb session is active, the connected target, the loaded ELF, and the cached KASLR offset (if computed).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_start","description":"Spawn a gdb subprocess against the given kernel ELF and connect it to the qemu gdb stub. Default target is `:1234` (qemu's default `-s` port). Pass target=\"none\" to spawn gdb without connecting (handy for testing). Only one session at a time.","inputSchema":{"type":"object","properties":{"elf":{"type":"string"},"target":{"type":"string"}},"required":["elf"],"additionalProperties":false}},
    \\  {"name":"gdb_end","description":"Tear down the active gdb session.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_reset","description":"Force-reset the daemon: kill the active session if any, then SIGKILL any orphaned gdb processes left behind by previous gdb_mcp instances that died ungracefully (Claude Code crash, SIGKILL, etc.). Use after a hang or if a previous session got stuck.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_verify","description":"Re-check DB↔ELF freshness: pulls 3 sentinel symbols from entry_point and asks gdb `info address` for each, comparing to bin_symbol.addr. Reports OK / consistent-rebase (KASLR) / stale-DB. The same check runs automatically at gdb_start; use this tool to recheck after rebuilds or to diagnose suspicious resolver output.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_set_kaslr","description":"Set the KASLR offset (runtime − link). Subsequent gdb_break / gdb_resolve / gdb_read_var apply this offset when translating callgraph DB addresses to runtime addresses. Accepts hex (0x...) or decimal; negative values allowed.","inputSchema":{"type":"object","properties":{"offset":{"type":"string"}},"required":["offset"],"additionalProperties":false}},
    \\  {"name":"gdb_resolve","description":"Look up a Zig qualified name (e.g., `sched.scheduler.core_states`) in the callgraph DB's bin_symbol table. Returns link_addr, size, and runtime_addr (link + KASLR offset). Useful for sanity-checking a symbol exists before setting a breakpoint or reading memory.","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"gdb_break","description":"Set a breakpoint. `at` is one of: `file.zig:LINE`, an explicit address `0x...`, or a Zig qualified name. Qualified names are resolved through the callgraph DB so gdb's Zig-namespace handling never gets in the way. `hardware:true` requests a hardware breakpoint.","inputSchema":{"type":"object","properties":{"at":{"type":"string"},"hardware":{"type":"boolean"}},"required":["at"],"additionalProperties":false}},
    \\  {"name":"gdb_break_clear","description":"Delete a breakpoint by id, or `id:\"all\"` to clear every breakpoint.","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}},
    \\  {"name":"gdb_break_list","description":"List active breakpoints/watchpoints (-break-list).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_continue","description":"Resume execution (-exec-continue) and block until the next stop event. Returns the *stopped payload (reason, frame, etc.).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_step","description":"Step one source line, descending into calls (-exec-step).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_step_instruction","description":"Step one machine instruction (-exec-step-instruction). Use this for asm-level walks like the L4 fast-path rendezvous.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_next","description":"Step one source line, stepping over calls (-exec-next).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_finish","description":"Run until the current function returns (-exec-finish).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_interrupt","description":"Send an async interrupt (-exec-interrupt --all) and wait briefly for the resulting stop event.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_pc","description":"Report the current frame (-stack-info-frame): PC, function, file:line. If the current function is sret-returning (return type > 16 bytes), also surfaces a Zig-aware register dump since gdb's args=[...] mis-identifies them.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_args","description":"Diagnose argument registers when gdb's args=[...] is unreliable. For Zig functions returning >16 bytes the ABI puts the sret pointer in %rdi and shifts real args right (first real arg observed at %rdx, not %rsi). Reads rdi/rsi/rdx/rcx/r8/r9 and reports them with sret-aware labels. Defaults to the current frame's func; pass `name` to query a specific function (no need for it to be the current frame, but the regs are read from the current frame).","inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":false}},
    \\  {"name":"gdb_regs","description":"Dump CPU registers (-data-list-register-values). `format` defaults to `x` (hex); also accepts `d`/`o`/`r`/`N` (natural) per the MI spec.","inputSchema":{"type":"object","properties":{"format":{"type":"string"}},"additionalProperties":false}},
    \\  {"name":"gdb_read_mem","description":"Read raw bytes from memory (-data-read-memory-bytes). `addr` may be hex (0x...) or any expression gdb accepts; `len` is byte count.","inputSchema":{"type":"object","properties":{"addr":{"type":"string"},"len":{"type":"integer"}},"required":["addr","len"],"additionalProperties":false}},
    \\  {"name":"gdb_backtrace","description":"List stack frames (-stack-list-frames).","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
    \\  {"name":"gdb_disasm","description":"Disassemble instructions. With no `at` arg, disassembles around $pc; otherwise around the given address. `count` is approx instruction count (default 16).","inputSchema":{"type":"object","properties":{"at":{"type":"string"},"count":{"type":"integer"}},"additionalProperties":false}},
    \\  {"name":"gdb_resolve_field","description":"Walk a dotted field path through the callgraph DB's type_field table. Returns total offset (bytes from struct base) and leaf field size. Pure DB lookup, no gdb session required. Example: type=`sched.scheduler.PerCore`, field=`current_ec` → offset=64, size=16.","inputSchema":{"type":"object","properties":{"type":{"type":"string"},"field":{"type":"string"}},"required":["type","field"],"additionalProperties":false}},
    \\  {"name":"gdb_read_var","description":"Read a Zig variable's bytes from kernel memory. `name` is the variable qname (e.g., `sched.scheduler.core_states`); the address comes from bin_symbol. Optional: `type` (element/struct type qname for array indexing or field walks), `array_index` (multiplied by sizeof(type)), `field` (dotted path through type_field), `len` (override read size). Combines DB resolution + KASLR rebase + -data-read-memory-bytes.","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"type":{"type":"string"},"array_index":{"type":"integer"},"field":{"type":"string"},"len":{"type":"integer"}},"required":["name"],"additionalProperties":false}},
    \\  {"name":"gdb_raw","description":"Send an arbitrary MI command (e.g., `-stack-list-frames`) and return the raw response (class, payload, console, log, async). Escape hatch for commands not covered by the higher-level tools.","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"],"additionalProperties":false}}
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
            std.debug.print("gdb mcp handler error: {s}\n", .{@errorName(err)});
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
        std.debug.print("gdb mcp parse error: {s}: {s}\n", .{ @errorName(err), line });
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
