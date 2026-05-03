//! Persistent gdb subprocess driving the MI3 (machine interface) protocol.
//!
//! gdb is spawned once per session with `--interpreter=mi3` and held open;
//! commands are dispatched through `run()` which writes a token-prefixed MI
//! command and reads stdout until the matching `^class` result record
//! arrives, terminated by the `(gdb)` prompt. Async exec events
//! (`*stopped`) are surfaced through `waitForStop()` since they don't carry
//! the request token.
//!
//! Only the slice of MI we use is parsed structurally — class, console
//! stream, and a couple of common attrs. The rest of the result-record
//! payload is returned as raw text; callers needing specific fields parse
//! them themselves (or escape via gdb_raw).
//!
//! Single-flight: at most one in-flight command per session. Callers
//! serialize externally — the MCP request loop already does.

const std = @import("std");

pub const Error = error{
    SpawnFailed,
    GdbExited,
    ReadFailed,
    WriteFailed,
    Timeout,
    UnexpectedClass,
};

pub const Response = struct {
    /// Result class — "done" | "running" | "connected" | "error" | "exit".
    class: []const u8,
    /// Everything after the class up to end-of-line (key=value pairs).
    /// Empty when the result-record carries no payload.
    payload: []const u8,
    /// Concatenated `~"..."` console-stream output (with escapes decoded).
    console: []const u8,
    /// Concatenated `&"..."` log-stream output (with escapes decoded).
    log: []const u8,
    /// Concatenated `*stopped` and `=...` async records, raw.
    async_records: []const u8,
};

pub const StopEvent = struct {
    /// Raw `*stopped,...` line (without the leading `*stopped,`).
    payload: []const u8,
    /// Anything else that came along (other async records, console).
    extra: []const u8,
};

pub const Session = struct {
    gpa: std.mem.Allocator,
    child: std.process.Child,
    stdin: std.fs.File,
    stdout: std.fs.File,
    next_token: u32 = 1,
    /// Persistent line-read buffer; carries partial bytes between reads.
    line_buf: std.ArrayList(u8) = .{},
    /// Path the session was opened against — for diagnostics + KASLR.
    elf_path: []const u8,
    /// Connected target string (e.g., "remote :1234") if a target is set.
    target: ?[]const u8 = null,
    /// Cached KASLR offset (runtime − link); set by KaslrProbe.
    kaslr_offset: ?i64 = null,

    pub fn spawn(
        gpa: std.mem.Allocator,
        gdb_path: []const u8,
        elf_path: []const u8,
    ) !*Session {
        const argv = [_][]const u8{ gdb_path, "--interpreter=mi3", "--quiet", "--nx", elf_path };
        var child = std.process.Child.init(&argv, gpa);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.spawn() catch return Error.SpawnFailed;

        const self = try gpa.create(Session);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .child = child,
            .stdin = child.stdin.?,
            .stdout = child.stdout.?,
            .elf_path = try gpa.dupe(u8, elf_path),
            .line_buf = .{},
        };

        // Drain the startup banner up to the first `(gdb)` prompt.
        var drain_arena = std.heap.ArenaAllocator.init(gpa);
        defer drain_arena.deinit();
        try self.drainToPrompt(drain_arena.allocator());
        return self;
    }

    pub fn close(self: *Session) void {
        // Best-effort -gdb-exit so gdb can flush state.
        const exit_cmd = "-gdb-exit\n";
        _ = self.stdin.write(exit_cmd) catch {};
        // Don't close pipes manually — `child.kill()` -> `cleanupStreams()`
        // already closes child.stdin / stdout / stderr. Double-closing
        // tripped a posix.BADF unreachable in Zig stdlib.
        _ = self.child.kill() catch {};
        self.line_buf.deinit(self.gpa);
        self.gpa.free(self.elf_path);
        if (self.target) |t| self.gpa.free(t);
        self.gpa.destroy(self);
    }

    /// Default per-command timeout. 30s covers most operations including
    /// remote-target select; gdb_continue overrides with a longer wait.
    pub const DEFAULT_TIMEOUT_MS: i32 = 30_000;

    /// Issue an MI command. Defaults to `DEFAULT_TIMEOUT_MS`; pass
    /// `runWithTimeout` directly for finer control. On timeout returns
    /// `Error.Timeout` — the caller is expected to consider the session
    /// poisoned and tear it down.
    pub fn run(self: *Session, arena: std.mem.Allocator, cmd: []const u8) !Response {
        return self.runWithTimeout(arena, cmd, DEFAULT_TIMEOUT_MS);
    }

    pub fn runWithTimeout(
        self: *Session,
        arena: std.mem.Allocator,
        cmd: []const u8,
        timeout_ms: i32,
    ) !Response {
        const token = self.next_token;
        self.next_token += 1;

        // Write `{token}{cmd}\n` in one call.
        const line = try std.fmt.allocPrint(arena, "{d}{s}\n", .{ token, cmd });
        try writeAll(self.stdin, line);

        const deadline_ms: ?i64 = if (timeout_ms > 0)
            std.time.milliTimestamp() + timeout_ms
        else
            null;

        var console: std.ArrayList(u8) = .{};
        var log_buf: std.ArrayList(u8) = .{};
        var async_buf: std.ArrayList(u8) = .{};
        var class: []const u8 = "";
        var payload: []const u8 = "";
        var matched = false;

        const tok_prefix = try std.fmt.allocPrint(arena, "{d}", .{token});

        while (true) {
            const got = try self.readLineWithDeadline(arena, deadline_ms);
            const ln = got orelse return Error.GdbExited;
            const trimmed = std.mem.trimRight(u8, ln, "\r\n");
            if (trimmed.len == 0) continue;
            // Prompt sentinel.
            if (std.mem.eql(u8, trimmed, "(gdb) ") or std.mem.eql(u8, trimmed, "(gdb)")) {
                if (matched) break;
                // Prompt without our result yet — keep reading.
                continue;
            }
            // Token-prefixed result-record: `42^done,...`
            if (std.mem.startsWith(u8, trimmed, tok_prefix)) {
                const rest = trimmed[tok_prefix.len..];
                if (rest.len > 0 and rest[0] == '^') {
                    const after = rest[1..];
                    const comma = std.mem.indexOfScalar(u8, after, ',');
                    if (comma) |i| {
                        class = try arena.dupe(u8, after[0..i]);
                        payload = try arena.dupe(u8, after[i + 1 ..]);
                    } else {
                        class = try arena.dupe(u8, after);
                        payload = "";
                    }
                    matched = true;
                    continue;
                }
            }
            // Stream records.
            if (trimmed[0] == '~') {
                try appendDecodedString(arena, &console, trimmed[1..]);
                continue;
            }
            if (trimmed[0] == '&') {
                try appendDecodedString(arena, &log_buf, trimmed[1..]);
                continue;
            }
            if (trimmed[0] == '@') continue; // target stream, ignored
            // Async records (`*stopped`, `=foo`).
            if (trimmed[0] == '*' or trimmed[0] == '=') {
                try async_buf.appendSlice(arena, trimmed);
                try async_buf.append(arena, '\n');
                continue;
            }
            // Untokened result-record (rare with MI3 but tolerate).
            if (trimmed[0] == '^') {
                const after = trimmed[1..];
                const comma = std.mem.indexOfScalar(u8, after, ',');
                if (comma) |i| {
                    class = try arena.dupe(u8, after[0..i]);
                    payload = try arena.dupe(u8, after[i + 1 ..]);
                } else {
                    class = try arena.dupe(u8, after);
                    payload = "";
                }
                matched = true;
                continue;
            }
            // Unknown — keep raw for diagnostics.
            try async_buf.appendSlice(arena, trimmed);
            try async_buf.append(arena, '\n');
        }

        return .{
            .class = class,
            .payload = payload,
            .console = try console.toOwnedSlice(arena),
            .log = try log_buf.toOwnedSlice(arena),
            .async_records = try async_buf.toOwnedSlice(arena),
        };
    }

    /// Wait for the next `*stopped` async record. `timeout_ms == 0` blocks
    /// forever. Returns Error.Timeout if no stop arrives in time.
    pub fn waitForStop(
        self: *Session,
        arena: std.mem.Allocator,
        timeout_ms: i32,
    ) !StopEvent {
        var extra: std.ArrayList(u8) = .{};
        var payload: []const u8 = "";
        var got_stop = false;

        const deadline_ms: ?i64 = if (timeout_ms > 0)
            std.time.milliTimestamp() + timeout_ms
        else
            null;

        while (true) {
            const got = try self.readLineWithDeadline(arena, deadline_ms);
            const ln = got orelse return Error.GdbExited;
            const trimmed = std.mem.trimRight(u8, ln, "\r\n");
            if (trimmed.len == 0) continue;
            if (std.mem.eql(u8, trimmed, "(gdb) ") or std.mem.eql(u8, trimmed, "(gdb)")) {
                if (got_stop) break;
                continue;
            }
            if (std.mem.startsWith(u8, trimmed, "*stopped")) {
                const after = if (trimmed.len > "*stopped,".len and trimmed["*stopped".len] == ',')
                    trimmed["*stopped,".len..]
                else
                    "";
                payload = try arena.dupe(u8, after);
                got_stop = true;
                continue;
            }
            try extra.appendSlice(arena, trimmed);
            try extra.append(arena, '\n');
        }

        return .{
            .payload = payload,
            .extra = try extra.toOwnedSlice(arena),
        };
    }

    /// Read until and including the next `(gdb)` prompt; discard everything.
    /// Used at startup to consume the banner.
    fn drainToPrompt(self: *Session, arena: std.mem.Allocator) !void {
        const deadline: i64 = std.time.milliTimestamp() + 5_000;
        while (true) {
            const got = try self.readLineWithDeadline(arena, deadline);
            const ln = got orelse return Error.GdbExited;
            const trimmed = std.mem.trimRight(u8, ln, "\r\n");
            if (std.mem.eql(u8, trimmed, "(gdb) ") or std.mem.eql(u8, trimmed, "(gdb)")) return;
        }
    }

    /// Read one line with optional deadline (absolute ms timestamp). Each
    /// `read()` is gated by `poll()` against the remaining time. Returns
    /// `Error.Timeout` if the deadline expires mid-line. Pass `null` to
    /// block forever (still subject to the read returning).
    fn readLineWithDeadline(
        self: *Session,
        arena: std.mem.Allocator,
        deadline_ms: ?i64,
    ) !?[]u8 {
        var byte: [1]u8 = undefined;
        while (true) {
            if (deadline_ms) |dl| {
                const now = std.time.milliTimestamp();
                if (now >= dl) return Error.Timeout;
                const remaining: i32 = @intCast(@min(@as(i64, std.math.maxInt(i32)), dl - now));
                if (!try waitReadable(self.stdout.handle, remaining)) return Error.Timeout;
            }
            const n = self.stdout.read(&byte) catch return Error.ReadFailed;
            if (n == 0) {
                if (self.line_buf.items.len == 0) return null;
                const out = try arena.dupe(u8, self.line_buf.items);
                self.line_buf.clearRetainingCapacity();
                return out;
            }
            try self.line_buf.append(self.gpa, byte[0]);
            if (byte[0] == '\n') {
                const out = try arena.dupe(u8, self.line_buf.items);
                self.line_buf.clearRetainingCapacity();
                return out;
            }
            // Special case: `(gdb) ` prompt is NOT newline-terminated.
            const buf = self.line_buf.items;
            if (buf.len >= 6 and std.mem.eql(u8, buf[buf.len - 6 ..], "(gdb) ")) {
                const out = try arena.dupe(u8, buf);
                self.line_buf.clearRetainingCapacity();
                return out;
            }
        }
    }
};

fn writeAll(file: std.fs.File, bytes: []const u8) !void {
    var rest = bytes;
    while (rest.len > 0) {
        const n = file.write(rest) catch return Error.WriteFailed;
        if (n == 0) return Error.WriteFailed;
        rest = rest[n..];
    }
}

fn waitReadable(fd: std.posix.fd_t, timeout_ms: i32) !bool {
    var pfd = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&pfd, timeout_ms) catch return Error.ReadFailed;
    return n > 0;
}

/// MI stream string: `"...escaped..."`. We unquote and decode \n \t \\ \".
fn appendDecodedString(
    arena: std.mem.Allocator,
    out: *std.ArrayList(u8),
    quoted: []const u8,
) !void {
    if (quoted.len < 2 or quoted[0] != '"') {
        try out.appendSlice(arena, quoted);
        return;
    }
    // Strip leading quote; trailing quote may or may not be present
    // depending on whether the line was truncated.
    var s: []const u8 = quoted[1..];
    if (s.len > 0 and s[s.len - 1] == '"') s = s[0 .. s.len - 1];
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '\\' and i + 1 < s.len) {
            const n = s[i + 1];
            switch (n) {
                'n' => try out.append(arena, '\n'),
                't' => try out.append(arena, '\t'),
                'r' => try out.append(arena, '\r'),
                '\\' => try out.append(arena, '\\'),
                '"' => try out.append(arena, '"'),
                else => {
                    try out.append(arena, c);
                    try out.append(arena, n);
                },
            }
            i += 2;
            continue;
        }
        try out.append(arena, c);
        i += 1;
    }
}
