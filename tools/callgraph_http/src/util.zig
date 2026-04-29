//! Small shared utilities: query-string parsing, URL decoding, simple
//! response helpers, and a writer for SQL-driven JSON.

const std = @import("std");

pub fn isTruthy(v: []const u8) bool {
    return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "on");
}

/// Pull a single value from a query string. Returns null when the key
/// isn't present. Does NOT URL-decode — caller does that if needed.
pub fn getQueryValue(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Minimal URL decoder: `%XX` and `+` → space. Anything malformed
/// passes through unchanged so a malicious URL never panics the server.
pub fn percentDecodeAlloc(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '+') {
            try out.append(alloc, ' ');
            i += 1;
        } else if (c == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch {
                try out.append(alloc, c);
                i += 1;
                continue;
            };
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch {
                try out.append(alloc, c);
                i += 1;
                continue;
            };
            try out.append(alloc, (hi << 4) | lo);
            i += 3;
        } else {
            try out.append(alloc, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(alloc);
}

/// JSON-string escape into `out`. Handles the standard set ("\\, ", \\n,
/// etc.) plus low-byte escapes. Doesn't surround in quotes — caller does.
pub fn jsonEscape(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    for (s) |b| {
        switch (b) {
            '"' => try out.appendSlice(gpa, "\\\""),
            '\\' => try out.appendSlice(gpa, "\\\\"),
            '\n' => try out.appendSlice(gpa, "\\n"),
            '\r' => try out.appendSlice(gpa, "\\r"),
            '\t' => try out.appendSlice(gpa, "\\t"),
            0x08 => try out.appendSlice(gpa, "\\b"),
            0x0c => try out.appendSlice(gpa, "\\f"),
            0...0x07, 0x0b, 0x0e...0x1f => {
                var buf: [8]u8 = undefined;
                const w = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{b});
                try out.appendSlice(gpa, w);
            },
            else => try out.append(gpa, b),
        }
    }
}

pub fn jsonStr(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    try out.append(gpa, '"');
    try jsonEscape(out, gpa, s);
    try out.append(gpa, '"');
}

pub fn parseHexU64(s: []const u8) ?u64 {
    const t = if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) s[2..] else s;
    if (t.len == 0) return null;
    return std.fmt.parseInt(u64, t, 16) catch null;
}

pub fn respondBytes(
    request: *std.http.Server.Request,
    status: std.http.Status,
    content_type: []const u8,
    body: []const u8,
) !void {
    try request.respond(body, .{
        .status = status,
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "cache-control", .value = "no-store" },
        },
    });
}
