// strings_extra — strdup / strerror / strerror_r / strsignal / strtok_r.
//
// strdup needs malloc; we declare extern. Once malloc.zig lands the
// linker resolves these.

extern fn malloc(n: usize) callconv(.c) ?[*]u8;

export fn strdup(s: [*:0]const u8) callconv(.c) ?[*:0]u8 {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    const len = i + 1;
    const p = malloc(len) orelse return null;
    var j: usize = 0;
    while (j < len) : (j += 1) p[j] = s[j];
    return @ptrCast(p);
}

// We don't carry full per-errno strings yet. Return a bare number-as-
// hex string buffer; LLVM's error reporting expects *some* string.
var strerror_buf: [16]u8 = @splat(0);

export fn strerror(errnum: c_int) callconv(.c) [*:0]const u8 {
    const v: u32 = @bitCast(errnum);
    var i: usize = 0;
    strerror_buf[i] = 'E';
    i += 1;
    if (v == 0) {
        strerror_buf[i] = '0';
        i += 1;
    } else {
        var d = v;
        var digs: [10]u8 = undefined;
        var n: usize = 0;
        while (d > 0) {
            digs[n] = '0' + @as(u8, @truncate(d % 10));
            d /= 10;
            n += 1;
        }
        while (n > 0) {
            n -= 1;
            strerror_buf[i] = digs[n];
            i += 1;
        }
    }
    strerror_buf[i] = 0;
    return @ptrCast(&strerror_buf);
}

export fn strerror_r(errnum: c_int, buf: [*]u8, buflen: usize) callconv(.c) c_int {
    const s = strerror(errnum);
    var i: usize = 0;
    while (i + 1 < buflen and s[i] != 0) {
        buf[i] = s[i];
        i += 1;
    }
    if (buflen > 0) buf[i] = 0;
    return 0;
}

export fn strsignal(signum: c_int) callconv(.c) [*:0]const u8 {
    _ = signum;
    return "Unknown signal";
}

export fn strtok_r(noalias s: ?[*]u8, noalias delim: [*:0]const u8, noalias save: *?[*]u8) callconv(.c) ?[*]u8 {
    var p: [*]u8 = if (s) |ss| ss else (save.* orelse return null);
    // skip leading delims
    skip: while (true) {
        const c = p[0];
        if (c == 0) {
            save.* = null;
            return null;
        }
        var i: usize = 0;
        while (delim[i] != 0) : (i += 1) {
            if (delim[i] == c) {
                p += 1;
                continue :skip;
            }
        }
        break;
    }
    const tok = p;
    while (true) {
        const c = p[0];
        if (c == 0) {
            save.* = null;
            return tok;
        }
        var i: usize = 0;
        while (delim[i] != 0) : (i += 1) {
            if (delim[i] == c) {
                p[0] = 0;
                save.* = p + 1;
                return tok;
            }
        }
        p += 1;
    }
}

// strftime — minimal: fail (return 0). LLVM uses it for debug/profile
// timestamps; an empty string is acceptable for now.
export fn strftime(buf: [*]u8, max: usize, fmt: [*:0]const u8, tm: ?*const anyopaque) callconv(.c) usize {
    _ = .{ fmt, tm };
    if (max > 0) buf[0] = 0;
    return 0;
}
export fn __strftime_l(buf: [*]u8, max: usize, fmt: [*:0]const u8, tm: ?*const anyopaque, loc: ?*anyopaque) callconv(.c) usize {
    _ = loc;
    return strftime(buf, max, fmt, tm);
}
export fn __wcsftime_l(buf: ?[*]u32, max: usize, fmt: ?*const anyopaque, tm: ?*const anyopaque, loc: ?*anyopaque) callconv(.c) usize {
    _ = .{ buf, fmt, tm, loc };
    if (buf != null and max > 0) buf.?[0] = 0;
    return 0;
}

// Float parsers — minimal positive/negative exponent-free parser.
// LLVM mostly uses these for command-line numeric args.

fn parseSignFloat(p: [*]const u8) struct { neg: bool, after: [*]const u8 } {
    if (p[0] == '+') return .{ .neg = false, .after = p + 1 };
    if (p[0] == '-') return .{ .neg = true, .after = p + 1 };
    return .{ .neg = false, .after = p };
}

fn skipWs(p: [*]const u8) [*]const u8 {
    var i: usize = 0;
    while (true) {
        const c = p[i];
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c) {
            i += 1;
            continue;
        }
        break;
    }
    return p + i;
}

fn parseDouble(nptr: [*:0]const u8, endptr: ?*[*]const u8) f64 {
    var p = skipWs(nptr);
    const sgn = parseSignFloat(p);
    p = sgn.after;
    var v: f64 = 0;
    var any: bool = false;
    while (p[0] >= '0' and p[0] <= '9') {
        v = v * 10.0 + @as(f64, @floatFromInt(p[0] - '0'));
        p += 1;
        any = true;
    }
    if (p[0] == '.') {
        p += 1;
        var scale: f64 = 0.1;
        while (p[0] >= '0' and p[0] <= '9') {
            v += @as(f64, @floatFromInt(p[0] - '0')) * scale;
            scale *= 0.1;
            p += 1;
            any = true;
        }
    }
    if (p[0] == 'e' or p[0] == 'E') {
        p += 1;
        const e_sgn = parseSignFloat(p);
        p = e_sgn.after;
        var exp_val: i32 = 0;
        while (p[0] >= '0' and p[0] <= '9') {
            exp_val = exp_val * 10 + @as(i32, p[0] - '0');
            p += 1;
        }
        var i: i32 = 0;
        var mult: f64 = 1.0;
        while (i < exp_val) : (i += 1) mult *= 10.0;
        if (e_sgn.neg) v /= mult else v *= mult;
    }
    if (sgn.neg) v = -v;
    if (endptr) |ep| ep.* = if (any) p else nptr;
    return v;
}

export fn strtod(nptr: [*:0]const u8, endptr: ?*[*]const u8) callconv(.c) f64 {
    return parseDouble(nptr, endptr);
}
export fn strtof(nptr: [*:0]const u8, endptr: ?*[*]const u8) callconv(.c) f32 {
    return @floatCast(parseDouble(nptr, endptr));
}
export fn strtold(nptr: [*:0]const u8, endptr: ?*[*]const u8) callconv(.c) f64 {
    return parseDouble(nptr, endptr);
}
export fn __strtod_l(nptr: [*:0]const u8, endptr: ?*[*]const u8, loc: ?*anyopaque) callconv(.c) f64 {
    _ = loc;
    return parseDouble(nptr, endptr);
}
export fn __strtof_l(nptr: [*:0]const u8, endptr: ?*[*]const u8, loc: ?*anyopaque) callconv(.c) f32 {
    _ = loc;
    return @floatCast(parseDouble(nptr, endptr));
}
export fn strtold_l(nptr: [*:0]const u8, endptr: ?*[*]const u8, loc: ?*anyopaque) callconv(.c) f64 {
    _ = loc;
    return parseDouble(nptr, endptr);
}
export fn strfromf128(s: [*]u8, n: usize, fmt: [*:0]const u8, x: f64) callconv(.c) c_int {
    _ = .{ fmt, x };
    if (n > 0) s[0] = 0;
    return 0;
}
export fn strtof128(nptr: [*:0]const u8, endptr: ?*[*]const u8) callconv(.c) f64 {
    return parseDouble(nptr, endptr);
}

// __isoc23_strto*: glibc 2.38+ versioned aliases. Forward to plain.
extern fn strtol(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_long;
extern fn strtoll(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_longlong;
extern fn strtoul(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_ulong;
extern fn strtoull(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_ulonglong;

export fn __isoc23_strtol(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_long {
    return strtol(nptr, endptr, base);
}
export fn __isoc23_strtoll(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_longlong {
    return strtoll(nptr, endptr, base);
}
export fn __isoc23_strtoul(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_ulong {
    return strtoul(nptr, endptr, base);
}
export fn __isoc23_strtoull(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_ulonglong {
    return strtoull(nptr, endptr, base);
}

// __isoc23_*scanf — very minimal: not implemented, return EOF.
export fn __isoc23_scanf(fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = fmt;
    return -1;
}
export fn __isoc23_sscanf(s: [*:0]const u8, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = .{ s, fmt };
    return -1;
}
