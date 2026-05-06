// wide — wchar_t / multibyte conversion (single-byte C-locale).
//
// In the C locale every byte is a 1-char wchar_t. We treat wchar_t as
// u32 (the standard on Linux) and pass through values unchanged. This
// is correct for ASCII; non-ASCII inputs just preserve the byte value
// in the high bits of wchar_t. UTF-8-aware conversions are out of
// scope until LLVM/Zig actually exercises them — for code generation
// they don't.

const wchar_t = u32;

export fn btowc(c: c_int) callconv(.c) wchar_t {
    if (c < 0 or c > 0xff) return @bitCast(@as(c_int, -1));
    return @intCast(c);
}

export fn wctob(c: wchar_t) callconv(.c) c_int {
    if (c > 0xff) return -1;
    return @intCast(c);
}

export fn mbrtowc(pwc: ?*wchar_t, s: ?[*]const u8, n: usize, st: ?*anyopaque) callconv(.c) usize {
    _ = st;
    if (s == null or n == 0) return 0;
    const c = s.?[0];
    if (pwc) |p| p.* = c;
    return if (c == 0) 0 else 1;
}

export fn wcrtomb(s: ?[*]u8, c: wchar_t, st: ?*anyopaque) callconv(.c) usize {
    _ = st;
    if (s == null) return 1;
    s.?[0] = @truncate(c);
    return 1;
}

export fn mbsnrtowcs(dest: ?[*]wchar_t, src: ?*[*]const u8, nms: usize, len: usize, st: ?*anyopaque) callconv(.c) usize {
    _ = .{ st, nms };
    if (src == null) return 0;
    var p = src.?.*;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (p[0] == 0) {
            if (dest) |d| d[i] = 0;
            src.?.* = p; // leave at NUL
            return i;
        }
        if (dest) |d| d[i] = p[0];
        p += 1;
    }
    src.?.* = p;
    return i;
}

export fn wcsnrtombs(dest: ?[*]u8, src: ?*[*]const wchar_t, nwc: usize, len: usize, st: ?*anyopaque) callconv(.c) usize {
    _ = .{ st, nwc };
    if (src == null) return 0;
    var p = src.?.*;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const c = p[0];
        if (c == 0) {
            if (dest) |d| d[i] = 0;
            src.?.* = p;
            return i;
        }
        if (dest) |d| d[i] = @truncate(c);
        p += 1;
    }
    src.?.* = p;
    return i;
}

export fn wcslen(s: [*:0]const wchar_t) callconv(.c) usize {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    return i;
}

export fn wcscmp(a: [*:0]const wchar_t, b: [*:0]const wchar_t) callconv(.c) c_int {
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) i += 1;
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
    return 0;
}

export fn wmemchr(s: [*]const wchar_t, c: wchar_t, n: usize) callconv(.c) ?[*]const wchar_t {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (s[i] == c) return s + i;
    }
    return null;
}

export fn wmemcmp(a: [*]const wchar_t, b: [*]const wchar_t, n: usize) callconv(.c) c_int {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

export fn wmemcpy(noalias dest: [*]wchar_t, noalias src: [*]const wchar_t, n: usize) callconv(.c) [*]wchar_t {
    @memcpy(dest[0..n], src[0..n]);
    return dest;
}

export fn wmemmove(dest: [*]wchar_t, src: [*]const wchar_t, n: usize) callconv(.c) [*]wchar_t {
    if (n == 0) return dest;
    if (@intFromPtr(dest) < @intFromPtr(src) or @intFromPtr(dest) >= @intFromPtr(src) + n * @sizeOf(wchar_t)) {
        @memcpy(dest[0..n], src[0..n]);
    } else {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            dest[i] = src[i];
        }
    }
    return dest;
}

export fn wmemset(s: [*]wchar_t, c: wchar_t, n: usize) callconv(.c) [*]wchar_t {
    var i: usize = 0;
    while (i < n) : (i += 1) s[i] = c;
    return s;
}

// _l-suffix wide variants — ignore locale, dispatch to base.
export fn __towlower_l(c: wchar_t, loc: ?*anyopaque) callconv(.c) wchar_t {
    _ = loc;
    if (c >= 'A' and c <= 'Z') return c + 0x20;
    return c;
}
export fn __towupper_l(c: wchar_t, loc: ?*anyopaque) callconv(.c) wchar_t {
    _ = loc;
    if (c >= 'a' and c <= 'z') return c - 0x20;
    return c;
}
export fn __iswctype_l(c: wchar_t, kind: c_int, loc: ?*anyopaque) callconv(.c) c_int {
    _ = .{ c, kind, loc };
    return 0;
}
export fn __wctype_l(name: [*:0]const u8, loc: ?*anyopaque) callconv(.c) c_int {
    _ = .{ name, loc };
    return 0;
}
export fn __wcscoll_l(a: [*:0]const wchar_t, b: [*:0]const wchar_t, loc: ?*anyopaque) callconv(.c) c_int {
    _ = loc;
    return wcscmp(a, b);
}
export fn __wcsxfrm_l(dest: ?[*]wchar_t, src: [*:0]const wchar_t, n: usize, loc: ?*anyopaque) callconv(.c) usize {
    _ = loc;
    const len = wcslen(src);
    if (dest) |d| {
        var i: usize = 0;
        while (i < len and i < n) {
            d[i] = src[i];
            i += 1;
        }
        if (i < n) d[i] = 0;
    }
    return len;
}
