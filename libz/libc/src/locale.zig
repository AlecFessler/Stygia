// locale — single C-locale stub.
//
// We support exactly one locale: "C" (synonym "POSIX"). setlocale(_, "C")
// or NULL succeeds returning "C"; anything else returns NULL. _l-suffix
// variants ignore their locale_t argument and dispatch to the regular
// (locale-less) implementation.
//
// libc++ / libstdc++ probe locales but don't strictly require non-C —
// they fall back to the C path when locale_t resolution returns the
// default object. nl_langinfo returns empty/default strings for items
// it's asked about; that's enough to satisfy std::ios_base init.

const C_LOCALE_NAME: [*:0]const u8 = "C";

const empty: [*:0]const u8 = "";

// locale_t is opaque to callers. We hand back a sentinel pointer.
var c_locale_storage: u8 = 0;
const c_locale: *anyopaque = @ptrCast(&c_locale_storage);

export fn setlocale(category: c_int, locale: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    _ = category;
    if (locale == null) return C_LOCALE_NAME;
    const l = locale.?;
    if (l[0] == 0 or // empty — POSIX default
        (l[0] == 'C' and l[1] == 0) or
        (l[0] == 'P' and l[1] == 'O' and l[2] == 'S' and l[3] == 'I' and l[4] == 'X' and l[5] == 0))
        return C_LOCALE_NAME;
    return null;
}

export fn newlocale(mask: c_int, locale: ?[*:0]const u8, base: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = .{ mask, base };
    if (locale == null) return c_locale;
    return c_locale;
}
export fn __newlocale(mask: c_int, locale: ?[*:0]const u8, base: ?*anyopaque) callconv(.c) ?*anyopaque {
    return newlocale(mask, locale, base);
}

export fn freelocale(loc: ?*anyopaque) callconv(.c) void {
    _ = loc;
}
export fn __freelocale(loc: ?*anyopaque) callconv(.c) void {
    _ = loc;
}

export fn duplocale(loc: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = loc;
    return c_locale;
}
export fn __duplocale(loc: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = loc;
    return c_locale;
}

export fn uselocale(loc: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = loc;
    return c_locale;
}
export fn __uselocale(loc: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = loc;
    return c_locale;
}

export fn nl_langinfo(item: c_int) callconv(.c) [*:0]const u8 {
    _ = item;
    return empty;
}
export fn nl_langinfo_l(item: c_int, loc: ?*anyopaque) callconv(.c) [*:0]const u8 {
    _ = .{ item, loc };
    return empty;
}
export fn __nl_langinfo_l(item: c_int, loc: ?*anyopaque) callconv(.c) [*:0]const u8 {
    return nl_langinfo_l(item, loc);
}

// _l-suffix collation/transformation: ignore locale, do regular work.

export fn __strcoll_l(a: [*:0]const u8, b: [*:0]const u8, loc: ?*anyopaque) callconv(.c) c_int {
    _ = loc;
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) i += 1;
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

export fn __strxfrm_l(dest: ?[*]u8, src: [*:0]const u8, n: usize, loc: ?*anyopaque) callconv(.c) usize {
    _ = loc;
    var i: usize = 0;
    while (src[i] != 0) i += 1;
    if (dest) |d| {
        var j: usize = 0;
        while (j < i and j < n) {
            d[j] = src[j];
            j += 1;
        }
        if (j < n) d[j] = 0;
    }
    return i;
}

// gettext-family: passthrough.
export fn gettext(s: [*:0]const u8) callconv(.c) [*:0]const u8 {
    return s;
}
export fn dgettext(domain: [*:0]const u8, s: [*:0]const u8) callconv(.c) [*:0]const u8 {
    _ = domain;
    return s;
}
export fn bindtextdomain(domain: [*:0]const u8, dir: ?[*:0]const u8) callconv(.c) [*:0]const u8 {
    _ = .{ domain, dir };
    return empty;
}
export fn bind_textdomain_codeset(domain: [*:0]const u8, codeset: ?[*:0]const u8) callconv(.c) [*:0]const u8 {
    _ = .{ domain, codeset };
    return empty;
}
