// string — memcpy / memmove / memset / memcmp / memchr + str* family.
//
// Memory ops route through @memcpy / @memset (LLVM lowers to optimal
// rep movsb / rep stosb on x86_64). String length / compare / search
// uses small inline loops rather than std.mem indirection so that
// LLVM's inliner sees them at the call site, and so this file does
// not transitively pull in std.fs / std.posix / std.debug (which
// have unimplemented entry points on Zag).

// ── memory ────────────────────────────────────────────────────────

export fn memcpy(noalias dest: [*]u8, noalias src: [*]const u8, n: usize) callconv(.c) [*]u8 {
    @memcpy(dest[0..n], src[0..n]);
    return dest;
}

export fn memmove(dest: [*]u8, src: [*]const u8, n: usize) callconv(.c) [*]u8 {
    if (n == 0) return dest;
    if (@intFromPtr(dest) < @intFromPtr(src) or @intFromPtr(dest) >= @intFromPtr(src) + n) {
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

export fn memset(dest: [*]u8, c: c_int, n: usize) callconv(.c) [*]u8 {
    @memset(dest[0..n], @truncate(@as(c_uint, @bitCast(c))));
    return dest;
}

export fn memcmp(a: [*]const u8, b: [*]const u8, n: usize) callconv(.c) c_int {
    var i: usize = 0;
    while (i < n) {
        if (a[i] != b[i]) return @as(c_int, a[i]) - @as(c_int, b[i]);
        i += 1;
    }
    return 0;
}

export fn memchr(s: [*]const u8, c: c_int, n: usize) callconv(.c) ?[*]const u8 {
    const target: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var i: usize = 0;
    while (i < n) {
        if (s[i] == target) return s + i;
        i += 1;
    }
    return null;
}

// ── strings ───────────────────────────────────────────────────────

export fn strlen(s: [*:0]const u8) callconv(.c) usize {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    return i;
}

export fn strnlen(s: [*]const u8, max: usize) callconv(.c) usize {
    var i: usize = 0;
    while (i < max and s[i] != 0) i += 1;
    return i;
}

export fn strcmp(a: [*:0]const u8, b: [*:0]const u8) callconv(.c) c_int {
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) i += 1;
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

export fn strncmp(a: [*]const u8, b: [*]const u8, n: usize) callconv(.c) c_int {
    var i: usize = 0;
    while (i < n) {
        const av = a[i];
        const bv = b[i];
        if (av != bv) return @as(c_int, av) - @as(c_int, bv);
        if (av == 0) return 0;
        i += 1;
    }
    return 0;
}

export fn strcpy(noalias dest: [*]u8, noalias src: [*:0]const u8) callconv(.c) [*]u8 {
    var i: usize = 0;
    while (src[i] != 0) {
        dest[i] = src[i];
        i += 1;
    }
    dest[i] = 0;
    return dest;
}

export fn strncpy(noalias dest: [*]u8, noalias src: [*]const u8, n: usize) callconv(.c) [*]u8 {
    var i: usize = 0;
    while (i < n and src[i] != 0) {
        dest[i] = src[i];
        i += 1;
    }
    while (i < n) {
        dest[i] = 0;
        i += 1;
    }
    return dest;
}

export fn strchr(s: [*:0]const u8, c: c_int) callconv(.c) ?[*]const u8 {
    const target: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var i: usize = 0;
    while (true) {
        if (s[i] == target) return s + i;
        if (s[i] == 0) return null;
        i += 1;
    }
}

export fn strrchr(s: [*:0]const u8, c: c_int) callconv(.c) ?[*]const u8 {
    const target: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var last: ?[*]const u8 = if (target == 0) blk: {
        var j: usize = 0;
        while (s[j] != 0) j += 1;
        break :blk s + j;
    } else null;
    var i: usize = 0;
    while (s[i] != 0) {
        if (s[i] == target) last = s + i;
        i += 1;
    }
    return last;
}

export fn strstr(haystack: [*:0]const u8, needle: [*:0]const u8) callconv(.c) ?[*]const u8 {
    if (needle[0] == 0) return haystack;
    var i: usize = 0;
    while (haystack[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (needle[j] != 0 and haystack[i + j] == needle[j]) j += 1;
        if (needle[j] == 0) return haystack + i;
    }
    return null;
}

export fn strspn(s: [*:0]const u8, accept: [*:0]const u8) callconv(.c) usize {
    var i: usize = 0;
    outer: while (s[i] != 0) {
        var j: usize = 0;
        while (accept[j] != 0) {
            if (s[i] == accept[j]) {
                i += 1;
                continue :outer;
            }
            j += 1;
        }
        return i;
    }
    return i;
}

export fn strpbrk(s: [*:0]const u8, accept: [*:0]const u8) callconv(.c) ?[*]const u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (accept[j] != 0) : (j += 1) {
            if (s[i] == accept[j]) return s + i;
        }
    }
    return null;
}
