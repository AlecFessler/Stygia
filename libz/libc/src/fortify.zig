// fortify — _chk variants (FORTIFY_SOURCE).
//
// glibc emits these when consumers compile with -D_FORTIFY_SOURCE=N.
// Each is a length-checked pass-through to the unchecked variant.
// We don't actually check — abort()-on-overflow would be safer but
// dependent on a working stdio for the message. For now, just call
// the unchecked impl.

extern fn memcpy(noalias dest: [*]u8, noalias src: [*]const u8, n: usize) callconv(.c) [*]u8;
extern fn memmove(dest: [*]u8, src: [*]const u8, n: usize) callconv(.c) [*]u8;
extern fn memset(dest: [*]u8, c: c_int, n: usize) callconv(.c) [*]u8;
extern fn strcpy(noalias dest: [*]u8, noalias src: [*:0]const u8) callconv(.c) [*]u8;
extern fn strncpy(noalias dest: [*]u8, noalias src: [*]const u8, n: usize) callconv(.c) [*]u8;

export fn __memcpy_chk(dest: [*]u8, src: [*]const u8, n: usize, destlen: usize) callconv(.c) [*]u8 {
    _ = destlen;
    return memcpy(dest, src, n);
}
export fn __memmove_chk(dest: [*]u8, src: [*]const u8, n: usize, destlen: usize) callconv(.c) [*]u8 {
    _ = destlen;
    return memmove(dest, src, n);
}
export fn __memset_chk(dest: [*]u8, c: c_int, n: usize, destlen: usize) callconv(.c) [*]u8 {
    _ = destlen;
    return memset(dest, c, n);
}
export fn __strcpy_chk(dest: [*]u8, src: [*:0]const u8, destlen: usize) callconv(.c) [*]u8 {
    _ = destlen;
    return strcpy(dest, src);
}
export fn __strncpy_chk(dest: [*]u8, src: [*]const u8, n: usize, destlen: usize) callconv(.c) [*]u8 {
    _ = destlen;
    return strncpy(dest, src, n);
}

extern fn __memcpy_chkF(dest: [*]u8, src: [*]const u8, n: usize) callconv(.c) [*]u8;

// wmemcpy/wmemset _chk
export fn __wmemcpy_chk(dest: [*]u32, src: [*]const u32, n: usize, destlen: usize) callconv(.c) [*]u32 {
    _ = destlen;
    @memcpy(dest[0..n], src[0..n]);
    return dest;
}
export fn __wmemset_chk(s: [*]u32, c: u32, n: usize, destlen: usize) callconv(.c) [*]u32 {
    _ = destlen;
    var i: usize = 0;
    while (i < n) : (i += 1) s[i] = c;
    return s;
}

// __mbsrtowcs_chk — wide-char convert with destlen check; pass through.
extern fn mbsnrtowcs(dest: ?[*]u32, src: ?*[*]const u8, nms: usize, len: usize, st: ?*anyopaque) callconv(.c) usize;

export fn __mbsrtowcs_chk(dest: ?[*]u32, src: ?*[*]const u8, len: usize, st: ?*anyopaque, destlen: usize) callconv(.c) usize {
    _ = destlen;
    return mbsnrtowcs(dest, src, ~@as(usize, 0), len, st);
}

// __read_chk — bounded read pass-through. Once read() lands.
extern fn read(fd: c_int, buf: [*]u8, n: usize) callconv(.c) isize;

export fn __read_chk(fd: c_int, buf: [*]u8, n: usize, buflen: usize) callconv(.c) isize {
    _ = buflen;
    return read(fd, buf, n);
}

// __realpath_chk — same.
extern fn realpath(path: [*:0]const u8, resolved: ?[*]u8) callconv(.c) ?[*:0]u8;

export fn __realpath_chk(path: [*:0]const u8, resolved: ?[*]u8, resolvedlen: usize) callconv(.c) ?[*:0]u8 {
    _ = resolvedlen;
    return realpath(path, resolved);
}
