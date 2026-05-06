// stdio — minimal FILE / fopen / fread / fwrite / fputc / printf-family.
//
// FILE is a tiny wrapper around an fd. No buffering on first cut —
// every fwrite/fread is a direct syscall through posix_io. fopen
// translates POSIX modes to flags; fclose does the right close.
//
// printf / fprintf / sprintf / snprintf / vsnprintf: minimal format
// parser handling %d %u %x %X %o %c %s %p %% with optional width/
// precision/zero-pad. No %f for the first cut — LLVM uses printf
// mostly for diagnostics where %f isn't critical. Once the cross-
// build works we can graduate to a full impl or wire std.fmt.

extern fn malloc(n: usize) callconv(.c) ?[*]u8;
extern fn free(p: ?*anyopaque) callconv(.c) void;

// Re-import the open helper so we can share path-resolution.
const posix_io = @import("posix_io.zig");
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int;
extern fn close(fd: c_int) callconv(.c) c_int;
extern fn read(fd: c_int, buf: [*]u8, n: usize) callconv(.c) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) callconv(.c) isize;
extern fn lseek(fd: c_int, offset: i64, whence: c_int) callconv(.c) i64;

// ── FILE struct ──────────────────────────────────────────────────

const FILE = extern struct {
    fd: c_int,
    flags: u32, // bit 0 = readable, bit 1 = writable, bit 2 = at EOF, bit 3 = error
    pushback_set: u8, // 1 if pushback_byte is valid
    pushback_byte: u8,
};

const FLAG_READ: u32 = 1 << 0;
const FLAG_WRITE: u32 = 1 << 1;
const FLAG_EOF: u32 = 1 << 2;
const FLAG_ERROR: u32 = 1 << 3;

var stdin_storage: FILE = .{ .fd = 0, .flags = FLAG_READ, .pushback_set = 0, .pushback_byte = 0 };
var stdout_storage: FILE = .{ .fd = 1, .flags = FLAG_WRITE, .pushback_set = 0, .pushback_byte = 0 };
var stderr_storage: FILE = .{ .fd = 2, .flags = FLAG_WRITE, .pushback_set = 0, .pushback_byte = 0 };

export var stdin: *FILE = &stdin_storage;
export var stdout: *FILE = &stdout_storage;
export var stderr: *FILE = &stderr_storage;

// ── fopen/fclose/fdopen ─────────────────────────────────────────

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_APPEND: c_int = 0o2000;

fn modeToFlags(mode: [*:0]const u8) struct { flags: c_int, file_flags: u32 } {
    if (mode[0] == 'r') {
        if (mode[1] == '+') return .{ .flags = O_RDWR, .file_flags = FLAG_READ | FLAG_WRITE };
        return .{ .flags = O_RDONLY, .file_flags = FLAG_READ };
    }
    if (mode[0] == 'w') {
        if (mode[1] == '+') return .{ .flags = O_RDWR | O_CREAT | O_TRUNC, .file_flags = FLAG_READ | FLAG_WRITE };
        return .{ .flags = O_WRONLY | O_CREAT | O_TRUNC, .file_flags = FLAG_WRITE };
    }
    if (mode[0] == 'a') {
        if (mode[1] == '+') return .{ .flags = O_RDWR | O_CREAT | O_APPEND, .file_flags = FLAG_READ | FLAG_WRITE };
        return .{ .flags = O_WRONLY | O_CREAT | O_APPEND, .file_flags = FLAG_WRITE };
    }
    return .{ .flags = O_RDONLY, .file_flags = FLAG_READ };
}

export fn fopen(path: [*:0]const u8, mode: [*:0]const u8) callconv(.c) ?*FILE {
    const m = modeToFlags(mode);
    const fd = open(path, m.flags, 0o644);
    if (fd < 0) return null;
    const f_bytes = malloc(@sizeOf(FILE)) orelse {
        _ = close(fd);
        return null;
    };
    const f: *FILE = @ptrCast(@alignCast(f_bytes));
    f.* = .{ .fd = fd, .flags = m.file_flags, .pushback_set = 0, .pushback_byte = 0 };
    return f;
}

export fn fdopen(fd: c_int, mode: [*:0]const u8) callconv(.c) ?*FILE {
    const m = modeToFlags(mode);
    const f_bytes = malloc(@sizeOf(FILE)) orelse return null;
    const f: *FILE = @ptrCast(@alignCast(f_bytes));
    f.* = .{ .fd = fd, .flags = m.file_flags, .pushback_set = 0, .pushback_byte = 0 };
    return f;
}

export fn fclose(f: ?*FILE) callconv(.c) c_int {
    const fp = f orelse return -1;
    const rc = close(fp.fd);
    if (fp != stdin and fp != stdout and fp != stderr) free(fp);
    return rc;
}

export fn fileno(f: ?*FILE) callconv(.c) c_int {
    return if (f) |fp| fp.fd else -1;
}

export fn fflush(f: ?*FILE) callconv(.c) c_int {
    _ = f; // No buffering yet.
    return 0;
}

export fn setvbuf(f: ?*FILE, buf: ?[*]u8, mode: c_int, size: usize) callconv(.c) c_int {
    _ = .{ f, buf, mode, size };
    return 0;
}

// ── fread / fwrite ───────────────────────────────────────────────

export fn fread(ptr: [*]u8, size: usize, nmemb: usize, f: ?*FILE) callconv(.c) usize {
    const fp = f orelse return 0;
    const total = size * nmemb;
    if (total == 0) return 0;
    var done: usize = 0;
    if (fp.pushback_set != 0) {
        ptr[0] = fp.pushback_byte;
        fp.pushback_set = 0;
        done = 1;
    }
    while (done < total) {
        const r = read(fp.fd, ptr + done, total - done);
        if (r < 0) {
            fp.flags |= FLAG_ERROR;
            return done / size;
        }
        if (r == 0) {
            fp.flags |= FLAG_EOF;
            break;
        }
        done += @intCast(r);
    }
    return done / size;
}

export fn fwrite(ptr: [*]const u8, size: usize, nmemb: usize, f: ?*FILE) callconv(.c) usize {
    const fp = f orelse return 0;
    const total = size * nmemb;
    if (total == 0) return 0;
    var done: usize = 0;
    while (done < total) {
        const w = write(fp.fd, ptr + done, total - done);
        if (w <= 0) {
            fp.flags |= FLAG_ERROR;
            return done / size;
        }
        done += @intCast(w);
    }
    return done / size;
}

export fn fputc(c: c_int, f: ?*FILE) callconv(.c) c_int {
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c)));
    const buf: [1]u8 = .{byte};
    if (fwrite(&buf, 1, 1, f) == 1) return c;
    return -1;
}

export fn putc(c: c_int, f: ?*FILE) callconv(.c) c_int {
    return fputc(c, f);
}

export fn fputs(s: [*:0]const u8, f: ?*FILE) callconv(.c) c_int {
    var n: usize = 0;
    while (s[n] != 0) n += 1;
    if (fwrite(s, 1, n, f) == n) return 0;
    return -1;
}

export fn fgetc(f: ?*FILE) callconv(.c) c_int {
    var b: [1]u8 = undefined;
    if (fread(&b, 1, 1, f) == 1) return b[0];
    return -1;
}

export fn getc(f: ?*FILE) callconv(.c) c_int {
    return fgetc(f);
}

export fn ungetc(c: c_int, f: ?*FILE) callconv(.c) c_int {
    const fp = f orelse return -1;
    if (fp.pushback_set != 0) return -1;
    fp.pushback_byte = @truncate(@as(c_uint, @bitCast(c)));
    fp.pushback_set = 1;
    fp.flags &= ~FLAG_EOF;
    return c;
}

const wint_t = u32;

export fn getwc(f: ?*FILE) callconv(.c) wint_t {
    const c = fgetc(f);
    if (c < 0) return ~@as(wint_t, 0);
    return @intCast(c);
}
export fn putwc(c: wint_t, f: ?*FILE) callconv(.c) wint_t {
    if (fputc(@intCast(c & 0xff), f) < 0) return ~@as(wint_t, 0);
    return c;
}
export fn ungetwc(c: wint_t, f: ?*FILE) callconv(.c) wint_t {
    if (ungetc(@intCast(c & 0xff), f) < 0) return ~@as(wint_t, 0);
    return c;
}

export fn fseeko64(f: ?*FILE, offset: i64, whence: c_int) callconv(.c) c_int {
    const fp = f orelse return -1;
    return if (lseek(fp.fd, offset, whence) < 0) -1 else 0;
}
export fn ftello64(f: ?*FILE) callconv(.c) i64 {
    const fp = f orelse return -1;
    return lseek(fp.fd, 0, 1); // SEEK_CUR
}

export fn fseek(f: ?*FILE, offset: c_long, whence: c_int) callconv(.c) c_int {
    return fseeko64(f, offset, whence);
}
export fn ftell(f: ?*FILE) callconv(.c) c_long {
    return @intCast(ftello64(f));
}

// ── Format parser (minimal) ──────────────────────────────────────

const FmtState = struct {
    out: *const fn (ctx: *anyopaque, byte: u8) callconv(.c) bool,
    ctx: *anyopaque,
    written: usize = 0,
};

fn putByte(s: *FmtState, b: u8) bool {
    if (!s.out(s.ctx, b)) return false;
    s.written += 1;
    return true;
}

fn writeUnsigned(s: *FmtState, v: u64, base: u64, upper: bool, width: u32, zero_pad: bool) void {
    var buf: [32]u8 = undefined;
    var n: usize = 0;
    var x = v;
    if (x == 0) {
        buf[0] = '0';
        n = 1;
    } else while (x > 0) {
        const digit: u8 = @truncate(x % base);
        buf[n] = if (digit < 10) '0' + digit else if (upper) 'A' + (digit - 10) else 'a' + (digit - 10);
        x /= base;
        n += 1;
    }
    var pad: u32 = if (width > n) width - @as(u32, @intCast(n)) else 0;
    while (pad > 0) {
        if (!putByte(s, if (zero_pad) '0' else ' ')) return;
        pad -= 1;
    }
    while (n > 0) {
        n -= 1;
        if (!putByte(s, buf[n])) return;
    }
}

fn writeSigned(s: *FmtState, v: i64, width: u32, zero_pad: bool) void {
    var u: u64 = undefined;
    var neg = false;
    if (v < 0) {
        neg = true;
        u = @bitCast(-v);
    } else {
        u = @bitCast(v);
    }
    if (neg) {
        if (zero_pad) {
            // Sign before zeros.
            _ = putByte(s, '-');
            writeUnsigned(s, u, 10, false, if (width > 0) width - 1 else 0, true);
        } else {
            // Sign as part of the number — count digits to handle width.
            var x = u;
            var digit_count: u32 = if (x == 0) 1 else 0;
            while (x > 0) {
                digit_count += 1;
                x /= 10;
            }
            const pad_count: u32 = if (width > digit_count + 1) width - digit_count - 1 else 0;
            var i: u32 = 0;
            while (i < pad_count) : (i += 1) _ = putByte(s, ' ');
            _ = putByte(s, '-');
            writeUnsigned(s, u, 10, false, 0, false);
        }
    } else {
        writeUnsigned(s, u, 10, false, width, zero_pad);
    }
}

fn formatInto(state: *FmtState, fmt: [*:0]const u8, ap: *@import("std").builtin.VaList) callconv(.c) void {
    const std = @import("std");
    var i: usize = 0;
    while (fmt[i] != 0) {
        const c = fmt[i];
        if (c != '%') {
            if (!putByte(state, c)) return;
            i += 1;
            continue;
        }
        i += 1;
        // flags
        var zero_pad = false;
        var left_align = false;
        var show_sign = false;
        flags: while (true) {
            switch (fmt[i]) {
                '0' => {
                    zero_pad = true;
                    i += 1;
                },
                '-' => {
                    left_align = true;
                    i += 1;
                },
                '+' => {
                    show_sign = true;
                    i += 1;
                },
                ' ', '#' => {
                    i += 1;
                },
                else => break :flags,
            }
        }
        _ = .{ left_align, show_sign };
        // width
        var width: u32 = 0;
        while (fmt[i] >= '0' and fmt[i] <= '9') : (i += 1) {
            width = width * 10 + (fmt[i] - '0');
        }
        // precision (consumed but ignored for ints; for %s we honor)
        var precision: i32 = -1;
        if (fmt[i] == '.') {
            i += 1;
            precision = 0;
            while (fmt[i] >= '0' and fmt[i] <= '9') : (i += 1) {
                precision = precision * 10 + (fmt[i] - '0');
            }
        }
        // length modifier
        var is_long: u8 = 0;
        while (true) {
            switch (fmt[i]) {
                'l' => {
                    is_long += 1;
                    i += 1;
                },
                'h' => {
                    i += 1;
                },
                'z', 'j', 't' => {
                    is_long = 1;
                    i += 1;
                },
                'L' => {
                    i += 1;
                },
                else => break,
            }
        }
        const spec = fmt[i];
        i += 1;
        switch (spec) {
            '%' => _ = putByte(state, '%'),
            'c' => {
                const v: c_int = @cVaArg(ap, c_int);
                _ = putByte(state, @truncate(@as(c_uint, @bitCast(v))));
            },
            's' => {
                const s = @cVaArg(ap, ?[*:0]const u8);
                if (s) |sp| {
                    var k: usize = 0;
                    while (sp[k] != 0 and (precision < 0 or k < @as(u32, @intCast(precision)))) : (k += 1) {
                        if (!putByte(state, sp[k])) return;
                    }
                } else {
                    const null_str = "(null)";
                    var k: usize = 0;
                    while (k < null_str.len) : (k += 1) {
                        if (!putByte(state, null_str[k])) return;
                    }
                }
            },
            'd', 'i' => {
                const v: i64 = if (is_long >= 1) @cVaArg(ap, c_long) else @cVaArg(ap, c_int);
                writeSigned(state, v, width, zero_pad);
            },
            'u' => {
                const v: u64 = if (is_long >= 1) @bitCast(@cVaArg(ap, c_long)) else @as(u64, @intCast(@cVaArg(ap, c_uint)));
                writeUnsigned(state, v, 10, false, width, zero_pad);
            },
            'x' => {
                const v: u64 = if (is_long >= 1) @bitCast(@cVaArg(ap, c_long)) else @as(u64, @intCast(@cVaArg(ap, c_uint)));
                writeUnsigned(state, v, 16, false, width, zero_pad);
            },
            'X' => {
                const v: u64 = if (is_long >= 1) @bitCast(@cVaArg(ap, c_long)) else @as(u64, @intCast(@cVaArg(ap, c_uint)));
                writeUnsigned(state, v, 16, true, width, zero_pad);
            },
            'o' => {
                const v: u64 = if (is_long >= 1) @bitCast(@cVaArg(ap, c_long)) else @as(u64, @intCast(@cVaArg(ap, c_uint)));
                writeUnsigned(state, v, 8, false, width, zero_pad);
            },
            'p' => {
                const v: usize = @intFromPtr(@cVaArg(ap, ?*const anyopaque) orelse @as(?*const anyopaque, null));
                _ = putByte(state, '0');
                _ = putByte(state, 'x');
                writeUnsigned(state, v, 16, false, 0, false);
            },
            'f', 'g', 'e', 'F', 'G', 'E' => {
                // Float formatting not implemented yet — emit placeholder.
                const placeholder = "<float>";
                var k: usize = 0;
                while (k < placeholder.len) : (k += 1) _ = putByte(state, placeholder[k]);
                _ = @cVaArg(ap, f64); // consume the va arg
            },
            else => {
                _ = putByte(state, '%');
                _ = putByte(state, spec);
            },
        }
        _ = std;
    }
}

// ── output sinks ─────────────────────────────────────────────────

const FileSink = struct {
    f: *FILE,
};

fn fileSinkPut(ctx: *anyopaque, byte: u8) callconv(.c) bool {
    const sink: *FileSink = @ptrCast(@alignCast(ctx));
    return fputc(byte, sink.f) != -1;
}

const BufSink = struct {
    buf: [*]u8,
    cap: usize,
    used: usize,
    truncate: bool,
};

fn bufSinkPut(ctx: *anyopaque, byte: u8) callconv(.c) bool {
    const sink: *BufSink = @ptrCast(@alignCast(ctx));
    if (sink.used + 1 < sink.cap) {
        sink.buf[sink.used] = byte;
        sink.used += 1;
        return true;
    }
    if (sink.truncate) return false;
    sink.used += 1;
    return true;
}

// ── public exports ──────────────────────────────────────────────

export fn vfprintf(f: ?*FILE, fmt: [*:0]const u8, ap: *@import("std").builtin.VaList) callconv(.c) c_int {
    const fp = f orelse return -1;
    var sink = FileSink{ .f = fp };
    var state = FmtState{ .out = fileSinkPut, .ctx = @ptrCast(&sink) };
    formatInto(&state, fmt, ap);
    return @intCast(state.written);
}

export fn fprintf(f: ?*FILE, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    const r = vfprintf(f, fmt, &ap);
    @cVaEnd(&ap);
    return r;
}

export fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    const r = vfprintf(stdout, fmt, &ap);
    @cVaEnd(&ap);
    return r;
}

export fn vsnprintf(buf: ?[*]u8, max: usize, fmt: [*:0]const u8, ap: *@import("std").builtin.VaList) callconv(.c) c_int {
    if (buf == null or max == 0) {
        // Count-only mode: walk fmt with a no-op sink. Approximate.
        var sink = BufSink{ .buf = undefined, .cap = 0, .used = 0, .truncate = false };
        var state = FmtState{ .out = bufSinkPut, .ctx = @ptrCast(&sink) };
        formatInto(&state, fmt, ap);
        return @intCast(state.written);
    }
    var sink = BufSink{ .buf = buf.?, .cap = max, .used = 0, .truncate = true };
    var state = FmtState{ .out = bufSinkPut, .ctx = @ptrCast(&sink) };
    formatInto(&state, fmt, ap);
    if (sink.used < max) buf.?[sink.used] = 0 else buf.?[max - 1] = 0;
    return @intCast(state.written);
}

export fn snprintf(buf: ?[*]u8, max: usize, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    const r = vsnprintf(buf, max, fmt, &ap);
    @cVaEnd(&ap);
    return r;
}

export fn sprintf(buf: [*]u8, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    const r = vsnprintf(buf, ~@as(usize, 0), fmt, &ap);
    @cVaEnd(&ap);
    return r;
}

export fn vsprintf(buf: [*]u8, fmt: [*:0]const u8, ap: *@import("std").builtin.VaList) callconv(.c) c_int {
    return vsnprintf(buf, ~@as(usize, 0), fmt, ap);
}

// FORTIFY _chk variants — pass through ignoring buflen.
export fn __printf_chk(flag: c_int, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = flag;
    var ap = @cVaStart();
    const r = vfprintf(stdout, fmt, &ap);
    @cVaEnd(&ap);
    return r;
}
export fn __fprintf_chk(f: ?*FILE, flag: c_int, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = flag;
    var ap = @cVaStart();
    const r = vfprintf(f, fmt, &ap);
    @cVaEnd(&ap);
    return r;
}
export fn __sprintf_chk(buf: [*]u8, flag: c_int, buflen: usize, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = .{ flag, buflen };
    var ap = @cVaStart();
    const r = vsnprintf(buf, ~@as(usize, 0), fmt, &ap);
    @cVaEnd(&ap);
    return r;
}
export fn __snprintf_chk(buf: ?[*]u8, max: usize, flag: c_int, buflen: usize, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = .{ flag, buflen };
    var ap = @cVaStart();
    const r = vsnprintf(buf, max, fmt, &ap);
    @cVaEnd(&ap);
    return r;
}
export fn __vsnprintf_chk(buf: ?[*]u8, max: usize, flag: c_int, buflen: usize, fmt: [*:0]const u8, ap: *@import("std").builtin.VaList) callconv(.c) c_int {
    _ = .{ flag, buflen };
    return vsnprintf(buf, max, fmt, ap);
}

export fn puts(s: [*:0]const u8) callconv(.c) c_int {
    if (fputs(s, stdout) < 0) return -1;
    if (fputc('\n', stdout) < 0) return -1;
    return 0;
}

export fn perror(msg: ?[*:0]const u8) callconv(.c) void {
    if (msg) |m| {
        _ = fputs(m, stderr);
        _ = fputs(": ", stderr);
    }
    _ = fputs("error\n", stderr);
}
