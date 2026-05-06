// libc surface the doomgeneric C build needs at link time. Every
// function is `export`-ed with C calling convention.
//
// Architecture:
//
//   - Memory: malloc / free / calloc / realloc are backed by
//     std.heap.FixedBufferAllocator over a heap region the Zig main
//     hands us at startup via setHeap(base, len). The FBA is wrapped
//     in a small bookkeeping header so realloc/free can recover the
//     original allocation length.
//   - Math: real implementations via std.math / @sin / @sqrt etc.
//   - printf family: std.fmt.bufPrint into a 1024-byte stack buffer,
//     routed through the COM1 log sink.
//   - File I/O: fopen against the embedded WAD blob (read-only) or a
//     heap-backed RAM file (write-mode). Fully in-memory — no fs server.
//   - Stubs: getenv → null; abort/exit → log + park; time() via the
//     timeMonotonic syscall.
//
// Doom-only — neighbouring services keep their own libc surfaces
// (currently only desktopOS/fs/sqlite/libc_shim.zig).

const std = @import("std");
const lib = @import("lib");
const com1 = @import("log");
const builtin = @import("builtin");
const syscall = lib.syscall;

// ============================================================================
// Heap — FixedBufferAllocator over a VMAR mapped by main.zig.
// ============================================================================

// std.heap.FixedBufferAllocator returns 16-byte-aligned blocks for any
// power-of-two alignment up to its `end_index`. We embed a small header
// in front of every allocation so free/realloc know the real length.
//
// Layout per allocation:
//   [u64 user_size][16-byte alignment pad][user_payload …]
const ALLOC_PREFIX_BYTES: usize = 16;

var heap_base: usize = 0;
var heap_len: usize = 0;
var fba: std.heap.FixedBufferAllocator = undefined;
var heap_initialized: bool = false;

pub fn setHeap(base_addr: usize, len: usize) void {
    const buf: [*]u8 = @ptrFromInt(base_addr);
    fba = std.heap.FixedBufferAllocator.init(buf[0..len]);
    heap_base = base_addr;
    heap_len = len;
    heap_initialized = true;
}

fn allocator() std.mem.Allocator {
    return fba.allocator();
}

fn allocBlock(n: usize) ?[*]u8 {
    if (!heap_initialized) panicShim("malloc before heap init");
    if (n == 0) return null;
    const total = ALLOC_PREFIX_BYTES + n;
    const block = allocator().alignedAlloc(u8, .@"16", total) catch return null;
    const hdr_ptr: *u64 = @ptrCast(@alignCast(block.ptr));
    hdr_ptr.* = @as(u64, n);
    return block.ptr + ALLOC_PREFIX_BYTES;
}

fn freeBlock(p: [*]u8) void {
    const block_ptr: [*]u8 = p - ALLOC_PREFIX_BYTES;
    const hdr_ptr: *const u64 = @ptrCast(@alignCast(block_ptr));
    const user_size: usize = @intCast(hdr_ptr.*);
    const total = ALLOC_PREFIX_BYTES + user_size;
    const aligned: []align(16) u8 = @alignCast(block_ptr[0..total]);
    allocator().free(aligned);
}

fn blockSize(p: [*]u8) usize {
    const block_ptr: [*]u8 = p - ALLOC_PREFIX_BYTES;
    const hdr_ptr: *const u64 = @ptrCast(@alignCast(block_ptr));
    return @intCast(hdr_ptr.*);
}

export fn malloc(n: usize) ?*anyopaque {
    const p = allocBlock(n) orelse return null;
    return @ptrCast(p);
}

export fn calloc(n: usize, m: usize) ?*anyopaque {
    const total = n * m;
    const p = allocBlock(total) orelse return null;
    var i: usize = 0;
    while (i < total) : (i += 1) p[i] = 0;
    return @ptrCast(p);
}

export fn realloc(maybe_p: ?*anyopaque, new_size: usize) ?*anyopaque {
    if (maybe_p == null) return malloc(new_size);
    if (new_size == 0) {
        free(maybe_p);
        return null;
    }
    const old_p: [*]u8 = @ptrCast(maybe_p.?);
    const old_size = blockSize(old_p);
    const new_p = allocBlock(new_size) orelse return null;
    const copy_n = if (old_size < new_size) old_size else new_size;
    var i: usize = 0;
    while (i < copy_n) : (i += 1) new_p[i] = old_p[i];
    freeBlock(old_p);
    return @ptrCast(new_p);
}

export fn free(maybe_p: ?*anyopaque) void {
    const p = maybe_p orelse return;
    freeBlock(@ptrCast(p));
}

// ============================================================================
// memory primitives
// ============================================================================

export fn memcpy(noalias dst: [*]u8, noalias src: [*]const u8, n: usize) [*]u8 {
    var i: usize = 0;
    while (i < n) : (i += 1) dst[i] = src[i];
    return dst;
}

export fn memmove(dst: [*]u8, src: [*]const u8, n: usize) [*]u8 {
    if (@intFromPtr(dst) < @intFromPtr(src)) {
        var i: usize = 0;
        while (i < n) : (i += 1) dst[i] = src[i];
    } else if (@intFromPtr(dst) > @intFromPtr(src)) {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            dst[i] = src[i];
        }
    }
    return dst;
}

export fn memset(s: [*]u8, c: c_int, n: usize) [*]u8 {
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var i: usize = 0;
    while (i < n) : (i += 1) s[i] = byte;
    return s;
}

export fn memcmp(a: [*]const u8, b: [*]const u8, n: usize) c_int {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) return @as(c_int, a[i]) - @as(c_int, b[i]);
    }
    return 0;
}

export fn memchr(s: [*]const u8, c: c_int, n: usize) ?[*]const u8 {
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (s[i] == byte) return s + i;
    }
    return null;
}

// ============================================================================
// string primitives
// ============================================================================

export fn strlen(s: [*:0]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    return i;
}

export fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int {
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) i += 1;
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

export fn strncmp(a: [*]const u8, b: [*]const u8, n: usize) c_int {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) return @as(c_int, a[i]) - @as(c_int, b[i]);
        if (a[i] == 0) return 0;
    }
    return 0;
}

export fn strcasecmp(a: [*:0]const u8, b: [*:0]const u8) c_int {
    var i: usize = 0;
    while (a[i] != 0 and b[i] != 0) : (i += 1) {
        const aa = asciiLower(a[i]);
        const bb = asciiLower(b[i]);
        if (aa != bb) return @as(c_int, aa) - @as(c_int, bb);
    }
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

export fn strncasecmp(a: [*]const u8, b: [*]const u8, n: usize) c_int {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const aa = asciiLower(a[i]);
        const bb = asciiLower(b[i]);
        if (aa != bb) return @as(c_int, aa) - @as(c_int, bb);
        if (a[i] == 0) return 0;
    }
    return 0;
}

fn asciiLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

export fn strcpy(dst: [*]u8, src: [*:0]const u8) [*]u8 {
    var i: usize = 0;
    while (true) {
        dst[i] = src[i];
        if (src[i] == 0) break;
        i += 1;
    }
    return dst;
}

export fn strncpy(dst: [*]u8, src: [*]const u8, n: usize) [*]u8 {
    var i: usize = 0;
    var hit_terminator = false;
    while (i < n) : (i += 1) {
        if (!hit_terminator and src[i] == 0) hit_terminator = true;
        dst[i] = if (hit_terminator) 0 else src[i];
    }
    return dst;
}

export fn strcat(dst: [*:0]u8, src: [*:0]const u8) [*:0]u8 {
    var d: usize = 0;
    while (dst[d] != 0) d += 1;
    var s: usize = 0;
    while (true) {
        dst[d + s] = src[s];
        if (src[s] == 0) break;
        s += 1;
    }
    return dst;
}

export fn strncat(dst: [*:0]u8, src: [*]const u8, n: usize) [*:0]u8 {
    var d: usize = 0;
    while (dst[d] != 0) d += 1;
    var s: usize = 0;
    while (s < n and src[s] != 0) : (s += 1) dst[d + s] = src[s];
    dst[d + s] = 0;
    return dst;
}

export fn strchr(s: [*:0]const u8, c: c_int) ?[*:0]const u8 {
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var i: usize = 0;
    while (true) : (i += 1) {
        if (s[i] == byte) return @ptrCast(s + i);
        if (s[i] == 0) return null;
    }
}

export fn strrchr(s: [*:0]const u8, c: c_int) ?[*:0]const u8 {
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var last: ?[*:0]const u8 = null;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (s[i] == byte) last = @ptrCast(s + i);
        if (s[i] == 0) return last;
    }
}

export fn strstr(haystack: [*:0]const u8, needle: [*:0]const u8) ?[*:0]const u8 {
    if (needle[0] == 0) return haystack;
    var i: usize = 0;
    while (haystack[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (needle[j] != 0 and haystack[i + j] == needle[j]) j += 1;
        if (needle[j] == 0) return @ptrCast(haystack + i);
    }
    return null;
}

export fn strspn(s: [*:0]const u8, accept: [*:0]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0 and indexOfChar(accept, s[i])) i += 1;
    return i;
}

export fn strcspn(s: [*:0]const u8, reject: [*:0]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0 and !indexOfChar(reject, s[i])) i += 1;
    return i;
}

export fn strpbrk(s: [*:0]const u8, accept: [*:0]const u8) ?[*:0]const u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        if (indexOfChar(accept, s[i])) return @ptrCast(s + i);
    }
    return null;
}

fn indexOfChar(set: [*:0]const u8, c: u8) bool {
    var i: usize = 0;
    while (set[i] != 0) : (i += 1) if (set[i] == c) return true;
    return false;
}

export fn strdup(s: [*:0]const u8) ?[*:0]u8 {
    const n = strlen(s);
    const p = allocBlock(n + 1) orelse return null;
    var i: usize = 0;
    while (i < n) : (i += 1) p[i] = s[i];
    p[n] = 0;
    return @ptrCast(p);
}

export fn strndup(s: [*:0]const u8, n: usize) ?[*:0]u8 {
    var actual: usize = 0;
    while (actual < n and s[actual] != 0) actual += 1;
    const p = allocBlock(actual + 1) orelse return null;
    var i: usize = 0;
    while (i < actual) : (i += 1) p[i] = s[i];
    p[actual] = 0;
    return @ptrCast(p);
}

export fn strerror(errnum: c_int) [*:0]const u8 {
    _ = errnum;
    const msg: [*:0]const u8 = "error";
    return msg;
}

// ============================================================================
// ctype
// ============================================================================

export fn isalpha(c: c_int) c_int {
    return @intFromBool((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'));
}
export fn isdigit(c: c_int) c_int {
    return @intFromBool(c >= '0' and c <= '9');
}
export fn isalnum(c: c_int) c_int {
    return @intFromBool(isalpha(c) != 0 or isdigit(c) != 0);
}
export fn isspace(c: c_int) c_int {
    return @intFromBool(c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0B or c == 0x0C);
}
export fn isxdigit(c: c_int) c_int {
    return @intFromBool(isdigit(c) != 0 or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'));
}
export fn isupper(c: c_int) c_int {
    return @intFromBool(c >= 'A' and c <= 'Z');
}
export fn islower(c: c_int) c_int {
    return @intFromBool(c >= 'a' and c <= 'z');
}
export fn isprint(c: c_int) c_int {
    return @intFromBool(c >= 0x20 and c < 0x7F);
}
export fn isgraph(c: c_int) c_int {
    return @intFromBool(c > 0x20 and c < 0x7F);
}
export fn ispunct(c: c_int) c_int {
    return @intFromBool(isprint(c) != 0 and isalnum(c) == 0 and c != ' ');
}
export fn iscntrl(c: c_int) c_int {
    return @intFromBool((c >= 0 and c < 0x20) or c == 0x7F);
}
export fn isblank(c: c_int) c_int {
    return @intFromBool(c == ' ' or c == '\t');
}
export fn tolower(c: c_int) c_int {
    if (c >= 'A' and c <= 'Z') return c + ('a' - 'A');
    return c;
}
export fn toupper(c: c_int) c_int {
    if (c >= 'a' and c <= 'z') return c - ('a' - 'A');
    return c;
}

// ============================================================================
// numeric parsing
// ============================================================================

export fn atoi(s: [*:0]const u8) c_int {
    return @truncate(atolImpl(s));
}

export fn atol(s: [*:0]const u8) c_long {
    return atolImpl(s);
}

export fn atof(s: [*:0]const u8) f64 {
    return strtodImpl(s, null);
}

fn atolImpl(s: [*:0]const u8) c_long {
    var i: usize = 0;
    while (isspace(s[i]) != 0) i += 1;
    var neg: bool = false;
    if (s[i] == '-') {
        neg = true;
        i += 1;
    } else if (s[i] == '+') {
        i += 1;
    }
    var n: c_long = 0;
    while (s[i] >= '0' and s[i] <= '9') : (i += 1) {
        n = n * 10 + @as(c_long, s[i] - '0');
    }
    return if (neg) -n else n;
}

export fn strtol(s: [*:0]const u8, endp: ?*[*:0]const u8, base: c_int) c_long {
    var i: usize = 0;
    while (isspace(s[i]) != 0) i += 1;
    var neg: bool = false;
    if (s[i] == '-') {
        neg = true;
        i += 1;
    } else if (s[i] == '+') {
        i += 1;
    }

    var bv: c_long = base;
    if (bv == 0) bv = 10;
    if (bv == 16 and s[i] == '0' and (s[i + 1] == 'x' or s[i + 1] == 'X')) i += 2;

    var n: c_long = 0;
    while (true) {
        const ch = s[i];
        var digit: c_long = -1;
        if (ch >= '0' and ch <= '9') digit = ch - '0';
        if (ch >= 'a' and ch <= 'z') digit = ch - 'a' + 10;
        if (ch >= 'A' and ch <= 'Z') digit = ch - 'A' + 10;
        if (digit < 0 or digit >= bv) break;
        n = n * bv + digit;
        i += 1;
    }
    if (endp) |p| p.* = @ptrCast(s + i);
    return if (neg) -n else n;
}

export fn strtoul(s: [*:0]const u8, endp: ?*[*:0]const u8, base: c_int) c_ulong {
    return @bitCast(strtol(s, endp, base));
}

export fn strtod(s: [*:0]const u8, endp: ?*[*:0]const u8) f64 {
    return strtodImpl(s, endp);
}

// Tiny strtod sufficient for Doom config-file parsing of floats like
// "2.0", "0.5", "-0.25". Doesn't handle exponents.
fn strtodImpl(s: [*:0]const u8, endp: ?*[*:0]const u8) f64 {
    var i: usize = 0;
    while (isspace(s[i]) != 0) i += 1;
    var neg: bool = false;
    if (s[i] == '-') {
        neg = true;
        i += 1;
    } else if (s[i] == '+') {
        i += 1;
    }
    var n: f64 = 0.0;
    while (s[i] >= '0' and s[i] <= '9') : (i += 1) {
        n = n * 10.0 + @as(f64, @floatFromInt(s[i] - '0'));
    }
    if (s[i] == '.') {
        i += 1;
        var frac: f64 = 0.1;
        while (s[i] >= '0' and s[i] <= '9') : (i += 1) {
            n += @as(f64, @floatFromInt(s[i] - '0')) * frac;
            frac *= 0.1;
        }
    }
    if (endp) |p| p.* = @ptrCast(s + i);
    return if (neg) -n else n;
}

export fn abs(x: c_int) c_int {
    return if (x < 0) -x else x;
}

export fn labs(x: c_long) c_long {
    return if (x < 0) -x else x;
}

// ============================================================================
// qsort / bsearch
// ============================================================================

export fn qsort(
    base: [*]u8,
    nmemb: usize,
    size: usize,
    cmp: *const fn (a: ?*const anyopaque, b: ?*const anyopaque) callconv(.c) c_int,
) void {
    var i: usize = 1;
    while (i < nmemb) : (i += 1) {
        var j: usize = i;
        while (j > 0) {
            const a = base + (j - 1) * size;
            const b = base + j * size;
            if (cmp(a, b) <= 0) break;
            var k: usize = 0;
            while (k < size) : (k += 1) {
                const tmp = a[k];
                a[k] = b[k];
                b[k] = tmp;
            }
            j -= 1;
        }
    }
}

export fn bsearch(
    key: ?*const anyopaque,
    base: [*]const u8,
    nmemb: usize,
    size: usize,
    cmp: *const fn (a: ?*const anyopaque, b: ?*const anyopaque) callconv(.c) c_int,
) ?*const anyopaque {
    var lo: usize = 0;
    var hi: usize = nmemb;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const elt = base + mid * size;
        const r = cmp(key, @ptrCast(elt));
        if (r == 0) return @ptrCast(elt);
        if (r < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return null;
}

// ============================================================================
// random — tiny LCG. Doom's gameplay RNG (m_random.c) uses its own
// table-driven generator; the libc rand() is only touched by some
// engine-init helpers.
// ============================================================================

var rand_state: u32 = 1;

export fn rand() c_int {
    rand_state = rand_state *% 1103515245 +% 12345;
    return @bitCast(rand_state >> 1);
}

export fn srand(seed: c_uint) void {
    rand_state = @bitCast(seed);
}

// ============================================================================
// math — real implementations
// ============================================================================

export fn sqrt(x: f64) f64 {
    return @sqrt(x);
}
export fn sqrtf(x: f32) f32 {
    return @sqrt(x);
}
export fn floor(x: f64) f64 {
    return @floor(x);
}
export fn floorf(x: f32) f32 {
    return @floor(x);
}
export fn ceil(x: f64) f64 {
    return @ceil(x);
}
export fn ceilf(x: f32) f32 {
    return @ceil(x);
}
export fn round(x: f64) f64 {
    return @round(x);
}
export fn trunc(x: f64) f64 {
    return @trunc(x);
}
export fn fabs(x: f64) f64 {
    return @abs(x);
}
export fn fabsf(x: f32) f32 {
    return @abs(x);
}
export fn sin(x: f64) f64 {
    return @sin(x);
}
export fn sinf(x: f32) f32 {
    return @sin(x);
}
export fn cos(x: f64) f64 {
    return @cos(x);
}
export fn cosf(x: f32) f32 {
    return @cos(x);
}
export fn tan(x: f64) f64 {
    return std.math.tan(x);
}
export fn asin(x: f64) f64 {
    return std.math.asin(x);
}
export fn acos(x: f64) f64 {
    return std.math.acos(x);
}
export fn atan(x: f64) f64 {
    return std.math.atan(x);
}
export fn atan2(y: f64, x: f64) f64 {
    return std.math.atan2(y, x);
}
export fn pow(x: f64, y: f64) f64 {
    return std.math.pow(f64, x, y);
}
export fn exp(x: f64) f64 {
    return @exp(x);
}
export fn log(x: f64) f64 {
    return @log(x);
}
export fn log10(x: f64) f64 {
    return @log10(x);
}
export fn log2(x: f64) f64 {
    return @log2(x);
}
export fn fmod(x: f64, y: f64) f64 {
    return @mod(x, y);
}
export fn sinh(x: f64) f64 {
    return std.math.sinh(x);
}
export fn cosh(x: f64) f64 {
    return std.math.cosh(x);
}
export fn tanh(x: f64) f64 {
    return std.math.tanh(x);
}

export fn ldexp(x: f64, exp_i: c_int) f64 {
    return std.math.ldexp(x, @intCast(exp_i));
}

export fn frexp(x: f64, exp_out: *c_int) f64 {
    const r = std.math.frexp(x);
    exp_out.* = @intCast(r.exponent);
    return r.significand;
}

export fn isnan(x: f64) c_int {
    return @intFromBool(std.math.isNan(x));
}

export fn isinf(x: f64) c_int {
    return @intFromBool(std.math.isInf(x));
}

export fn isfinite(x: f64) c_int {
    return @intFromBool(std.math.isFinite(x));
}

// ============================================================================
// printf family — std.fmt routed through the COM1 log
// ============================================================================

const PRINTF_BUF_BYTES: usize = 1024;

// Tiny printf formatter implemented over std.fmt.bufPrint for the small
// subset Doom + the platform shim use: %s, %d, %i, %u, %x, %X, %ld,
// %lu, %c, %p, %f, %lf, %%, plus length specifiers (l, ll). Field
// width and precision follow.
fn formatVa(out: []u8, fmt_z: [*:0]const u8, ap_in: *std.builtin.VaList) usize {
    var idx: usize = 0;
    var fi: usize = 0;
    while (fmt_z[fi] != 0 and idx < out.len) {
        if (fmt_z[fi] != '%') {
            out[idx] = fmt_z[fi];
            idx += 1;
            fi += 1;
            continue;
        }
        fi += 1; // past '%'
        // Flags
        var flag_left = false;
        var flag_zero = false;
        var flag_plus = false;
        var flag_space = false;
        var flag_alt = false;
        while (true) : (fi += 1) {
            switch (fmt_z[fi]) {
                '-' => flag_left = true,
                '0' => flag_zero = true,
                '+' => flag_plus = true,
                ' ' => flag_space = true,
                '#' => flag_alt = true,
                else => break,
            }
        }
        // Width
        var width: usize = 0;
        if (fmt_z[fi] == '*') {
            const w: c_int = @cVaArg(ap_in, c_int);
            if (w > 0) width = @intCast(w);
            fi += 1;
        } else {
            while (fmt_z[fi] >= '0' and fmt_z[fi] <= '9') : (fi += 1) {
                width = width * 10 + (fmt_z[fi] - '0');
            }
        }
        // Precision
        var precision: ?usize = null;
        if (fmt_z[fi] == '.') {
            fi += 1;
            var p: usize = 0;
            if (fmt_z[fi] == '*') {
                const pp: c_int = @cVaArg(ap_in, c_int);
                if (pp > 0) p = @intCast(pp);
                fi += 1;
            } else {
                while (fmt_z[fi] >= '0' and fmt_z[fi] <= '9') : (fi += 1) {
                    p = p * 10 + (fmt_z[fi] - '0');
                }
            }
            precision = p;
        }
        // Length
        var len_long: u8 = 0;
        if (fmt_z[fi] == 'h') {
            fi += 1;
            if (fmt_z[fi] == 'h') fi += 1;
        } else if (fmt_z[fi] == 'l') {
            fi += 1;
            len_long = 1;
            if (fmt_z[fi] == 'l') {
                fi += 1;
                len_long = 2;
            }
        } else if (fmt_z[fi] == 'z') {
            fi += 1;
            len_long = 1;
        }
        // Conversion
        const conv = fmt_z[fi];
        fi += 1;

        var tmp: [64]u8 = undefined;
        var tmp_used: usize = 0;
        switch (conv) {
            '%' => {
                out[idx] = '%';
                idx += 1;
            },
            's' => {
                const sv: ?[*:0]const u8 = @cVaArg(ap_in, ?[*:0]const u8);
                if (sv) |s| {
                    var k: usize = 0;
                    while (s[k] != 0) : (k += 1) {
                        if (precision) |p| if (k >= p) break;
                    }
                    idx = padCopy(out, idx, s[0..k], width, flag_left);
                } else {
                    idx = padCopy(out, idx, "(null)", width, flag_left);
                }
            },
            'c' => {
                const ch: c_int = @cVaArg(ap_in, c_int);
                tmp[0] = @truncate(@as(c_uint, @bitCast(ch)));
                idx = padCopy(out, idx, tmp[0..1], width, flag_left);
            },
            'd', 'i' => {
                const v: i64 = if (len_long == 0)
                    @as(i64, @cVaArg(ap_in, c_int))
                else if (len_long == 1)
                    @as(i64, @cVaArg(ap_in, c_long))
                else
                    @cVaArg(ap_in, i64);
                tmp_used = formatInt(&tmp, v, 10, false, false, flag_plus, flag_space);
                idx = padNumeric(out, idx, tmp[0..tmp_used], width, flag_left, flag_zero);
            },
            'u' => {
                const v: u64 = if (len_long == 0)
                    @as(u64, @cVaArg(ap_in, c_uint))
                else if (len_long == 1)
                    @as(u64, @cVaArg(ap_in, c_ulong))
                else
                    @cVaArg(ap_in, u64);
                tmp_used = formatUint(&tmp, v, 10, false, false);
                idx = padNumeric(out, idx, tmp[0..tmp_used], width, flag_left, flag_zero);
            },
            'x' => {
                const v: u64 = if (len_long == 0)
                    @as(u64, @cVaArg(ap_in, c_uint))
                else if (len_long == 1)
                    @as(u64, @cVaArg(ap_in, c_ulong))
                else
                    @cVaArg(ap_in, u64);
                tmp_used = formatUint(&tmp, v, 16, false, flag_alt);
                idx = padNumeric(out, idx, tmp[0..tmp_used], width, flag_left, flag_zero);
            },
            'X' => {
                const v: u64 = if (len_long == 0)
                    @as(u64, @cVaArg(ap_in, c_uint))
                else if (len_long == 1)
                    @as(u64, @cVaArg(ap_in, c_ulong))
                else
                    @cVaArg(ap_in, u64);
                tmp_used = formatUint(&tmp, v, 16, true, flag_alt);
                idx = padNumeric(out, idx, tmp[0..tmp_used], width, flag_left, flag_zero);
            },
            'p' => {
                const pv: ?*const anyopaque = @cVaArg(ap_in, ?*const anyopaque);
                const v: u64 = @intFromPtr(pv);
                tmp_used = formatUint(&tmp, v, 16, false, true);
                idx = padCopy(out, idx, tmp[0..tmp_used], width, flag_left);
            },
            'f', 'F', 'g', 'G', 'e', 'E', 'a' => {
                const fv: f64 = @cVaArg(ap_in, f64);
                tmp_used = formatFloat(&tmp, fv, precision orelse 6);
                idx = padNumeric(out, idx, tmp[0..tmp_used], width, flag_left, flag_zero);
            },
            'n' => {
                // No-op; writing %n is a security footgun and Doom doesn't
                // need it for anything correct.
            },
            else => {
                if (idx + 1 < out.len) {
                    out[idx] = '%';
                    idx += 1;
                    if (idx < out.len) {
                        out[idx] = conv;
                        idx += 1;
                    }
                }
            },
        }
    }
    return idx;
}

fn padCopy(out: []u8, idx0: usize, src: []const u8, width: usize, left: bool) usize {
    var idx = idx0;
    if (src.len >= width) {
        return appendBytes(out, idx, src);
    }
    const pad_n = width - src.len;
    if (!left) {
        var i: usize = 0;
        while (i < pad_n and idx < out.len) : (i += 1) {
            out[idx] = ' ';
            idx += 1;
        }
        idx = appendBytes(out, idx, src);
    } else {
        idx = appendBytes(out, idx, src);
        var i: usize = 0;
        while (i < pad_n and idx < out.len) : (i += 1) {
            out[idx] = ' ';
            idx += 1;
        }
    }
    return idx;
}

fn padNumeric(out: []u8, idx0: usize, src: []const u8, width: usize, left: bool, zero: bool) usize {
    var idx = idx0;
    if (src.len >= width) return appendBytes(out, idx, src);
    const pad_n = width - src.len;
    const pad: u8 = if (zero and !left) '0' else ' ';
    if (!left) {
        var i: usize = 0;
        while (i < pad_n and idx < out.len) : (i += 1) {
            out[idx] = pad;
            idx += 1;
        }
        idx = appendBytes(out, idx, src);
    } else {
        idx = appendBytes(out, idx, src);
        var i: usize = 0;
        while (i < pad_n and idx < out.len) : (i += 1) {
            out[idx] = ' ';
            idx += 1;
        }
    }
    return idx;
}

fn appendBytes(out: []u8, idx0: usize, src: []const u8) usize {
    var idx = idx0;
    var i: usize = 0;
    while (i < src.len and idx < out.len) : (i += 1) {
        out[idx] = src[i];
        idx += 1;
    }
    return idx;
}

fn formatInt(buf: []u8, v: i64, base: u8, upper: bool, alt: bool, plus: bool, space: bool) usize {
    _ = alt;
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    const neg = v < 0;
    var u: u64 = if (neg) @bitCast(-v) else @intCast(v);
    var rev: [32]u8 = undefined;
    var n: usize = 0;
    while (u != 0) {
        const d: u8 = @intCast(u % base);
        rev[n] = if (d < 10) '0' + d else if (upper) 'A' + (d - 10) else 'a' + (d - 10);
        u /= base;
        n += 1;
    }
    var idx: usize = 0;
    if (neg) {
        buf[idx] = '-';
        idx += 1;
    } else if (plus) {
        buf[idx] = '+';
        idx += 1;
    } else if (space) {
        buf[idx] = ' ';
        idx += 1;
    }
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        buf[idx] = rev[i];
        idx += 1;
    }
    return idx;
}

fn formatUint(buf: []u8, v: u64, base: u8, upper: bool, alt: bool) usize {
    var idx: usize = 0;
    if (alt and base == 16) {
        buf[idx] = '0';
        idx += 1;
        buf[idx] = if (upper) 'X' else 'x';
        idx += 1;
    }
    if (v == 0) {
        buf[idx] = '0';
        return idx + 1;
    }
    var u = v;
    var rev: [32]u8 = undefined;
    var n: usize = 0;
    while (u != 0) {
        const d: u8 = @intCast(u % base);
        rev[n] = if (d < 10) '0' + d else if (upper) 'A' + (d - 10) else 'a' + (d - 10);
        u /= base;
        n += 1;
    }
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        buf[idx] = rev[i];
        idx += 1;
    }
    return idx;
}

// Tiny float formatter — fixed-point with `prec` digits after the
// decimal. Doom rarely uses %f; only m_config "%f" config writes touch
// it. Rounds toward zero.
fn formatFloat(buf: []u8, value: f64, prec: usize) usize {
    var v = value;
    var idx: usize = 0;
    if (std.math.isNan(v)) {
        const s = "nan";
        var i: usize = 0;
        while (i < s.len) : (i += 1) buf[idx + i] = s[i];
        return s.len;
    }
    if (std.math.isInf(v)) {
        const s: []const u8 = if (v < 0) "-inf" else "inf";
        var i: usize = 0;
        while (i < s.len) : (i += 1) buf[idx + i] = s[i];
        return s.len;
    }
    if (v < 0) {
        buf[idx] = '-';
        idx += 1;
        v = -v;
    }
    const int_part: u64 = @intFromFloat(@floor(v));
    var frac = v - @as(f64, @floatFromInt(int_part));
    const int_n = formatUint(buf[idx..], int_part, 10, false, false);
    idx += int_n;
    if (prec > 0) {
        buf[idx] = '.';
        idx += 1;
        var p: usize = 0;
        while (p < prec) : (p += 1) {
            frac *= 10.0;
            const d: u8 = @intFromFloat(@floor(frac));
            const dd: u8 = if (d > 9) 9 else d;
            buf[idx] = '0' + dd;
            idx += 1;
            frac -= @as(f64, @floatFromInt(dd));
        }
    }
    return idx;
}

fn vformatToBuf(out: []u8, fmt_z: [*:0]const u8, ap: *std.builtin.VaList) usize {
    return formatVa(out, fmt_z, ap);
}

export fn printf(fmt_z: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var buf: [PRINTF_BUF_BYTES]u8 = undefined;
    const n = vformatToBuf(&buf, fmt_z, &ap);
    com1.print(buf[0..n]);
    return @intCast(n);
}

export fn fprintf(stream: ?*FILE, fmt_z: [*:0]const u8, ...) callconv(.c) c_int {
    _ = stream;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var buf: [PRINTF_BUF_BYTES]u8 = undefined;
    const n = vformatToBuf(&buf, fmt_z, &ap);
    com1.print(buf[0..n]);
    return @intCast(n);
}

export fn vfprintf(stream: ?*FILE, fmt_z: [*:0]const u8, ap_in: std.builtin.VaList) callconv(.c) c_int {
    _ = stream;
    var ap = @cVaCopy(@constCast(&ap_in));
    defer @cVaEnd(&ap);
    var buf: [PRINTF_BUF_BYTES]u8 = undefined;
    const n = vformatToBuf(&buf, fmt_z, &ap);
    com1.print(buf[0..n]);
    return @intCast(n);
}

export fn vprintf(fmt_z: [*:0]const u8, ap_in: std.builtin.VaList) callconv(.c) c_int {
    var ap = @cVaCopy(@constCast(&ap_in));
    defer @cVaEnd(&ap);
    var buf: [PRINTF_BUF_BYTES]u8 = undefined;
    const n = vformatToBuf(&buf, fmt_z, &ap);
    com1.print(buf[0..n]);
    return @intCast(n);
}

export fn snprintf(dst: [*]u8, n: usize, fmt_z: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    if (n == 0) return 0;
    const out = dst[0 .. n - 1];
    const written = vformatToBuf(out, fmt_z, &ap);
    dst[written] = 0;
    return @intCast(written);
}

export fn vsnprintf(dst: [*]u8, n: usize, fmt_z: [*:0]const u8, ap_in: std.builtin.VaList) callconv(.c) c_int {
    var ap = @cVaCopy(@constCast(&ap_in));
    defer @cVaEnd(&ap);
    if (n == 0) return 0;
    const out = dst[0 .. n - 1];
    const written = vformatToBuf(out, fmt_z, &ap);
    dst[written] = 0;
    return @intCast(written);
}

export fn sprintf(dst: [*]u8, fmt_z: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    // No bound — assume caller has enough room. Format into a scratch
    // and copy out. Cap at PRINTF_BUF_BYTES; Doom's sprintf call sites
    // are short status strings.
    var buf: [PRINTF_BUF_BYTES]u8 = undefined;
    const n = vformatToBuf(&buf, fmt_z, &ap);
    var i: usize = 0;
    while (i < n) : (i += 1) dst[i] = buf[i];
    dst[n] = 0;
    return @intCast(n);
}

export fn vsprintf(dst: [*]u8, fmt_z: [*:0]const u8, ap_in: std.builtin.VaList) callconv(.c) c_int {
    var ap = @cVaCopy(@constCast(&ap_in));
    defer @cVaEnd(&ap);
    var buf: [PRINTF_BUF_BYTES]u8 = undefined;
    const n = vformatToBuf(&buf, fmt_z, &ap);
    var i: usize = 0;
    while (i < n) : (i += 1) dst[i] = buf[i];
    dst[n] = 0;
    return @intCast(n);
}

export fn sscanf(src: [*:0]const u8, fmt_z: [*:0]const u8, ...) callconv(.c) c_int {
    _ = src;
    _ = fmt_z;
    // Doom uses sscanf in m_config.c to read back integer/float defaults.
    // This service writes a fresh config every run via fprintf, so the
    // read path never reaches sscanf — defaults are applied via the
    // hard-coded table values. Stub.
    return 0;
}

export fn fscanf(stream: ?*FILE, fmt_z: [*:0]const u8, ...) callconv(.c) c_int {
    _ = stream;
    _ = fmt_z;
    return 0;
}

// ============================================================================
// stdio — fopen / fread / fwrite / fclose / fseek / ftell / feof / ungetc
// ============================================================================
//
// FILE handles refer to entries in the `file_table`. Each handle is
// either:
//   - a read-only view of the embedded WAD blob (set via setWadBlob);
//   - a heap-backed RAM file (write-mode fopen). Writes grow the
//     buffer on demand.

pub const FILE = anyopaque;

const FileBackend = enum { wad, ram };

const RamFile = struct {
    buf: ?[]u8,
    cap: usize,
    len: usize,
    pos: usize,
};

const WadFile = struct {
    blob: []const u8,
    pos: usize,
};

const FileEntry = struct {
    used: bool,
    eof: bool,
    err: bool,
    pushback: i32, // ungetc one-byte pushback, or -1
    backend: FileBackend,
    wad: WadFile,
    ram: RamFile,
};

const FILE_TABLE_CAP: usize = 16;
var file_table: [FILE_TABLE_CAP]FileEntry = undefined;
var file_table_initialized: bool = false;

var wad_blob: []const u8 = &.{};

pub fn setWadBlob(blob: []const u8) void {
    wad_blob = blob;
}

fn ensureTable() void {
    if (file_table_initialized) return;
    var i: usize = 0;
    while (i < FILE_TABLE_CAP) : (i += 1) {
        file_table[i].used = false;
        file_table[i].pushback = -1;
    }
    file_table_initialized = true;
}

fn allocFileEntry() ?usize {
    ensureTable();
    var i: usize = 0;
    while (i < FILE_TABLE_CAP) : (i += 1) {
        if (!file_table[i].used) {
            file_table[i].used = true;
            file_table[i].eof = false;
            file_table[i].err = false;
            file_table[i].pushback = -1;
            return i;
        }
    }
    return null;
}

// Stable fake addresses for stdin/stdout/stderr.
var stdin_obj: u8 = 0;
var stdout_obj: u8 = 0;
var stderr_obj: u8 = 0;

export var stdin: ?*FILE = null;
export var stdout: ?*FILE = null;
export var stderr: ?*FILE = null;

pub fn initStdio() void {
    stdin = @ptrCast(&stdin_obj);
    stdout = @ptrCast(&stdout_obj);
    stderr = @ptrCast(&stderr_obj);
}

fn entryFromFile(stream: ?*FILE) ?*FileEntry {
    if (stream) |sp| {
        const addr = @intFromPtr(sp);
        // stdin/stdout/stderr are routed to a sink — the caller expects
        // print-to-log via fputs/fputc/fprintf. We return null here so
        // the byte-level fread/fseek paths don't try to index file_table
        // for them. The print-side helpers handle these specially.
        if (addr == @intFromPtr(&stdin_obj)) return null;
        if (addr == @intFromPtr(&stdout_obj)) return null;
        if (addr == @intFromPtr(&stderr_obj)) return null;
        // Otherwise the FILE* is a tagged pointer into file_table:
        // we encode the entry index as a multiple of 256 plus the
        // file_table base. Simpler: we return the tagged address.
        const base = @intFromPtr(&file_table[0]);
        const stride = @sizeOf(FileEntry);
        if (addr >= base and addr < base + FILE_TABLE_CAP * stride) {
            const idx = (addr - base) / stride;
            return &file_table[idx];
        }
    }
    return null;
}

fn fileToFile(idx: usize) *FILE {
    return @ptrCast(&file_table[idx]);
}

export fn fopen(path_z: [*:0]const u8, mode_z: [*:0]const u8) ?*FILE {
    ensureTable();
    // Read mode → embed-WAD path. Anything not matching the WAD name
    // resolves to NULL — Doom falls through to its default-IWAD search
    // which we short-circuit by name match in main.zig.
    const m0 = mode_z[0];
    const writable = m0 == 'w' or m0 == 'a';
    if (!writable) {
        // Read mode: only the embedded WAD blob is reachable.
        if (matchesWad(path_z)) {
            const idx = allocFileEntry() orelse return null;
            file_table[idx].backend = .wad;
            file_table[idx].wad = .{ .blob = wad_blob, .pos = 0 };
            file_table[idx].ram = .{ .buf = null, .cap = 0, .len = 0, .pos = 0 };
            return fileToFile(idx);
        }
        return null;
    }
    // Write mode: hand back a RAM-backed sink.
    const idx = allocFileEntry() orelse return null;
    file_table[idx].backend = .ram;
    file_table[idx].wad = .{ .blob = &.{}, .pos = 0 };
    file_table[idx].ram = .{ .buf = null, .cap = 0, .len = 0, .pos = 0 };
    return fileToFile(idx);
}

fn matchesWad(path_z: [*:0]const u8) bool {
    if (wad_blob.len == 0) return false;
    // Match if the path's basename ends in .wad/.WAD (case-insensitive).
    var n: usize = 0;
    while (path_z[n] != 0) n += 1;
    if (n < 4) return false;
    const e0 = asciiLower(path_z[n - 4]);
    const e1 = asciiLower(path_z[n - 3]);
    const e2 = asciiLower(path_z[n - 2]);
    const e3 = asciiLower(path_z[n - 1]);
    return e0 == '.' and e1 == 'w' and e2 == 'a' and e3 == 'd';
}

export fn fclose(stream: ?*FILE) c_int {
    const e = entryFromFile(stream) orelse return 0;
    if (e.backend == .ram) {
        if (e.ram.buf) |b| {
            const aligned: []align(16) u8 = @alignCast(b);
            allocator().free(aligned);
        }
        e.ram = .{ .buf = null, .cap = 0, .len = 0, .pos = 0 };
    }
    e.used = false;
    return 0;
}

export fn fread(buf: [*]u8, size: usize, nmemb: usize, stream: ?*FILE) usize {
    const e = entryFromFile(stream) orelse return 0;
    const want = size * nmemb;
    var got: usize = 0;
    // Drain any pushback first.
    if (e.pushback >= 0 and got < want) {
        buf[got] = @truncate(@as(c_uint, @bitCast(e.pushback)));
        e.pushback = -1;
        got += 1;
    }
    switch (e.backend) {
        .wad => {
            const blob = e.wad.blob;
            while (got < want) {
                if (e.wad.pos >= blob.len) {
                    e.eof = true;
                    break;
                }
                buf[got] = blob[e.wad.pos];
                e.wad.pos += 1;
                got += 1;
            }
        },
        .ram => {
            const ram_buf = e.ram.buf orelse {
                e.eof = true;
                return got / size;
            };
            while (got < want) {
                if (e.ram.pos >= e.ram.len) {
                    e.eof = true;
                    break;
                }
                buf[got] = ram_buf[e.ram.pos];
                e.ram.pos += 1;
                got += 1;
            }
        },
    }
    return got / size;
}

export fn fwrite(buf: [*]const u8, size: usize, nmemb: usize, stream: ?*FILE) usize {
    if (stream) |sp| {
        const addr = @intFromPtr(sp);
        if (addr == @intFromPtr(&stdout_obj) or addr == @intFromPtr(&stderr_obj)) {
            const total = size * nmemb;
            com1.print(buf[0..total]);
            return nmemb;
        }
    }
    const e = entryFromFile(stream) orelse return 0;
    if (e.backend == .wad) {
        e.err = true;
        return 0;
    }
    const total = size * nmemb;
    if (!ramReserve(e, e.ram.pos + total)) {
        e.err = true;
        return 0;
    }
    const ram_buf = e.ram.buf.?;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        ram_buf[e.ram.pos + i] = buf[i];
    }
    e.ram.pos += total;
    if (e.ram.pos > e.ram.len) e.ram.len = e.ram.pos;
    return nmemb;
}

fn ramReserve(e: *FileEntry, want_cap: usize) bool {
    if (want_cap <= e.ram.cap) return true;
    var new_cap: usize = if (e.ram.cap == 0) 4096 else e.ram.cap * 2;
    while (new_cap < want_cap) new_cap *= 2;
    const new_buf = allocator().alignedAlloc(u8, .@"16", new_cap) catch return false;
    if (e.ram.buf) |old| {
        var i: usize = 0;
        while (i < e.ram.len) : (i += 1) new_buf[i] = old[i];
        const aligned: []align(16) u8 = @alignCast(old);
        allocator().free(aligned);
    }
    e.ram.buf = new_buf;
    e.ram.cap = new_cap;
    return true;
}

export fn fseek(stream: ?*FILE, offset: c_long, whence: c_int) c_int {
    const e = entryFromFile(stream) orelse return -1;
    e.eof = false;
    e.pushback = -1;
    switch (e.backend) {
        .wad => {
            const blob_len = e.wad.blob.len;
            const new_pos: c_long = switch (whence) {
                0 => offset, // SEEK_SET
                1 => @as(c_long, @intCast(e.wad.pos)) + offset,
                2 => @as(c_long, @intCast(blob_len)) + offset,
                else => return -1,
            };
            if (new_pos < 0) return -1;
            e.wad.pos = @intCast(new_pos);
        },
        .ram => {
            const new_pos: c_long = switch (whence) {
                0 => offset,
                1 => @as(c_long, @intCast(e.ram.pos)) + offset,
                2 => @as(c_long, @intCast(e.ram.len)) + offset,
                else => return -1,
            };
            if (new_pos < 0) return -1;
            e.ram.pos = @intCast(new_pos);
        },
    }
    return 0;
}

export fn ftell(stream: ?*FILE) c_long {
    const e = entryFromFile(stream) orelse return -1;
    return switch (e.backend) {
        .wad => @intCast(e.wad.pos),
        .ram => @intCast(e.ram.pos),
    };
}

export fn rewind(stream: ?*FILE) void {
    _ = fseek(stream, 0, 0);
}

export fn feof(stream: ?*FILE) c_int {
    const e = entryFromFile(stream) orelse return 1;
    return @intFromBool(e.eof);
}

export fn ferror(stream: ?*FILE) c_int {
    const e = entryFromFile(stream) orelse return 0;
    return @intFromBool(e.err);
}

export fn clearerr(stream: ?*FILE) void {
    const e = entryFromFile(stream) orelse return;
    e.eof = false;
    e.err = false;
}

export fn fflush(stream: ?*FILE) c_int {
    _ = stream;
    return 0;
}

export fn ungetc(c: c_int, stream: ?*FILE) c_int {
    const e = entryFromFile(stream) orelse return -1;
    e.pushback = c;
    e.eof = false;
    return c;
}

export fn fgetc(stream: ?*FILE) c_int {
    var ch: u8 = 0;
    const got = fread(@as([*]u8, @ptrCast(&ch)), 1, 1, stream);
    if (got == 0) return -1;
    return @as(c_int, ch);
}

export fn getc(stream: ?*FILE) c_int {
    return fgetc(stream);
}

export fn fputc(c: c_int, stream: ?*FILE) c_int {
    if (stream) |sp| {
        const addr = @intFromPtr(sp);
        if (addr == @intFromPtr(&stdout_obj) or addr == @intFromPtr(&stderr_obj)) {
            com1.putc(@truncate(@as(c_uint, @bitCast(c))));
            return c;
        }
    }
    var ch: u8 = @truncate(@as(c_uint, @bitCast(c)));
    _ = fwrite(@as([*]const u8, @ptrCast(&ch)), 1, 1, stream);
    return c;
}

export fn putc(c: c_int, stream: ?*FILE) c_int {
    return fputc(c, stream);
}

export fn putchar(c: c_int) c_int {
    com1.putc(@truncate(@as(c_uint, @bitCast(c))));
    return c;
}

export fn puts(s: [*:0]const u8) c_int {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    com1.print(s[0..i]);
    com1.putc('\n');
    return 0;
}

export fn fputs(s: [*:0]const u8, stream: ?*FILE) c_int {
    if (stream) |sp| {
        const addr = @intFromPtr(sp);
        if (addr == @intFromPtr(&stdout_obj) or addr == @intFromPtr(&stderr_obj)) {
            var i: usize = 0;
            while (s[i] != 0) i += 1;
            com1.print(s[0..i]);
            return 0;
        }
    }
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    _ = fwrite(@ptrCast(s), 1, i, stream);
    return 0;
}

export fn fgets(buf: [*]u8, n: c_int, stream: ?*FILE) ?[*]u8 {
    if (n <= 0) return null;
    const limit: usize = @intCast(n);
    var i: usize = 0;
    while (i + 1 < limit) {
        var ch: u8 = 0;
        const got = fread(@as([*]u8, @ptrCast(&ch)), 1, 1, stream);
        if (got == 0) {
            if (i == 0) return null;
            break;
        }
        buf[i] = ch;
        i += 1;
        if (ch == '\n') break;
    }
    buf[i] = 0;
    return buf;
}

export fn freopen(path_z: [*:0]const u8, mode_z: [*:0]const u8, stream: ?*FILE) ?*FILE {
    _ = fclose(stream);
    return fopen(path_z, mode_z);
}

export fn tmpfile() ?*FILE {
    return null;
}

export fn fileno(stream: ?*FILE) c_int {
    _ = stream;
    return 0;
}

export fn setvbuf(stream: ?*FILE, buf: ?[*]u8, mode: c_int, size: usize) c_int {
    _ = stream;
    _ = buf;
    _ = mode;
    _ = size;
    return 0;
}

export fn remove(path_z: [*:0]const u8) c_int {
    _ = path_z;
    return 0;
}

export fn rename(old_z: [*:0]const u8, new_z: [*:0]const u8) c_int {
    _ = old_z;
    _ = new_z;
    return 0;
}

// ============================================================================
// time
// ============================================================================

const time_t = c_long;

export fn time(t: ?*time_t) time_t {
    const ns = syscall.timeMonotonic().v1;
    const sec: time_t = @intCast(ns / 1_000_000_000);
    if (t) |p| p.* = sec;
    return sec;
}

export fn clock() c_long {
    const ns = syscall.timeMonotonic().v1;
    // CLOCKS_PER_SEC = 1_000_000 → microseconds.
    return @intCast(ns / 1_000);
}

export fn difftime(a: time_t, b: time_t) f64 {
    return @floatFromInt(a - b);
}

export fn mktime(tm_in: ?*const Tm) time_t {
    _ = tm_in;
    return 0;
}

const Tm = extern struct {
    tm_sec: c_int = 0,
    tm_min: c_int = 0,
    tm_hour: c_int = 0,
    tm_mday: c_int = 1,
    tm_mon: c_int = 0,
    tm_year: c_int = 70,
    tm_wday: c_int = 0,
    tm_yday: c_int = 0,
    tm_isdst: c_int = 0,
    tm_gmtoff: c_long = 0,
    tm_zone: ?[*:0]const u8 = null,
};

var tm_storage: Tm = .{};

export fn localtime(t: ?*const c_long) ?*Tm {
    _ = t;
    return &tm_storage;
}

export fn gmtime(t: ?*const c_long) ?*Tm {
    _ = t;
    return &tm_storage;
}

export fn strftime(out: [*]u8, max: usize, fmt: [*:0]const u8, tm_in: ?*const Tm) usize {
    _ = tm_in;
    _ = fmt;
    if (max == 0) return 0;
    out[0] = 0;
    return 0;
}

// ============================================================================
// abort / exit / assert
// ============================================================================

export fn abort() callconv(.c) noreturn {
    panicShim("abort()");
}

export fn exit(status: c_int) callconv(.c) noreturn {
    com1.print("\n[doom] exit(");
    com1.dec(@intCast(@as(c_uint, @bitCast(status))));
    com1.print(")\n");
    park();
}

export fn _Exit(status: c_int) callconv(.c) noreturn {
    exit(status);
}

export fn atexit(func: ?*const fn () callconv(.c) void) c_int {
    _ = func;
    return 0;
}

export fn __desktopos_assert_fail(expr: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    com1.print("\nassert failed: ");
    com1.print(zigSpan(expr));
    com1.print(" at ");
    com1.print(zigSpan(file));
    com1.print(":");
    com1.dec(@as(u64, @intCast(line)));
    com1.print("\n");
    panicShim("assert");
}

fn zigSpan(s: [*:0]const u8) []const u8 {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    return s[0..i];
}

fn panicShim(msg: []const u8) noreturn {
    com1.print("\nlibc_shim panic: ");
    com1.print(msg);
    com1.print("\n");
    park();
}

fn park() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}

// ============================================================================
// env / system
// ============================================================================

export fn getenv(name: [*:0]const u8) ?[*:0]const u8 {
    _ = name;
    return null;
}

export fn system(cmd_z: ?[*:0]const u8) c_int {
    _ = cmd_z;
    return -1;
}

export fn putenv(s: [*]u8) c_int {
    _ = s;
    return 0;
}

export fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int {
    _ = name;
    _ = value;
    _ = overwrite;
    return 0;
}

export fn mkstemp(template: [*]u8) c_int {
    _ = template;
    return -1;
}

// ============================================================================
// errno storage
// ============================================================================

export var errno_storage: c_int = 0;

// ============================================================================
// sys/stat & unistd stubs
// ============================================================================

const Stat = extern struct {
    st_dev: c_ulong = 0,
    st_ino: c_ulong = 0,
    st_mode: c_uint = 0,
    st_nlink: c_ulong = 0,
    st_uid: c_uint = 0,
    st_gid: c_uint = 0,
    st_rdev: c_ulong = 0,
    st_size: c_long = 0,
    st_blksize: c_long = 0,
    st_blocks: c_long = 0,
    st_atime: c_long = 0,
    st_mtime: c_long = 0,
    st_ctime: c_long = 0,
};

export fn stat(path_z: [*:0]const u8, st: *Stat) c_int {
    _ = path_z;
    _ = st;
    return -1;
}

export fn fstat(fd: c_int, st: *Stat) c_int {
    _ = fd;
    _ = st;
    return -1;
}

export fn lstat(path_z: [*:0]const u8, st: *Stat) c_int {
    _ = path_z;
    _ = st;
    return -1;
}

export fn mkdir(path_z: [*:0]const u8, mode: c_uint) c_int {
    _ = path_z;
    _ = mode;
    return 0;
}

export fn access(path_z: [*:0]const u8, mode: c_int) c_int {
    _ = path_z;
    _ = mode;
    return -1;
}

export fn close(fd: c_int) c_int {
    _ = fd;
    return 0;
}

export fn unlink(path_z: [*:0]const u8) c_int {
    _ = path_z;
    return 0;
}

export fn rmdir(path_z: [*:0]const u8) c_int {
    _ = path_z;
    return 0;
}

export fn chdir(path_z: [*:0]const u8) c_int {
    _ = path_z;
    return 0;
}

export fn isatty(fd: c_int) c_int {
    _ = fd;
    return 0;
}

export fn open(path_z: [*:0]const u8, flags: c_int, ...) c_int {
    _ = path_z;
    _ = flags;
    return -1;
}

export fn creat(path_z: [*:0]const u8, mode: c_uint) c_int {
    _ = path_z;
    _ = mode;
    return -1;
}

export fn read(fd: c_int, buf: [*]u8, n: usize) c_long {
    _ = fd;
    _ = buf;
    _ = n;
    return 0;
}

export fn write(fd: c_int, buf: [*]const u8, n: usize) c_long {
    _ = fd;
    com1.print(buf[0..n]);
    return @intCast(n);
}

export fn lseek(fd: c_int, off: c_long, whence: c_int) c_long {
    _ = fd;
    _ = off;
    _ = whence;
    return -1;
}

export fn getcwd(buf: [*]u8, n: usize) ?[*]u8 {
    if (n < 2) return null;
    buf[0] = '/';
    buf[1] = 0;
    return buf;
}

export fn sleep(secs: c_uint) c_uint {
    var s: c_uint = 0;
    while (s < secs) : (s += 1) {
        var i: u32 = 0;
        while (i < 1_000) : (i += 1) _ = syscall.yieldEc(0);
    }
    return 0;
}

export fn usleep(us: c_uint) c_int {
    _ = us;
    _ = syscall.yieldEc(0);
    return 0;
}

export fn getpid() c_int {
    return 1;
}

// ============================================================================
// setjmp / longjmp — naked x86-64 state save/restore
// ============================================================================
//
// jmp_buf layout (matches setjmp.h: long[8]):
//   [0] rbx
//   [1] rbp
//   [2] r12
//   [3] r13
//   [4] r14
//   [5] r15
//   [6] rsp (caller's stack pointer)
//   [7] return address (rip)

comptime {
    if (builtin.cpu.arch == .x86_64) {
        asm (
            \\.global setjmp
            \\.type setjmp, @function
            \\setjmp:
            \\  movq %rbx, 0(%rdi)
            \\  movq %rbp, 8(%rdi)
            \\  movq %r12, 16(%rdi)
            \\  movq %r13, 24(%rdi)
            \\  movq %r14, 32(%rdi)
            \\  movq %r15, 40(%rdi)
            \\  leaq 8(%rsp), %rax
            \\  movq %rax, 48(%rdi)
            \\  movq (%rsp), %rax
            \\  movq %rax, 56(%rdi)
            \\  xorl %eax, %eax
            \\  ret
            \\
            \\.global longjmp
            \\.type longjmp, @function
            \\longjmp:
            \\  movq 0(%rdi), %rbx
            \\  movq 8(%rdi), %rbp
            \\  movq 16(%rdi), %r12
            \\  movq 24(%rdi), %r13
            \\  movq 32(%rdi), %r14
            \\  movq 40(%rdi), %r15
            \\  movq 48(%rdi), %rsp
            \\  movq 56(%rdi), %rdx
            \\  movl %esi, %eax
            \\  testl %eax, %eax
            \\  jne 1f
            \\  movl $1, %eax
            \\1:
            \\  jmp *%rdx
            \\
            \\.global sigsetjmp
            \\.type sigsetjmp, @function
            \\sigsetjmp:
            \\  jmp setjmp
            \\
            \\.global siglongjmp
            \\.type siglongjmp, @function
            \\siglongjmp:
            \\  jmp longjmp
        );
    }
}
