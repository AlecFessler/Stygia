// libc surface SQLite expects when compiled freestanding. Each
// function is exported with C calling convention so the SQLite
// amalgamation links cleanly.
//
// SQLITE_OS_OTHER + SQLITE_OMIT_LOAD_EXTENSION + SQLITE_THREADSAFE=0
// + SQLITE_ENABLE_MEMSYS5 + SQLITE_ZERO_MALLOC together prune the
// surface dramatically — SQLite never calls open / read / write /
// fsync / pthread_*, so this shim only covers mem*, str*, ctype,
// abort/exit, and the few math/time stubs the parser/expressions
// reach for. Anything not listed here is either unused or only ever
// compiled into the amalgamation as dead code (linker-DCE'd).

const lib = @import("lib");
const com1 = @import("log");
const builtin = @import("builtin");
const syscall = lib.syscall;

// ── Memory primitives ────────────────────────────────────────────

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
        if (a[i] != b[i]) {
            return @as(c_int, a[i]) - @as(c_int, b[i]);
        }
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

// ── String primitives ────────────────────────────────────────────

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
    while (set[i] != 0) : (i += 1) {
        if (set[i] == c) return true;
    }
    return false;
}

// ── ctype ────────────────────────────────────────────────────────

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
    return @intFromBool(c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '\x0B' or c == '\x0C');
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
export fn ispunct(c: c_int) c_int {
    return @intFromBool(isprint(c) != 0 and isalnum(c) == 0 and c != ' ');
}
export fn iscntrl(c: c_int) c_int {
    return @intFromBool((c >= 0 and c < 0x20) or c == 0x7F);
}
export fn tolower(c: c_int) c_int {
    if (c >= 'A' and c <= 'Z') return c + ('a' - 'A');
    return c;
}
export fn toupper(c: c_int) c_int {
    if (c >= 'a' and c <= 'z') return c - ('a' - 'A');
    return c;
}

// ── Numeric parsing (minimal — atoi/atol; SQLite's own parser is
//    used for SQL, these only show up in user-facing helpers like
//    sqlite3_complete which we don't exercise) ─────────────────────

export fn atoi(s: [*:0]const u8) c_int {
    return @truncate(atolImpl(s));
}

export fn atol(s: [*:0]const u8) c_long {
    return atolImpl(s);
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

// strtol / strtod stubs — SQLite's value parser handles SQL literals
// internally; the libc forms only show up on the callback-API edges
// we don't exercise. Stub.
export fn strtol(s: [*:0]const u8, endp: ?*[*:0]const u8, base: c_int) c_long {
    _ = base;
    if (endp) |p| p.* = s;
    return atolImpl(s);
}

export fn strtod(s: [*:0]const u8, endp: ?*[*:0]const u8) f64 {
    if (endp) |p| p.* = s;
    return 0;
}

// ── qsort (called once, by SQLite's main module init) ───────────

export fn qsort(
    base: [*]u8,
    nmemb: usize,
    size: usize,
    cmp: *const fn (a: ?*const anyopaque, b: ?*const anyopaque) callconv(.c) c_int,
) void {
    // Simple insertion sort. SQLite's call sites are tiny lookup
    // tables (function/keyword arrays sized in the dozens); insertion
    // sort is fine.
    var i: usize = 1;
    while (i < nmemb) : (i += 1) {
        var j: usize = i;
        while (j > 0) {
            const a = base + (j - 1) * size;
            const b = base + j * size;
            if (cmp(a, b) <= 0) break;
            // swap a, b
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

// ── Allocation stubs (never called: SQLITE_ZERO_MALLOC routes through
//    sqlite3_mem_methods + memsys5) ────────────────────────────────

export fn malloc(n: usize) ?*anyopaque {
    _ = n;
    panicShim("malloc called — should be routed through memsys5");
}
export fn calloc(n: usize, m: usize) ?*anyopaque {
    _ = n;
    _ = m;
    panicShim("calloc called — should be routed through memsys5");
}
export fn realloc(p: ?*anyopaque, n: usize) ?*anyopaque {
    _ = p;
    _ = n;
    panicShim("realloc called — should be routed through memsys5");
}
export fn free(p: ?*anyopaque) void {
    _ = p;
    panicShim("free called — should be routed through memsys5");
}

// ── abort / exit / assert ────────────────────────────────────────

export fn abort() callconv(.c) noreturn {
    panicShim("abort()");
}

export fn exit(status: c_int) callconv(.c) noreturn {
    _ = status;
    panicShim("exit()");
}

export fn __desktopos_assert_fail(expr: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    com1.print("assert failed: ");
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
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}

// ── Math stubs (SQLite math functions disabled by config) ───────

export fn sqrt(x: f64) f64 {
    _ = x;
    return 0;
}
export fn floor(x: f64) f64 {
    return @floor(x);
}
export fn ceil(x: f64) f64 {
    return @ceil(x);
}
export fn log(x: f64) f64 {
    _ = x;
    return 0;
}
export fn log10(x: f64) f64 {
    _ = x;
    return 0;
}
export fn pow(x: f64, y: f64) f64 {
    _ = x;
    _ = y;
    return 0;
}
export fn exp(x: f64) f64 {
    _ = x;
    return 0;
}
export fn sin(x: f64) f64 {
    _ = x;
    return 0;
}
export fn cos(x: f64) f64 {
    _ = x;
    return 0;
}
export fn tan(x: f64) f64 {
    _ = x;
    return 0;
}
export fn asin(x: f64) f64 {
    _ = x;
    return 0;
}
export fn acos(x: f64) f64 {
    _ = x;
    return 0;
}
export fn atan(x: f64) f64 {
    _ = x;
    return 0;
}
export fn atan2(y: f64, x: f64) f64 {
    _ = y;
    _ = x;
    return 0;
}
export fn fabs(x: f64) f64 {
    return @abs(x);
}
export fn fmod(x: f64, y: f64) f64 {
    _ = y;
    return x;
}

// ── Time stubs (SQLite uses these in date funcs; our VFS overrides
//    sqlite3_currentTime so these are barely reached) ─────────────

const time_t = c_long;
export fn time(t: ?*time_t) time_t {
    const ns = syscall.timeGetwall().v1;
    const sec: time_t = @intCast(ns / 1_000_000_000);
    if (t) |p| p.* = sec;
    return sec;
}

// ── stdio stubs — drop output on the floor or route to COM1 ─────

const FILE = anyopaque;
export var stdin: ?*FILE = null;
export var stdout: ?*FILE = null;
export var stderr: ?*FILE = null;

export fn fputs(s: [*:0]const u8, stream: ?*FILE) c_int {
    _ = stream;
    com1.print(zigSpan(s));
    return 0;
}
export fn fputc(c: c_int, stream: ?*FILE) c_int {
    _ = stream;
    com1.putc(@truncate(@as(c_uint, @bitCast(c))));
    return c;
}
export fn fflush(stream: ?*FILE) c_int {
    _ = stream;
    return 0;
}
export fn fclose(stream: ?*FILE) c_int {
    _ = stream;
    return 0;
}

// ── errno ────────────────────────────────────────────────────────

export var errno_storage: c_int = 0;

// ── struct tm + localtime stub (toLocaltime in date.c calls it) ──

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

export fn localtime(_: ?*const c_long) ?*Tm {
    return &tm_storage;
}

export fn gmtime(_: ?*const c_long) ?*Tm {
    return &tm_storage;
}

// ── SQLite OS_OTHER hooks ────────────────────────────────────────
// SQLITE_OS_OTHER=1 requires the user to provide sqlite3_os_init /
// sqlite3_os_end. The default unix/win versions register the default
// VFS; we register ours separately via sqlite3_vfs_register, so these
// are no-ops.
export fn sqlite3_os_init() c_int {
    return 0; // SQLITE_OK
}

export fn sqlite3_os_end() c_int {
    return 0; // SQLITE_OK
}
