// stdlib — exit / abort / abs / qsort / getenv / strtol family.
//
// Most are straightforward; getenv returns null until we wire the
// runtime's argv/envp setup (cap-table-driven, follow-up). qsort is
// a small Sedgewick-tuned quicksort with insertion-sort cutoff.

extern fn __cxa_finalize(dso: ?*anyopaque) callconv(.c) void;

extern fn zag_exit(status: u8) callconv(.c) noreturn;

// ── exit / abort / _Exit ─────────────────────────────────────────

export fn exit(status: c_int) callconv(.c) noreturn {
    __cxa_finalize(null);
    zag_exit(@truncate(@as(c_uint, @bitCast(status))));
}

export fn _Exit(status: c_int) callconv(.c) noreturn {
    zag_exit(@truncate(@as(c_uint, @bitCast(status))));
}

export fn _exit(status: c_int) callconv(.c) noreturn {
    zag_exit(@truncate(@as(c_uint, @bitCast(status))));
}

export fn abort() callconv(.c) noreturn {
    zag_exit(0x7f); // 127 = "abort signal" by convention.
}

// ── abs / labs / llabs ───────────────────────────────────────────

export fn abs(n: c_int) callconv(.c) c_int {
    return if (n < 0) -n else n;
}

export fn labs(n: c_long) callconv(.c) c_long {
    return if (n < 0) -n else n;
}

export fn llabs(n: c_longlong) callconv(.c) c_longlong {
    return if (n < 0) -n else n;
}

// ── env (stub until runtime wires argv/envp) ─────────────────────

export fn getenv(name: [*:0]const u8) callconv(.c) ?[*:0]const u8 {
    _ = name;
    return null;
}

export fn secure_getenv(name: [*:0]const u8) callconv(.c) ?[*:0]const u8 {
    _ = name;
    return null;
}

export fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) callconv(.c) c_int {
    _ = .{ name, value, overwrite };
    return -1;
}

export fn unsetenv(name: [*:0]const u8) callconv(.c) c_int {
    _ = name;
    return -1;
}

// glibc-internal globals — empty environment for now.
var empty_envp: [1]?[*:0]u8 = .{null};
export var environ: [*]?[*:0]u8 = &empty_envp;
export var __environ: [*]?[*:0]u8 = &empty_envp;

// ── strto* family ────────────────────────────────────────────────
// Minimal strict-parse: skip whitespace, optional sign, optional 0x
// prefix when base is 0 or 16, parse digits, set endptr to first
// non-digit or to nptr on parse failure. errno not set on overflow
// for simplicity (LLVM's strto* callsites usually don't check it).

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

fn parseSign(p: [*]const u8) struct { neg: bool, after: [*]const u8 } {
    if (p[0] == '+') return .{ .neg = false, .after = p + 1 };
    if (p[0] == '-') return .{ .neg = true, .after = p + 1 };
    return .{ .neg = false, .after = p };
}

fn digitVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'z') return c - 'a' + 10;
    if (c >= 'A' and c <= 'Z') return c - 'A' + 10;
    return null;
}

fn strtoull_inner(nptr: [*:0]const u8, endptr: ?*[*]const u8, base_in: c_int) u64 {
    var p = skipWs(nptr);
    const sgn = parseSign(p);
    p = sgn.after;
    var base: u32 = if (base_in < 0) 10 else @intCast(base_in);
    if (base == 0) {
        if (p[0] == '0' and (p[1] == 'x' or p[1] == 'X')) {
            base = 16;
            p += 2;
        } else if (p[0] == '0') {
            base = 8;
            p += 1;
        } else base = 10;
    } else if (base == 16 and p[0] == '0' and (p[1] == 'x' or p[1] == 'X')) {
        p += 2;
    }
    var any: bool = false;
    var v: u64 = 0;
    while (true) {
        const dv = digitVal(p[0]) orelse break;
        if (dv >= base) break;
        v = v * base + dv;
        p += 1;
        any = true;
    }
    if (endptr) |ep| ep.* = if (any) p else nptr;
    if (sgn.neg and v != 0) v = @as(u64, @bitCast(-@as(i64, @bitCast(v))));
    return v;
}

export fn strtoul(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_ulong {
    return @as(c_ulong, @intCast(strtoull_inner(nptr, endptr, base) & 0xFFFFFFFFFFFFFFFF));
}

export fn strtoull(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_ulonglong {
    return strtoull_inner(nptr, endptr, base);
}

export fn strtol(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_long {
    return @bitCast(strtoull_inner(nptr, endptr, base));
}

export fn strtoll(nptr: [*:0]const u8, endptr: ?*[*]const u8, base: c_int) callconv(.c) c_longlong {
    return @bitCast(strtoull_inner(nptr, endptr, base));
}

export fn atoi(s: [*:0]const u8) callconv(.c) c_int {
    return @truncate(strtol(s, null, 10));
}

export fn atol(s: [*:0]const u8) callconv(.c) c_long {
    return strtol(s, null, 10);
}

export fn atoll(s: [*:0]const u8) callconv(.c) c_longlong {
    return strtoll(s, null, 10);
}

// ── qsort (introsort would be nicer; this is just the textbook
//    quicksort with median-of-three + insertion-sort cutoff for
//    small partitions) ──────────────────────────────────────────

const Cmp = *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) c_int;

fn swapBytes(a: [*]u8, b: [*]u8, n: usize) void {
    var i: usize = 0;
    while (i < n) {
        const t = a[i];
        a[i] = b[i];
        b[i] = t;
        i += 1;
    }
}

fn insertionSort(base: [*]u8, count: usize, sz: usize, cmp: Cmp) void {
    var i: usize = 1;
    while (i < count) : (i += 1) {
        var j: usize = i;
        while (j > 0) {
            const a = base + (j - 1) * sz;
            const b = base + j * sz;
            if (cmp(a, b) <= 0) break;
            swapBytes(a, b, sz);
            j -= 1;
        }
    }
}

export fn qsort(base: [*]u8, count: usize, sz: usize, cmp: Cmp) callconv(.c) void {
    if (count < 2 or sz == 0) return;
    if (count < 16) {
        insertionSort(base, count, sz, cmp);
        return;
    }
    // median-of-three pivot
    const mid = count / 2;
    const a0 = base;
    const am = base + mid * sz;
    const al = base + (count - 1) * sz;
    if (cmp(a0, am) > 0) swapBytes(a0, am, sz);
    if (cmp(am, al) > 0) swapBytes(am, al, sz);
    if (cmp(a0, am) > 0) swapBytes(a0, am, sz);
    // Lomuto partition with the median pivot at the end.
    swapBytes(am, al, sz);
    const pivot = al;
    var store: usize = 0;
    var i: usize = 0;
    while (i < count - 1) : (i += 1) {
        const cur = base + i * sz;
        if (cmp(cur, pivot) < 0) {
            if (store != i) swapBytes(base + store * sz, cur, sz);
            store += 1;
        }
    }
    swapBytes(base + store * sz, pivot, sz);
    qsort(base, store, sz, cmp);
    qsort(base + (store + 1) * sz, count - store - 1, sz, cmp);
}

// ── rand / srand: trivial LCG (LLVM uses for hash randomization,
//    not cryptographic) ─────────────────────────────────────────

var rand_state: u64 = 1;

export fn rand() callconv(.c) c_int {
    rand_state = rand_state *% 6364136223846793005 +% 1442695040888963407;
    return @truncate(@as(c_long, @bitCast(rand_state >> 33)) & 0x7fffffff);
}

export fn srand(seed: c_uint) callconv(.c) void {
    rand_state = seed;
}

// arc4random — non-cryptographic; same LCG. Static-builds of LLVM's
// hash tables only need *some* entropy; this is enough.
export fn arc4random() callconv(.c) u32 {
    rand_state = rand_state *% 6364136223846793005 +% 1442695040888963407;
    return @truncate(rand_state >> 32);
}
