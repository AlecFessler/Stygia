// ctype — character classification + case mapping.
//
// glibc-compat: __ctype_b_loc / __ctype_tolower_loc / __ctype_toupper_loc
// return pointers to thread-local table-pointer slots, biased so the
// table is indexed at offset −128. We provide the C locale tables
// statically and return pointers to them. The bias is what the macro
// expansions in <ctype.h> assume; if a consumer reaches in directly
// they'll index the table from a "char" (potentially negative on x86),
// so the table is sized 384 entries with 128 leading "sign-extension"
// rows.

// ASCII C-locale ctype mask bits (glibc layout).
const _ISupper: u16 = 1 << 8;
const _ISlower: u16 = 1 << 9;
const _ISalpha: u16 = 1 << 10;
const _ISdigit: u16 = 1 << 11;
const _ISxdigit: u16 = 1 << 12;
const _ISspace: u16 = 1 << 13;
const _ISprint: u16 = 1 << 14;
const _ISgraph: u16 = 1 << 15;
const _ISblank: u16 = 1 << 0;
const _IScntrl: u16 = 1 << 1;
const _ISpunct: u16 = 1 << 2;
const _ISalnum: u16 = 1 << 3;

fn classify(c: u8) u16 {
    var m: u16 = 0;
    if (c >= 'A' and c <= 'Z') m |= _ISupper | _ISalpha | _ISxdigit & (if (c <= 'F') @as(u16, _ISxdigit) else 0) | _ISprint | _ISgraph | _ISalnum;
    if (c >= 'a' and c <= 'z') m |= _ISlower | _ISalpha | _ISprint | _ISgraph | _ISalnum;
    if (c >= '0' and c <= '9') m |= _ISdigit | _ISxdigit | _ISprint | _ISgraph | _ISalnum;
    if ((c >= 'A' and c <= 'F') or (c >= 'a' and c <= 'f')) m |= _ISxdigit;
    if (c == ' ' or c == '\t') m |= _ISblank;
    if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c) m |= _ISspace;
    if (c < 0x20 or c == 0x7f) m |= _IScntrl;
    if (c >= 0x21 and c <= 0x7e) {
        m |= _ISprint | _ISgraph;
        const is_alnum = (c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z');
        if (!is_alnum) m |= _ISpunct;
    }
    if (c == ' ') m |= _ISprint;
    return m;
}

fn buildClassTable() [384]u16 {
    var t: [384]u16 = @splat(0);
    var i: u32 = 0;
    while (i < 256) : (i += 1) {
        t[128 + i] = classify(@truncate(i));
    }
    return t;
}

fn buildToupperTable() [384]i32 {
    var t: [384]i32 = @splat(0);
    var i: u32 = 0;
    while (i < 256) : (i += 1) {
        const c: u8 = @truncate(i);
        const u: u8 = if (c >= 'a' and c <= 'z') c - 0x20 else c;
        t[128 + i] = @as(i32, u);
    }
    return t;
}

fn buildTolowerTable() [384]i32 {
    var t: [384]i32 = @splat(0);
    var i: u32 = 0;
    while (i < 256) : (i += 1) {
        const c: u8 = @truncate(i);
        const u: u8 = if (c >= 'A' and c <= 'Z') c + 0x20 else c;
        t[128 + i] = @as(i32, u);
    }
    return t;
}

const class_table: [384]u16 = buildClassTable();
const toupper_table: [384]i32 = buildToupperTable();
const tolower_table: [384]i32 = buildTolowerTable();

// Pointers biased to index 0, so consumers do `ptr[(int)(char)c]`
// and naturally hit row 128 + c (works for c in [-128..127]).
const class_ptr: *const u16 = &class_table[128];
const toupper_ptr: *const i32 = &toupper_table[128];
const tolower_ptr: *const i32 = &tolower_table[128];

export fn __ctype_b_loc() callconv(.c) **const u16 {
    const Holder = struct {
        var p: *const u16 = class_ptr;
    };
    return &Holder.p;
}

export fn __ctype_tolower_loc() callconv(.c) **const i32 {
    const Holder = struct {
        var p: *const i32 = tolower_ptr;
    };
    return &Holder.p;
}

export fn __ctype_toupper_loc() callconv(.c) **const i32 {
    const Holder = struct {
        var p: *const i32 = toupper_ptr;
    };
    return &Holder.p;
}

export fn __ctype_get_mb_cur_max() callconv(.c) usize {
    return 1; // C-locale: single-byte chars only.
}

// ── Predicate fns (pure, no table lookup needed) ──────────────────

fn inRange(c: c_int, lo: u8, hi: u8) bool {
    if (c < 0 or c > 0xff) return false;
    const u: u8 = @truncate(@as(c_uint, @bitCast(c)));
    return u >= lo and u <= hi;
}

export fn isalnum(c: c_int) callconv(.c) c_int {
    if (inRange(c, '0', '9') or inRange(c, 'A', 'Z') or inRange(c, 'a', 'z')) return 1;
    return 0;
}

export fn isalpha(c: c_int) callconv(.c) c_int {
    if (inRange(c, 'A', 'Z') or inRange(c, 'a', 'z')) return 1;
    return 0;
}

export fn isblank(c: c_int) callconv(.c) c_int {
    return @intFromBool(c == ' ' or c == '\t');
}

export fn iscntrl(c: c_int) callconv(.c) c_int {
    if (inRange(c, 0, 0x1f) or c == 0x7f) return 1;
    return 0;
}

export fn isdigit(c: c_int) callconv(.c) c_int {
    return @intFromBool(inRange(c, '0', '9'));
}

export fn isgraph(c: c_int) callconv(.c) c_int {
    return @intFromBool(inRange(c, 0x21, 0x7e));
}

export fn islower(c: c_int) callconv(.c) c_int {
    return @intFromBool(inRange(c, 'a', 'z'));
}

export fn isprint(c: c_int) callconv(.c) c_int {
    return @intFromBool(inRange(c, 0x20, 0x7e));
}

export fn ispunct(c: c_int) callconv(.c) c_int {
    if (!inRange(c, 0x21, 0x7e)) return 0;
    return @intFromBool(isalnum(c) == 0);
}

export fn isspace(c: c_int) callconv(.c) c_int {
    return @intFromBool(c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c);
}

export fn isupper(c: c_int) callconv(.c) c_int {
    return @intFromBool(inRange(c, 'A', 'Z'));
}

export fn isxdigit(c: c_int) callconv(.c) c_int {
    if (inRange(c, '0', '9') or inRange(c, 'A', 'F') or inRange(c, 'a', 'f')) return 1;
    return 0;
}

export fn isascii(c: c_int) callconv(.c) c_int {
    return @intFromBool(c >= 0 and c < 0x80);
}

export fn toascii(c: c_int) callconv(.c) c_int {
    return c & 0x7f;
}

export fn tolower(c: c_int) callconv(.c) c_int {
    if (inRange(c, 'A', 'Z')) return c + 0x20;
    return c;
}

export fn toupper(c: c_int) callconv(.c) c_int {
    if (inRange(c, 'a', 'z')) return c - 0x20;
    return c;
}
