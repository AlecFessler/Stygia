// cxxabi — minimal C++ ABI bits LLVM/libc++abi expect.
//
// __cxa_atexit / __cxa_finalize : per-DSO atexit registry, walked in
// LIFO order at process exit. The (func, arg, dso) triple is what
// libc++abi registers when a thread_local has a destructor or a
// `static T x;` block-scope variable goes out of scope. For our
// static-archive build there's only ever one DSO, so we ignore the
// dso handle and walk a single global stack.
//
// __cxa_pure_virtual : virtual call on an abstract base — should never
// happen in well-formed code; abort.
//
// __cxa_guard_acquire / _release / _abort : block-scope static-init
// guard. Single-threaded first cut: a 1-byte guard, atomically-ish.
// When threading lands these need futex.

extern fn abort() callconv(.c) noreturn;

const ATEXIT_MAX: usize = 256;

const Entry = extern struct {
    func: ?*const fn (*anyopaque) callconv(.c) void = null,
    arg: ?*anyopaque = null,
    dso: ?*anyopaque = null,
};

var atexit_stack: [ATEXIT_MAX]Entry = @splat(.{}); // All-null defaults.
var atexit_count: usize = 0;

export fn __cxa_atexit(
    func: *const fn (*anyopaque) callconv(.c) void,
    arg: ?*anyopaque,
    dso: ?*anyopaque,
) callconv(.c) c_int {
    if (atexit_count >= ATEXIT_MAX) return -1;
    atexit_stack[atexit_count] = .{ .func = func, .arg = arg, .dso = dso };
    atexit_count += 1;
    return 0;
}

export fn __cxa_finalize(dso: ?*anyopaque) callconv(.c) void {
    var i: usize = atexit_count;
    while (i > 0) {
        i -= 1;
        const e = atexit_stack[i];
        // dso == null = "everything"; otherwise filter by DSO handle.
        if (dso != null and e.dso != dso) continue;
        if (e.func) |f| {
            atexit_stack[i] = .{};
            f(e.arg orelse undefined);
        }
    }
    if (dso == null) atexit_count = 0;
}

// Plain POSIX atexit — wraps __cxa_atexit with a void→() shim.
const ATEXIT_FN = *const fn () callconv(.c) void;
var atexit_fns: [ATEXIT_MAX]?ATEXIT_FN = @splat(null);
var atexit_fns_count: usize = 0;

fn atexitTrampoline(arg: *anyopaque) callconv(.c) void {
    const idx: usize = @intFromPtr(arg);
    if (idx >= atexit_fns_count) return;
    if (atexit_fns[idx]) |f| f();
}

export fn atexit(func: ATEXIT_FN) callconv(.c) c_int {
    if (atexit_fns_count >= ATEXIT_MAX) return -1;
    const idx = atexit_fns_count;
    atexit_fns[idx] = func;
    atexit_fns_count += 1;
    return __cxa_atexit(atexitTrampoline, @ptrFromInt(idx), null);
}

export fn __cxa_pure_virtual() callconv(.c) noreturn {
    abort();
}

// Block-scope static guard. ABI: 64-bit guard variable, low byte is
// the "init done" flag. We treat the 2nd byte as "in progress" to
// detect recursive init (which is UB in C++ but cheap to check).
//
// Single-threaded: lock is just a sequence point; no atomicity.

export fn __cxa_guard_acquire(guard: *u64) callconv(.c) c_int {
    const bytes: *[8]u8 = @ptrCast(guard);
    if (bytes[0] != 0) return 0; // Already initialized.
    if (bytes[1] != 0) abort(); // Recursive init.
    bytes[1] = 1;
    return 1;
}

export fn __cxa_guard_release(guard: *u64) callconv(.c) void {
    const bytes: *[8]u8 = @ptrCast(guard);
    bytes[1] = 0;
    bytes[0] = 1;
}

export fn __cxa_guard_abort(guard: *u64) callconv(.c) void {
    const bytes: *[8]u8 = @ptrCast(guard);
    bytes[1] = 0;
}

// __cxa_thread_atexit_impl — registers a per-thread destructor. In
// single-threaded mode this is just __cxa_atexit (everything runs at
// process exit anyway).
export fn __cxa_thread_atexit_impl(
    func: *const fn (*anyopaque) callconv(.c) void,
    arg: ?*anyopaque,
    dso: ?*anyopaque,
) callconv(.c) c_int {
    return __cxa_atexit(func, arg, dso);
}
