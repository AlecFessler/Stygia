// pthread — single-threaded no-op layer.
//
// First cut targets `-fsingle-threaded` for the cross-compiled Zig+
// LLVM compiler. Mutex / cond / rwlock / once succeed without doing
// anything (there's only one thread). pthread_create/join return
// EAGAIN — caller must handle that, but the Zig compiler driver
// configures itself for single-threaded mode based on probes that
// see `-fsingle-threaded`. pthread_self returns 1, pthread_self != 0
// is the canonical "is the thread library available" probe.
//
// pthread_key / getspecific / setspecific use a fixed-size static
// slot table — fine since there's only one thread, and POSIX
// mandates at least PTHREAD_KEYS_MAX (512) keys. We pick 64 for
// minimal storage; bump if a real workload trips it.
//
// When Stygia grows real ECs-as-threads + an FS-base set primitive,
// this whole file gets replaced with futex-backed primitives. Until
// then: keep the surface, drop the work.

const EAGAIN: c_int = 11;
const EINVAL: c_int = 22;

// ── opaque types are typedef'd to "big enough byte arrays" in the
//    public headers; we just declare them as pointer-sized opaques
//    here. The C side passes pointers to its own struct buffers.

const KEY_MAX: usize = 64;

// Per-key destructor + slot-occupied bit. Single-threaded → one slot
// per key total.
const Key = struct {
    in_use: bool = false,
    destructor: ?*const fn (?*anyopaque) callconv(.c) void = null,
    value: ?*anyopaque = null,
};

var keys: [KEY_MAX]Key = @splat(.{});

// ── attribute setup (all no-op success) ──────────────────────────

export fn pthread_attr_init(attr: ?*anyopaque) callconv(.c) c_int {
    _ = attr;
    return 0;
}
export fn pthread_attr_destroy(attr: ?*anyopaque) callconv(.c) c_int {
    _ = attr;
    return 0;
}
export fn pthread_attr_setguardsize(attr: ?*anyopaque, sz: usize) callconv(.c) c_int {
    _ = .{ attr, sz };
    return 0;
}
export fn pthread_attr_setstacksize(attr: ?*anyopaque, sz: usize) callconv(.c) c_int {
    _ = .{ attr, sz };
    return 0;
}

// ── thread creation: refused (single-threaded) ──────────────────

export fn pthread_create(
    thread: ?*usize,
    attr: ?*anyopaque,
    start_routine: ?*const fn (?*anyopaque) callconv(.c) ?*anyopaque,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = .{ thread, attr, start_routine, arg };
    return EAGAIN;
}

export fn pthread_join(thread: usize, retval: ?**anyopaque) callconv(.c) c_int {
    _ = .{ thread, retval };
    return EINVAL;
}

export fn pthread_detach(thread: usize) callconv(.c) c_int {
    _ = thread;
    return EINVAL;
}

export fn pthread_self() callconv(.c) usize {
    return 1;
}

export fn pthread_setname_np(thread: usize, name: [*:0]const u8) callconv(.c) c_int {
    _ = .{ thread, name };
    return 0;
}

export fn pthread_getname_np(thread: usize, name: [*]u8, size: usize) callconv(.c) c_int {
    _ = thread;
    if (size == 0) return EINVAL;
    name[0] = 0;
    return 0;
}

export fn pthread_setschedparam(thread: usize, policy: c_int, param: ?*const anyopaque) callconv(.c) c_int {
    _ = .{ thread, policy, param };
    return 0;
}

export fn pthread_sigmask(how: c_int, set: ?*const anyopaque, oldset: ?*anyopaque) callconv(.c) c_int {
    _ = .{ how, set, oldset };
    return 0;
}

// ── mutex / cond / rwlock / once: succeed silently ──────────────

export fn pthread_mutex_init(mutex: ?*anyopaque, attr: ?*const anyopaque) callconv(.c) c_int {
    _ = .{ mutex, attr };
    return 0;
}
export fn pthread_mutex_destroy(mutex: ?*anyopaque) callconv(.c) c_int {
    _ = mutex;
    return 0;
}
export fn pthread_mutex_lock(mutex: ?*anyopaque) callconv(.c) c_int {
    _ = mutex;
    return 0;
}
export fn pthread_mutex_trylock(mutex: ?*anyopaque) callconv(.c) c_int {
    _ = mutex;
    return 0;
}
export fn pthread_mutex_unlock(mutex: ?*anyopaque) callconv(.c) c_int {
    _ = mutex;
    return 0;
}
export fn pthread_mutexattr_init(attr: ?*anyopaque) callconv(.c) c_int {
    _ = attr;
    return 0;
}
export fn pthread_mutexattr_destroy(attr: ?*anyopaque) callconv(.c) c_int {
    _ = attr;
    return 0;
}
export fn pthread_mutexattr_settype(attr: ?*anyopaque, kind: c_int) callconv(.c) c_int {
    _ = .{ attr, kind };
    return 0;
}

export fn pthread_cond_init(cond: ?*anyopaque, attr: ?*const anyopaque) callconv(.c) c_int {
    _ = .{ cond, attr };
    return 0;
}
export fn pthread_cond_destroy(cond: ?*anyopaque) callconv(.c) c_int {
    _ = cond;
    return 0;
}
export fn pthread_cond_wait(cond: ?*anyopaque, mutex: ?*anyopaque) callconv(.c) c_int {
    _ = .{ cond, mutex };
    return 0;
}
export fn pthread_cond_signal(cond: ?*anyopaque) callconv(.c) c_int {
    _ = cond;
    return 0;
}
export fn pthread_cond_broadcast(cond: ?*anyopaque) callconv(.c) c_int {
    _ = cond;
    return 0;
}
export fn pthread_cond_timedwait(cond: ?*anyopaque, mutex: ?*anyopaque, ts: ?*const anyopaque) callconv(.c) c_int {
    _ = .{ cond, mutex, ts };
    return 0;
}

export fn pthread_rwlock_init(rw: ?*anyopaque, attr: ?*const anyopaque) callconv(.c) c_int {
    _ = .{ rw, attr };
    return 0;
}
export fn pthread_rwlock_destroy(rw: ?*anyopaque) callconv(.c) c_int {
    _ = rw;
    return 0;
}
export fn pthread_rwlock_rdlock(rw: ?*anyopaque) callconv(.c) c_int {
    _ = rw;
    return 0;
}
export fn pthread_rwlock_wrlock(rw: ?*anyopaque) callconv(.c) c_int {
    _ = rw;
    return 0;
}
export fn pthread_rwlock_unlock(rw: ?*anyopaque) callconv(.c) c_int {
    _ = rw;
    return 0;
}

// pthread_once: pthread_once_t is a 32-bit int that starts as 0 and
// becomes nonzero after the once_routine has run.

export fn pthread_once(
    once_control: *c_int,
    init_routine: *const fn () callconv(.c) void,
) callconv(.c) c_int {
    if (once_control.* == 0) {
        once_control.* = 1;
        init_routine();
    }
    return 0;
}

// ── per-thread keys (single-thread → single-slot table) ─────────

export fn pthread_key_create(
    key: *c_int,
    destructor: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) c_int {
    var i: usize = 0;
    while (i < KEY_MAX) : (i += 1) {
        if (!keys[i].in_use) {
            keys[i] = .{ .in_use = true, .destructor = destructor };
            key.* = @intCast(i);
            return 0;
        }
    }
    return EAGAIN;
}

export fn pthread_key_delete(key: c_int) callconv(.c) c_int {
    if (key < 0 or key >= KEY_MAX) return EINVAL;
    keys[@intCast(key)] = .{};
    return 0;
}

export fn pthread_getspecific(key: c_int) callconv(.c) ?*anyopaque {
    if (key < 0 or key >= KEY_MAX) return null;
    return keys[@intCast(key)].value;
}

export fn pthread_setspecific(key: c_int, value: ?*const anyopaque) callconv(.c) c_int {
    if (key < 0 or key >= KEY_MAX) return EINVAL;
    keys[@intCast(key)].value = @ptrCast(@constCast(value));
    return 0;
}

// glibc-internal: a flag the linker may pull in.
export var __libc_single_threaded: c_int = 1;
