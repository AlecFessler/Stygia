// signal — stub layer.
//
// Zag has no signal delivery; consumers register handlers (LLVM crash
// reporter installs SIGSEGV/SIGABRT) but they never fire. We accept
// the registrations so initialization succeeds, then ignore.
//
// kill / raise — stub. abort handles the SIGABRT-on-self path
// directly via _Exit().

extern fn abort() callconv(.c) noreturn;

const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SIG_ERR: usize = ~@as(usize, 0);

export fn signal(signum: c_int, handler: usize) callconv(.c) usize {
    _ = .{ signum, handler };
    return SIG_DFL;
}

export fn sigaction(signum: c_int, act: ?*const anyopaque, oldact: ?*anyopaque) callconv(.c) c_int {
    _ = .{ signum, act, oldact };
    return 0;
}

export fn sigprocmask(how: c_int, set: ?*const anyopaque, oldset: ?*anyopaque) callconv(.c) c_int {
    _ = .{ how, set, oldset };
    return 0;
}

export fn sigaltstack(ss: ?*const anyopaque, oss: ?*anyopaque) callconv(.c) c_int {
    _ = .{ ss, oss };
    return 0;
}

export fn sigemptyset(set: *anyopaque) callconv(.c) c_int {
    const p: [*]u8 = @ptrCast(set);
    var i: usize = 0;
    while (i < 128) : (i += 1) p[i] = 0;
    return 0;
}

export fn sigfillset(set: *anyopaque) callconv(.c) c_int {
    const p: [*]u8 = @ptrCast(set);
    var i: usize = 0;
    while (i < 128) : (i += 1) p[i] = 0xff;
    return 0;
}

export fn sigaddset(set: *anyopaque, signum: c_int) callconv(.c) c_int {
    _ = .{ set, signum };
    return 0;
}

export fn sigdelset(set: *anyopaque, signum: c_int) callconv(.c) c_int {
    _ = .{ set, signum };
    return 0;
}

export fn sigismember(set: *const anyopaque, signum: c_int) callconv(.c) c_int {
    _ = .{ set, signum };
    return 0;
}

export fn raise(signum: c_int) callconv(.c) c_int {
    if (signum == 6) abort(); // SIGABRT
    return 0;
}

export fn kill(pid: c_int, signum: c_int) callconv(.c) c_int {
    _ = .{ pid, signum };
    return 0;
}

export fn alarm(seconds: c_uint) callconv(.c) c_uint {
    _ = seconds;
    return 0;
}

// __register_atfork — glibc-internal pthread_atfork registration.
// We're single-threaded with no fork, so accept and ignore.
export fn __register_atfork(
    prepare: ?*const fn () callconv(.c) void,
    parent: ?*const fn () callconv(.c) void,
    child: ?*const fn () callconv(.c) void,
    dso_handle: ?*anyopaque,
) callconv(.c) c_int {
    _ = .{ prepare, parent, child, dso_handle };
    return 0;
}
