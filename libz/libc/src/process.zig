// process — proc info, fork/exec stubs, sysconf, getrlimit, backtrace.
//
// The cross-compiled Zig+LLVM doesn't fork/exec children when its
// driver is configured to use in-process LLD (the cross-build sets
// this up). So all the spawning primitives are pure ENOSYS stubs.
// What it DOES need is realistic answers for getpid, getpagesize,
// sysconf(_SC_*), get_nprocs, uname — those drive sizing decisions.

const ENOSYS: c_int = 38;

extern fn __errno_location() callconv(.c) *c_int;
extern fn _exit(status: c_int) callconv(.c) noreturn;

fn fail(err: c_int) c_int {
    __errno_location().* = err;
    return -1;
}

// ── identity / process info ──────────────────────────────────────

export fn getpid() callconv(.c) c_int {
    return 1;
}
export fn getuid() callconv(.c) c_uint {
    return 0;
}
export fn geteuid() callconv(.c) c_uint {
    return 0;
}
export fn getgid() callconv(.c) c_uint {
    return 0;
}
export fn getegid() callconv(.c) c_uint {
    return 0;
}
export fn getsid(pid: c_int) callconv(.c) c_int {
    _ = pid;
    return 1;
}
export fn getppid() callconv(.c) c_int {
    return 0;
}
export fn getpgid(pid: c_int) callconv(.c) c_int {
    _ = pid;
    return 1;
}

export fn setpgid(pid: c_int, pgid: c_int) callconv(.c) c_int {
    _ = .{ pid, pgid };
    return 0;
}
export fn setregid(rgid: c_uint, egid: c_uint) callconv(.c) c_int {
    _ = .{ rgid, egid };
    return 0;
}
export fn setreuid(ruid: c_uint, euid: c_uint) callconv(.c) c_int {
    _ = .{ ruid, euid };
    return 0;
}
export fn setsid() callconv(.c) c_int {
    return 1;
}
export fn umask(mask: c_uint) callconv(.c) c_uint {
    _ = mask;
    return 0o022;
}

// ── auxv / system info ────────────────────────────────────────────

export fn getauxval(kind: c_ulong) callconv(.c) c_ulong {
    _ = kind;
    return 0;
}

export fn getpagesize() callconv(.c) c_int {
    return 4096;
}

export fn get_nprocs() callconv(.c) c_int {
    return 1; // single-threaded for now
}

export fn get_nprocs_conf() callconv(.c) c_int {
    return 1;
}

export fn sched_getaffinity(pid: c_int, cpusetsize: usize, mask: ?*anyopaque) callconv(.c) c_int {
    _ = .{ pid, cpusetsize };
    if (mask) |m| {
        const p: [*]u8 = @ptrCast(m);
        if (cpusetsize > 0) {
            p[0] = 1;
            var i: usize = 1;
            while (i < cpusetsize) : (i += 1) p[i] = 0;
        }
    }
    return 0;
}

export fn sched_yield() callconv(.c) c_int {
    return 0;
}

export fn __sched_cpucount(setsize: usize, set: ?*const anyopaque) callconv(.c) c_int {
    _ = .{ setsize, set };
    return 1;
}

export fn sysconf(name: c_int) callconv(.c) c_long {
    return switch (name) {
        2 => 4096, // _SC_CLK_TCK
        3 => 1024, // _SC_NGROUPS_MAX
        7 => 65536, // _SC_OPEN_MAX
        8 => 65536, // _SC_STREAM_MAX
        29 => 1, // _SC_NPROCESSORS_ONLN
        83 => 1, // _SC_NPROCESSORS_CONF
        30 => 4096, // _SC_PAGESIZE
        else => -1,
    };
}

export fn uname(buf: ?*anyopaque) callconv(.c) c_int {
    if (buf == null) return -1;
    const arr: [*]u8 = @ptrCast(buf.?);
    var i: usize = 0;
    while (i < 65 * 6) : (i += 1) arr[i] = 0;
    const sysname = "Stygia";
    @memcpy(arr[0..sysname.len], sysname);
    @memcpy(arr[65 .. 65 + 4], "node");
    @memcpy(arr[130 .. 130 + 5], "0.1.0");
    @memcpy(arr[195 .. 195 + 5], "0.1.0");
    @memcpy(arr[260 .. 260 + 6], "x86_64");
    return 0;
}

const Rlimit = extern struct { cur: u64, max: u64 };
const RLIM_INFINITY: u64 = ~@as(u64, 0);

export fn getrlimit(resource: c_int, rlim: *Rlimit) callconv(.c) c_int {
    _ = resource;
    rlim.* = .{ .cur = RLIM_INFINITY, .max = RLIM_INFINITY };
    return 0;
}
export fn getrlimit64(resource: c_int, rlim: *Rlimit) callconv(.c) c_int {
    return getrlimit(resource, rlim);
}
export fn setrlimit(resource: c_int, rlim: *const Rlimit) callconv(.c) c_int {
    _ = .{ resource, rlim };
    return 0;
}
export fn setrlimit64(resource: c_int, rlim: *const Rlimit) callconv(.c) c_int {
    _ = .{ resource, rlim };
    return 0;
}

const Rusage = extern struct { _padding: [144]u8 = @splat(0) };
export fn getrusage(who: c_int, usage: *Rusage) callconv(.c) c_int {
    _ = who;
    usage.* = .{};
    return 0;
}

// passwd lookups — stub ENOENT-ish.
export fn getpwnam_r(name: [*:0]const u8, pw: ?*anyopaque, buf: ?[*]u8, buflen: usize, result: ?*?*anyopaque) callconv(.c) c_int {
    _ = .{ name, pw, buf, buflen };
    if (result) |r| r.* = null;
    return 0;
}
export fn getpwuid_r(uid: c_uint, pw: ?*anyopaque, buf: ?[*]u8, buflen: usize, result: ?*?*anyopaque) callconv(.c) c_int {
    _ = .{ uid, pw, buf, buflen };
    if (result) |r| r.* = null;
    return 0;
}

// ── randomness ────────────────────────────────────────────────────

export fn getrandom(buf: [*]u8, buflen: usize, flags: c_uint) callconv(.c) isize {
    _ = flags;
    var i: usize = 0;
    while (i < buflen) : (i += 1) buf[i] = 0; // TODO: hook RDRAND or a real entropy source
    return @intCast(buflen);
}

export fn getentropy(buf: [*]u8, buflen: usize) callconv(.c) c_int {
    if (buflen > 256) return fail(5); // EIO
    var i: usize = 0;
    while (i < buflen) : (i += 1) buf[i] = 0;
    return 0;
}

// ── fork / exec / wait — pure ENOSYS, never called when -fno-exec ──

export fn fork() callconv(.c) c_int {
    return fail(ENOSYS);
}
export fn execv(path: [*:0]const u8, argv: ?*anyopaque) callconv(.c) c_int {
    _ = .{ path, argv };
    return fail(ENOSYS);
}
export fn execve(path: [*:0]const u8, argv: ?*anyopaque, envp: ?*anyopaque) callconv(.c) c_int {
    _ = .{ path, argv, envp };
    return fail(ENOSYS);
}
export fn wait(status: ?*c_int) callconv(.c) c_int {
    _ = status;
    return fail(ENOSYS);
}
export fn waitpid(pid: c_int, status: ?*c_int, opts: c_int) callconv(.c) c_int {
    _ = .{ pid, status, opts };
    return fail(ENOSYS);
}
export fn wait4(pid: c_int, status: ?*c_int, opts: c_int, rusage: ?*Rusage) callconv(.c) c_int {
    _ = .{ pid, status, opts, rusage };
    return fail(ENOSYS);
}
export fn posix_spawn(pid: ?*c_int, path: [*:0]const u8, fa: ?*anyopaque, attr: ?*anyopaque, argv: ?*anyopaque, envp: ?*anyopaque) callconv(.c) c_int {
    _ = .{ pid, path, fa, attr, argv, envp };
    return ENOSYS;
}
export fn posix_spawn_file_actions_init(fa: ?*anyopaque) callconv(.c) c_int {
    _ = fa;
    return 0;
}
export fn posix_spawn_file_actions_destroy(fa: ?*anyopaque) callconv(.c) c_int {
    _ = fa;
    return 0;
}
export fn posix_spawn_file_actions_adddup2(fa: ?*anyopaque, oldfd: c_int, newfd: c_int) callconv(.c) c_int {
    _ = .{ fa, oldfd, newfd };
    return 0;
}
export fn posix_spawn_file_actions_addopen(fa: ?*anyopaque, fd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    _ = .{ fa, fd, path, flags, mode };
    return 0;
}

// ── inotify / epoll / poll — stub ENOSYS ───────────────────────

export fn inotify_init1(flags: c_int) callconv(.c) c_int {
    _ = flags;
    return fail(ENOSYS);
}
export fn inotify_add_watch(fd: c_int, path: [*:0]const u8, mask: c_uint) callconv(.c) c_int {
    _ = .{ fd, path, mask };
    return fail(ENOSYS);
}
export fn inotify_rm_watch(fd: c_int, wd: c_int) callconv(.c) c_int {
    _ = .{ fd, wd };
    return fail(ENOSYS);
}

export fn epoll_create1(flags: c_int) callconv(.c) c_int {
    _ = flags;
    return fail(ENOSYS);
}
export fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: ?*anyopaque) callconv(.c) c_int {
    _ = .{ epfd, op, fd, event };
    return fail(ENOSYS);
}
export fn epoll_wait(epfd: c_int, events: ?*anyopaque, maxevents: c_int, timeout: c_int) callconv(.c) c_int {
    _ = .{ epfd, events, maxevents, timeout };
    return fail(ENOSYS);
}
export fn poll(fds: ?*anyopaque, nfds: c_uint, timeout: c_int) callconv(.c) c_int {
    _ = .{ fds, nfds, timeout };
    return fail(ENOSYS);
}

export fn pipe(fds: *[2]c_int) callconv(.c) c_int {
    _ = fds;
    return fail(ENOSYS);
}
export fn pipe2(fds: *[2]c_int, flags: c_int) callconv(.c) c_int {
    _ = .{ fds, flags };
    return fail(ENOSYS);
}

// ── runtime stubs the linker may pull in ─────────────────────────

extern fn abort() callconv(.c) noreturn;

export fn __assert_fail(expr: [*:0]const u8, file: [*:0]const u8, line: c_uint, func: [*:0]const u8) callconv(.c) noreturn {
    _ = .{ expr, file, line, func };
    abort();
}

export fn backtrace(buffer: ?[*]?*anyopaque, size: c_int) callconv(.c) c_int {
    _ = .{ buffer, size };
    return 0;
}

export fn __stack_chk_fail() callconv(.c) noreturn {
    abort();
}

// __morestack: split-stack runtime — stub that just returns. Not used
// when we build with -fno-split-stack (default).
export fn __morestack() callconv(.c) void {}

// __longjmp_chk: FORTIFY_SOURCE wrapper — call siglongjmp via __libc.
// Since we have no setjmp/longjmp infrastructure, just abort.
export fn __longjmp_chk(env: *anyopaque, val: c_int) callconv(.c) noreturn {
    _ = .{ env, val };
    abort();
}

// _setjmp: returns 0 on direct call. With no thread-cleanup or
// signal-mask handling, this is sufficient for crash-handler probes.
export fn _setjmp(env: *anyopaque) callconv(.c) c_int {
    _ = env;
    return 0;
}

// __libc_start_main: replaced by our own _start in crt0 — but the
// linker may search for it. Stub abort so missing-runtime is loud.
export fn __libc_start_main(
    main: ?*anyopaque,
    argc: c_int,
    argv: ?*anyopaque,
    init: ?*anyopaque,
    fini: ?*anyopaque,
    rtld_fini: ?*anyopaque,
    stack_end: ?*anyopaque,
) callconv(.c) c_int {
    _ = .{ main, argc, argv, init, fini, rtld_fini, stack_end };
    abort();
}

// __tls_get_addr: only used by dynamically-linked code; stub null.
export fn __tls_get_addr(arg: ?*const anyopaque) callconv(.c) ?*anyopaque {
    _ = arg;
    return null;
}

// __gmon_start__: gprof start hook; weak no-op.
export fn __gmon_start__() callconv(.c) void {}

// libstdc++ thread-safe-init helpers (unique-instances of guard
// objects). The `_ZN9__gnu_cxx21zoneinfo_dir_overrideEv` and `_ZGTt*`
// symbols are the std::tzdata override + thread-safe-init wrapper.
// They're called once per process; safe to no-op.
export fn _ZN9__gnu_cxx21zoneinfo_dir_overrideEv() callconv(.c) ?[*:0]const u8 {
    return null;
}
export fn _ZGTtdlPv(p: ?*anyopaque) callconv(.c) void {
    _ = p;
}
export fn _ZGTtnam(n: usize) callconv(.c) ?*anyopaque {
    _ = n;
    return null;
}
export var _ZTHN4llvm8parallel11threadIndexE: c_int = 0;
