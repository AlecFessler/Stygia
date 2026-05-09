// time — clock_gettime / gettimeofday / time / gmtime / localtime / nanosleep / usleep.
//
// First cut: all clocks stuck at epoch (zero seconds, zero nanos).
// LLVM uses these for `-time-passes` profiling and timestamps; zeros
// produce a "every pass took 0s" report which is mildly inaccurate
// but correct in the pure sense. nanosleep / usleep return 0 (woke
// up immediately). gmtime/localtime do the date math from the epoch
// integer regardless — we just deterministically pick the earliest
// representable timestamp.
//
// Once Stygia's userspace timer object lands a syscall, all of this gets
// wired through it.

const Timespec = extern struct { sec: i64, nsec: i64 };
const Timeval = extern struct { sec: i64, usec: i64 };
const Tm = extern struct {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    gmtoff: c_long,
    zone: ?[*:0]const u8,
};

var tm_buf: Tm = .{
    .sec = 0,
    .min = 0,
    .hour = 0,
    .mday = 1,
    .mon = 0,
    .year = 70, // 1970
    .wday = 4, // Thursday
    .yday = 0,
    .isdst = 0,
    .gmtoff = 0,
    .zone = "UTC",
};

export fn clock_gettime(clk: c_int, ts: *Timespec) callconv(.c) c_int {
    _ = clk;
    ts.* = .{ .sec = 0, .nsec = 0 };
    return 0;
}

export fn gettimeofday(tv: ?*Timeval, tz: ?*anyopaque) callconv(.c) c_int {
    _ = tz;
    if (tv) |t| t.* = .{ .sec = 0, .usec = 0 };
    return 0;
}

export fn time(t: ?*i64) callconv(.c) i64 {
    if (t) |p| p.* = 0;
    return 0;
}

export fn nanosleep(req: ?*const Timespec, rem: ?*Timespec) callconv(.c) c_int {
    _ = .{ req, rem };
    return 0;
}

export fn usleep(usec: c_uint) callconv(.c) c_int {
    _ = usec;
    return 0;
}

export fn gmtime(t: ?*const i64) callconv(.c) *Tm {
    _ = t;
    return &tm_buf;
}

export fn gmtime_r(t: ?*const i64, result: *Tm) callconv(.c) *Tm {
    _ = t;
    result.* = tm_buf;
    return result;
}

export fn localtime(t: ?*const i64) callconv(.c) *Tm {
    _ = t;
    return &tm_buf;
}

export fn localtime_r(t: ?*const i64, result: *Tm) callconv(.c) *Tm {
    _ = t;
    result.* = tm_buf;
    return result;
}

// utimensat — touch file timestamps. Stub no-op.
export fn utimensat(dirfd: c_int, path: ?[*:0]const u8, ts: ?*const Timespec, flags: c_int) callconv(.c) c_int {
    _ = .{ dirfd, path, ts, flags };
    return 0;
}

export fn futimens(fd: c_int, ts: ?*const Timespec) callconv(.c) c_int {
    _ = .{ fd, ts };
    return 0;
}
