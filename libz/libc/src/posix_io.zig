// posix_io — file I/O wrappers over stygia_fs_* extern hooks.
//
// The consuming binary (cross-compiled Zig+LLVM, statically linked
// with libc.a) provides the stygia_fs_* implementations talking to the
// SQL-FS server over IPC. Phase 4c.5 wires these.
//
// Until then, calls return -1 with errno=ENOSYS for ops that don't
// have a stygia_fs_* extern; the linker still resolves cleanly because
// extern declarations don't require runtime defs at libc.a build time.

extern fn __errno_location() callconv(.c) *c_int;

extern fn stygia_fs_openat(dir_fd: c_int, path_ptr: [*]const u8, path_len: usize, flags: u32, mode: u32) callconv(.c) i64;
extern fn stygia_fs_mkdirat(dir_fd: c_int, path_ptr: [*]const u8, path_len: usize, mode: u32) callconv(.c) c_int;
extern fn stygia_fs_unlinkat(dir_fd: c_int, path_ptr: [*]const u8, path_len: usize) callconv(.c) c_int;
extern fn stygia_fs_statat(dir_fd: c_int, path_ptr: [*]const u8, path_len: usize, stat_out: *anyopaque) callconv(.c) c_int;
extern fn stygia_fs_read(fd: i32, buf_ptr: [*]u8, buf_len: usize, offset: i64) callconv(.c) i64;
extern fn stygia_fs_close(fd: i32) callconv(.c) i32;
extern fn stygia_fs_fstat(fd: i32, stat_out: *anyopaque) callconv(.c) i32;
// Extensions (consumer must provide; first cut from stdio path).
extern fn stygia_fs_write(fd: i32, buf_ptr: [*]const u8, buf_len: usize, offset: i64) callconv(.c) i64;
extern fn stygia_fs_stat(path_ptr: [*]const u8, path_len: usize, stat_out: *anyopaque) callconv(.c) i32;
extern fn stygia_fs_unlink(path_ptr: [*]const u8, path_len: usize) callconv(.c) i32;
extern fn stygia_fs_lseek(fd: i32, offset: i64, whence: c_int) callconv(.c) i64;
extern fn stygia_fs_mkdir(path_ptr: [*]const u8, path_len: usize, mode: u32) callconv(.c) i32;
extern fn stygia_fs_truncate(path_ptr: [*]const u8, path_len: usize, size: i64) callconv(.c) i32;
extern fn stygia_fs_ftruncate(fd: i32, size: i64) callconv(.c) i32;

extern fn stygia_write_console(buf: [*]const u8, count: usize) callconv(.c) usize;

const ENOSYS: c_int = 38;
const EBADF: c_int = 9;
const EINVAL: c_int = 22;

fn fail(err: c_int) c_int {
    __errno_location().* = err;
    return -1;
}

fn pathLen(p: [*:0]const u8) usize {
    var i: usize = 0;
    while (p[i] != 0) i += 1;
    return i;
}

// ── open family ───────────────────────────────────────────────────

pub fn openatImpl(path: [*:0]const u8, flags: u32, mode: u32) c_int {
    return openatAtImpl(-100, path, flags, mode); // -100 = AT_FDCWD
}

pub fn openatAtImpl(dir_fd: c_int, path: [*:0]const u8, flags: u32, mode: u32) c_int {
    const len = pathLen(path);
    const rc = stygia_fs_openat(dir_fd, path, len, flags, mode);
    if (rc < 0) {
        __errno_location().* = @intCast(-rc);
        return -1;
    }
    return @intCast(rc);
}

export fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openatImpl(path, @bitCast(flags), mode);
}
export fn open64(path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openatImpl(path, @bitCast(flags), mode);
}
export fn openat(dir_fd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openatAtImpl(dir_fd, path, @bitCast(flags), mode);
}
export fn openat64(dir_fd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openat(dir_fd, path, flags, mode);
}
export fn __openat_2(dir_fd: c_int, path: [*:0]const u8, flags: c_int) callconv(.c) c_int {
    return openat(dir_fd, path, flags, 0);
}

// ── close ─────────────────────────────────────────────────────────

export fn close(fd: c_int) callconv(.c) c_int {
    if (fd < 0) return fail(EBADF);
    if (fd <= 2) return 0; // stdin/stdout/stderr
    return stygia_fs_close(fd);
}

// ── read / write ──────────────────────────────────────────────────

const Iovec = extern struct { base: [*]u8, len: usize };
const IovecConst = extern struct { base: [*]const u8, len: usize };

pub fn readAt(fd: c_int, buf: [*]u8, n: usize, offset: i64) isize {
    const rc = stygia_fs_read(fd, buf, n, offset);
    if (rc < 0) {
        __errno_location().* = @intCast(-rc);
        return -1;
    }
    return @intCast(rc);
}

pub fn writeAt(fd: c_int, buf: [*]const u8, n: usize, offset: i64) isize {
    if (fd == 1 or fd == 2) {
        const written = stygia_write_console(buf, n);
        const signed: isize = @bitCast(written);
        if (signed < 0) {
            __errno_location().* = @intCast(-signed);
            return -1;
        }
        return @intCast(written);
    }
    const rc = stygia_fs_write(fd, buf, n, offset);
    if (rc < 0) {
        __errno_location().* = @intCast(-rc);
        return -1;
    }
    return @intCast(rc);
}

// offset = -1 → use the runtime's per-fd current position (advance it).
// offset >= 0 → explicit (pread/pwrite); do not advance the position.
export fn read(fd: c_int, buf: [*]u8, n: usize) callconv(.c) isize {
    return readAt(fd, buf, n, -1);
}
export fn write(fd: c_int, buf: [*]const u8, n: usize) callconv(.c) isize {
    return writeAt(fd, buf, n, -1);
}
export fn pread(fd: c_int, buf: [*]u8, n: usize, offset: i64) callconv(.c) isize {
    return readAt(fd, buf, n, offset);
}
export fn pread64(fd: c_int, buf: [*]u8, n: usize, offset: i64) callconv(.c) isize {
    return readAt(fd, buf, n, offset);
}
export fn pwrite64(fd: c_int, buf: [*]const u8, n: usize, offset: i64) callconv(.c) isize {
    return writeAt(fd, buf, n, offset);
}
export fn readv(fd: c_int, iov: [*]const Iovec, count: c_int) callconv(.c) isize {
    var total: isize = 0;
    var i: c_int = 0;
    while (i < count) : (i += 1) {
        const r = readAt(fd, iov[@intCast(i)].base, iov[@intCast(i)].len, -1);
        if (r < 0) return r;
        total += r;
        if (@as(usize, @intCast(r)) < iov[@intCast(i)].len) return total;
    }
    return total;
}
export fn writev(fd: c_int, iov: [*]const IovecConst, count: c_int) callconv(.c) isize {
    var total: isize = 0;
    var i: c_int = 0;
    while (i < count) : (i += 1) {
        const r = writeAt(fd, iov[@intCast(i)].base, iov[@intCast(i)].len, -1);
        if (r < 0) return r;
        total += r;
    }
    return total;
}
export fn preadv64(fd: c_int, iov: [*]const Iovec, count: c_int, offset: i64) callconv(.c) isize {
    _ = .{ fd, iov, count, offset };
    return fail(ENOSYS);
}
export fn pwritev64(fd: c_int, iov: [*]const IovecConst, count: c_int, offset: i64) callconv(.c) isize {
    _ = .{ fd, iov, count, offset };
    return fail(ENOSYS);
}

// ── lseek ─────────────────────────────────────────────────────────

export fn lseek(fd: c_int, offset: i64, whence: c_int) callconv(.c) i64 {
    if (fd <= 2) {
        __errno_location().* = 29; // ESPIPE
        return -1;
    }
    const rc = stygia_fs_lseek(fd, offset, whence);
    if (rc < 0) {
        __errno_location().* = @intCast(-rc);
        return -1;
    }
    return rc;
}
export fn lseek64(fd: c_int, offset: i64, whence: c_int) callconv(.c) i64 {
    return lseek(fd, offset, whence);
}

// ── stat family ───────────────────────────────────────────────────

const Stat = extern struct { _padding: [144]u8 = @splat(0) };

export fn stat(path: [*:0]const u8, st: *Stat) callconv(.c) c_int {
    return stygia_fs_statat(-100, path, pathLen(path), st);
}
export fn fstatat(dir_fd: c_int, path: [*:0]const u8, st: *Stat, flags: c_int) callconv(.c) c_int {
    _ = flags;
    return stygia_fs_statat(dir_fd, path, pathLen(path), st);
}
export fn stat64(path: [*:0]const u8, st: *Stat) callconv(.c) c_int {
    return stat(path, st);
}
export fn lstat(path: [*:0]const u8, st: *Stat) callconv(.c) c_int {
    return stat(path, st);
}
export fn lstat64(path: [*:0]const u8, st: *Stat) callconv(.c) c_int {
    return stat(path, st);
}
export fn fstat(fd: c_int, st: *Stat) callconv(.c) c_int {
    return stygia_fs_fstat(fd, st);
}
export fn fstat64(fd: c_int, st: *Stat) callconv(.c) c_int {
    return fstat(fd, st);
}
export fn fstatfs(fd: c_int, st: ?*anyopaque) callconv(.c) c_int {
    _ = .{ fd, st };
    return 0;
}
export fn statfs(path: [*:0]const u8, st: ?*anyopaque) callconv(.c) c_int {
    _ = .{ path, st };
    return 0;
}
export fn statvfs(path: [*:0]const u8, st: ?*anyopaque) callconv(.c) c_int {
    _ = .{ path, st };
    return 0;
}

// ── access / mode / ownership ────────────────────────────────────

export fn access(path: [*:0]const u8, mode: c_int) callconv(.c) c_int {
    _ = mode;
    var st: Stat = .{};
    return stat(path, &st);
}
export fn faccessat(dir_fd: c_int, path: [*:0]const u8, mode: c_int, flags: c_int) callconv(.c) c_int {
    _ = .{ dir_fd, mode, flags };
    return access(path, mode);
}
export fn chmod(path: [*:0]const u8, mode: c_uint) callconv(.c) c_int {
    _ = .{ path, mode };
    return 0;
}
export fn fchmod(fd: c_int, mode: c_uint) callconv(.c) c_int {
    _ = .{ fd, mode };
    return 0;
}
export fn fchmodat(dir_fd: c_int, path: [*:0]const u8, mode: c_uint, flags: c_int) callconv(.c) c_int {
    _ = .{ dir_fd, path, mode, flags };
    return 0;
}
export fn fchown(fd: c_int, uid: c_uint, gid: c_uint) callconv(.c) c_int {
    _ = .{ fd, uid, gid };
    return 0;
}
export fn truncate(path: [*:0]const u8, size: i64) callconv(.c) c_int {
    return stygia_fs_truncate(path, pathLen(path), size);
}
export fn ftruncate(fd: c_int, size: i64) callconv(.c) c_int {
    return stygia_fs_ftruncate(fd, size);
}
export fn ftruncate64(fd: c_int, size: i64) callconv(.c) c_int {
    return ftruncate(fd, size);
}

// ── path manipulation ─────────────────────────────────────────────

export fn unlink(path: [*:0]const u8) callconv(.c) c_int {
    return stygia_fs_unlinkat(-100, path, pathLen(path));
}
export fn unlinkat(dir_fd: c_int, path: [*:0]const u8, flags: c_int) callconv(.c) c_int {
    _ = flags;
    return stygia_fs_unlinkat(dir_fd, path, pathLen(path));
}
export fn remove(path: [*:0]const u8) callconv(.c) c_int {
    return unlink(path);
}
export fn rename(old_path: [*:0]const u8, new_path: [*:0]const u8) callconv(.c) c_int {
    _ = .{ old_path, new_path };
    return fail(ENOSYS);
}
export fn renameat(olddir: c_int, oldp: [*:0]const u8, newdir: c_int, newp: [*:0]const u8) callconv(.c) c_int {
    _ = .{ olddir, newdir };
    return rename(oldp, newp);
}
export fn link(oldp: [*:0]const u8, newp: [*:0]const u8) callconv(.c) c_int {
    _ = .{ oldp, newp };
    return fail(ENOSYS);
}
export fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) callconv(.c) c_int {
    _ = .{ target, linkpath };
    return fail(ENOSYS);
}
export fn symlinkat(target: [*:0]const u8, dir_fd: c_int, linkpath: [*:0]const u8) callconv(.c) c_int {
    _ = .{ target, dir_fd, linkpath };
    return fail(ENOSYS);
}
export fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) callconv(.c) isize {
    _ = .{ path, buf, bufsiz };
    return fail(ENOSYS);
}
export fn readlinkat(dir_fd: c_int, path: [*:0]const u8, buf: [*]u8, bufsiz: usize) callconv(.c) isize {
    _ = .{ dir_fd, path, buf, bufsiz };
    return fail(ENOSYS);
}
export fn realpath(path: [*:0]const u8, resolved: ?[*]u8) callconv(.c) ?[*:0]u8 {
    if (resolved) |r| {
        var i: usize = 0;
        while (path[i] != 0) : (i += 1) r[i] = path[i];
        r[i] = 0;
        return @ptrCast(r);
    }
    return null;
}

export fn mkdir(path: [*:0]const u8, mode: c_uint) callconv(.c) c_int {
    return stygia_fs_mkdirat(-100, path, pathLen(path), mode);
}
export fn mkdirat(dir_fd: c_int, path: [*:0]const u8, mode: c_uint) callconv(.c) c_int {
    return stygia_fs_mkdirat(dir_fd, path, pathLen(path), mode);
}
export fn mknod(path: [*:0]const u8, mode: c_uint, dev: u64) callconv(.c) c_int {
    _ = .{ path, mode, dev };
    return fail(ENOSYS);
}

// ── directory enumeration — stub-ENOSYS until stygia_fs_dir extern lands ──

export fn opendir(path: [*:0]const u8) callconv(.c) ?*anyopaque {
    _ = path;
    return null;
}
export fn closedir(d: ?*anyopaque) callconv(.c) c_int {
    _ = d;
    return 0;
}
export fn readdir(d: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = d;
    return null;
}
export fn dirfd(d: ?*anyopaque) callconv(.c) c_int {
    _ = d;
    return -1;
}
export fn fdopendir(fd: c_int) callconv(.c) ?*anyopaque {
    _ = fd;
    return null;
}

// ── misc ──────────────────────────────────────────────────────────

export fn dup2(oldfd: c_int, newfd: c_int) callconv(.c) c_int {
    _ = .{ oldfd, newfd };
    return fail(ENOSYS);
}

export fn fcntl(fd: c_int, cmd: c_int, arg: c_long) callconv(.c) c_int {
    _ = .{ fd, cmd, arg };
    return 0; // Quiet success — F_SETFD/FD_CLOEXEC etc. are queries we ignore.
}

export fn ioctl(fd: c_int, request: c_ulong, arg: c_ulong) callconv(.c) c_int {
    _ = .{ fd, request, arg };
    return fail(EINVAL);
}

export fn isatty(fd: c_int) callconv(.c) c_int {
    return @intFromBool(fd == 1 or fd == 2);
}

export fn chdir(path: [*:0]const u8) callconv(.c) c_int {
    _ = path;
    return 0;
}

export fn fchdir(fd: c_int) callconv(.c) c_int {
    _ = fd;
    return 0;
}

export fn getcwd(buf: ?[*]u8, size: usize) callconv(.c) ?[*]u8 {
    if (buf == null or size < 2) return null;
    buf.?[0] = '/';
    buf.?[1] = 0;
    return buf.?;
}

export fn copy_file_range(in_fd: c_int, in_off: ?*i64, out_fd: c_int, out_off: ?*i64, len: usize, flags: c_uint) callconv(.c) isize {
    _ = .{ in_fd, in_off, out_fd, out_off, len, flags };
    return fail(ENOSYS);
}

export fn sendfile(out_fd: c_int, in_fd: c_int, offset: ?*i64, count: usize) callconv(.c) isize {
    _ = .{ out_fd, in_fd, offset, count };
    return fail(ENOSYS);
}
export fn sendfile64(out_fd: c_int, in_fd: c_int, offset: ?*i64, count: usize) callconv(.c) isize {
    return sendfile(out_fd, in_fd, offset, count);
}

export fn flock(fd: c_int, op: c_int) callconv(.c) c_int {
    _ = .{ fd, op };
    return 0;
}

export fn syscall(n: c_long, a: c_long, b: c_long, c: c_long, d: c_long, e: c_long, f: c_long) callconv(.c) c_long {
    _ = .{ n, a, b, c, d, e, f };
    return -1;
}
