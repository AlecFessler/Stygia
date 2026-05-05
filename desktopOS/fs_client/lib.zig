// fs_client — stateless client library for the FS protocol.
//
// Each function performs one IPC round-trip against the FS server.
// Callers supply path, offset, and length on every call; the library
// holds NO per-file state. Anything that looks like a "handle" (an
// open File, a Dir iterator) is built on top of this in the caller's
// own code by tracking (path, pos) or (path, cookie) locally.
//
// The shared `io_scratch` page_frame is the data plane; both this
// library and the FS server alias the same page_frame at their own
// virtual address. The caller hands `scratch_va` to every call so
// the library can stage paths + data into it.

const lib = @import("lib");
const fs_ops = @import("fs_ops");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

pub const Status = fs_ops.Status;
pub const Kind = fs_ops.Kind;

pub const FsError = error{
    NotFound,
    NotADirectory,
    IsADirectory,
    NameTooLong,
    PathTooLong,
    NoSpace,
    Exists,
    NotEmpty,
    BadOp,
    Invalid,
    IoError,
    BadPath,
    TooManyLinks,
    Fail,
};

pub fn statusErr(s: Status) FsError!void {
    return switch (s) {
        .ok => {},
        .not_found => FsError.NotFound,
        .not_a_directory => FsError.NotADirectory,
        .is_a_directory => FsError.IsADirectory,
        .name_too_long => FsError.NameTooLong,
        .path_too_long => FsError.PathTooLong,
        .no_space => FsError.NoSpace,
        .exists => FsError.Exists,
        .not_empty => FsError.NotEmpty,
        .bad_op => FsError.BadOp,
        .invalid => FsError.Invalid,
        .io_error => FsError.IoError,
        .bad_path => FsError.BadPath,
        .too_many_links => FsError.TooManyLinks,
        .fail => FsError.Fail,
        else => FsError.Fail,
    };
}

pub const Stat = struct {
    inode: u64,
    kind: Kind,
    mode: u64,
    size: u64,
    mtime: u64,
    ctime: u64,
    atime: u64,
    link_count: u64,
};

pub const DirEntry = struct {
    inode: u64,
    kind: Kind,
    name: []const u8, // points into the scratch buffer the caller supplied
};

pub const ReaddirResult = struct {
    entries: []DirEntry,
    next_cookie: []const u8, // empty = end of directory
    end_of_dir: bool,
};

// ── Op wrappers ──────────────────────────────────────────────────

pub fn lookup(port: HandleId, scratch_va: u64, path: []const u8) FsError!Stat {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.lookup, .{ .v4 = path.len });
    try statusErr(@enumFromInt(r.v1));
    return Stat{
        .inode = r.v2,
        .kind = @enumFromInt(r.v3),
        .mode = 0,
        .size = r.v4,
        .mtime = r.v5,
        .ctime = 0,
        .atime = 0,
        .link_count = 1,
    };
}

pub fn stat(port: HandleId, scratch_va: u64, path: []const u8) FsError!Stat {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.stat, .{ .v4 = path.len });
    try statusErr(@enumFromInt(r.v1));
    return Stat{
        .inode = r.v2,
        .kind = @enumFromInt(r.v3),
        .size = r.v4,
        .mtime = r.v5,
        .mode = r.v6,
        .link_count = r.v7,
        .ctime = r.v8,
        .atime = r.v9,
    };
}

pub fn pread(
    port: HandleId,
    scratch_va: u64,
    path: []const u8,
    offset: u64,
    dst: []u8,
) FsError!usize {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.pread, .{
        .v4 = path.len,
        .v5 = offset,
        .v6 = dst.len,
    });
    try statusErr(@enumFromInt(r.v1));
    const n: usize = @intCast(r.v2);
    const data_off: usize = @intCast(r.v3);
    const src: [*]const u8 = @ptrFromInt(scratch_va + data_off);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

pub fn pwrite(
    port: HandleId,
    scratch_va: u64,
    path: []const u8,
    offset: u64,
    src: []const u8,
) FsError!struct { written: u64, new_size: u64 } {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const data_off = fs_ops.alignUp8(path.len);
    if (data_off + src.len > fs_ops.SCRATCH_BYTES) return FsError.Invalid;
    const dst: [*]u8 = @ptrFromInt(scratch_va + data_off);
    @memcpy(dst[0..src.len], src);
    const r = submit(port, fs_ops.Op.pwrite, .{
        .v4 = path.len,
        .v5 = offset,
        .v6 = data_off,
        .v7 = src.len,
    });
    try statusErr(@enumFromInt(r.v1));
    return .{ .written = r.v2, .new_size = r.v3 };
}

pub fn truncate(port: HandleId, scratch_va: u64, path: []const u8, new_size: u64) FsError!void {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.truncate, .{
        .v4 = path.len,
        .v5 = new_size,
    });
    try statusErr(@enumFromInt(r.v1));
}

pub fn createFile(port: HandleId, scratch_va: u64, path: []const u8, mode: u64) FsError!u64 {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.create_file, .{
        .v4 = path.len,
        .v5 = mode,
    });
    try statusErr(@enumFromInt(r.v1));
    return r.v2;
}

pub fn unlink(port: HandleId, scratch_va: u64, path: []const u8) FsError!void {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.unlink, .{ .v4 = path.len });
    try statusErr(@enumFromInt(r.v1));
}

pub fn mkdir(port: HandleId, scratch_va: u64, path: []const u8, mode: u64) FsError!u64 {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.mkdir, .{ .v4 = path.len, .v5 = mode });
    try statusErr(@enumFromInt(r.v1));
    return r.v2;
}

pub fn rmdir(port: HandleId, scratch_va: u64, path: []const u8) FsError!void {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.rmdir, .{ .v4 = path.len });
    try statusErr(@enumFromInt(r.v1));
}

pub fn rename(port: HandleId, scratch_va: u64, old: []const u8, new: []const u8) FsError!void {
    if (old.len + 1 + new.len > fs_ops.SCRATCH_BYTES) return FsError.Invalid;
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    @memcpy(buf[0..old.len], old);
    buf[old.len] = 0;
    @memcpy(buf[old.len + 1 .. old.len + 1 + new.len], new);
    const r = submit(port, fs_ops.Op.rename, .{ .v4 = old.len, .v5 = new.len });
    try statusErr(@enumFromInt(r.v1));
}

pub fn symlink(port: HandleId, scratch_va: u64, path: []const u8, target: []const u8) FsError!u64 {
    if (path.len + 1 + target.len > fs_ops.SCRATCH_BYTES) return FsError.Invalid;
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    @memcpy(buf[path.len + 1 .. path.len + 1 + target.len], target);
    const r = submit(port, fs_ops.Op.symlink, .{ .v4 = path.len, .v5 = target.len });
    try statusErr(@enumFromInt(r.v1));
    return r.v2;
}

pub fn readlink(port: HandleId, scratch_va: u64, path: []const u8, dst: []u8) FsError!usize {
    if (!writePath(scratch_va, path)) return FsError.BadPath;
    const r = submit(port, fs_ops.Op.readlink, .{ .v4 = path.len });
    try statusErr(@enumFromInt(r.v1));
    const n: usize = @intCast(r.v2);
    if (n > dst.len) return FsError.Invalid;
    const src: [*]const u8 = @ptrFromInt(scratch_va);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

pub fn readdir(
    port: HandleId,
    scratch_va: u64,
    path: []const u8,
    cookie: []const u8,
    out_entries: []DirEntry,
) FsError!ReaddirResult {
    if (path.len + 1 + cookie.len > fs_ops.SCRATCH_BYTES) return FsError.Invalid;
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    if (cookie.len > 0) {
        @memcpy(buf[path.len + 1 .. path.len + 1 + cookie.len], cookie);
    }
    const r = submit(port, fs_ops.Op.readdir, .{
        .v4 = path.len,
        .v5 = cookie.len,
        .v6 = out_entries.len,
    });
    try statusErr(@enumFromInt(r.v1));

    const entry_count: usize = @intCast(r.v2);
    const entries_off: usize = @intCast(r.v3);
    const entries_bytes: usize = @intCast(r.v4);
    _ = entries_bytes;
    const next_cookie_off: usize = @intCast(r.v5);
    const next_cookie_len: usize = @intCast(r.v6);

    var i: usize = 0;
    var off: usize = entries_off;
    while (i < entry_count and i < out_entries.len) : (i += 1) {
        const inode_le: [*]const u8 = @ptrFromInt(scratch_va + off);
        const inode = readU64Le(inode_le);
        const kind: Kind = @enumFromInt(inode_le[8]);
        const name_len: usize = inode_le[9];
        const name_ptr: [*]const u8 = @ptrFromInt(scratch_va + off + 16);
        out_entries[i] = .{
            .inode = inode,
            .kind = kind,
            .name = name_ptr[0..name_len],
        };
        off += fs_ops.alignUp8(16 + name_len);
    }

    const next_cookie_ptr: [*]const u8 = @ptrFromInt(scratch_va + next_cookie_off);
    return .{
        .entries = out_entries[0..entry_count],
        .next_cookie = next_cookie_ptr[0..next_cookie_len],
        .end_of_dir = next_cookie_len == 0,
    };
}

pub fn sync(port: HandleId, scratch_va: u64) FsError!void {
    _ = scratch_va;
    const r = submit(port, fs_ops.Op.sync, .{});
    try statusErr(@enumFromInt(r.v1));
}

// ── Internals ────────────────────────────────────────────────────

const SubmitArgs = struct {
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
};

fn submit(port: HandleId, op: fs_ops.Op, args: SubmitArgs) syscall.Regs {
    return syscall.issueReg(
        .@"suspend",
        0,
        .{
            .v1 = @as(u64, caps.SLOT_INITIAL_EC),
            .v2 = @as(u64, port),
            .v3 = @intFromEnum(op),
            .v4 = args.v4,
            .v5 = args.v5,
            .v6 = args.v6,
            .v7 = args.v7,
        },
    );
}

fn writePath(scratch_va: u64, path: []const u8) bool {
    if (path.len == 0 or path.len > fs_ops.PATH_MAX) return false;
    const buf: [*]u8 = @ptrFromInt(scratch_va);
    @memcpy(buf[0..path.len], path);
    return true;
}

fn readU64Le(p: [*]const u8) u64 {
    var v: u64 = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) v |= @as(u64, p[i]) << @intCast(i * 8);
    return v;
}
