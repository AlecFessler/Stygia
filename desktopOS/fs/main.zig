// fs — filesystem service.
//
// Owns the SQLite handle and serves the stateless FS protocol from
// `protocols/fs_ops.zig` over a recv-side port. Clients (verify_fs
// today; std.fs adapter tomorrow) suspend onto fs_port with the op
// in v3 and any arguments in v4..v7; paths and data live in the
// shared `io_scratch` page_frame.
//
// Cap-table layout from root_service (in passed-handle order):
//
//   [3] COM1 device_region (logging)
//   [4] blockdev port (xfer|bind) — fs is the client
//   [5] blockdev scratch_pf (1 page)
//   [6] fs port (recv|bind) — fs is the server
//   [7] io_scratch_pf (SCRATCH_PAGES, shared with fs clients)
//
// fs differentiates the two ports by whether the recv bit is set;
// the page_frames are taken in passed-handle order.

const lib = @import("lib");
const log = @import("log");
const blockdev = @import("blockdev");
const fs_ops = @import("fs_ops");
const sqlite = @import("sqlite");

const builtin = @import("builtin");

// libc_shim's exports are referenced from the linked-in sqlite3.c,
// not from Zig — keep the module alive at link time.
comptime {
    _ = @import("libc_shim");
}

const c = sqlite.c;
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;
const vfs = sqlite.vfs;
const files = @import("files.zig");
const superblock = @import("superblock.zig");

const PAGE_4K: u64 = 4096;
const BLOCKDEV_SCRATCH_PAGES: u64 = 1;

// In-memory scratch the server uses for read-modify-write of inode
// blobs. Caps the maximum pwrite-extended file size until phase 3
// switches to incremental BLOB I/O.
const PWRITE_SCRATCH_BYTES: usize = 1 * 1024 * 1024;
var pwrite_scratch: [PWRITE_SCRATCH_BYTES]u8 = undefined;

// Spec §[recv] [2]: 0 = block indefinitely.
const RECV_TIMEOUT_NS: u64 = 0;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[fs] starting\n");

    const inv = scanInbound(cap_table_base);
    if (inv.blockdev_port == null or inv.fs_port == null or
        inv.blockdev_scratch == null or inv.io_scratch == null)
    {
        log.print("[fs] FATAL: missing handles (blockdev_port=");
        log.dec(if (inv.blockdev_port) |h| @as(u64, h) else 0);
        log.print(" fs_port=");
        log.dec(if (inv.fs_port) |h| @as(u64, h) else 0);
        log.print(" blockdev_scratch=");
        log.dec(if (inv.blockdev_scratch) |h| @as(u64, h) else 0);
        log.print(" io_scratch=");
        log.dec(if (inv.io_scratch) |h| @as(u64, h) else 0);
        log.print(")\n");
        park();
    }

    const blockdev_scratch_va = mapPfRw(inv.blockdev_scratch.?, BLOCKDEV_SCRATCH_PAGES) orelse {
        log.print("[fs] FATAL: mapPf(blockdev_scratch) failed\n");
        park();
    };
    const io_scratch_va = mapPfRw(inv.io_scratch.?, fs_ops.SCRATCH_PAGES) orelse {
        log.print("[fs] FATAL: mapPf(io_scratch) failed\n");
        park();
    };

    log.print("[fs] blockdev_scratch=0x");
    log.hex64(blockdev_scratch_va);
    log.print(" io_scratch=0x");
    log.hex64(io_scratch_va);
    log.print("\n");

    // Probe LBA 0 for an fs superblock. Decides format-vs-mount before
    // any SQLite call sees the volume.
    const sb_state = readSuperblock(inv.blockdev_port.?, blockdev_scratch_va);
    if (sb_state.valid) {
        log.print("[fs] superblock found, mounting (logical_size=");
        log.dec(sb_state.logical_size);
        log.print(")\n");
    } else {
        log.print("[fs] no valid superblock; formatting fresh volume\n");
        writeSuperblock(inv.blockdev_port.?, blockdev_scratch_va, superblock.Superblock.fresh());
    }

    // Bring SQLite up.
    if (sqlite.configureHeap() != c.SQLITE_OK) {
        log.print("[fs] FATAL: configureHeap\n");
        park();
    }
    if (vfs.registerVfs(inv.blockdev_port.?, blockdev_scratch_va, BLOCKDEV_SCRATCH_PAGES) != c.SQLITE_OK) {
        log.print("[fs] FATAL: registerVfs\n");
        park();
    }
    if (sb_state.valid) {
        vfs.setLogicalSize(sb_state.logical_size);
    }
    if (c.sqlite3_initialize() != c.SQLITE_OK) {
        log.print("[fs] FATAL: sqlite3_initialize\n");
        park();
    }

    const db = sqlite.open("file:db?vfs=blockdev") catch {
        log.print("[fs] FATAL: sqlite3_open\n");
        park();
    };
    defer sqlite.close(db);

    if (sqlite.exec(db, "PRAGMA journal_mode=MEMORY;") != c.SQLITE_OK) {
        log.print("[fs] FATAL: PRAGMA journal_mode\n");
        park();
    }
    if (sqlite.exec(db, "PRAGMA synchronous=OFF;") != c.SQLITE_OK) {
        log.print("[fs] FATAL: PRAGMA synchronous\n");
        park();
    }
    if (sqlite.exec(db, "PRAGMA locking_mode=EXCLUSIVE;") != c.SQLITE_OK) {
        log.print("[fs] FATAL: PRAGMA locking_mode\n");
        park();
    }

    files.migrate(db) catch {
        log.print("[fs] FATAL: schema migrate\n");
        park();
    };

    log.print("[fs] schema ready; entering serve loop\n");
    serveLoop(db, inv.fs_port.?, io_scratch_va, inv.blockdev_port.?, blockdev_scratch_va);
}

// ── superblock helpers ───────────────────────────────────────────

const SbState = struct {
    valid: bool,
    logical_size: u64,
};

fn readSuperblock(port: HandleId, scratch_va: u64) SbState {
    const status = blockdevSubmit(port, .read, 0, 1, 0);
    if (status != .ok) return .{ .valid = false, .logical_size = 0 };
    const scratch: *const superblock.Superblock = @ptrFromInt(scratch_va);
    if (!scratch.isValid()) return .{ .valid = false, .logical_size = 0 };
    return .{ .valid = true, .logical_size = scratch.logical_size };
}

fn writeSuperblock(port: HandleId, scratch_va: u64, sb: superblock.Superblock) void {
    const dst: *superblock.Superblock = @ptrFromInt(scratch_va);
    dst.* = sb;
    _ = blockdevSubmit(port, .write, 0, 1, 0);
}

fn persistSuperblock(port: HandleId, scratch_va: u64) void {
    const sb = superblock.Superblock{
        .magic = superblock.MAGIC,
        .version = superblock.VERSION,
        ._reserved0 = 0,
        .logical_size = vfs.getLogicalSize(),
        ._reserved_tail = [_]u8{0} ** (superblock.SIZE_BYTES - 24),
    };
    writeSuperblock(port, scratch_va, sb);
}

fn blockdevSubmit(
    port: HandleId,
    op: blockdev.Op,
    lba: u64,
    count: u64,
    buf_off: u64,
) blockdev.Status {
    const r = syscall.issueReg(
        .@"suspend",
        0,
        .{
            .v1 = @as(u64, caps.SLOT_INITIAL_EC),
            .v2 = @as(u64, port),
            .v3 = @intFromEnum(op),
            .v4 = lba,
            .v5 = count,
            .v6 = buf_off,
        },
    );
    return @enumFromInt(r.v1);
}

const Inbound = struct {
    blockdev_port: ?HandleId = null,
    fs_port: ?HandleId = null,
    blockdev_scratch: ?HandleId = null,
    io_scratch: ?HandleId = null,
};

fn scanInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(cap_table_base, slot);
        switch (cap.handleType()) {
            .port => {
                const port_caps = cap.caps();
                const has_recv = (port_caps & (1 << 3)) != 0;
                if (has_recv) {
                    if (inv.fs_port == null) inv.fs_port = @truncate(slot);
                } else {
                    if (inv.blockdev_port == null) inv.blockdev_port = @truncate(slot);
                }
            },
            .page_frame => {
                if (inv.blockdev_scratch == null) {
                    inv.blockdev_scratch = @truncate(slot);
                } else if (inv.io_scratch == null) {
                    inv.io_scratch = @truncate(slot);
                }
            },
            else => {},
        }
    }
    return inv;
}

fn mapPfRw(pf_handle: HandleId, pages: u64) ?u64 {
    const var_caps_word = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011;
    const cv = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        pages,
        0,
        0,
    );
    if (cv.v1 < 16) return null;
    const vmar_handle: HandleId = @truncate(cv.v1 & 0xFFF);
    const vmar_base = cv.v2;
    const pairs = [_]u64{ 0, pf_handle };
    const mp = syscall.mapPf(vmar_handle, pairs[0..]);
    if (mp.v1 != 0) return null;
    return vmar_base;
}

// ── serve loop ───────────────────────────────────────────────────

fn serveLoop(
    db: *c.sqlite3,
    port: HandleId,
    io_scratch_va: u64,
    blockdev_port: HandleId,
    blockdev_scratch_va: u64,
) noreturn {
    const scratch: [*]u8 = @ptrFromInt(io_scratch_va);
    const scratch_slice: []u8 = scratch[0..fs_ops.SCRATCH_BYTES];

    while (true) {
        const got = syscall.recv(port, RECV_TIMEOUT_NS);

        if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) continue;

        const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);
        const op_raw = got.regs.v3;
        const op: fs_ops.Op = @enumFromInt(op_raw);

        var rep_v1: u64 = @intFromEnum(fs_ops.Status.ok);
        var rep_v2: u64 = 0;
        var rep_v3: u64 = 0;
        var rep_v4: u64 = 0;
        var rep_v5: u64 = 0;
        var rep_v6: u64 = 0;
        var rep_v7: u64 = 0;
        var rep_v8: u64 = 0;
        var rep_v9: u64 = 0;

        switch (op) {
            .lookup => handleLookup(db, scratch_slice, got.regs, &rep_v1, &rep_v2, &rep_v3, &rep_v4, &rep_v5),
            .stat => handleStat(db, scratch_slice, got.regs, &rep_v1, &rep_v2, &rep_v3, &rep_v4, &rep_v5, &rep_v6, &rep_v7, &rep_v8, &rep_v9),
            .pread => handlePread(db, scratch_slice, got.regs, &rep_v1, &rep_v2, &rep_v3),
            .pwrite => handlePwrite(db, scratch_slice, got.regs, &rep_v1, &rep_v2, &rep_v3),
            .truncate => handleTruncate(db, scratch_slice, got.regs, &rep_v1),
            .create_file => handleCreateFile(db, scratch_slice, got.regs, &rep_v1, &rep_v2),
            .unlink => handleUnlink(db, scratch_slice, got.regs, &rep_v1),
            .mkdir => handleMkdir(db, scratch_slice, got.regs, &rep_v1, &rep_v2),
            .rmdir => handleRmdir(db, scratch_slice, got.regs, &rep_v1),
            .rename => handleRename(db, scratch_slice, got.regs, &rep_v1),
            .symlink => handleSymlink(db, scratch_slice, got.regs, &rep_v1, &rep_v2),
            .readlink => handleReadlink(db, scratch_slice, got.regs, &rep_v1, &rep_v2),
            .readdir => handleReaddir(db, scratch_slice, got.regs, &rep_v1, &rep_v2, &rep_v3, &rep_v4, &rep_v5, &rep_v6),
            .sync => {
                // Force any dirty SQLite page-cache entries to xWrite,
                // then commit our superblock. Without the cacheflush,
                // recently-INSERTed rows can sit in the page cache
                // indefinitely under journal_mode=MEMORY+sync=OFF.
                _ = c.sqlite3_db_cacheflush(db);
                persistSuperblock(blockdev_port, blockdev_scratch_va);
                rep_v1 = @intFromEnum(fs_ops.Status.ok);
            },
            else => rep_v1 = @intFromEnum(fs_ops.Status.bad_op),
        }

        _ = syscall.issueReg(
            .reply,
            syscall.extraReplyHandle(reply_handle),
            .{
                .v1 = rep_v1,
                .v2 = rep_v2,
                .v3 = rep_v3,
                .v4 = rep_v4,
                .v5 = rep_v5,
                .v6 = rep_v6,
                .v7 = rep_v7,
                .v8 = rep_v8,
                .v9 = rep_v9,
            },
        );
    }
}

// ── handlers ─────────────────────────────────────────────────────

fn handleLookup(
    db: *c.sqlite3,
    scratch: []u8,
    regs: anytype,
    s: *u64,
    inode: *u64,
    kind: *u64,
    size: *u64,
    mtime: *u64,
) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const info = files.stat(db, path) catch |e| {
        s.* = mapErr(e);
        return;
    };
    inode.* = @intCast(info.inode);
    kind.* = @intFromEnum(info.kind);
    size.* = @intCast(info.size);
    mtime.* = @intCast(info.mtime);
}

fn handleStat(
    db: *c.sqlite3,
    scratch: []u8,
    regs: anytype,
    s: *u64,
    inode: *u64,
    kind: *u64,
    size: *u64,
    mtime: *u64,
    mode: *u64,
    link_count: *u64,
    ctime: *u64,
    atime: *u64,
) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const info = files.stat(db, path) catch |e| {
        s.* = mapErr(e);
        return;
    };
    inode.* = @intCast(info.inode);
    kind.* = @intFromEnum(info.kind);
    size.* = @intCast(info.size);
    mtime.* = @intCast(info.mtime);
    mode.* = @intCast(info.mode);
    link_count.* = @intCast(info.link_count);
    ctime.* = @intCast(info.ctime);
    atime.* = @intCast(info.atime);
}

fn handlePread(
    db: *c.sqlite3,
    scratch: []u8,
    regs: anytype,
    s: *u64,
    bytes_read: *u64,
    data_off: *u64,
) void {
    const path_len = regs.v4;
    const offset = regs.v5;
    const max_len = regs.v6;
    const path = readPathLen(scratch, path_len) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const out_off = fs_ops.alignUp8(@intCast(path_len));
    if (out_off + max_len > scratch.len) {
        s.* = @intFromEnum(fs_ops.Status.invalid);
        return;
    }
    const dst = scratch[out_off .. out_off + @as(usize, @intCast(max_len))];
    const n = files.pread(db, path, offset, dst) catch |e| {
        s.* = mapErr(e);
        return;
    };
    bytes_read.* = @intCast(n);
    data_off.* = @intCast(out_off);
}

fn handlePwrite(
    db: *c.sqlite3,
    scratch: []u8,
    regs: anytype,
    s: *u64,
    bytes_written: *u64,
    new_size: *u64,
) void {
    const path = readPathLen(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const offset = regs.v5;
    const data_off = regs.v6;
    const data_len = regs.v7;
    if (data_off + data_len > scratch.len) {
        s.* = @intFromEnum(fs_ops.Status.invalid);
        return;
    }
    const src = scratch[@intCast(data_off) .. @as(usize, @intCast(data_off)) + @as(usize, @intCast(data_len))];
    const r = files.pwrite(db, path, offset, src, &pwrite_scratch) catch |e| {
        s.* = mapErr(e);
        return;
    };
    bytes_written.* = @intCast(r.written);
    new_size.* = r.new_size;
}

fn handleTruncate(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const new_size = regs.v5;
    files.truncate(db, path, new_size, &pwrite_scratch) catch |e| {
        s.* = mapErr(e);
    };
}

fn handleCreateFile(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64, inode: *u64) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const mode: i64 = @intCast(regs.v5);
    const new_inode = files.createFile(db, path, mode) catch |e| {
        s.* = mapErr(e);
        return;
    };
    inode.* = @intCast(new_inode);
}

fn handleUnlink(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    files.unlink(db, path) catch |e| {
        s.* = mapErr(e);
    };
}

fn handleMkdir(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64, inode: *u64) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    const mode: i64 = @intCast(regs.v5);
    const new_inode = files.mkdir(db, path, mode) catch |e| {
        s.* = mapErr(e);
        return;
    };
    inode.* = @intCast(new_inode);
}

fn handleRmdir(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    files.rmdir(db, path) catch |e| {
        s.* = mapErr(e);
    };
}

fn handleRename(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64) void {
    const old_len: usize = @intCast(regs.v4);
    const new_len: usize = @intCast(regs.v5);
    if (old_len == 0 or old_len > fs_ops.PATH_MAX or new_len == 0 or new_len > fs_ops.PATH_MAX) {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    }
    if (old_len + 1 + new_len > scratch.len) {
        s.* = @intFromEnum(fs_ops.Status.invalid);
        return;
    }
    const old = scratch[0..old_len];
    const new = scratch[old_len + 1 .. old_len + 1 + new_len];
    files.rename(db, old, new) catch |e| {
        s.* = mapErr(e);
    };
}

fn handleSymlink(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64, inode: *u64) void {
    const path_len: usize = @intCast(regs.v4);
    const target_len: usize = @intCast(regs.v5);
    if (path_len == 0 or path_len > fs_ops.PATH_MAX or target_len == 0 or target_len > fs_ops.PATH_MAX) {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    }
    if (path_len + 1 + target_len > scratch.len) {
        s.* = @intFromEnum(fs_ops.Status.invalid);
        return;
    }
    const path = scratch[0..path_len];
    const target = scratch[path_len + 1 .. path_len + 1 + target_len];
    const new_inode = files.symlink(db, path, target) catch |e| {
        s.* = mapErr(e);
        return;
    };
    inode.* = @intCast(new_inode);
}

fn handleReadlink(db: *c.sqlite3, scratch: []u8, regs: anytype, s: *u64, target_len: *u64) void {
    const path = readPath(scratch, regs.v4) orelse {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    };
    // Read into a stack buffer first so we can place the result at the
    // start of scratch without aliasing the in-flight path.
    var tmp: [fs_ops.PATH_MAX]u8 = undefined;
    const n = files.readlink(db, path, &tmp) catch |e| {
        s.* = mapErr(e);
        return;
    };
    @memcpy(scratch[0..n], tmp[0..n]);
    target_len.* = @intCast(n);
}

fn handleReaddir(
    db: *c.sqlite3,
    scratch: []u8,
    regs: anytype,
    s: *u64,
    entry_count: *u64,
    entries_off: *u64,
    entries_bytes: *u64,
    next_cookie_off: *u64,
    next_cookie_len: *u64,
) void {
    const path_len: usize = @intCast(regs.v4);
    const cookie_len: usize = @intCast(regs.v5);
    const max_entries: usize = @intCast(regs.v6);
    if (path_len == 0 or path_len > fs_ops.PATH_MAX or path_len + 1 + cookie_len > scratch.len) {
        s.* = @intFromEnum(fs_ops.Status.bad_path);
        return;
    }

    // Snapshot path + cookie out of scratch — readdir writes results
    // back into the same buffer so we can't share storage with inputs.
    var path_buf: [fs_ops.PATH_MAX]u8 = undefined;
    @memcpy(path_buf[0..path_len], scratch[0..path_len]);
    var cookie_buf_in: [fs_ops.NAME_MAX]u8 = undefined;
    if (cookie_len > 0) {
        if (cookie_len > cookie_buf_in.len) {
            s.* = @intFromEnum(fs_ops.Status.name_too_long);
            return;
        }
        @memcpy(cookie_buf_in[0..cookie_len], scratch[path_len + 1 .. path_len + 1 + cookie_len]);
    }

    // Reserve room at the front of scratch for the next_cookie and
    // pack entries after it.
    const cookie_slot = fs_ops.NAME_MAX;
    const entries_start = fs_ops.alignUp8(cookie_slot);
    const r = files.readdir(
        db,
        path_buf[0..path_len],
        cookie_buf_in[0..cookie_len],
        max_entries,
        scratch[entries_start..],
        scratch[0..cookie_slot],
    ) catch |e| {
        s.* = mapErr(e);
        return;
    };

    entry_count.* = @intCast(r.entries_written);
    entries_off.* = @intCast(entries_start);
    entries_bytes.* = @intCast(r.bytes_used);
    next_cookie_off.* = 0;
    next_cookie_len.* = @intCast(r.next_cookie.len);
}

// ── helpers ──────────────────────────────────────────────────────

fn readPath(scratch: []u8, len_word: u64) ?[]const u8 {
    return readPathLen(scratch, len_word);
}

fn readPathLen(scratch: []u8, len_word: u64) ?[]const u8 {
    const len: usize = @intCast(len_word);
    if (len == 0 or len > fs_ops.PATH_MAX or len > scratch.len) return null;
    return scratch[0..len];
}

fn mapErr(e: files.Error) u64 {
    return @intFromEnum(switch (e) {
        files.Error.NotFound => fs_ops.Status.not_found,
        files.Error.NotADirectory => fs_ops.Status.not_a_directory,
        files.Error.IsADirectory => fs_ops.Status.is_a_directory,
        files.Error.NameTooLong => fs_ops.Status.name_too_long,
        files.Error.PathTooLong => fs_ops.Status.path_too_long,
        files.Error.NoSpace => fs_ops.Status.no_space,
        files.Error.Exists => fs_ops.Status.exists,
        files.Error.NotEmpty => fs_ops.Status.not_empty,
        files.Error.Invalid => fs_ops.Status.invalid,
        files.Error.BadPath => fs_ops.Status.bad_path,
        files.Error.SqliteError => fs_ops.Status.io_error,
        files.Error.Truncated => fs_ops.Status.invalid,
    });
}

fn park() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}
