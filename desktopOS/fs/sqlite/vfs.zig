// Custom sqlite3_vfs that proxies xRead/xWrite to the block_device
// service over the spec-v3 suspend/recv/reply IPC defined in
// `desktopOS/protocols/blockdev.zig`.
//
// Single-file VFS: every sqlite3_open_v2 returns the same physical
// blob, starting STORAGE_OFFSET_LBA sectors into the volume so LBA 0
// can carry an fs superblock. Filename is ignored. xFileSize returns
// `logical_size`, which fs/main.zig primes from the superblock at
// boot (so SQLite sees the existing DB instead of an empty file).

const std = @import("std");
const lib = @import("lib");
const log = @import("log");
const blockdev = @import("blockdev");
const glue = @import("glue.zig");

const c = glue.c;
const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const SECTOR_SIZE: i64 = @intCast(blockdev.BLOCK_SIZE);
const PAGE_4K: u64 = 4096;

/// LBA where the SQLite-managed region starts. LBA 0 is reserved for
/// the fs superblock so we can recover logical_size on reboot.
pub const STORAGE_OFFSET_LBA: u64 = 1;
const STORAGE_OFFSET_BYTES: i64 = @as(i64, STORAGE_OFFSET_LBA) * SECTOR_SIZE;

// Globals filled in at registerVfs time. The single-VFS / single-DB
// model means no per-file state besides logical size.
var g_port: HandleId = 0;
var g_scratch_va: u64 = 0;
var g_scratch_pages: u64 = 0;
var logical_size: i64 = 0;

/// Set by fs/main.zig after reading the superblock so SQLite's first
/// xFileSize call sees the on-disk DB length instead of zero.
pub fn setLogicalSize(size: u64) void {
    logical_size = @intCast(size);
}

pub fn getLogicalSize() u64 {
    return @intCast(logical_size);
}

const FileExt = extern struct {
    base: c.sqlite3_file,
    // Future: per-handle locks, etc.
};

// ── sqlite3_io_methods ───────────────────────────────────────────

fn ioClose(_: [*c]c.sqlite3_file) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn ioRead(
    _: [*c]c.sqlite3_file,
    out: ?*anyopaque,
    n: c_int,
    ofst: c.sqlite3_int64,
) callconv(.c) c_int {
    const want: usize = @intCast(n);
    if (want == 0) return c.SQLITE_OK;
    if (ofst >= logical_size) {
        // Past EOF: SQLite expects SHORT_READ + zero-fill.
        const dst: [*]u8 = @ptrCast(out.?);
        @memset(dst[0..want], 0);
        return c.SQLITE_IOERR_SHORT_READ;
    }
    const dst: [*]u8 = @ptrCast(out.?);
    var done: usize = 0;
    while (done < want) {
        const phys = ofst + STORAGE_OFFSET_BYTES + @as(c.sqlite3_int64, @intCast(done));
        const lba: u64 = @intCast(@divFloor(phys, SECTOR_SIZE));
        const lba_offset_bytes: usize = @intCast(@mod(phys, SECTOR_SIZE));
        const remaining = want - done;
        // Read one sector at a time into scratch, then copy out the
        // requested slice. Alignment-tolerant; later we batch contiguous
        // sector runs.
        const status = submit(.read, lba, 1, 0);
        if (status != .ok) return c.SQLITE_IOERR_READ;
        const scratch: [*]u8 = @ptrFromInt(g_scratch_va);
        const take = @min(remaining, blockdev.BLOCK_SIZE - lba_offset_bytes);
        @memcpy(dst[done .. done + take], scratch[lba_offset_bytes .. lba_offset_bytes + take]);
        done += take;
    }
    return c.SQLITE_OK;
}

fn ioWrite(
    _: [*c]c.sqlite3_file,
    in: ?*const anyopaque,
    n: c_int,
    ofst: c.sqlite3_int64,
) callconv(.c) c_int {
    const want: usize = @intCast(n);
    if (want == 0) return c.SQLITE_OK;
    const src: [*]const u8 = @ptrCast(in.?);
    var done: usize = 0;
    while (done < want) {
        const phys = ofst + STORAGE_OFFSET_BYTES + @as(c.sqlite3_int64, @intCast(done));
        const lba: u64 = @intCast(@divFloor(phys, SECTOR_SIZE));
        const lba_offset_bytes: usize = @intCast(@mod(phys, SECTOR_SIZE));
        const remaining = want - done;
        const take = @min(remaining, blockdev.BLOCK_SIZE - lba_offset_bytes);
        const scratch: [*]u8 = @ptrFromInt(g_scratch_va);
        if (lba_offset_bytes != 0 or take != blockdev.BLOCK_SIZE) {
            // Partial sector: read-modify-write.
            const r = submit(.read, lba, 1, 0);
            if (r != .ok) {
                // First-write past EOF: zero-fill the scratch instead.
                @memset(scratch[0..blockdev.BLOCK_SIZE], 0);
            }
        }
        @memcpy(scratch[lba_offset_bytes .. lba_offset_bytes + take], src[done .. done + take]);
        const w = submit(.write, lba, 1, 0);
        if (w != .ok) return c.SQLITE_IOERR_WRITE;
        done += take;
    }
    if (ofst + @as(c.sqlite3_int64, @intCast(want)) > logical_size) {
        logical_size = ofst + @as(c.sqlite3_int64, @intCast(want));
    }
    return c.SQLITE_OK;
}

fn ioTruncate(_: [*c]c.sqlite3_file, size: c.sqlite3_int64) callconv(.c) c_int {
    logical_size = size;
    return c.SQLITE_OK;
}

fn ioSync(_: [*c]c.sqlite3_file, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn ioFileSize(_: [*c]c.sqlite3_file, out: [*c]c.sqlite3_int64) callconv(.c) c_int {
    out.* = logical_size;
    return c.SQLITE_OK;
}

fn ioLock(_: [*c]c.sqlite3_file, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn ioUnlock(_: [*c]c.sqlite3_file, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn ioCheckReservedLock(_: [*c]c.sqlite3_file, out: [*c]c_int) callconv(.c) c_int {
    out.* = 0;
    return c.SQLITE_OK;
}

fn ioFileControl(_: [*c]c.sqlite3_file, _: c_int, _: ?*anyopaque) callconv(.c) c_int {
    return c.SQLITE_NOTFOUND;
}

fn ioSectorSize(_: [*c]c.sqlite3_file) callconv(.c) c_int {
    return @intCast(SECTOR_SIZE);
}

fn ioDeviceCharacteristics(_: [*c]c.sqlite3_file) callconv(.c) c_int {
    return c.SQLITE_IOCAP_ATOMIC512 | c.SQLITE_IOCAP_SAFE_APPEND | c.SQLITE_IOCAP_SEQUENTIAL;
}

const io_methods = c.sqlite3_io_methods{
    .iVersion = 1,
    .xClose = ioClose,
    .xRead = ioRead,
    .xWrite = ioWrite,
    .xTruncate = ioTruncate,
    .xSync = ioSync,
    .xFileSize = ioFileSize,
    .xLock = ioLock,
    .xUnlock = ioUnlock,
    .xCheckReservedLock = ioCheckReservedLock,
    .xFileControl = ioFileControl,
    .xSectorSize = ioSectorSize,
    .xDeviceCharacteristics = ioDeviceCharacteristics,
    .xShmMap = null,
    .xShmLock = null,
    .xShmBarrier = null,
    .xShmUnmap = null,
    .xFetch = null,
    .xUnfetch = null,
};

// ── sqlite3_vfs ──────────────────────────────────────────────────

fn vfsOpen(
    _: [*c]c.sqlite3_vfs,
    _: c.sqlite3_filename,
    file: [*c]c.sqlite3_file,
    _: c_int,
    out_flags: [*c]c_int,
) callconv(.c) c_int {
    file.*.pMethods = &io_methods;
    if (out_flags != null) out_flags.* = c.SQLITE_OPEN_READWRITE;
    return c.SQLITE_OK;
}

fn vfsDelete(_: [*c]c.sqlite3_vfs, name: [*c]const u8, _: c_int) callconv(.c) c_int {
    // Single-file VFS: the only "real" file is the main DB. SQLite
    // asks us to delete journal/wal sidecars during recovery — those
    // never had storage backing them, so it's a no-op. CRITICAL: do
    // NOT zero logical_size here; SQLite will (correctly) call
    // xDelete("db-journal") on every open after a clean close, and
    // resetting size on that call masks the on-disk DB on reboot.
    if (isMainDb(name)) logical_size = 0;
    return c.SQLITE_OK;
}

fn vfsAccess(
    _: [*c]c.sqlite3_vfs,
    name: [*c]const u8,
    _: c_int,
    out: [*c]c_int,
) callconv(.c) c_int {
    // Only the main DB "exists". Journal sidecars never do — that
    // tells SQLite there's no stale rollback journal to recover from.
    out.* = if (isMainDb(name) and logical_size > 0) 1 else 0;
    return c.SQLITE_OK;
}

fn isMainDb(name: [*c]const u8) bool {
    if (name == null) return false;
    // The main DB is opened as "db" (see fs/main.zig sqlite.open).
    // Anything ending in "-journal", "-wal", "-shm", or any other
    // suffix is a sidecar this single-file VFS can't host.
    var i: usize = 0;
    var len: usize = 0;
    while (name[i] != 0) : (i += 1) len += 1;
    if (len < 2) return false;
    if (name[len - 2] == 'd' and name[len - 1] == 'b') return true;
    return false;
}

fn vfsFullPathname(
    _: [*c]c.sqlite3_vfs,
    name: [*c]const u8,
    nout: c_int,
    out: [*c]u8,
) callconv(.c) c_int {
    var i: usize = 0;
    const cap: usize = @intCast(nout - 1);
    while (i < cap and name[i] != 0) : (i += 1) out[i] = name[i];
    out[i] = 0;
    return c.SQLITE_OK;
}

fn vfsRandomness(_: [*c]c.sqlite3_vfs, n: c_int, out: [*c]u8) callconv(.c) c_int {
    var done: c_int = 0;
    while (done < n) {
        const r = syscall.random(8);
        // 8 bytes via random; copy what fits.
        const v = r.v1;
        var i: c_int = 0;
        while (i < 8 and done < n) : (i += 1) {
            out[@intCast(done)] = @truncate((v >> @intCast(i * 8)) & 0xFF);
            done += 1;
        }
    }
    return n;
}

fn vfsSleep(_: [*c]c.sqlite3_vfs, micros: c_int) callconv(.c) c_int {
    // Spin-yield for the requested duration. SQLite only sleeps in
    // contention paths we won't hit in single-threaded mode.
    const start = syscall.timeMonotonic().v1;
    const want_ns: u64 = @as(u64, @intCast(micros)) * 1000;
    while (syscall.timeMonotonic().v1 - start < want_ns) {
        _ = syscall.yieldEc(0);
    }
    return micros;
}

fn vfsCurrentTime(_: [*c]c.sqlite3_vfs, out: [*c]f64) callconv(.c) c_int {
    var ms: c.sqlite3_int64 = undefined;
    const rc = vfsCurrentTimeInt64(null, &ms);
    if (rc != c.SQLITE_OK) return rc;
    out.* = @as(f64, @floatFromInt(ms)) / 86_400_000.0 + 2440587.5;
    return c.SQLITE_OK;
}

fn vfsCurrentTimeInt64(_: [*c]c.sqlite3_vfs, out: [*c]c.sqlite3_int64) callconv(.c) c_int {
    const ns = syscall.timeGetwall().v1;
    out.* = @intCast(ns / 1_000_000);
    return c.SQLITE_OK;
}

fn vfsGetLastError(_: [*c]c.sqlite3_vfs, _: c_int, _: [*c]u8) callconv(.c) c_int {
    return 0;
}

var blockdev_vfs: c.sqlite3_vfs = .{
    .iVersion = 2,
    .szOsFile = @sizeOf(FileExt),
    .mxPathname = 64,
    .pNext = null,
    .zName = "blockdev",
    .pAppData = null,
    .xOpen = vfsOpen,
    .xDelete = vfsDelete,
    .xAccess = vfsAccess,
    .xFullPathname = vfsFullPathname,
    .xDlOpen = null,
    .xDlError = null,
    .xDlSym = null,
    .xDlClose = null,
    .xRandomness = vfsRandomness,
    .xSleep = vfsSleep,
    .xCurrentTime = vfsCurrentTime,
    .xGetLastError = vfsGetLastError,
    .xCurrentTimeInt64 = vfsCurrentTimeInt64,
    // v3 fields zeroed
    .xSetSystemCall = null,
    .xGetSystemCall = null,
    .xNextSystemCall = null,
};

pub fn registerVfs(port_handle: HandleId, scratch_va: u64, scratch_pages: u64) c_int {
    g_port = port_handle;
    g_scratch_va = scratch_va;
    g_scratch_pages = scratch_pages;
    return c.sqlite3_vfs_register(&blockdev_vfs, 1);
}

// ── blockdev IPC submit (same wire shape as fs/main's smoke) ────

fn submit(op: blockdev.Op, lba: u64, count: u64, buf_off: u64) blockdev.Status {
    const r = syscall.issueReg(
        .@"suspend",
        0,
        .{
            .v1 = @as(u64, caps.SLOT_INITIAL_EC),
            .v2 = @as(u64, g_port),
            .v3 = @intFromEnum(op),
            .v4 = lba,
            .v5 = count,
            .v6 = buf_off,
        },
    );
    return @enumFromInt(r.v1);
}
