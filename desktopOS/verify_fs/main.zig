// verify_fs — smoke harness for the stateless FS protocol.
//
// Walks through the public surface of `fs_client` and asserts that
// each op behaves: directory creation/listing, file write/read at
// random offsets, rename across dirs, symlink + readlink, and the
// error cases that must NOT succeed (ENOENT, ENOTDIR, EEXIST,
// ENOTEMPTY, EISDIR).
//
// Cap-table layout the root service hands us:
//   [3] COM1 device_region (logging)
//   [4] fs port (xfer|bind)
//   [5] io_scratch_pf (SCRATCH_PAGES, r+w)

const lib = @import("lib");
const log = @import("log");
const fs_client = @import("fs_client");
const fs_ops = @import("fs_ops");

const builtin = @import("builtin");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

var pass_count: usize = 0;
var fail_count: usize = 0;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[verify_fs] starting\n");

    const inv = scanInbound(cap_table_base);
    if (inv.fs_port == null or inv.io_scratch == null) {
        log.print("[verify_fs] FATAL: missing handles\n");
        park();
    }

    const scratch_va = mapPfRw(inv.io_scratch.?, fs_ops.SCRATCH_PAGES) orelse {
        log.print("[verify_fs] FATAL: mapPf(io_scratch)\n");
        park();
    };

    const port = inv.fs_port.?;
    log.print("[verify_fs] fs_port=");
    log.dec(port);
    log.print(" scratch=0x");
    log.hex64(scratch_va);
    log.print("\n");

    runPhase("persistence", testPersistence, port, scratch_va);
    runPhase("cleanup", testCleanup, port, scratch_va);
    runPhase("dir-ops", testDirOps, port, scratch_va);
    runPhase("file-rw", testFileRw, port, scratch_va);
    runPhase("random-io", testRandomIo, port, scratch_va);
    runPhase("rename", testRename, port, scratch_va);
    runPhase("symlink", testSymlink, port, scratch_va);
    runPhase("errors", testErrors, port, scratch_va);
    runPhase("readdir-walk", testReaddirWalk, port, scratch_va);
    runPhase("sync", testSync, port, scratch_va);

    log.print("[verify_fs] DONE: ");
    log.dec(pass_count);
    log.print(" pass / ");
    log.dec(fail_count);
    log.print(" fail\n");

    park();
}

// ── Test phases ──────────────────────────────────────────────────

const PERSIST_MARKER = "/persist_marker";
const PERSIST_PAYLOAD = "ZAGFS_PERSIST_OK";

fn testPersistence(port: HandleId, scratch_va: u64) bool {
    // Reading the marker: if present and matches, prior boot's data
    // survived. If absent, this is first boot — we create it for the
    // next boot to find.
    if (fs_client.stat(port, scratch_va, PERSIST_MARKER)) |s| {
        var buf: [64]u8 = undefined;
        const n = fs_client.pread(port, scratch_va, PERSIST_MARKER, 0, buf[0..@intCast(s.size)]) catch return false;
        if (!sliceEq(buf[0..n], PERSIST_PAYLOAD)) {
            log.print("[verify_fs]   persistence marker corrupted: '");
            log.print(buf[0..n]);
            log.print("'\n");
            return false;
        }
        log.print("[verify_fs]   persistence verified: marker survived reboot\n");
        return true;
    } else |e| {
        if (e != fs_client.FsError.NotFound) {
            log.print("[verify_fs]   stat marker err=");
            log.dec(@intFromError(e));
            log.print("\n");
            return false;
        }
        if (!ok(fs_client.createFile(port, scratch_va, PERSIST_MARKER, 0o644), "createFile marker")) return false;
        const w = fs_client.pwrite(port, scratch_va, PERSIST_MARKER, 0, PERSIST_PAYLOAD) catch return false;
        if (w.written != PERSIST_PAYLOAD.len) return false;
        log.print("[verify_fs]   first boot: marker created (sync at end persists it)\n");
        return true;
    }
}

fn testCleanup(port: HandleId, scratch_va: u64) bool {
    // Best-effort sweep of fixtures from prior boots so the destructive
    // phases below run against a known-empty tree. NotFound is fine.
    const fixtures = [_][]const u8{
        "/etc/motd-link",
        "/etc/notes.txt",
        "/etc/motd",
        "/etc/bigfile",
        "/etc/zag",
        "/etc",
        "/home/alec/notes.txt",
        "/home/alec/note",
        "/home/alec",
        "/home",
    };
    for (fixtures) |p| {
        const s = fs_client.stat(port, scratch_va, p) catch continue;
        switch (s.kind) {
            .dir => _ = fs_client.rmdir(port, scratch_va, p) catch {},
            else => _ = fs_client.unlink(port, scratch_va, p) catch {},
        }
    }
    return true;
}

fn testDirOps(port: HandleId, scratch_va: u64) bool {
    if (!ok(fs_client.mkdir(port, scratch_va, "/etc", 0o755), "mkdir /etc")) return false;
    if (!ok(fs_client.mkdir(port, scratch_va, "/etc/zag", 0o755), "mkdir /etc/zag")) return false;
    if (!ok(fs_client.mkdir(port, scratch_va, "/home", 0o755), "mkdir /home")) return false;
    if (!ok(fs_client.mkdir(port, scratch_va, "/home/alec", 0o755), "mkdir /home/alec")) return false;

    const s = fs_client.stat(port, scratch_va, "/etc/zag") catch |e| {
        log.print("[verify_fs]   stat /etc/zag err=");
        log.dec(@intFromError(e));
        log.print("\n");
        return false;
    };
    if (s.kind != .dir) {
        log.print("[verify_fs]   /etc/zag not a directory\n");
        return false;
    }
    return true;
}

fn testFileRw(port: HandleId, scratch_va: u64) bool {
    if (!ok(fs_client.createFile(port, scratch_va, "/etc/motd", 0o644), "create /etc/motd")) return false;

    const motd = "the quick brown fox jumps over the lazy dog";
    const w = fs_client.pwrite(port, scratch_va, "/etc/motd", 0, motd) catch |e| {
        log.print("[verify_fs]   pwrite err=");
        log.dec(@intFromError(e));
        log.print("\n");
        return false;
    };
    if (w.written != motd.len or w.new_size != motd.len) {
        log.print("[verify_fs]   pwrite returned wrong sizes\n");
        return false;
    }

    var rd: [128]u8 = undefined;
    const n = fs_client.pread(port, scratch_va, "/etc/motd", 0, &rd) catch |e| {
        log.print("[verify_fs]   pread err=");
        log.dec(@intFromError(e));
        log.print("\n");
        return false;
    };
    if (n != motd.len) return false;
    if (!sliceEq(rd[0..n], motd)) return false;

    const s = fs_client.stat(port, scratch_va, "/etc/motd") catch return false;
    if (s.size != motd.len or s.kind != .file) return false;
    return true;
}

fn testRandomIo(port: HandleId, scratch_va: u64) bool {
    // Build a 4 KiB file by writing four 1 KiB chunks at staggered offsets.
    if (!ok(fs_client.createFile(port, scratch_va, "/etc/bigfile", 0o644), "create bigfile")) return false;

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var chunk: [1024]u8 = undefined;
        var j: usize = 0;
        while (j < chunk.len) : (j += 1) chunk[j] = @truncate((i * 1024 + j) & 0xFF);
        const off: u64 = @intCast(i * 1024);
        const w = fs_client.pwrite(port, scratch_va, "/etc/bigfile", off, &chunk) catch return false;
        if (w.written != chunk.len) return false;
    }

    const s = fs_client.stat(port, scratch_va, "/etc/bigfile") catch return false;
    if (s.size != 4096) {
        log.print("[verify_fs]   bigfile size=");
        log.dec(s.size);
        log.print(", expect 4096\n");
        return false;
    }

    // Read the whole file in 256-byte chunks at random-looking offsets and verify bytes.
    const offsets = [_]u64{ 0, 1024, 2048, 3072, 250, 1500, 2700, 3900 };
    for (offsets) |off| {
        var buf: [256]u8 = undefined;
        const n = fs_client.pread(port, scratch_va, "/etc/bigfile", off, &buf) catch return false;
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const want: u8 = @truncate((off + k) & 0xFF);
            if (buf[k] != want) {
                log.print("[verify_fs]   bigfile byte mismatch at off=");
                log.dec(off + k);
                log.print("\n");
                return false;
            }
        }
    }
    return true;
}

fn testRename(port: HandleId, scratch_va: u64) bool {
    if (!ok(fs_client.createFile(port, scratch_va, "/home/alec/note", 0o644), "create note")) return false;
    const body = "hello rename";
    _ = fs_client.pwrite(port, scratch_va, "/home/alec/note", 0, body) catch return false;

    if (!ok(fs_client.rename(port, scratch_va, "/home/alec/note", "/home/alec/notes.txt"), "rename")) return false;

    if (fs_client.stat(port, scratch_va, "/home/alec/note")) |_| {
        log.print("[verify_fs]   old name still exists\n");
        return false;
    } else |e| {
        if (e != fs_client.FsError.NotFound) return false;
    }

    var rd: [64]u8 = undefined;
    const n = fs_client.pread(port, scratch_va, "/home/alec/notes.txt", 0, &rd) catch return false;
    if (!sliceEq(rd[0..n], body)) return false;

    if (!ok(fs_client.rename(port, scratch_va, "/home/alec/notes.txt", "/etc/notes.txt"), "rename across dirs")) return false;
    return true;
}

fn testSymlink(port: HandleId, scratch_va: u64) bool {
    if (!ok(fs_client.symlink(port, scratch_va, "/etc/motd-link", "/etc/motd"), "symlink")) return false;
    var buf: [128]u8 = undefined;
    const n = fs_client.readlink(port, scratch_va, "/etc/motd-link", &buf) catch return false;
    if (!sliceEq(buf[0..n], "/etc/motd")) return false;
    return true;
}

fn testErrors(port: HandleId, scratch_va: u64) bool {
    const FE = fs_client.FsError;

    // ENOENT
    if (fs_client.stat(port, scratch_va, "/no/such/path")) |_| {
        log.print("[verify_fs]   stat of nonexistent path returned ok\n");
        return false;
    } else |e| {
        if (e != FE.NotFound) return false;
    }

    // EEXIST
    if (fs_client.mkdir(port, scratch_va, "/etc", 0o755)) |_| {
        log.print("[verify_fs]   mkdir over existing returned ok\n");
        return false;
    } else |e| {
        if (e != FE.Exists) return false;
    }

    // ENOTEMPTY
    if (fs_client.rmdir(port, scratch_va, "/etc")) |_| {
        log.print("[verify_fs]   rmdir of non-empty dir returned ok\n");
        return false;
    } else |e| {
        if (e != FE.NotEmpty) return false;
    }

    // EISDIR
    if (fs_client.unlink(port, scratch_va, "/etc")) |_| {
        log.print("[verify_fs]   unlink of dir returned ok\n");
        return false;
    } else |e| {
        if (e != FE.IsADirectory) return false;
    }

    // ENOTDIR
    if (fs_client.mkdir(port, scratch_va, "/etc/motd/sub", 0o755)) |_| {
        log.print("[verify_fs]   mkdir under file returned ok\n");
        return false;
    } else |e| {
        if (e != FE.NotADirectory) return false;
    }

    return true;
}

fn testSync(port: HandleId, scratch_va: u64) bool {
    return ok(fs_client.sync(port, scratch_va), "sync");
}

fn testReaddirWalk(port: HandleId, scratch_va: u64) bool {
    var entries_buf: [16]fs_client.DirEntry = undefined;
    var cookie: [256]u8 = undefined;
    var cookie_len: usize = 0;

    var seen_motd = false;
    var seen_zag = false;
    var seen_bigfile = false;
    var seen_motd_link = false;
    var seen_notes = false;

    while (true) {
        const r = fs_client.readdir(port, scratch_va, "/etc", cookie[0..cookie_len], &entries_buf) catch return false;
        for (r.entries) |e| {
            if (sliceEq(e.name, "motd")) seen_motd = true;
            if (sliceEq(e.name, "zag")) seen_zag = true;
            if (sliceEq(e.name, "bigfile")) seen_bigfile = true;
            if (sliceEq(e.name, "motd-link")) seen_motd_link = true;
            if (sliceEq(e.name, "notes.txt")) seen_notes = true;
        }
        if (r.end_of_dir) break;
        if (r.next_cookie.len > cookie.len) return false;
        @memcpy(cookie[0..r.next_cookie.len], r.next_cookie);
        cookie_len = r.next_cookie.len;
    }

    if (!(seen_motd and seen_zag and seen_bigfile and seen_motd_link and seen_notes)) {
        log.print("[verify_fs]   readdir missed entries: motd=");
        log.dec(@intFromBool(seen_motd));
        log.print(" zag=");
        log.dec(@intFromBool(seen_zag));
        log.print(" bigfile=");
        log.dec(@intFromBool(seen_bigfile));
        log.print(" motd-link=");
        log.dec(@intFromBool(seen_motd_link));
        log.print(" notes.txt=");
        log.dec(@intFromBool(seen_notes));
        log.print("\n");
        return false;
    }
    return true;
}

// ── Helpers ──────────────────────────────────────────────────────

fn ok(result: anytype, label: []const u8) bool {
    return switch (@typeInfo(@TypeOf(result))) {
        .error_union => blk: {
            if (result) |_| {
                break :blk true;
            } else |e| {
                log.print("[verify_fs]   ");
                log.print(label);
                log.print(" err=");
                log.dec(@intFromError(e));
                log.print("\n");
                break :blk false;
            }
        },
        else => @compileError("ok() expects error union"),
    };
}

fn runPhase(
    name: []const u8,
    f: *const fn (HandleId, u64) bool,
    port: HandleId,
    scratch_va: u64,
) void {
    log.print("[verify_fs] phase ");
    log.print(name);
    log.print(": ");
    if (f(port, scratch_va)) {
        log.print("PASS\n");
        pass_count += 1;
    } else {
        log.print("FAIL\n");
        fail_count += 1;
    }
}

fn sliceEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

const Inbound = struct {
    fs_port: ?HandleId = null,
    io_scratch: ?HandleId = null,
};

fn scanInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(cap_table_base, slot);
        switch (cap.handleType()) {
            .port => if (inv.fs_port == null) {
                inv.fs_port = @truncate(slot);
            },
            .page_frame => if (inv.io_scratch == null) {
                inv.io_scratch = @truncate(slot);
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

fn park() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}
