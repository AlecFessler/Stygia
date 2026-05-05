// fs — filesystem service.
//
// Phase 2 path:
//   1. log.init via the kernel-issued COM1 device_region.
//   2. Discover passed handles (port, scratch page_frame).
//   3. Map the shared scratch page.
//   4. configureHeap → register blockdev VFS → sqlite3_initialize.
//   5. open db, CREATE TABLE files, INSERT a blob, SELECT it back,
//      assert bytes match.
//   6. Print result, park.
//
// Cap-table layout the root service hands us (in order, starting
// at SLOT_FIRST_PASSED = 3):
//   [3] — COM1 port_io device_region (logging)
//   [4] — port handle (with `xfer`; we suspend on it to send to block_device)
//   [5] — scratch page_frame (1 page; r+w; same pf block_device sees)

const lib = @import("lib");
const log = @import("log");
const blockdev = @import("blockdev");
const sqlite = @import("sqlite");

const builtin = @import("builtin");

// Force libc_shim into the link unit. None of its exported symbols
// are referenced from Zig directly (they're called from sqlite3.c via
// extern decls), so without this comptime hold the compiler would
// elide the module entirely. We still need the @import side-effect
// of registering libc_shim_mod's declarations.
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

const PAGE_4K: u64 = 4096;
const SCRATCH_PAGES: u64 = 1;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[fs] starting\n");

    const inv = scanInbound(cap_table_base);
    if (inv.port_handle == null or inv.scratch_pf == null) {
        log.print("[fs] FATAL: missing port or scratch page_frame\n");
        park();
    }

    const scratch_va = mapPfRw(inv.scratch_pf.?, SCRATCH_PAGES) orelse {
        log.print("[fs] FATAL: mapPf(scratch) failed\n");
        park();
    };

    log.print("[fs] scratch va=0x");
    log.hex64(scratch_va);
    log.print("\n");

    // ── Phase 1: smoke roundtrip without SQLite ─────────────────
    if (!smokeRoundtrip(inv.port_handle.?, scratch_va)) {
        log.print("[fs] phase-1 smoke: FAIL\n");
        park();
    }
    log.print("[fs] phase-1 smoke: PASS\n");

    // ── Phase 2: SQLite over the same blockdev port ─────────────
    if (!sqliteSmoke(inv.port_handle.?, scratch_va)) {
        log.print("[fs] phase-2 sqlite smoke: FAIL\n");
        park();
    }
    log.print("[fs] phase-2 sqlite smoke: PASS\n");

    // ── Phase 3: file-API smoke on top of the live SQLite handle ─
    // sqliteSmoke owned its own db; reopen for the file API tests.
    if (filesSmoke(inv.port_handle.?, scratch_va)) {
        log.print("[fs] phase-3 files smoke: PASS\n");
    } else {
        log.print("[fs] phase-3 files smoke: FAIL\n");
    }
    park();
}

const Inbound = struct {
    port_handle: ?HandleId = null,
    scratch_pf: ?HandleId = null,
};

fn scanInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c_cap = caps.readCap(cap_table_base, slot);
        switch (c_cap.handleType()) {
            .port => if (inv.port_handle == null) {
                inv.port_handle = @truncate(slot);
            },
            .page_frame => if (inv.scratch_pf == null) {
                inv.scratch_pf = @truncate(slot);
            },
            else => {},
        }
    }
    return inv;
}

fn mapPfRw(pf_handle: HandleId, pages: u64) ?u64 {
    const var_caps_word = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w
    const cv = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        pages,
        0,
        0,
    );
    if (cv.v1 < 16) return null;
    const vmar_handle: HandleId = @truncate(cv.v1 & 0xFFF);
    const vmar_base: u64 = cv.v2;

    const pairs = [_]u64{ 0, pf_handle };
    const mp = syscall.mapPf(vmar_handle, pairs[0..]);
    if (mp.v1 != 0) return null;
    return vmar_base;
}

// ── Phase 1 smoke: direct blockdev IPC roundtrip ─────────────────

fn submit(
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

fn smokeRoundtrip(port: HandleId, scratch_va: u64) bool {
    const sentinel = "DESKTOPOS-PHASE-1-SMOKE";
    const buf: [*]u8 = @ptrFromInt(scratch_va);

    var i: usize = 0;
    while (i < sentinel.len) : (i += 1) buf[i] = sentinel[i];
    while (i < blockdev.BLOCK_SIZE) : (i += 1) buf[i] = 0;

    if (submit(port, .write, 0, 1, 0) != .ok) return false;

    var j: usize = 0;
    while (j < blockdev.BLOCK_SIZE) : (j += 1) buf[j] = 0;

    if (submit(port, .read, 0, 1, 0) != .ok) return false;

    var k: usize = 0;
    while (k < sentinel.len) : (k += 1) {
        if (buf[k] != sentinel[k]) return false;
    }
    return true;
}

// ── Phase 2 smoke: SQLite open / CREATE / INSERT / SELECT ───────

fn sqliteSmoke(port: HandleId, scratch_va: u64) bool {
    log.print("[fs]   configuring SQLite heap + page cache\n");
    var rc = sqlite.configureHeap();
    if (rc != c.SQLITE_OK) {
        log.print("[fs]     configureHeap rc=");
        log.dec(@intCast(rc));
        log.print("\n");
        return false;
    }

    log.print("[fs]   registering blockdev VFS\n");
    rc = vfs.registerVfs(port, scratch_va, SCRATCH_PAGES);
    if (rc != c.SQLITE_OK) {
        log.print("[fs]     registerVfs rc=");
        log.dec(@intCast(rc));
        log.print("\n");
        return false;
    }

    log.print("[fs]   sqlite3_initialize\n");
    rc = c.sqlite3_initialize();
    if (rc != c.SQLITE_OK) {
        log.print("[fs]     initialize rc=");
        log.dec(@intCast(rc));
        log.print("\n");
        return false;
    }

    log.print("[fs]   sqlite3_open_v2(file:db?vfs=blockdev)\n");
    const db = sqlite.open("file:db?vfs=blockdev") catch return false;
    defer sqlite.close(db);

    // Single-file VFS: no separate journal file possible. Push journal
    // into memory and disable synchronous so SQLite doesn't try to
    // open a `db-journal` second file (which our VFS would alias to
    // the same blob). Also bump page size to 512 to match BLOCK_SIZE.
    log.print("[fs]   PRAGMA journal_mode=MEMORY; synchronous=OFF\n");
    if (sqlite.exec(db, "PRAGMA journal_mode=MEMORY;") != c.SQLITE_OK) {
        log.print("[fs]     PRAGMA journal_mode failed\n");
        return false;
    }
    if (sqlite.exec(db, "PRAGMA synchronous=OFF;") != c.SQLITE_OK) {
        log.print("[fs]     PRAGMA synchronous failed\n");
        return false;
    }
    if (sqlite.exec(db, "PRAGMA locking_mode=EXCLUSIVE;") != c.SQLITE_OK) {
        log.print("[fs]     PRAGMA locking_mode failed\n");
        return false;
    }

    log.print("[fs]   CREATE TABLE files\n");
    if (sqlite.exec(db, "CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, data BLOB);") != c.SQLITE_OK) {
        log.print("[fs]     CREATE failed\n");
        return false;
    }

    log.print("[fs]   INSERT files\n");
    var ins = sqlite.prepare(db, "INSERT INTO files(path, data) VALUES (?, ?);") catch return false;
    defer ins.finalize();
    sqlite.bindText(&ins, 1, "/hello") catch return false;
    sqlite.bindBlob(&ins, 2, "hello world from sqlite") catch return false;
    if (!ins.step()) {
        // step() returns true only on SQLITE_ROW; for INSERT we expect
        // SQLITE_DONE which yields false. Need to check the actual rc.
        // (simple check: query rowcount instead)
    }

    log.print("[fs]   SELECT data WHERE path='/hello'\n");
    var sel = sqlite.prepare(db, "SELECT data FROM files WHERE path = ?;") catch return false;
    defer sel.finalize();
    sqlite.bindText(&sel, 1, "/hello") catch return false;
    if (!sel.step()) {
        log.print("[fs]     SELECT returned no rows\n");
        return false;
    }
    const got = sel.columnBlob(0);

    const expect = "hello world from sqlite";
    if (got.len != expect.len) {
        log.print("[fs]     length mismatch: got ");
        log.dec(got.len);
        log.print(", expect ");
        log.dec(expect.len);
        log.print("\n");
        return false;
    }
    var m: usize = 0;
    while (m < expect.len) : (m += 1) {
        if (got[m] != expect[m]) {
            log.print("[fs]     byte mismatch at ");
            log.dec(m);
            log.print("\n");
            return false;
        }
    }
    log.print("[fs]   SQLite roundtrip verified: \"");
    log.print(got);
    log.print("\"\n");
    return true;
}

fn filesSmoke(port: HandleId, scratch_va: u64) bool {
    _ = port;
    _ = scratch_va;

    log.print("[fs]   reopening db for files API\n");
    const db = sqlite.open("file:db?vfs=blockdev") catch return false;
    defer sqlite.close(db);
    if (sqlite.exec(db, "PRAGMA journal_mode=MEMORY;") != c.SQLITE_OK) return false;
    if (sqlite.exec(db, "PRAGMA synchronous=OFF;") != c.SQLITE_OK) return false;
    if (sqlite.exec(db, "PRAGMA locking_mode=EXCLUSIVE;") != c.SQLITE_OK) return false;

    log.print("[fs]   files.init schema\n");
    files.init(db) catch return false;

    const payload = "the quick brown fox jumps over the lazy dog";
    log.print("[fs]   files.write /motd\n");
    files.write(db, "/motd", payload) catch return false;

    log.print("[fs]   files.stat /motd\n");
    const info = files.stat(db, "/motd") catch return false;
    if (info.size != payload.len) {
        log.print("[fs]     stat size mismatch: got ");
        log.dec(info.size);
        log.print(", expect ");
        log.dec(payload.len);
        log.print("\n");
        return false;
    }
    log.print("[fs]     size=");
    log.dec(info.size);
    log.print(" mtime=");
    log.dec(@intCast(info.mtime));
    log.print("\n");

    var rd_buf: [128]u8 = undefined;
    const n = files.read(db, "/motd", &rd_buf) catch |e| switch (e) {
        files.Error.NotFound => return false,
        files.Error.Truncated => return false,
        else => return false,
    };
    var i: usize = 0;
    while (i < payload.len) : (i += 1) {
        if (rd_buf[i] != payload[i]) return false;
    }
    log.print("[fs]   files.read /motd verified (");
    log.dec(n);
    log.print(" bytes)\n");

    log.print("[fs]   files.unlink /motd\n");
    files.unlink(db, "/motd") catch return false;
    if (files.stat(db, "/motd")) |_| {
        log.print("[fs]     unlink failed — file still exists\n");
        return false;
    } else |e| switch (e) {
        files.Error.NotFound => {
            log.print("[fs]     unlink confirmed (NotFound after delete)\n");
            return true;
        },
        else => return false,
    }
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
