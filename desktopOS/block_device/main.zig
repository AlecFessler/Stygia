// block_device — interim mock storage service.
//
// Owns a "disk" page_frame as its backing store and serves
// read_lba / write_lba requests on a port via the spec-v3
// suspend/recv/reply IPC. Same wire shape the eventual NVMe
// driver will speak, so the fs service is portable across them.
//
// Cap-table layout the root service hands us (in order, starting
// at SLOT_FIRST_PASSED = 3):
//   [3]      — COM1 port_io device_region (logging)
//   [4]      — port handle (with `recv`)
//   [5]      — scratch page_frame (1 page; r+w; shared with fs)
//   [6]      — disk page_frame (DISK_PAGES; r+w; private to this service)
//
// Once IOMMU mapping lands and the real NVMe driver replaces this
// service, the wire protocol stays the same; only the backing
// flips from a memcpy against an in-memory page_frame to actual
// NVM submission/completion queues.

const lib = @import("lib");
const log = @import("log");
const blockdev = @import("blockdev");

const builtin = @import("builtin");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const PAGE_4K: u64 = 4096;
const SCRATCH_PAGES: u64 = 1;
const DISK_PAGES: u64 = 4096; // 16 MiB
const DISK_BYTES: u64 = DISK_PAGES * PAGE_4K;

// Spec §[recv] [2]: 0 = block indefinitely, nonzero = relative ns
// timeout. `0xFFFF_FFFF_FFFF_FFFF` overflows the kernel's deadline
// computation and panics — use 0.
const RECV_TIMEOUT_NS: u64 = 0;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[block_device] starting\n");

    const inv = scanInbound(cap_table_base);
    if (inv.port_handle == null) {
        log.print("[block_device] FATAL: no port handle in cap table\n");
        park();
    }
    if (inv.pf_count < 2) {
        log.print("[block_device] FATAL: expected 2 page_frames, got ");
        log.dec(inv.pf_count);
        log.print("\n");
        park();
    }

    // The two page_frames arrive in passed-handle order: scratch
    // first, then disk. Their slot ids are deterministic given the
    // root service's spawn order.
    const scratch_pf = inv.pfs[0];
    const disk_pf = inv.pfs[1];

    const scratch_va = mapPfRw(scratch_pf, SCRATCH_PAGES) orelse {
        log.print("[block_device] FATAL: mapPf(scratch) failed\n");
        park();
    };
    const disk_va = mapPfRw(disk_pf, DISK_PAGES) orelse {
        log.print("[block_device] FATAL: mapPf(disk) failed\n");
        park();
    };

    // Zero the disk so a freshly-spawned service comes up clean.
    const disk_buf: [*]u8 = @ptrFromInt(disk_va);
    var i: u64 = 0;
    while (i < DISK_BYTES) : (i += 1) disk_buf[i] = 0;

    log.print("[block_device] ready: scratch=0x");
    log.hex64(scratch_va);
    log.print(" disk=0x");
    log.hex64(disk_va);
    log.print(" (");
    log.dec(DISK_BYTES / blockdev.BLOCK_SIZE);
    log.print(" sectors)\n");

    serveLoop(inv.port_handle.?, scratch_va, disk_va);
}

const Inbound = struct {
    port_handle: ?HandleId = null,
    pfs: [4]HandleId = undefined,
    pf_count: usize = 0,
};

fn scanInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        switch (c.handleType()) {
            .port => if (inv.port_handle == null) {
                inv.port_handle = @truncate(slot);
            },
            .page_frame => if (inv.pf_count < inv.pfs.len) {
                inv.pfs[inv.pf_count] = @truncate(slot);
                inv.pf_count += 1;
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

fn serveLoop(port: HandleId, scratch_va: u64, disk_va: u64) noreturn {
    log.print("[block_device] entering serve loop\n");
    while (true) {
        const got = syscall.recv(port, RECV_TIMEOUT_NS);

        if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) {
            log.print("[block_device] recv timeout\n");
            continue;
        }

        // §[reply] reply_handle_id at returned syscall-word bits 32-43.
        const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);

        // The sender's suspend payload is in vregs v3..v6 (we stuffed
        // op/lba/count/buf_off there). v1/v2 carry suspend-side
        // arg slots (target_ec / port) and don't echo through to recv.
        const op_raw = got.regs.v3;
        const lba = got.regs.v4;
        const count = got.regs.v5;
        const buf_off = got.regs.v6;

        log.print("[block_device]   request op=");
        log.dec(op_raw);
        log.print(" lba=");
        log.dec(lba);
        log.print(" count=");
        log.dec(count);
        log.print(" reply_h=");
        log.dec(reply_handle);
        log.print("\n");

        const status = serveOne(scratch_va, disk_va, op_raw, lba, count, buf_off);
        log.print("[block_device]   serveOne status=");
        log.dec(@intFromEnum(status));
        log.print("; replying\n");

        const rep = syscall.issueReg(
            .reply,
            syscall.extraReplyHandle(reply_handle),
            .{ .v1 = @intFromEnum(status) },
        );
        log.print("[block_device]   reply rc=");
        log.dec(rep.v1);
        log.print("\n");
    }
}

fn serveOne(
    scratch_va: u64,
    disk_va: u64,
    op_raw: u64,
    lba: u64,
    count: u64,
    buf_off: u64,
) blockdev.Status {
    const op: blockdev.Op = @enumFromInt(op_raw);
    const bytes = count * blockdev.BLOCK_SIZE;
    const disk_off = lba * blockdev.BLOCK_SIZE;

    if (disk_off + bytes > DISK_BYTES) return .out_of_range;
    if (buf_off + bytes > SCRATCH_PAGES * PAGE_4K) return .out_of_range;

    const scratch_buf: [*]u8 = @ptrFromInt(scratch_va);
    const disk_buf: [*]u8 = @ptrFromInt(disk_va);

    switch (op) {
        .read => {
            var i: u64 = 0;
            while (i < bytes) : (i += 1) {
                scratch_buf[buf_off + i] = disk_buf[disk_off + i];
            }
        },
        .write => {
            var i: u64 = 0;
            while (i < bytes) : (i += 1) {
                disk_buf[disk_off + i] = scratch_buf[buf_off + i];
            }
        },
        else => return .bad_op,
    }
    return .ok;
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
