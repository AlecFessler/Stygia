// serial_server — userspace owner of COM1.
//
// Maps the kernel-issued port_io device_region for 0x3F8/8 (same path
// as desktopOS/log/log.zig) and serves the protocol from
// `protocols/serial.zig` over a recv-side port. Clients place bytes in
// the shared scratch page_frame and suspend with op=print + byte_count;
// the server writes bytes 1-by-1 to COM1 and replies with a status.
//
// Cap-table layout from root_service (in passed-handle order):
//
//   [3] COM1 device_region (the sink we own)
//   [4] serial_port (recv|bind) — we are the server
//   [5] serial_scratch page_frame (1 page, shared with clients)

const lib = @import("lib");
const log = @import("log");
const serial = @import("serial");

const builtin = @import("builtin");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

// Spec §[recv] [2]: 0 = block indefinitely.
const RECV_TIMEOUT_NS: u64 = 0;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[serial_server] starting\n");

    const inv = scanInbound(cap_table_base);
    if (inv.serial_port == null or inv.scratch_pf == null) {
        log.print("[serial_server] FATAL: missing handles (port=");
        log.dec(if (inv.serial_port) |h| @as(u64, h) else 0);
        log.print(" scratch=");
        log.dec(if (inv.scratch_pf) |h| @as(u64, h) else 0);
        log.print(")\n");
        park();
    }

    const scratch_va = mapPfRw(inv.scratch_pf.?, serial.SCRATCH_PAGES) orelse {
        log.print("[serial_server] FATAL: mapPf(scratch) failed\n");
        park();
    };

    log.print("[serial_server] port=");
    log.dec(inv.serial_port.?);
    log.print(" scratch=0x");
    log.hex64(scratch_va);
    log.print("; entering serve loop\n");

    serveLoop(inv.serial_port.?, scratch_va);
}

const Inbound = struct {
    serial_port: ?HandleId = null,
    scratch_pf: ?HandleId = null,
};

fn scanInbound(cap_table_base: u64) Inbound {
    var inv: Inbound = .{};
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(cap_table_base, slot);
        switch (cap.handleType()) {
            .port => {
                if (inv.serial_port == null) inv.serial_port = @truncate(slot);
            },
            .page_frame => {
                if (inv.scratch_pf == null) inv.scratch_pf = @truncate(slot);
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

fn serveLoop(port: HandleId, scratch_va: u64) noreturn {
    const scratch: [*]const u8 = @ptrFromInt(scratch_va);

    while (true) {
        const got = syscall.recv(port, RECV_TIMEOUT_NS);
        if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) continue;

        const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);
        const op_raw = got.regs.v3;
        const op: serial.Op = @enumFromInt(op_raw);

        var status: serial.Status = .ok;
        switch (op) {
            .print => {
                const byte_count = got.regs.v4;
                if (byte_count > serial.SCRATCH_BYTES) {
                    status = .too_big;
                } else {
                    var i: usize = 0;
                    const n: usize = @intCast(byte_count);
                    while (i < n) : (i += 1) {
                        log.putc(scratch[i]);
                    }
                }
            },
            else => status = .bad_op,
        }

        _ = syscall.issueReg(
            .reply,
            syscall.extraReplyHandle(reply_handle),
            .{ .v1 = @intFromEnum(status) },
        );
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
