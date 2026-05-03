//! COM1 (0x3F8-0x3FF) port-IO emulation for the guest.
//!
//! TX is bridged via `log.print` — both log.zig and serial.zig write
//! to the same host COM1 device_region, so we reuse log.zig's
//! mapping rather than discovering COM1 a second time.
//!
//! Spec-v3 host-RX bridging is deferred. The pre-port driver wired
//! `pollHostRx` into the exit loop, polling the host LSR via a
//! private MMIO VAR and asserting IRQ 4 when bytes arrived. To
//! restore that path:
//!   1. Expose `serial_base` from log.zig (or do a second
//!      `createVar` + `map_mmio` over the same COM1 device_region,
//!      with the read-side caps).
//!   2. In `pollHostRx`, peek at `host_serial_base + REG_LSR`; on
//!      data-ready, read `REG_DATA` into rx_buf and set irq_pending.
//!
//! Until then, RX always reports "no data" (rxHasData returns false),
//! which is enough for QEMU+embedded-asset boots that don't depend on
//! interactive shell input.

const log = @import("log.zig");

const COM1_BASE: u16 = 0x3F8;
const COM1_DATA: u16 = 0x3F8;
const COM1_IER: u16 = 0x3F9;
const COM1_IIR: u16 = 0x3FA;
const COM1_LCR: u16 = 0x3FB;
const COM1_MCR: u16 = 0x3FC;
const COM1_LSR: u16 = 0x3FD;
const COM1_MSR: u16 = 0x3FE;
const COM1_SCR: u16 = 0x3FF;

var lcr: u8 = 0;
var mcr: u8 = 0;
var ier: u8 = 0;
var dll: u8 = 0;
var dlm: u8 = 0;
var scr: u8 = 0;
var fcr: u8 = 0;

pub var irq_pending: bool = false;

fn dlab() bool {
    return (lcr & 0x80) != 0;
}

pub fn init(cap_table_base: u64) void {
    _ = cap_table_base;
    // Host-RX bridging deferred (see module header). log.init has
    // already discovered COM1 for TX.
}

pub fn pollHostRx() void {
    // Stub — see module header.
}

pub fn isSerialPort(port: u16) bool {
    return port >= COM1_BASE and port <= COM1_SCR;
}

pub fn handleOut(port: u16, value: u8) void {
    switch (port) {
        COM1_DATA => {
            if (dlab()) {
                dll = value;
            } else {
                const ch: [1]u8 = .{value};
                log.print(&ch);
                if (ier & 0x02 != 0) irq_pending = true;
            }
        },
        COM1_IER => {
            if (dlab()) {
                dlm = value;
            } else {
                const old_ier = ier;
                ier = value;
                if (value & 0x02 != 0 and old_ier & 0x02 == 0) irq_pending = true;
            }
        },
        COM1_IIR => fcr = value,
        COM1_LCR => lcr = value,
        COM1_MCR => mcr = value,
        COM1_SCR => scr = value,
        else => {},
    }
}

pub fn handleIn(port: u16) u32 {
    return switch (port) {
        COM1_DATA => if (dlab()) @as(u32, dll) else @as(u32, 0),
        COM1_IER => if (dlab()) @as(u32, dlm) else @as(u32, ier),
        COM1_IIR => blk: {
            const fifo_bits: u32 = if (fcr & 0x01 != 0) 0xC0 else 0x00;
            if (ier & 0x02 != 0) break :blk fifo_bits | 0x02;
            break :blk fifo_bits | 0x01;
        },
        COM1_LCR => lcr,
        COM1_MCR => mcr,
        COM1_LSR => 0x60, // TX empty + THRE; no RX data ever
        COM1_MSR => 0xB0,
        COM1_SCR => scr,
        else => 0xFF,
    };
}
