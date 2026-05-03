//! PL011 PrimeCell UART emulation.
//!
//! Models just enough of the ARM PL011 r1p5 register file (ARM DDI 0183G)
//! to let Linux's amba-pl011 driver push characters to the host. Only TX
//! is implemented — RX is a no-op (UARTFR.RXFE is permanently set).
//!
//! Register map (relative to UARTBASE, all u32 unless noted):
//!   0x000  UARTDR    — data register        (r1p5 §3.3.1)
//!   0x004  UARTRSR   — receive status / err (r1p5 §3.3.2)
//!   0x018  UARTFR    — flag register        (r1p5 §3.3.3)
//!   0x020  UARTILPR  — IrDA low-power       (r1p5 §3.3.4)
//!   0x024  UARTIBRD  — integer baud divisor (r1p5 §3.3.5)
//!   0x028  UARTFBRD  — fractional baud      (r1p5 §3.3.6)
//!   0x02C  UARTLCR_H — line control         (r1p5 §3.3.7)
//!   0x030  UARTCR    — control              (r1p5 §3.3.8)
//!   0x034  UARTIFLS  — interrupt FIFO level (r1p5 §3.3.9)
//!   0x038  UARTIMSC  — interrupt mask       (r1p5 §3.3.10)
//!   0x03C  UARTRIS   — raw interrupt status (r1p5 §3.3.11)
//!   0x040  UARTMIS   — masked int status    (r1p5 §3.3.12)
//!   0x044  UARTICR   — interrupt clear      (r1p5 §3.3.13)
//!
//! The only side effect on writes is UARTDR: the byte is forwarded to
//! the VMM's write syscall so the host debug console sees guest output.

const log = @import("log.zig");

// Forwarding sink for guest UARTDR writes. Set by `bindTxSink` once
// the boot path has discovered a host MMIO surface (e.g. the host
// PL011 device_region passed in at boot, mapped via createVmar +
// mapMmio). Until then, TX bytes are dropped. The marker
// `"hello from guest"` only appears in the host serial output once
// this is wired.
var tx_sink: ?[*]volatile u8 = null;

pub fn bindTxSink(sink: [*]volatile u8) void {
    tx_sink = sink;
}

pub const UART_BASE: u64 = 0x09000000;
pub const UART_SIZE: u64 = 0x1000;

/// Guest physical MMIO range covered by this device.
pub fn contains(addr: u64) bool {
    return addr >= UART_BASE and addr < UART_BASE + UART_SIZE;
}

/// UARTFR bits we advertise (r1p5 §3.3.3):
///   bit 4  RXFE — receive FIFO empty (always 1 — no host→guest input)
///   bit 7  TXFE — transmit FIFO empty (always 1 — we flush instantly)
const UARTFR_RXFE: u32 = 1 << 4;
const UARTFR_TXFE: u32 = 1 << 7;

/// Read an emulated PL011 register. Returns the 64-bit load value to
/// place in the guest's destination register.
pub fn read(offset: u64) u64 {
    return switch (offset) {
        // UARTDR: no input available; return 0 and keep UARTFR.RXFE high.
        0x000 => 0,
        // UARTFR: permanently "TX empty, RX empty, not busy" so Linux
        // busy-loops never stall waiting for the FIFO.
        0x018 => UARTFR_RXFE | UARTFR_TXFE,
        // PrimeCell peripheral / PrimeCell ID registers live at the top
        // of the page. Linux probes these to confirm the part is a PL011.
        // Values are from r1p5 §4.3 Table 4-2. Returning zero works for
        // DT-driven probes because Linux's amba-pl011 binding matches on
        // the "arm,pl011" compatible string; the ID page read is only
        // used for the AMBA bus probe. We still supply them for safety.
        0xFE0 => 0x11, // PeriphID0
        0xFE4 => 0x10, // PeriphID1
        0xFE8 => 0x34, // PeriphID2 (rev)
        0xFEC => 0x00, // PeriphID3
        0xFF0 => 0x0D, // PCellID0
        0xFF4 => 0xF0, // PCellID1
        0xFF8 => 0x05, // PCellID2
        0xFFC => 0xB1, // PCellID3
        else => 0,
    };
}

/// Handle a stage-2 fault inside the PL011 MMIO range. Decodes the
/// fault's access classification (read vs write, destination register,
/// access size) from the §[vm_exit_state] aarch64 stage2_fault payload
/// (vreg 120 packed flags), dispatches to `read`/`write`, and advances
/// the guest PC past the trapping instruction. Returns true to keep
/// the run loop alive.
pub fn handleFault(state: *vm_exit.VmExitState, guest_phys: u64) bool {
    const offset = guest_phys - UART_BASE;
    // exit_payload[2] layout (per spec §[vm_exit_state] aarch64):
    //   [0..7]   access_size (u8)
    //   [8..15]  srt (u8) destination register
    //   [16..23] fsc (u8) fault status code
    //   [24..31] flags (u8): bit1 = write, bit2 = iss_valid, ...
    const info = state.exit_payload[2];
    const srt: u8 = @truncate(info >> 8);
    const flags: u8 = @truncate(info >> 24);
    const is_write: bool = (flags & 0x02) != 0;
    if (is_write) {
        const value = readGpr(state, srt);
        write(offset, value);
    } else {
        writeGpr(state, srt, read(offset));
    }
    state.pc += 4;
    return false;
}

const vm_exit = @import("vm_exit.zig");

fn readGpr(state: *const vm_exit.VmExitState, idx: u8) u64 {
    return switch (idx) {
        0 => state.x0,
        1 => state.x1,
        2 => state.x2,
        3 => state.x3,
        4 => state.x4,
        5 => state.x5,
        6 => state.x6,
        7 => state.x7,
        8 => state.x8,
        9 => state.x9,
        10 => state.x10,
        11 => state.x11,
        12 => state.x12,
        13 => state.x13,
        14 => state.x14,
        15 => state.x15,
        16 => state.x16,
        17 => state.x17,
        18 => state.x18,
        19 => state.x19,
        20 => state.x20,
        21 => state.x21,
        22 => state.x22,
        23 => state.x23,
        24 => state.x24,
        25 => state.x25,
        26 => state.x26,
        27 => state.x27,
        28 => state.x28,
        29 => state.x29,
        30 => state.x30,
        else => 0,
    };
}

fn writeGpr(state: *vm_exit.VmExitState, idx: u8, val: u64) void {
    switch (idx) {
        0 => state.x0 = val,
        1 => state.x1 = val,
        2 => state.x2 = val,
        3 => state.x3 = val,
        4 => state.x4 = val,
        5 => state.x5 = val,
        6 => state.x6 = val,
        7 => state.x7 = val,
        8 => state.x8 = val,
        9 => state.x9 = val,
        10 => state.x10 = val,
        11 => state.x11 = val,
        12 => state.x12 = val,
        13 => state.x13 = val,
        14 => state.x14 = val,
        15 => state.x15 = val,
        16 => state.x16 = val,
        17 => state.x17 = val,
        18 => state.x18 = val,
        19 => state.x19 = val,
        20 => state.x20 = val,
        21 => state.x21 = val,
        22 => state.x22 = val,
        23 => state.x23 = val,
        24 => state.x24 = val,
        25 => state.x25 = val,
        26 => state.x26 = val,
        27 => state.x27 = val,
        28 => state.x28 = val,
        29 => state.x29 = val,
        30 => state.x30 = val,
        else => {},
    }
}

/// Write an emulated PL011 register. Only UARTDR has a side effect.
pub fn write(offset: u64, value: u64) void {
    switch (offset) {
        0x000 => {
            // UARTDR: low 8 bits are the TX byte; forward to the
            // bound host serial sink (set by `bindTxSink` after the
            // VMM maps a host PL011 MMIO VMAR). Without a sink, drop
            // silently — Linux still progresses, just quietly.
            const ch: u8 = @intCast(value & 0xFF);
            if (tx_sink) |sink| sink[0] = ch;
        },
        // Baud rate / line control / control / interrupt mask — Linux
        // writes them during probe and console takeover. We accept and
        // ignore; no interrupts fire because we advertise TXFE always
        // clear (the transmit path is effectively a noop-fast-path).
        0x004, 0x020, 0x024, 0x028, 0x02C, 0x030, 0x034, 0x038, 0x044 => {},
        else => {
            // Unknown writes: swallow silently but announce the offset
            // so a genuine driver bug is still observable.
            log.print("pl011: wr @");
            log.hex64(offset);
            log.print("\n");
        },
    }
}
