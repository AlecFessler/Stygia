const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const sync = zag.utils.sync;

/// Standard ISA I/O base addresses for COM1-COM4.
/// These are the conventional PC/AT port assignments for 16550-compatible UARTs.
const Ports = enum(u16) {
    com1 = 0x3F8,
    com2 = 0x2F8,
    com3 = 0x3E8,
    com4 = 0x2E8,
};

/// NS16550 / TL16C550C register offsets from the base I/O port.
/// TL16C550C datasheet, §8 "Register Descriptions":
///   DLL (offset 0) — Divisor Latch LSB (DLAB=1)
///   IER (offset 1) — Interrupt Enable Register (DLAB=0)
///   DLH (offset 1) — Divisor Latch MSB (DLAB=1)
///   FCR (offset 2) — FIFO Control Register (write-only)
///   LCR (offset 3) — Line Control Register
///   LSR (offset 5) — Line Status Register
const offsets = struct {
    const dll = 0;
    const ier = 1;
    const dlh = 1;
    const fcr = 2;
    const lcr = 3;
    const lsr = 5;
};

var g_port: Ports = .com1;

/// Initializes a 16550 UART: sets 8N1 line protocol, disables interrupts and FIFOs,
/// then programs the baud rate divisor via DLL/DLH with DLAB set.
/// TL16C550C datasheet, §8.4 "Line Control Register" — DLAB bit (bit 7) gates
/// access to the divisor latch registers at offsets 0 and 1.
pub fn init(port: Ports, baud: u32) void {
    // Serial init is unconditional: the kernel test harness captures
    // `[PASS] §X.Y.Z` messages off COM1 regardless of optimize mode, so
    // we cannot gate this on `.Debug`. The earlier gate existed because
    // production kernels want serial stripped, but that's a policy the
    // test/bench profiles override — see also `print` below.
    const p = @intFromEnum(port);
    cpu.outb(0b00_000_0_00, p + offsets.lcr);
    cpu.outb(0, p + offsets.ier);
    cpu.outb(0, p + offsets.fcr);

    const divisor = 115200 / baud;
    const c = cpu.inb(p + offsets.lcr);
    cpu.outb(c | 0b1000_0000, p + offsets.lcr);
    cpu.outb(@truncate(divisor & 0xFF), p + offsets.dll);
    cpu.outb(@truncate((divisor >> 8) & 0xFF), p + offsets.dlh);
    cpu.outb(c & 0b0111_1111, p + offsets.lcr);

    g_port = port;
}

var print_lock = sync.SpinLock{ .class = "serial.print_lock" };

pub fn printRaw(s: []const u8) void {
    for (s) |b| writeByte(b, g_port);
}

pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    // No optimize-mode gate: see `init` above. Test output and debug
    // panics both rely on this path in every build mode.
    var temp_buffer: [256]u8 = undefined;
    const s = std.fmt.bufPrint(
        temp_buffer[0..],
        format,
        args,
    ) catch @panic("Print would be truncated!");

    const irq = print_lock.lockIrqSave(@src());
    defer print_lock.unlockIrqRestore(irq);

    for (s) |b| {
        writeByte(b, g_port);
    }
}

/// Polls LSR bit 5 (Transmitter Holding Register Empty) before writing.
/// TL16C550C datasheet, §8.6 "Line Status Register" — bit 5 indicates THR is empty.
fn writeByte(
    byte: u8,
    port: Ports,
) void {
    while ((cpu.inb(@intFromEnum(port) + offsets.lsr) & 0b0010_0000) == 0) {}
    cpu.outb(byte, @intFromEnum(port));
}
