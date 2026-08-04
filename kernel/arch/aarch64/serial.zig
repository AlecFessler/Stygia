//! PL011 UART driver for AArch64 serial output.
//!
//! The PL011 is ARM's standard UART IP. It replaces x86's NS16550 (COM port).
//! Base address is discovered from ACPI SPCR (Serial Port Console Redirection)
//! table or DBG2 (Debug Port Table 2).
//!
//! Only the transmit path is implemented: poll UARTFR.TXFF, write UARTDR.
//! UEFI firmware initializes baud rate, line control, and FIFO settings
//! before handoff, so this driver skips hardware setup entirely.
//!
//! References:
//! - ARM DDI 0183G: PrimeCell UART (PL011) Technical Reference Manual
//! - ACPI 6.5, Section 5.2.32: SPCR

const std = @import("std");
const stygia = @import("stygia");

const sync = stygia.utils.sync;

/// PL011 register offsets from base address.
/// DDI0183G Section 3.2, Table 3-1.
const offsets = struct {
    /// Data Register — write byte to transmit FIFO.
    /// DDI0183G Section 3.3.1, Table 3-2.
    const uartdr = 0x000;

    /// Flag Register — contains TX/RX status flags.
    /// DDI0183G Section 3.3.3, Table 3-4.
    const uartfr = 0x018;
};

/// UARTFR bit masks.
/// DDI0183G Section 3.3.3, Table 3-4.
const fr_bits = struct {
    /// Bit 5: Transmit FIFO full. When set, the TX FIFO cannot accept more data.
    const txff: u32 = (1 << 5);

    /// Bit 3: UART busy. Set while a character is still being shifted out, or
    /// while the TX FIFO is non-empty. Clear means everything written has
    /// physically left the pin.
    const busy: u32 = (1 << 3);
};

/// MMIO base address of the PL011 UART, set at runtime from ACPI SPCR.
/// Null until `setBase` is called during early boot.
var base_addr: ?u64 = null;

var print_lock = sync.SpinLock{ .class = "serial.print_lock" };

/// Set the PL011 MMIO base address. Called by ACPI SPCR/DBG2 parsing
/// during early boot before any serial output is needed.
pub fn setBase(addr: u64) void {
    base_addr = addr;
}

/// Initialize the PL011 UART for transmit.
///
/// Intentionally a no-op for now: the PL011 MMIO page is not yet mapped
/// into the kernel's TTBR1 physmap range at this point in boot
/// (memory.init() has not run), so installing a physmap-based base
/// address here would cause the very next print to translation-fault
/// before parseAcpi() can install the real mapping. Leaving
/// `base_addr` null keeps `arch.earlyDebugChar` on the raw PA fallback
/// (which is reachable via UEFI's TTBR0 identity map at this stage),
/// and `parseSpcr`/`parseAcpi` will call `setBase` once the physmap
/// VA for the PL011 page is actually mapped. UEFI firmware configures
/// baud rate, line control, and enables the UART before handoff so
/// the raw-PA writes are sufficient until then.
pub fn init() void {}

/// Lockless raw-bytes write. Used by panic / lockdep paths that must
/// not recurse through `print_lock` (which is itself detector-instrumented).
/// Silently returns if the base address has not yet been set.
pub fn printRaw(s: []const u8) void {
    const base = base_addr orelse return;
    for (s) |b| writeByte(b, base);
}

/// Format and transmit a string over the PL011 UART.
/// Silently returns if the base address has not yet been set (early boot
/// before ACPI SPCR discovery).
pub fn print(comptime format: []const u8, args: anytype) void {
    const base = base_addr orelse return;

    // Once another core has claimed the panic gate, the machine is
    // dying and only the panic owner may write to the wire. Continuing
    // here interleaved this printer's output INTO the panic report at
    // UART-FIFO granularity — every multi-core corpse from the rig had
    // its first report line shredded by a concurrent [NOROUTE] print.
    // Halting a non-owner core that is merely trying to print is
    // strictly better than destroying the evidence.
    if (stygia.panic.claimedByOtherCore()) stygia.arch.aarch64.cpu.halt();

    var temp_buffer: [256]u8 = undefined;
    const s = std.fmt.bufPrint(
        temp_buffer[0..],
        format,
        args,
    ) catch @panic("Print would be truncated!");

    const irq = print_lock.lockIrqSave(@src());
    defer print_lock.unlockIrqRestore(irq);

    for (s) |b| {
        writeByte(b, base);
    }
}

/// Wait until everything written has physically left the pin.
///
/// `writeByte` only waits for the FIFO to be non-FULL, so up to a FIFO's worth of
/// characters (32 on a PL011) can still be queued when it returns. That is harmless
/// right up until something resets the machine: PSCI `SYSTEM_RESET` does not drain
/// the UART, so those bytes are simply lost.
///
/// Measured on the bare-metal Pi 5 rig, where the casualty was the single most
/// important line of the entire run — the runner's cross-run aggregate, cut off
/// mid-number as the reboot took effect:
///
///     [runner] === aggregate over 2 runs: 9
///
/// with `57 pass / 11 fail / 2 miss ===` never reaching the wire. Any verdict read
/// off a serial console has to survive the reset that immediately follows it, so
/// the power path drains before handing over to PSCI.
///
/// Bounded and `tx_dead`-aware for the same reasons as `writeByte`: a UART that
/// never reports idle must not convert a clean reboot into a hang.
pub fn flush() void {
    if (tx_dead) return;
    const base = base_addr orelse return;

    const fr_ptr: *volatile u32 = @ptrFromInt(base + offsets.uartfr);
    var spins: u32 = 0;
    while ((fr_ptr.* & fr_bits.busy) != 0) {
        spins += 1;
        if (spins > tx_spin_budget) return;
    }
}

/// Latched once the TX FIFO has failed to drain within `tx_spin_budget`.
///
/// Latched rather than checked per call so a UART that never drains costs one
/// budget in total instead of one per byte. A per-byte bound on a 4 KB log would
/// stall for minutes and still produce nothing.
var tx_dead: bool = false;

/// A 115200 8N1 character takes ~87 µs to shift out, and even a PCIe-attached
/// register read (~1 µs each) needs only ~100 iterations to cover that. A million
/// leaves four orders of magnitude of headroom for a slow emulated UART while still
/// bounding a dead one, so this cannot drop output on a working console.
const tx_spin_budget: u32 = 1_000_000;

/// Poll UARTFR.TXFF until the transmit FIFO has space, then write one
/// byte to UARTDR.
/// DDI0183G Section 3.3.3 (UARTFR) and Section 3.3.1 (UARTDR).
///
/// The poll is bounded, which matters on exactly one configuration: bare metal,
/// where `base_addr` comes from the loader rather than from firmware this kernel
/// has already been talking through. A window that reads all-ones has TXFF
/// permanently set, so an unbounded poll would never return from the *first*
/// `print` — the kernel would die before emitting one byte on either console, and
/// the symptom (total silence after the loader stops) is indistinguishable from a
/// hang anywhere else in early boot. Dropping characters is the strictly better
/// failure.
fn writeByte(byte: u8, base: u64) void {
    if (tx_dead) return;

    const fr_ptr: *volatile u32 = @ptrFromInt(base + offsets.uartfr);
    const dr_ptr: *volatile u32 = @ptrFromInt(base + offsets.uartdr);

    var spins: u32 = 0;
    while ((fr_ptr.* & fr_bits.txff) != 0) {
        spins += 1;
        if (spins > tx_spin_budget) {
            tx_dead = true;
            return;
        }
    }
    dr_ptr.* = byte;
}
