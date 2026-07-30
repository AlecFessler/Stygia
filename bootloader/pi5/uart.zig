//! PL011 probe and live console for the Pi 5 native loader.
//!
//! The DRAM early log is a POSTMORTEM channel: you see it only after the board
//! resets, and only if it resets. A real UART is a live one, and more importantly
//! it is the channel the kernel needs in order to hand a console to userspace. So
//! the loader's job here is twofold — get itself a live console if it can, and
//! establish which of the two candidate UARTs the kernel should actually target.
//!
//! There are two on this board and they are NOT interchangeable:
//!
//!   * SoC PL011 — `/soc/serial@7d001000`, `compatible = "arm,pl011"`, CPU
//!     physical **0x10_7D00_1000** (`reg` 0x7d001000 translated through /soc's
//!     `ranges = <0x7c000000 0x10 0x7c000000 0x4000000>`). Needs no PCIe, so it is
//!     available at the very first instruction. Its pins land on the Pi 5 JST-SH
//!     debug connector, which needs a pigtail that is not currently wired — so it
//!     is reachable but unobservable here.
//!
//!   * RP1 uart0 — `/axi/pcie@120000/rp1/serial@30000`,
//!     `compatible = "arm,pl011-axi"`, the DT `serial0` alias, and Linux's
//!     `ttyAMA0`. This is the GPIO 14/15 header, i.e. the cable that actually
//!     exists. Its `reg` is a PCI address (0xc0_40030000) translated twice: rp1's
//!     `ranges` puts it at PCI memory 0x30000, then pcie@120000's
//!     `ranges = <0x2000000 0 0  0x1f 0  0 0xfffffffc>` maps PCI memory 0x0 to CPU
//!     physical 0x1F_0000_0000. So: **0x1F_0003_0000**.
//!
//! Whether the RP1 one is usable at all depends on something this loader does not
//! control: firmware must have brought the PCIe link up and assigned BARs. It
//! plausibly has (USB boot is in BOOT_ORDER and RP1 owns the USB controllers), but
//! "plausibly" is not good enough to build a console on, hence `probe`.
//!
//! Neither UART's baud rate is programmed here, matching the kernel's own driver
//! (`arch/aarch64/serial.zig` is TX-poll only and relies on firmware init). A
//! nonzero IBRD/FBRD in the probe output is the evidence that firmware did it.

const std = @import("std");
const stygia = @import("stygia");

const log = @import("early_log.zig");
const mmu = @import("mmu.zig");

const address = stygia.memory.address;
const paging = stygia.memory.paging;

/// CPU-physical bases, both derived from the real DTB rather than documentation.
/// See the module comment for the translation chains.
pub const SOC_PL011_BASE: u64 = 0x10_7D00_1000;
pub const RP1_UART0_BASE: u64 = 0x1F_0003_0000;

// PL011 register offsets — ARM DDI 0183G.
const DR: u64 = 0x00;
const FR: u64 = 0x18;
const IBRD: u64 = 0x24;
const FBRD: u64 = 0x28;
const LCRH: u64 = 0x2C;
const CR: u64 = 0x30;
/// PrimeCell identification. PeriphID reads 0x11,0x10,0x14,0x00 and PCellID reads
/// 0x0D,0xF0,0x05,0xB1 ("0xB105F00D") on a genuine PL011.
const PERIPHID0: u64 = 0xFE0;
const PCELLID0: u64 = 0xFF0;

const FR_TXFF: u32 = 1 << 5;
const FR_BUSY: u32 = 1 << 3;

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;

/// A read that came back from nothing. See the signatures documented in `probe`.
fn isDead(v: u32) bool {
    return v == 0xFFFF_FFFF or v == 0xDEAD_DEAD;
}

fn rd(base: u64, off: u64) u32 {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(base + off)));
    return p.*;
}

fn wr(base: u64, off: u64, v: u32) void {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(base + off)));
    p.* = v;
}

/// What a probe concluded about a candidate UART.
pub const Probe = struct {
    base: u64,
    /// Every read returned all-ones, the classic signature of an address that
    /// nothing decodes (an unassigned BAR, or a downed PCIe link).
    floating: bool,
    /// PCellID matched 0xB105F00D — this is genuinely a PrimeCell.
    primecell: bool,
    /// UARTEN and TXE are set, i.e. somebody already enabled it.
    enabled: bool,
    /// Nonzero baud divisors, i.e. somebody already configured the line rate.
    baud_set: bool,
    cr: u32,
    fr: u32,
    ibrd: u32,
    fbrd: u32,

    pub fn usable(self: Probe) bool {
        // Deliberately does NOT require `primecell`: RP1's `reg` window is only
        // 0x100 bytes, so its ID registers at 0xFE0 may not be exposed even though
        // the core registers work. Requiring the ID match would reject a perfectly
        // good console.
        return !self.floating and self.enabled and self.baud_set;
    }
};

/// Map a candidate's register page as Device memory.
///
/// `.kernel_mmio` maps to MAIR index 0 (Device-nGnRnE), which is mandatory for
/// MMIO: a cacheable mapping would let writes sit in the D-cache and reorder,
/// turning a serial console into garbage. Both bases are far above RAM
/// (0x10_xxxx_xxxx and 0x1F_xxxx_xxxx), so this cannot collide with the identity
/// map's coarser RAM blocks — see mmu.mapRange's overlap guard for why that
/// matters.
pub fn map(alloc: std.mem.Allocator, ttbr0_root: u64, base: u64) !void {
    try mmu.mapMmio(alloc, ttbr0_root, base, paging.PAGE4K);
}

/// Read a candidate's registers and classify it. Reads only — never writes, so a
/// probe cannot disturb a UART that firmware is still using.
pub fn probe(base: u64) Probe {
    const cr = rd(base, CR);
    const fr = rd(base, FR);
    const ibrd = rd(base, IBRD);
    const fbrd = rd(base, FBRD);

    // Two distinct "nothing is there" signatures, both observed on this board:
    //
    //   0xFFFFFFFF — the generic floating-bus read.
    //   0xDEADDEAD — what BCM2712's PCIe returns for an access the root complex
    //                decodes but the downstream device never answers. Measured
    //                reading RP1 uart0 at 0x1F_0003_0000 before the link is up.
    //                Note this is NOT an abort: the bridge window IS live, so the
    //                read completes and returns data. Treating it as a real
    //                register value made the probe report `baud_set` on a device
    //                that does not exist.
    const dead = isDead(cr) and isDead(fr) and isDead(ibrd) and isDead(fbrd);

    var primecell = false;
    if (!dead) {
        const c0 = rd(base, PCELLID0 + 0) & 0xFF;
        const c1 = rd(base, PCELLID0 + 4) & 0xFF;
        const c2 = rd(base, PCELLID0 + 8) & 0xFF;
        const c3 = rd(base, PCELLID0 + 12) & 0xFF;
        primecell = c0 == 0x0D and c1 == 0xF0 and c2 == 0x05 and c3 == 0xB1;
    }

    return .{
        .base = base,
        .floating = dead,
        .primecell = primecell,
        .enabled = !dead and (cr & (CR_UARTEN | CR_TXE)) == (CR_UARTEN | CR_TXE),
        .baud_set = !dead and (ibrd != 0 or fbrd != 0),
        .cr = cr,
        .fr = fr,
        .ibrd = ibrd,
        .fbrd = fbrd,
    };
}

pub fn dumpProbe(name: []const u8, p: Probe) void {
    log.str("    ");
    log.str(name);
    log.str(" @ ");
    log.hex(p.base);
    if (p.floating) {
        log.str("  *** dead (all reads 0xFFFFFFFF or 0xDEADDEAD: nothing answers)\n");
        return;
    }
    log.str("\n      CR=");
    log.hex(p.cr);
    log.str(" FR=");
    log.hex(p.fr);
    log.str(" IBRD=");
    log.hex(p.ibrd);
    log.str(" FBRD=");
    log.hex(p.fbrd);
    log.byte('\n');
    log.str("      primecell=");
    log.dec(@intFromBool(p.primecell));
    log.str(" enabled=");
    log.dec(@intFromBool(p.enabled));
    log.str(" baud_set=");
    log.dec(@intFromBool(p.baud_set));
    log.str(" -> ");
    log.str(if (p.usable()) "USABLE\n" else "not usable\n");
}

/// Configure a PL011 for 115200 8N1.
///
/// Needed for RP1 uart0 and NOT for the SoC PL011: firmware initialises the latter
/// (it arrives with CR=0x301, IBRD=0x18) but has never touched the former, because
/// the PCIe link is down until this loader trains it.
///
/// Values are the ones Linux runs this exact UART at, read back from
/// `/dev/mem` on the booted system rather than derived: IBRD=27, FBRD=8,
/// LCRH=0x70 (8 bits, FIFOs enabled), CR=0xf01. They check out against the
/// measured 50 MHz `clk_uart`: 50e6/(16*115200) = 27.127, so IBRD 27 and
/// FBRD round(0.127*64) = 8.
pub fn configure(base: u64) void {
    // Disable before touching the divisors; changing them while enabled gives
    // undefined line behaviour.
    wr(base, CR, 0);
    // Let any in-flight character drain.
    var spins: u32 = 0;
    while ((rd(base, FR) & FR_BUSY) != 0 and spins < 100_000) : (spins += 1) {}

    wr(base, IBRD, 27);
    wr(base, FBRD, 8);
    // LCRH must be written after IBRD/FBRD: the divisor latch updates on the
    // LCRH write (ARM DDI 0183G §3.3.6).
    wr(base, LCRH, 0x70);
    wr(base, CR, 0x0F01);
}

/// The UART this loader is writing to, once one has been chosen. Zero means the
/// loader is still DRAM-log-only.
var console_base: u64 = 0;

pub fn setConsole(base: u64) void {
    console_base = base;
    // Everything the loader has logged so far is still sitting in the DRAM buffer.
    // Hand it to the wire and keep every later line coming live — this is what turns
    // a postmortem channel into an actual console, and without it only the handful
    // of explicit `puts` calls ever reach the cable.
    log.setMirror(&mirrorByte);
}

/// Latched once a mirrored write times out.
///
/// Without it, a UART that decodes but never drains costs the full `tryPutc` spin
/// budget for *every* byte of a multi-kilobyte log instead of once. That is the
/// difference between a moment's stall and minutes of one — and the mirror is first
/// installed during PCIe bring-up, before the watchdog is armed, so there is nothing
/// to rescue the board from the slow version.
var mirror_wedged: bool = false;

fn mirrorByte(c: u8) void {
    if (mirror_wedged) return;
    // The far end is a terminal, which wants CRLF.
    if (c == '\n' and !tryPutc('\r')) {
        mirror_wedged = true;
        return;
    }
    if (!tryPutc(c)) mirror_wedged = true;
}

pub fn haveConsole() bool {
    return console_base != 0;
}

/// CPU-physical base of the chosen console, or 0 if there is none.
///
/// Physical and not virtual even though `putc` dereferences it directly:
/// translation is identity under this loader's TTBR0 (`mmu.mapMmio` maps
/// VA == PA), so the two are the same number here. The kernel needs the
/// PHYSICAL one for `BootInfo.console_base`, since it will re-map the page
/// into its own physmap.
pub fn consoleBase() u64 {
    return console_base;
}

/// Write one character, reporting whether it actually reached the FIFO.
///
/// Bounded spin. An unbounded `while (TXFF)` on a UART that is decoding but not
/// actually draining would hang the board, and a hang here costs a physical
/// power cycle plus the DRAM log — strictly worse than dropping a character.
/// The bool exists so the log mirror can give up permanently rather than pay this
/// budget once per byte; see `mirrorByte`.
pub fn tryPutc(c: u8) bool {
    if (console_base == 0) return false;
    var spins: u32 = 0;
    while ((rd(console_base, FR) & FR_TXFF) != 0) {
        spins += 1;
        if (spins > 1_000_000) return false;
    }
    wr(console_base, DR, c);
    return true;
}

pub fn putc(c: u8) void {
    _ = tryPutc(c);
}

pub fn puts(s: []const u8) void {
    if (console_base == 0) return;
    for (s) |c| {
        // The far end is a terminal, which wants CRLF.
        if (c == '\n') putc('\r');
        putc(c);
    }
}

/// Wait for the FIFO to drain, so a reset immediately after a write does not
/// truncate it.
pub fn flush() void {
    if (console_base == 0) return;
    var spins: u32 = 0;
    while ((rd(console_base, FR) & FR_BUSY) != 0) {
        spins += 1;
        if (spins > 1_000_000) return;
    }
}
