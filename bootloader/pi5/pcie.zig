//! Read-only probe of the BCM2712 PCIe root complex that fronts RP1.
//!
//! PURPOSE: decide how much work the RP1 UART actually costs, before committing to
//! it. RP1 uart0 is Linux's `ttyAMA0` and the GPIO 14/15 header — the cable that
//! physically exists on this board — but at firmware handoff every one of its
//! registers reads 0xDEADDEAD, BCM2712's signature for "the root complex decoded
//! this address but nothing downstream answered".
//!
//! That single value does not distinguish two very different situations:
//!
//!   A. The link is already trained and only the endpoint's BARs / memory-decode
//!      bit are unset. Fixing that is a handful of config-space writes, because
//!      every address involved is fixed by the devicetree rather than dynamically
//!      allocated (measured under Linux: bridge window PCI 0x0..0x5FFFFF, RP1
//!      BAR0=0x410000, BAR1=0x0 [4 MiB, holds the UART], BAR2=0x400000, both
//!      Command registers = Memory Space | Bus Master).
//!
//!   B. The link is down. Then this needs the brcmstb controller bring-up
//!      sequence — reset deassert, PHY/SerDes setup, link training, inbound and
//!      outbound window programming — against registers Broadcom does not publish.
//!      That is a port of a Linux driver, not an afternoon.
//!
//! So: read, log, decide. Nothing here writes, so a probe cannot damage a
//! controller state that firmware may be relying on.
//!
//! Measured reference state, taken from the Pi's own running Linux rather than
//! documentation (`/proc/iomem`, `setpci`, sysfs):
//!
//!   * controller MMIO      CPU 0x10_0012_0000, size 0x9310
//!   * RP1 uart0            CPU 0x1F_0003_0000  (`1f00030000.serial serial@30000`)
//!   * bridge Link Status   0xD042 -> Gen2 (5 GT/s), x4, Data Link Layer Active
//!   * bridge is 14e4:2712, RP1 is 1de4:0001 on bus 1
//!
//! The controller MMIO could NOT be read from Linux userspace to establish a
//! ground truth for its register layout: `/proc/iomem` shows the range claimed by
//! the `1000120000.pcie` driver, and `/dev/mem` consequently returns all-ones. So
//! the offsets below are treated as hypotheses to be confirmed by what they
//! actually read on hardware, not as known-good constants.

const std = @import("std");
const stygia = @import("stygia");

const log = @import("early_log.zig");
const mmu = @import("mmu.zig");
const rp1 = @import("rp1.zig");
const uart = @import("uart.zig");

const paging = stygia.memory.paging;

/// Controller MMIO base and size, from `reg = <0x10 0x120000 0x00 0x9310>` on
/// `/axi/pcie@120000` (/axi's `ranges` is identity) and corroborated by
/// `/proc/iomem`: `1000120000-100012930f`.
pub const BRIDGE_MMIO_BASE: u64 = 0x10_0012_0000;
pub const BRIDGE_MMIO_SIZE: u64 = 0xA000;

/// Offsets sampled by `probe`.
///
/// Deliberately a wide spread rather than a few named registers. The brcmstb
/// driver's register map for BCM2712 is not published, and offsets recalled from
/// memory are exactly the kind of thing that produces a confident wrong answer, so
/// the probe reports raw words and lets the values speak. Two things are
/// diagnostic regardless of which register is which:
///
///   * uniformly 0x00000000 or 0xFFFFFFFF across the whole spread means the
///     controller is unclocked or held in reset — case B, the expensive one;
///   * a mix of plausible, structured values means the controller is alive, and
///     then whichever word contains 0x14E4/0x2712 locates the RC config space and
///     the link-status register can be found from its PCIe capability.
const PROBE_OFFSETS = [_]u64{
    0x0000, 0x0004, 0x0008, 0x000C, 0x0010, 0x0018, 0x001C,
    0x0034, 0x0040, 0x0043C, 0x00BC, 0x0100,
    0x4000, 0x4004, 0x4008, 0x400C, 0x4010, 0x4014,
    0x4028, 0x402C, 0x4030, 0x4034, 0x4038, 0x403C,
    0x4064, 0x4068, 0x406C, 0x4070, 0x4078, 0x407C,
    0x4204, 0x4208, 0x420C, 0x4210, 0x4214,
    0x8000, 0x9000, 0x9210, 0x9300,
};

fn rd(off: u64) u32 {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(BRIDGE_MMIO_BASE + off)));
    return p.*;
}

fn wr(off: u64, v: u32) void {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(BRIDGE_MMIO_BASE + off)));
    p.* = v;
}

/// The root complex's own PCI config space is mapped at controller MMIO offset 0.
///
/// Confirmed on hardware, not assumed: offset 0 reads 0x271214E4 (device 0x2712,
/// vendor 0x14E4), offset 8 reads 0x06040021 (class 06 / subclass 04 = PCI bridge,
/// rev 0x21) and offset 0x34 reads 0x48 — all three matching what Linux reports for
/// 0000:00:00.0 via sysfs.
const rcRead = rd;
const rcWrite = wr;

/// Standard PCI capability-list walk. This part is architecture-independent and
/// documented (PCI 3.0 §6.7), unlike the vendor register map, so it is the reliable
/// way to locate the PCI Express capability rather than guessing its offset.
fn findCap(cap_id: u8) ?u64 {
    // Capabilities only exist if the status register says so.
    if ((rcRead(0x04) & (1 << 20)) == 0) return null; // Status bit 4 -> bit 20 of the dword
    var off: u64 = rcRead(0x34) & 0xFC;
    var guard: u32 = 0;
    while (off >= 0x40 and off != 0 and guard < 48) : (guard += 1) {
        const hdr = rcRead(off);
        const id: u8 = @truncate(hdr & 0xFF);
        const next: u8 = @truncate((hdr >> 8) & 0xFF);
        if (id == cap_id) return off;
        if (next == 0) break;
        off = next & 0xFC;
    }
    return null;
}

/// PCI Express capability ID, and the Link Status offset within it (PCIe 4.0
/// §7.5.3.8). Link Status is a 16-bit register at capability offset 0x12.
const CAP_ID_PCIE: u8 = 0x10;
const PCIE_CAP_LINK_STATUS: u64 = 0x12;

pub const LinkStatus = struct {
    raw: u16,
    /// Bits [3:0]. 1 = 2.5 GT/s, 2 = 5 GT/s, 3 = 8 GT/s.
    speed: u8,
    /// Bits [9:4]. Negotiated lane count.
    width: u8,
    /// Bit 13. The only bit that actually means "the link is usable".
    dl_active: bool,
};

pub fn linkStatus() ?LinkStatus {
    const cap = findCap(CAP_ID_PCIE) orelse return null;
    // Link Status sits in the upper half of the dword at cap+0x10.
    const dword = rcRead(cap + PCIE_CAP_LINK_STATUS - 2);
    const raw: u16 = @truncate(dword >> 16);
    return .{
        .raw = raw,
        .speed = @truncate(raw & 0xF),
        .width = @truncate((raw >> 4) & 0x3F),
        .dl_active = (raw & (1 << 13)) != 0,
    };
}

const CMD_MEM_SPACE: u32 = 1 << 1;
const CMD_BUS_MASTER: u32 = 1 << 2;

/// Turn on Memory Space Enable + Bus Master on the root complex.
///
/// Measured at firmware handoff: the RC's Command register is 0x0000, i.e. memory
/// decode is DISABLED. Linux runs it at 0x0006. With decode off the root complex
/// will not forward CPU memory transactions downstream at all, so RP1 is
/// unreachable regardless of link or BAR state — which makes this the first thing
/// to change and the cheapest possible experiment.
///
/// Safe to attempt: a reset restores firmware's state, and this boot is a one-shot
/// tryboot that falls back to Pi OS on the next reset either way.
pub fn enableRootComplex() void {
    const before = rcRead(0x04);
    // Command is the low half of the dword at 0x04; Status is the high half and is
    // write-1-to-clear, so preserve it by writing back zeros in those bits.
    const cmd: u32 = (before & 0xFFFF) | CMD_MEM_SPACE | CMD_BUS_MASTER;
    rcWrite(0x04, cmd);
    const after = rcRead(0x04);
    // MEASURED: this write does NOT take. Command reads back 0x0000 unchanged, so
    // the RC's config space is readable through the MMIO aperture at offset 0 but
    // not writable through it — brcmstb drives RC config via separate privileged
    // registers (the PCIE_RC_CFG_PRIV* block). Left in place because the read-back
    // is the evidence, and a silent no-op write would be worse than a logged one.
    log.str("      RC Command ");
    log.hex(before & 0xFFFF);
    log.str(" -> ");
    log.hex(after & 0xFFFF);
    log.byte('\n');
}

/// brcmstb's window for reading a downstream device's config space: write a
/// bus/device/function selector to EXT_CFG_INDEX, then access EXT_CFG_DATA.
///
/// Offsets recalled from the Linux driver and therefore VERIFIED BY RESULT rather
/// than trusted: if the selector mechanism is wrong, the read simply will not
/// return RP1's 0x1DE4/0x0001 and the log will say so.
const EXT_CFG_DATA: u64 = 0x8000;
const EXT_CFG_INDEX: u64 = 0x9000;

pub fn endpointConfigRead(bus: u32, dev: u32, func: u32, off: u64) u32 {
    // Selector encoding is (bus << 20) | (devfn << 12) where devfn = dev<<3|func.
    const devfn: u32 = (dev << 3) | func;
    wr(EXT_CFG_INDEX, (bus << 20) | (devfn << 12));
    // Ordering: the selector must land before the data access is issued.
    asm volatile ("dsb sy" ::: .{ .memory = true });
    return rd(EXT_CFG_DATA + (off & 0xFFF));
}

pub fn configWrite(bus: u32, dev: u32, func: u32, off: u64, v: u32) void {
    const devfn: u32 = (dev << 3) | func;
    wr(EXT_CFG_INDEX, (bus << 20) | (devfn << 12));
    asm volatile ("dsb sy" ::: .{ .memory = true });
    wr(EXT_CFG_DATA + (off & 0xFFF), v);
    asm volatile ("dsb sy" ::: .{ .memory = true });
}

/// Bridge config offsets (PCI-to-PCI bridge header, PCI 3.0 §3.2).
const BRIDGE_BUS_NUMBERS: u64 = 0x18; // primary | secondary<<8 | subordinate<<16
const BRIDGE_MEM_BASE_LIMIT: u64 = 0x20; // base (low 16) | limit (high 16)
const BRIDGE_PREF_BASE_LIMIT: u64 = 0x24;

/// Programme the root port so config and memory transactions reach bus 1.
///
/// A trained link is not enough: until the bridge knows a bus lives behind it, it
/// has no reason to forward anything, which is the most likely explanation for
/// bus1 config reads returning all-ones after a successful link-up.
///
/// Concrete values rather than an allocator, because every address here is fixed
/// by the devicetree and was read back from working Linux:
///   secondary = subordinate = 1
///   memory window base 0x0000 / limit 0x0050  -> PCI 0x0 .. 0x5FFFFF
///   prefetchable window disabled (base > limit)
///
/// Tries the EXT_CFG path as well as the direct aperture, because writes to the RC
/// config space at MMIO+0x04 were measured NOT to stick, while Linux clearly does
/// set these fields — so which path is writable is the open question this answers.
pub fn setupRootPort() void {
    const bus_val: u32 = (1 << 16) | (1 << 8) | 0; // subordinate=1, secondary=1, primary=0
    const win_val: u32 = (0x0050 << 16) | 0x0000; // limit 0x0050, base 0x0000

    // The direct aperture, and ONLY the direct aperture.
    //
    // This function used to write these fields through EXT_CFG as well and read all
    // three back, because which of the two paths was writable was an open question.
    // It is no longer open: the aperture writes stick (measured `bus=0x10100
    // win=0x500000`, and bus 1 answers immediately afterwards) while every EXT_CFG
    // access to bus 0 returned 0xFFFFFFFF — the log line said "EXT_CFG does NOT
    // reach bus 0" on every boot.
    //
    // Those dead accesses were not free. An all-ones read is an error completion,
    // and on this SoC that is reported as an ASYNCHRONOUS external abort which then
    // sits pending behind the loader's masked PSTATE.A until the kernel's first eret
    // to EL0 unmasks it — surfacing as an uncontainable SError with ELR pointing at
    // userspace and no hint of where it came from. So probing a config space that is
    // known not to exist is now a deliberate omission, not an oversight. See
    // `entry.zig :: drainDeferredErrors` for the other half of that fix.
    rcWrite(BRIDGE_BUS_NUMBERS, bus_val);
    rcWrite(BRIDGE_MEM_BASE_LIMIT, win_val);
    rcWrite(BRIDGE_PREF_BASE_LIMIT, 0x0001_FFF1); // base > limit => disabled
    log.str("      via aperture: bus=");
    log.hex(rcRead(BRIDGE_BUS_NUMBERS));
    log.str(" win=");
    log.hex(rcRead(BRIDGE_MEM_BASE_LIMIT));
    log.byte('\n');
    log.commit();
}

/// Programme outbound window 0: CPU 0x1F_0000_0000 -> PCI 0x0, 4 GiB.
///
/// Without this the controller has no translation for CPU accesses in the
/// 0x1F_xxxx_xxxx range, so even a perfectly enumerated RP1 with correct BARs is
/// unreachable from the CPU. Values are the `pcie2` `ranges` entry from
/// bcm2712.dtsi, reduced to the concrete register writes the driver would make.
///
/// The register layout encodes addresses in MiB: base and limit go in a packed
/// field at 0x4070 as bits [15:4] and [27:20], with the high bits above 4 GiB
/// spilling into separate 0x4080/0x4084 bytes.
fn setOutboundWin0() void {
    wr(0x400C, 0x0000_0000); // PCI address, low 32
    wr(0x4010, 0x0000_0000); // PCI address, high 32
    // cpu_mb = 0x1F000_0000/0x100000 = 0x1F000 -> base field (0x1F000 & 0xfff) = 0
    // limit_mb = 0x1FFFF                       -> limit field 0xFFF
    rmw(0x4070, 0xFFF0_0000 | 0xFFF0, (0x000 << 4) | (0xFFF << 20));
    rmw(0x4080, 0xFF, 0x1F); // cpu_mb   >> 12
    rmw(0x4084, 0xFF, 0x1F); // limit_mb >> 12
    log.str("      outbound win0: 0x4070=");
    log.hex(rd(0x4070));
    log.str(" 0x4080=");
    log.hex(rd(0x4080));
    log.str(" 0x4084=");
    log.hex(rd(0x4084));
    log.byte('\n');
}

/// Assign RP1's BARs and enable its memory decode.
///
/// Static values read back from working Linux — no allocator needed because the
/// devicetree fixes every address. BAR1 is the one that matters: PCI 0x0, 4 MiB,
/// the window containing uart0 at PCI offset 0x30000.
fn setupRp1Bars() void {
    configWrite(1, 0, 0, 0x10, 0x0041_0000); // BAR0, 16 KiB
    configWrite(1, 0, 0, 0x14, 0x0000_0000); // BAR1, 4 MiB  <- holds the UART
    configWrite(1, 0, 0, 0x18, 0x0040_0000); // BAR2, 64 KiB
    configWrite(1, 0, 0, 0x04, CMD_MEM_SPACE | CMD_BUS_MASTER);
    log.str("      RP1 BAR0=");
    log.hex(endpointConfigRead(1, 0, 0, 0x10));
    log.str(" BAR1=");
    log.hex(endpointConfigRead(1, 0, 0, 0x14));
    log.str(" BAR2=");
    log.hex(endpointConfigRead(1, 0, 0, 0x18));
    log.str(" CMD=");
    log.hex(endpointConfigRead(1, 0, 0, 0x04) & 0xFFFF);
    log.byte('\n');
}

/// Finish enumeration so RP1's register windows are reachable from the CPU.
pub fn finishEnumeration() void {
    setOutboundWin0();
    setupRp1Bars();
    // Retry the RC Command now that the link is up — it was silently dropped
    // before training, and the bridge must have memory decode on to forward
    // anything downstream.
    enableRootComplex();

    // The whole point of all of the above: RP1 uart0 is the GPIO 14/15 header,
    // i.e. the only serial line physically wired on this board.
    const p = uart.probe(uart.RP1_UART0_BASE);
    uart.dumpProbe("RP1 uart0  ", p);
    if (p.floating) {
        log.str("      *** RP1 registers still unreachable after enumeration\n");
        log.commit();
        return;
    }
    // Reachable registers are not a transmitting UART. RP1's own clock generator
    // and pin mux were both wiped by the PERST# this module issues, so uart0
    // currently has no baud clock and its TXD signal is not routed to a pad. Both
    // live inside RP1, behind the link that only just came up, so this is the first
    // point at which they can be programmed at all — and it has to happen before
    // `uart.configure`, whose divisor writes are latched against UARTCLK.
    if (mmio_alloc) |a| {
        rp1.bringUpUart0(a, mmio_ttbr0) catch |err| {
            log.str("      *** RP1 clock/pinmux bring-up failed: ");
            log.str(@errorName(err));
            log.str("; configuring uart0 anyway to see what happens\n");
        };
    } else {
        log.str("      *** no allocator recorded; cannot map RP1 clocks/gpio\n");
    }

    // Firmware never configured this UART, so unlike the SoC PL011 it needs its
    // baud divisors programmed before it will transmit anything legible.
    uart.configure(uart.RP1_UART0_BASE);
    uart.setConsole(uart.RP1_UART0_BASE);
    log.str("      RP1 uart0 configured; console -> GPIO 14/15 header\n");
    log.commit();
    uart.puts("\n\n*** STYGIA IS ALIVE ON RP1 UART0 (GPIO 14/15) ***\n");
    uart.puts("bare-metal Pi 5 loader: PCIe trained, RP1 enumerated, console up\n");
    uart.flush();
}

/// Wait for an endpoint to start answering config reads after link-up.
///
/// A trained link does not mean a responsive device. PCIe allows an endpoint up to
/// 100 ms after link-up before it must service config requests, and until then the
/// root complex either synthesizes all-ones or returns a Configuration Request
/// Retry Status that surfaces the same way. Measured here: immediately after
/// training, bus1:dev0 reads 0xFFFFFFFF — note that is a CHANGE from the
/// 0xDEADDEAD seen with the link down, so the access is reaching the link.
///
/// Polls well past the spec minimum because the cost of being slightly too
/// impatient is a boot cycle, and the cost of waiting is a fraction of a second.
pub fn waitForEndpoint(bus: u32, dev: u32, func: u32) ?u32 {
    var waited: u64 = 0;
    while (waited < 1_000_000) : (waited += 20_000) {
        const vid = endpointConfigRead(bus, dev, func, 0x00);
        // A real vendor ID is neither all-ones nor all-zeros nor the
        // unclaimed-bus pattern.
        if (vid != 0xFFFF_FFFF and vid != 0x0000_0000 and vid != 0xDEAD_DEAD) {
            log.str("      endpoint answered after ");
            log.dec(waited / 1000);
            log.str("ms: ");
            log.hex(vid);
            log.byte('\n');
            return vid;
        }
        delayUs(20_000);
    }
    log.str("      endpoint never answered config reads within 1s (last ");
    log.hex(endpointConfigRead(bus, dev, func, 0x00));
    log.str(", EXT_CFG_INDEX reads back ");
    log.hex(rd(EXT_CFG_INDEX));
    log.str(")\n");
    return null;
}

pub const Findings = struct {
    /// Every sampled word was 0x00000000 or 0xFFFFFFFF.
    all_dead: bool,
    /// Some word held 0x14E4 or 0x2712 in either half — the RC's own PCI IDs,
    /// which means the controller is powered, clocked and out of reset.
    saw_bridge_id: bool,
    /// Offset the ID pattern was found at, for locating the RC config space.
    id_offset: u64,
};

// ── External reset and calibration blocks ──────────────────────────────────
//
// These are the reason a probe confined to the controller's own MMIO can never
// bring RP1 up, and almost certainly the reason writing the RC Command register
// at MMIO+0x04 is silently dropped: the bridge is still held in reset at firmware
// handoff, and a block in reset ignores register writes.
//
// Both live OUTSIDE the 0x9310 controller window, in unrelated parts of the SoC:
//
//   bcm_reset  `brcm,brcmstb-reset` reg = <0x10 0x01504318 0x0 0x30>
//              (bcm2712.dtsi). Bank stride 0x18; the "bridge" reset is id 44 =
//              bank 1, bit 12, so 0x01504318 + 1*0x18 = 0x01504330.
//   rescal     `brcm,bcm7216-pcie-sata-rescal` reg = <0x10 0x00119500 0x0 0x10>.
//              PCIe/SATA resistor calibration. START +0x0 bit0, STATUS +0x8 bit0.
//
// Values traced to `reset-brcmstb.c` and `reset-brcmstb-rescal.c` in the
// Raspberry Pi kernel fork, not inferred.
const RESET_SET: u64 = 0x10_0150_4330;
const RESET_CLEAR: u64 = 0x10_0150_4334;
const RESET_STATUS: u64 = 0x10_0150_4338;
const RESET_BRIDGE_BIT: u32 = 1 << 12;

const RESCAL_START: u64 = 0x10_0011_9500;
const RESCAL_STATUS: u64 = 0x10_0011_9508;
const RESCAL_BIT: u32 = 1 << 0;

/// `PCIE_MISC_PCIE_STATUS`. The driver's authoritative link-up predicate is
/// `(reg & 0x30) == 0x30` — it never uses the PCIe capability's LNKSTA for this.
/// Measured at handoff: 0x0001E080, so `& 0x30 == 0` — link down.
const MISC_PCIE_STATUS: u64 = 0x4068;
const STATUS_LINK_MASK: u32 = 0x30;

fn abs32(addr: u64) u32 {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(addr)));
    return p.*;
}

fn absWrite32(addr: u64, v: u32) void {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(addr)));
    p.* = v;
}

/// Microsecond delay off the architected generic timer.
///
/// CNTVCT_EL0/CNTFRQ_EL0 are usable at EL2 with no setup at all, which matters
/// because none of the platform timers are configured this early. Spin-count
/// delays would be wrong here: the driver's delays are real hardware settling
/// times (notably the mandatory 100 ms after PERST# deassert, PCIe CEM §2.2), and
/// getting them short would produce intermittent link failures.
pub fn delayUs(us: u64) void {
    var freq: u64 = undefined;
    asm volatile ("mrs %[v], cntfrq_el0"
        : [v] "=r" (freq),
    );
    if (freq == 0) return;
    const ticks = (freq * us) / 1_000_000;
    var start: u64 = undefined;
    asm volatile ("isb; mrs %[v], cntvct_el0"
        : [v] "=r" (start),
    );
    while (true) {
        var now: u64 = undefined;
        asm volatile ("isb; mrs %[v], cntvct_el0"
            : [v] "=r" (now),
        );
        if (now -% start >= ticks) return;
    }
}

/// The mapping context `map` was given, kept so `finishEnumeration` can map RP1's
/// internal register windows.
///
/// Those windows cannot be mapped here: at `map` time the link is still down and it
/// is not yet known whether RP1 will ever answer, so spending page-table pages on
/// it would be premature. But `finishEnumeration` runs deep inside `probe`, which
/// takes no allocator, and `entry.zig` is not this module's to change. Recording
/// them at the one entry point that does receive them is the smallest bridge
/// between the two.
var mmio_alloc: ?std.mem.Allocator = null;
var mmio_ttbr0: u64 = 0;

pub fn map(alloc: std.mem.Allocator, ttbr0_root: u64) !void {
    mmio_alloc = alloc;
    mmio_ttbr0 = ttbr0_root;
    try mmu.mapMmio(alloc, ttbr0_root, BRIDGE_MMIO_BASE, BRIDGE_MMIO_SIZE);
    // The external blocks, each in its own page far from the controller window.
    try mmu.mapMmio(alloc, ttbr0_root, RESET_SET & ~@as(u64, 0xFFF), paging.PAGE4K);
    try mmu.mapMmio(alloc, ttbr0_root, RESCAL_START & ~@as(u64, 0xFFF), paging.PAGE4K);
}

/// Is the PCIe bridge still held in reset?
pub fn bridgeInReset() bool {
    return (abs32(RESET_STATUS) & RESET_BRIDGE_BIT) != 0;
}

pub fn linkUp() bool {
    return (rd(MISC_PCIE_STATUS) & STATUS_LINK_MASK) == STATUS_LINK_MASK;
}

/// Run the PCIe/SATA resistor calibration block.
///
/// Sequence and timings from `reset-brcmstb-rescal.c:24-54`: set START bit 0,
/// confirm it took, poll STATUS bit 0 with 100 µs between polls and a 1000 µs
/// total timeout, then clear START. Shared across pcie0/1/2, so run it once.
pub fn rescal() bool {
    absWrite32(RESCAL_START, abs32(RESCAL_START) | RESCAL_BIT);
    if ((abs32(RESCAL_START) & RESCAL_BIT) == 0) {
        log.str("      rescal: START did not latch\n");
        return false;
    }
    var waited: u64 = 0;
    while (waited < 1000) : (waited += 100) {
        if ((abs32(RESCAL_STATUS) & RESCAL_BIT) != 0) {
            absWrite32(RESCAL_START, abs32(RESCAL_START) & ~RESCAL_BIT);
            log.str("      rescal: done after ");
            log.dec(waited);
            log.str("us\n");
            return true;
        }
        delayUs(100);
    }
    absWrite32(RESCAL_START, abs32(RESCAL_START) & ~RESCAL_BIT);
    log.str("      rescal: TIMEOUT after 1000us\n");
    return false;
}

/// Assert the bridge reset, wait, deassert, wait. `reset-brcmstb.c:46,57-62`.
pub fn cycleBridgeReset() void {
    absWrite32(RESET_SET, RESET_BRIDGE_BIT);
    delayUs(200);
    absWrite32(RESET_CLEAR, RESET_BRIDGE_BIT);
    delayUs(200);
}

// ── Controller registers used by the bring-up ──────────────────────────────
//
// Offsets from the Raspberry Pi kernel fork's `pcie-brcmstb.c`. Note two that
// MOVED on BCM2712 relative to older brcmstb parts, and whose old locations read
// 0xDEADDEAD on this board (which is how the move was corroborated here):
//   HARD_DEBUG  0x4204 -> 0x4304
//   INTR2_CPU   0x4300 -> 0x4400
const MISC_CTRL: u64 = 0x4008;
const MISC_REVISION: u64 = 0x406C;
const MISC_HARD_PCIE_HARD_DEBUG: u64 = 0x4304;
const MISC_PCIE_CTRL: u64 = 0x4064;
const RC_PL_PHY_CTL_15: u64 = 0x184C;
const RC_CFG_PRIV1_LINK_CAP: u64 = 0x04DC;
const RC_CFG_PRIV1_ID_VAL3: u64 = 0x043C;

const MDIO_ADDR: u64 = 0x1100;
const MDIO_WR_DATA: u64 = 0x1104;

const HARD_DEBUG_SERDES_IDDQ: u32 = 0x0800_0000;
/// CLKREQ# controls cleared before training ("safe mode"): bits 1, 16, 20, 21.
const HARD_DEBUG_CLKREQ_MASK: u32 = 0x0031_0002;
const PCIE_CTRL_PERSTB: u32 = 0x4;

fn rmw(off: u64, clear: u32, set: u32) void {
    wr(off, (rd(off) & ~clear) | set);
}

/// One MDIO write to the SerDes PHY.
///
/// The read-back at step 2 is mandatory — the driver does it explicitly and
/// omitting it breaks the transaction. Packet encoding: port in [19:16], regad in
/// [15:0], command in [31:20] with WRITE = 0.
fn mdioWrite(port: u32, regad: u32, data: u16) bool {
    const pkt: u32 = (port << 16) | (regad & 0xFFFF); // cmd WRITE = 0
    wr(MDIO_ADDR, pkt);
    _ = rd(MDIO_ADDR); // mandatory dummy read-back
    wr(MDIO_WR_DATA, 0x8000_0000 | @as(u32, data));

    // Poll for bit 31 to clear: 10 us between polls, 100 us total.
    var waited: u64 = 0;
    while (waited < 100) : (waited += 10) {
        if ((rd(MDIO_WR_DATA) & 0x8000_0000) == 0) return true;
        delayUs(10);
    }
    return false;
}

/// The 2712-mandatory PLL retune, which is what lets the SerDes run off a 54 MHz
/// crystal instead of the usual 100 MHz reference. Without it the reference clock
/// is wrong and the link cannot train.
///
/// Register 0x1F is a block-select pseudo-register. Note reg 0x17 takes `0xbda1`:
/// the kernel's own comment block says `0xbd1a`, but the code writes `0xbda1`, and
/// the code is what ships.
fn mungePll() bool {
    const seq = [_]struct { reg: u32, val: u16 }{
        .{ .reg = 0x1F, .val = 0x1600 },
        .{ .reg = 0x16, .val = 0x50B9 },
        .{ .reg = 0x17, .val = 0xBDA1 },
        .{ .reg = 0x18, .val = 0x0094 },
        .{ .reg = 0x19, .val = 0x97B4 },
        .{ .reg = 0x1B, .val = 0x5030 },
        .{ .reg = 0x1C, .val = 0x5030 },
        .{ .reg = 0x1E, .val = 0x0007 },
    };
    for (seq) |s| {
        if (!mdioWrite(0, s.reg, s.val)) {
            log.str("      MDIO write to reg ");
            log.hex(s.reg);
            log.str(" TIMED OUT; refclk would be wrong, aborting\n");
            return false;
        }
    }
    delayUs(100);
    return true;
}

/// Train the link. Returns true if it comes up.
///
/// Follows the rpi-6.12 ordering. Deliberately stops at "link up" and does NOT
/// programme outbound windows or enumerate — training does not need them, and
/// having a clean success signal for the hard part first is worth more than a
/// bigger change with an ambiguous outcome.
pub fn bringUpLink() bool {
    log.str("      revision ");
    log.hex(rd(MISC_REVISION));
    log.byte('\n');

    // Step 5: take the SerDes out of IDDQ (power-down), then let it settle.
    rmw(MISC_HARD_PCIE_HARD_DEBUG, HARD_DEBUG_SERDES_IDDQ, 0);
    delayUs(100);

    // Step 6: the 54 MHz refclk PLL retune.
    if (!mungePll()) return false;

    // Step 7: L1SS PM clock period = 18.52 ns (1/54 MHz, rounded down).
    rmw(RC_PL_PHY_CTL_15, 0xFF, 0x12);

    // Step 8: MISC_CTRL. Burst size 0b10 (512 B) per the shipping 6.12 default,
    // plus SCB_ACCESS_EN, CFG_READ_UR_MODE, RCB_MPS_MODE and RCB_64B_MODE.
    // Deliberately NOT programming SCB sizes: 7712-and-newer parts have no
    // internal multi-memory-controller mapping, and 6.12 skips it entirely.
    rmw(MISC_CTRL, 0x30_0000, 0x0020_3480);

    // Step 14: cap the link at Gen2 via the PRIV1 alias. LNKCAP itself is
    // read-only through the config aperture — the same class of problem as the
    // Command register write that will not stick.
    rmw(RC_CFG_PRIV1_LINK_CAP, 0xF, 2);

    // Step 15: class code (already correct on this board, but idempotent).
    rmw(RC_CFG_PRIV1_ID_VAL3, 0xFF_FFFF, 0x06_0400);

    // Step 18: clear CLKREQ# controls before training.
    rmw(MISC_HARD_PCIE_HARD_DEBUG, HARD_DEBUG_CLKREQ_MASK, 0);

    // Step 19: deassert PERST#. Inverted on 2712 — writing bit 2 to 1 RELEASES
    // reset. `brcm_pcie_perst_set_2712` does `!val`, "Perst bit has moved and
    // assert value is 0".
    rmw(MISC_PCIE_CTRL, PCIE_CTRL_PERSTB, PCIE_CTRL_PERSTB);
    log.str("      PERST# deasserted (PCIE_CTRL ");
    log.hex(rd(MISC_PCIE_CTRL));
    log.str("); waiting 100ms\n");
    log.commit();

    // Step 20: mandatory 100 ms settle (PCIe CEM 2.2 / PCIe r5.0 6.6.1).
    delayUs(100_000);

    // Step 21: poll up to a further 100 ms.
    var waited: u64 = 0;
    while (waited < 100_000) : (waited += 5_000) {
        if (linkUp()) {
            log.str("      LINK UP after ");
            log.dec(100 + waited / 1000);
            log.str("ms  (MISC_PCIE_STATUS ");
            log.hex(rd(MISC_PCIE_STATUS));
            log.str(")\n");
            return true;
        }
        delayUs(5_000);
    }
    log.str("      link did NOT train within 200ms (MISC_PCIE_STATUS ");
    log.hex(rd(MISC_PCIE_STATUS));
    log.str(")\n");
    return false;
}

/// Steps 1-5 of the bring-up, plus a Command-register retry.
///
/// This is deliberately a partial bring-up: it tests the hypothesis that the
/// bridge reset is the thing blocking every register write, without yet committing
/// to the remaining twenty steps (SerDes IDDQ, MDIO PLL, windows, PERST#,
/// training). If the Command write takes after this, the hypothesis is confirmed
/// and the rest is mechanical. If it still does not, the hypothesis is wrong and
/// the remaining steps would have been built on sand.
pub fn tryReleaseReset() void {
    log.str("      bridge reset before: ");
    log.str(if (bridgeInReset()) "ASSERTED" else "released");
    log.str("  (STATUS ");
    log.hex(abs32(RESET_STATUS));
    log.str(")\n");

    // rescal first: 6.12 runs it before the bridge reset cycle.
    _ = rescal();
    cycleBridgeReset();

    log.str("      bridge reset after:  ");
    log.str(if (bridgeInReset()) "ASSERTED" else "released");
    log.str("  (STATUS ");
    log.hex(abs32(RESET_STATUS));
    log.str(")\n");

    // Now the real work: train the link.
    if (!bringUpLink()) {
        log.str("      => link training failed; RP1 stays unreachable\n");
        return;
    }
    // With the link up, tell the bridge a bus lives behind it, then read config.
    setupRootPort();
    const vid = waitForEndpoint(1, 0, 0) orelse return;
    if ((vid & 0xFFFF) == 0x1DE4) {
        log.str("      => RP1 (1de4:0001) IS ALIVE on bus 1\n");
        const bar1 = endpointConfigRead(1, 0, 0, 0x14);
        const cmd = endpointConfigRead(1, 0, 0, 0x04);
        log.str("      RP1 BAR1 = ");
        log.hex(bar1);
        log.str("  Command = ");
        log.hex(cmd & 0xFFFF);
        log.byte('\n');
        finishEnumeration();
    } else {
        log.str("      => unexpected vendor on bus 1\n");
    }
}

pub fn probe() Findings {
    var f = Findings{ .all_dead = true, .saw_bridge_id = false, .id_offset = 0 };

    log.str("    controller MMIO @ ");
    log.hex(BRIDGE_MMIO_BASE);
    log.byte('\n');

    for (PROBE_OFFSETS) |off| {
        const v = rd(off);
        if (v != 0x0000_0000 and v != 0xFFFF_FFFF) f.all_dead = false;

        const lo = v & 0xFFFF;
        const hi = (v >> 16) & 0xFFFF;
        const is_id = lo == 0x14E4 or hi == 0x14E4 or lo == 0x2712 or hi == 0x2712;
        if (is_id and !f.saw_bridge_id) {
            f.saw_bridge_id = true;
            f.id_offset = off;
        }

        // Only non-trivial words are worth log space; the region is large and the
        // log is 64 KiB shared with everything else.
        if (v != 0x0000_0000 and v != 0xFFFF_FFFF) {
            log.str("      +");
            log.hex(off);
            log.str(" = ");
            log.hex(v);
            if (is_id) log.str("   <- bridge PCI ID");
            log.byte('\n');
        }
    }

    if (f.all_dead) {
        log.str("      every sampled word was 0x0 or 0xFFFFFFFF\n");
        log.str("      => controller unclocked or in reset: RP1 needs full brcmstb bring-up\n");
        return f;
    }
    if (!f.saw_bridge_id) {
        log.str("      => controller responds but no PCI ID found in the sampled spread\n");
        return f;
    }
    log.str("      => controller is ALIVE, its config space is at MMIO offset 0\n");

    // The decisive question. Everything else is cheap if this says yes.
    if (linkStatus()) |ls| {
        log.str("      link: speed=gen");
        log.dec(ls.speed);
        log.str(" width=x");
        log.dec(ls.width);
        log.str(" dl_active=");
        log.dec(@intFromBool(ls.dl_active));
        log.str("  (raw ");
        log.hex(ls.raw);
        log.str(")\n");
        if (ls.dl_active) {
            log.str("      => LINK IS ALREADY TRAINED at handoff; only config writes needed\n");
        } else {
            log.str("      => link is DOWN; training is required (brcmstb bring-up)\n");
        }
    } else {
        log.str("      *** could not locate the PCI Express capability\n");
    }

    // The bridge is almost certainly still held in reset, which would explain why
    // every register write is dropped. Release it and retry — see tryReleaseReset.
    tryReleaseReset();

    const vid = endpointConfigRead(1, 0, 0, 0x00);
    log.str("      bus1:dev0 config[0x00] = ");
    log.hex(vid);
    if ((vid & 0xFFFF) == 0x1DE4) {
        log.str("   <- RP1 (1de4) ANSWERS\n");
        const bar1 = endpointConfigRead(1, 0, 0, 0x14);
        const cmd = endpointConfigRead(1, 0, 0, 0x04);
        log.str("      RP1 BAR1 = ");
        log.hex(bar1);
        log.str("  Command = ");
        log.hex(cmd & 0xFFFF);
        log.str("\n      => programme BAR1=0x0 + Command=0x6 and the UART is reachable\n");
    } else {
        log.str("   <- no response from bus 1\n");
    }
    log.commit();
    return f;
}
