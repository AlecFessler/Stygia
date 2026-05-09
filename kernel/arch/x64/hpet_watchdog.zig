//! HPET-NMI hang watchdog.
//!
//! Programs HPET timer 0 in periodic mode with FSB Interrupt Delivery
//! routed as a CPU NMI to the BSP. Period is ~500 ms. The NMI handler in
//! `arch/x64/exceptions.zig` calls `utils.hang_detector.tickCheck()`,
//! which is the same path the LAPIC scheduler tick + #PF + exception
//! entry already use. The point of routing through the HPET (rather
//! than the LAPIC timer) is that HPET keeps ticking even when every
//! core is parked in a user-mode idle hlt loop with the LAPIC timer
//! disarmed — the smp=4 lost-wakeup signature on this branch.
//!
//! Build-gated by `-Dkernel_hang_watchdog=true`. When off, every public
//! symbol is a no-op and no HPET register is touched.
//!
//! Spec references (IA-PC HPET Specification 1.0a):
//!   - §2.3.8 Timer N Configuration and Capabilities Register
//!   - §2.3.9 Timer N Comparator Value Register
//!   - §2.3.10 Timer N FSB Interrupt Route Register
//!
//! NMI delivery via FSB uses the standard MSI message format
//! (Intel SDM Vol 3A §11.11.1, Figure 11-25 "Format of the Interrupt
//! Address" / Figure 11-26 "Format of the Interrupt Data"):
//!   - address: 0xFEE0_0000 | (dest_apic_id << 12)
//!     bit 2 = redirection hint (0 = directed), bit 3 = dest mode
//!     (0 = physical)
//!   - value: bits 7:0 = vector (ignored for NMI), bits 10:8 = delivery
//!     mode (100b = NMI), bit 14 = level, bit 15 = trigger (0 = edge)

const build_options = @import("build_options");
const std = @import("std");
const stygia = @import("stygia");

const apic = stygia.arch.x64.apic;
const cpu = stygia.arch.x64.cpu;
const irq = stygia.arch.x64.irq;
const timers = stygia.arch.x64.timers;

pub const enabled: bool = build_options.kernel_hang_watchdog;

/// Period in nanoseconds. 100 ms gives ≥1 watchdog tick inside even
/// a sub-second hang window (the smp=4 reply-FP failure exits via KVM
/// halt detection within ~1 s of last userspace progress), while still
/// being a tiny fraction of the wallclock so the per-NMI overhead is
/// negligible.
const PERIOD_NS: u64 = 100_000_000;

/// HPET Timer N config register layout. IA-PC HPET 1.0a §2.3.8.
/// Only the low 32 bits of the 64-bit register are control; the high
/// 32 bits (capabilities) are read-only.
const TimerNConfig = packed struct(u64) {
    /// 0: reserved (writes ignored)
    _r0: u1 = 0,
    /// 1: Tn_INT_TYPE_CNF — 0 = edge, 1 = level
    int_type: u1 = 0,
    /// 2: Tn_INT_ENB_CNF — 1 = enabled
    int_enable: u1 = 0,
    /// 3: Tn_TYPE_CNF — 1 = periodic (only writable if Tn_PER_INT_CAP)
    periodic: u1 = 0,
    /// 4: Tn_PER_INT_CAP — read-only; 1 = periodic supported
    periodic_cap: u1 = 0,
    /// 5: Tn_SIZE_CAP — read-only; 1 = 64-bit timer
    size_64_cap: u1 = 0,
    /// 6: Tn_VAL_SET_CNF — periodic-mode comparator-write enable
    val_set: u1 = 0,
    /// 7: reserved
    _r7: u1 = 0,
    /// 8: Tn_32MODE_CNF — 1 = force 32-bit
    mode_32: u1 = 0,
    /// 9-13: Tn_INT_ROUTE_CNF — IOAPIC GSI when not FSB
    int_route: u5 = 0,
    /// 14: Tn_FSB_EN_CNF — 1 = use FSB (MSI-style) delivery
    fsb_enable: u1 = 0,
    /// 15: Tn_FSB_INT_DEL_CAP — read-only; 1 = supports FSB delivery
    fsb_cap: u1 = 0,
    /// 16-31: reserved
    _r16: u16 = 0,
    /// 32-63: Tn_INT_ROUTE_CAP — bitmap of IOAPIC GSIs the timer can drive
    int_route_cap: u32 = 0,
};

/// HPET Timer N MMIO register block. IA-PC HPET 1.0a §2.3, Table 2 —
/// per-timer registers start at offset 0x100 + 0x20 * N from the HPET
/// base address.
const TimerN = struct {
    config: *volatile TimerNConfig,
    comparator: *volatile u64,
    fsb_route_value: *volatile u32,
    fsb_route_address: *volatile u32,

    fn at(hpet_base_addr: u64, n: u6) TimerN {
        const block = hpet_base_addr + 0x100 + 0x20 * @as(u64, n);
        return .{
            .config = @ptrFromInt(block + 0x00),
            .comparator = @ptrFromInt(block + 0x08),
            // FSB route: low 32 = value, high 32 = address. The HPET
            // exposes them as a single 64-bit register at offset 0x10
            // within the timer block; we treat them as two 32-bit
            // halves for clarity.
            .fsb_route_value = @ptrFromInt(block + 0x10),
            .fsb_route_address = @ptrFromInt(block + 0x14),
        };
    }
};

var armed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Program HPET timer 0 to fire periodically (~PERIOD_NS) as an NMI on
/// the BSP. Must be called after `timers.hpet_timer` is initialised
/// (i.e. after `arch.boot.parseFirmwareTables`) and after the LAPIC is
/// up (so we know the BSP's APIC ID for the FSB destination). No-op
/// when the watchdog is build-disabled.
pub fn init() void {
    if (!enabled) return;

    const serial = stygia.arch.x64.serial;
    serial.printRaw("[hpet-wdg] init begin\n");

    const hpet = &timers.hpet_timer;
    const hpet_base_addr: u64 = @intFromPtr(hpet.gen_caps_and_id);

    // Validate periodic + FSB capability before touching anything. Both
    // are required by this design; QEMU's HPET emulation advertises
    // both for timer 0 (qemu/hw/timer/hpet.c). Bare-metal HPETs vary —
    // some only advertise FSB on a subset of timers, but timer 0 is
    // the most consistent.
    const t0 = TimerN.at(hpet_base_addr, 0);
    const cur_cfg: TimerNConfig = t0.config.*;
    {
        var dbgbuf: [128]u8 = undefined;
        const raw_u64: u64 = @bitCast(cur_cfg);
        const dbg = std.fmt.bufPrint(&dbgbuf, "[hpet-wdg] raw cfg=0x{x} route_cap_field=0x{x}\n", .{ raw_u64, cur_cfg.int_route_cap }) catch return;
        serial.printRaw(dbg);
    }
    if (cur_cfg.periodic_cap == 0) {
        serial.printRaw("[hpet-wdg] periodic_cap missing\n");
        return;
    }
    // Two delivery paths:
    //   (a) FSB Interrupt Delivery (preferred — bypasses IOAPIC). Some
    //       physical HPETs advertise this; QEMU's TCG/KVM HPET model does
    //       not (it only emulates legacy IOAPIC routing).
    //   (b) IOAPIC routing with NMI delivery mode in the redirection
    //       table entry. Picks the lowest GSI advertised in
    //       Tn_INT_ROUTE_CAP and programs the IOAPIC redirection slot
    //       to deliver as NMI to the BSP. This works under QEMU.
    const use_fsb = cur_cfg.fsb_cap == 1;

    // Disable while we reprogram. Mask + clear the enable bit, then
    // we'll flip the rest atomically.
    {
        var cfg = cur_cfg;
        cfg.int_enable = 0;
        cfg.periodic = 0;
        cfg.fsb_enable = 0;
        t0.config.* = cfg;
    }

    const bsp_apic_id: u32 = @truncate(apic.coreID());
    var picked_gsi: u32 = 0;
    if (use_fsb) {
        // FSB route address: BSP LAPIC, physical destination, no
        // redirection hint. Intel SDM Vol 3A §11.11.1 Figure 11-25.
        const fsb_addr: u32 = 0xFEE0_0000 | (bsp_apic_id << 12);

        // FSB route value: NMI delivery mode (100b in bits 10:8), edge
        // trigger, vector field is ignored for NMI (use 0x02 just to
        // match the architectural NMI vector — purely cosmetic).
        const fsb_val: u32 = (0b100 << 8) | 0x02;

        t0.fsb_route_address.* = fsb_addr;
        t0.fsb_route_value.* = fsb_val;
    } else {
        // IOAPIC fallback. Pick the lowest GSI advertised in
        // Tn_INT_ROUTE_CAP and program IOAPIC redirection for that
        // GSI to deliver as NMI to the BSP. We start scanning from
        // GSI 8 to skip the legacy ISA range so we don't fight any
        // pre-existing IOAPIC routing for those.
        var found_gsi: u32 = 0xFFFF_FFFF;
        // Start from GSI 2 — HPET timer 0 under QEMU only advertises
        // GSI 2 in its int_route_cap bitmap. GSI 2 is the legacy 8259
        // cascade slot and is reserved on bare-metal IBM PC machines,
        // but QEMU uses it for HPET routing per its IRQ-routing tables.
        var i: u32 = 2;
        while (i < 32) {
            const shift: u5 = @intCast(i);
            const bit = (cur_cfg.int_route_cap >> shift) & 1;
            if (bit == 1) {
                found_gsi = i;
                break;
            }
            i += 1;
        }
        var dbgbuf: [128]u8 = undefined;
        const dbg = std.fmt.bufPrint(&dbgbuf, "[hpet-wdg] route_cap=0x{x} chose gsi={d}\n", .{ cur_cfg.int_route_cap, found_gsi }) catch return;
        serial.printRaw(dbg);
        if (found_gsi == 0xFFFF_FFFF) {
            serial.printRaw("[hpet-wdg] no usable GSI in route cap\n");
            return;
        }
        if (!irq.programIoapicNmi(found_gsi, bsp_apic_id)) {
            serial.printRaw("[hpet-wdg] ioapic not initialized\n");
            return;
        }
        picked_gsi = found_gsi;
    }

    // Compute period in HPET ticks. `hpet.freq_hz` was derived from
    // the counter clock period in `Hpet.init`.
    const period_ticks: u64 = (hpet.freq_hz * PERIOD_NS) / 1_000_000_000;

    // Periodic-mode comparator write protocol (IA-PC HPET 1.0a §2.3.9):
    //   1. Set Tn_VAL_SET_CNF and Tn_TYPE_CNF (periodic).
    //   2. Write the *absolute* fire time to the comparator (= now + period).
    //   3. Write the *period* to the comparator a second time. Hardware
    //      auto-increments the absolute fire time by this period each tick.
    {
        var cfg = TimerNConfig{};
        cfg.periodic_cap = cur_cfg.periodic_cap;
        cfg.size_64_cap = cur_cfg.size_64_cap;
        cfg.fsb_cap = cur_cfg.fsb_cap;
        cfg.int_route_cap = cur_cfg.int_route_cap;
        cfg.int_type = 0; // edge
        cfg.periodic = 1;
        cfg.val_set = 1;
        cfg.fsb_enable = if (use_fsb) 1 else 0;
        if (!use_fsb) cfg.int_route = @intCast(picked_gsi);
        cfg.int_enable = 0; // still disabled — flip after comparator
        t0.config.* = cfg;
    }

    const now_ticks: u64 = hpet.main_counter_val.val;
    t0.comparator.* = now_ticks +% period_ticks;
    t0.comparator.* = period_ticks;

    // Flip enable. From here HPET timer 0 will deliver an NMI to the
    // BSP every `PERIOD_NS`.
    {
        var cfg: TimerNConfig = t0.config.*;
        cfg.int_enable = 1;
        // val_set self-clears once the comparator has been written;
        // explicitly clear here too in case hardware leaves it set.
        cfg.val_set = 0;
        t0.config.* = cfg;
    }

    // Make sure the main counter is running — `Hpet.timer()` would
    // normally arm it, but the watchdog can be initialised before
    // any timer interface is fetched.
    if (!hpet.gen_config.enable) {
        hpet.gen_config.enable = true;
    }

    armed.store(true, .release);
    if (use_fsb) {
        serial.printRaw("[hpet-wdg] armed via FSB-NMI\n");
    } else {
        serial.printRaw("[hpet-wdg] armed via IOAPIC-NMI\n");
    }
}

/// True when the HPET-NMI watchdog has been programmed. The NMI
/// handler reads this to decide whether to consume the NMI as a
/// watchdog tick (call hang_detector.tickCheck and return) or to
/// fall through to its previous behaviour (kprof_sample / panic).
pub fn isArmed() bool {
    if (!enabled) return false;
    return armed.load(.acquire);
}

// Unused-warning silencer for the build_options-disabled path. Zig
// will still emit references to `cpu` from outer scope when
// `enabled == false`, so we keep the import.
comptime {
    _ = cpu;
}
