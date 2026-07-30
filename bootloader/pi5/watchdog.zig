//! BCM2712 PM watchdog — the safety net that makes unattended bare-metal boots
//! possible.
//!
//! The tryboot fallback only triggers on a RESET. A wedged core never resets, so
//! it leaves the board dark until somebody pulls power — and a cold boot also
//! erases the DRAM early log, destroying the evidence. Up to now the loader's own
//! EL2 vectors covered that: a fault logged and then PSCI-reset itself.
//!
//! That stops being enough the moment control passes to the kernel. The kernel
//! installs its OWN exception vectors, so the loader's reset-on-fault no longer
//! applies, and a kernel that panics and spins (or simply runs forever) never
//! comes back. Arming this before the ERET means the board resets no matter what
//! happens next: kernel panic, silent hang, infinite loop, or a perfectly healthy
//! run that just never terminates. It converts "needs a human to power cycle" into
//! "back at a Linux prompt in ~15 s", which is the difference between an
//! autonomous test loop and a manual one.
//!
//! Deliberately arm-and-never-pet. Nothing pets this: the point is a hard upper
//! bound on how long a bare-metal boot can hold the board, not liveness detection.
//! When the kernel eventually needs longer than one timeout it should pet it
//! explicitly, which is a conscious decision rather than a default.
//!
//! Registers are the long-standing Broadcom PM block (bcm2835_wdt in Linux),
//! unchanged in layout on BCM2712. Every write needs PM_PASSWORD in the top byte
//! or the block silently ignores it — a missing password looks exactly like a
//! watchdog that does not work.

const std = @import("std");
const stygia = @import("stygia");

const log = @import("early_log.zig");
const mmu = @import("mmu.zig");

const paging = stygia.memory.paging;

/// `/soc/watchdog@7d200000`, `compatible = "brcm,bcm2712-pm"`, `reg = <0x7d200000
/// 0x308>`, translated through `/soc`'s `ranges = <0x7c000000 0x10 0x7c000000
/// 0x4000000>`: 0x7d200000 - 0x7c000000 = 0x1200000, plus parent base
/// 0x10_7c000000.
pub const PM_BASE: u64 = 0x10_7D20_0000;

const PM_RSTC: u64 = 0x1C;
const PM_RSTS: u64 = 0x20;
const PM_WDOG: u64 = 0x24;

/// Required in the top byte of every PM register write; without it the write is
/// discarded with no error.
const PM_PASSWORD: u32 = 0x5A00_0000;

/// The counter is 20 bits wide.
const PM_WDOG_TIME_SET: u32 = 0x000F_FFFF;
const PM_RSTC_WRCFG_CLR: u32 = 0xFFFF_FFCF;
const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x0000_0020;

/// The watchdog counts at 65536 Hz.
const TICKS_PER_SEC: u32 = 65536;

/// Hardware maximum: a 20-bit counter at 65536 Hz is 0xFFFFF/65536 = 15.99 s. Not
/// a chosen policy — arming for longer would silently truncate, so callers must
/// know the ceiling is low and that a long-running kernel has to pet it.
pub const MAX_SECONDS: u32 = 15;

fn rd(off: u64) u32 {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(PM_BASE + off)));
    return p.*;
}

fn wr(off: u64, v: u32) void {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(PM_BASE + off)));
    p.* = v;
}

pub fn map(alloc: std.mem.Allocator, ttbr0_root: u64) !void {
    try mmu.mapMmio(alloc, ttbr0_root, PM_BASE, paging.PAGE4K);
}

/// Arm a full-reset watchdog `seconds` from now. Clamped to `MAX_SECONDS`.
pub fn arm(seconds: u32) void {
    const secs = @min(seconds, MAX_SECONDS);
    const ticks: u32 = secs * TICKS_PER_SEC;

    wr(PM_WDOG, PM_PASSWORD | (ticks & PM_WDOG_TIME_SET));
    // Read-modify-write RSTC: preserve the bits we do not own, then select
    // full-reset mode. Writing RSTC is what actually starts the counter.
    const rstc = rd(PM_RSTC);
    wr(PM_RSTC, PM_PASSWORD | (rstc & PM_RSTC_WRCFG_CLR) | PM_RSTC_WRCFG_FULL_RESET);

    log.str("    watchdog armed for ");
    log.dec(secs);
    log.str("s (ticks ");
    log.hex(ticks);
    log.str(", RSTC ");
    log.hex(rd(PM_RSTC));
    log.str(", WDOG ");
    log.hex(rd(PM_WDOG) & PM_WDOG_TIME_SET);
    log.str(")\n");
}

/// Remaining ticks. Reading this twice with work in between is the cheapest proof
/// that the counter is actually running rather than merely written.
pub fn remainingTicks() u32 {
    return rd(PM_WDOG) & PM_WDOG_TIME_SET;
}

/// Disarm. Only for the case where the loader decides NOT to hand off and would
/// rather PSCI-reset cleanly, so the two reset paths cannot race.
pub fn disarm() void {
    wr(PM_RSTC, PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET);
}

/// Confirm the counter is decrementing. Returns false if two reads separated by a
/// delay are identical, which means the arm did not take — almost always a missing
/// PM_PASSWORD or a wrong base address, and worth catching here because a watchdog
/// that silently does nothing removes the entire safety net without any symptom.
pub fn verifyRunning() bool {
    const first = remainingTicks();
    // Busy-wait rather than a timer: no timer is set up at this point, and this
    // runs once. ~200k iterations of a volatile read is comfortably longer than
    // one 65536 Hz tick.
    var spins: u32 = 0;
    while (spins < 200_000) : (spins += 1) {
        _ = rd(PM_RSTS);
    }
    const second = remainingTicks();

    log.str("    watchdog counter ");
    log.hex(first);
    log.str(" -> ");
    log.hex(second);
    if (second < first and second != 0) {
        log.str("  counting down OK\n");
        return true;
    }
    log.str("  *** NOT counting: watchdog is not armed\n");
    return false;
}
