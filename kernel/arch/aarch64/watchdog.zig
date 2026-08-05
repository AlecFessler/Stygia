//! BCM2712 PM watchdog pet — the kernel half of the bare-metal Pi 5 safety
//! net.
//!
//! The bare-metal loader (`bootloader/pi5/watchdog.zig`) arms this block for a
//! full reset just before the ERET into the kernel, because from that point on
//! the loader's own reset-on-fault vectors no longer apply: the kernel installs
//! its own exception vectors, so a kernel panic or a silent hang would leave the
//! board dark until somebody pulls power — and a cold boot also erases the DRAM
//! early log, destroying the postmortem.
//!
//! The problem that makes this file necessary is that the counter is **20 bits
//! wide at 65536 Hz**, so `0xFFFFF / 65536` = 15.99 s is a HARD ceiling. It
//! cannot be extended by arming a larger value — a larger value silently
//! truncates. Anything the kernel does that legitimately takes longer than one
//! timeout has to re-arm the counter. The 485-test suite is exactly that: the
//! first bare-metal run of it reset the board partway through `batch 16..32` of
//! ~31 batches.
//!
//! ## Every exit converges on a reset
//!
//! The petting is deliberately NOT open-ended, because the goal is a board that
//! can run the suite N times unattended. A *clean* run does not need this file
//! at all: the suite's `-Dreboot_at_end` makes the runner finish with
//! `power_reboot`, which on this board is a warm PSCI `SYSTEM_RESET` that
//! preserves DRAM (and so the loader's early log) and lands back in Pi OS via
//! tryboot. What the pet has to guarantee is that the *unclean* outcomes also
//! come back on their own rather than holding the board up forever. It stops in
//! each of these cases, and once it stops the already-armed watchdog fires
//! within ≤15 s:
//!
//!   - `CEILING_SECONDS` after `setBase`. **This is the real safety net.** It
//!     covers a hang that keeps servicing timer interrupts — the one failure
//!     mode a watchdog cannot otherwise see, because the IRQ path keeps petting
//!     on schedule while nothing progresses. Deliberately far larger than any
//!     legitimate run; see the constant.
//!   - A claimed panic gate, checked in `pet()`. `panic.panic` ends in
//!     `cpu.halt()`, a `while (true) wfi` park that does NOT mask interrupts,
//!     so without this the timer PPI would keep petting a dead kernel until the
//!     ceiling expired.
//!   - `stopPetting()` from `power.doShutdown` / `power.doReboot` before they
//!     park, for the same reason. A backstop rather than a normal path: it
//!     matters for a bare-metal image built *without* `-Dreboot_at_end`, whose
//!     runner asks for a genuine `SYSTEM_OFF` that would be unrecoverable
//!     remotely. It only stops the pet — choosing between off and reset is the
//!     suite's decision, not the watchdog's.
//!
//! A hang that stops taking interrupts needs none of these: it stops petting by
//! construction.
//!
//! Petting itself is a *single* 32-bit MMIO store: the loader's arm already
//! wrote RSTC with `WRCFG = full-reset`, and RSTC keeps that configuration
//! across reloads, so rewriting PM_WDOG is all that is needed to restart the
//! countdown. That also means a pet on a board where nothing armed the
//! watchdog is inert — writing PM_WDOG alone does not start the counter, only
//! writing RSTC does.
//!
//! Every write needs `PM_PASSWORD` in the top byte or the PM block discards it
//! with no error. A missing password is indistinguishable from a watchdog that
//! does not exist.
//!
//! **Complete no-op off this hardware.** `pm_base` stays 0 unless
//! `dt_discovery.discoverWatchdog` found a `brcm,bcm2712-pm` node in a real
//! devicetree and mapped it. QEMU virt, a Pi 5 running under KVM (whose guest
//! DTB is QEMU's, not the board's), and every UEFI/ACPI boot leave it 0, and
//! `pet()` then touches nothing — not even a timestamp read. The gate is the
//! discovered address, not a build flag, so one kernel binary is correct on all
//! of them.
//!
//! Registers are the long-standing Broadcom PM block (`bcm2835_wdt` in Linux),
//! unchanged in layout on BCM2712.

const stygia = @import("stygia");

const cpu = stygia.arch.aarch64.cpu;
const panic = stygia.panic;
const serial = stygia.arch.aarch64.serial;

/// Kernel VA of the PM block base, or 0 for "do not pet". Zero covers three
/// distinct states that all want identical behaviour: no PM node in the
/// devicetree (every target but a bare-metal BCM2712), the `CEILING_SECONDS`
/// ceiling having expired, and a shutdown having been requested.
///
/// Set once during single-threaded early boot (before `gic.init`, before any
/// secondary exists, before interrupts are enabled) and afterwards only ever
/// cleared. Accessed atomically because the clear can come from IRQ context on
/// any core; `.monotonic` is sufficient — the only value ever published is a
/// pointer whose page was mapped strictly before the store, and the only other
/// transition is to 0, which is idempotent no matter how many cores race to
/// perform it.
var pm_base: usize = 0;

/// CNTVCT_EL0 value at which petting stops for good. Written once by `setBase`
/// before `pm_base` is published, so every reader that sees a non-zero
/// `pm_base` also sees the final deadline.
var pet_deadline: u64 = 0;

/// Required in the top byte of every PM register write; without it the write
/// is discarded with no error.
const PM_PASSWORD: u32 = 0x5A00_0000;

/// Offset of PM_WDOG (the reload / count register) within the PM block.
const PM_WDOG_OFFSET: usize = 0x24;

/// The counter is 20 bits wide and counts at 65536 Hz, so this is also the
/// mask that makes the reload value's truncation explicit rather than silent.
const PM_WDOG_TIME_SET: u32 = 0x000F_FFFF;
const TICKS_PER_SEC: u32 = 65536;

/// Reload value written by every pet: 15 s, one second under the 15.99 s
/// hardware ceiling. Matches the loader's arm exactly (verified read-back
/// `0xF0000`), so the kernel's window is the same length the loader proved
/// counts down on this board.
const RELOAD_TICKS: u32 = (15 * TICKS_PER_SEC) & PM_WDOG_TIME_SET;

/// Absolute upper bound on how long the kernel will keep the board alive,
/// measured from `setBase` (devicetree discovery, a few milliseconds into
/// kernel entry — time the loader itself spent is not counted).
///
/// This is the **safety net against a hang that still services timer
/// interrupts**, and the only thing in this module that catches it. That case
/// is otherwise invisible to a watchdog: the IRQ path keeps petting on schedule
/// while nothing actually progresses, so the board stays up forever and an
/// unattended harness waiting for `boot_id` to change waits forever. A hang
/// that stops taking interrupts needs none of this — it stops petting on its
/// own and resets in ≤15 s.
///
/// It is NOT the normal exit. A clean run reboots itself: with the suite's
/// `-Dreboot_at_end`, the runner ends in `power_reboot` → PSCI `SYSTEM_RESET`,
/// which on this board is a warm reset that returns to Pi OS immediately and
/// involves the watchdog not at all. That is what makes it correct for this
/// constant to be far larger than any legitimate run rather than tuned close to
/// one: a tight ceiling buys nothing (the clean path is already immediate) and
/// risks truncating a real run, which is exactly the failure this module was
/// written to remove.
///
/// A single boot may legitimately run for many minutes: the suite has an
/// internal loop mode that runs the whole 485-test set N times back to back in
/// one boot, so run length is a harness parameter rather than a fixed cost.
/// The original value was 600 s, chosen when there was no bare-metal timing for
/// even one iteration, together with the standing instruction "raise this
/// before raising N far enough to approach it".
///
/// N=100 passed that point and the instruction was missed, silently, for three
/// cycles. MEASURED: four independent `-Drepeat=100` runs on this board, on
/// four different kernel builds, ended after 668 s, 670 s, 674 s and 669 s
/// — a 6 s spread — having completed 64, 68, 73 and 77 passes respectively, a
/// 20 % spread. A stochastic kernel wedge cannot produce a constant wall clock
/// across builds; a fixed deadline can, and this is the only one in the system.
/// Each run died the same way: the last line is a normal `[runner] spawned
/// 16/16` mid-pass, then nothing, then the board resets and Pi OS comes back.
/// That is exactly `pet()` taking the `cntvct >= pet_deadline` branch — which
/// calls `stopPetting()` and returns without a word — followed by the armed
/// BCM2712 watchdog firing ≤15 s later.
///
/// The implied per-pass costs (600 s / passes) are 9.4, 8.8, 8.2 and 7.8 s, in
/// the order the fixes landed. So the run lengths were not a cliff that kept
/// moving; they were one constant divided by a shrinking per-pass cost, and
/// reading them as a kernel bug ("the spawn-loop wedge") cost three cycles.
///
/// 2400 s accordingly: a diagnostic-heavy work-stealing N=100 pass can exceed
/// 1200 s while still making ordinary runner progress. The wider budget keeps
/// that valid stability gate on the clean runner-controlled reboot path while
/// still bounding an IRQ-servicing hang at ~40 min. Raising N again requires
/// revisiting this ceiling and the outer harness timeout together.
const CEILING_SECONDS: u64 = 2400;

/// Point the pet at a PM block whose MMIO page is already mapped, `va` being
/// the kernel VA of the block's base (not of PM_WDOG), and start the
/// `CEILING_SECONDS` budget.
///
/// Returns false, leaving petting disabled, when CNTFRQ_EL0 reads 0. Without a
/// counter frequency the ceiling cannot be honoured, and an un-ceilinged pet is
/// precisely the unrecoverable case this module exists to avoid — so the honest
/// fallback is to leave the loader's single 15 s window in force and let the
/// caller say so out loud. (CNTFRQ_EL0 reading 0 would also mean the scheduler
/// has no time base at all, so this is a "nothing works" signal rather than a
/// watchdog-specific one.)
///
/// Called only from `dt_discovery.discoverWatchdog`, which owns both the
/// devicetree match and the mapping. Taking a VA rather than a PAddr keeps this
/// module free of any assumption about how the physmap is laid out.
pub fn setBase(va: u64) bool {
    const freq = readCntfrq();
    if (freq == 0) return false;
    pet_deadline = cpu.readCntvct() + CEILING_SECONDS * freq;
    @atomicStore(usize, &pm_base, @as(usize, @intCast(va)), .monotonic);
    return true;
}

/// Restart the watchdog countdown at `RELOAD_TICKS`, unless the
/// `CEILING_SECONDS` budget has run out — in which case petting stops for
/// good and the watchdog resets the board within ≤15 s.
///
/// The write is a single uncached 32-bit store, which is why it is affordable
/// on every interrupt rather than needing a dedicated timer or thread. `inline`
/// so that on every target without a PM block the whole body folds down to one
/// load and a branch in the caller's straight-line code — the counter read and
/// the reload constant are never even reached.
///
/// Safe from any context: it takes no lock, allocates nothing, and cannot fault
/// (the page was mapped before the address was published).
pub inline fn pet() void {
    const base = @atomicLoad(usize, &pm_base, .monotonic);
    if (base == 0) return;
    if (cpu.readCntvct() >= pet_deadline) {
        // SAY SO. This branch used to stop petting in total silence, so the
        // board simply went quiet mid-pass and reset ~15 s later, which reads
        // on the captured serial exactly like a kernel wedge in whatever the
        // runner was doing at the time. Three cycles diagnosed it as one. A
        // deliberate exit path must never be indistinguishable from a hang.
        //
        // `printRaw` because this runs from the timer IRQ, where the lock the
        // normal printer takes may already be held by this core — same reason
        // the fault reporters use it. One-shot: `stopPetting` zeroes `pm_base`,
        // so the `base == 0` early return above makes every later pet a no-op.
        serial.printRaw("\n[wdog] CEILING_SECONDS budget exhausted — petting stops, board resets within 15s\n");
        stopPetting();
        return;
    }
    // A panicked kernel is an exit path too, and the most interesting one:
    // `panic.panic` ends in `cpu.halt()`, a `while (true) wfi` that does NOT
    // mask interrupts, so the timer PPI keeps arriving here and would keep
    // petting a dead kernel until the `CEILING_SECONDS` backstop. Folding the
    // panic gate in turns that into the same ≤15 s reset as any other exit,
    // which matters because a *warm* reset preserves the DRAM early log while
    // the cold boot a human power-cycle would cause destroys it.
    //
    // `panic_owner` is only ever claimed by `panic.panic` itself (the
    // diagnostic dumpers document the gate but do not take it), so a non-zero
    // owner is not ambiguous: the kernel is going down.
    if (panic.panic_owner.load(.monotonic) != panic.PANIC_OWNER_NONE) {
        stopPetting();
        return;
    }
    const reg: *volatile u32 = @ptrFromInt(base + PM_WDOG_OFFSET);
    reg.* = PM_PASSWORD | RELOAD_TICKS;
}

/// Stop petting permanently, handing the board back to the armed watchdog so
/// it resets within ≤15 s.
///
/// Called on the shutdown and reboot paths (`power.doShutdown`,
/// `power.doReboot`) and by `pet()` itself when the ceiling expires or a panic
/// has been claimed. Idempotent and safe from IRQ context; on every target with
/// no PM block it is already the state we are in, so it does nothing.
pub fn stopPetting() void {
    @atomicStore(usize, &pm_base, 0, .monotonic);
}

/// Remaining ticks, or null when petting is not active. Diagnostic only —
/// reading this right after a pet is the cheapest available proof that the
/// mapping and the password are both right.
pub fn remainingTicks() ?u32 {
    const base = @atomicLoad(usize, &pm_base, .monotonic);
    if (base == 0) return null;
    const reg: *volatile u32 = @ptrFromInt(base + PM_WDOG_OFFSET);
    return reg.* & PM_WDOG_TIME_SET;
}

/// Length of the window each pet buys, in whole seconds. For boot diagnostics.
pub fn windowSeconds() u32 {
    return RELOAD_TICKS / TICKS_PER_SEC;
}

/// The `CEILING_SECONDS` budget, for boot diagnostics.
pub fn ceilingSeconds() u64 {
    return CEILING_SECONDS;
}

/// Read CNTFRQ_EL0 — the counter frequency firmware programmed.
///
/// Duplicated from `timers.zig`'s private helper rather than reaching for its
/// cached `cntFreqHz()`: this runs during devicetree discovery, well before
/// anything has populated that cache, and a lazily-cached read from here would
/// be a surprising side effect on a module the watchdog otherwise has no
/// business initialising. ARM ARM D13.8.1.
inline fn readCntfrq() u64 {
    var freq: u64 = undefined;
    asm volatile ("mrs %[freq], cntfrq_el0"
        : [freq] "=r" (freq),
    );
    return freq;
}
