//! ARM Generic Timer driver.
//!
//! The ARM Generic Timer is a mandatory architectural feature that provides
//! high-resolution monotonic timekeeping and per-core timer interrupts.
//! It replaces both x86's TSC (for timestamps) and LAPIC timer / HPET
//! (for preemption / monotonic clock).
//!
//! Timer registers (ARM ARM D11.2):
//!   CNTFRQ_EL0:     counter frequency in Hz (set by firmware, read-only to OS)
//!   CNTVCT_EL0:     virtual counter value (monotonically increasing, read-only)
//!   CNTPCT_EL0:     physical counter value
//!   CNTP_CTL_EL0:   physical timer control (ENABLE, IMASK, ISTATUS)
//!   CNTP_CVAL_EL0:  physical timer comparator value (fire when CNTPCT >= CVAL)
//!   CNTP_TVAL_EL0:  physical timer countdown value (sets CVAL = CNTPCT + TVAL)
//!   CNTV_CTL_EL0:   virtual timer control
//!   CNTV_CVAL_EL0:  virtual timer comparator value
//!   CNTV_TVAL_EL0:  virtual timer countdown value
//!
//! Which timer to use:
//! - Non-virtualized kernel: physical timer (CNTP_*) for preemption.
//! - Under a hypervisor: virtual timer (CNTV_*) — host controls physical.
//! - Timestamp reads: CNTVCT_EL0 (virtual counter) is always safe to use.
//!
//! Timer interrupt: PPI 30 (physical) or PPI 27 (virtual). The GIC must
//! be configured to route these to the exception handler. When the timer
//! fires, the handler calls the scheduler's preemption logic.
//!
//! Tick → nanosecond conversion:
//!   ns = ticks * 1_000_000_000 / CNTFRQ_EL0
//! Use the arch/timer.zig nanosFromTicksFloor / ticksFromNanosCeil helpers
//! with freq = CNTFRQ_EL0.
//!
//! Dispatch interface mapping:
//!   getPreemptionTimer()  → Timer backed by CNTP_CVAL_EL0 (arm interrupt at deadline)
//!   getMonotonicClock()   → Timer backed by CNTVCT_EL0 (read-only clock source)
//!   readTimestamp()       → MRS CNTVCT_EL0
//!
//! References:
//! - ARM ARM D11.2: The Generic Timer
//! - ARM ARM D13.8: Generic Timer registers

const stygia = @import("stygia");

const cpu = stygia.arch.aarch64.cpu;
const timer_mod = stygia.arch.timer;

const Timer = stygia.arch.timer.Timer;

var preemption_timer_instance: PreemptionTimer = undefined;
var monotonic_clock_instance: MonotonicClock = undefined;
var cached_freq_hz: u64 = 0;

/// Read CNTFRQ_EL0 — the counter frequency set by firmware.
/// ARM ARM D13.8.1: CNTFRQ_EL0, Counter-timer Frequency register.
inline fn readCntfrq() u64 {
    var freq: u64 = undefined;
    asm volatile ("mrs %[freq], cntfrq_el0"
        : [freq] "=r" (freq),
    );
    return freq;
}

/// Write CNTV_TVAL_EL0 — virtual timer 32-bit downcounter.
///
/// We use the virtual timer (PPI 27) rather than the physical timer
/// (PPI 30) because the virtual timer is always accessible from EL1
/// and does not require EL2-level configuration of CNTHCTL_EL2 to
/// route the interrupt. On QEMU virt with UEFI AAVMF, the physical
/// timer interrupt is delivered to EL2 and not forwarded to EL1 unless
/// the firmware has explicitly enabled EL1PCEN, which it does not
/// reliably do across AAVMF versions.
///
/// ARM ARM D13.8.21: CNTV_TVAL_EL0. Writing TVAL sets CVAL = CNTVCT + TVAL.
inline fn writeCntvTval(val: u32) void {
    asm volatile ("msr cntv_tval_el0, %[val]"
        :
        : [val] "r" (@as(u64, val)),
    );
}

/// Write CNTV_CTL_EL0 — virtual timer control register.
/// ARM ARM D13.8.20: CNTV_CTL_EL0. Same bit layout as CNTP_CTL_EL0.
inline fn writeCntvCtl(val: u64) void {
    asm volatile ("msr cntv_ctl_el0, %[val]"
        :
        : [val] "r" (val),
    );
}

inline fn ensureFreqCached() void {
    if (cached_freq_hz != 0) return;
    cached_freq_hz = readCntfrq();
}

/// Returns the architectural counter frequency in Hz (CNTFRQ_EL0).
/// Surfaces through the `info_cores` syscall (spec §[system_info] vreg 2
/// freq_hz). The value is the system counter rate, which on ARMv8 is
/// the architecturally-visible time base — always non-zero on a
/// correctly-configured platform.
pub fn cntFreqHz() u64 {
    ensureFreqCached();
    return cached_freq_hz;
}

/// Virtual timer for preemption — arms a deadline interrupt via CNTV_TVAL_EL0.
///
/// We use the virtual timer (INTID 27) instead of the physical timer
/// (INTID 30) because the virtual timer is always accessible from EL1
/// without EL2 firmware having to set CNTHCTL_EL2.EL1PCEN. Some QEMU
/// AAVMF images drop to EL1 without enabling EL1 access to the physical
/// timer, and every PPI 30 interrupt is silently discarded. The virtual
/// timer has no such gating and is the conventional choice for guest
/// kernels on GICv3 (see Linux arm64 arch_timer_kvm_info).
///
/// ARM ARM D11.2.4: Timer conditions and timer interrupts.
const PreemptionTimer = struct {
    fn timer(self: *PreemptionTimer) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    /// Read current time as nanoseconds via CNTVCT_EL0.
    /// ARM ARM D11.2.3: CNTVCT_EL0 increments at CNTFRQ_EL0 Hz.
    fn now(_: *anyopaque) u64 {
        return timer_mod.nanosFromTicksFloor(cached_freq_hz, cpu.readCntvct());
    }

    /// Arm a one-shot interrupt `delta_ns` nanoseconds from now.
    ///
    /// The `Timer` vtable contract (shared with x64 LAPIC/HPET) treats
    /// `timer_val_ns` as a RELATIVE delta, not an absolute deadline. The
    /// ARM generic timer provides CNTV_TVAL_EL0 which internally computes
    /// CVAL = CNTVCT + TVAL, so we clamp the delta to 32 bits and let
    /// hardware do the offset math.
    ///
    /// ARM ARM D13.8.21: CNTV_TVAL_EL0.
    /// ARM ARM D13.8.20: CNTV_CTL_EL0 — ENABLE=1, IMASK=0.
    fn armInterruptTimer(_: *anyopaque, delta_ns: u64) void {
        var delta_ticks = timer_mod.ticksFromNanosCeil(cached_freq_hz, delta_ns);
        if (delta_ticks == 0) delta_ticks = 1;
        if (delta_ticks > 0x7FFF_FFFF) delta_ticks = 0x7FFF_FFFF;
        writeCntvTval(@intCast(delta_ticks));
        // ENABLE=1 (bit 0), IMASK=0 (bit 1 clear)
        writeCntvCtl(0x1);
    }
};

/// Monotonic clock — read-only time source backed by CNTVCT_EL0.
/// Never arms interrupts; used only for timestamp queries.
const MonotonicClock = struct {
    fn timer(self: *MonotonicClock) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    /// ARM ARM D11.2.3: CNTVCT_EL0, virtual counter.
    fn now(_: *anyopaque) u64 {
        return timer_mod.nanosFromTicksFloor(cached_freq_hz, cpu.readCntvct());
    }

    /// The monotonic clock never arms interrupts — this is unreachable.
    /// Mirrors x64 HPET behavior where armInterruptTimer is unreachable.
    fn armInterruptTimer(_: *anyopaque, _: u64) void {
        unreachable;
    }
};

// Module-scope const vtables. Keeping them here (rather than in an
// anonymous `&.{...}` literal inside a method) means the address is
// taken at comptime rather than through any runtime pool, and the
// resulting `Timer` can be returned by value through a single register
// pair with no per-call ABI struct-return shuffling — see the note on
// `getPreemptionTimer` below.
const preemption_vtable: timer_mod.VTable = .{
    .now = PreemptionTimer.now,
    .armInterruptTimer = PreemptionTimer.armInterruptTimer,
};

const monotonic_vtable: timer_mod.VTable = .{
    .now = MonotonicClock.now,
    .armInterruptTimer = MonotonicClock.armInterruptTimer,
};

/// `inline` is load-bearing on aarch64 + TCG SMP. When this function is
/// emitted as a free-standing out-of-line body, secondary cores brought
/// up via PSCI CPU_ON hang somewhere between its prologue and the caller
/// receiving the returned `Timer` (observed with earlyDebugChar markers:
/// core 0 completes the call, cores 1..N enter but never return to the
/// caller). The exact miscompile is not pinned down — it may be an
/// LLVM/Zig ABI issue with 16-byte struct returns, KASLR-relocated .text
/// calls, or a TCG GICv3/Cortex-A72 interaction — but `inline` makes the
/// call disappear entirely at the call site and SMP bring-up succeeds.
/// `getMonotonicClock` is inlined for symmetry and to avoid any latent
/// variant of the same miscompile.
pub inline fn getPreemptionTimer() Timer {
    ensureFreqCached();
    return .{
        .ptr = &preemption_timer_instance,
        .vtable = &preemption_vtable,
    };
}

pub inline fn getMonotonicClock() Timer {
    ensureFreqCached();
    return .{
        .ptr = &monotonic_clock_instance,
        .vtable = &monotonic_vtable,
    };
}

/// Arm CNTV_CVAL_EL0 to fire at absolute monotonic-clock time
/// `deadline_ns`. Spec §[timer].
pub fn armDeadline(deadline_ns: u64) void {
    const monotonic = getMonotonicClock();
    const now_ns = monotonic.now();
    const delta_ns: u64 = if (deadline_ns > now_ns) deadline_ns - now_ns else 0;
    const preemption = getPreemptionTimer();
    preemption.armInterruptTimer(delta_ns);
}
