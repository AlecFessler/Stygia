const stygia = @import("stygia");

const apic = stygia.arch.x64.apic;
const cpu = stygia.arch.x64.cpu;
const interrupts = stygia.arch.x64.interrupts;
const timer_mod = stygia.arch.timer;

const Timer = stygia.arch.timer.Timer;
const VAddr = stygia.memory.address.VAddr;

var tsc_timer_instance: Tsc = undefined;
var lapic_timer_instance: Lapic = undefined;

/// High Precision Event Timer (HPET).
/// IA-PC HPET Spec 1.0a, §2.3 "Timer Register Space" — register offsets and layout.
pub const Hpet = struct {
    /// IA-PC HPET Spec 1.0a, §2.3.1 "General Capabilities and ID Register"
    pub const GenCapsAndId = packed struct(u64) {
        revision_id: u8,
        num_timers_minus_one: u5,
        counter_64_bit: bool,
        _res: u1 = 0,
        legacy_mapping_cap: bool,
        vendor_id: u16,
        counter_clock_period: u32,
    };

    /// IA-PC HPET Spec 1.0a, §2.3.2 "General Configuration Register"
    pub const GenConfig = packed struct(u64) {
        enable: bool,
        legacy_mapping: bool,
        _res: u62 = 0,
    };

    /// IA-PC HPET Spec 1.0a, §2.3.3 "General Interrupt Status Register"
    pub const GenIntStatus = packed struct(u64) {
        level_triggered_timer_active: bool,
        _res: u63 = 0,
    };

    /// IA-PC HPET Spec 1.0a, §2.3.4 "Main Counter Value Register"
    pub const MainCounterVal = packed struct(u64) {
        val: u64,
    };

    /// IA-PC HPET Spec 1.0a, §2.3, Table 2 — register offsets from HPET base address.
    pub const Register = enum(u64) {
        gen_caps_and_id = 0x0,
        gen_config = 0x10,
        gen_int_status = 0x20,
        main_counter_val = 0xF0,
    };

    freq_hz: u64,

    gen_caps_and_id: *const volatile GenCapsAndId,
    gen_config: *volatile GenConfig,
    gen_int_status: *volatile GenIntStatus,
    main_counter_val: *volatile MainCounterVal,

    pub fn init(base_virt: VAddr) Hpet {
        const base_addr = base_virt.addr;
        const gen_caps_and_id: *const volatile GenCapsAndId = @ptrFromInt(
            base_addr + @intFromEnum(Register.gen_caps_and_id),
        );
        return .{
            .freq_hz = timer_mod.ONE_QUADRILLION_NS / @as(u64, gen_caps_and_id.counter_clock_period),

            .gen_caps_and_id = gen_caps_and_id,
            .gen_config = @ptrFromInt(base_addr + @intFromEnum(Register.gen_config)),
            .gen_int_status = @ptrFromInt(base_addr + @intFromEnum(Register.gen_int_status)),
            .main_counter_val = @ptrFromInt(base_addr + @intFromEnum(Register.main_counter_val)),
        };
    }

    pub fn timer(self: *Hpet) Timer {
        if (!self.gen_config.enable) {
            self.gen_config.enable = true;
        }
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    fn armInterruptTimer(ctx: *anyopaque, timer_val_ns: u64) void {
        _ = ctx;
        _ = timer_val_ns;
        unreachable;
    }

    fn now(ctx: *anyopaque) u64 {
        const self: *Hpet = @ptrCast(@alignCast(ctx));
        return timer_mod.nanosFromTicksFloor(self.freq_hz, self.main_counter_val.val);
    }
};

/// Local APIC one-shot timer.
/// Intel SDM Vol 3A, §13.5.4 "APIC Timer" — 32-bit programmable count-down timer.
/// Intel SDM Vol 3A, Figure 13-10 "Divide Configuration Register" — divider encoding.
/// Intel SDM Vol 3A, Figure 13-11 "Initial Count and Current Count Registers"
pub const Lapic = struct {
    freq_hz: u64,
    divider: u32,
    vector: u8,

    /// Calibrates the LAPIC timer frequency by counting ticks against the HPET over
    /// three 10ms samples. The divide configuration register encoding 0b011 selects
    /// divide-by-16 per Intel SDM Vol 3A, Figure 13-10.
    pub fn init(hpet: *Hpet, int_vec: u8) Lapic {
        const DIV_CODE: u32 = 0b011;
        const DIVIDER: u32 = 16;

        if (cached_freq_hz) |freq| {
            apic.initLapicTimer(DIV_CODE, int_vec, false);
            return .{
                .freq_hz = freq,
                .divider = DIVIDER,
                .vector = int_vec,
            };
        }

        apic.initLapicTimer(
            DIV_CODE,
            @intFromEnum(interrupts.IntVecs.spurious),
            true,
        );

        const hpet_iface = hpet.timer();
        var estimate: u64 = 0;

        for (0..3) |i| {
            if (apic.x2_apic) {
                cpu.wrmsr(
                    @intFromEnum(apic.X2ApicMsr.timer_initial_count_register),
                    0xFFFF_FFFF,
                );
            } else {
                apic.writeReg(.init_count_reg, 0xFFFF_FFFF);
            }

            const start_ns = hpet_iface.now();
            var now_ns = start_ns;
            const target_ns = timer_mod.TEN_MILLION_NS;
            while ((now_ns - start_ns) < target_ns) now_ns = hpet_iface.now();

            const cur: u64 = if (apic.x2_apic)
                cpu.rdmsr(@intFromEnum(apic.X2ApicMsr.timer_current_count_register))
            else
                apic.readReg(.curr_count_reg);

            const elapsed: u64 = 0xFFFF_FFFF - cur;

            if (apic.x2_apic) {
                cpu.wrmsr(
                    @intFromEnum(apic.X2ApicMsr.timer_initial_count_register),
                    0,
                );
            } else {
                apic.writeReg(.init_count_reg, 0);
            }

            const delta_ns = now_ns - start_ns;
            const sample = (elapsed * @as(u64, DIVIDER) * timer_mod.ONE_BILLION_NS) / delta_ns;
            estimate = if (i == 0) sample else (estimate + sample) / 2;
        }

        apic.initLapicTimer(
            DIV_CODE,
            int_vec,
            false,
        );

        cached_freq_hz = estimate;

        return .{
            .freq_hz = estimate,
            .divider = DIVIDER,
            .vector = int_vec,
        };
    }

    pub fn timer(self: *Lapic) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    fn armInterruptTimer(ctx: *anyopaque, timer_val_ns: u64) void {
        const self: *Lapic = @ptrCast(@alignCast(ctx));

        const eff_hz: u64 = self.freq_hz / self.divider;
        var ticks: u64 = timer_mod.ticksFromNanosCeil(eff_hz, timer_val_ns);
        if (ticks == 0) ticks = 1;
        if (ticks > 0xFFFF_FFFF) ticks = 0xFFFF_FFFF;

        apic.armLapicOneShot(@intCast(ticks), self.vector);
    }

    fn now(ctx: *anyopaque) u64 {
        _ = ctx;
        unreachable;
    }
};

/// Time-Stamp Counter (TSC) based timer.
/// Intel SDM Vol 3B, §20.17 "Time-Stamp Counter" — RDTSC/RDTSCP monotonic counter.
/// Intel SDM Vol 3B, §20.17.1 "Invariant TSC" — constant rate across P-states.
/// Intel SDM Vol 3A, §13.5.4.1 "TSC-Deadline Mode" — IA32_TSC_DEADLINE MSR (6E0H)
/// arms a one-shot interrupt at an absolute TSC value.
pub const Tsc = struct {
    freq_hz: u64,

    pub fn init(hpet: *Hpet) Tsc {
        if (cached_freq_hz) |freq| {
            return .{ .freq_hz = freq };
        }

        const hpet_iface = hpet.timer();

        var estimate: u64 = 0;

        for (0..3) |i| {
            const target_ns = timer_mod.TEN_MILLION_NS;

            const tsc_start = cpu.rdtscLFenced();
            const hpet_start_ns = hpet_iface.now();

            var now_ns = hpet_start_ns;
            while ((now_ns - hpet_start_ns) < target_ns) {
                now_ns = hpet_iface.now();
            }

            const hpet_end_ns = hpet_iface.now();
            const tsc_end = cpu.rdtscpLFenced();

            const delta_tsc = tsc_end - tsc_start;
            const delta_hpet_ns = hpet_end_ns - hpet_start_ns;

            const sample_hz = (delta_tsc * timer_mod.ONE_BILLION_NS) / delta_hpet_ns;

            estimate = if (i == 0) sample_hz else (estimate + sample_hz) / 2;
        }

        cached_freq_hz = estimate;

        return .{ .freq_hz = estimate };
    }

    pub fn timer(self: *Tsc) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    /// Arms a one-shot interrupt via IA32_TSC_DEADLINE MSR.
    /// Intel SDM Vol 3A, §13.5.4.1 — writes an absolute TSC target; the timer fires
    /// when TSC >= target and then disarms itself.
    fn armInterruptTimer(ctx: *anyopaque, timer_val_ns: u64) void {
        const self: *Tsc = @ptrCast(@alignCast(ctx));
        const delta_ticks: u64 = timer_mod.ticksFromNanosCeil(self.freq_hz, timer_val_ns);
        const now_ticks: u64 = cpu.rdtscp();
        apic.armTscDeadline(now_ticks + delta_ticks);
    }

    fn now(ctx: *anyopaque) u64 {
        const self: *Tsc = @ptrCast(@alignCast(ctx));
        return timer_mod.nanosFromTicksFloor(self.freq_hz, cpu.rdtscp());
    }
};

pub fn getPreemptionTimer() Timer {
    if (apic.programLocalApicTimerTscDeadline(@intFromEnum(interrupts.IntVecs.sched))) {
        tsc_timer_instance = Tsc.init(&hpet_timer);
        tsc_monotonic_ready = true;
        return tsc_timer_instance.timer();
    } else {
        lapic_timer_instance = Lapic.init(&hpet_timer, @intFromEnum(interrupts.IntVecs.sched));
        return lapic_timer_instance.timer();
    }
}

/// Calibrate the TSC monotonic clock against the HPET so that
/// `getMonotonicClock()` can return TSC instead of HPET. Must run on the
/// BSP after `hpet_timer` is initialized but before any code path on the
/// scheduler tick reads the monotonic clock — schedTimerHandler reads
/// the clock for idle/busy accounting on every tick (regular preemption
/// AND `triggerSchedulerInterrupt` IPIs), so a single HPET MMIO read
/// (~15-20 µs vm-exit on KVM) per tick blows the §2.2.34 wake-to-pinned
/// budget by orders of magnitude. Intel SDM Vol 3B §20.17.1 — "Invariant
/// TSC" guarantees a constant rate across P/C states; QEMU exposes it as
/// `-cpu host,+invtsc`. When invariant TSC isn't advertised, fall back
/// to HPET so non-virtualized hardware without invariant TSC still gets
/// a correct (if slow) clock.
pub fn initMonotonicClock() void {
    if (!cpu.hasPowerFeatureEdx(cpu.cpuidRaw(0x80000007, 0).edx, .constant_tsc)) return;
    tsc_timer_instance = Tsc.init(&hpet_timer);
    tsc_monotonic_ready = true;
}

pub fn getMonotonicClock() Timer {
    if (tsc_monotonic_ready) return tsc_timer_instance.timer();
    return hpet_timer.timer();
}

var cached_freq_hz: ?u64 = null;
var tsc_monotonic_ready: bool = false;

pub var hpet_timer: Hpet = undefined;

/// Returns the calibrated TSC frequency in Hz, or 0 if calibration has
/// not yet completed (initMonotonicClock not run, or invariant TSC
/// unsupported and only HPET is being used). Surfaces through the
/// `info_cores` syscall (spec §[system_info] vreg 2 freq_hz).
pub fn tscFreqHz() u64 {
    return cached_freq_hz orelse 0;
}
