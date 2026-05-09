const std = @import("std");
const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;
const interrupts = stygia.arch.x64.interrupts;

const LocalApic = stygia.arch.x64.acpi.LocalApic;
const VAddr = stygia.memory.address.VAddr;

// ── Register offsets (xAPIC MMIO) ────────────────────────────────

/// xAPIC MMIO register offsets relative to the APIC base address.
/// Intel SDM Vol 3A, Section 13.4, Table 13-1 "Local APIC Register Address Map".
pub const Register = enum(u32) {
    lapic_id_reg = 0x20,
    lapic_version_reg = 0x30,
    task_prio_reg = 0x80,
    arbitration_prio_reg = 0x90,
    processor_prio_reg = 0xA0,
    eoi_reg = 0xB0,
    remote_read_reg = 0xC0,
    logical_dest_reg = 0xD0,
    dest_fmt_reg = 0xE0,
    spurious_int_vec_reg = 0xF0,

    in_service_0_reg = 0x100,
    in_service_1_reg = 0x110,
    in_service_2_reg = 0x120,
    in_service_3_reg = 0x130,
    in_service_4_reg = 0x140,
    in_service_5_reg = 0x150,
    in_service_6_reg = 0x160,
    in_service_7_reg = 0x170,

    trigger_mode_0_reg = 0x180,
    trigger_mode_1_reg = 0x190,
    trigger_mode_2_reg = 0x1A0,
    trigger_mode_3_reg = 0x1B0,
    trigger_mode_4_reg = 0x1C0,
    trigger_mode_5_reg = 0x1D0,
    trigger_mode_6_reg = 0x1E0,
    trigger_mode_7_reg = 0x1F0,

    int_request_0_reg = 0x200,
    int_request_1_reg = 0x210,
    int_request_2_reg = 0x220,
    int_request_3_reg = 0x230,
    int_request_4_reg = 0x240,
    int_request_5_reg = 0x250,
    int_request_6_reg = 0x260,
    int_request_7_reg = 0x270,

    err_status_reg = 0x280,

    lvt_corrected_machine_check_int_reg = 0x2F0,
    int_cmd_low_reg = 0x300,
    int_cmd_high_reg = 0x310,
    lvt_timer_reg = 0x320,
    lvt_thermal_sensor_reg = 0x330,
    lvt_perf_monitoring_counters_reg = 0x340,
    lvt_lint0_reg = 0x350,
    lvt_lint1_reg = 0x360,
    lvt_err_reg = 0x370,

    init_count_reg = 0x380,
    curr_count_reg = 0x390,
    div_config_reg = 0x3E0,
};

// ── x2APIC MSR addresses ────────────────────────────────────────

/// x2APIC MSR address space. Each register is accessed via RDMSR/WRMSR
/// at MSR addresses 800H-8FFH.
/// Intel SDM Vol 3A, Section 13.12.1.2, Table 13-6 "Local APIC Register Address Map Supported by x2APIC".
pub const X2ApicMsr = enum(u32) {
    local_apic_id_register = 0x802,
    local_apic_version_register = 0x803,

    task_priority_register = 0x808,
    processor_priority_register = 0x80a,
    end_of_interrupt_register = 0x80b,
    logical_destination_register = 0x80d,
    spurious_interrupt_vector_register = 0x80f,

    in_service_register_bits_0_to_31 = 0x810,
    in_service_register_bits_32_to_63 = 0x811,
    in_service_register_bits_64_to_95 = 0x812,
    in_service_register_bits_96_to_127 = 0x813,
    in_service_register_bits_128_to_159 = 0x814,
    in_service_register_bits_160_to_191 = 0x815,
    in_service_register_bits_192_to_223 = 0x816,
    in_service_register_bits_224_to_255 = 0x817,

    trigger_mode_register_bits_0_to_31 = 0x818,
    trigger_mode_register_bits_32_to_63 = 0x819,
    trigger_mode_register_bits_64_to_95 = 0x81a,
    trigger_mode_register_bits_96_to_127 = 0x81b,
    trigger_mode_register_bits_128_to_159 = 0x81c,
    trigger_mode_register_bits_160_to_191 = 0x81d,
    trigger_mode_register_bits_192_to_223 = 0x81e,
    trigger_mode_register_bits_224_to_255 = 0x81f,

    interrupt_request_register_bits_0_to_31 = 0x820,
    interrupt_request_register_bits_32_to_63 = 0x821,
    interrupt_request_register_bits_64_to_95 = 0x822,
    interrupt_request_register_bits_96_to_127 = 0x823,
    interrupt_request_register_bits_128_to_159 = 0x824,
    interrupt_request_register_bits_160_to_191 = 0x825,
    interrupt_request_register_bits_192_to_223 = 0x826,
    interrupt_request_register_bits_224_to_255 = 0x827,

    error_status_register = 0x828,

    local_vector_table_corrected_machine_check_interrupt = 0x82f,
    interrupt_command_register = 0x830,

    local_vector_table_timer_register = 0x832,
    local_vector_table_thermal_sensor_register = 0x833,
    local_vector_table_performance_monitor_register = 0x834,
    local_vector_table_lint0_register = 0x835,
    local_vector_table_lint1_register = 0x836,
    local_vector_table_error_register = 0x837,

    timer_initial_count_register = 0x838,
    timer_current_count_register = 0x839,
    timer_divide_configuration_register = 0x83e,

    self_interrupt_register = 0x83f,
};

// ── Packed struct types (used only for @bitCast, never via pointer deref) ──

/// LVT Timer Register layout. Bits [18:17] select the timer mode (one-shot,
/// periodic, or TSC-deadline). Bit 16 is the mask bit.
/// Intel SDM Vol 3A, Section 13.5.1, Figure 13-8 "Local Vector Table (LVT)".
pub const LvtTimer = packed struct(u32) {
    vector: u8,
    _res0: u4 = 0,
    delivery_status: bool,
    _res1: u3 = 0,
    mask: bool,
    timer_mode: u2,
    _res2: u13 = 0,
};

/// Spurious-Interrupt Vector Register (SVR). Bit 8 is the APIC software
/// enable/disable flag. Bit 12 controls EOI-broadcast suppression.
/// Intel SDM Vol 3A, Section 13.9, Figure 13-23 "Spurious-Interrupt Vector Register".
pub const SpuriousIntVec = packed struct(u32) {
    spurious_vector: u8,
    apic_enable: bool,
    focus_check_disable: bool,
    _res0: u2 = 0,
    eoi_bcast_supp: bool,
    _res1: u19 = 0,
};

/// Divide Configuration Register. Bits [3,1:0] encode the timer divide value
/// (1, 2, 4, 8, 16, 32, 64, or 128).
/// Intel SDM Vol 3A, Section 13.5.4, Figure 13-10 "Divide Configuration Register".
pub const DivConfig = packed struct(u32) {
    div0: u1,
    div1: u1,
    _res0: u1 = 0,
    div3: u1,
    _res1: u28 = 0,
};

// ── Constants ────────────────────────────────────────────────────

pub const lvt_mask_bit: u6 = 16;
pub const lvt_mode_shift: u6 = 17;
pub const lvt_mode_one_shot: u2 = 0;

pub const tsc_deadline_msr: u32 = 0x6e0;

// ── State ────────────────────────────────────────────────────────

var lapic_base: u64 = 0;
pub var x2_apic: bool = false;
pub var lapics: ?[]LocalApic = null;

/// True once every core has written its core_index into IA32_TSC_AUX
/// (`writeTscAuxCoreId`) AND the host CPU advertises RDPID. After this
/// flips to true, `coreID()` issues a single RDPID instead of an
/// RDMSR(IA32_X2APIC_ID) + lapic-table linear scan. RDMSR on the LAPIC
/// ID register is supposed to be virtualized by APICv/AVIC, but in
/// practice many KVM configurations still trap it (we measured ~1.5 µs
/// per call on AMD AVIC), which blew the §2.2.34 wake-to-pinned budget
/// because lockdep's `acquire`/`release` call coreID several times per
/// SpinLock op. RDPID reads IA32_TSC_AUX, which is exposed
/// unconditionally by KVM (needed for TSC virtualization), so the fast
/// path executes natively in ~5 cycles.
///
/// The slow `RDMSR + lookup` path remains for two reasons:
///   1. On hosts that lack RDPID (pre-Goldmont Intel, pre-Zen 2 AMD)
///      `rdpid_ready` never flips and we always take the slow path.
///   2. During boot, before each core has had `writeTscAuxCoreId` run
///      on it, RDPID would return the firmware-default TSC_AUX (often
///      garbage). The flag flips only once `enableRdpidFastPath` runs
///      after `smpInit` has finished bringing every AP online.
///
/// Intel SDM Vol 2B, "RDPID — Read Processor ID" (CPUID.07H:ECX[22]).
var rdpid_ready: bool = false;

// ── Raw MMIO helpers (always 32-bit aligned access) ─────────────

pub fn readReg(reg: Register) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(lapic_base + @intFromEnum(reg));
    return ptr.*;
}

pub fn writeReg(reg: Register, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(lapic_base + @intFromEnum(reg));
    ptr.* = val;
}

// ── Public API ───────────────────────────────────────────────────

/// Write a TSC deadline value to IA32_TSC_DEADLINE MSR (6E0H). The timer fires
/// when the TSC reaches this value.
/// Intel SDM Vol 3A, Section 13.5.4.1 "TSC-Deadline Mode".
pub fn armTscDeadline(deadline_tsc: u64) void {
    cpu.wrmsr(tsc_deadline_msr, deadline_tsc);
}

/// Arm the LAPIC timer to fire at absolute monotonic-clock time
/// `deadline_ns`. Used by the per-core timer wheel
/// (`sched.timer.wheelInsert`) to schedule the next wheel wake on the
/// local core. Spec §[timer].
///
/// Reuses the same scheduler vector (`IntVecs.sched`) the preemption
/// timer is already on — `schedTimerHandler` calls
/// `sched.timer.wheelExpireDue` so a wheel-driven IRQ and a
/// preemption-driven IRQ run through the same handler. Computes a
/// delta from the current monotonic time and delegates to the same
/// LAPIC programming path used by the preemption tick
/// (`getPreemptionTimer().armInterruptTimer`), so the LAPIC vs.
/// TSC-deadline split stays in one place.
pub fn armDeadline(deadline_ns: u64) void {
    const timers = stygia.arch.x64.timers;
    const preemption = timers.getPreemptionTimer();
    const monotonic = timers.getMonotonicClock();
    const now_ns = monotonic.now();
    const delta_ns: u64 = if (deadline_ns > now_ns) deadline_ns - now_ns else 0;
    preemption.armInterruptTimer(delta_ns);
}

/// Signal end-of-interrupt by writing 0 to the EOI register. For level-triggered
/// interrupts, this also causes an EOI message to be broadcast to I/O APICs.
/// Intel SDM Vol 3A, Section 13.8.5 "Signaling Interrupt Servicing Completion", Figure 13-21.
pub fn endOfInterrupt() void {
    if (x2_apic) {
        cpu.wrmsr(@intFromEnum(X2ApicMsr.end_of_interrupt_register), 0);
    } else {
        writeReg(.eoi_reg, 0);
    }
}

/// Configure the local APIC timer in TSC-deadline mode. Returns false if the
/// processor does not support TSC-deadline or invariant TSC.
/// Intel SDM Vol 3A, Section 13.5.4.1 "TSC-Deadline Mode", Figure 13-8.
pub fn programLocalApicTimerTscDeadline(vector: u8) bool {
    const feat = cpu.cpuid(.basic_features, 0);
    if (!cpu.hasFeatureEcx(feat.ecx, .tsc_deadline)) return false;

    const max_ext = cpu.cpuid(.ext_max, 0).eax;
    if (max_ext < @intFromEnum(cpu.CpuidLeaf.ext_max)) return false;

    const pwr = cpu.cpuid(.ext_power, 0);
    if (!cpu.hasPowerFeatureEdx(pwr.edx, .constant_tsc)) return false;

    const timer_mode_lsb: u6 = 17;
    const tsc_deadline: u2 = 0b10;

    var lvt: u64 = vector;
    lvt |= (@as(u64, tsc_deadline) << timer_mode_lsb);
    cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), lvt);

    return true;
}

pub fn init(lapic_base_virt: VAddr) void {
    // Mask all legacy 8259 PIC interrupts by writing 0xFF to both the
    // master (port 0x21) and slave (port 0xA1) PIC data registers.
    // This ensures no spurious PIC interrupts fire after switching to APIC mode.
    cpu.outb(0xFF, 0x21);
    cpu.outb(0xFF, 0xA1);

    // Intel SDM Vol 3A, Section 13.12.1 "Detecting and Enabling x2APIC Mode".
    x2_apic = cpu.enableX2Apic(@intFromEnum(interrupts.IntVecs.spurious));
    if (x2_apic) return;

    lapic_base = lapic_base_virt.addr;
}

/// Initialize the local APIC timer in one-shot mode with the given divide
/// configuration and vector. See DivConfig and LvtTimer for register layouts.
/// Intel SDM Vol 3A, Section 13.5.4 "APIC Timer", Figures 13-8 and 13-10.
pub fn initLapicTimer(div_code: u32, vector: u8, masked: bool) void {
    if (x2_apic) {
        const m: u64 =
            vector | (@as(u64, lvt_mode_one_shot) << lvt_mode_shift) | (@as(u64, @intFromBool(masked)) << lvt_mask_bit);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.timer_divide_configuration_register), div_code);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), m);
    } else {
        const d: DivConfig = .{
            .div0 = @intCast(div_code & 0b001),
            .div1 = @intCast((div_code >> 1) & 0b001),
            .div3 = @intCast((div_code >> 3) & 0b001),
        };
        writeReg(.div_config_reg, @bitCast(d));

        const l: LvtTimer = .{
            .vector = vector,
            .delivery_status = false,
            .mask = masked,
            .timer_mode = lvt_mode_one_shot,
        };
        writeReg(.lvt_timer_reg, @bitCast(l));
    }
}

/// Arm the local APIC timer in one-shot mode with an initial count. Writing
/// a non-zero value to the initial-count register starts the countdown.
/// Intel SDM Vol 3A, Section 13.5.4 "APIC Timer", Figure 13-11.
pub fn armLapicOneShot(ticks: u32, vector: u8) void {
    if (x2_apic) {
        const m: u64 = vector | (@as(u64, lvt_mode_one_shot) << lvt_mode_shift);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), m);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.timer_initial_count_register), ticks);
    } else {
        const l: LvtTimer = .{
            .vector = vector,
            .delivery_status = false,
            .mask = false,
            .timer_mode = lvt_mode_one_shot,
        };
        writeReg(.lvt_timer_reg, @bitCast(l));
        writeReg(.init_count_reg, ticks);
    }
}

pub fn coreCount() u64 {
    return lapics.?.len;
}

pub fn rawApicId() u32 {
    if (x2_apic) {
        return @intCast(cpu.rdmsr(@intFromEnum(X2ApicMsr.local_apic_id_register)));
    } else {
        return (readReg(.lapic_id_reg) >> 24) & 0xFF;
    }
}

/// Slow path: read this core's APIC ID and linear-scan the `lapics`
/// table for the matching index. Used during boot before
/// `enableRdpidFastPath` runs, and on hosts without RDPID. Public so
/// `smpInit`/`coreInit` can prime each core's TSC_AUX before flipping
/// the fast-path switch.
pub fn coreIDSlow() u64 {
    const raw = rawApicId();
    for (lapics.?, 0..) |la, i| {
        if (la.apic_id == raw) return i;
    }
    unreachable;
}

pub fn coreID() u64 {
    if (rdpid_ready) {
        // RDPID reads IA32_TSC_AUX (MSR 0xC0000103) — populated by
        // `writeTscAuxCoreId` to hold the per-core index, not the raw
        // APIC ID, so no lapic-table lookup is needed.
        var idx: u64 = undefined;
        asm volatile (
            \\rdpid %[idx]
            : [idx] "=r" (idx),
        );
        return idx;
    }
    return coreIDSlow();
}

/// Returns true when the host advertises RDPID
/// (CPUID.07H:ECX[22] = 1). Intel: Goldmont / Skylake-X and later.
/// AMD: Zen 2 and later. Result is fixed across all cores in a system,
/// so callers cache the result.
pub fn hasRdpid() bool {
    return (cpu.cpuidRaw(0x7, 0).ecx & (1 << 22)) != 0;
}

/// Write `core_id` into the calling core's IA32_TSC_AUX MSR so a
/// subsequent `RDPID` returns it directly. Per-core; must be called
/// once on every core (BSP and each AP) before that core's
/// `coreID()` call can rely on the RDPID fast path. Safe to call
/// even when RDPID is unsupported — the MSR is also returned by
/// RDTSCP[%ecx], so writing it is harmless on older parts.
/// Intel SDM Vol 4 §2.16.1 "Auxiliary TSC".
pub fn writeTscAuxCoreId(core_id: u64) void {
    cpu.wrmsr(0xC0000103, core_id);
}

/// Flip `coreID()` to the RDPID fast path. Call ONCE on the BSP
/// after `smpInit` has finished bringing every AP online — at that
/// point each core has run `writeTscAuxCoreId` on itself and the MSR
/// holds the correct index. No-op if RDPID isn't supported.
pub fn enableRdpidFastPath() void {
    if (!hasRdpid()) return;
    rdpid_ready = true;
}

/// Poll the ICR delivery status bit (bit 12) until it clears, indicating
/// the IPI has been sent. Only needed in xAPIC mode; x2APIC writes are atomic.
/// Intel SDM Vol 3A, Section 13.6.1, Figure 13-12 (Delivery Status field).
pub fn waitForDelivery() void {
    if (x2_apic) return;
    while (readReg(.int_cmd_low_reg) & (1 << 12) != 0) {
        std.atomic.spinLoopHint();
    }
}

/// Send an INIT IPI to the target processor. Sets delivery mode to INIT (101b),
/// level assert, and edge trigger in the ICR.
/// Intel SDM Vol 3A, Section 13.6.1 "Interrupt Command Register (ICR)", Figure 13-12.
pub fn sendInitIpi(apic_id_target: u8) void {
    if (x2_apic) {
        const icr: u64 = (@as(u64, apic_id_target) << 32) | (0b101 << 8) | (1 << 14) | (1 << 15);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.interrupt_command_register), icr);
    } else {
        writeReg(.int_cmd_high_reg, @as(u32, apic_id_target) << 24);
        writeReg(.int_cmd_low_reg, (0b101 << 8) | (1 << 14) | (1 << 15));
        waitForDelivery();
    }
}

/// Send a Startup IPI (SIPI) to the target processor. Sets delivery mode to
/// Start Up (110b) with the vector specifying the real-mode entry page.
/// Intel SDM Vol 3A, Section 13.6.1 "Interrupt Command Register (ICR)", Figure 13-12.
pub fn sendSipi(apic_id_target: u8, vector: u8) void {
    if (x2_apic) {
        const icr: u64 = (@as(u64, apic_id_target) << 32) | (0b110 << 8) | vector;
        cpu.wrmsr(@intFromEnum(X2ApicMsr.interrupt_command_register), icr);
    } else {
        writeReg(.int_cmd_high_reg, @as(u32, apic_id_target) << 24);
        writeReg(.int_cmd_low_reg, (0b110 << 8) | @as(u32, vector));
        waitForDelivery();
    }
}

/// Send an IPI to the given logical core, looking up its APIC ID from the lapics table.
/// If the target is the current core, uses the self-IPI fast path.
pub fn sendIpiToCore(core_id: u64, vector: u8) void {
    if (core_id == coreID()) {
        sendSelfIpi(vector);
    } else {
        sendIpi(
            @intCast(lapics.?[core_id].apic_id),
            vector,
        );
    }
}

/// Send the scheduler-rearm IPI to `core_id`. Encapsulates the
/// `IntVecs.sched` vector choice so callers don't have to know which
/// vector the scheduler listens on.
pub fn sendSchedulerIpi(core_id: u64) void {
    sendIpiToCore(core_id, @intFromEnum(interrupts.IntVecs.sched));
}

/// Send a self-IPI. In x2APIC mode uses the dedicated Self IPI Register (MSR 83FH).
/// In xAPIC mode uses the ICR with shorthand destination "self" (bits [19:18] = 01b).
/// Intel SDM Vol 3A, Section 13.12.11 "SELF IPI Register", Figure 13-30.
pub fn sendSelfIpi(vector: u8) void {
    if (x2_apic) {
        cpu.wrmsr(@intFromEnum(X2ApicMsr.self_interrupt_register), vector);
    } else {
        writeReg(.int_cmd_high_reg, 0);
        writeReg(.int_cmd_low_reg, @as(u32, vector) | (1 << 18));
    }
}

/// Send a fixed-delivery IPI to the target processor with the given vector.
/// Intel SDM Vol 3A, Section 13.6.1 "Interrupt Command Register (ICR)", Figure 13-12.
pub fn sendIpi(apic_id_target: u8, vector: u8) void {
    if (x2_apic) {
        const icr: u64 = (@as(u64, apic_id_target) << 32) | (1 << 14) | @as(u64, vector);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.interrupt_command_register), icr);
    } else {
        writeReg(.int_cmd_high_reg, @as(u32, apic_id_target) << 24);
        writeReg(.int_cmd_low_reg, (1 << 14) | @as(u32, vector));
        waitForDelivery();
    }
}

/// Program the spurious-interrupt vector register to enable the local APIC
/// and set the spurious interrupt vector number.
/// Intel SDM Vol 3A, Section 13.9 "Spurious Interrupt", Figure 13-23.
pub fn enableSpuriousVector(vector: u8) void {
    if (x2_apic) {
        _ = cpu.enableX2Apic(vector);
    } else {
        const svr: SpuriousIntVec = .{
            .spurious_vector = vector,
            .apic_enable = true,
            .focus_check_disable = false,
            .eoi_bcast_supp = false,
        };
        writeReg(.spurious_int_vec_reg, @bitCast(svr));
    }
}
