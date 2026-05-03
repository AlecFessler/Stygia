//! Intel architectural PMU backend.
//!
//! Invoked through the vendor-dispatching façade in `kernel/arch/x64/pmu.zig`.
//! All Intel-specific concepts (CPUID leaf 0x0A, IA32_PERFEVTSELx, IA32_PMCx,
//! IA32_PERF_GLOBAL_CTRL, IA32_PERF_GLOBAL_STATUS, IA32_PERF_GLOBAL_OVF_CTRL)
//! live in this file and are never visible to generic kernel code.
//!
//! Spec references:
//!   * Intel SDM Vol 3, Ch 18 "Performance Monitoring"
//!     - §18.2.1 Architectural Performance Monitoring Version 1 Facilities
//!     - §18.2.1.1 Architectural Performance Monitoring Events (table 18-1)
//!     - §18.2.1.2 Pre-defined Architectural Performance Events (table 18-2)
//!     - §18.2.2 CPUID leaf 0Ah (figures 18-6/18-7)
//!     - §18.2.3 Full-Width Writes to Performance Counter Registers
//!   * Intel SDM Vol 4 "Model-Specific Registers":
//!     - IA32_PMCx (MSR 0xC1 + x)
//!     - IA32_PERFEVTSELx (MSR 0x186 + x)
//!     - IA32_PERF_GLOBAL_CTRL (MSR 0x38F)
//!     - IA32_PERF_GLOBAL_STATUS (MSR 0x38E)
//!     - IA32_PERF_GLOBAL_OVF_CTRL (MSR 0x390)

const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const pmu_facade = zag.arch.x64.pmu;
const pmu_sched = zag.syscall.pmu;

const PmuCounterConfig = pmu_sched.PmuCounterConfig;
const PmuEvent = pmu_sched.PmuEvent;
const PmuInfo = pmu_sched.PmuInfo;
const PmuSample = pmu_sched.PmuSample;
const PmuState = pmu_facade.PmuState;
const MAX_COUNTERS = pmu_facade.MAX_COUNTERS;

// ── MSR numbers (Intel SDM Vol 4) ──────────────────────────────────────
const IA32_PMC_BASE: u32 = 0xC1;
const IA32_PERFEVTSEL_BASE: u32 = 0x186;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
const IA32_PERF_GLOBAL_STATUS: u32 = 0x38E;
const IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

// ── IA32_PERFEVTSELx bit layout (Intel SDM Vol 3 §18.2.1.1, figure 18-1) ──
//   bits  0-7:  Event Select
//   bits  8-15: Unit Mask (UMASK)
//   bit   16:   USR — count events in CPL > 0 (ring 3)
//   bit   17:   OS  — count events in CPL = 0 (ring 0)
//   bit   18:   E (edge detect)
//   bit   19:   PC (pin control)
//   bit   20:   INT — enable APIC PMI on counter overflow
//   bit   21:   ANY
//   bit   22:   EN — enable the counter
//   bit   23:   INV
//   bits 24-31: CMASK
const PERFEVTSEL_USR: u64 = 1 << 16;
const PERFEVTSEL_OS: u64 = 1 << 17;
const PERFEVTSEL_INT: u64 = 1 << 20;
const PERFEVTSEL_EN: u64 = 1 << 22;

const PMI_VECTOR: u8 = @intFromEnum(interrupts.IntVecs.pmu);

/// Architectural event index (CPUID.0AH:EBX bits [6:0], 1 bit per
/// architectural event; bit set means event is NOT available).
/// Intel SDM Vol 3 §18.2.1.2 and Table 18-1.
const ARCH_EVENT_CORE_CYCLES: u8 = 0; // UnHalted Core Cycles
const ARCH_EVENT_INST_RETIRED: u8 = 1; // Instructions Retired
const ARCH_EVENT_REF_CYCLES: u8 = 2; // UnHalted Reference Cycles
const ARCH_EVENT_LLC_REF: u8 = 3; // LLC Reference
const ARCH_EVENT_LLC_MISS: u8 = 4; // LLC Misses
const ARCH_EVENT_BR_INST_RETIRED: u8 = 5; // Branch Instruction Retired
const ARCH_EVENT_BR_MISS_RETIRED: u8 = 6; // Branch Mispredict Retired

const EventEncoding = struct {
    event_select: u8,
    unit_mask: u8,
    arch_idx: ?u8,
};

fn eventEncoding(e: PmuEvent) EventEncoding {
    return switch (e) {
        .cycles => .{ .event_select = 0x3C, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_CORE_CYCLES },
        .instructions => .{ .event_select = 0xC0, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_INST_RETIRED },
        .cache_references => .{ .event_select = 0x2E, .unit_mask = 0x4F, .arch_idx = ARCH_EVENT_LLC_REF },
        .cache_misses => .{ .event_select = 0x2E, .unit_mask = 0x41, .arch_idx = ARCH_EVENT_LLC_MISS },
        .branch_instructions => .{ .event_select = 0xC4, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_BR_INST_RETIRED },
        .branch_misses => .{ .event_select = 0xC5, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_BR_MISS_RETIRED },
        .bus_cycles => .{ .event_select = 0x3C, .unit_mask = 0x01, .arch_idx = ARCH_EVENT_REF_CYCLES },
        .stalled_cycles_frontend, .stalled_cycles_backend => .{
            .event_select = 0x00,
            .unit_mask = 0x00,
            .arch_idx = null,
        },
    };
}

var cached_info: PmuInfo = .{
    .num_counters = 0,
    .supported_events = 0,
    .overflow_support = false,
};

/// Hardware counter bit width from CPUID.0AH:EAX[23:16]. 0 means "PMU
/// not present / init bailed out".
var counter_bitwidth: u8 = 0;

/// Returns true if Intel architectural PMU v2+ is usable on this CPU.
/// Caller is the façade's detection path.
pub fn probe() bool {
    const max_basic = cpu.cpuid(.basic_max, 0).eax;
    if (max_basic < 0x0A) return false;
    const leaf = cpu.cpuidRaw(0x0A, 0);
    const version: u8 = @truncate(leaf.eax & 0xFF);
    if (version < 2) return false;
    const num_gp: u8 = @truncate((leaf.eax >> 8) & 0xFF);
    const width: u8 = @truncate((leaf.eax >> 16) & 0xFF);
    if (num_gp == 0 or width == 0) return false;
    return true;
}

/// BSP PMU bring-up. Caches PmuInfo, wires the PMI vector into the IDT.
/// Per-core LAPIC LVT programming runs from `perCoreInit`.
pub fn init() void {
    const leaf = cpu.cpuidRaw(0x0A, 0);
    const num_gp: u8 = @truncate((leaf.eax >> 8) & 0xFF);
    const width: u8 = @truncate((leaf.eax >> 16) & 0xFF);
    const ebx_len: u8 = @truncate((leaf.eax >> 24) & 0xFF);
    const ebx_bits = leaf.ebx;

    counter_bitwidth = width;

    var supported_mask: u64 = 0;
    inline for (@typeInfo(PmuEvent).@"enum".fields) |field| {
        const variant: PmuEvent = @enumFromInt(field.value);
        const enc = eventEncoding(variant);
        if (enc.arch_idx) |idx| {
            if (idx < ebx_len) {
                const shift: u5 = @intCast(idx);
                const missing = ((ebx_bits >> shift) & 1) == 1;
                if (!missing) {
                    const bit_idx: u6 = @intCast(field.value);
                    supported_mask |= @as(u64, 1) << bit_idx;
                }
            }
        }
    }

    const counters = @min(num_gp, MAX_COUNTERS);

    cached_info = .{
        .num_counters = counters,
        .supported_events = supported_mask,
        .overflow_support = true,
    };

    interrupts.registerVector(PMI_VECTOR, pmiHandler, .external);
    idt.openInterruptGate(
        PMI_VECTOR,
        interrupts.stubs[PMI_VECTOR],
        zag.arch.x64.gdt.KERNEL_CODE_OFFSET,
        .ring_0,
        .interrupt_gate,
    );
}

pub fn getInfo() PmuInfo {
    return cached_info;
}

pub fn start(state: *PmuState, configs: []const PmuCounterConfig) !void {
    programCounters(state, configs);
}

pub fn stop(state: *PmuState) void {
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    var i: u8 = 0;
    while (i < state.num_counters) {
        cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), 0);
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), 0);
        i += 1;
    }
    clearAllOverflowStatus(state.num_counters);
    state.num_counters = 0;
}

pub fn configureState(state: *PmuState, configs: []const PmuCounterConfig) void {
    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        state.values[i] = preloadValue(configs[i]);
        i += 1;
    }
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

pub fn clearState(state: *PmuState) void {
    state.num_counters = 0;
    var i: usize = 0;
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

pub fn save(state: *PmuState) void {
    if (state.num_counters == 0) return;
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    var i: u8 = 0;
    while (i < state.num_counters) {
        state.values[i] = cpu.rdmsr(IA32_PMC_BASE + @as(u32, i));
        i += 1;
    }
}

pub fn restore(state: *PmuState) void {
    if (state.num_counters == 0) return;
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    var enable_mask: u64 = 0;
    var i: u8 = 0;
    while (i < state.num_counters) {
        const cfg = state.configs[i];
        const enc = eventEncoding(cfg.event);
        cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), perfevtselWord(enc, cfg));
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), state.values[i]);
        const shift_i: u6 = @intCast(i);
        enable_mask |= @as(u64, 1) << shift_i;
        i += 1;
    }
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, enable_mask);
}

pub fn read(state: *PmuState, sample: *PmuSample) void {
    var i: usize = 0;
    while (i < sample.counters.len) {
        sample.counters[i] = 0;
        i += 1;
    }
    i = 0;
    while (i < state.num_counters) {
        sample.counters[i] = state.values[i];
        i += 1;
    }
}

fn programCounters(state: *PmuState, configs: []const PmuCounterConfig) void {
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);

    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        const enc = eventEncoding(configs[i].event);
        cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), perfevtselWord(enc, configs[i]));
        const preload = preloadValue(configs[i]);
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), preload);
        state.values[i] = preload;
        i += 1;
    }
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }

    if (n == 0) return;

    var enable_mask: u64 = 0;
    var j: u8 = 0;
    while (j < n) {
        const sh: u6 = @intCast(j);
        enable_mask |= @as(u64, 1) << sh;
        j += 1;
    }
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, enable_mask);
}

fn perfevtselWord(enc: EventEncoding, cfg: PmuCounterConfig) u64 {
    var w: u64 = 0;
    w |= @as(u64, enc.event_select);
    w |= @as(u64, enc.unit_mask) << 8;
    w |= PERFEVTSEL_USR;
    w |= PERFEVTSEL_EN;
    if (cfg.has_threshold) w |= PERFEVTSEL_INT;
    return w;
}

fn preloadValue(cfg: PmuCounterConfig) u64 {
    if (!cfg.has_threshold) return 0;
    const threshold = cfg.overflow_threshold;
    if (counter_bitwidth == 0 or counter_bitwidth >= 64) return 0;
    const bw_shift: u6 = @intCast(counter_bitwidth);
    const span: u64 = @as(u64, 1) << bw_shift;
    const clamped = if (threshold >= span) span - 1 else threshold;
    return span - clamped;
}

fn clearAllOverflowStatus(num_counters: u8) void {
    if (num_counters == 0) return;
    var mask: u64 = 0;
    var i: u8 = 0;
    while (i < num_counters) {
        const sh: u6 = @intCast(i);
        mask |= @as(u64, 1) << sh;
        i += 1;
    }
    cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, mask);
}

/// Mirror of the AMD hook. Returns false because Intel sample-mode
/// wiring isn't done yet; the NMI handler will fall through to its
/// existing (panic) policy, which is the right thing under Intel
/// until this is implemented.
pub fn kprofSampleCheckAndRearm(period_cycles: u64) bool {
    _ = period_cycles;
    return false;
}

/// Intel trace-counter stub. Wire IA32_PERFEVTSELx programming here
/// when an Intel test rig exists. Currently the host test machine is
/// AMD, so this is intentionally unimplemented.
pub fn kprofTraceCountersPerCoreInit() void {}

/// Intel trace-counter read stub. Zeros the output so trace records
/// built on Intel at least produce well-defined numbers instead of
/// garbage until the real backend lands.
pub inline fn kprofTraceCountersRead(out: *[3]u64) void {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
}

fn pmiHandler(ctx: *cpu.Context) void {
    _ = ctx;
    // The PMI vector is registered as `.external`, so `dispatchInterrupt`
    // already issues `apic.endOfInterrupt()` after this handler returns.
    // Do NOT EOI here.
    const status = cpu.rdmsr(IA32_PERF_GLOBAL_STATUS);
    cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, status);

    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);

    // TODO(spec-v3): pmu_state has been removed from ExecutionContext;
    // PMI ownership / state lookup needs to be re-wired against the new
    // PMU storage location (per-core or per-port?). Until then we panic
    // — userspace cannot start counters, so this should be unreachable
    // in practice.
    @panic("not implemented: PMI handler — pmu_state migrated off ExecutionContext");
}
