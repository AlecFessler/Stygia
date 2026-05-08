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

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const pmu_facade = zag.arch.x64.pmu;
const pmu_sched = zag.syscall.pmu;
const port_mod = zag.sched.port;
const scheduler = zag.sched.scheduler;

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

/// PMU overflow handler. Registered on the LAPIC PerfMon vector via
/// `interrupts.registerVector(PMI_VECTOR, ..., .external)`, so
/// `dispatchInterrupt` issues `apic.endOfInterrupt()` after this returns
/// — the handler MUST NOT EOI here.
///
/// Behavior (mirrors aarch64 PMUv3 PMI in `arch/aarch64/pmu.zig`):
///   1. Read `IA32_PERF_GLOBAL_STATUS` (MSR 0x38E) to find the
///      overflow-status bitmap. Intel SDM Vol 3B §19.2.1 / §19.2.4:
///      bits [0..N-1] of GLOBAL_STATUS map to GP PMC overflow flags
///      (one bit per `IA32_PMCx`). Bits 32+ cover fixed counters and
///      the trace overflow which we do not configure here.
///   2. For every overflowed PMC slot owned by the running EC's
///      configured counter range, re-arm by writing the configured
///      preload via `IA32_PMCx` (MSR 0xC1+x). Without re-preload the
///      counter would only wrap again after a full 2^width events,
///      losing the configured `overflow_threshold` periodicity (Intel
///      SDM Vol 3B §19.2.3 "Full-Width Writes").
///   3. Write the overflowed bitmap back to
///      `IA32_PERF_GLOBAL_STATUS_RESET` (MSR 0x390 — same MSR alias as
///      `IA32_PERF_GLOBAL_OVF_CTRL` on PMU v1/v2; per Intel SDM Vol 3B
///      §19.2.4 writing 1 to bit n clears `GLOBAL_STATUS[n]`) so the
///      LAPIC PerfMon line deasserts.
///   4. Re-enable the counters via `IA32_PERF_GLOBAL_CTRL` (MSR 0x38F)
///      so the re-armed counters keep ticking after we ERET. The
///      hardware does NOT auto-disable counters on overflow on Intel
///      v2+ — only the LAPIC LVT PerfMon mask bit is auto-set, which
///      we don't manipulate here (the LAPIC EOI path re-arms the
///      vector). Restoring `GLOBAL_CTRL` to the active mask matches
///      the value `programCounters` last wrote.
///   5. Deliver a single `.pmu_overflow` event to the running EC via
///      `port.firePmuOverflow`. Subcode = lowest-index overflowed
///      PMC. Spec §[event_route] no-route fallback drops the event
///      and the EC keeps running.
///
/// Defensive paths: if no EC is dispatched on this core or the EC has
/// no `perfmon_state` attached, we still clear the overflow bits and
/// disable the contributing counters so a subsequent ERET does not
/// re-trigger the PMI on the same residual flags.
fn pmiHandler(ctx: *cpu.Context) void {
    _ = ctx;

    const status = cpu.rdmsr(IA32_PERF_GLOBAL_STATUS);
    // GP-PMC overflow bits are the low 32; we never arm fixed counters
    // or the trace overflow on this kernel, so mask the relevant bits.
    const gp_overflow = status & gpCounterMask();
    if (gp_overflow == 0) return;

    const ec_opt = scheduler.currentEc();

    // Defensive cleanup: no EC is dispatched, or it has no perfmon
    // state. Clear the overflow bits and zero the matching
    // PERFEVTSELx slots so the PMI doesn't re-fire on ERET.
    if (ec_opt == null or ec_opt.?.perfmon_state == null) {
        cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, gp_overflow);
        var cleanup_remaining = gp_overflow;
        while (cleanup_remaining != 0) {
            const i: u8 = @intCast(@ctz(cleanup_remaining));
            const sh: u6 = @intCast(i);
            cleanup_remaining &= ~(@as(u64, 1) << sh);
            cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), 0);
        }
        return;
    }

    const ec = ec_opt.?;
    const ps_ref = ec.perfmon_state.?;
    const ps_lr = ps_ref.lockIrqSave(@src()) catch {
        // Slab gen flipped — perfmon was deallocated by a remote
        // core between our null-check and lock. Fall back to the
        // defensive cleanup path.
        cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, gp_overflow);
        var cleanup_remaining = gp_overflow;
        while (cleanup_remaining != 0) {
            const i: u8 = @intCast(@ctz(cleanup_remaining));
            const sh: u6 = @intCast(i);
            cleanup_remaining &= ~(@as(u64, 1) << sh);
            cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), 0);
        }
        return;
    };
    const ps = ps_lr.ptr;
    const ps_irq_state = ps_lr.irq_state;
    const state = &ps.arch_state;

    // Stop counting while we re-preload to avoid races between
    // PMC writes and live counting (Intel SDM Vol 3B §19.2.3
    // recommends disabling via GLOBAL_CTRL before MSR full-width
    // writes when the counter is enabled).
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);

    var lowest_idx: u8 = 0xFF;
    var enable_mask: u64 = 0;
    var remaining = gp_overflow;
    while (remaining != 0) {
        const i: u8 = @intCast(@ctz(remaining));
        const sh: u6 = @intCast(i);
        remaining &= ~(@as(u64, 1) << sh);
        if (lowest_idx == 0xFF) lowest_idx = i;
        if (i >= state.num_counters) {
            // Not ours — disable the contributing PERFEVTSEL so it
            // can't fire again before the EC is rebound.
            cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), 0);
            continue;
        }
        const cfg = state.configs[i];
        if (!cfg.has_threshold) continue;
        const preload = preloadValue(cfg);
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), preload);
        state.values[i] = preload;
        enable_mask |= @as(u64, 1) << sh;
    }

    // Add back any previously-active counters that weren't part of
    // this overflow set, so we restore the full enable mask.
    var j: u8 = 0;
    while (j < state.num_counters) {
        const sh: u6 = @intCast(j);
        const bit: u64 = @as(u64, 1) << sh;
        if ((gp_overflow & bit) == 0) enable_mask |= bit;
        j += 1;
    }

    // Write-1-to-clear the overflow flags. GLOBAL_STATUS_RESET
    // (alias 0x390) is the documented clear path (Intel SDM Vol 3B
    // §19.2.4).
    cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, gp_overflow);

    // Re-enable counters.
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, enable_mask);

    ps_ref.unlockIrqRestore(ps_irq_state);

    if (lowest_idx == 0xFF) return;

    port_mod.firePmuOverflow(ec, lowest_idx);

    // If event delivery suspended the EC (route bound), drive the
    // scheduler so this core dispatches the next ready EC instead of
    // ERET-ing back to the now-parked context.
    const core: u8 = @truncate(apic.coreID());
    if (!scheduler.coreCurrentIs(core, ec)) {
        scheduler.preempt();
    }
}

/// Mask covering all general-purpose PMC slots configurable on this
/// CPU. Bit n = 1 means `IA32_PMCn` is in scope. Used to filter
/// `IA32_PERF_GLOBAL_STATUS` so we ignore fixed-counter / uncore /
/// trace overflow flags this kernel never arms.
fn gpCounterMask() u64 {
    const n = cached_info.num_counters;
    if (n == 0) return 0;
    if (n >= 64) return ~@as(u64, 0);
    const sh: u6 = @intCast(n);
    return (@as(u64, 1) << sh) - 1;
}
