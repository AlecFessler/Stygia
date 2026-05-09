//! AMD PMU backend.
//!
//! Invoked through the vendor-dispatching façade in `kernel/arch/x64/pmu.zig`.
//! AMD does not implement Intel's architectural PMU (CPUID leaf 0x0A) on the
//! processors this kernel targets, so we program the AMD-specific PerfCtr /
//! PerfEvtSel MSRs directly.
//!
//! Spec references:
//!   * AMD APM Vol 2, Ch 13 "Hardware Performance Monitoring"
//!     - §13.2.1 Legacy PMC MSRs (0xC001_0000..0xC001_0007)
//!     - §13.2.2 Extended PMC MSRs (0xC001_0200..0xC001_020B, PerfCtrExtCore)
//!     - §13.2.3 PerfEvtSel register layout
//!   * AMD APM Vol 3 Appendix E, CPUID Fn8000_0001h ECX bit 23 (PerfCtrExtCore)
//!   * AMD APM Vol 2 §16.4 "Local APIC LVT PerfMon Entry" — same LAPIC LVT
//!     register as Intel; the PMI is delivered as a fixed-vector interrupt
//!     via the existing IDT wiring.
//!
//! Differences from Intel:
//!   * Pre-PerfMonV2 AMD: each counter is enabled independently by its
//!     own PerfEvtSel.EN bit. PerfMonV2 (CPUID Fn8000_0022 EAX bit 0,
//!     present on Zen 4+) adds PerfCntrGlobalCtl (MSR 0xC000_0301), an
//!     additional per-core gate — bit i must be set for PMC i to tick
//!     even when PerfEvtSel.EN is set. We program GlobalCtl to the
//!     all-PMCs-enabled mask once per core in `perCoreInit`, leaving
//!     PerfEvtSel.EN as the per-counter gate as before.
//!   * Counters are 48 bits wide on all supported AMD families.
//!   * Event codes differ from Intel; we only encode the always-present
//!     core events (cycles, retired instructions, branches, mispredicts).

const std = @import("std");
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

// ── Legacy PMC MSRs (AMD APM Vol 2 §13.2.1) ────────────────────────────
//   PerfEvtSel0..3 at 0xC001_0000..0xC001_0003
//   PerfCtr0..3    at 0xC001_0004..0xC001_0007
const LEGACY_PERFEVTSEL_BASE: u32 = 0xC001_0000;
const LEGACY_PERFCTR_BASE: u32 = 0xC001_0004;

// ── Extended PMC MSRs (AMD APM Vol 2 §13.2.2, PerfCtrExtCore) ─────────
//   Interleaved layout: PerfEvtSel0=0xC001_0200, PerfCtr0=0xC001_0201,
//   PerfEvtSel1=0xC001_0202, PerfCtr1=0xC001_0203, ...
//   Six counters total (indices 0..5).
const EXT_BASE: u32 = 0xC001_0200;

// ── PerfEvtSel bit layout (AMD APM Vol 2 §13.2.3) ──────────────────────
// Identical to Intel for the low 32 bits we use here:
//   bits  0-7:  Event Select [7:0]
//   bits  8-15: Unit Mask
//   bit   16:   USR
//   bit   17:   OS
//   bit   20:   INT (APIC interrupt on overflow)
//   bit   22:   EN
//   bits 32-35: Event Select [11:8] (AMD extension for 12-bit event codes)
const PERFEVTSEL_USR: u64 = 1 << 16;
const PERFEVTSEL_INT: u64 = 1 << 20;
const PERFEVTSEL_EN: u64 = 1 << 22;

// ── PerfMonV2 (AMD APM Vol 2 §13.2.4) ──────────────────────────────────
// CPUID Fn8000_0022 EAX bit 0 = PerfMonV2 supported. When present, every
// PMC is gated by PerfCntrGlobalCtl in addition to its PerfEvtSel.EN bit
// — bit i = enable PMC i. Without writing GlobalCtl the counter never
// ticks even with EN set, which is what PMC0 returning 0 looks like on
// Zen 4 KVM guests.
//
// MSR layout per Linux's `arch/x86/include/asm/msr-index.h`
// (MSR_AMD64_PERF_CNTR_GLOBAL_*):
//   0xC000_0300  PerfCntrGlobalStatus      (RO)
//   0xC000_0301  PerfCntrGlobalCtl         (RW)
//   0xC000_0302  PerfCntrGlobalStatusClr   (WO)
const PERFMON_V2_LEAF: u32 = 0x8000_0022;
const PERFCNTR_GLOBAL_STATUS: u32 = 0xC000_0300;
const PERFCNTR_GLOBAL_CTL: u32 = 0xC000_0301;
const PERFCNTR_GLOBAL_STATUS_CLR: u32 = 0xC000_0302;

const PMI_VECTOR: u8 = @intFromEnum(interrupts.IntVecs.pmu);

/// AMD counters are 48 bits wide across all supported families (K8+).
const AMD_COUNTER_BITS: u8 = 48;

/// Extended-core PMC layout: PerfEvtSel and PerfCtr are interleaved,
/// two MSRs per counter index.
var use_extended: bool = false;

var cached_info: PmuInfo = .{
    .num_counters = 0,
    .supported_events = 0,
    .overflow_support = false,
};

/// PerfMonV2 detected by `init` via CPUID Fn8000_0022 EAX bit 0. When
/// true, `perCoreInit` programs PerfCntrGlobalCtl on each core.
var has_perfmon_v2: bool = false;

const EventEncoding = struct {
    /// Low 8 bits of the 12-bit event select. High 4 bits are zero for
    /// every event we currently encode.
    event_select: u8,
    unit_mask: u8,
    supported: bool,
};

fn eventEncoding(e: PmuEvent) EventEncoding {
    // Event codes are from AMD APM Vol 2 Appendix A "Core Performance Event
    // Reference" — common events across Zen 1/2/3/4/5 families. The cache
    // event approximations below (DC access / DC refill) don't match Intel's
    // LLC definitions exactly; they're the best general-purpose Zen analogs.
    return switch (e) {
        // CPU Clocks not Halted (event 0x76).
        .cycles => .{ .event_select = 0x76, .unit_mask = 0x00, .supported = true },
        // Retired Instructions (event 0xC0).
        .instructions => .{ .event_select = 0xC0, .unit_mask = 0x00, .supported = true },
        // Retired Branch Instructions (event 0xC2).
        .branch_instructions => .{ .event_select = 0xC2, .unit_mask = 0x00, .supported = true },
        // Retired Branch Instructions Mispredicted (event 0xC3).
        .branch_misses => .{ .event_select = 0xC3, .unit_mask = 0x00, .supported = true },
        // Data Cache Accesses (event 0x40) — L1 DC access rate. The closest
        // Zen analog to Intel's "LLC reference"; agents using this for
        // cross-vendor comparison should treat the number as a cache-access
        // proxy rather than a strict LLC metric.
        .cache_references => .{ .event_select = 0x40, .unit_mask = 0x00, .supported = true },
        // Data Cache Refills from L2 or System (event 0x43) — L1 DC miss
        // refill rate. Zen analog to "LLC miss"; same caveat.
        .cache_misses => .{ .event_select = 0x43, .unit_mask = 0x00, .supported = true },
        // Stall and bus-cycle events are family-specific. Report unsupported;
        // the generic syscall layer filters these out of any pmu_start.
        else => .{ .event_select = 0x00, .unit_mask = 0x00, .supported = false },
    };
}

fn perfevtselMsr(counter: u8) u32 {
    if (use_extended) return EXT_BASE + @as(u32, counter) * 2;
    return LEGACY_PERFEVTSEL_BASE + @as(u32, counter);
}

fn perfctrMsr(counter: u8) u32 {
    if (use_extended) return EXT_BASE + 1 + @as(u32, counter) * 2;
    return LEGACY_PERFCTR_BASE + @as(u32, counter);
}

pub fn probe() bool {
    // Vendor string is checked by the façade before this runs. Detect
    // extended-core PMCs via CPUID Fn8000_0001 ECX bit 23 (PerfCtrExtCore).
    const ext_max = cpu.cpuid(.ext_max, 0).eax;
    if (ext_max < 0x8000_0001) return false;
    return true;
}

pub fn init() void {
    const ext_features = cpu.cpuid(.ext_features, 0);
    const has_ext = (ext_features.ecx & (1 << 23)) != 0;

    use_extended = has_ext;
    const raw_counters: u8 = if (has_ext) 6 else 4;
    const counters = @min(raw_counters, MAX_COUNTERS);

    const ext_max = cpu.cpuid(.ext_max, 0).eax;
    if (ext_max >= PERFMON_V2_LEAF) {
        has_perfmon_v2 = (cpu.cpuidRaw(PERFMON_V2_LEAF, 0).eax & 1) != 0;
    }

    var supported_mask: u64 = 0;
    inline for (@typeInfo(PmuEvent).@"enum".fields) |field| {
        const variant: PmuEvent = @enumFromInt(field.value);
        if (eventEncoding(variant).supported) {
            const bit_idx: u6 = @intCast(field.value);
            supported_mask |= @as(u64, 1) << bit_idx;
        }
    }

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

/// Per-core PMU bring-up. On PerfMonV2 hardware the global enable mask
/// gates every PMC; without this write PerfEvtSel.EN is necessary but
/// not sufficient, so userspace `perfmon_start` and kprof trace counters
/// silently read back zero. Pre-PerfMonV2 cores have no GlobalCtl — the
/// PerfEvtSel.EN bit is the sole gate, so this is a no-op.
pub fn perCoreInit() void {
    if (!has_perfmon_v2) return;
    const all_pmcs: u64 = (@as(u64, 1) << @intCast(cached_info.num_counters)) - 1;
    cpu.wrmsr(PERFCNTR_GLOBAL_CTL, all_pmcs);
}

pub fn getInfo() PmuInfo {
    return cached_info;
}

pub fn start(state: *PmuState, configs: []const PmuCounterConfig) !void {
    programCounters(state, configs);
}

pub fn stop(state: *PmuState) void {
    var i: u8 = 0;
    while (i < state.num_counters) {
        cpu.wrmsr(perfevtselMsr(i), 0);
        cpu.wrmsr(perfctrMsr(i), 0);
        i += 1;
    }
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
    // Disable each counter first so the readback reflects the exact
    // end-of-timeslice value. AMD has no global disable, so we clear
    // EN per counter.
    var i: u8 = 0;
    while (i < state.num_counters) {
        cpu.wrmsr(perfevtselMsr(i), 0);
        i += 1;
    }
    i = 0;
    while (i < state.num_counters) {
        state.values[i] = cpu.rdmsr(perfctrMsr(i)) & COUNTER_MASK;
        i += 1;
    }
}

pub fn restore(state: *PmuState) void {
    if (state.num_counters == 0) return;
    var i: u8 = 0;
    while (i < state.num_counters) {
        const cfg = state.configs[i];
        const enc = eventEncoding(cfg.event);
        cpu.wrmsr(perfctrMsr(i), state.values[i]);
        cpu.wrmsr(perfevtselMsr(i), perfevtselWord(enc, cfg));
        i += 1;
    }
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

const COUNTER_MASK: u64 = (@as(u64, 1) << AMD_COUNTER_BITS) - 1;

fn programCounters(state: *PmuState, configs: []const PmuCounterConfig) void {
    // Disable any previously configured counters first so no in-flight
    // PMI fires against half-reprogrammed state.
    var k: u8 = 0;
    while (k < state.num_counters) {
        cpu.wrmsr(perfevtselMsr(k), 0);
        k += 1;
    }

    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        const enc = eventEncoding(configs[i].event);
        const preload = preloadValue(configs[i]);
        cpu.wrmsr(perfctrMsr(i), preload);
        cpu.wrmsr(perfevtselMsr(i), perfevtselWord(enc, configs[i]));
        state.values[i] = preload;
        i += 1;
    }
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

fn perfevtselWord(enc: EventEncoding, cfg: PmuCounterConfig) u64 {
    var w: u64 = 0;
    w |= @as(u64, enc.event_select);
    w |= @as(u64, enc.unit_mask) << 8;
    // Count in user mode (ring 3) only — kernel activity on the thread's
    // core would otherwise be attributed to whichever thread was running
    // when e.g. a timer tick fires.
    w |= PERFEVTSEL_USR;
    w |= PERFEVTSEL_EN;
    if (cfg.has_threshold) w |= PERFEVTSEL_INT;
    return w;
}

/// Preload so the counter overflows exactly `overflow_threshold` events
/// from now. AMD counters are 48 bits wide; overflow fires when the
/// register wraps past `2**48`. Preload with `(2**48) - threshold`.
fn preloadValue(cfg: PmuCounterConfig) u64 {
    if (!cfg.has_threshold) return 0;
    const threshold = cfg.overflow_threshold;
    const span: u64 = @as(u64, 1) << AMD_COUNTER_BITS;
    const clamped = if (threshold >= span) span - 1 else threshold;
    return span - clamped;
}

/// PMC index reserved for kprof sample-mode. Userspace `perfmon_start`
/// allocates from PMC0 upward, so sample mode claims the top slot of
/// AMD's 6 extended PMCs (0xC001_0200..0xC001_020B) — same top-of-range
/// strategy as trace mode (`KPROF_PMC_CYCLES/CACHE_MISSES/BRANCH_MISSES`
/// at 3/4/5). Sample and trace modes are mutually exclusive build modes
/// (`-Dkernel_profile={sample,trace}`), so sample reuses slot 5 here.
const KPROF_SAMPLE_PMC: u8 = 5;

/// Program `KPROF_SAMPLE_PMC` for cycle-overflow sampling and flip the
/// LAPIC LVT PerfMon entry to NMI delivery so the PMI fires even when
/// interrupts are masked. Called once per core under `-Dkernel_profile=sample`.
///
/// AMD APM Vol 2, Appendix A: event 0x76 = "CPU Clocks not Halted".
/// AMD APM Vol 2 §16.4 + Intel SDM Vol 3A §12.5.1: LVT delivery-mode
/// field is bits [10:8] — value 0b100 selects NMI delivery.
/// Program PMCs 0/1/2 for free-running cycles / L1 DC refill /
/// branch-mispredict counting. No overflow interrupt — the trace
/// helpers just RDMSR these at each tracepoint. Runs exclusively
/// under `-Dkernel_profile=trace`; sample mode uses the overflow
/// path in `kprofSamplePerCoreInit` instead.
///
/// Event codes + unit masks: AMD APM Vol 2 Appendix A "Core
/// Performance Event Reference" (Zen family).
///   PMC0: event 0x76 umask 0x00 = CPU Clocks not Halted
///   PMC1: event 0x43 umask 0xFF = Data Cache Refills from L2/System
///         (all refill sources). An umask of 0 counts nothing, which
///         is why the first attempt showed cmiss=0 everywhere.
///   PMC2: event 0xC3 umask 0x00 = Retired Branch Mispredicts
/// Counter slots reserved for kprof. Userspace `perfmon_start`
/// allocates from PMC0 upward; kprof picks the top 3 of AMD's 6
/// extended PMCs (0xC001_0200..0xC001_020B) so the two never overlap
/// — without this split, a perfmon test running mid-trace would
/// silently zero PMC0 and the kprof scope deltas would all read 0.
pub const KPROF_PMC_CYCLES: u8 = 3;
pub const KPROF_PMC_CACHE_MISSES: u8 = 4;
pub const KPROF_PMC_BRANCH_MISSES: u8 = 5;

pub fn kprofTraceCountersPerCoreInit() void {
    const cfg = [_]struct { pmc: u8, event: u8, umask: u8 }{
        .{ .pmc = KPROF_PMC_CYCLES, .event = 0x76, .umask = 0x00 },
        .{ .pmc = KPROF_PMC_CACHE_MISSES, .event = 0x43, .umask = 0xFF },
        .{ .pmc = KPROF_PMC_BRANCH_MISSES, .event = 0xC3, .umask = 0x00 },
    };
    const PERFEVTSEL_OS: u64 = 1 << 17;
    var i: usize = 0;
    while (i < cfg.len) {
        const c = cfg[i];
        cpu.wrmsr(perfevtselMsr(c.pmc), 0);
        cpu.wrmsr(perfctrMsr(c.pmc), 0);
        const word: u64 =
            @as(u64, c.event) |
            (@as(u64, c.umask) << 8) |
            PERFEVTSEL_USR |
            PERFEVTSEL_OS |
            PERFEVTSEL_EN;
        cpu.wrmsr(perfevtselMsr(c.pmc), word);
        i += 1;
    }
}

/// Snapshot the three trace counters. Masked to AMD's 48-bit
/// counter width so the raw MSR value doesn't carry high-bit noise.
pub inline fn kprofTraceCountersRead(out: *[3]u64) void {
    out[0] = cpu.rdmsr(perfctrMsr(KPROF_PMC_CYCLES)) & COUNTER_MASK;
    out[1] = cpu.rdmsr(perfctrMsr(KPROF_PMC_CACHE_MISSES)) & COUNTER_MASK;
    out[2] = cpu.rdmsr(perfctrMsr(KPROF_PMC_BRANCH_MISSES)) & COUNTER_MASK;
}

/// Called from the NMI handler. Reads `KPROF_SAMPLE_PMC` — if it's
/// below the preload value, the counter wrapped past 2^48 and fired
/// an NMI that belongs to kprof; in that case we rearm with a fresh
/// preload and return true. Otherwise the NMI is for someone else.
///
/// The LAPIC auto-sets the LVT PerfMon mask bit (bit 16) when it
/// delivers a PerfMon interrupt (Intel SDM Vol 3 §10.5.1 — AMD LAPIC
/// is Intel-compatible). If the handler only writes the counter MSR
/// and never touches the LVT entry, exactly one NMI fires per core
/// and subsequent overflows are silently masked. We re-write the LVT
/// entry here on every rearm to clear the mask and keep the overflow
/// interrupt live.
pub fn kprofSampleCheckAndRearm(period_cycles: u64) bool {
    const span: u64 = @as(u64, 1) << AMD_COUNTER_BITS;
    const clamped = if (period_cycles == 0 or period_cycles >= span) span - 1 else period_cycles;
    const preload = span - clamped;

    const val = cpu.rdmsr(perfctrMsr(KPROF_SAMPLE_PMC)) & COUNTER_MASK;
    if (val >= preload) return false;

    cpu.wrmsr(perfctrMsr(KPROF_SAMPLE_PMC), preload);

    // Clear the auto-set LVT PerfMon mask bit by re-writing the LVT
    // entry with NMI delivery and no mask.
    const NMI_DELIVERY: u32 = 0b100 << 8;
    const lvt: u32 = @as(u32, PMI_VECTOR) | NMI_DELIVERY;
    if (apic.x2_apic) {
        cpu.wrmsr(
            @intFromEnum(apic.X2ApicMsr.local_vector_table_performance_monitor_register),
            @as(u64, lvt),
        );
    } else {
        apic.writeReg(.lvt_perf_monitoring_counters_reg, lvt);
    }
    return true;
}

/// AMD PMU overflow handler. Registered on the LAPIC PerfMon vector
/// via `interrupts.registerVector(PMI_VECTOR, ..., .external)`, so
/// `dispatchInterrupt` issues the LAPIC EOI after this returns — the
/// handler MUST NOT EOI here.
///
/// Behavior (mirrors aarch64 PMUv3 PMI in `arch/aarch64/pmu.zig`):
///   1. Detect which PMCs overflowed.
///        * PerfMonV2 (Zen 4+): read `PerfCntrGlobalStatus`
///          (MSR 0xC000_0300) — bit n = PMC n overflow flag.
///          AMD APM Vol 2 §13.2.4.
///        * Pre-PerfMonV2: AMD has no architectural global status MSR,
///          so we infer overflow from the per-counter PMC value: an
///          armed counter that is currently below its preload value
///          must have wrapped past 2^48 and re-entered the low region
///          (AMD APM Vol 2 §13.2.1 / §13.2.3 — the overflow interrupt
///          is fired on counter wrap, and the EN bit stays asserted).
///   2. For every overflowed PMC owned by the running EC's configured
///      counter range, re-arm by writing the configured preload to
///      the per-counter PMC register (`PerfCtrx`).
///   3. Clear the overflow flag.
///        * PerfMonV2: write 1 to bit n of `PerfCntrGlobalStatusClr`
///          (MSR 0xC000_0302). AMD APM Vol 2 §13.2.4.
///        * Pre-PerfMonV2: the per-counter PMC write in step 2 already
///          re-arms the counter past the wrap, so no separate clear is
///          required (the wrap detection is purely value-based).
///   4. Deliver a single `.pmu_overflow` event to the running EC via
///      `port.firePmuOverflow`. Subcode = lowest-index overflowed PMC.
///      Spec §[event_route] no-route fallback drops the event and the
///      EC keeps running.
///
/// Defensive paths: if no EC is dispatched on this core or the EC has
/// no `perfmon_state` attached, we still clear the overflow source
/// (PerfMonV2 status clear, or per-counter EN disable on pre-V2) so a
/// subsequent ERET does not re-trigger the PMI on the same residual
/// flags.
fn pmiHandler(ctx: *cpu.Context) void {
    _ = ctx;

    const ec_opt = scheduler.currentEc();

    // Without a running EC we have no way to identify which counter
    // wrapped on pre-V2 hardware (no global status MSR). On V2 we can
    // still ack the global status. In both cases mask the LAPIC LVT
    // entry's contributing counters by zeroing every PerfEvtSelx so
    // residual EN bits can't re-trigger the PMI on ERET.
    if (ec_opt == null or ec_opt.?.perfmon_state == null) {
        if (has_perfmon_v2) {
            const status = cpu.rdmsr(PERFCNTR_GLOBAL_STATUS) & gpCounterMask();
            if (status != 0) cpu.wrmsr(PERFCNTR_GLOBAL_STATUS_CLR, status);
        }
        var i: u8 = 0;
        while (i < cached_info.num_counters) {
            cpu.wrmsr(perfevtselMsr(i), 0);
            i += 1;
        }
        return;
    }

    const ec = ec_opt.?;
    const ps_ref = ec.perfmon_state.?;
    const ps_lr = ps_ref.lockIrqSave(@src()) catch {
        if (has_perfmon_v2) {
            const status = cpu.rdmsr(PERFCNTR_GLOBAL_STATUS) & gpCounterMask();
            if (status != 0) cpu.wrmsr(PERFCNTR_GLOBAL_STATUS_CLR, status);
        }
        var i: u8 = 0;
        while (i < cached_info.num_counters) {
            cpu.wrmsr(perfevtselMsr(i), 0);
            i += 1;
        }
        return;
    };
    const ps = ps_lr.ptr;
    const ps_irq_state = ps_lr.irq_state;
    const state = &ps.arch_state;

    const overflow_mask = detectOverflow(state);
    if (overflow_mask == 0) {
        ps_ref.unlockIrqRestore(ps_irq_state);
        return;
    }

    var lowest_idx: u8 = 0xFF;
    var remaining = overflow_mask;
    while (remaining != 0) {
        const i: u8 = @intCast(@ctz(remaining));
        const sh: u6 = @intCast(i);
        remaining &= ~(@as(u64, 1) << sh);
        if (lowest_idx == 0xFF) lowest_idx = i;
        if (i >= state.num_counters) {
            cpu.wrmsr(perfevtselMsr(i), 0);
            continue;
        }
        const cfg = state.configs[i];
        if (!cfg.has_threshold) continue;
        const preload = preloadValue(cfg);
        cpu.wrmsr(perfctrMsr(i), preload);
        state.values[i] = preload;
    }

    // PerfMonV2: write-1-to-clear so the LAPIC PerfMon line deasserts.
    // Pre-V2 has no architectural status MSR; the per-counter
    // PMC re-preload above is the entire ack — the LAPIC PerfMon LVT
    // mask bit will be auto-cleared by the EOI path.
    if (has_perfmon_v2) {
        cpu.wrmsr(PERFCNTR_GLOBAL_STATUS_CLR, overflow_mask);
    }

    ps_ref.unlockIrqRestore(ps_irq_state);

    if (lowest_idx == 0xFF) return;

    port_mod.firePmuOverflow(ec, lowest_idx);

    const core: u8 = @truncate(apic.coreID());
    if (!scheduler.coreCurrentIs(core, ec)) {
        scheduler.preempt();
    }
}

/// Mask covering all configurable PMC slots on this CPU. Used to
/// filter PerfCntrGlobalStatus and to bound pre-V2 PMC scans.
fn gpCounterMask() u64 {
    const n = cached_info.num_counters;
    if (n == 0) return 0;
    if (n >= 64) return ~@as(u64, 0);
    const sh: u6 = @intCast(n);
    return (@as(u64, 1) << sh) - 1;
}

/// Build a bitmap of PMC indices whose hardware counter overflowed.
///
/// PerfMonV2 (Zen 4+): exact via `PerfCntrGlobalStatus` (AMD APM Vol 2
/// §13.2.4). Pre-V2: AMD does not expose an architectural overflow
/// status MSR, so we infer overflow from the counter value — an armed
/// counter (`has_threshold`) that currently reads below its preload
/// must have wrapped past 2^48 and re-entered the low region. Same
/// approach as `kprofSampleCheckAndRearm`. The 48-bit counter
/// guarantees no false positives at any realistic event rate within
/// the PMI service window.
fn detectOverflow(state: *PmuState) u64 {
    if (cached_info.num_counters == 0) return 0;

    if (has_perfmon_v2) {
        return cpu.rdmsr(PERFCNTR_GLOBAL_STATUS) & gpCounterMask();
    }

    var mask: u64 = 0;
    var i: u8 = 0;
    while (i < state.num_counters) : (i += 1) {
        const cfg = state.configs[i];
        if (!cfg.has_threshold) continue;
        const preload = preloadValue(cfg);
        const val = cpu.rdmsr(perfctrMsr(i)) & COUNTER_MASK;
        if (val < preload) {
            const sh: u6 = @intCast(i);
            mask |= @as(u64, 1) << sh;
        }
    }
    return mask;
}
