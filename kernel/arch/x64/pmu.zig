//! x86_64 PMU façade — runtime dispatch between Intel architectural PMU
//! and AMD PerfCtr/PerfEvtSel. Follows the same vendor-dispatch pattern as
//! `kernel/arch/x64/vm.zig` (Intel VMX vs AMD SVM) and
//! `kernel/arch/x64/iommu.zig` (Intel VT-d vs AMD-Vi).
//!
//! Implements the arch-dispatched PMU interface documented in systems.md
//! §13 (Architecture Interface) and §20 (PMU Internals). This file holds
//! the shared `PmuState` type, the backend enum, the one-time vendor
//! detection, and thin dispatch wrappers. The actual MSR-level logic lives
//! in `intel/pmu.zig` and `amd/pmu.zig`.

const zag = @import("zag");

const amd_pmu = zag.arch.x64.amd.pmu;
const cpu = zag.arch.x64.cpu;
const intel_pmu = zag.arch.x64.intel.pmu;
const pmu_sched = zag.syscall.pmu;

const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PmuCounterConfig = pmu_sched.PmuCounterConfig;
const PmuInfo = pmu_sched.PmuInfo;
const PmuSample = pmu_sched.PmuSample;

/// Per-arch alias for the generic compile-time ceiling. See
/// `zag.syscall.pmu.MAX_COUNTERS` for the rationale.
pub const MAX_COUNTERS: u8 = pmu_sched.MAX_COUNTERS;

const default_config: PmuCounterConfig = .{
    .event = .cycles,
    .has_threshold = false,
    .overflow_threshold = 0,
};

/// Per-thread arch PMU state. Backend-agnostic: both Intel and AMD need
/// the same layout (configured counter count, config array, saved values).
pub const PmuState = extern struct {
    _gen_lock: GenLock = .{},
    num_counters: u8 = 0,
    _pad: [7]u8 = .{0} ** 7,
    configs: [MAX_COUNTERS]PmuCounterConfig = .{default_config} ** MAX_COUNTERS,
    values: [MAX_COUNTERS]u64 = .{0} ** MAX_COUNTERS,
};

const Backend = enum {
    none,
    intel,
    amd,
};

var active_backend: Backend = .none;

const Vendor = enum { intel, amd, unknown };

fn detectVendor() Vendor {
    const result = cpu.cpuid(.basic_max, 0);
    // "GenuineIntel" = EBX:EDX:ECX (Intel SDM Vol 2 "CPUID").
    if (result.ebx == 0x756e6547 and result.edx == 0x49656e69 and result.ecx == 0x6c65746e)
        return .intel;
    // "AuthenticAMD" = EBX:EDX:ECX (AMD APM Vol 3 Appendix E).
    if (result.ebx == 0x68747541 and result.edx == 0x69746e65 and result.ecx == 0x444d4163)
        return .amd;
    return .unknown;
}

/// BSP PMU bring-up. Detects vendor, delegates to the appropriate backend
/// for CPUID probing and PMI vector wiring. Called from `kMain` between
/// `arch.vm.vmInit()` and `sched.globalInit()`.
pub fn pmuInit() void {
    switch (detectVendor()) {
        .intel => {
            if (intel_pmu.probe()) {
                intel_pmu.init();
                active_backend = .intel;
            }
        },
        .amd => {
            if (amd_pmu.probe()) {
                amd_pmu.init();
                active_backend = .amd;
            }
        },
        .unknown => {},
    }
}

/// Per-core PMU bring-up. Required on AMD PerfMonV2 (Zen 4+) to write
/// PerfCntrGlobalCtl; no-op on Intel and pre-PerfMonV2 AMD where the
/// per-counter PerfEvtSel.EN is the sole gate.
pub fn pmuPerCoreInit() void {
    switch (active_backend) {
        .intel => {},
        .amd => amd_pmu.perCoreInit(),
        .none => {},
    }
}

pub fn pmuGetInfo() PmuInfo {
    return switch (active_backend) {
        .intel => intel_pmu.getInfo(),
        .amd => amd_pmu.getInfo(),
        .none => .{
            .num_counters = 0,
            .supported_events = 0,
            .overflow_support = false,
        },
    };
}

pub fn pmuStart(state: *PmuState, configs: []const PmuCounterConfig) !void {
    switch (active_backend) {
        .intel => try intel_pmu.start(state, configs),
        .amd => try amd_pmu.start(state, configs),
        .none => return error.NoPmu,
    }
}

pub fn pmuStop(state: *PmuState) void {
    switch (active_backend) {
        .intel => intel_pmu.stop(state),
        .amd => amd_pmu.stop(state),
        .none => {},
    }
}

pub fn pmuRead(state: *PmuState, sample: *PmuSample) void {
    switch (active_backend) {
        .intel => intel_pmu.read(state, sample),
        .amd => amd_pmu.read(state, sample),
        .none => {},
    }
}

pub fn pmuSave(state: *PmuState) void {
    switch (active_backend) {
        .intel => intel_pmu.save(state),
        .amd => amd_pmu.save(state),
        .none => {},
    }
}

pub fn pmuRestore(state: *PmuState) void {
    switch (active_backend) {
        .intel => intel_pmu.restore(state),
        .amd => amd_pmu.restore(state),
        .none => {},
    }
}

pub fn pmuConfigureState(state: *PmuState, configs: []const PmuCounterConfig) void {
    switch (active_backend) {
        .intel => intel_pmu.configureState(state, configs),
        .amd => amd_pmu.configureState(state, configs),
        .none => {},
    }
}

pub fn pmuClearState(state: *PmuState) void {
    switch (active_backend) {
        .intel => intel_pmu.clearState(state),
        .amd => amd_pmu.clearState(state),
        .none => {},
    }
}

/// kprof sample-mode NMI check. Returns true if the dedicated
/// sampling PMC overflowed and was rearmed with a fresh
/// `period_cycles` preload.
pub fn kprofSampleCheckAndRearm(period_cycles: u64) bool {
    return switch (active_backend) {
        .intel => intel_pmu.kprofSampleCheckAndRearm(period_cycles),
        .amd => amd_pmu.kprofSampleCheckAndRearm(period_cycles),
        .none => false,
    };
}

/// kprof trace-mode per-core init. Programs three PMCs for
/// free-running cycles / L1 DC refill / branch-mispredict counting.
pub fn kprofTraceCountersPerCoreInit() void {
    switch (active_backend) {
        .intel => intel_pmu.kprofTraceCountersPerCoreInit(),
        .amd => amd_pmu.kprofTraceCountersPerCoreInit(),
        .none => {},
    }
}

/// kprof trace-mode counter snapshot. Reads the three trace PMCs
/// into `out` in (cycles, cache_misses, branch_misses) order.
pub inline fn kprofTraceCountersRead(out: *[3]u64) void {
    switch (active_backend) {
        .intel => intel_pmu.kprofTraceCountersRead(out),
        .amd => amd_pmu.kprofTraceCountersRead(out),
        .none => {
            out[0] = 0;
            out[1] = 0;
            out[2] = 0;
        },
    }
}
