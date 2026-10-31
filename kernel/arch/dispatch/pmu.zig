const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

const PmuCounterConfig = stygia.syscall.pmu.PmuCounterConfig;
const PmuInfo = stygia.syscall.pmu.PmuInfo;
const PmuSample = stygia.syscall.pmu.PmuSample;

// --- PMU (performance monitoring unit) dispatch (systems.md §arch-interface, §pmu) ---

pub const PmuState = switch (builtin.cpu.arch) {
    .x86_64 => x64.pmu.PmuState,
    .aarch64 => aarch64.pmu.PmuState,
    else => @compileError("unsupported arch for PMU"),
};

/// Compile-time ceiling on the number of counter slots in `PmuSample`.
/// Duplicated from `stygia.syscall.pmu.MAX_COUNTERS` so the arch dispatch
/// layer does not force its callers to pull in `stygia.syscall.pmu` just to
/// size a stack buffer.
pub fn pmuInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuInit(),
        .aarch64 => aarch64.pmu.pmuInit(),
        else => unreachable,
    }
}

/// Per-core PMU bring-up. Required on AMD PerfMonV2 (Zen 4+) to enable
/// PerfCntrGlobalCtl; no-op on Intel x86 and on aarch64.
pub fn pmuPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuPerCoreInit(),
        .aarch64 => {},
        else => unreachable,
    }
}

pub fn pmuGetInfo() PmuInfo {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuGetInfo(),
        .aarch64 => aarch64.pmu.pmuGetInfo(),
        else => unreachable,
    };
}

pub fn pmuSave(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuSave(state),
        .aarch64 => aarch64.pmu.pmuSave(state),
        else => unreachable,
    }
}

pub fn pmuRestore(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuRestore(state),
        .aarch64 => aarch64.pmu.pmuRestore(state),
        else => unreachable,
    }
}

pub fn pmuStart(state: *PmuState, configs: []const PmuCounterConfig) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.pmu.pmuStart(state, configs),
        .aarch64 => try aarch64.pmu.pmuStart(state, configs),
        else => unreachable,
    }
}

pub fn pmuRead(state: *PmuState, sample: *PmuSample) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuRead(state, sample),
        .aarch64 => aarch64.pmu.pmuRead(state, sample),
        else => unreachable,
    }
}

pub fn pmuStop(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuStop(state),
        .aarch64 => aarch64.pmu.pmuStop(state),
        else => unreachable,
    }
}

/// Stamp `state` with `configs` without touching any hardware registers.
/// Used by the generic PMU syscall layer when an external profiler calls
/// pmu_start / pmu_reset on a non-running target thread; the target's
/// next `pmuRestore` programs the hardware when it is rescheduled.
pub fn pmuConfigureState(state: *PmuState, configs: []const PmuCounterConfig) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuConfigureState(state, configs),
        .aarch64 => aarch64.pmu.pmuConfigureState(state, configs),
        else => unreachable,
    }
}

/// Zero `state` for a non-running target without touching any hardware
/// registers. Used by pmu_stop / Thread.deinit on remote targets and on
/// thread teardown.
pub fn pmuClearState(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuClearState(state),
        .aarch64 => aarch64.pmu.pmuClearState(state),
        else => unreachable,
    }
}
