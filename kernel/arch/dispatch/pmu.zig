const builtin = @import("builtin");
const std = @import("std");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const paging = stygia.arch.dispatch.paging;
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

/// Called from the NMI handler. Returns true if PMC 0 overflowed and
/// was rearmed with a fresh `period_cycles` preload — i.e. this NMI
/// belongs to kprof. Returns false for any non-sampling NMI.
pub fn kprofSampleCheckAndRearm(period_cycles: u64) bool {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.pmu.kprofSampleCheckAndRearm(period_cycles),
        .aarch64 => return false,
        else => unreachable,
    }
}

/// Program PMCs 0/1/2 on the local core for free-running
/// cycles / cache-miss / branch-mispredict counting. Called under
/// `-Dkernel_profile=trace` from `sched.perCoreInit`. Counters run
/// unattended forever; the trace helpers in `kprof.trace_id`
/// snapshot them into each emitted record so the post-processor
/// can compute per-scope deltas.
pub fn kprofTraceCountersPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.kprofTraceCountersPerCoreInit(),
        .aarch64 => {},
        else => unreachable,
    }
}

/// Read the three free-running trace counters into `out` in the
/// order (cycles, cache_misses, branch_misses). NMI-safe: pure
/// RDMSR reads, no allocation, no locks. On aarch64 (stub) fills
/// with zeros.
pub inline fn kprofTraceCountersRead(out: *[3]u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.kprofTraceCountersRead(out),
        .aarch64 => {
            out[0] = 0;
            out[1] = 0;
            out[2] = 0;
        },
        else => unreachable,
    }
}

/// NMI-safe read of a `u64` at a supposed kernel virtual address.
///
/// Returns `null` if the address is obviously not a valid kernel
/// pointer (zero, not 8-byte aligned, or not in the upper / kernel
/// half of the virtual address space). Used by the kprof sample-mode
/// frame-pointer unwinder, which must never fault: every pointer
/// dereferenced on the interrupted stack is passed through this
/// helper first.
///
/// A caller is still responsible for being reasonable about the
/// address — this helper assumes the kernel half of virtual memory
/// is fully mapped on the current core (which is true for Stygia: kernel
/// code + stacks + physmap are all pre-mapped by boot and never torn
/// down). It does not probe the page tables.
pub fn readKernelU64Safe(addr: u64) ?u64 {
    if (addr == 0) return null;
    if ((addr & 0x7) != 0) return null;
    // Kernel half starts at `addr_space.kernel.start` on both
    // supported architectures (see the canonical layout above).
    if (addr < paging.addr_space.kernel.start) return null;
    // Last 8 bytes must be in-range — reject a pointer that straddles
    // the top of canonical space (defensive; never hit in practice).
    if (addr > std.math.maxInt(u64) - 8) return null;
    const ptr: *const u64 = @ptrFromInt(addr);
    return ptr.*;
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

