const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

pub fn coreCount() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.coreCount(),
        .aarch64 => aarch64.gic.coreCount(),
        else => unreachable,
    };
}

pub fn coreID() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.coreID(),
        .aarch64 => aarch64.gic.coreID(),
        else => unreachable,
    };
}

pub fn smpInit() !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.smp.smpInit(),
        .aarch64 => try aarch64.smp.smpInit(),
        else => unreachable,
    }
}

pub fn triggerSchedulerInterrupt(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendSchedulerIpi(core_id),
        .aarch64 => aarch64.gic.sendSchedulerIpi(core_id),
        else => unreachable,
    }
}


// ── Spec v3 SMP primitives ───────────────────────────────────────────

/// Cross-core wake reuses the scheduler-rearm vector on x86: an idle
/// core parked in HLT exits on any IDT-dispatched interrupt and re-runs
/// the scheduler regardless of which vector poked it. On aarch64 SGIs
/// 0 and 1 are already taken by the scheduler and kprof-dump paths, so
/// the wake path claims SGI 2.
const wake_ipi_vector: u8 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(x64.interrupts.IntVecs.sched),
    .aarch64 => 2,
    else => unreachable,
};

/// Wake an idle remote core so it picks up freshly enqueued work.
/// Spec §[execution_context] cross-core enqueue.
pub fn sendWakeIpi(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendIpiToCore(core_id, wake_ipi_vector),
        .aarch64 => aarch64.gic.sendIpiToCore(core_id, wake_ipi_vector),
        else => unreachable,
    }
}

