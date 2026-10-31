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

/// Cross-core wake. The wake's only job is to make a halted core's
/// `hlt`/`wfi` retire so its park primitive falls through to
/// `scheduler_run_after_park` -> `run()` -> `dequeueOrIdle`, which finds
/// the freshly enqueued thread. It does NOT need to dispatch by itself, and
/// on aarch64 it deliberately must not — see `exceptions.dispatchIrq`
/// case 3.
///
/// aarch64 history, twice wrong, recorded so it isn't repeated:
///
///  1. It originally claimed SGI 2 on the reasoning that SGIs 0 and 1
///     were taken by the scheduler path. SGI 2 was not
///     free either: `arch.dispatch.cpu.sendFpuFlushIpi` raises it for
///     the lazy-FPU cross-core flush, so a wake ran
///     `fpu.flushIpiHandler` against an empty mailbox. That still woke
///     a core already inside `wfi` (WFI retires on any pending
///     interrupt regardless of its handler), but it meant the wake and
///     the FPU flush were indistinguishable at the INTID level.
///
///  2. Repointing it at SGI 0 — the scheduler vector, mirroring x86 —
///     fixed the aliasing but broke the park contract: SGI 0's handler
///     ends in `scheduler.preempt()`, which dispatches and never
///     returns, so `parkAndAwaitIRQ`'s trailing
///     `b scheduler_run_after_park` was skipped and the previously
///     dispatched thread's `on_cpu` was stranded set. Details at
///     `exceptions.dispatchIrq` case 3.
///
/// So: its own INTID, its own do-nothing handler.
///
/// x86 keeps using `IntVecs.sched` because its park primitive has the
/// same structure (`sti; hlt; cli; jmp scheduler_run_after_park`) and
/// therefore the same skip hazard — that is pre-existing there and is
/// tracked separately; it is not made worse by this file.
const wake_ipi_vector: u8 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(x64.interrupts.IntVecs.sched),
    .aarch64 => aarch64.gic.wake_sgi_id,
    else => unreachable,
};

/// Wake an idle remote core so it picks up freshly enqueued work.
/// Spec §[thread] cross-core enqueue.
pub fn sendWakeIpi(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendIpiToCore(core_id, wake_ipi_vector),
        .aarch64 => aarch64.gic.sendIpiToCore(core_id, wake_ipi_vector),
        else => unreachable,
    }
}

