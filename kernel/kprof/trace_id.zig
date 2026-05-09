const mode = @import("mode.zig");
const record = @import("record.zig");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const log = @import("log.zig");

/// Central registry of every kernel tracepoint.
///
/// Each enum value is a stable numeric id emitted into the log so the
/// post-processor can map records back to a name without shipping
/// strings in the log. The `names` table below supplies the id-to-name
/// mapping emitted once at session end.
///
/// Add entries here before inserting new kprof.enter/exit call sites.
pub const TraceId = enum(u32) {
    // ── Page operations ──────────────────────────────────────
    handle_page_fault = 100,
    page_fault_hw,
    map_page,
    unmap_page,
    tlb_shootdown,

    // ── IPC suspend ↔ recv rendezvous ─────────────────────────
    // Each scoped pair brackets one Zig handler in `kernel/sched/port.zig`.
    // Use these to compare per-handler cycle costs before/after the L4
    // zero-copy fast path lands. Existing tests exercise the slow Zig
    // path (libz emits `suspend = 14` with `pair_count` in the syscall
    // word, so the asm classifier `cmpq $13` falls through). When
    // userspace adopts the fast-suspend ABI (`syscall_op = 0..13`), the
    // asm path bypasses these points entirely — apparent zero-cost there
    // is the proof of zero-copy.
    suspend_ec = 200,
    recv,
    reply,
    deliver_event,

    // ── Scheduler ────────────────────────────────────────────
    sched_tick = 300,
    yield,
    dispatch,

    // ── Virtualization ───────────────────────────────────────
    vm_exit = 400,
    vm_enter,

    // ── Outer kernel-entry pairs ─────────────────────────────
    // Wrap the very top of every hardware-/syscall-driven kernel
    // entry handler so a single (enter, exit) pair brackets total
    // kernel residency for that boundary class. `syscall` carries
    // the syscall number as a `point` arg right after the enter.
    exception = 500,
    page_fault,
    irq,
    syscall,

    // ── Heavy syscall handlers ───────────────────────────────
    // Per-handler scoped pairs for the syscalls expected to dominate
    // the syscall budget — futex fan-out, var bulk paths, EC/cap-domain
    // create, FPU swap. The dispatcher-level `syscall` pair already
    // brackets every syscall coarsely; these add per-name attribution.
    futex_wait = 600,
    futex_wake,
    map_pf,
    idc_read,
    idc_write,
    create_cap_domain,
    create_ec,
    fpu_swap,
};

/// Emit an enter record for a scoped tracepoint. Paired with `exit`.
/// Compiles to nothing unless `-Dkernel_profile=trace`.
///
/// Must short-circuit on `log.active` BEFORE calling `arch.smp.coreID()`.
/// Tracepoints fire throughout boot (e.g. in the page-fault handler
/// for lazily-mapped slab pages), but `coreID()` depends on
/// `apic.lapics` which is only populated by ACPI parsing partway
/// through `kMain`. Constructing the record first would evaluate
/// `coreID()` unconditionally and panic on `lapics.?` in the early
/// window.
pub inline fn enter(comptime id: TraceId) void {
    if (!mode.trace_enabled) return;
    if (!@atomicLoad(bool, &log.active, .acquire)) return;
    var counters: [3]u64 = undefined;
    arch.pmu.kprofTraceCountersRead(&counters);
    log.emit(.{
        .tsc = arch.time.readTimestamp(false),
        .kind = @intFromEnum(record.Kind.trace_enter),
        .cpu = @truncate(arch.smp.coreID()),
        ._pad = 0,
        .id = @intFromEnum(id),
        .ip = @returnAddress(),
        .arg = 0,
        .cycles = counters[0],
        .cache_misses = counters[1],
        .branch_misses = counters[2],
        ._pad2 = 0,
    });
}

/// Emit an exit record for a scoped tracepoint. Paired with `enter`.
pub inline fn exit(comptime id: TraceId) void {
    if (!mode.trace_enabled) return;
    if (!@atomicLoad(bool, &log.active, .acquire)) return;
    var counters: [3]u64 = undefined;
    arch.pmu.kprofTraceCountersRead(&counters);
    log.emit(.{
        .tsc = arch.time.readTimestamp(false),
        .kind = @intFromEnum(record.Kind.trace_exit),
        .cpu = @truncate(arch.smp.coreID()),
        ._pad = 0,
        .id = @intFromEnum(id),
        .ip = @returnAddress(),
        .arg = 0,
        .cycles = counters[0],
        .cache_misses = counters[1],
        .branch_misses = counters[2],
        ._pad2 = 0,
    });
}

/// Emit a single-shot tracepoint with an optional payload argument.
/// Use for point-in-time events that don't bracket a scope
/// (e.g. a page fault address, a thread id, a vm-exit reason).
pub inline fn point(comptime id: TraceId, arg: u64) void {
    if (!mode.trace_enabled) return;
    if (!@atomicLoad(bool, &log.active, .acquire)) return;
    var counters: [3]u64 = undefined;
    arch.pmu.kprofTraceCountersRead(&counters);
    log.emit(.{
        .tsc = arch.time.readTimestamp(false),
        .kind = @intFromEnum(record.Kind.trace_point),
        .cpu = @truncate(arch.smp.coreID()),
        ._pad = 0,
        .id = @intFromEnum(id),
        .ip = @returnAddress(),
        .arg = arg,
        .cycles = counters[0],
        .cache_misses = counters[1],
        .branch_misses = counters[2],
        ._pad2 = 0,
    });
}
