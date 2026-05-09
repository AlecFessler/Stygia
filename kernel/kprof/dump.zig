//! Kprof serial dump path.
//!
//! `end(reason)` is the single entry point. The first caller to flip
//! `log_mod.ending` becomes the dumper; concurrent losers fall into
//! `parkForDump()` so their in-flight `emit()`s drain. The dumper
//! IPIs every other core to park, spins until they all do, then
//! serial-dumps every per-CPU log in core-id order, signals
//! `dump_done`, and halts. End-of-session — the machine doesn't
//! resume after a dump.
//!
//! Two triggers wired today:
//!   1. Scheduler timer tick observes `log_mod.terminate_requested == 1`
//!      (set by `emit` on the first per-CPU log overflow) and calls
//!      `end(.log_full)`.
//!   2. Userspace `kprof_dump` syscall calls `end(.root_exit)` from
//!      the test runner's primary after all results are collected.

const log_mod = @import("log.zig");
const mode = @import("mode.zig");
const record_mod = @import("record.zig");
const trace_id_mod = @import("trace_id.zig");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const debug_info = stygia.utils.debug_info;

const Record = record_mod.Record;

fn dumpOneLog(cpu: usize) void {
    const log = &log_mod.cpu_logs[cpu];
    const head = @atomicLoad(u64, &log.head, .acquire);
    const overflowed = @atomicLoad(u64, &log.overflowed, .acquire);
    const bytes_used = @min(head, log.limit);
    const n_records = bytes_used / @sizeOf(Record);

    arch.boot.print("[KPROF] cpu_begin cpu={d} records={d} overflowed={d}\n", .{
        cpu,
        n_records,
        overflowed,
    });

    var idx: usize = 0;
    while (idx < n_records) {
        const slot: *const Record = @ptrFromInt(log.base + idx * @sizeOf(Record));
        const sym = resolveSym(slot.ip);
        if (comptime mode.trace_enabled) {
            arch.boot.print(
                "[KPROF] rec cpu={d} tsc={d} kind={d} id={d} ip=0x{x} arg=0x{x} cyc={d} cmiss={d} bmiss={d} sym={s}\n",
                .{
                    slot.cpu,
                    slot.tsc,
                    slot.kind,
                    slot.id,
                    slot.ip,
                    slot.arg,
                    slot.cycles,
                    slot.cache_misses,
                    slot.branch_misses,
                    sym,
                },
            );
        } else {
            arch.boot.print(
                "[KPROF] rec cpu={d} tsc={d} kind={d} id={d} ip=0x{x} arg=0x{x} sym={s}\n",
                .{
                    slot.cpu,
                    slot.tsc,
                    slot.kind,
                    slot.id,
                    slot.ip,
                    slot.arg,
                    sym,
                },
            );
        }
        idx += 1;
    }

    arch.boot.print("[KPROF] cpu_end cpu={d}\n", .{cpu});
}

/// Resolve a runtime address to a function name via the kernel's own
/// DWARF (same path `panic.zig` uses). Returns `"?"` when debug info
/// isn't loaded or the address falls outside the kernel image.
fn resolveSym(ip: u64) []const u8 {
    if (ip == 0) return "?";
    const dbg = debug_info.global_ptr orelse return "?";
    if (ip < debug_info.kaslr_slide) return "?";
    return dbg.getSymbolName(ip - debug_info.kaslr_slide) orelse "?";
}

pub const EndReason = enum {
    log_full,
    root_exit,
    oneshot,
};

/// Stop-the-world session-end dump. Called from
///   1. the scheduler timer tick when it observes
///      `log_mod.terminate_requested == 1` (some CPU's log filled), or
///   2. an explicit userspace `kprof_dump` syscall (root_exit reason).
/// The first caller to flip `log_mod.ending` becomes the dumper;
/// concurrent losers fall into `parkForDump` so their in-flight
/// `emit()`s drain before the dumper begins writing. The dumper IPIs
/// every other core to park, spins until they all do, then dumps every
/// log to serial in core-id order, signals dump_done, and halts. The
/// machine is done once any session ends.
pub fn end(reason: EndReason) void {
    if (!mode.any_enabled) return;

    if (@cmpxchgStrong(bool, &log_mod.ending, false, true, .acq_rel, .monotonic) != null) {
        parkForDump();
        return;
    }

    @atomicStore(bool, &log_mod.active, false, .release);

    arch.cpu.broadcastKprofIpi();

    const expected: u32 = @intCast(log_mod.n_cpus -| 1);
    while (@atomicLoad(u32, &log_mod.parked_cores, .acquire) < expected) {
        arch.cpu.cpuRelax();
    }

    arch.boot.print("[KPROF] begin cpus={d} mode={s} reason={s}\n", .{
        log_mod.n_cpus,
        @tagName(mode.active),
        @tagName(reason),
    });
    inline for (@typeInfo(trace_id_mod.TraceId).@"enum".fields) |f| {
        arch.boot.print("[KPROF] name id={d} name={s}\n", .{ f.value, f.name });
    }
    var cpu: usize = 0;
    while (cpu < log_mod.n_cpus) {
        dumpOneLog(cpu);
        cpu += 1;
    }
    arch.boot.print("[KPROF] done\n", .{});

    @atomicStore(u32, &log_mod.dump_done, 1, .release);
    arch.cpu.halt();
}

/// Called from the kprof-dump IPI handler on non-dumping cores and
/// from the loser of `end()`'s `ending` cmpxchg. Bumps the parked
/// counter so the dumper can proceed, then spins until the dumper
/// publishes `dump_done` and halts. End-of-session — the CPU does
/// not resume.
pub fn parkForDump() void {
    if (!mode.any_enabled) return;
    _ = @atomicRmw(u32, &log_mod.parked_cores, .Add, 1, .acq_rel);
    while (@atomicLoad(u32, &log_mod.dump_done, .acquire) == 0) {
        arch.cpu.cpuRelax();
    }
    arch.cpu.halt();
}
