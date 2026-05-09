//! Per-CPU kernel profiling log.
//!
//! Each CPU owns a pre-mapped, fixed-size bump log. Tracepoint and
//! sample records are appended via `emit`. The session ends when any
//! CPU fills its log, or when the root process exits — whichever
//! comes first — at which point all CPUs quiesce and dump their logs
//! to serial in core-id order.
//!
//! The bump pointer is advanced via an atomic RMW (monotonic) on
//! `head`. This is single-producer from the main thread side, but
//! the NMI sampling handler may reenter on the same CPU. Atomic RMW
//! makes the NMI-vs-main race correct without any additional lock.
//!
//! The backing storage lives in the kernel image as `.bss` when any
//! profiling mode is compiled in, so pages are physically backed at
//! load time (bootloader zeroes BSS) — no heap dep, no pre-fault pass,
//! no page faults possible during emit. Under `-Dkernel_profile=none`
//! the backing collapses to a zero-length array and costs nothing.

const mode = @import("mode.zig");
const record_mod = @import("record.zig");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;

const Record = record_mod.Record;

/// Hard upper bound on CPUs the profiling log array supports.
/// Kept tight because every bump costs `LOG_SIZE_BYTES` of BSS.
pub const MAX_CPUS: usize = 4;

/// Bytes per per-CPU log. 16 MiB × MAX_CPUS = 64 MiB BSS when kprof is
/// compiled in (zero when `-Dkernel_profile=none`). Sized to fit the
/// full 477-test run on the busiest core (cpu=0 receives the bulk of
/// the page-fault + map_page point records when the L4 fast path keeps
/// the rendezvous local) before any overflow → end-of-session dump.
pub const LOG_SIZE_BYTES: usize = 16 * 1024 * 1024;

/// Inline BSS backing for every per-CPU log. Zero bytes when profiling
/// is compiled out; `MAX_CPUS * LOG_SIZE_BYTES` bytes otherwise.
const BACKING_BYTES: usize = if (mode.any_enabled) MAX_CPUS * LOG_SIZE_BYTES else 0;
var inline_backing: [BACKING_BYTES]u8 align(4096) = undefined;

pub const CpuLog = extern struct {
    base: u64 align(64), // virtual base of this CPU's log buffer
    head: u64, // byte offset; atomic RMW bumped
    limit: u64, // byte size of the mapped buffer
    overflowed: u64, // non-zero once head reached limit
};

pub var cpu_logs: [MAX_CPUS]CpuLog align(64) = [_]CpuLog{.{
    .base = 0,
    .head = 0,
    .limit = 0,
    .overflowed = 0,
}} ** MAX_CPUS;

/// Number of per-CPU logs actually initialized (== coreCount at init time).
pub var n_cpus: usize = 0;

/// True once logs are allocated and accepting records.
/// Set by `start()`, cleared by `end()`.
pub var active: bool = false;

/// Global "some CPU filled its log" flag. Set by `emit()` on first overflow
/// on any CPU; polled from the scheduler timer tick so the next core to tick
/// kicks off the IPI-coordinated dump in `dump.end(.log_full)`.
pub var terminate_requested: u32 = 0;

/// Single-shot "session is ending" flag. The first core to call `dump.end`
/// (either the timer-tick observer of `terminate_requested` or root-exit
/// path) cmpxchg's this from false → true and becomes the dumper; concurrent
/// callers fall into `parkForDump` so their in-flight `emit()`s drain.
pub var ending: bool = false;

/// Non-dumping cores increment this while parked in the dump IPI handler.
/// The dumping core spins until it reaches `n_cpus - 1` before emitting
/// records, guaranteeing no in-flight `emit()` can race with the dump.
pub var parked_cores: u32 = 0;

/// Set to 1 by the dumper after the serial dump completes. Parked cores
/// spin on this in `parkForDump` and halt once they observe it set.
pub var dump_done: u32 = 0;

/// Reserved for future rolling-dump epochs (currently unused — the dump
/// is a single-shot session-end event, not rolling). Kept so the IPI
/// handler can be extended without an ABI break.
pub var epoch: u64 = 0;

/// Point every per-CPU CpuLog at its slice of the inline BSS backing.
/// No allocation, no pre-fault — BSS pages are physically backed by
/// the kernel image loader. No-op when profiling is compiled out.
pub fn init() !void {
    if (!mode.any_enabled) return;

    const cores = arch.smp.coreCount();
    if (cores > MAX_CPUS) @panic("kprof: coreCount exceeds MAX_CPUS");
    n_cpus = @intCast(cores);

    for (0..n_cpus) |i| {
        cpu_logs[i] = .{
            .base = @intFromPtr(&inline_backing[i * LOG_SIZE_BYTES]),
            .head = 0,
            .limit = LOG_SIZE_BYTES,
            .overflowed = 0,
        };
    }
}

/// Begin accepting records. Call after boot completes, right before
/// the root process resumes on its first scheduling tick.
pub fn start() void {
    if (!mode.any_enabled) return;
    if (n_cpus == 0) return;
    @atomicStore(bool, &active, true, .release);
}

/// Append one record to the current CPU's log.
///
/// Callable from NMI context. Will not fault — `init()` pre-faults
/// every backing page, and the bump pointer never advances past
/// the pre-mapped range.
///
/// On the first overflow, sets the CPU's `overflowed` flag and
/// silently drops the record. The session-end path polls this
/// and triggers `end()` on first observed overflow.
pub inline fn emit(rec: Record) void {
    if (!mode.any_enabled) return;
    if (!@atomicLoad(bool, &active, .acquire)) return;

    const log = &cpu_logs[rec.cpu];
    const off = @atomicRmw(u64, &log.head, .Add, @sizeOf(Record), .monotonic);
    if (off + @sizeOf(Record) > log.limit) {
        @atomicStore(u64, &log.overflowed, 1, .release);
        @atomicStore(u32, &terminate_requested, 1, .release);
        return;
    }
    const slot: *Record = @ptrFromInt(log.base + off);
    slot.* = rec;
}

