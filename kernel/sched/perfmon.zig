//! Per-EC PMU counter state. Lazy-allocated on first `perfmon_start`
//! against an EC; freed on `perfmon_stop` or implicitly on EC destroy.
//! See spec §[execution_context] perfmon_* syscalls.
//!
//! Not a handle-bearing object — referenced only from
//! `ExecutionContext.perfmon_state` as `?SlabRef(PerfmonState)`.
//! Slab-allocated so ECs that never call perfmon don't carry the
//! per-counter buffers as inline bloat.

const stygia = @import("stygia");

const GenLock = stygia.memory.allocators.secure_slab.GenLock;
const PmuState = stygia.arch.dispatch.pmu.PmuState;
const SecureSlab = stygia.memory.allocators.secure_slab.SecureSlab;

/// Maximum hardware PMU counters the state struct accommodates.
/// Common architectures expose 4-8 general-purpose counters; this
/// caps the inline arrays at a power-of-two reasonable for both.
pub const MAX_COUNTERS: u8 = 8;

pub const PerfmonState = struct {
    /// Slab generation lock + per-instance mutex.
    _gen_lock: GenLock = .{},

    /// Bitmap of which counters (bits 0..MAX_COUNTERS) are active.
    active_counters: u8 = 0,

    /// Per-counter event index (per `perfmon_info`'s
    /// `supported_events` bitmask). Valid only for active counters.
    counter_events: [MAX_COUNTERS]u8 = [_]u8{0} ** MAX_COUNTERS,

    /// Per-counter overflow threshold. Used only when the
    /// corresponding bit in `has_threshold` is set.
    counter_thresholds: [MAX_COUNTERS]u64 = [_]u64{0} ** MAX_COUNTERS,

    /// Bitmap of which counters have an overflow threshold configured
    /// (matches the `has_threshold` bit in the original config_event).
    has_threshold: u8 = 0,

    /// Arch PMU control state — MSR snapshots, hardware counter
    /// assignment, sub-counter event-select encodings. Carried inline
    /// because the kernel has no general-purpose heap; the only
    /// allocators for kernel objects are SecureSlabs.
    arch_state: PmuState = .{},
};

pub const Allocator = SecureSlab(PerfmonState, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: stygia.utils.range.Range,
    ptrs_range: stygia.utils.range.Range,
    links_range: stygia.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

