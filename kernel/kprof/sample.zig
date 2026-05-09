//! Sample-mode PMU bring-up and NMI hook.
//!
//! Compiled in only when `-Dkernel_profile=sample`. On every core the
//! PMU is programmed to count retired cycles and overflow every
//! `SAMPLE_PERIOD_CYCLES` cycles; the overflow is routed through the
//! LAPIC LVT PerfMon entry with NMI delivery mode so sampling fires
//! even when the targeted code has interrupts masked. The NMI handler
//! calls `onNmi()` with the interrupted instruction pointer and the
//! interrupted frame pointer; when `onNmi()` returns true the caller
//! treats the NMI as consumed.
//!
//! For each consumed NMI, `onNmi()` emits a leaf `sample` record
//! carrying the interrupted RIP, then walks the kernel frame-pointer
//! chain to emit up to `MAX_FRAMES` `sample_frame` records carrying
//! the saved return address at each level with a 1-based depth in
//! `arg`. All unwind reads go through `arch.pmu.readKernelU64Safe`, so
//! the handler never faults: a malformed / non-canonical / unaligned
//! frame pointer simply terminates the walk early.
//!
//! Emit happens from NMI context. The kprof log is NMI-safe by design
//! (inline BSS backing, atomic-RMW bump head), so the handler can
//! write `sample` and `sample_frame` records without any lock or
//! heap interaction.

const log = @import("log.zig");
const mode = @import("mode.zig");
const record = @import("record.zig");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;

const Kind = record.Kind;

/// Target number of cycles between samples. Kept modest so a short
/// workload (e.g. tests/prof yield) produces enough samples to fill a
/// per-CPU log, but large enough that sampling overhead is a small
/// fraction of the kernel's cycle budget.
pub const SAMPLE_PERIOD_CYCLES: u64 = 10_000;

/// Maximum number of caller frames walked per sample. The kernel's
/// call stack is bounded (scheduler tick + syscall dispatch + driver
/// path is ~dozens at worst); 32 is comfortably above worst case and
/// keeps one sample's emit cost a small constant.
pub const MAX_FRAMES: usize = 32;

/// Called from the NMI exception handler. Returns true if this NMI
/// came from the kprof sampling counter — in that case the counter is
/// rearmed, a leaf `sample` record is emitted for `ip`, and up to
/// `MAX_FRAMES` `sample_frame` records are emitted by walking the
/// frame-pointer chain starting at `fp`. Returns false if the NMI is
/// for anything else, so the caller can fall through to its existing
/// policy (panic today).
///
/// `fp` is the interrupted frame pointer, read from the saved CPU
/// context (x86-64: `ctx.regs.rbp`). On aarch64 the kprof NMI path is
/// a stub and callers pass 0; the unwinder handles zero-fp gracefully
/// by emitting no frame records.
pub fn onNmi(ip: u64, fp: u64) bool {
    if (comptime !mode.sample_enabled) return false;
    if (!arch.pmu.kprofSampleCheckAndRearm(SAMPLE_PERIOD_CYCLES)) return false;

    const cpu: u8 = @truncate(arch.smp.coreID());

    // Leaf sample: interrupted RIP. Record is the short (32 B)
    // variant under sample mode — the counter fields only exist
    // when `trace_enabled`, which is comptime-mutex with
    // `sample_enabled`, so the struct literal below matches the
    // Record layout exactly for this build.
    log.emit(.{
        .tsc = arch.time.readTimestamp(false),
        .kind = @intFromEnum(Kind.sample),
        .cpu = cpu,
        ._pad = 0,
        .id = 0,
        .ip = ip,
        .arg = 0,
    });

    // Walk the frame pointer chain.
    //
    // ABI (System V AMD64, AAPCS64 with frame pointers enabled):
    //   *(fp + 0) = previous saved frame pointer
    //   *(fp + 8) = return address into the caller
    //
    // Every dereference goes through `arch.pmu.readKernelU64Safe`, which
    // rejects null, unaligned, and non-kernel-half addresses. That is
    // sufficient defense — Stygia maps the entire kernel half on boot
    // and never unmaps it at runtime, so any address passing those
    // checks is safely readable from NMI context.
    var cur_fp: u64 = fp;
    var prev_fp: u64 = 0;
    var depth: u64 = 1;
    while (depth <= MAX_FRAMES) {
        const next_fp = arch.pmu.readKernelU64Safe(cur_fp) orelse break;
        const ra = arch.pmu.readKernelU64Safe(cur_fp + 8) orelse break;
        if (ra == 0) break;

        log.emit(.{
            .tsc = arch.time.readTimestamp(false),
            .kind = @intFromEnum(Kind.sample_frame),
            .cpu = cpu,
            ._pad = 0,
            .id = 0,
            .ip = ra,
            .arg = depth,
        });

        // Pathological-loop guard: a self-referential frame pointer
        // (or a chain that folds back on itself one step later) would
        // otherwise emit the same RA indefinitely up to MAX_FRAMES.
        if (next_fp == cur_fp) break;
        if (next_fp == prev_fp) break;

        prev_fp = cur_fp;
        cur_fp = next_fp;
        depth += 1;
    }

    return true;
}
