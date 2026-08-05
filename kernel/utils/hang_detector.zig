//! SMP=4 lost-wakeup hang detector.
//!
//! Wired into `arch.x64.serial.printRaw` (every kernel/userspace COM1 byte
//! bumps `last_progress_ns`) and the LAPIC scheduler tick (compares
//! `now - last_progress_ns` against `HANG_THRESHOLD_NS`; on overshoot,
//! calls `dump()` exactly once).
//!
//! `dump()` walks every initialized core_states[i] and emits the ec/state/
//! on_cpu/run-queue snapshot for each, plus the runner's likely result-port
//! wait queue if it can be inferred. Output is unlocked `printRaw` (same
//! discipline as panic) so it can run mid-spinlock without deadlocking.
//!
//! Build-gated by `-Dkernel_hang_detector` (default true under -Dprofile=test).
//! When off, every public symbol is a no-op and storage is zero-sized.

const std = @import("std");
const builtin = @import("builtin");
const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;
const execution_context = stygia.sched.execution_context;
const capability_domain = stygia.caps.capability_domain;
const lifecycle = stygia.sched.lifecycle;
const scheduler = stygia.sched.scheduler;
const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const State = stygia.sched.execution_context.State;

/// 4s of no-newline-progress = hang. Used as a backstop only — the
/// primary detector on this branch is `allCoresIdle()` driven from the
/// HPET-NMI watchdog, which fires within ~30 ms of every core entering
/// the user-mode idle hlt loop with current_ec=null (the smp=4 reply-FP
/// signature). The 4s threshold catches the slow-tail variants where
/// userspace IS still running but a single EC is wedged in a fault
/// loop.
pub const HANG_THRESHOLD_NS: u64 = 4_000_000_000;

/// Last monotonic-ns timestamp anything emitted on the serial path. Bumped
/// from `arch.x64.serial.printRaw`. Read from the scheduler tick.
pub var last_progress_ns: std.atomic.Value(u64) =
    std.atomic.Value(u64).init(0);

/// One-shot. Set by `dump` so a tick that fires while another core is mid-
/// dump skips re-entering. Also gates the second hang from re-running the
/// (potentially page-fault-prone) walk.
pub var dump_fired: std.atomic.Value(bool) =
    std.atomic.Value(bool).init(false);

/// True once `init()` has stamped the first `last_progress_ns` value. The
/// detector is dormant until then so very-early boot before timers /
/// monotonic clock are up doesn't trip it on the first BSP print.
pub var armed: std.atomic.Value(bool) =
    std.atomic.Value(bool).init(false);

/// Monotonic-ns at which `arm()` ran. Used by the all-cores-idle detector
/// to skip a grace window after arm() so very-early boot before the
/// runner has actually started doesn't false-positive (every core IS
/// idle then).
pub var armed_ns: std.atomic.Value(u64) =
    std.atomic.Value(u64).init(0);

/// Force-dump on demand. Wired to NMI handler when the watchdog is
/// build-enabled but the HPET trigger path failed to arm (QEMU's HPET
/// doesn't advertise FSB and IOAPIC isn't yet wired here for NMI
/// routing). With this hook in place, manually injecting an NMI from
/// outside (`info registers`/`nmi` on QEMU monitor) drives the dump.
pub fn forceDump() void {
    if (builtin.cpu.arch != .x86_64) return;
    if (dump_fired.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return;
    emitHeartbeatByte('F');
    dump(0);
}

/// Stamp current time into `last_progress_ns`. Call after monotonic clock
/// initialization, before SMP bringup.
pub fn arm() void {
    if (builtin.cpu.arch != .x86_64) return;
    const t = arch.time.currentMonotonicNs();
    last_progress_ns.store(t, .release);
    armed_ns.store(t, .release);
    armed.store(true, .release);
    emitHeartbeatByte('A'); // confirm arm() ran (use 'A' not '@' — '@' is the all-idle dump trigger)
}

/// Stamps progress on a `\n` byte. Used in the userspace COM1 emulation
/// path: a partial line emitted between long stalls (the smp=4 hang
/// signature in this branch — runner intermittently completes one PASS,
/// prints `[`, then re-stalls for tens of seconds) is not progress. A
/// full line worth of bytes is.
pub fn noteProgressOnNewline(b: u8) void {
    if (builtin.cpu.arch != .x86_64) return;
    if (b != '\n') return;
    if (!armed.load(.acquire)) return;
    last_progress_ns.store(arch.time.currentMonotonicNs(), .release);
}

/// Per-core tick counter — bumped every tickCheck. Used to confirm the
/// hang detector is actually being invoked (debug instrumentation; emits
/// a raw heartbeat byte every N ticks).
var tick_counter: std.atomic.Value(u64) =
    std.atomic.Value(u64).init(0);

/// Called from the LAPIC scheduler tick after the periodic work. Cheap
/// fast path when nothing is wrong: one atomic load + one TSC read +
/// one subtraction.
pub fn tickCheck() void {
    if (builtin.cpu.arch != .x86_64) return;
    // Pre-armed-check counter so we can distinguish "tickCheck never
    // called" from "called but armed gate keeps it silent".
    const t = tick_counter.fetchAdd(1, .monotonic);
    if ((t & 0x3F) == 0) emitHeartbeatByte('~');
    if (!armed.load(.acquire)) return;
    if (dump_fired.load(.acquire)) return;
    const now = arch.time.currentMonotonicNs();
    const last = last_progress_ns.load(.acquire);
    if (now < last) return; // clock skew safety
    const delta = now - last;

    // Threshold-based detector. Trips when no userspace newline has
    // emitted for HANG_THRESHOLD_NS — the canonical Type B / slow-tail
    // signature.
    if (delta >= HANG_THRESHOLD_NS) {
        if (dump_fired.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return;
        emitHeartbeatByte('!');
        dump(delta);
        return;
    }

    // The original all-cores-idle detector tripped on transient between-
    // batch all-idle windows. The 2 s newline-progress threshold above
    // is the reliable signal — a real lost-wakeup hang never emits more
    // newlines.
}

fn emitHeartbeatByte(b: u8) void {
    @setRuntimeSafety(false);
    var i: u8 = 0;
    while (i < 4) {
        asm volatile (
            \\outb %[bb], %[p]
            :
            : [bb] "{al}" (b),
              [p] "{dx}" (@as(u16, 0x3F8)),
            : .{ .memory = true });
        i += 1;
    }
}

/// Lockless raw COM1 write — polls LSR THR-empty before each byte. Used
/// in the dump path so the structured output cannot deadlock on
/// `serial.print_lock` and cannot recurse through `noteProgress` (which
/// would reset our own progress timer mid-dump and re-arm).
fn rawWrite(s: []const u8) void {
    @setRuntimeSafety(false);
    const com1: u16 = 0x3F8;
    const lsr: u16 = 0x3F8 + 5;
    for (s) |b| {
        // Poll THR-empty (LSR bit 5) — bounded by UART hardware (~10us).
        while (true) {
            const status = asm volatile (
                \\inb %[p], %[ret]
                : [ret] "={al}" (-> u8),
                : [p] "{dx}" (lsr),
                : .{ .memory = true });
            if ((status & 0x20) != 0) break;
        }
        asm volatile (
            \\outb %[b], %[p]
            :
            : [b] "{al}" (b),
              [p] "{dx}" (com1),
            : .{ .memory = true });
    }
}

fn dump(elapsed_ns: u64) void {
    rawWrite("\n[HANG] no serial progress for ");
    printDecimal(elapsed_ns / 1_000_000);
    rawWrite(" ms — dumping per-core state\n");

    const num_cores = arch.smp.coreCount();
    rawWrite("[HANG] num_cores=");
    printDecimal(@as(u64, num_cores));
    rawWrite("\n");

    const this_core: u8 = @truncate(arch.smp.coreID());
    rawWrite("[HANG] dumping from core=");
    printDecimal(@as(u64, this_core));
    rawWrite("\n");

    var core_id: u8 = 0;
    while (core_id < num_cores) {
        dumpCore(core_id);
        core_id += 1;
    }

    dumpLifecycleCounters();
    dumpSpawnTraceSamples();

    // Walk every alive EC slab slot and emit its state. Catches
    // orphaned waiters parked in port wait queues that don't show up
    // in any per-core current_ec / run_queue. Bounded by the slab
    // total — typically <100 in a smp=4 test run, so this is cheap.
    rawWrite("[HANG] live ECs:\n");
    execution_context.slab_instance.forEachAlive(@as(*u8, @ptrCast(&dump_visit_dummy)), dumpAliveEc);

    rawWrite("[HANG] (end)\n");
}

fn dumpLifecycleCounters() void {
    rawWrite("[HANG] lifecycle counters:");
    rawWrite(" p2=");
    printDecimal(loadCounter(&capability_domain.p2_enter));
    rawWrite("/");
    printDecimal(loadCounter(&capability_domain.p2_after_reap));
    rawWrite("/");
    printDecimal(loadCounter(&capability_domain.p2_walk_done));
    rawWrite("/");
    printDecimal(loadCounter(&capability_domain.p2_exit));
    rawWrite(" p2_residue=");
    printDecimal(loadCounter(&capability_domain.p2_residue));
    rawWrite(" abandoned_p2=");
    printDecimal(loadCounter(&capability_domain.abandoned_in_p2));
    rawWrite(" abandoned_other=");
    printDecimal(loadCounter(&capability_domain.abandoned_other));
    rawWrite(" walk=");
    printDecimal(loadCounter(&execution_context.walk_visit_enter));
    rawWrite("/");
    printDecimal(loadCounter(&execution_context.walk_visit_done));
    rawWrite(" slow_post=");
    printDecimal(loadCounter(&execution_context.slow_post_spins));
    rawWrite("/");
    printDecimal(loadCounter(&execution_context.slow_post_done));
    rawWrite(" slow_self=");
    printDecimal(loadCounter(&execution_context.slow_post_self));
    rawWrite(" inline=");
    printDecimal(loadCounter(&execution_context.inline_finalize_ok));
    rawWrite("/");
    printDecimal(loadCounter(&execution_context.inline_finalize_no));
    rawWrite(" park=");
    printDecimal(loadCounter(&execution_context.park_calls));
    rawWrite("\n");

    dumpPreReportTerminalSamples();
}

fn loadCounter(counter: *u64) u64 {
    return @atomicLoad(u64, counter, .monotonic);
}

fn dumpPreReportTerminalSamples() void {
    if (!build_options.kernel_spawn_diag) return;
    const max_seq = @atomicLoad(u64, &execution_context.pre_report_terminal_seq, .monotonic);
    rawWrite("[HANG] pre-report terminal samples: seq=");
    printDecimal(max_seq);
    rawWrite("\n");
    if (max_seq == 0) return;

    const ring_len = execution_context.PRE_REPORT_TERMINAL_RING_LEN;
    const first_seq = if (max_seq > ring_len) max_seq - ring_len + 1 else 1;
    var seq = first_seq;
    while (seq <= max_seq) : (seq += 1) {
        const idx: usize = @intCast(seq % ring_len);
        const slot = &execution_context.pre_report_terminal_ring[idx];
        const before = slot.publish_seq.load(.acquire);
        if (before != seq) continue;
        const sample_seq = slot.seq;
        const tag = slot.tag;
        const cd = slot.cd;
        const ec = slot.ec;
        const reason = slot.reason;
        const after = slot.publish_seq.load(.acquire);
        if (after != before or sample_seq != seq) continue;

        rawWrite("[HANG]   term seq=");
        printDecimal(sample_seq);
        rawWrite(" tag=");
        printHex(tag);
        rawWrite(" index=");
        printDecimal(tag - 0x8000);
        rawWrite(" cd=");
        printHex(@as(u64, cd));
        rawWrite(" ec=");
        printHex(@as(u64, ec));
        rawWrite(" reason=");
        rawWrite(reason);
        rawWrite("\n");
    }
}

fn dumpSpawnTraceSamples() void {
    if (!build_options.kernel_spawn_diag) return;
    const max_seq = @atomicLoad(u64, &execution_context.spawn_trace_seq, .monotonic);
    rawWrite("[HANG] spawn trace samples: seq=");
    printDecimal(max_seq);
    rawWrite("\n");
    if (max_seq == 0) return;

    const ring_len = execution_context.SPAWN_TRACE_RING_LEN;
    const first_seq = if (max_seq > ring_len) max_seq - ring_len + 1 else 1;
    var seq = first_seq;
    while (seq <= max_seq) : (seq += 1) {
        const idx: usize = @intCast(seq % ring_len);
        const slot = &execution_context.spawn_trace_ring[idx];
        const before = slot.publish_seq.load(.acquire);
        if (before != seq) continue;
        const sample_seq = slot.seq;
        const event = slot.event;
        const tag = slot.tag;
        const core = slot.core;
        const ec = slot.ec;
        const cd = slot.cd;
        const gen = slot.gen;
        const state = slot.state;
        const owner = slot.owner;
        const queue_core = slot.queue_core;
        const aux = slot.aux;
        const after = slot.publish_seq.load(.acquire);
        if (after != before or sample_seq != seq) continue;

        rawWrite("[HANG]   trace seq=");
        printDecimal(sample_seq);
        rawWrite(" ev=");
        printSpawnTraceEvent(event);
        rawWrite(" tag=");
        printHex(tag);
        rawWrite(" index=");
        printDecimal(tag - 0x8000);
        rawWrite(" core=");
        printDecimal(core);
        rawWrite(" ec=");
        printHex(@as(u64, ec));
        rawWrite(" cd=");
        printHex(@as(u64, cd));
        rawWrite(" gen=");
        printHex(gen);
        rawWrite(" st=");
        printTraceState(state);
        rawWrite(" owner=");
        printDecimal(owner);
        rawWrite(" q=");
        printDecimal(queue_core);
        rawWrite(" aux=");
        printHex(aux);
        rawWrite("\n");
    }
}

fn printSpawnTraceEvent(event: execution_context.SpawnTraceEvent) void {
    rawWrite(switch (event) {
        .spawn_child => "spawn",
        .enqueue_attempt => "enq-attempt",
        .enqueue_publish => "enq-publish",
        .enqueue_skip_not_live => "enq-skip-live",
        .enqueue_skip_not_publishable => "enq-skip-pub",
        .enqueue_skip_state => "enq-skip-state",
        .dequeue_select => "deq-select",
        .dequeue_skip_not_publishable => "deq-skip-pub",
        .dispatch_tail => "dispatch-tail",
        .report_enter => "report-enter",
        .terminal => "terminal",
        .retire => "retire",
        .finalize => "finalize",
    });
}

fn printTraceState(state: u8) void {
    if (state == 0xff) {
        rawWrite("none");
        return;
    }
    printState(@enumFromInt(state));
}

var dump_visit_dummy: u8 = 0;

fn dumpAliveEc(_: *u8, ec: *ExecutionContext, gen: u63) bool {
    @setRuntimeSafety(false);
    rawWrite("[HANG]   ec=");
    printHex(@intFromPtr(ec));
    rawWrite(" gen=");
    printHex(@as(u64, gen));
    rawWrite(" state=");
    printState(lifecycle.load(ec));
    rawWrite(" owner=");
    printDecimal(@as(u64, ec.owner_core));
    rawWrite(" wait=");
    printDecimal(@as(u64, @intFromEnum(ec.wait.kind)));
    if (ec.suspend_port) |sp| {
        rawWrite(" susp_port=");
        printHex(@intFromPtr(sp.ptr));
    }
    if (ec.pending_reply_holder) |_| {
        rawWrite(" has_pending_reply");
    }
    rawWrite("\n");
    return true;
}

fn dumpCore(core_id: u8) void {
    rawWrite("[HANG] core=");
    printDecimal(@as(u64, core_id));

    const pc = &scheduler.core_states[core_id];

    if (pc.current_ec) |ec| {
        rawWrite(" current_ec=");
        printHex(@intFromPtr(ec));
        rawWrite(" ref_gen=");
        printHex(@as(u64, pc.current_ec_gen));
        rawWrite(" slot_gen=");
        printHex(@as(u64, ec._gen_lock.currentGen()));
        rawWrite(" state=");
        printState(lifecycle.load(ec));
        rawWrite(" owner=");
        printDecimal(@as(u64, ec.owner_core));
        rawWrite(" wait=");
        printDecimal(@as(u64, @intFromEnum(ec.wait.kind)));
        if (ec.suspend_port) |sp| {
            rawWrite(" suspend_port=");
            printHex(@intFromPtr(sp.ptr));
        }
        if (ec.pending_reply_holder) |_| {
            rawWrite(" has_pending_reply");
        }
    } else {
        rawWrite(" current_ec=null");
    }

    if (pc.teardown_pending != null) rawWrite(" teardown_pending=1");

    rawWrite("\n");

    // Dump run-queue contents (head per level — full walk is a pointer
    // chase that can fault if a queue link is corrupt; we want signal,
    // not noise).
    var any_q = false;
    var lvl: usize = 0;
    while (lvl < pc.run_queue.levels.len) {
        const head_ec: ?*ExecutionContext = pc.run_queue.levels[lvl].head;
        if (head_ec) |e| {
            if (!any_q) {
                rawWrite("[HANG]   run_queue:");
                any_q = true;
            }
            rawWrite(" L");
            printDecimal(@as(u64, lvl));
            rawWrite("=");
            printHex(@intFromPtr(e));
            rawWrite("(st=");
            printState(e.state);
            rawWrite(")");
        }
        lvl += 1;
    }
    if (any_q) {
        rawWrite("\n");
    } else {
        rawWrite("[HANG]   run_queue: empty\n");
    }
}

fn printState(s: State) void {
    rawWrite(switch (s) {
        .running => "RUN",
        .ready => "RDY",
        .parking => "PARK",
        .waiting => "WAIT",
        .claimed => "CLAM",
        .pended => "PEND",
        .retired => "RETD",
    });
}

fn printDecimal(n: u64) void {
    var buf: [20]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            buf[i] = @intCast(@as(u8, '0') + @as(u8, @intCast(v % 10)));
            v /= 10;
        }
    }
    rawWrite(buf[i..]);
}

fn printHex(n: u64) void {
    rawWrite("0x");
    var buf: [16]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            const d: u8 = @intCast(v & 0xF);
            buf[i] = if (d < 10) d + '0' else d - 10 + 'A';
            v >>= 4;
        }
    }
    rawWrite(buf[i..]);
}
