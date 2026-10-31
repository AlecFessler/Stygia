//! SMP=4 lost-wakeup hang detector.
//!
//! Wired into `arch.x64.serial.printRaw` (every kernel/userspace COM1 byte
//! bumps `last_progress_ns`) and the LAPIC scheduler tick (compares
//! `now - last_progress_ns` against `HANG_THRESHOLD_NS`; on overshoot,
//! calls `dump()` exactly once).
//!
//! `dump()` walks every initialized core_states[i] and emits the thread/state/
//! on_cpu/run-queue snapshot for each, plus the runner's likely result-port
//! wait queue if it can be inferred. Output is unlocked `printRaw` (same
//! discipline as panic) so it can run mid-spinlock without deadlocking.
//!
//! NOT build-gated. This module is compiled into every profile, and the
//! x86-only paths self-disable via `builtin.cpu.arch` (`tickCheck`,
//! `arm` and `forceDump` all open with that guard).
//!
//! **The fast path is not as cheap as this comment used to claim.** It
//! was described as "one atomic load plus a clock read"; it is actually
//! a globally-shared `tick_counter.fetchAdd` — a contended cacheline,
//! every tick on every core — plus FOUR `outb` to COM1 every 64th tick
//! via `emitHeartbeatByte`, then `armed.load`, `dump_fired.load`, the
//! clock read, and `last_progress_ns.load`. That is one atomic RMW,
//! three atomic loads, a clock read, and periodic port I/O. The cost is
//! still judged acceptable for an always-on hang detector, but it is
//! stated honestly here because that cost is the entire justification
//! for not gating this module, and an understated cost is how a gate
//! decision gets made on bad information. An earlier version
//! of this comment claimed a `-Dkernel_hang_detector` gate "default true
//! under -Dprofile=test" — no such `b.option` has ever existed, and the
//! string appeared nowhere in the tree except in that claim. The nearest
//! real flag is `-Dkernel_hang_watchdog`, which arms the HPET-NMI
//! watchdog as a second entry point into `dump` and is a different thing.
//! The one real gate reachable from here is `-Dspin_entry_diag`, which
//! controls only `spin_diag.entries` / the `sched_entries` column.

const std = @import("std");
const builtin = @import("builtin");
const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;
const thread_mod = stygia.sched.thread;
const process_mod = stygia.caps.process;
const lifecycle = stygia.sched.lifecycle;
const scheduler = stygia.sched.scheduler;
const spin_diag = stygia.utils.spin_diag;
const Thread = stygia.sched.thread.Thread;
const EventType = stygia.sched.thread.EventType;
const State = stygia.sched.thread.State;
const WaitKind = stygia.sched.thread.WaitKind;

/// 4s of no-newline-progress = hang. Used as a backstop only — the
/// primary detector on this branch is `allCoresIdle()` driven from the
/// HPET-NMI watchdog, which fires within ~30 ms of every core entering
/// the user-mode idle hlt loop with current_thread=null (the smp=4 reply-FP
/// signature). The 4s threshold catches the slow-tail variants where
/// userspace IS still running but a single thread is wedged in a fault
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

/// stygia-8xl: how many hang photographs one boot may emit. See the
/// re-arm in `tickCheck`.
pub const DUMP_BUDGET: u32 = 6;
pub var dumps_emitted: u32 = 0;

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

/// Called from the LAPIC scheduler tick after the periodic work. The
/// fast path when nothing is wrong is one shared atomic RMW
/// (`tick_counter`), three atomic loads, a clock read, and — every 64th
/// tick — four `outb` to COM1. See the module header: this used to be
/// documented as "one atomic load + one TSC read + one subtraction",
/// which was never true of the code below it.
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
        // stygia-8xl: the one-shot latch used to cost us every event
        // after the first in a repeat-100 boot. The runner RECOVERS from
        // one of these (it skips the batch and carries on), so a boot can
        // produce several independent hangs and only the first was ever
        // photographed. Allow a small budget instead, and re-arm the
        // progress stamp after each dump so the next one needs a fresh
        // HANG_THRESHOLD_NS of silence rather than tripping immediately
        // on the dump's own elapsed time.
        if (dump_fired.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return;
        emitHeartbeatByte('!');
        dump(delta);
        const dumps = @atomicRmw(u32, &dumps_emitted, .Add, 1, .monotonic) + 1;
        last_progress_ns.store(arch.time.currentMonotonicNs(), .release);
        if (dumps < DUMP_BUDGET) dump_fired.store(false, .release);
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

    dumpSpinLiveness(num_cores);
    dumpLifecycleCounters();
    dumpSpawnTraceSamples();

    // Walk every alive thread slab slot and emit its state. Catches
    // orphaned waiters parked in port wait queues that don't show up
    // in any per-core current_thread / run_queue. Bounded by the slab
    // total — typically <100 in a smp=4 test run, so this is cheap.
    rawWrite("[HANG] live Threads:\n");
    thread_mod.slab_instance.forEachAlive(@as(*u8, @ptrCast(&dump_visit_dummy)), dumpAliveThread);

    rawWrite("[HANG] (end)\n");
}

/// stygia-8xl liveness probe. Snapshot every core's spin/entry counters,
/// busy-wait a bounded window, snapshot again, print the deltas.
///
/// This is the half that makes the breadcrumbs interpretable:
///   spin+ > 0   → the core is spinning AT `site` right now.
///   spin+ = 0, ent+ > 0 → not spinning anywhere instrumented, but still
///                 taking the scheduler vector: it is in userspace or a
///                 bounded kernel path, and `site` is a stale leftover.
///   both 0      → the core is taking no interrupts at all: wedged with
///                 IRQs masked, or halted without a wake source.
fn dumpSpinLiveness(num_cores: u64) void {
    var i: u64 = 0;
    while (i < num_cores) : (i += 1) {
        before_spin[i] = @atomicLoad(u64, &spin_diag.iters[i], .monotonic);
        before_ent[i] = spin_diag.entryCount(i);
    }

    // Bounded busy-wait. Two constraints shape it:
    //
    //  * It must SERVICE TLB MAINTENANCE. This core is IRQ-masked for the
    //    whole window, and a peer inside `waitForShootdownAcks` is waiting
    //    on our ack — measured at 10.7M spin iterations against an earlier
    //    version of this loop that only issued `pause`. Not a deadlock
    //    (the window is bounded) but it perturbs the very state we are
    //    here to photograph, and with a dump budget above 1 it does so
    //    repeatedly.
    //  * It is 60 ms, not 120. A core actually spinning racks up ~10^5
    //    iterations in that time versus exactly 0 for a frozen one, which
    //    is all the discrimination this probe needs; halving it halves the
    //    perturbation.
    const start = arch.time.currentMonotonicNs();
    while (arch.time.currentMonotonicNs() -% start < 60_000_000) {
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        asm volatile ("pause" ::: .{ .memory = true });
    }

    const this_core: u64 = @truncate(arch.smp.coreID());
    rawWrite("[HANG] liveness over 60ms:\n");
    i = 0;
    while (i < num_cores) : (i += 1) {
        rawWrite("[HANG]   core=");
        printDecimal(i);
        rawWrite(" spins+=");
        printDecimal(@atomicLoad(u64, &spin_diag.iters[i], .monotonic) -% before_spin[i]);
        rawWrite(" sched_entries+=");
        printDecimal(spin_diag.entryCount(i) -% before_ent[i]);
        rawWrite(" site=");
        rawWrite(spin_diag.siteName(@atomicLoad(u16, &spin_diag.site[i], .monotonic)));
        rawWrite(" arg=");
        printHex(@atomicLoad(u64, &spin_diag.arg[i], .monotonic));
        // The dumping core is frozen by this very loop for the whole
        // window, so its deltas are 0 BY CONSTRUCTION. Unlabelled, that
        // reads as "wedged with interrupts masked" under the rule below
        // and turns the probe into exactly the false-signal trap it was
        // built to remove.
        if (i == this_core) rawWrite("   <-- DUMPING CORE: deltas frozen by this probe, NOT a signal");
        rawWrite("\n");
    }
    rawWrite("[HANG]   (spins+>0 = spinning at site; spins+=0 with sched_entries+>0 = not spinning, site is stale; both 0 = taking no interrupts)\n");
}

fn dumpLifecycleCounters() void {
    rawWrite("[HANG] lifecycle counters:");
    rawWrite(" p2=");
    printDecimal(loadCounter(&process_mod.p2_enter));
    rawWrite("/");
    printDecimal(loadCounter(&process_mod.p2_after_reap));
    rawWrite("/");
    printDecimal(loadCounter(&process_mod.p2_walk_done));
    rawWrite("/");
    printDecimal(loadCounter(&process_mod.p2_exit));
    rawWrite(" p2_residue=");
    printDecimal(loadCounter(&process_mod.p2_residue));
    rawWrite(" abandoned_p2=");
    printDecimal(loadCounter(&process_mod.abandoned_in_p2));
    rawWrite(" abandoned_other=");
    printDecimal(loadCounter(&process_mod.abandoned_other));
    rawWrite(" walk=");
    printDecimal(loadCounter(&thread_mod.walk_visit_enter));
    rawWrite("/");
    printDecimal(loadCounter(&thread_mod.walk_visit_done));
    rawWrite(" slow_post=");
    printDecimal(loadCounter(&thread_mod.slow_post_spins));
    rawWrite("/");
    printDecimal(loadCounter(&thread_mod.slow_post_done));
    rawWrite(" slow_self=");
    printDecimal(loadCounter(&thread_mod.slow_post_self));
    rawWrite(" inline=");
    printDecimal(loadCounter(&thread_mod.inline_finalize_ok));
    rawWrite("/");
    printDecimal(loadCounter(&thread_mod.inline_finalize_no));
    rawWrite(" park=");
    printDecimal(loadCounter(&thread_mod.park_calls));
    rawWrite("\n");

    dumpPreReportTerminalSamples();
}

fn loadCounter(counter: *u64) u64 {
    return @atomicLoad(u64, counter, .monotonic);
}

fn dumpPreReportTerminalSamples() void {
    if (!build_options.kernel_spawn_diag) return;
    const max_seq = @atomicLoad(u64, &thread_mod.pre_report_terminal_seq, .monotonic);
    rawWrite("[HANG] pre-report terminal samples: seq=");
    printDecimal(max_seq);
    rawWrite("\n");
    if (max_seq == 0) return;

    const ring_len = thread_mod.PRE_REPORT_TERMINAL_RING_LEN;
    const first_seq = if (max_seq > ring_len) max_seq - ring_len + 1 else 1;
    var seq = first_seq;
    while (seq <= max_seq) : (seq += 1) {
        const idx: usize = @intCast(seq % ring_len);
        const slot = &thread_mod.pre_report_terminal_ring[idx];
        const before = slot.publish_seq.load(.acquire);
        if (before != seq) continue;
        const sample_seq = slot.seq;
        const tag = slot.tag;
        const process = slot.process;
        const thread = slot.thread;
        const reason = slot.reason;
        const after = slot.publish_seq.load(.acquire);
        if (after != before or sample_seq != seq) continue;

        rawWrite("[HANG]   term seq=");
        printDecimal(sample_seq);
        rawWrite(" tag=");
        printHex(tag);
        rawWrite(" index=");
        printDecimal(tag - 0x8000);
        rawWrite(" process=");
        printHex(@as(u64, process));
        rawWrite(" thread=");
        printHex(@as(u64, thread));
        rawWrite(" reason=");
        rawWrite(reason);
        rawWrite("\n");
    }
}

fn dumpSpawnTraceSamples() void {
    if (!build_options.kernel_spawn_diag) return;
    const max_seq = @atomicLoad(u64, &thread_mod.spawn_trace_seq, .monotonic);
    rawWrite("[HANG] spawn trace samples: seq=");
    printDecimal(max_seq);
    rawWrite("\n");
    if (max_seq == 0) return;

    const ring_len = thread_mod.SPAWN_TRACE_RING_LEN;
    const first_seq = if (max_seq > ring_len) max_seq - ring_len + 1 else 1;
    var seq = first_seq;
    while (seq <= max_seq) : (seq += 1) {
        const idx: usize = @intCast(seq % ring_len);
        const slot = &thread_mod.spawn_trace_ring[idx];
        const before = slot.publish_seq.load(.acquire);
        if (before != seq) continue;
        const sample_seq = slot.seq;
        const event = slot.event;
        const tag = slot.tag;
        const core = slot.core;
        const thread = slot.thread;
        const process = slot.process;
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
        rawWrite(" thread=");
        printHex(@as(u64, thread));
        rawWrite(" process=");
        printHex(@as(u64, process));
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

fn printSpawnTraceEvent(event: thread_mod.SpawnTraceEvent) void {
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

/// Scratch for `dumpSpinLiveness`. Module-scope rather than stack locals:
/// two `[MAX_CORES]u64` is 1 KiB, and this path is reachable from a timer
/// IRQ whose kernel stack we do not want to spend that on. `dump_fired`
/// serialises the dump, so a single shared pair is sufficient, and zero-
/// init beats `undefined` on a diagnostic that prints what it reads.
var before_spin: [scheduler.MAX_CORES]u64 = [_]u64{0} ** scheduler.MAX_CORES;
var before_ent: [scheduler.MAX_CORES]u64 = [_]u64{0} ** scheduler.MAX_CORES;

fn dumpAliveThread(_: *u8, thread: *Thread, gen: u63) bool {
    @setRuntimeSafety(false);
    rawWrite("[HANG]   thread=");
    printHex(@intFromPtr(thread));
    rawWrite(" gen=");
    printHex(@as(u64, gen));
    rawWrite(" state=");
    printState(lifecycle.load(thread));
    rawWrite(" owner=");
    printDecimal(@as(u64, thread.owner_core));
    rawWrite(" q=");
    printQueueCore(thread);
    rawWrite(" pin=");
    printDecimal(@as(u64, thread.pin_depth.load(.acquire)));
    rawWrite(" mark=");
    printHex(@as(u64, thread.mark_state.load(.acquire)));
    rawWrite(" dir=");
    printDirective(thread);
    rawWrite(" wait=");
    printWaitSummary(thread);
    rawWrite("\n");
    return true;
}

fn dumpCore(core_id: u8) void {
    rawWrite("[HANG] core=");
    printDecimal(@as(u64, core_id));

    const pc = &scheduler.core_states[core_id];

    if (pc.current_thread) |thread| {
        rawWrite(" current_thread=");
        printHex(@intFromPtr(thread));
        rawWrite(" ref_gen=");
        printHex(@as(u64, pc.current_thread_gen));
        rawWrite(" slot_gen=");
        printHex(@as(u64, thread._gen_lock.currentGen()));
        rawWrite(" state=");
        printState(lifecycle.load(thread));
        rawWrite(" owner=");
        printDecimal(@as(u64, thread.owner_core));
        rawWrite(" q=");
        printQueueCore(thread);
        rawWrite(" pin=");
        printDecimal(@as(u64, thread.pin_depth.load(.acquire)));
        rawWrite(" mark=");
        printHex(@as(u64, thread.mark_state.load(.acquire)));
        rawWrite(" dir=");
        printDirective(thread);
        rawWrite(" wait=");
        printWaitSummary(thread);
    } else {
        rawWrite(" current_thread=null");
    }

    if (pc.teardown_pending != null) rawWrite(" teardown_pending=1");
    if (pc.idle_parked) rawWrite(" idle_parked=1");

    rawWrite("\n");

    // stygia-8xl: WHERE is this core, not just what does it hold. See
    // `utils/spin_diag.zig`; `dumpSpinLiveness` below re-samples the two
    // counters so a stale breadcrumb can be told from a live spin.
    rawWrite("[HANG]   wait: site=");
    rawWrite(spin_diag.siteName(@atomicLoad(u16, &spin_diag.site[core_id], .monotonic)));
    rawWrite(" arg=");
    printHex(@atomicLoad(u64, &spin_diag.arg[core_id], .monotonic));
    rawWrite(" spins=");
    printDecimal(@atomicLoad(u64, &spin_diag.iters[core_id], .monotonic));
    rawWrite(" sched_entries=");
    printDecimal(spin_diag.entryCount(core_id));
    rawWrite("\n");

    // Dump run-queue heads plus a short bounded walk per level. This is
    // enough to distinguish "idle and empty" from "ready work stranded"
    // without turning a recovered watchdog event into a giant log.
    var any_q = false;
    var lvl: usize = 0;
    while (lvl < pc.run_queue.levels.len) {
        const head_thread: ?*Thread = pc.run_queue.levels[lvl].head;
        if (head_thread) |e| {
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
            rawWrite(" q=");
            printQueueCore(e);
            rawWrite(" n=");
            printDecimal(countQueueLevelBounded(e));
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

fn countQueueLevelBounded(head: *Thread) u64 {
    var count: u64 = 0;
    var cur: ?*Thread = head;
    while (cur) |thread| {
        count += 1;
        if (count == 8) {
            if (thread.next != null) return 9; // 9 means "8+"
            return count;
        }
        cur = thread.next;
    }
    return count;
}

fn printWaitSummary(thread: *Thread) void {
    printWaitKind(thread.wait.kind);
    rawWrite("(");
    printDecimal(@as(u64, @intFromEnum(thread.wait.kind)));
    rawWrite(")");
    rawWrite(" payload_done=");
    printBool(thread.wait.payload_done.load(.acquire));

    if (thread.wait.port) |p| {
        rawWrite(" wait_port=");
        printHex(@intFromPtr(p.ptr));
        rawWrite("/g=");
        printHex(@as(u64, p.gen));
    }
    if (thread.wait.deadline_ns != 0) {
        rawWrite(" wait_due=");
        printDeadlineDelta(thread.wait.deadline_ns, arch.time.currentMonotonicNs());
    }
    if (thread.recv_deadline_ns != 0) {
        rawWrite(" recv_due=");
        printDeadlineDelta(thread.recv_deadline_ns, arch.time.currentMonotonicNs());
    }
    if (thread.futex_deadline_ns != 0) {
        rawWrite(" futex_due=");
        printDeadlineDelta(thread.futex_deadline_ns, arch.time.currentMonotonicNs());
    }
    if (thread.futex_bucket_count != 0) {
        rawWrite(" futex_n=");
        printDecimal(@as(u64, thread.futex_bucket_count));
        rawWrite(" wake_idx=");
        printDecimal(@as(u64, thread.futex_wake_index));
    }
    if (thread.suspend_port) |sp| {
        rawWrite(" susp_port=");
        printHex(@intFromPtr(sp.ptr));
        rawWrite("/g=");
        printHex(@as(u64, sp.gen));
    }
    if (thread.pending_pair_count != 0) {
        rawWrite(" pairs=");
        printDecimal(@as(u64, thread.pending_pair_count));
    }
    if (thread.pending_reply_holder) |holder| {
        rawWrite(" reply_holder=");
        printHex(@intFromPtr(holder));
        if (thread.pending_reply_process) |prd| {
            rawWrite(" reply_process=");
            printHex(@intFromPtr(prd.ptr));
            rawWrite("/slot=");
            printDecimal(@as(u64, thread.pending_reply_slot));
        }
    }
    if (thread.pending_event_word_valid) rawWrite(" event_word_pending");
    if (thread.pending_event_rip_valid) rawWrite(" event_rip_pending");
    if (thread.event_type != .none) {
        rawWrite(" event=");
        printEventType(thread.event_type);
        rawWrite("/");
        printDecimal(@as(u64, thread.event_subcode));
        rawWrite(" addr=");
        printHex(thread.event_addr);
    }
}

fn printQueueCore(thread: *Thread) void {
    const q = thread.current_queue_core.load(.acquire);
    if (q == stygia.sched.thread.NOT_IN_RUN_QUEUE) {
        rawWrite("none");
    } else {
        printDecimal(@as(u64, q));
    }
}

fn printDirective(thread: *Thread) void {
    const word = thread.directive_state.load(.acquire);
    printDirectiveTag(lifecycle.directiveTag(word));
    const slot = lifecycle.directiveOwnerSlot(word);
    if (slot != 0) {
        rawWrite("/slot=");
        printDecimal(@as(u64, slot));
    }
    if (thread.directive_port) |p| {
        rawWrite("/port=");
        printHex(@intFromPtr(p.ptr));
    }
    if (thread.directive_owner) |owner| {
        rawWrite("/owner=");
        printHex(@intFromPtr(owner));
    }
}

fn printDeadlineDelta(deadline_ns: u64, now_ns: u64) void {
    if (deadline_ns == std.math.maxInt(u64)) {
        rawWrite("timeout");
        return;
    }
    if (deadline_ns <= now_ns) {
        rawWrite("-");
        printDecimal((now_ns - deadline_ns) / 1_000_000);
    } else {
        rawWrite("+");
        printDecimal((deadline_ns - now_ns) / 1_000_000);
    }
    rawWrite("ms");
}

fn printBool(v: bool) void {
    rawWrite(if (v) "1" else "0");
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

fn printWaitKind(kind: WaitKind) void {
    rawWrite(switch (kind) {
        .none => "none",
        .port_sender => "port_sender",
        .port_receiver => "port_receiver",
        .reply => "reply",
        .futex => "futex",
        .idle => "idle",
        .requeue => "requeue",
    });
}

fn printDirectiveTag(tag: lifecycle.DirectiveTag) void {
    rawWrite(switch (tag) {
        .none => "none",
        .suspending => "susp",
        .claiming => "claim",
        .armed => "armed",
        .dead => "dead",
        .failed => "failed",
    });
}

fn printEventType(event_type: EventType) void {
    rawWrite(switch (event_type) {
        .none => "none",
        .suspension => "suspension",
        .vm_exit => "vm_exit",
        _ => "reserved",
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
