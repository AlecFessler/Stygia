//! Spec-v3 syscall dispatch table — switches on the syscall number
//! encoded in the syscall word and trampolines into the per-object
//! handler in this directory. The arch-specific entry path collects
//! register-passed args and any vreg-passed extras into the `args`
//! slice before calling here. See docs/kernel/specv3.md §[syscall].
//!
//! `caller` is the calling EC, type-erased to keep the syscall surface
//! free of the per-arch context type. Each handler casts it back to
//! `*ExecutionContext` internally.

const std = @import("std");
const stygia = @import("stygia");

const capability = stygia.syscall.capability;
const capability_domain = stygia.syscall.capability_domain;
const errors = stygia.syscall.errors;
const event_route = stygia.syscall.event_route;
const execution_context = stygia.syscall.execution_context;
const futex = stygia.syscall.futex;
const kprof = stygia.kprof.trace_id;
const page_frame = stygia.syscall.page_frame;
const port = stygia.syscall.port;
const reply = stygia.syscall.reply;
const system = stygia.syscall.system;
const timer = stygia.syscall.timer;
const vmar = stygia.syscall.vmar;
const virtual_machine = stygia.syscall.virtual_machine;

pub const SyscallNum = enum(u64) {
    @"suspend" = 14,
    restrict = 15,
    delete = 16,
    revoke = 17,
    sync = 18,
    create_capability_domain = 19,
    acquire_ecs = 20,
    acquire_vmars = 21,
    create_execution_context = 22,
    self = 23,
    terminate = 24,
    yield = 25,
    priority = 26,
    affinity = 27,
    perfmon_info = 28,
    perfmon_start = 29,
    perfmon_read = 30,
    perfmon_stop = 31,
    create_vmar = 32,
    map_pf = 33,
    map_mmio = 34,
    unmap = 35,
    remap = 36,
    snapshot = 37,
    idc_read = 38,
    idc_write = 39,
    create_page_frame = 40,
    ack = 41,
    create_virtual_machine = 42,
    create_vcpu = 43,
    map_guest = 44,
    unmap_guest = 45,
    vm_set_policy = 46,
    vm_inject_irq = 47,
    create_port = 48,
    recv = 49,
    bind_event_route = 50,
    clear_event_route = 51,
    reply = 52,
    timer_arm = 54,
    timer_rearm = 55,
    timer_cancel = 56,
    futex_wait_val = 57,
    futex_wait_change = 58,
    futex_wake = 59,
    time_monotonic = 60,
    time_getwall = 61,
    time_setwall = 62,
    random = 63,
    info_system = 64,
    info_cores = 65,
    power_shutdown = 66,
    power_reboot = 67,
    power_sleep = 68,
    power_screen_off = 69,
    power_set_freq = 70,
    power_set_idle = 71,
    kprof_dump = 72,
};

/// Read `args[i]`, returning 0 when the index is past the end. Lets
/// handlers that take fewer args than the max not have to special-case
/// the slice length.
inline fn arg(args: []const u64, i: usize) u64 {
    return if (i < args.len) args[i] else 0;
}

/// Compute the highest vreg index a syscall could read (1-based per
/// Spec §[syscall_abi]; vreg 0 = syscall word, vregs 1..=N are payload).
/// Used by the arch slow-path entry to size the user-stack read window.
/// vregs above the architecture's register-backed band (vreg > 13 on
/// x86-64, vreg > 31 on aarch64) live on the user stack and require
/// an SMAP/PAN-gated load. The libz issue primitives reserve enough
/// user stack to cover any vreg in 0..127, so the kernel can always
/// read up to the syscall's structurally-required upper bound without
/// page-faulting.
///
/// Each high-arg syscall encodes its count in syscall-word bits 12-19
/// (or 13-20 for `vm_set_policy`). The mapping from count to upper
/// vreg follows §[syscall_abi]'s per-syscall layout.
pub fn expectedMaxVreg(syscall_word: u64) u8 {
    const num_raw: u64 = syscall_word & 0xFFF;
    if (num_raw <= 13) return 2; // fast-suspend: target + port
    const num = std.meta.intToEnum(SyscallNum, num_raw) catch return 13;
    const n_reg: u64 = (syscall_word >> 12) & 0xFF;
    return switch (num) {
        // Register-only — at most 5 args, all in vregs 1..N.
        .restrict, .delete, .revoke, .sync,
        .acquire_ecs, .acquire_vmars,
        .self, .terminate, .yield, .priority, .affinity,
        .perfmon_info, .perfmon_read, .perfmon_stop,
        .create_execution_context,
        .create_vmar, .map_mmio, .remap, .snapshot, .idc_read,
        .create_page_frame, .ack,
        .create_virtual_machine, .create_vcpu,
        .vm_inject_irq,
        .create_port, .recv, .bind_event_route, .clear_event_route,
        .timer_arm, .timer_rearm, .timer_cancel,
        .futex_wake,
        .time_monotonic, .time_getwall, .time_setwall,
        .random,
        .info_system, .info_cores,
        .power_shutdown, .power_reboot, .power_sleep, .power_screen_off,
        .power_set_freq, .power_set_idle,
        .kprof_dump,
        => 13,

        // create_capability_domain: passed_handles list, no syscall-word
        // count. Surface the full upper window.
        .create_capability_domain => 127,

        // perfmon_start: vreg 1=target, 2=num_configs, 3..2+2*count =
        // configs (each config = (event, threshold) pair = 2 vregs).
        .perfmon_start => @intCast(@min(2 + 2 * n_reg, 127)),

        // map_pf, map_guest, futex_wait_val/change: pairs of 2 vregs
        // each. Vreg 1 = handle/timeout, vregs 2..1+2N = pair data.
        .map_pf, .map_guest, .futex_wait_val, .futex_wait_change => @intCast(@min(1 + 2 * n_reg, 127)),

        // unmap, unmap_guest: singleton entries. vreg 1 = handle,
        // vregs 2..1+N = entries.
        .unmap, .unmap_guest => @intCast(@min(1 + n_reg, 127)),

        // idc_write: vreg 1 = vmar, vreg 2 = offset, vregs 3..2+count
        // = qwords.
        .idc_write => @intCast(@min(2 + n_reg, 127)),

        // vm_set_policy: bit 12 = kind, bits 13-20 = count. Per-arch
        // entry width — surface the full upper window.
        .vm_set_policy => 127,

        // suspend (general variant): pair_count in bits 12-19; pair
        // entries in the high band [128-N..127] so when pair_count > 0
        // the entire upper window must be covered.
        .@"suspend" => if (n_reg > 0) @as(u8, 127) else @as(u8, 13),

        // reply / reply_transfer: pair_count in bits 12-19; pair entries
        // in the high band — handler reads them itself via userAccess
        // gating, so dispatch's args slice does NOT need to carry them.
        .reply => 13,
    };
}

/// TEMP DIAGNOSTIC (stygia-2u0, REMOVE). State for `logSpawnError`.
var spawn_err_prints: u32 = 0;
var syscall_seq: u64 = 0;

/// TEMP DIAGNOSTIC (stygia-2u0, REMOVE). The multi-pass collapse is
/// entirely silent: ten clean passes, then decay to zero delivered
/// results, with no panic, no fault, and — measured — no allocBlock
/// failure and no handle-table exhaustion. Every candidate resource
/// tested so far returns its "empty" signal without printing anything,
/// so instead of guessing at the next one, report which SPAWN syscall
/// starts refusing and with what code. Restricted to the two spawn
/// syscalls so the budget is not eaten by tests that fail on purpose,
/// and stamped with a sequence number so the failures can be located
/// relative to the runner's own pass summaries in the same log.
fn logSpawnError(num_raw: u64, res: i64) void {
    if (res >= 0) return;
    if (num_raw != @intFromEnum(SyscallNum.create_capability_domain) and
        num_raw != @intFromEnum(SyscallNum.create_execution_context)) return;
    if (spawn_err_prints >= 24) return;
    spawn_err_prints += 1;
    stygia.arch.dispatch.boot.print(
        "[2u0] spawn syscall {d} -> {d} (seq {d})\n",
        .{ num_raw, res, syscall_seq },
    );
}

/// TEMP DIAGNOSTIC (stygia-2u0, REMOVE). Census state.
const EcCensus = struct {
    total: u32 = 0,
    on_cpu: u32 = 0,
    susp: u32 = 0,
    with_port: u32 = 0,
    pending_reply: u32 = 0,
    /// Per-`State` histogram: running/ready/suspended_on_port/
    /// futex_wait/idle_wait/exited. The three hand-picked counters
    /// above were not enough — `with_port` and `pending_reply` stayed
    /// FLAT across a run where `total` more than quadrupled, so the
    /// accumulating population is in some other state entirely. Let it
    /// name itself rather than guessing which counter to add next.
    by_state: [6]u32 = @splat(0),
    /// Alive but never dispatched (`last_dispatched_core` == 0xFF).
    never_disp: u32 = 0,
    /// Leaked-`.exited` breakdown by originating writer (leak_tag):
    /// [1]=parkSelfFaulted [2]=terminate [3]=destroyExecutionContextLocked,
    /// [0]=never tagged (state set somewhere untagged).
    exit_by_tag: [4]u32 = @splat(0),
    /// `.exited` ECs with `on_cpu` still set. A stranded `on_cpu` makes
    /// every reap path skip the EC forever (the stygia-7jm residual that
    /// `takeOwnPendingZombie` has a bounded escape for) — if this tracks
    /// `exit`, that escape is not covering these.
    exit_on_cpu: u32 = 0,
    /// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Alive ECs whose owning CD
    /// slot no longer carries the gen the EC captured — i.e. the domain
    /// was destroyed (or its slot recycled) and this EC outlived it.
    /// This is the direct measurement of "the domain-teardown EC walk is
    /// missing them". If the climbing population is NOT orphaned, the
    /// whole domain-teardown story is refuted and the ECs belong to a
    /// still-live domain that simply never reaps them.
    orphan: u32 = 0,
    /// Orphan histogram over the same six states, so we can tell a
    /// stranded-runnable leak from a stranded-parked one.
    orphan_by_state: [6]u32 = @splat(0),
};

fn censusVisit(ctx: *EcCensus, ec: *stygia.sched.execution_context.ExecutionContext, gen: u63) bool {
    ctx.total += 1;
    if (ec.on_cpu.load(.acquire)) ctx.on_cpu += 1;
    if (ec.suspend_port != null) ctx.with_port += 1;
    const st = @intFromEnum(ec.state);
    if (st < ctx.by_state.len) ctx.by_state[st] += 1;
    if (ec.last_dispatched_core == 0xFF) ctx.never_disp += 1;
    // TEMP DIAGNOSTIC (stygia-afo, REMOVE). caller-pinned: the CD slab is
    // statically backed, so reading the gen word of a dead (even zeroed)
    // slot is safe; we never touch any other field.
    if (ec.domain.ptr._gen_lock.currentGen() != ec.domain.gen) {
        ctx.orphan += 1;
        if (st < ctx.orphan_by_state.len) ctx.orphan_by_state[st] += 1;
    }
    if (ec.state == .exited and ec.on_cpu.load(.acquire)) ctx.exit_on_cpu += 1;
    if (ec.state == .exited) {
        const t = ec.leak_tag;
        ctx.exit_by_tag[if (t < 4) t else 0] += 1;
    }
    if (ec.pending_reply_holder != null) {
        ctx.pending_reply += 1;
        // Identify the stuck ones. Only ~9 at collapse, so printing each
        // is cheap and tells us what they are: state, which port they
        // are parked on, and which core last ran them. An EC parked
        // SUSP on a port holding an undelivered reply, whose partner is
        // already dead, is the shape to confirm or rule out.
        if (ctx.pending_reply <= 6) {
            stygia.arch.dispatch.boot.print(
                "[2u0]   stuck ec=0x{x} gen={d} state={d} on_cpu={d} last_disp={d} port=0x{x}\n",
                .{
                    @intFromPtr(ec),
                    @as(u64, gen),
                    @intFromEnum(ec.state),
                    @as(u8, if (ec.on_cpu.load(.acquire)) 1 else 0),
                    @as(u64, ec.last_dispatched_core),
                    if (ec.suspend_port) |sp| @intFromPtr(sp.ptr) else 0,
                },
            );
        }
    }
    return true;
}

/// TEMP DIAGNOSTIC (stygia-2u0, REMOVE). Five mechanisms have now been
/// tested and refuted (kstack A/B neutral, allocBlock never fails,
/// handle table never full, spawn syscalls never error, timer
/// propagation not hot). Spawns succeed and workers stop delivering, so
/// stop proposing resources and just watch what DRIFTS across the ten
/// good passes: how many ECs are alive, how many are parked on a port,
/// how many hold an undelivered reply. A monotone climb in any of these
/// across passes 1-10 is the accumulating state; flat lines refute the
/// whole "accumulation" framing and point at the runner side instead.
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Count LIVE capability domains.
/// Every previous census logged `cd_slots` = slab `count_total`, which is
/// monotonic by construction and says nothing about liveness. ECs that
/// are `.ready` but in no run queue are simply never-started ECs — which
/// is normal — so the real question is whether their DOMAINS are being
/// torn down. If live CDs climb with the same slope, domains leak and
/// every per-domain object rides along.
var cd_live_count: u32 = 0;
fn cdCountVisit(ctx: *u32, cd: *stygia.caps.capability_domain.CapabilityDomain, gen: u63) bool {
    _ = cd;
    _ = gen;
    ctx.* += 1;
    return true;
}

fn ecCensus() void {
    var c: EcCensus = .{};
    stygia.sched.execution_context.slab_instance.forEachAlive(&c, censusVisit);
    cd_live_count = 0;
    stygia.caps.capability_domain.slab_instance.forEachAlive(&cd_live_count, cdCountVisit);
    // How many pending_zombie columns are actually occupied right now,
    // across every core. `.exited` ECs pile up ~8/pass; this says
    // whether they are POSTED and never drained (pz high) or were never
    // posted at all (pz ~0) — different bugs, different fixes.
    var pz: u32 = 0;
    var ci: usize = 0;
    // Per-core "parked with work queued" detector. READY ECs that were
    // never dispatched accumulate before the collapse (rdy 10 -> 44,
    // nodisp -> 56), which means workers get enqueued but never
    // scheduled. A core sitting `idle_parked` while its own run_queue is
    // NON-EMPTY is a lost wake, and is decisive without walking the
    // queues. Encoded one char per core: '.' idle+empty, 'R' running,
    // 'q' awake with work, '!' PARKED WITH WORK QUEUED (the bug).
    var qmap: [8]u8 = @splat('-');
    while (ci < stygia.sched.scheduler.MAX_CORES) : (ci += 1) {
        const st = &stygia.sched.scheduler.core_states[ci];
        const slots = &st.pending_zombie;
        var si: usize = 0;
        while (si < slots.len) : (si += 1) {
            if (slots[si] != null) pz += 1;
        }
        if (ci < qmap.len) {
            const empty = st.run_queue.isEmpty();
            const parked = st.idle_parked;
            qmap[ci] = if (parked and !empty) '!' else if (parked) '.' else if (!empty) 'q' else 'R';
        }
    }
    stygia.arch.dispatch.boot.print(
        "[2u0] census seq={d} alive={d} run={d} rdy={d} susp={d} futex={d} idle={d} exit={d} exit_oncpu={d} pz_occupied={d} nodisp={d} port={d} preply={d} parks={d} cores=[{s}] tag0={d} tag1={d} tag2={d} tag3={d} ec_slots={d} cd_slots={d} cd_live={d}\n",
        .{
            syscall_seq,
            c.total,
            c.by_state[0],
            c.by_state[1],
            c.by_state[2],
            c.by_state[3],
            c.by_state[4],
            c.by_state[5],
            c.exit_on_cpu,
            pz,
            c.never_disp,
            c.with_port,
            c.pending_reply,
            stygia.sched.execution_context.park_calls,
            qmap[0..@min(stygia.sched.scheduler.MAX_CORES, qmap.len)],
            c.exit_by_tag[0],
            c.exit_by_tag[1],
            c.exit_by_tag[2],
            c.exit_by_tag[3],
            stygia.sched.execution_context.slab_instance.count_total,
            stygia.caps.capability_domain.slab_instance.count_total,
            cd_live_count,
        },
    );
    // TEMP DIAGNOSTIC (stygia-afo, REMOVE). Second line: the two
    // discriminators for "domain teardown strands ECs".
    stygia.arch.dispatch.boot.print(
        "[afo] census seq={d} orph={d} orph_st=[{d},{d},{d},{d},{d},{d}] p2_enter={d} p2_reap={d} p2_walk={d} p2_exit={d} p2_resid={d} slowpost={d}\n",
        .{
            syscall_seq,
            c.orphan,
            c.orphan_by_state[0],
            c.orphan_by_state[1],
            c.orphan_by_state[2],
            c.orphan_by_state[3],
            c.orphan_by_state[4],
            c.orphan_by_state[5],
            stygia.caps.capability_domain.p2_enter,
            stygia.caps.capability_domain.p2_after_reap,
            stygia.caps.capability_domain.p2_walk_done,
            stygia.caps.capability_domain.p2_exit,
            stygia.caps.capability_domain.p2_residue,
            stygia.sched.execution_context.slow_post_spins,
        },
    );
    // TEMP DIAGNOSTIC (stygia-afo, REMOVE). Third line: WHERE the residual
    // phase-2 abandonments happen. `sp_in`/`sp_out` bracket the contended
    // IRQ-enabling postZombie spin; `wv_in`/`wv_out` bracket the walk's
    // per-victim destroy; `ab_p2` counts abandonments observed directly at
    // the `switchTo`-with-null-current_ec that loses the frame. Three
    // independent instruments for one number.
    stygia.arch.dispatch.boot.print(
        "[afo2] census seq={d} sp_in={d} sp_out={d} sp_self={d} wv_in={d} wv_out={d} ab_p2={d} ab_other={d} inl_ok={d} inl_no={d}\n",
        .{
            syscall_seq,
            stygia.sched.execution_context.slow_post_spins,
            stygia.sched.execution_context.slow_post_done,
            stygia.sched.execution_context.slow_post_self,
            stygia.sched.execution_context.walk_visit_enter,
            stygia.sched.execution_context.walk_visit_done,
            stygia.caps.capability_domain.abandoned_in_p2,
            stygia.caps.capability_domain.abandoned_other,
            stygia.sched.execution_context.inline_finalize_ok,
            stygia.sched.execution_context.inline_finalize_no,
        },
    );
    // TEMP DIAGNOSTIC (stygia-9zr, REMOVE). Fourth line: does the timer
    // propagate walk read a CapabilityDomain that died under it?
    // `w_gen` counts visitor invocations whose CD gen changed between
    // entry and exit; `w_null` counts those whose handle-table base
    // pointer changed or went null in the same window — the exact
    // condition behind the x86 pass-79 panic (104*3687 from a NULL
    // base at timer.zig propagateField1Visitor). `w_stale` counts CDs
    // the walk declined to touch because verify-and-acquire found the
    // slot already dead.
    stygia.arch.dispatch.boot.print(
        "[9zr2] census seq={d} w_visits={d} w_gen={d} w_null={d} w_stale={d}\n",
        .{
            syscall_seq,
            stygia.sched.timer.w_visits,
            stygia.sched.timer.w_gen,
            stygia.sched.timer.w_null,
            stygia.sched.timer.w_stale,
        },
    );
}

pub fn dispatch(caller: *anyopaque, syscall_word: u64, args: []const u64) i64 {
    kprof.enter(.syscall);
    defer kprof.exit(.syscall);
    syscall_seq +%= 1;
    // TEMP DIAGNOSTIC (stygia-2u0, REMOVE).
    if (syscall_seq % 100_000 == 0) ecCensus();

    // Spec §[syscall]: syscall number lives in bits 0-11 of the syscall
    // word. Anything beyond that range is per-syscall metadata
    // (pair_count, kind, etc.) and is the handler's responsibility.
    const num_raw: u64 = syscall_word & 0xFFF;
    kprof.point(.syscall, num_raw);

    // Fast-suspend wire format: syscall_op in 0..13 encodes a suspend
    // with payload_count = syscall_op and pair_count = 0. The asm L4
    // fast path normally handles this; reaching the slow path means
    // a predicate failed (no receiver queued, port lock contended,
    // wrong type tag, etc.). Route through the regular suspend handler
    // so the same caps + state mutations apply.
    if (num_raw <= 13) {
        return port.@"suspend"(caller, arg(args, 0), arg(args, 1), 0);
    }

    const num = std.meta.intToEnum(SyscallNum, num_raw) catch return errors.E_INVAL;

    const dispatch_res = switch (num) {
        .restrict => capability.restrict(caller, arg(args, 0), arg(args, 1)),
        .delete => capability.delete(caller, arg(args, 0)),
        .revoke => capability.revoke(caller, arg(args, 0)),
        .sync => capability.sync(caller, arg(args, 0)),

        .create_capability_domain => capability_domain.createCapabilityDomain(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
            if (args.len > 5) args[5..] else &.{},
        ),
        .acquire_ecs => capability_domain.acquireEcs(caller, arg(args, 0)),
        .acquire_vmars => capability_domain.acquireVmars(caller, arg(args, 0)),

        .create_execution_context => execution_context.createExecutionContext(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
        ),
        .self => execution_context.self(caller),
        .terminate => execution_context.terminate(caller, arg(args, 0)),
        .yield => execution_context.yield(caller, arg(args, 0)),
        .priority => execution_context.priority(caller, arg(args, 0), arg(args, 1)),
        .affinity => execution_context.affinity(caller, arg(args, 0), arg(args, 1)),
        .perfmon_info => execution_context.perfmonInfo(caller),
        .perfmon_start => execution_context.perfmonStart(
            caller,
            arg(args, 0),
            arg(args, 1),
            if (args.len > 2) args[2..] else &.{},
        ),
        .perfmon_read => execution_context.perfmonRead(caller, arg(args, 0)),
        .perfmon_stop => execution_context.perfmonStop(caller, arg(args, 0)),

        .create_vmar => vmar.createVmar(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
        ),
        .map_pf => blk: {
            // Spec §[var].map_pf: syscall word bits 12-19 carry N, the
            // number of (offset, page_frame) pairs. The pairs occupy
            // vregs 2..2+2N-1 — args[1..1+2N]. Without this slice the
            // handler sees uninitialized vregs as junk pairs.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk vmar.mapPf(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .map_mmio => vmar.mapMmio(caller, arg(args, 0), arg(args, 1)),
        .unmap => blk: {
            // Spec §[var].unmap: syscall word bits 12-19 carry N, the
            // number of selectors (0 = unmap everything). The selectors
            // occupy vregs 2..1+N — args[1..1+N]. Without this slice the
            // handler sees uninitialized vregs above the user's payload
            // as junk selectors (e.g. a `&.{}` call would gate into the
            // map=1/3 selector arms and trip E_BADCAP / E_INVAL on
            // garbage values, breaking the N=0 "unmap everything" path).
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const end_idx: usize = @min(1 + @as(usize, @intCast(n)), args.len);
            break :blk vmar.unmap(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .remap => vmar.remap(caller, arg(args, 0), arg(args, 1)),
        .snapshot => vmar.snapshot(caller, arg(args, 0), arg(args, 1)),
        .idc_read => blk: {
            // Spec §[var].idc_read: syscall word bits 12-19 carry count
            // (number of qwords, max 125). Args carry only [1] var and
            // [2] offset — vreg 3 onwards holds the *return* qwords, so
            // sourcing count from `arg(args, 2)` would read whatever the
            // caller left in rdx (typically 0) and trip the count-zero
            // guard before the BADCAP / alignment / size checks ever
            // run, breaking [test 01] / [test 02] / [test 07] / [test 08].
            const n: u8 = @truncate((syscall_word >> 12) & 0xFF);
            break :blk vmar.idcRead(
                caller,
                arg(args, 0),
                arg(args, 1),
                n,
            );
        },
        .idc_write => blk: {
            // Spec §[var].idc_write: syscall word bits 12-19 carry count
            // (number of qwords, max 125). Qwords occupy vregs 3..2+count
            // — args[2..2+count]. The handler needs the *raw* count
            // (before slice truncation) so it can return E_INVAL for
            // count > 125 even though the args slice tops out at 13
            // entries (test 04 boundary).
            const n: u8 = @truncate((syscall_word >> 12) & 0xFF);
            const end_idx: usize = @min(2 + @as(usize, n), args.len);
            break :blk vmar.idcWrite(
                caller,
                arg(args, 0),
                arg(args, 1),
                n,
                if (end_idx > 2) args[2..end_idx] else &.{},
            );
        },

        .create_page_frame => page_frame.createPageFrame(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),

        .ack => reply.ack(caller, arg(args, 0)),

        .create_port => port.createPort(caller, arg(args, 0)),
        .@"suspend" => blk: {
            // Spec §[handle_attachments]: syscall word bits 12-19 carry
            // `pair_count` `N`. When N > 0 the [2] port handle must
            // carry the `xfer` cap (test 01), entries must be valid,
            // etc. The handler needs the count to gate that check.
            const pair_count: u8 = @truncate((syscall_word >> 12) & 0xFF);
            break :blk port.@"suspend"(caller, arg(args, 0), arg(args, 1), pair_count);
        },
        .recv => port.recv(caller, arg(args, 0), arg(args, 1)),

        .bind_event_route => event_route.bindEventRoute(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .clear_event_route => event_route.clearEventRoute(caller, arg(args, 0), arg(args, 1)),

        .reply => reply.reply(caller, syscall_word),

        .timer_arm => timer.timerArm(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .timer_rearm => timer.timerRearm(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .timer_cancel => timer.timerCancel(caller, arg(args, 0)),

        .futex_wait_val => blk: {
            // Spec §[futex_wait_val]: syscall word bits 12-19 carry N
            // (number of (addr, expected) pairs, 1..63). The pairs
            // occupy vregs 2..1+2N — args[1..1+2N]. Without this slice
            // the handler sees uninitialized vregs as junk pairs.
            //
            // [test 02] N = 0 or N > 63 must surface E_INVAL. We
            // validate the raw N here BEFORE slicing — otherwise an
            // out-of-range N could silently truncate to a smaller
            // valid count once clamped against args.len, masking the
            // bounds violation.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            if (n == 0 or n > 63) break :blk errors.E_INVAL;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk futex.futexWaitVal(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .futex_wait_change => blk: {
            // Spec §[futex_wait_change]: identical N-bounds rule as
            // futex_wait_val — see comment above.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            if (n == 0 or n > 63) break :blk errors.E_INVAL;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk futex.futexWaitChange(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .futex_wake => futex.futexWake(caller, arg(args, 0), arg(args, 1)),

        .create_virtual_machine => virtual_machine.createVirtualMachine(
            caller,
            arg(args, 0),
            arg(args, 1),
        ),
        .create_vcpu => virtual_machine.createVcpu(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
        ),
        .map_guest => blk: {
            // Spec §[virtual_machine].map_guest: syscall word bits 12-19
            // carry N, the number of (guest_addr, page_frame) pairs. The
            // pairs occupy vregs 2..2+2N-1 — args[1..1+2N]. Without this
            // slice the handler sees uninitialized vregs above the user's
            // payload as junk pairs (pairs.len ends up odd or carries
            // garbage handles, tripping E_INVAL/E_BADCAP before the
            // user's actual error path can fire).
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk virtual_machine.mapGuest(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .unmap_guest => blk: {
            // Spec §[virtual_machine].unmap_guest: syscall word bits 12-19
            // carry N, the number of page_frames to unmap. The handles
            // occupy vregs 2..1+N — args[1..1+N]. Without this slice the
            // handler sees uninitialized vregs above the user's payload
            // as junk handles, tripping E_BADCAP before the user's
            // intended error path runs.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const end_idx: usize = @min(1 + @as(usize, @intCast(n)), args.len);
            break :blk virtual_machine.unmapGuest(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .vm_set_policy => blk: {
            // Spec §[virtual_machine].vm_set_policy: syscall word bit 12
            // = kind, bits 13-20 = count. Each entry occupies a per-arch,
            // per-kind number of vregs (3 on x86-64 for kind 0/1; 2 or 3
            // on aarch64 per §[vm_set_policy]). The handler resolves the
            // exact vreg count against count + the (kind, arch) layout;
            // dispatch hands it the full vreg space above [1] so the
            // handler can validate `entries.len == count * vregs/entry`
            // and reject malformed wires.
            const end_idx: usize = args.len;
            break :blk virtual_machine.vmSetPolicy(
                caller,
                syscall_word,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .vm_inject_irq => virtual_machine.vmInjectIrq(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),

        .time_monotonic => system.timeMonotonic(caller),
        .time_getwall => system.timeGetwall(caller),
        .time_setwall => system.timeSetwall(caller, arg(args, 0)),
        .random => blk: {
            // Spec §[rng] random: count packed in syscall word bits 12-19.
            const count: u8 = @truncate((syscall_word >> 12) & 0xFF);
            break :blk system.random(caller, count);
        },
        .info_system => system.infoSystem(caller),
        .info_cores => system.infoCores(caller, arg(args, 0)),
        .power_shutdown => system.powerShutdown(caller),
        .power_reboot => system.powerReboot(caller),
        .power_sleep => system.powerSleep(caller, arg(args, 0)),
        .power_screen_off => system.powerScreenOff(caller),
        .power_set_freq => system.powerSetFreq(caller, arg(args, 0), arg(args, 1)),
        .power_set_idle => system.powerSetIdle(caller, arg(args, 0), arg(args, 1)),
        .kprof_dump => blk: {
            // Stop-the-world quiesce + dump. IPIs every other core to
            // park, drains in-flight emits, dumps every CPU's log to
            // serial in core-id order, then halts. Doesn't return.
            stygia.kprof.dump.end(.root_exit);
            break :blk 0;
        },
    };
    // TEMP DIAGNOSTIC (stygia-2u0, REMOVE).
    logSpawnError(num_raw, dispatch_res);
    return dispatch_res;
}
