//! Spec-v3 syscall dispatch table — switches on the syscall number
//! encoded in the syscall word and trampolines into the per-object
//! handler in this directory. The arch-specific entry path collects
//! register-passed args and any vreg-passed extras into the `args`
//! slice before calling here. See docs/kernel/specv3.md §[syscall].
//!
//! `caller` is the calling thread, type-erased to keep the syscall surface
//! free of the per-arch context type. Each handler casts it back to
//! `*Thread` internally.

const std = @import("std");
const stygia = @import("stygia");
const build_options = @import("build_options");

const capability = stygia.syscall.capability;
const process = stygia.syscall.process;
const errors = stygia.syscall.errors;
const thread_mod = stygia.syscall.thread;
const futex = stygia.syscall.futex;
const page_frame = stygia.syscall.page_frame;
const port = stygia.syscall.port;
const reply = stygia.syscall.reply;
const system = stygia.syscall.system;
const vmar = stygia.syscall.vmar;
const virtual_machine = stygia.syscall.virtual_machine;

pub const SyscallNum = enum(u64) {
    @"suspend" = 14,
    restrict = 15,
    delete = 16,
    revoke = 17,
    sync = 18,
    create_process = 19,
    create_thread = 22,
    self = 23,
    terminate = 24,
    yield = 25,
    priority = 26,
    affinity = 27,
    create_vmar = 32,
    map_pf = 33,
    map_mmio = 34,
    unmap = 35,
    remap = 36,
    snapshot = 37,
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
    reply = 52,
    futex_wait_val = 57,
    futex_wait_change = 58,
    futex_wake = 59,
    time_monotonic = 60,
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
    const num = std.enums.fromInt(SyscallNum, num_raw) orelse return 13;
    const n_reg: u64 = (syscall_word >> 12) & 0xFF;
    return switch (num) {
        // Register-only — at most 5 args, all in vregs 1..N.
        .restrict,
        .delete,
        .revoke,
        .sync,
        .self,
        .terminate,
        .yield,
        .priority,
        .affinity,
        .create_thread,
        .create_vmar,
        .map_mmio,
        .remap,
        .snapshot,
        .create_page_frame,
        .ack,
        .create_virtual_machine,
        .create_vcpu,
        .vm_inject_irq,
        .create_port,
        .recv,
        .futex_wake,
        .time_monotonic,
        => 13,

        // create_process: passed_handles list, no syscall-word
        // count. Surface the full upper window.
        .create_process => 127,

        // map_pf, map_guest, futex_wait_val/change: pairs of 2 vregs
        // each. Vreg 1 = handle/timeout, vregs 2..1+2N = pair data.
        .map_pf, .map_guest, .futex_wait_val, .futex_wait_change => @intCast(@min(1 + 2 * n_reg, 127)),

        // unmap, unmap_guest: singleton entries. vreg 1 = handle,
        // vregs 2..1+N = entries.
        .unmap, .unmap_guest => @intCast(@min(1 + n_reg, 127)),

        // vm_set_policy: bit 12 = kind, bits 13-20 = count. Per-arch
        // entry width — surface the full upper window.
        .vm_set_policy => 127,

        // suspend (general variant): pair_count in bits 12-19; pair
        // entries in the high band [128-N..127] so when pair_count > 0
        // the entire upper window must be covered.
        .@"suspend" => if (n_reg > 0) @as(u8, 127) else @as(u8, 13),

        // reply / reply_transfer: pair_count in bits 12-19; pair entries
        // in the high band [128-N..127]. The arch entry path has the
        // syscall-time user SP; the reply handler must consume entries
        // from `args` rather than re-reading `thread.ctx`, which may still
        // hold the prior saved user frame for the current syscall.
        .reply => if (n_reg > 0) @as(u8, 127) else @as(u8, 13),
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
    if (!build_options.kernel_spawn_diag) return;
    if (res >= 0) return;
    if (num_raw != @intFromEnum(SyscallNum.create_process) and
        num_raw != @intFromEnum(SyscallNum.create_thread)) return;
    const n = @atomicRmw(u32, &spawn_err_prints, .Add, 1, .monotonic);
    if (n >= 24) return;
    stygia.arch.dispatch.boot.print(
        "[2u0] spawn syscall {d} -> {d} (seq {d})\n",
        .{ num_raw, res, syscall_seq },
    );
}

pub fn dispatch(caller: *anyopaque, syscall_word: u64, args: []const u64) i64 {
    syscall_seq +%= 1;

    // Spec §[syscall]: syscall number lives in bits 0-11 of the syscall
    // word. Anything beyond that range is per-syscall metadata
    // (pair_count, kind, etc.) and is the handler's responsibility.
    const num_raw: u64 = syscall_word & 0xFFF;

    // Fast-suspend wire format: syscall_op in 0..13 encodes a suspend
    // with payload_count = syscall_op and pair_count = 0. The asm L4
    // fast path normally handles this; reaching the slow path means
    // a predicate failed (no receiver queued, port lock contended,
    // wrong type tag, etc.). Route through the regular suspend handler
    // so the same caps + state mutations apply.
    if (num_raw <= 13) {
        return port.@"suspend"(caller, arg(args, 0), arg(args, 1), 0, @truncate(num_raw));
    }

    const num = std.enums.fromInt(SyscallNum, num_raw) orelse return errors.E_INVAL;

    const dispatch_res = switch (num) {
        .restrict => capability.restrict(caller, arg(args, 0), arg(args, 1)),
        .delete => capability.delete(caller, arg(args, 0)),
        .revoke => capability.revoke(caller, arg(args, 0)),
        .sync => capability.sync(caller, arg(args, 0)),

        .create_process => process.createProcess(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
            if (args.len > 5) args[5..] else &.{},
        ),
        .create_thread => thread_mod.createThread(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
        ),
        .self => thread_mod.self(caller),
        .terminate => thread_mod.terminate(caller, arg(args, 0)),
        .yield => thread_mod.yield(caller, arg(args, 0)),
        .priority => thread_mod.priority(caller, arg(args, 0), arg(args, 1)),
        .affinity => thread_mod.affinity(caller, arg(args, 0), arg(args, 1)),
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
            const payload_count: u7 = @truncate((syscall_word >> 20) & 0x7F);
            break :blk port.@"suspend"(caller, arg(args, 0), arg(args, 1), pair_count, payload_count);
        },
        .recv => port.recv(caller, arg(args, 0), arg(args, 1)),

        .reply => reply.reply(caller, syscall_word, args),

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
    };
    // TEMP DIAGNOSTIC (stygia-2u0, REMOVE).
    logSpawnError(num_raw, dispatch_res);
    return dispatch_res;
}
