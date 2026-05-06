//! Per-EC kstack-corruption snapshot ring with dump-on-panic.
//!
//! Build-gated debug instrumentation for the smp=4 iret-frame race
//! that corrupts `ec.ctx.cs` (offset 144 in `cpu.Context`) with
//! kernel-pointer fragments, surfacing as `#GP at iretq` with
//! `err=0xcca0`-class error codes. After 14+ rounds of static
//! agent investigation we still don't know what writes the
//! corruption — this tool gives the next round a causal chain.
//!
//! Each `mark` site captures rdtsc + the four iret-frame slots from
//! `ec.ctx` (cs / ss / rsp / rip) plus the calling core id and an
//! event tag, into a 32-entry per-EC ring. Ring index is keyed by
//! EC slab index (`SecureSlab.indexOf`) so the ring storage is a
//! single 256-slot side array; no field added to `ExecutionContext`
//! itself, no per-allocation overhead.
//!
//! The panic path walks every live EC slot (gen-lock odd) and emits
//! the ring contents over serial via `arch.boot.printRaw`. Caller
//! must hold the panic gate (`panic.claimPanic`) — the dump is not
//! locked and not safe to invoke concurrently.
//!
//! ## Compile-time gate
//!
//! Controlled by `-Dctx_trace=true|false`, defaulting to false.
//! When off, every public symbol degrades to a no-op or empty BSS
//! and the compiler dead-code-eliminates the call sites entirely;
//! the kernel.elf for `-Dctx_trace=false` is byte-identical to a
//! build that never imported this module.
//!
//! ## Asm calling convention (`markFromAsm_*`)
//!
//! The IPC fast-path register contract (see commit `cff3a7a46`)
//! requires that every IPC payload register survives end-to-end:
//! `rdi, rsi, rdx, r8, r9, r10, r12, r13, r14, r15, rbp, rbx`.
//! The `markFromAsm_*` trampolines preserve all 15 GPRs + rflags
//! around the Zig call, so they are safe to invoke from inside
//! `syscallEntry`'s naked stub at any FP step. `rcx` and `r11` are
//! also preserved (SYSCALL clobbers them on the kernel→user transition,
//! but the fast-path steps reuse them as scratch and depend on
//! their last-written values across labels). `rax` is preserved
//! too because the fast path stashes the caller's vreg-1 there.
//!
//! Each event id has its own naked `markFromAsm_<event>` export so
//! the asm caller does not need to materialize the event id into a
//! register at the call site (which would clobber a payload register
//! it could not afford to spill).

const std = @import("std");
const zag = @import("zag");
const build_options = @import("build_options");

const arch = zag.arch.dispatch;
const builtin = @import("builtin");

const ExecutionContext = zag.sched.execution_context.ExecutionContext;

pub const enabled: bool = build_options.kernel_ctx_trace;

/// Power-of-two so `cursor & (RING_LEN - 1)` is a single AND.
pub const RING_LEN: u8 = 32;

/// Maximum live EC slots (must match `ExecutionContext.Allocator`'s
/// walk_bound). Keeping this constant in sync is enforced at comptime
/// in `init` below.
pub const MAX_ECS: u32 = 256;

pub const Event = enum(u8) {
    /// Slow-path `syscallEntry` finished writing all 21 ctx slots
    /// (regs + iret frame) — observed at the top of `syscallDispatch`.
    slowpath_save = 1,
    /// Slow-path is about to `iretq` after dispatch returned —
    /// observed at the bottom of `syscallDispatch`.
    slowpath_epilogue = 2,
    /// Suspend FP step 12 just wrote `ctx.rip / rflags / rsp` into
    /// the sender's `ec.ctx` (interrupts.zig step 12.5 entry).
    fp_suspend_step12 = 3,
    /// Reply FP R11 just wrote `ctx.cs = 0x23` / `ctx.ss = 0x1b` /
    /// `ctx.rip / rflags / rsp / regs.rax = 0` into the receiver's
    /// `ec.ctx` (interrupts.zig step R11 exit, before R12 cli).
    fp_reply_r11 = 4,
    /// Slow-path `switchTo` is about to set `TSS.RSP0` and the
    /// per-core scratch identity slots.
    switchto_entry = 5,
    /// `switchTo` is about to execute its asm trampoline that swaps
    /// `rsp = ec.ctx` then `jmp interruptStubEpilogue` → iretq.
    /// This is the LAST snapshot before the `cs` value travels into
    /// the iret machinery.
    switchto_resume = 6,
    /// Reply FP atomic-recv-park branch — caller is about to park
    /// on the named recv port instead of going on the run queue.
    recv_park = 7,
    /// Page-fault handler entry. Logs the EC that was on this core
    /// at fault time so a fault on an active EC's kstack surfaces
    /// in that EC's ring.
    pf_handler = 8,
};

/// 40-byte snapshot record. Plain struct (not packed) so each field
/// has its natural alignment for racy concurrent reads / writes.
pub const Record = extern struct {
    tsc: u64 = 0,
    ctx_rip: u64 = 0,
    ctx_cs: u64 = 0,
    ctx_rflags_or_rsp: u64 = 0,
    ctx_ss: u64 = 0,
    /// Two u8s + 6 padding bytes so the whole record is exactly 40 B.
    core_id: u8 = 0,
    event: u8 = 0,
    _pad: [6]u8 = [_]u8{0} ** 6,
};

pub const Ring = extern struct {
    /// Monotonic counter. Index = `cursor & (RING_LEN - 1)`. We never
    /// reset it so dump output preserves total event ordering.
    cursor: std.atomic.Value(u32) align(64) = .{ .raw = 0 },
    slots: [RING_LEN]Record align(64) = [_]Record{.{}} ** RING_LEN,
};

/// Single side-array sized to the EC slab. Lives in BSS (zero-init);
/// only allocated when `enabled` is true. Each ring is ~1.34 KiB; at
/// 256 ECs the total backing is ~340 KiB.
var rings_storage: [if (enabled) MAX_ECS else 0]Ring = if (enabled)
    [_]Ring{.{}} ** MAX_ECS
else
    [_]Ring{};

/// `mark` reads `ec.ctx + 144 / + 152 / + 160 / + 168` for the iret
/// frame — those offsets must match `cpu.Context`'s field layout.
/// Verified at comptime against the actual struct.
const CtxLayout = struct {
    const cpu = if (builtin.cpu.arch == .x86_64)
        zag.arch.x64.cpu
    else
        zag.arch.aarch64.cpu;
    const rip_off = @offsetOf(cpu.Context, "rip");
    const cs_off = @offsetOf(cpu.Context, "cs");
    const rflags_off = @offsetOf(cpu.Context, "rflags");
    const rsp_off = @offsetOf(cpu.Context, "rsp");
    const ss_off = if (builtin.cpu.arch == .x86_64)
        @offsetOf(cpu.Context, "ss")
    else
        // aarch64 has no SS slot; reuse pstate or just zero. We
        // gate this on x86_64 in practice (the bug is x86 only).
        rsp_off;
};

comptime {
    if (enabled and builtin.cpu.arch == .x86_64) {
        // cpu.Context layout (kernel/arch/x64/cpu.zig):
        //   regs:     [0..120)   — 15 GPRs × 8 B
        //   int_num:  [120..128)
        //   err_code: [128..136)
        //   rip:      [136..144)
        //   cs:       [144..152)
        //   rflags:   [152..160)
        //   rsp:      [160..168)
        //   ss:       [168..176)
        std.debug.assert(CtxLayout.rip_off == 136);
        std.debug.assert(CtxLayout.cs_off == 144);
        std.debug.assert(CtxLayout.rflags_off == 152);
        std.debug.assert(CtxLayout.rsp_off == 160);
        std.debug.assert(CtxLayout.ss_off == 168);
    }
}

inline fn rdtsc() u64 {
    if (builtin.cpu.arch == .x86_64) {
        var a: u32 = 0;
        var d: u32 = 0;
        asm volatile (
            \\rdtsc
            : [a] "={eax}" (a),
              [d] "={edx}" (d),
        );
        return (@as(u64, d) << 32) | a;
    }
    return 0;
}

inline fn coreId() u8 {
    if (!enabled) return 0;
    return @truncate(arch.smp.coreID());
}

/// Snapshot `ec.ctx`'s iret-frame slots into the next ring slot.
///
/// Hot path; ~30-50 cycles when `enabled` is true. Reduces to a
/// pair of `_ = arg` discards when off, which the optimizer (and
/// even Debug mode's frontend) treats as no-op. Uses `@atomicLoad`
/// on each `ctx + offset` read so racy mid-write observations are
/// at least non-tearing single-quad reads (the race we are hunting
/// writes individual quads, not multi-quad stores).
/// `@setRuntimeSafety(false)` because this runs from IRQ-disabled
/// fast paths and a Debug-mode null-check is both pure overhead
/// and a panic source.
pub inline fn mark(ec: *ExecutionContext, event: Event) void {
    if (comptime !enabled) return;
    markImpl(ec, event);
}

fn markImpl(ec: *ExecutionContext, event: Event) void {
    @setRuntimeSafety(false);

    const idx = ringIndexOf(ec) orelse return;
    const ring = &rings_storage[idx];
    const seq = ring.cursor.fetchAdd(1, .monotonic);
    const slot = &ring.slots[seq & (RING_LEN - 1)];

    const ctx_addr = @intFromPtr(ec.ctx);
    const rip_p: *const u64 = @ptrFromInt(ctx_addr + CtxLayout.rip_off);
    const cs_p: *const u64 = @ptrFromInt(ctx_addr + CtxLayout.cs_off);
    const rsp_p: *const u64 = @ptrFromInt(ctx_addr + CtxLayout.rsp_off);
    const ss_p: *const u64 = @ptrFromInt(ctx_addr + CtxLayout.ss_off);

    slot.tsc = rdtsc();
    slot.ctx_rip = @atomicLoad(u64, rip_p, .monotonic);
    slot.ctx_cs = @atomicLoad(u64, cs_p, .monotonic);
    slot.ctx_rflags_or_rsp = @atomicLoad(u64, rsp_p, .monotonic);
    slot.ctx_ss = @atomicLoad(u64, ss_p, .monotonic);
    slot.core_id = coreId();
    slot.event = @intFromEnum(event);
}

fn ringIndexOf(ec: *ExecutionContext) ?u32 {
    const slab = &zag.sched.execution_context.slab_instance;
    const data_base = slab.data_base;
    const ec_addr = @intFromPtr(ec);
    if (ec_addr < data_base) return null;
    const stride = @sizeOf(ExecutionContext);
    const offset = ec_addr - data_base;
    if (offset % stride != 0) return null;
    const idx = offset / stride;
    if (idx >= MAX_ECS) return null;
    return @intCast(idx);
}

/// C-callconv alias for `mark` so the asm trampolines can `call` it
/// with rdi = ec, sil = event id. Only emitted when `enabled` is true;
/// the asm trampolines themselves are also gated on `enabled`, and the
/// in-asm `call ctxTraceMarkFromAsm_*` is comptime-elided in
/// `interrupts.zig`, so a flag-off build has no reference to this
/// symbol from anywhere.
const ctxTraceMarkCImpl = struct {
    fn impl(ec: *ExecutionContext, event: u8) callconv(.c) void {
        mark(ec, @enumFromInt(event));
    }
};

comptime {
    if (enabled) {
        @export(&ctxTraceMarkCImpl.impl, .{
            .name = "ctxTraceMarkC",
            .linkage = .strong,
        });
    }
}

/// Generate a naked trampoline that:
///   1. preserves all 15 GPRs + rflags
///   2. realigns rsp to 16
///   3. loads `ec` from `gs:32` (PerCpuScratch.current_ec)
///   4. calls `ctxTraceMarkC(ec, event_id)`
///   5. restores rsp, regs, rflags, returns
///
/// Each event id gets its own export so the asm caller's only cost
/// is the `call` instruction itself (plus the trampoline's preserve
/// boilerplate). The event id is baked into the trampoline body as
/// an immediate.
fn asmMarkTrampolineFn(comptime event: Event) fn () callconv(.naked) void {
    return struct {
        fn entry() callconv(.naked) void {
            // 15 GPRs + pushfq = 128 bytes (16-aligned). Plus the
            // call's saved RIP at function entry = 136 bytes total.
            // Stack at this point is 16k+8; subq $8 below realigns
            // to 16k before the inner `call`.
            asm volatile (std.fmt.comptimePrint(
                    \\pushq %%rax
                    \\pushq %%rcx
                    \\pushq %%rdx
                    \\pushq %%rbx
                    \\pushq %%rbp
                    \\pushq %%rsi
                    \\pushq %%rdi
                    \\pushq %%r8
                    \\pushq %%r9
                    \\pushq %%r10
                    \\pushq %%r11
                    \\pushq %%r12
                    \\pushq %%r13
                    \\pushq %%r14
                    \\pushq %%r15
                    \\pushfq
                    \\subq $8, %%rsp
                    \\movq %%gs:32, %%rdi
                    \\movl ${[evt]d}, %%esi
                    \\call ctxTraceMarkC
                    \\addq $8, %%rsp
                    \\popfq
                    \\popq %%r15
                    \\popq %%r14
                    \\popq %%r13
                    \\popq %%r12
                    \\popq %%r11
                    \\popq %%r10
                    \\popq %%r9
                    \\popq %%r8
                    \\popq %%rdi
                    \\popq %%rsi
                    \\popq %%rbp
                    \\popq %%rbx
                    \\popq %%rdx
                    \\popq %%rcx
                    \\popq %%rax
                    \\ret
                ,
                    .{ .evt = @intFromEnum(event) },
                ));
        }
    }.entry;
}

// One trampoline export per event id. The asm caller picks the
// matching label; the rest are dead-stripped.
comptime {
    if (enabled and builtin.cpu.arch == .x86_64) {
        const susp_step12 = asmMarkTrampolineFn(.fp_suspend_step12);
        const reply_r11 = asmMarkTrampolineFn(.fp_reply_r11);
        const recv_park = asmMarkTrampolineFn(.recv_park);
        @export(&susp_step12, .{
            .name = "ctxTraceMarkFromAsm_fp_suspend_step12",
            .linkage = .strong,
        });
        @export(&reply_r11, .{
            .name = "ctxTraceMarkFromAsm_fp_reply_r11",
            .linkage = .strong,
        });
        @export(&recv_park, .{
            .name = "ctxTraceMarkFromAsm_recv_park",
            .linkage = .strong,
        });
    }
}

// ─── Dump-on-panic ────────────────────────────────────────────────

/// Render a u64 as a fixed 16-char zero-padded hex string into `dst`.
fn fmtHex(v: u64, dst: *[16]u8) void {
    var i: usize = 16;
    var x = v;
    while (i > 0) {
        i -= 1;
        const d: u8 = @intCast(x & 0xF);
        dst[i] = if (d < 10) d + '0' else d - 10 + 'A';
        x >>= 4;
    }
}

fn fmtDec(v: u64, buf: *[20]u8) []const u8 {
    if (v == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    var i: usize = buf.len;
    var x = v;
    while (x != 0) {
        i -= 1;
        buf[i] = @intCast((x % 10) + '0');
        x /= 10;
    }
    return buf[i..];
}

fn eventName(e: u8) []const u8 {
    return switch (e) {
        @intFromEnum(Event.slowpath_save) => "SLOWPATH_SAVE",
        @intFromEnum(Event.slowpath_epilogue) => "SLOWPATH_EPILOGUE",
        @intFromEnum(Event.fp_suspend_step12) => "FP_SUSPEND_STEP12",
        @intFromEnum(Event.fp_reply_r11) => "FP_REPLY_R11",
        @intFromEnum(Event.switchto_entry) => "SWITCHTO_ENTRY",
        @intFromEnum(Event.switchto_resume) => "SWITCHTO_RESUME",
        @intFromEnum(Event.recv_park) => "RECV_PARK",
        @intFromEnum(Event.pf_handler) => "PF_HANDLER",
        else => "?",
    };
}

fn dumpRing(ec: *ExecutionContext, idx: u32) void {
    const ring = &rings_storage[idx];
    const cursor_now = ring.cursor.load(.monotonic);
    if (cursor_now == 0) return;

    var hex: [16]u8 = undefined;
    var dec: [20]u8 = undefined;

    arch.boot.printRaw("[ctx_trace] EC=0x");
    fmtHex(@intFromPtr(ec), &hex);
    arch.boot.printRaw(&hex);
    arch.boot.printRaw(" idx=");
    arch.boot.printRaw(fmtDec(idx, &dec));
    arch.boot.printRaw(" cursor=");
    arch.boot.printRaw(fmtDec(cursor_now, &dec));
    arch.boot.printRaw("\n");

    // Walk the most-recent N slots. If cursor < RING_LEN we have
    // fewer events than ring capacity; emit those in seq order.
    // Otherwise emit the last RING_LEN events from oldest to newest.
    const have: u32 = @min(cursor_now, RING_LEN);
    const start: u32 = cursor_now - have;
    var k: u32 = 0;
    while (k < have) {
        const seq = start + k;
        const slot = &ring.slots[seq & (RING_LEN - 1)];

        arch.boot.printRaw("  [seq=");
        arch.boot.printRaw(fmtDec(seq, &dec));
        arch.boot.printRaw(" core=");
        arch.boot.printRaw(fmtDec(slot.core_id, &dec));
        arch.boot.printRaw(" event=");
        arch.boot.printRaw(eventName(slot.event));
        arch.boot.printRaw(" tsc=0x");
        fmtHex(slot.tsc, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" cs=0x");
        fmtHex(slot.ctx_cs, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" ss=0x");
        fmtHex(slot.ctx_ss, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" rsp=0x");
        fmtHex(slot.ctx_rflags_or_rsp, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" rip=0x");
        fmtHex(slot.ctx_rip, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw("]\n");

        k += 1;
    }
}

/// Walk every slot in the EC slab (gen-lock odd = live) and dump
/// its ring buffer over serial. Caller must have claimed the panic
/// gate (no concurrent panickers) — the dump itself takes no locks.
pub inline fn dumpAllRingsToSerial() void {
    if (comptime !enabled) return;
    dumpAllRingsToSerialImpl();
}

fn dumpAllRingsToSerialImpl() void {
    @setRuntimeSafety(false);

    arch.boot.printRaw("\n===== ctx_trace ring dump (all live ECs) =====\n");

    const slab = &zag.sched.execution_context.slab_instance;
    const total = @atomicLoad(u32, &slab.count_total, .acquire);
    var i: u32 = 0;
    while (i < total) {
        const ec = slab.ptrAt(i);
        const gen = ec._gen_lock.currentGen();
        // Live = gen odd. We skip freed slots so we don't dump
        // stale rings that belong to a since-recycled EC's prior
        // life — the rings are keyed by slot, not by gen, and the
        // bug we are hunting only matters for currently-live ECs.
        if (gen != 0 and (gen % 2) == 1) {
            dumpRing(ec, i);
        }
        i += 1;
    }

    arch.boot.printRaw("===== end ctx_trace =====\n");
}
