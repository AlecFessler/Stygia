//! Per-core current_ec transition log with dump-on-panic.
//!
//! Build-gated debug instrumentation for the smp=4 race that surfaces
//! as "kernel page fault on user VA with no current EC" in
//! `kernel/memory/fault.zig` — i.e. the page-fault handler observed
//! `scheduler.currentEc()` returning null on a user-VA fault. To pin
//! down whether `current_ec` was cleared without a matching set (or
//! whether the fault was reaching the handler from kernel mode masked
//! as user), we need a causal chain of every transition that touches
//! either `core_states[core].current_ec` (Zig setter / clearer) or
//! `SyscallScratch.current_ec` at `gs:32` (asm-side authority written
//! by the IPC fast path's Step 14 / Step R14).
//!
//! Each `mark` site captures rdtsc + core id + event tag + prev/next
//! EC pointers + the calling return address, into a per-core fixed
//! ring of 64 records. The panic path dumps every initialized core's
//! ring over serial.
//!
//! ## Compile-time gate
//!
//! Controlled by `-Dec_log=true|false`, defaulting to false. When off,
//! every public symbol is a no-op, the BSS storage is zero-sized, and
//! the asm trampoline calls in `interrupts.zig` are comptime-elided —
//! the kernel.elf for `-Dec_log=false` is byte-identical to a build
//! that never imported this module.
//!
//! ## Asm calling convention (`ecLogMarkFromAsm_*`)
//!
//! Mirrors `ctx_trace`'s asm trampolines: preserves all 15 GPRs +
//! rflags around the C-callable inner. The two FP-side trampolines
//! both run AT the gs:32 write site — placed BEFORE the write, they
//! observe `prev_ec = gs:32` (still the outgoing EC) and
//! `next_ec = gs:88` (suspend Step 14, receiver_ec_ptr) or
//! `next_ec = gs:72` (reply Step R14, sender_ec_ptr). The trampoline
//! reads both gs slots itself; the caller need not materialize either
//! pointer in a register before the `call`.

const std = @import("std");
const zag = @import("zag");
const build_options = @import("build_options");

const arch = zag.arch.dispatch;
const builtin = @import("builtin");

const ExecutionContext = zag.sched.execution_context.ExecutionContext;

pub const enabled: bool = build_options.kernel_ec_log;

/// Power-of-two so `cursor & (RING_LEN - 1)` is a single AND.
pub const RING_LEN: u8 = 64;

/// Maximum cores we instrument. Matches `scheduler.MAX_CORES` upper
/// limit for the active testbeds (smp=4 today; bumping does not
/// require code changes here).
pub const MAX_CORES: u8 = 64;

pub const Event = enum(u8) {
    /// `scheduler.setCurrentEc(core, ec)` was called. `prev_ec` is the
    /// `current_ec` slot value at entry; `next_ec` is the `ec` arg.
    set_current_ec = 1,
    /// `scheduler.clearCurrentEc(core)` was called. `prev_ec` is the
    /// slot value at entry; `next_ec` is null.
    clear_current_ec = 2,
    /// Suspend FP Step 14 ran the asm-side `gs:32 ← receiver_ec_ptr`
    /// write. `prev_ec` is gs:32 before the write (= sender_ec_ptr);
    /// `next_ec` is gs:88 (= receiver_ec_ptr).
    fp_suspend_s14 = 3,
    /// Reply FP Step R14 ran the asm-side `gs:32 ← sender_ec_ptr`
    /// write. `prev_ec` is gs:32 before the write (= receiver_ec_ptr);
    /// `next_ec` is gs:72 (= sender_ec_ptr).
    fp_reply_r14 = 4,
};

/// 40-byte record. extern struct so each field has natural alignment
/// for racy concurrent reads (we tolerate slight tearing on dump).
pub const Record = extern struct {
    tsc: u64 = 0,
    prev_ec: u64 = 0,
    next_ec: u64 = 0,
    called_from: u64 = 0,
    /// Packed tail: core_id (1) + event (1) + 6 padding bytes for
    /// 8-byte alignment of the next record. Total = 40 bytes.
    core_id: u8 = 0,
    event: u8 = 0,
    _pad: [6]u8 = [_]u8{0} ** 6,
};

comptime {
    if (@sizeOf(Record) != 40) @compileError("ec_log.Record must be 40 bytes");
}

pub const Ring = extern struct {
    /// Monotonic counter; index = `cursor & (RING_LEN - 1)`. Never
    /// reset — preserves total event ordering for the dump.
    cursor: std.atomic.Value(u32) align(64) = .{ .raw = 0 },
    slots: [RING_LEN]Record align(64) = [_]Record{.{}} ** RING_LEN,
};

/// Per-core ring storage. Lives in BSS (zero-init); only allocated
/// when `enabled`. 4 cores × 64 records × 32 bytes = 8 KiB at MAX=4,
/// 64 cores × 64 × 32 = 128 KiB at the upper bound (MAX_CORES). We
/// take the upper bound because the testbed quantum is small enough
/// that BSS bytes are not the constraint, and a single MAX_CORES
/// constant simplifies the dump walk.
var rings_storage: [if (enabled) MAX_CORES else 0]Ring = if (enabled)
    [_]Ring{.{}} ** MAX_CORES
else
    [_]Ring{};

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

/// Append one record to the per-core ring.
///
/// Hot path; ~30-50 cycles when `enabled`. Reduces to a no-op when
/// off (the comptime guard short-circuits before any side effect).
/// `@setRuntimeSafety(false)` because IRQ-disabled callers can't
/// afford a Debug-mode null/index check.
pub inline fn mark(
    event: Event,
    prev_ec: ?*ExecutionContext,
    next_ec: ?*ExecutionContext,
) void {
    if (comptime !enabled) return;
    markImpl(event, prev_ec, next_ec, @returnAddress());
}

fn markImpl(
    event: Event,
    prev_ec: ?*ExecutionContext,
    next_ec: ?*ExecutionContext,
    called_from: u64,
) void {
    @setRuntimeSafety(false);

    const core: u8 = coreId();
    if (core >= MAX_CORES) return;

    const ring = &rings_storage[core];
    const seq = ring.cursor.fetchAdd(1, .monotonic);
    const slot = &ring.slots[seq & (RING_LEN - 1)];

    slot.tsc = rdtsc();
    slot.prev_ec = if (prev_ec) |p| @intFromPtr(p) else 0;
    slot.next_ec = if (next_ec) |n| @intFromPtr(n) else 0;
    slot.called_from = called_from;
    slot.core_id = core;
    slot.event = @intFromEnum(event);
}

/// C-callconv inner used by the asm trampolines. Takes raw u64 ec
/// pointers (the asm side has no notion of `?*EC`); the Zig wrapper
/// reinterprets them. Only emitted when `enabled`.
const ecLogMarkCImpl = struct {
    fn impl(
        event: u8,
        prev_ec: u64,
        next_ec: u64,
        called_from: u64,
    ) callconv(.c) void {
        @setRuntimeSafety(false);
        if (comptime !enabled) return;
        const core: u8 = coreId();
        if (core >= MAX_CORES) return;

        const ring = &rings_storage[core];
        const seq = ring.cursor.fetchAdd(1, .monotonic);
        const slot = &ring.slots[seq & (RING_LEN - 1)];

        slot.tsc = rdtsc();
        slot.prev_ec = prev_ec;
        slot.next_ec = next_ec;
        slot.called_from = called_from;
        slot.core_id = core;
        slot.event = event;
    }
};

comptime {
    if (enabled) {
        @export(&ecLogMarkCImpl.impl, .{
            .name = "ecLogMarkC",
            .linkage = .strong,
        });
    }
}

/// Generate a naked trampoline that:
///   1. preserves all 15 GPRs + rflags (mirrors ctx_trace convention)
///   2. realigns rsp to 16
///   3. reads `prev_ec` from gs:32 (still the OUTGOING EC at the
///      call site — the trampoline must be invoked BEFORE the
///      `movq %%r11, %%gs:32` write that step 14 / R14 perform)
///   4. reads `next_ec` from `gs:next_off` (gs:88 for S14, gs:72 for R14)
///   5. captures the call's return-address from the saved RIP slot at
///      `[rsp + 128]` (15 pushq + pushfq = 128 bytes above the saved RIP)
///   6. calls `ecLogMarkC(event, prev_ec, next_ec, called_from)`
///   7. restores rsp, regs, rflags, returns
///
/// Each trampoline bakes its event id and `next_ec` gs offset as
/// immediates so the asm caller's only cost is the `call` itself.
fn asmMarkTrampolineFn(
    comptime event: Event,
    comptime next_gs_off: u8,
) fn () callconv(.naked) void {
    return struct {
        fn entry() callconv(.naked) void {
            // Layout after pushfq: [rsp..rsp+8) = rflags, [+8..+128)
            // = 15 GPRs (each 8 B), [+128..+136) = saved RIP. We read
            // the saved RIP for the `called_from` argument. After the
            // pushfq we subq $8 to realign rsp to 16 before `call` —
            // accounting for that, the saved RIP sits at rsp+136
            // inside the call.
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
                    \\movl ${[evt]d}, %%edi
                    \\movq %%gs:32, %%rsi
                    \\movq %%gs:{[next_off]d}, %%rdx
                    \\movq 136(%%rsp), %%rcx
                    \\call ecLogMarkC
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
                    .{
                        .evt = @intFromEnum(event),
                        .next_off = next_gs_off,
                    },
                ));
        }
    }.entry;
}

comptime {
    if (enabled and builtin.cpu.arch == .x86_64) {
        // Suspend FP step 14: receiver_ec_ptr lives in gs:88 (= the
        // fast_temp[3] slot the entry stub stashed it into).
        const susp_s14 = asmMarkTrampolineFn(.fp_suspend_s14, 88);
        // Reply FP step R14: sender_ec_ptr lives in gs:72 (= the
        // reply-side fast_temp[1] slot).
        const reply_r14 = asmMarkTrampolineFn(.fp_reply_r14, 72);
        @export(&susp_s14, .{
            .name = "ecLogMarkFromAsm_FP_S14",
            .linkage = .strong,
        });
        @export(&reply_r14, .{
            .name = "ecLogMarkFromAsm_FP_R14",
            .linkage = .strong,
        });
    }
}

// ─── Dump-on-panic ────────────────────────────────────────────────

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
        @intFromEnum(Event.set_current_ec) => "SET_CURRENT_EC",
        @intFromEnum(Event.clear_current_ec) => "CLEAR_CURRENT_EC",
        @intFromEnum(Event.fp_suspend_s14) => "FP_SUSPEND_S14",
        @intFromEnum(Event.fp_reply_r14) => "FP_REPLY_R14",
        else => "?",
    };
}

fn dumpRing(core: u8) void {
    const ring = &rings_storage[core];
    const cursor_now = ring.cursor.load(.monotonic);
    if (cursor_now == 0) return;

    var hex: [16]u8 = undefined;
    var dec: [20]u8 = undefined;

    arch.boot.printRaw("[ec_log] core=");
    arch.boot.printRaw(fmtDec(core, &dec));
    arch.boot.printRaw(" ");
    arch.boot.printRaw(fmtDec(cursor_now, &dec));
    arch.boot.printRaw(" events\n");

    // Walk the most-recent N slots in oldest→newest order. If
    // cursor_now < RING_LEN we have fewer events than capacity.
    const have: u32 = @min(cursor_now, RING_LEN);
    const start: u32 = cursor_now - have;
    var k: u32 = 0;
    while (k < have) {
        const seq = start + k;
        const slot = &ring.slots[seq & (RING_LEN - 1)];

        arch.boot.printRaw("  [seq=");
        arch.boot.printRaw(fmtDec(seq, &dec));
        arch.boot.printRaw(" tsc=0x");
        fmtHex(slot.tsc, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" event=");
        arch.boot.printRaw(eventName(slot.event));
        arch.boot.printRaw(" prev=0x");
        fmtHex(slot.prev_ec, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" next=0x");
        fmtHex(slot.next_ec, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" from=0x");
        fmtHex(slot.called_from, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw("]\n");

        k += 1;
    }
}

/// Walk every per-core ring and dump its contents over serial. Caller
/// must have claimed the panic gate (`panic.claimPanic`) — the dump
/// itself takes no locks.
pub inline fn dumpAllRingsToSerial() void {
    if (comptime !enabled) return;
    dumpAllRingsToSerialImpl();
}

fn dumpAllRingsToSerialImpl() void {
    @setRuntimeSafety(false);

    arch.boot.printRaw("\n===== ec_log ring dump (per-core) =====\n");

    const cores: u8 = @truncate(arch.smp.coreCount());
    const limit: u8 = if (cores < MAX_CORES) cores else MAX_CORES;
    var i: u8 = 0;
    while (i < limit) {
        dumpRing(i);
        i += 1;
    }

    arch.boot.printRaw("===== end ec_log =====\n");
}
