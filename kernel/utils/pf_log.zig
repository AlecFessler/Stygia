//! Global page-fault outcome ring with dump-on-panic.
//!
//! Build-gated debug instrumentation for the smp=4 page-fault loop:
//! an EC traps, the PF handler claims to resolve it, but the user
//! resumes at the same RIP and faults again. The handler MUST be
//! returning success on each fire, otherwise the kernel would panic
//! immediately on an unrecoverable fault. This tool records what each
//! invocation of the handler actually decided — enter event + outcome
//! + resume — so the lie shows up in the dump.
//!
//! Companion to `ctx_trace.zig` which records ctx-slot snapshots at
//! PF_HANDLER entry. `ctx_trace` answers "what ctx did the EC have at
//! fault time?". `pf_log` answers "what did the handler do with that
//! fault?".
//!
//! ## Design
//!
//! 256-entry global ring (~10 KiB). Each record carries the EC pointer
//! so no per-EC side array is needed. The ring is single-producer per
//! invocation and shared across cores via an atomic-RMW cursor — the
//! sequence number gives a total order across cores.
//!
//! ## Compile-time gate
//!
//! Controlled by `-Dpf_log=true|false`, default false. When off, every
//! public symbol degrades to an empty inline call; the compiler dead-
//! code-eliminates the ring storage and call sites, leaving the kernel
//! .text byte-identical (modulo alignment-nop padding) to a build that
//! never imported this module.

const std = @import("std");
const zag = @import("zag");
const build_options = @import("build_options");

const arch = zag.arch.dispatch;
const builtin = @import("builtin");

const ExecutionContext = zag.sched.execution_context.ExecutionContext;

pub const enabled: bool = build_options.kernel_pf_log;

/// Power-of-two so `cursor & (RING_LEN - 1)` is a single AND.
pub const RING_LEN: u32 = 256;

pub const Outcome = enum(u8) {
    /// PF entry: just trapped, before any decision.
    ENTER = 1,
    /// Handler returning, ec.ctx.rip unchanged (the suspected liar
    /// in the smp=4 fault-loop bug).
    RESUME = 2,
    /// Reserved-bits violation in the page tables → panic.
    RSVD_PANIC = 3,
    /// Port-IO virtual_bar fault: emulateVirtualBar handled the
    /// MOV decode + IN/OUT and advanced RIP.
    USER_PORT_IO = 4,
    /// Kernel privilege touched a user VA — surfaced as memory_fault,
    /// EC suspended/terminated via fireMemoryFault.
    KERNEL_ON_USER_VA = 5,
    /// Kernel privilege, kstack-usable or kalloc range — demand-paged.
    KERNEL_DEMAND = 6,
    /// Kernel privilege hit a kernel-stack guard page → panic.
    KERNEL_STACK_OVERFLOW = 7,
    /// Kernel privilege, fault outside any handled range → panic.
    KERNEL_VA_INVALID = 8,
    /// `current_ec` was null on a kernel-on-user-VA fault → panic.
    KERNEL_NO_EC = 9,
    /// `current_ec` was null on a user fault → panic.
    USER_NO_EC = 10,
    /// Domain gen-lock failed (domain torn down between trap entry
    /// and dispatch); fired memory_fault.
    USER_DOMAIN_GONE = 11,
    /// vmar.handlePageFault returned 0 — fault resolved (demand alloc
    /// or other in-VMAR resolution).
    USER_RESOLVED = 12,
    /// vmar.handlePageFault returned non-zero — VA outside any VMA,
    /// rights mismatch, or NOMEM. Fired memory_fault.
    USER_INVALID = 13,
};

/// 40-byte fixed record. Plain `extern struct` so each field has its
/// natural alignment for racy concurrent reads from the dumper.
pub const Record = extern struct {
    tsc: u64 = 0,
    ec_ptr: u64 = 0,
    fault_va: u64 = 0,
    ctx_rip: u64 = 0,
    ctx_rsp: u64 = 0,
    err_code: u32 = 0,
    core_id: u8 = 0,
    outcome: u8 = 0,
    _pad: [2]u8 = [_]u8{0} ** 2,
};

/// Cursor & ring storage. Cursor is monotonic — index = cursor & mask.
/// We never reset it, so dump output preserves total event ordering.
var cursor: std.atomic.Value(u32) = if (enabled) .{ .raw = 0 } else .{ .raw = 0 };
var ring: [if (enabled) RING_LEN else 0]Record = if (enabled)
    [_]Record{.{}} ** RING_LEN
else
    [_]Record{};

/// `mark` reads `ec.ctx + rip_off / + rsp_off` if ec is non-null.
/// Verified at comptime against the actual `cpu.Context` layout.
const CtxLayout = struct {
    const Ctx = arch.cpu.ArchCpuContext;
    const rip_off = @offsetOf(Ctx, "rip");
    const rsp_off = @offsetOf(Ctx, "rsp");
};

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

/// Append a record to the global ring.
///
/// Hot path; ~50 cycles when `enabled` is true (rdtsc + atomic-RMW
/// cursor + four u64 reads from `ec.ctx` + 6 u64/u32/u8 stores).
/// Reduces to a no-op when off — the inline body returns immediately
/// on the comptime gate and the optimizer drops the call site.
///
/// `@setRuntimeSafety(false)` because this runs from inside the page-
/// fault handler with interrupts disabled and Debug-mode null-checks
/// would both add overhead and turn a recoverable PF into a panic.
pub inline fn mark(
    ec: ?*ExecutionContext,
    outcome: Outcome,
    fault_va: u64,
    err_code: u32,
) void {
    if (comptime !enabled) return;
    markImpl(ec, outcome, fault_va, err_code);
}

fn markImpl(
    ec: ?*ExecutionContext,
    outcome: Outcome,
    fault_va: u64,
    err_code: u32,
) void {
    @setRuntimeSafety(false);

    const seq = cursor.fetchAdd(1, .monotonic);
    const slot = &ring[seq & (RING_LEN - 1)];

    var rip: u64 = 0;
    var rsp: u64 = 0;
    if (ec) |ec_p| {
        const ctx_addr = @intFromPtr(ec_p.ctx);
        const rip_p: *const u64 = @ptrFromInt(ctx_addr + CtxLayout.rip_off);
        const rsp_p: *const u64 = @ptrFromInt(ctx_addr + CtxLayout.rsp_off);
        rip = @atomicLoad(u64, rip_p, .monotonic);
        rsp = @atomicLoad(u64, rsp_p, .monotonic);
    }

    slot.tsc = rdtsc();
    slot.ec_ptr = if (ec) |e| @intFromPtr(e) else 0;
    slot.fault_va = fault_va;
    slot.ctx_rip = rip;
    slot.ctx_rsp = rsp;
    slot.err_code = err_code;
    slot.core_id = coreId();
    slot.outcome = @intFromEnum(outcome);
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

fn outcomeName(o: u8) []const u8 {
    return switch (o) {
        @intFromEnum(Outcome.ENTER) => "ENTER",
        @intFromEnum(Outcome.RESUME) => "RESUME",
        @intFromEnum(Outcome.RSVD_PANIC) => "RSVD_PANIC",
        @intFromEnum(Outcome.USER_PORT_IO) => "USER_PORT_IO",
        @intFromEnum(Outcome.KERNEL_ON_USER_VA) => "KERNEL_ON_USER_VA",
        @intFromEnum(Outcome.KERNEL_DEMAND) => "KERNEL_DEMAND",
        @intFromEnum(Outcome.KERNEL_STACK_OVERFLOW) => "KERNEL_STACK_OVERFLOW",
        @intFromEnum(Outcome.KERNEL_VA_INVALID) => "KERNEL_VA_INVALID",
        @intFromEnum(Outcome.KERNEL_NO_EC) => "KERNEL_NO_EC",
        @intFromEnum(Outcome.USER_NO_EC) => "USER_NO_EC",
        @intFromEnum(Outcome.USER_DOMAIN_GONE) => "USER_DOMAIN_GONE",
        @intFromEnum(Outcome.USER_RESOLVED) => "USER_RESOLVED",
        @intFromEnum(Outcome.USER_INVALID) => "USER_INVALID",
        else => "?",
    };
}

/// Walk the global ring in seq order and emit every record over serial.
/// Caller must have claimed the panic gate (no concurrent panickers) —
/// the dump itself takes no locks.
pub inline fn dumpAllRingsToSerial() void {
    if (comptime !enabled) return;
    dumpAllRingsToSerialImpl();
}

fn dumpAllRingsToSerialImpl() void {
    @setRuntimeSafety(false);

    const cursor_now = cursor.load(.monotonic);
    var hex: [16]u8 = undefined;
    var dec: [20]u8 = undefined;

    arch.boot.printRaw("\n===== pf_log ring dump =====\n");
    arch.boot.printRaw("[pf_log] ");
    arch.boot.printRaw(fmtDec(cursor_now, &dec));
    arch.boot.printRaw(" events\n");

    if (cursor_now == 0) {
        arch.boot.printRaw("===== end pf_log =====\n");
        return;
    }

    // Walk the most-recent N slots in seq order. If cursor < RING_LEN
    // we have fewer events than ring capacity; emit those in seq order.
    // Otherwise emit the last RING_LEN events from oldest to newest.
    const have: u32 = @min(cursor_now, RING_LEN);
    const start: u32 = cursor_now - have;
    var k: u32 = 0;
    while (k < have) {
        const seq = start + k;
        const slot = &ring[seq & (RING_LEN - 1)];

        arch.boot.printRaw("  [seq=");
        arch.boot.printRaw(fmtDec(seq, &dec));
        arch.boot.printRaw(" tsc=0x");
        fmtHex(slot.tsc, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" core=");
        arch.boot.printRaw(fmtDec(slot.core_id, &dec));
        arch.boot.printRaw(" ec=0x");
        fmtHex(slot.ec_ptr, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" outcome=");
        arch.boot.printRaw(outcomeName(slot.outcome));
        arch.boot.printRaw(" fault_va=0x");
        fmtHex(slot.fault_va, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" err=0x");
        fmtHex(@intCast(slot.err_code), &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" rip=0x");
        fmtHex(slot.ctx_rip, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw(" rsp=0x");
        fmtHex(slot.ctx_rsp, &hex);
        arch.boot.printRaw(&hex);
        arch.boot.printRaw("]\n");

        k += 1;
    }

    arch.boot.printRaw("===== end pf_log =====\n");
}
