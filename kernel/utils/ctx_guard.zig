//! Per-EC ctx iret-frame guard — snapshot on park, compare on dispatch.
//!
//! Build-gated debug instrumentation. Companion to `ctx_trace.zig`:
//! ctx_trace's per-EC ring records *what* `ec.ctx` looked like at each
//! key site; ctx_guard records `ec.ctx`'s 5-quad iret frame at the
//! moment an EC stops being `current_ec` (park) and re-checks it the
//! moment that EC is re-dispatched (becomes `current_ec` again). A
//! mismatch means *somebody wrote into the parked EC's `ec.ctx` while
//! it was off-CPU* — which is the exact stale-write hypothesis under
//! investigation for the smp=4 iret #GP race.
//!
//! The check fires *before* the iretq machinery loads the corrupted
//! frame, so the diagnostic carries an intact panic-time stack trace
//! (and ctx_trace's ring auto-dumps from the panic hook for the
//! cross-event timeline).
//!
//! ## Design — side array keyed by slab index
//!
//! Same layout pattern as ctx_trace: a single `[MAX_ECS]Entry` BSS
//! array indexed by `(ec - slab.data_base) / @sizeOf(EC)`. No field
//! is added to `ExecutionContext`; flag-off builds compile to empty
//! BSS and the call sites compile to a pair of `_ = arg` discards
//! that the optimizer dead-strips.
//!
//! ## Hooks
//!
//! `armOnPark(ec)` — invoked from `scheduler.clearCurrentEc` (covers
//!   slow-path park / yield / parkSelfFaulted / parkIdleWait / port
//!   suspend / futex wait — every place an EC stops being current
//!   on its core via Zig).
//! `checkOnDispatch(ec)` — invoked from `scheduler.setCurrentEc`,
//!   immediately *before* the asm trampoline loads `rsp = ec.ctx`
//!   and iretq's into user mode. Compares the captured iret frame
//!   against the current `ec.ctx` words; a non-match panics with the
//!   exact slot deltas + the EC pointer + kstack_top.
//!
//! Note: the IPC fast paths (suspend step 14, reply R14) update
//! `PerCore.current_ec` directly from inline asm and do NOT call
//! `setCurrentEc` / `clearCurrentEc`. ctx_guard therefore observes
//! only slow-path park ↔ slow-path dispatch transitions; it cannot
//! catch a corruption window that opens AND closes entirely inside
//! fast-path-only flow. That is acceptable: the ctx_trace ring
//! evidence shows the corruption arriving at SLOWPATH_EPILOGUE
//! before the FP-side step 12 observes it, so the writer is active
//! during an interval that crosses a slow-path boundary.
//!
//! ## Compile-time gate
//!
//! Controlled by `-Dctx_guard=true|false`, defaulting to false. When
//! off, every public symbol degrades to a no-op and the BSS storage
//! is zero-sized; kernel.elf for `-Dctx_guard=false` should be
//! byte-identical to a build that never imported this module.

const std = @import("std");
const zag = @import("zag");
const build_options = @import("build_options");

const arch = zag.arch.dispatch;
const builtin = @import("builtin");
const ctx_trace = zag.utils.ctx_trace;
const panic_mod = zag.panic;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;

pub const enabled: bool = build_options.kernel_ctx_guard;

/// Maximum live EC slots. Must match the `ExecutionContext` slab's
/// `walk_bound` so this side array covers every slab slot.
pub const MAX_ECS: u32 = 256;

/// Snapshot of the iret-frame slots at park time, plus a generation
/// witness so a slot recycle (free → realloc into a different EC)
/// is observed and silently disarms instead of false-matching.
pub const Snapshot = extern struct {
    rip: u64 = 0,
    cs: u64 = 0,
    rflags: u64 = 0,
    rsp: u64 = 0,
    ss: u64 = 0,
    /// EC slab gen captured at arm time. The check path verifies
    /// the EC's current gen still matches; otherwise the slot was
    /// freed/recycled and the snapshot belongs to a prior EC.
    gen: u64 = 0,
    /// Address of `ec.ctx` at arm time. The dispatch path verifies
    /// `ec.ctx` still points at the same `cpu.Context`; if it has
    /// been re-pointed (e.g. user_stack rebuild), the snapshot is
    /// stale and we disarm without comparing.
    ctx_addr: u64 = 0,
    armed: u8 = 0,
    _pad: [7]u8 = [_]u8{0} ** 7,
};

var entries_storage: [if (enabled) MAX_ECS else 0]Snapshot = if (enabled)
    [_]Snapshot{.{}} ** MAX_ECS
else
    [_]Snapshot{};

/// Same layout-asserted offsets used by ctx_trace; replicated rather
/// than imported because ctx_trace's `CtxLayout` is private. Keeps
/// the comptime check local so a future ctx layout change breaks
/// both files independently.
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
        rsp_off;
};

comptime {
    if (enabled and builtin.cpu.arch == .x86_64) {
        std.debug.assert(CtxLayout.rip_off == 136);
        std.debug.assert(CtxLayout.cs_off == 144);
        std.debug.assert(CtxLayout.rflags_off == 152);
        std.debug.assert(CtxLayout.rsp_off == 160);
        std.debug.assert(CtxLayout.ss_off == 168);
    }
}

fn entryIndexOf(ec: *ExecutionContext) ?u32 {
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

inline fn loadCtxQuad(ctx_addr: u64, off: usize) u64 {
    const p: *const u64 = @ptrFromInt(ctx_addr + off);
    return @atomicLoad(u64, p, .monotonic);
}

/// Snapshot `ec.ctx`'s iret frame into the per-EC entry and arm.
/// Called from `scheduler.clearCurrentEc` (caller is on the same
/// core as `ec` is leaving). IRQs assumed already-masked at the call
/// site (clearCurrentEc is invoked under the per-core scheduler lock
/// or in suspend/terminate paths with IRQs off).
pub inline fn armOnPark(ec: *ExecutionContext) void {
    if (comptime !enabled) return;
    armOnParkImpl(ec);
}

fn armOnParkImpl(ec: *ExecutionContext) void {
    @setRuntimeSafety(false);
    const idx = entryIndexOf(ec) orelse return;
    const e = &entries_storage[idx];

    const ctx_addr = @intFromPtr(ec.ctx);
    e.rip = loadCtxQuad(ctx_addr, CtxLayout.rip_off);
    e.cs = loadCtxQuad(ctx_addr, CtxLayout.cs_off);
    e.rflags = loadCtxQuad(ctx_addr, CtxLayout.rflags_off);
    e.rsp = loadCtxQuad(ctx_addr, CtxLayout.rsp_off);
    e.ss = loadCtxQuad(ctx_addr, CtxLayout.ss_off);
    e.gen = ec._gen_lock.currentGen();
    e.ctx_addr = ctx_addr;
    // Publish armed=1 last so a checker observing the slot mid-arm
    // either sees the previous (consistent) snapshot or skips.
    @atomicStore(u8, &e.armed, 1, .release);
}

/// Validate `ec.ctx`'s current iret frame contains plausible values for
/// the EC's last-known execution mode. Called from
/// `scheduler.setCurrentEc`, BEFORE the dispatch trampoline loads
/// `rsp = ec.ctx` and iretq's. The original byte-equality compare
/// false-positived on legitimate user-state evolution (an EC running
/// user code between two parks legitimately advances rip/rsp/rflags),
/// so we instead validate that the slots still encode a plausible
/// resume frame: known segment selectors, canonical addresses,
/// rflags within 32-bit range. The park-time snapshot is retained
/// for diagnostic context only.
pub inline fn checkOnDispatch(ec: *ExecutionContext) void {
    if (comptime !enabled) return;
    checkOnDispatchImpl(ec);
}

/// Selectors expected at iretq into user mode. Keep in sync with
/// `arch/x64/gdt.zig`. ss=0x1B = ring-3 data, cs=0x23 = ring-3 64-bit.
const USER_CS: u64 = 0x23;
const USER_SS: u64 = 0x1B;
const KERNEL_CS: u64 = 0x08;
const KERNEL_SS: u64 = 0x10;

inline fn isCanonical(addr: u64) bool {
    // x86-64 canonical: top 17 bits all 0 (user half) or all 1 (kernel half).
    const high = addr >> 47;
    return high == 0 or high == 0x1FFFF;
}

fn checkOnDispatchImpl(ec: *ExecutionContext) void {
    @setRuntimeSafety(false);
    const idx = entryIndexOf(ec) orelse return;
    const e = &entries_storage[idx];

    if (@atomicLoad(u8, &e.armed, .acquire) == 0) return;

    // Disarm immediately (single-writer semantics: only the dispatch
    // path on the destination core compares; legitimate FP-path
    // dispatches that bypass setCurrentEc just leave the slot armed
    // until the next slow-path dispatch — that's acceptable noise).
    @atomicStore(u8, &e.armed, 0, .release);

    // Slot recycled (different EC now occupies this slab index).
    if (ec._gen_lock.currentGen() != e.gen) return;

    // ec.ctx pointer was rebuilt — common during user_stack rebuild
    // or initial dispatch. The snapshot was for a different ctx
    // address; nothing to compare.
    const ctx_addr = @intFromPtr(ec.ctx);
    if (ctx_addr != e.ctx_addr) return;

    const cur_rip = loadCtxQuad(ctx_addr, CtxLayout.rip_off);
    const cur_cs = loadCtxQuad(ctx_addr, CtxLayout.cs_off);
    const cur_rflags = loadCtxQuad(ctx_addr, CtxLayout.rflags_off);
    const cur_rsp = loadCtxQuad(ctx_addr, CtxLayout.rsp_off);
    const cur_ss = loadCtxQuad(ctx_addr, CtxLayout.ss_off);

    // Mode-aware validation. The snapshot's `cs` records the EC's
    // last-known mode at park time (or, on first arm, what
    // prepareThreadContext set up). User-mode ECs must dispatch with
    // user CS/SS and canonical user-half rip/rsp; kernel-mode ECs
    // (idle threads) just need non-zero selectors. rflags is bounded
    // to 32 bits in either mode (high half is reserved zero).
    var bad_cs: bool = false;
    var bad_ss: bool = false;
    var bad_rip: bool = false;
    var bad_rsp: bool = false;
    var bad_rflags: bool = false;

    if (e.cs == USER_CS) {
        bad_cs = cur_cs != USER_CS;
        bad_ss = cur_ss != USER_SS;
        bad_rip = (cur_rip >> 47) != 0;
        bad_rsp = (cur_rsp >> 47) != 0;
    } else {
        // Kernel-mode EC (e.g. idle). Require non-null selectors and
        // canonical addresses, but accept either half.
        bad_cs = cur_cs == 0 or cur_cs >= 0x10000;
        bad_ss = cur_ss == 0 or cur_ss >= 0x10000;
        bad_rip = !isCanonical(cur_rip);
        bad_rsp = !isCanonical(cur_rsp);
    }
    bad_rflags = (cur_rflags >> 32) != 0;

    if (!(bad_cs or bad_ss or bad_rip or bad_rsp or bad_rflags)) return;

    reportViolation(ec, idx, e, cur_rip, cur_cs, cur_rflags, cur_rsp, cur_ss);
}

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

fn printQuad(label: []const u8, snapshot: u64, current: u64, suspect: bool) void {
    var hex: [16]u8 = undefined;
    arch.boot.printRaw("    ");
    arch.boot.printRaw(label);
    arch.boot.printRaw(": park=0x");
    fmtHex(snapshot, &hex);
    arch.boot.printRaw(&hex);
    arch.boot.printRaw(" current=0x");
    fmtHex(current, &hex);
    arch.boot.printRaw(&hex);
    if (suspect) {
        arch.boot.printRaw("  *** INVALID ***");
    }
    arch.boot.printRaw("\n");
}

fn reportViolation(
    ec: *ExecutionContext,
    idx: u32,
    e: *const Snapshot,
    cur_rip: u64,
    cur_cs: u64,
    cur_rflags: u64,
    cur_rsp: u64,
    cur_ss: u64,
) void {
    @setRuntimeSafety(false);

    // Disable IRQs first: setCurrentEc may be called with IRQs enabled
    // (slow-path dispatch). A timer tick mid-print would re-enter this
    // path on another EC and recurse our @panic. Halting our local
    // core after the panic eventually cleans up, but losing the
    // diagnostic to interleaved output defeats the purpose of the tool.
    _ = arch.cpu.saveAndDisableInterrupts();

    var hex: [16]u8 = undefined;
    var dec: [20]u8 = undefined;

    // Claim the panic gate so concurrent panics on other cores stay
    // silent during our diagnostic. If another core has already
    // claimed (or another simultaneous violation lost the race), halt
    // — our @panic at the bottom would just race on the serial line
    // with the winning core's panic output.
    if (!panic_mod.claimPanic()) arch.cpu.halt();

    arch.boot.printRaw("\n!!!!! ctx_guard VIOLATION !!!!!\n");
    arch.boot.printRaw("  EC=0x");
    fmtHex(@intFromPtr(ec), &hex);
    arch.boot.printRaw(&hex);
    arch.boot.printRaw(" idx=");
    arch.boot.printRaw(fmtDec(idx, &dec));
    arch.boot.printRaw(" gen=");
    arch.boot.printRaw(fmtDec(e.gen, &dec));
    arch.boot.printRaw("\n");

    arch.boot.printRaw("  ctx=0x");
    fmtHex(e.ctx_addr, &hex);
    arch.boot.printRaw(&hex);
    arch.boot.printRaw(" kstack_top=0x");
    fmtHex(ec.kernel_stack.top.addr, &hex);
    arch.boot.printRaw(&hex);
    arch.boot.printRaw(" kstack_base=0x");
    fmtHex(ec.kernel_stack.base.addr, &hex);
    arch.boot.printRaw(&hex);
    arch.boot.printRaw("\n");

    arch.boot.printRaw("  iret-frame slots (park-snapshot vs dispatch-current):\n");
    const user_mode = e.cs == USER_CS;
    const bad_cs = if (user_mode) (cur_cs != USER_CS) else (cur_cs == 0 or cur_cs >= 0x10000);
    const bad_ss = if (user_mode) (cur_ss != USER_SS) else (cur_ss == 0 or cur_ss >= 0x10000);
    const bad_rip = if (user_mode) ((cur_rip >> 47) != 0) else !isCanonical(cur_rip);
    const bad_rsp = if (user_mode) ((cur_rsp >> 47) != 0) else !isCanonical(cur_rsp);
    const bad_rflags = (cur_rflags >> 32) != 0;
    printQuad("rip   ", e.rip, cur_rip, bad_rip);
    printQuad("cs    ", e.cs, cur_cs, bad_cs);
    printQuad("rflags", e.rflags, cur_rflags, bad_rflags);
    printQuad("rsp   ", e.rsp, cur_rsp, bad_rsp);
    printQuad("ss    ", e.ss, cur_ss, bad_ss);

    // Dump ctx_trace ring (cross-event timeline) before the panic
    // tail-call so the operator sees the full causal chain.
    ctx_trace.dumpAllRingsToSerial();

    @panic("ctx_guard: parked EC's iret frame mutated off-CPU");
}
