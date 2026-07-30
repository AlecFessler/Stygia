const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const ctx_trace = stygia.utils.ctx_trace;
const debug_info = stygia.utils.debug_info;
const ec_log = stygia.utils.ec_log;
const pf_log = stygia.utils.pf_log;

/// Kernel panic handler.
///
/// Uses `arch.boot.printRaw` exclusively rather than `arch.boot.print` so
/// the panic output path bypasses the kernel `print_lock` entirely. This
/// matters because:
///
///   1. A panic can fire from inside a code path that already holds
///      `print_lock` (the timer-tick `[tick]` print, the user-PF
///      diagnostic in `memory.fault`, anything else under a `print()`
///      call). If panic.panic then re-took `print_lock`, the lockdep
///      detector would trip on a recursive same-core acquire and call
///      `@panic` again → recursion that swallows the original panic
///      message and locks the kernel into a tight printer loop.
///
///   2. Even without lockdep, taking a SpinLock from the panic path is
///      a deadlock in disguise: if the lock holder also panics on
///      another core (or this same panic caused the holder's stack to
///      become inconsistent), the spin never terminates.
///
/// The output may interleave with other cores' serial bytes; that is
/// acceptable in a panic — getting *something* out is more important
/// than clean ordering.
/// Sentinel for "no panicker yet". Any value < 0xff is a winning core id.
pub const PANIC_OWNER_NONE: u32 = 0xff;

pub var panic_owner: std.atomic.Value(u32) = std.atomic.Value(u32).init(PANIC_OWNER_NONE);

/// Set by `panic` on entry and never cleared. Distinct from `panic_owner`,
/// which deliberately lets the SAME core back in so a fault-handler
/// diagnostic can claim the gate and then `@panic` — see `claimPanic`.
/// That allowance is also a recursion hole, because everything `panic`
/// does after the first line needs stack: `printRaw` calls, a 64-frame
/// `StackIterator` walk, symbolization, and three ring dumps.
///
/// When the panic IS a kernel stack overflow, that work faults on the
/// guard page. The fault handler classifies it, calls
/// `@panic("Kernel stack overflow")`, re-enters here, `claimPanic`
/// returns true again for this core, and the next `printRaw` faults at
/// the same depth. Each turn of the loop makes no forward progress and
/// emits nothing, so the observable result is output that stops
/// mid-sentence and a machine that never comes back.
///
/// Measured on the aarch64 KVM rig under 4-core spread: the entire panic
/// output was the single line `KERNEL PANIC: user page fault with no
/// current EC` — not even the `\n` that follows the message, let alone a
/// frame. With this guard the second entry halts immediately, so the
/// first panic's message is the last thing written and stays readable.
///
/// This cannot fully rescue an aarch64 stack overflow: the vector entry
/// at `exceptions.exceptionVectorTable` does `stp x0, x30, [sp, #-16]!`
/// with no stack switch, so once SP is below the guard the *hardware*
/// takes a nested abort before any of this code runs. Reporting that
/// properly needs a per-core exception stack (the moral equivalent of
/// x86's IST), which is not attempted here.
var panicking: [MAX_PANIC_CORES]bool = [_]bool{false} ** MAX_PANIC_CORES;

/// Bound for the `panicking` flags. `smp.MAX_CORES` is 256 in the
/// scheduler; a byte each is cheap and indexing is bounds-checked below so
/// an out-of-range core id degrades to "no guard" rather than corruption.
const MAX_PANIC_CORES: usize = 256;

/// Try to claim the panic gate. Used both by pre-panic diagnostic prints
/// (e.g. fault-handler dumps) and by `panic()` itself. The winning core
/// is the only one allowed to print; loser cores halt silently.
///
/// `core_id` should be the calling core's APIC id. The first call wins;
/// any subsequent call from a DIFFERENT core returns false. Repeat calls
/// from the SAME core (e.g. fault-handler print → `@panic`) return true.
pub fn claimPanic() bool {
    const self_core: u32 = @truncate(stygia.arch.dispatch.smp.coreID());
    const prev = panic_owner.cmpxchgStrong(
        PANIC_OWNER_NONE,
        self_core,
        .seq_cst,
        .seq_cst,
    );
    if (prev == null) return true;
    return prev.? == self_core;
}

pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, ret_addr: ?u64) noreturn {
    @branchHint(.cold);
    _ = trace;

    if (!claimPanic()) arch.cpu.halt();

    // Re-entry on this core means the panic path itself faulted. Halt
    // without touching the serial port or the stack: whatever we already
    // emitted is the evidence, and any further work re-faults at the same
    // depth. See `panicking`.
    const self: usize = @truncate(stygia.arch.dispatch.smp.coreID());
    if (self < MAX_PANIC_CORES) {
        if (panicking[self]) arch.cpu.halt();
        panicking[self] = true;
    }

    arch.boot.printRaw("KERNEL PANIC: ");
    arch.boot.printRaw(msg);

    if (ret_addr) |ra| {
        arch.boot.printRaw(" @ 0x");
        printHex(ra);
        if (debug_info.global_ptr) |dbg_info| {
            const sym_name = dbg_info.getSymbolName(ra - debug_info.kaslr_slide);
            if (sym_name) |sym| {
                arch.boot.printRaw(" ");
                arch.boot.printRaw(sym);
            }
        }
    }
    arch.boot.printRaw(" core=0x");
    printHex(stygia.arch.dispatch.smp.coreID());
    arch.boot.printRaw("\n");

    // Validated frame walk. `std.debug.StackIterator` loads each frame
    // record with no checks, and panics are exactly where the chain may
    // be garbage — measured on the Pi 5 rig as a `switch on corrupt
    // value @ 0x2` panic (ret_addr slot held 2) whose walker then
    // faulted on the corrupt chain and hit the `panicking` re-entry
    // guard, eating the entire backtrace. Gate every load on the
    // address actually resolving, exactly like memory.fault's
    // dumpFrameChain, and symbolize what survives.
    var fp: u64 = @frameAddress();
    var frames: u64 = 0;
    while (frames < 64) : (frames += 1) {
        if (fp == 0 or fp % 16 != 0) break;
        if (fp < stygia.memory.address.AddrSpacePartition.user.end) break;
        const page = stygia.memory.address.VAddr.fromInt(
            std.mem.alignBackward(u64, fp, stygia.memory.paging.PAGE4K),
        );
        if (arch.paging.resolveVaddr(stygia.memory.init.kernel_addr_space_root, page) == null) break;
        const rec: *const [2]u64 = @ptrFromInt(fp);
        const pc = rec[1];
        if (pc == 0) break;

        const sym: ?[]const u8 = if (debug_info.global_ptr) |dbg_info|
            dbg_info.getSymbolName(pc - debug_info.kaslr_slide)
        else
            null;
        if (sym) |s| {
            arch.boot.printRaw(s);
            arch.boot.printRaw("\n");
        } else {
            arch.boot.printRaw("PC: 0x");
            printHex(pc);
            arch.boot.printRaw(" (no symbol)\n");
        }
        if (rec[0] <= fp) break;
        fp = rec[0];
    }

    ctx_trace.dumpAllRingsToSerial();
    ec_log.dumpAllRingsToSerial();
    pf_log.dumpAllRingsToSerial();

    arch.cpu.halt();
}

/// Print `n` as uppercase hex with no lock and no allocator.
///
/// Public because the panic path is not the only place that has to report
/// something while `print_lock` may already be held by this very core —
/// `memory.fault`'s kernel-fault diagnostic is in exactly that position.
/// See the module doc above for why a locked printer cannot be used there.
pub fn printHex(n: u64) void {
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
    arch.boot.printRaw(buf[i..]);
}
