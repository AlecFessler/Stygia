//! Wake-side diagnostic — emits one lockless COM1 line for every
//! `markReady` / `enqueueOnCore` call. Lets a captured lost-wakeup hang
//! be retrospectively triaged: cross-reference the [HANG] dump's SUSP
//! ECs against this trail to see whether each one ever received a wake
//! attempt and where the attempt came from.
//!
//! Output uses raw THR-poll outb (same discipline as `spin_diag` /
//! `hang_detector.rawWrite`) so it can run while `serial.print_lock`
//! is held.

const std = @import("std");
const builtin = @import("builtin");
const zag = @import("zag");

const arch = zag.arch.dispatch;

pub const SrcLoc = std.builtin.SourceLocation;

/// Per-call monotonic sequence so duplicate-looking `[WAKE]` lines can
/// be told apart from a single line whose bytes were interleaved with
/// concurrent COM1 writers. Two real calls always carry distinct seq
/// values; one call interrupted mid-print only ever shows one seq.
var seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Print-side serialization. Held only across the multi-byte raw-COM1
/// emit; the lock is private to wake_diag so it can't participate in
/// any kernel-side cycle.
var print_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn lockPrint() u64 {
    @setRuntimeSafety(false);
    const irq = asm volatile (
        \\pushfq
        \\popq %[r]
        \\cli
        : [r] "=r" (-> u64),
        :
        : .{ .memory = true });
    while (print_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
    return irq;
}

fn unlockPrint(irq: u64) void {
    @setRuntimeSafety(false);
    print_lock.store(0, .release);
    if ((irq & 0x200) != 0) asm volatile ("sti" ::: .{ .memory = true });
}

/// Note one wake attempt. `ec_ptr` is the target EC pointer, `state`
/// is its observed state at entry (BEFORE the wake's state mutation),
/// `via` is the wake site label, `src` carries the caller src.
pub fn note(ec_ptr: usize, state_byte: u8, via: []const u8, src: SrcLoc) void {
    if (builtin.cpu.arch != .x86_64) return;
    const my_seq = seq.fetchAdd(1, .monotonic);
    const irq = lockPrint();
    defer unlockPrint(irq);
    dumpLine(my_seq, ec_ptr, state_byte, via, src);
}

fn dumpLine(my_seq: u64, ec_ptr: usize, state_byte: u8, via: []const u8, src: SrcLoc) void {
    @setRuntimeSafety(false);
    rawWrite("[WAKE seq=");
    printDecimal(my_seq);
    rawWrite(" core=");
    printDecimal(arch.smp.coreID());
    rawWrite(" ec=0x");
    printHex(@as(u64, ec_ptr));
    rawWrite(" was=");
    rawWriteByte(state_byte);
    rawWrite(" via=");
    rawWrite(via);
    rawWrite(" @ ");
    rawWrite(src.file);
    rawWrite(":");
    printDecimal(@intCast(src.line));
    rawWrite("]\n");
}

fn rawWrite(s: []const u8) void {
    @setRuntimeSafety(false);
    for (s) |b| rawWriteByte(b);
}

fn rawWriteByte(b: u8) void {
    @setRuntimeSafety(false);
    const com1: u16 = 0x3F8;
    const lsr: u16 = 0x3F8 + 5;
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

fn printDecimal(n: u64) void {
    @setRuntimeSafety(false);
    if (n == 0) {
        rawWriteByte('0');
        return;
    }
    var buf: [21]u8 = undefined;
    var i: usize = 21;
    var v = n;
    while (v > 0) {
        i -= 1;
        buf[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }
    rawWrite(buf[i..]);
}

fn printHex(n: u64) void {
    @setRuntimeSafety(false);
    var buf: [16]u8 = undefined;
    var i: usize = 16;
    var v = n;
    if (v == 0) {
        rawWriteByte('0');
        return;
    }
    while (v > 0) {
        i -= 1;
        const nib: u8 = @intCast(v & 0xF);
        buf[i] = if (nib < 10) ('0' + nib) else ('a' + nib - 10);
        v >>= 4;
    }
    rawWrite(buf[i..]);
}
