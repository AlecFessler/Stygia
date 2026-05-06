//! Threshold spin-print: dumps one lockless COM1 line every ~16M
//! iterations so a captured deadlock self-identifies. Wired into every
//! spin loop in the kernel — `SpinLock`, `GenLock`, and ad-hoc spins
//! (e.g. `terminate.postZombie`). No-op on non-x86 for now.
//!
//! Output uses raw THR-poll outb (same discipline as
//! `utils.hang_detector.rawWrite`) so it can fire while
//! `serial.print_lock` is held — print_lock can itself be part of the
//! cycle.

const std = @import("std");
const builtin = @import("builtin");
const zag = @import("zag");

const arch = zag.arch.dispatch;

pub const SrcLoc = std.builtin.SourceLocation;

/// One in-loop tick. Increment counter; on every Nth tick (~16M) emit
/// one diagnostic line. The N is chosen large enough that a normal
/// briefly-held SpinLock acquire never trips — even worst-case held
/// windows clear in microseconds (~ a few thousand iterations).
pub fn tick(counter: *u64, src: SrcLoc, label: []const u8) void {
    if (builtin.cpu.arch != .x86_64) return;
    counter.* +%= 1;
    if (counter.* & 0x00FFFFFF != 0) return;
    dumpLine(src, label);
}

fn dumpLine(src: SrcLoc, label: []const u8) void {
    @setRuntimeSafety(false);
    rawWrite("[SPIN core=");
    printDecimal(arch.smp.coreID());
    rawWrite(" ");
    rawWrite(label);
    rawWrite(" @ ");
    rawWrite(src.file);
    rawWrite(":");
    printDecimal(@intCast(src.line));
    rawWrite("]\n");
}

fn rawWrite(s: []const u8) void {
    @setRuntimeSafety(false);
    const com1: u16 = 0x3F8;
    const lsr: u16 = 0x3F8 + 5;
    for (s) |b| {
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

fn printDecimal(n: u64) void {
    @setRuntimeSafety(false);
    if (n == 0) {
        rawWrite("0");
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
