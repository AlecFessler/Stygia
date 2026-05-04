const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug_info = zag.utils.debug_info;

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
pub var panic_in_progress: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Try to win the panic gate without claiming it irrevocably. Used by
/// pre-panic diagnostic prints (e.g. fault-handler dumps) so they can
/// race-test before splatting bytes onto the serial line. Returns true if
/// this core is now the sole panicker; subsequent panic() will see flag=2
/// and proceed without re-CASing.
pub fn beginPrePanic() bool {
    return panic_in_progress.cmpxchgStrong(0, 2, .seq_cst, .seq_cst) == null;
}

pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, ret_addr: ?u64) noreturn {
    @branchHint(.cold);
    _ = trace;

    // First panicker wins; later cores halt silently so output isn't
    // shredded by interleaved bytes. Cheap enough — at most one CAS per
    // never-returns path.
    //
    // States: 0 = idle, 2 = pre-panic print holder (this core), 1 = panic
    // committed. Pre-panic owners pass through directly to the prints.
    const prev = panic_in_progress.swap(1, .seq_cst);
    if (prev == 1) arch.cpu.halt();

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
    arch.boot.printRaw("\n");

    const first = @returnAddress();
    var it = std.debug.StackIterator.init(first, null);
    var frames: u64 = 0;

    while (frames < 64) : (frames += 1) {
        const pc = it.next() orelse break;

        if (debug_info.global_ptr) |dbg_info| {
            const sym_name = dbg_info.getSymbolName(pc - debug_info.kaslr_slide);
            if (sym_name) |sym| {
                arch.boot.printRaw(sym);
                arch.boot.printRaw("\n");
            } else {
                arch.boot.printRaw("PC: 0x");
                printHex(pc);
                arch.boot.printRaw(" (no symbol)\n");
            }
        } else {
            arch.boot.printRaw("PC: 0x");
            printHex(pc);
            arch.boot.printRaw(" (no symbol)\n");
        }
        if (pc == 0) break;
    }

    arch.cpu.halt();
}

fn printHex(n: u64) void {
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
