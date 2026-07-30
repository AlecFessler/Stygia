//! Fixed-address DRAM log for the Raspberry Pi 5 native loader.
//!
//! This is the loader's ONLY output channel, and it exists because on this board
//! there is no console available at the point where a boot can fail:
//!
//!   * The GPIO 14/15 header UART is RP1's uart0 at 0x1f00030000, behind a PCIe
//!     link that has to be brought up first — so it is unavailable during
//!     exactly the window where bring-up bugs live.
//!   * The SoC debug PL011 at 0x107d001000 needs no PCIe, but observing it needs
//!     a JST-SH pigtail that is not currently wired.
//!
//! So instead of a console we write to a physical address that Linux has been
//! told to leave alone, then read it back from Pi OS after the board resets. It
//! is a postmortem log rather than a live one, which is a real limitation: you
//! see it only after the fact, and only if the board resets. In exchange it
//! works from the very first instruction, needs zero device setup, and survives
//! a fault that would silence any peripheral.
//!
//! Why this is sound on this board, all of it measured rather than assumed:
//!
//!   * `mem=3968M` on the Linux cmdline caps Pi OS at 0xF83FFFFF. NOT at
//!     0xF8000000 as the arithmetic suggests — the 4 MB hole at
//!     vc_mem.mem_base=0x3fc00000 makes Linux extend its top by exactly that
//!     much to still reach 3968 MB of usable RAM. Siting this log at
//!     0xF8000000 would put it INSIDE live kernel memory.
//!   * 0xF9000000 is real DRAM (the DTB /memory node covers
//!     0x40000000-0xFFFFFFFF) and sits 12 MB above that top.
//!   * DRAM contents survive the warm reset this board performs (firmware
//!     injects `reboot=w`); verified with a magic+nonce+checksum stamp that read
//!     back byte-identical across a reset.
//!
//! Layout, deliberately trivial so the reader needs no framing logic:
//!
//!     0x0000  magic, 16 bytes
//!     0x0010  u32 text length   <- written LAST; this is the commit point
//!     0x0014  text
//!
//! `length == 0` with the magic present is a meaningful state, not a bug: it
//! means the loader stamped the magic on entry and then died before committing.
//! Distinguishing "never ran" from "ran and died early" is most of the
//! diagnostic value, so the reader reports them differently.
//!
//! Read it with `sudo python3 read_earlylog.py` under Pi OS. Note that ARM64
//! maps this range as Device memory via /dev/mem, which forbids unaligned
//! access — the reader must copy the whole page with one aligned read rather
//! than slicing the mapping at an unaligned offset, or it dies with SIGBUS.

/// Region base. Must stay above Linux's `mem=` top (0xF83FFFFF) and inside the
/// DTB's second RAM range (0x40000000-0xFFFFFFFF).
pub const REGION: usize = 0xF900_0000;

/// 64 KB is far more than a boot log needs, but the region is carved from ~124 MB
/// of RAM that nothing else can touch, so there is no reason to be stingy — and
/// a memory-map dump plus a page-table trace adds up faster than you expect.
pub const REGION_SIZE: usize = 0x1_0000;

const MAGIC = "STYGIA-EARLYLOG\x00";

const OFF_MAGIC: usize = 0x00;
const OFF_LEN: usize = 0x10;
const OFF_TEXT: usize = 0x14;

/// Leave a little headroom below the region end so a runaway logger truncates
/// instead of writing past the region into memory we have not reserved.
const TEXT_CAP: u32 = REGION_SIZE - OFF_TEXT - 0x100;

var len: u32 = 0;
var truncated: bool = false;

/// Optional live sink, attached once a UART console exists. Until then this really
/// is a postmortem-only channel; afterwards every logged byte also goes out on the
/// wire, which is the difference between reading the boot after the fact and
/// watching it happen.
var mirror: ?*const fn (u8) void = null;
/// How much of the buffer the sink has already seen.
var mirrored: u32 = 0;

/// Attach a live sink and hand it everything logged so far.
///
/// The replay is a TAIL replay, which is what makes this idempotent: a console can
/// legitimately be selected more than once (the PCIe path brings RP1 up and claims
/// it, then the selection in `entry.zig` confirms it), and replaying from zero each
/// time would print the whole log again on every call.
pub fn setMirror(sink: *const fn (u8) void) void {
    mirror = sink;
    while (mirrored < len) : (mirrored += 1) {
        const p: *volatile u8 = @ptrFromInt(REGION + OFF_TEXT + mirrored);
        sink(p.*);
    }
}

/// Stamp the magic and reset the length. Call this first, before anything that
/// could fault, so that even an immediate crash leaves evidence we got here.
pub fn init() void {
    const magic_dst: *volatile [MAGIC.len]u8 = @ptrFromInt(REGION + OFF_MAGIC);
    for (MAGIC, 0..) |c, i| magic_dst[i] = c;
    len = 0;
    truncated = false;
    lenCell().* = 0;
}

fn lenCell() *volatile u32 {
    return @ptrFromInt(REGION + OFF_LEN);
}

pub fn byte(b: u8) void {
    if (len >= TEXT_CAP) {
        truncated = true;
        // Still put it on the wire. A live console that outlives the DRAM buffer is
        // strictly better than losing both channels at once.
        if (mirror) |sink| sink(b);
        return;
    }
    const p: *volatile u8 = @ptrFromInt(REGION + OFF_TEXT + len);
    p.* = b;
    len += 1;
    if (mirror) |sink| {
        sink(b);
        // Keep `mirrored == len` while a sink is attached, so a later `setMirror`
        // replays nothing rather than repeating the log.
        mirrored = len;
    }
}

pub fn str(s: []const u8) void {
    for (s) |c| byte(c);
}

pub fn hex(v: u64) void {
    str("0x");
    var started = false;
    var shift: u6 = 60;
    while (true) {
        const nib: u8 = @truncate((v >> shift) & 0xF);
        if (nib != 0 or started or shift == 0) {
            started = true;
            byte(if (nib < 10) '0' + nib else 'a' + (nib - 10));
        }
        if (shift == 0) break;
        shift -= 4;
    }
}

pub fn dec(v: u64) void {
    if (v >= 10) dec(v / 10);
    byte('0' + @as(u8, @truncate(v % 10)));
}

/// Render a byte count as a human-readable size. Memory-map dumps are unreadable
/// in raw bytes and this is the difference between spotting a wrong range and
/// squinting at 3221225472.
pub fn size(bytes: u64) void {
    if (bytes >= 1024 * 1024 * 1024 and bytes % (1024 * 1024 * 1024) == 0) {
        dec(bytes / (1024 * 1024 * 1024));
        str(" GiB");
    } else if (bytes >= 1024 * 1024 and bytes % (1024 * 1024) == 0) {
        dec(bytes / (1024 * 1024));
        str(" MiB");
    } else if (bytes >= 1024 and bytes % 1024 == 0) {
        dec(bytes / 1024);
        str(" KiB");
    } else {
        dec(bytes);
        str(" B");
    }
}

/// Publish the length. Until this runs the reader treats the record as
/// incomplete, so every meaningful checkpoint should call it — a log that is
/// only committed at the very end tells you nothing about where a hang was.
pub fn commit() void {
    if (truncated) {
        // Record the truncation in the log itself rather than only in a flag no
        // reader will ever see. A silently truncated log reads as a complete one.
        const note = "\n*** early log TRUNCATED ***\n";
        var i: usize = 0;
        while (i < note.len and len < TEXT_CAP + 0x80) : (i += 1) {
            const p: *volatile u8 = @ptrFromInt(REGION + OFF_TEXT + len);
            p.* = note[i];
            len += 1;
        }
        truncated = false;
    }
    lenCell().* = len;
    // Order the stores, then force them out to DRAM.
    //
    // With the MMU off these stores are non-cacheable and a barrier alone would
    // do. That stopped being true the moment the loader began enabling the MMU:
    // this region is inside a RAM range mapped Normal Write-Back, so committed
    // text can sit in this core's D-cache, and a reset with dirty lines still
    // resident loses exactly the postmortem the region exists to preserve.
    //
    // Cleaning here rather than mapping the region as Device is deliberate. A
    // Device carve-out inside a 1 GiB Normal block means layering a 4 KiB mapping
    // inside a block descriptor, and `mapPageBoot` cannot tell a block from a
    // table — it descends into the block's output address and corrupts whatever
    // lives there (measured: DFSC=0x0, FAR=0xFFFF_FFFF_F000). Uniform granularity
    // plus explicit maintenance is the safe half of that trade.
    asm volatile ("dsb sy" ::: .{ .memory = true });
    cleanToPoC(REGION, OFF_TEXT + len);
    asm volatile ("dsb sy" ::: .{ .memory = true });
}

/// Clean-and-invalidate `[base, base+bytes)` to the point of coherency.
///
/// Stride comes from CTR_EL0.DminLine (log2 of the line size in 32-bit words)
/// rather than a hardcoded 64. A stride larger than the real line size would skip
/// lines and silently lose part of the log; reading the register costs two
/// instructions and removes the guess.
fn cleanToPoC(base: usize, bytes: usize) void {
    var ctr: u64 = undefined;
    asm volatile ("mrs %[v], ctr_el0"
        : [v] "=r" (ctr),
    );
    const dmin_line: u6 = @truncate((ctr >> 16) & 0xF);
    const line: usize = @as(usize, 4) << dmin_line;

    var addr = base & ~(line - 1);
    const end = base + bytes;
    while (addr < end) : (addr += line) {
        asm volatile ("dc civac, %[a]"
            :
            : [a] "r" (addr),
            : .{ .memory = true });
    }
}
