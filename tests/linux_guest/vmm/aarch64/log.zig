//! Logging helper for the aarch64 linux_guest VMM.
//!
//! On boot the kernel passes an MMIO device_region for the host PL011
//! UART (QEMU virt machine UART0 @ 0x09000000) into root_service's cap
//! table. `init` scans for it, allocates a VAR with the `mmio` cap,
//! `mapMmio`s the device into it, and pins the resulting host VA so
//! `print`/`hex*`/`dec` and `pl011.bindTxSink` can write bytes that
//! end up on QEMU's `-serial stdio`.
//!
//! Until `init` runs, all calls are no-ops — the VMM may want to log
//! before init lands and we don't want a crash.

const lib = @import("lib");

const pl011 = @import("pl011.zig");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

var sink: ?[*]volatile u8 = null;

const PL011_BASE: u64 = 0x0900_0000;
const PL011_SIZE: u64 = 0x1000;

pub fn init(cap_table_base: u64) void {
    if (sink != null) return;
    const dev = findPl011(cap_table_base) orelse return;

    const var_caps_word = caps.VarCap{
        .r = true,
        .w = true,
        .mmio = true,
    };
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (0 << 3) | // sz = 0 (4 KiB)
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        props,
        1,
        0,
        0,
    );
    if (cvar.v1 < 16) return;
    const var_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const mm = syscall.mapMmio(var_handle, dev);
    if (mm.v1 != 0) return;

    sink = @ptrFromInt(var_base);
    pl011.bindTxSink(@ptrFromInt(var_base));
}

fn findPl011(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            // field0 layout (mmio):
            //   bits 0-3   dev_type (0)
            //   bits 4-51  base_paddr >> 12
            //   bits 52-63 size_pages
            const dev_type: u4 = @truncate(c.field0 & 0xF);
            if (dev_type == 0) {
                const base_paddr = ((c.field0 >> 4) & ((1 << 48) - 1)) << 12;
                const size_pages = (c.field0 >> 52) & 0xFFF;
                if (base_paddr == PL011_BASE and size_pages * 4096 == PL011_SIZE) {
                    return @truncate(slot);
                }
            }
        }
        slot += 1;
    }
    return null;
}

pub fn print(msg: []const u8) void {
    const s = sink orelse return;
    var i: usize = 0;
    while (i < msg.len) {
        s[0] = msg[i];
        i += 1;
    }
}

const HEX_CHARS = "0123456789abcdef";

pub fn hex8(v: u8) void {
    const s = sink orelse return;
    s[0] = HEX_CHARS[v >> 4];
    s[0] = HEX_CHARS[v & 0xF];
}

pub fn hex16(v: u16) void {
    hex8(@truncate(v >> 8));
    hex8(@truncate(v));
}

pub fn hex32(v: u32) void {
    hex16(@truncate(v >> 16));
    hex16(@truncate(v));
}

pub fn hex64(v: u64) void {
    hex32(@truncate(v >> 32));
    hex32(@truncate(v));
}

pub fn dec(v: u64) void {
    const s = sink orelse return;
    if (v == 0) {
        s[0] = '0';
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var n = v;
    while (n > 0) {
        i -= 1;
        buf[i] = @intCast('0' + (n % 10));
        n /= 10;
    }
    while (i < 20) {
        s[0] = buf[i];
        i += 1;
    }
}
