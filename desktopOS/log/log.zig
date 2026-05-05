// desktopOS shared COM1 log sink. Same pattern as the test runner's
// serial.zig — discover the boot-issued port_io device_region for
// 0x3F8/8, stage an MMIO VMAR over it, then 1-byte MOV stores trap to
// `out (base_port + offset), al` per §[port_io_virtualization].

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

var sink: ?[*]volatile u8 = null;

pub fn init(cap_table_base: u64) void {
    const dev = findCom1(cap_table_base) orelse return;

    const var_caps_word = caps.VmarCap{
        .r = true,
        .w = true,
        .mmio = true,
    };
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (0 << 3) | // sz = 0 (4 KiB)
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        1,
        0,
        0,
    );
    if (cvar.v1 == 0) return;
    const vmar_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const mm = syscall.mapMmio(vmar_handle, dev);
    if (mm.v1 != 0) return;

    sink = @ptrFromInt(var_base);
}

fn findCom1(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dr = caps.deviceRegionFields(c);
            if (dr.dev_type == .port_io and
                dr.base_port == COM1_BASE_PORT and
                dr.port_count == COM1_PORT_COUNT)
            {
                return @truncate(slot);
            }
        }
        slot += 1;
    }
    return null;
}

pub fn putc(byte: u8) void {
    const b = sink orelse return;
    b[0] = byte;
}

pub fn print(s: []const u8) void {
    const b = sink orelse return;
    var i: usize = 0;
    while (i < s.len) {
        b[0] = s[i];
        i += 1;
    }
}

const HEX: []const u8 = "0123456789abcdef";

pub fn hex8(v: u8) void {
    putc(HEX[v >> 4]);
    putc(HEX[v & 0xF]);
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

pub fn dec(n: u64) void {
    var buf: [20]u8 = undefined;
    if (n == 0) {
        putc('0');
        return;
    }
    var v: u64 = n;
    var i: usize = 0;
    while (v != 0) {
        buf[i] = @intCast('0' + (v % 10));
        v /= 10;
        i += 1;
    }
    while (i > 0) {
        i -= 1;
        putc(buf[i]);
    }
}
