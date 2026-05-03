// COM1 serial-output glue for the v3 test runner. Discovers the
// boot-issued port_io device_region for 0x3F8/8, stages an MMIO VAR
// over it via map_mmio, then performs 1-byte MOV stores against the
// VAR base — each store traps and the kernel issues the equivalent
// `out (base_port + offset), al`. Per §[port_io_virtualization], MOV
// width 1 with `cur_rwx.w = 1` is the simplest form supported.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

pub const Serial = struct {
    base: ?[*]volatile u8,

    pub fn putc(self: *const Serial, byte: u8) void {
        const b = self.base orelse return;
        b[0] = byte;
    }

    pub fn print(self: *const Serial, s: []const u8) void {
        const b = self.base orelse return;
        var i: usize = 0;
        while (i < s.len) {
            b[0] = s[i];
            i += 1;
        }
    }

    pub fn printU64(self: *const Serial, n: u64) void {
        const b = self.base orelse return;
        var buf: [20]u8 = undefined;
        if (n == 0) {
            b[0] = '0';
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
            b[0] = buf[i];
        }
    }
};

pub const DISABLED: Serial = .{ .base = null };

pub fn init(cap_table_base: u64) Serial {
    const dev = findCom1(cap_table_base) orelse return DISABLED;

    // SPEC AMBIGUITY: §[map_mmio] test 05 requires VAR.size ==
    // device_region.size, but §[device_region] does not define a size
    // field for port_io regions (only base_port and port_count). The
    // kernel must reconcile: assume one 4 KiB page covers any port_io
    // range whose port_count fits in 4096 bytes. COM1 has 8 ports so
    // this trivially holds.
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
    if (cvar.v1 == 0) return DISABLED; // E_* in vreg 1 on failure
    const var_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const mm = syscall.mapMmio(var_handle, dev);
    if (mm.v1 != 0) return DISABLED;

    return .{ .base = @ptrFromInt(var_base) };
}

fn findCom1(cap_table_base: u64) ?HandleId {
    // SPEC AMBIGUITY: boot-time root-service handle layout undefined.
    // Slots 0/1/2 are self / initial EC / self-IDC; passed_handles
    // start at 3 for create_capability_domain callers, but the spec
    // does not pin where the kernel populates root-service-only
    // handles like device_regions. Scan the full table.
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
