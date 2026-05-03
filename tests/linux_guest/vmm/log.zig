/// Debug logging helpers for linux_guest VMM.
///
/// Spec v3 has no debug-write syscall. Output goes to COM1 (0x3F8/8) via
/// the port-IO virtualization path: the bootloader hands the kernel a
/// `device_region` for COM1 with `dev_type = port_io`; the kernel
/// passes it into the root-service domain at create-time as a passed
/// handle. We discover it by scanning the cap table, build an MMIO VAR
/// over it via `map_mmio`, and 1-byte stores to the VAR's base address
/// trap and emulate as `out (base_port + offset), al` per
/// §[port_io_virtualization].
///
/// Initialized lazily by `init` from `_start`'s cap_table_base; until
/// then, all print/hex/dec calls are no-ops. That's deliberate — the
/// VMM may want to log VERY early (cap-table walk diagnostics) and we
/// don't want to crash the path if init hasn't run yet.
const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

var serial_base: ?[*]volatile u8 = null;

/// Discover COM1 in the cap table, map an MMIO VAR over it, store the
/// base for `print`/`hex*`/`dec` to use. Idempotent — repeated calls
/// are no-ops once `serial_base` is set.
pub fn init(cap_table_base: u64) void {
    if (serial_base != null) return;
    const dev = findCom1(cap_table_base) orelse return;

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
    // FRAGILE — relies on the current spec convention that error codes
    // are positive 1..15 and handle words are ≥ 0x1000 (the type tag in
    // cap word 0 bits 12-15 is non-zero for any real handle, so no real
    // handle ever lives in [1..15]). That makes `< 16` a clean
    // success/failure split.
    //
    // If error codes are EVER changed to be negative (signed) — or to
    // any encoding where the error and success-handle ranges overlap —
    // every site in libz/linux_guest that disambiguates with `< 16` (or
    // similar small-positive checks) MUST be revisited. Grep for
    // `cvar.v1 <` and `lib.errors.isError` before flipping the
    // convention.
    if (cvar.v1 < 16) return;
    const var_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const mm = syscall.mapMmio(var_handle, dev);
    if (mm.v1 != 0) return;

    serial_base = @ptrFromInt(var_base);
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

pub fn print(msg: []const u8) void {
    const b = serial_base orelse return;
    var i: usize = 0;
    while (i < msg.len) {
        b[0] = msg[i];
        i += 1;
    }
}

const hex_chars = "0123456789ABCDEF";

pub fn hex8(val: u8) void {
    const b = serial_base orelse return;
    b[0] = hex_chars[val >> 4];
    b[0] = hex_chars[val & 0xF];
}

pub fn hex16(val: u16) void {
    hex8(@truncate(val >> 8));
    hex8(@truncate(val));
}

pub fn hex32(val: u32) void {
    hex16(@truncate(val >> 16));
    hex16(@truncate(val));
}

pub fn hex64(val: u64) void {
    hex32(@truncate(val >> 32));
    hex32(@truncate(val));
}

pub fn dec(val: u64) void {
    const b = serial_base orelse return;
    if (val == 0) {
        b[0] = '0';
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var v = val;
    while (v > 0) {
        i -= 1;
        buf[i] = @truncate((v % 10) + '0');
        v /= 10;
    }
    while (i < 20) {
        b[0] = buf[i];
        i += 1;
    }
}
