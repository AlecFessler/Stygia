// Spec §[ack] — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   §[ack] takes [1] as a `device_region handle`. Per §[capabilities]
//   the convention for handle-only args is that bits 0-11 carry the
//   12-bit handle id and bits 12-63 are _reserved. Setting any bit in
//   the reserved range must surface E_INVAL at the syscall ABI layer
//   regardless of whether the rest of the call would otherwise have
//   succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check from the BADCAP check (test 01),
//   the low 12 bits must hold a valid handle id. The runner does not
//   forward a device_region handle to test children today (slots 0/1/2
//   are self / initial EC / self-IDC, slot 3 is the result port). Mint
//   a fresh port handle via create_port and use its id in the low 12
//   bits — sync_02 / delete_02 use the same shape (any valid id is
//   sufficient because the reserved-bit check is ABI-layer and fires
//   before the type/cap gates).
//
//   We pick bit 63 (top of the reserved range) to mirror the reference
//   pattern in create_var_17.zig — it sits well above any current or
//   plausible future field on a handle word and cannot be mistaken for
//   a real id bit.
//
//   The libz `syscall.ack` wrapper takes `device_region: u12`, which
//   cannot carry reserved bits in [1]. We bypass that wrapper and
//   dispatch through `syscall.issueReg` directly so we can stuff
//   bit 63 into vreg 1.
//
// Action
//   1. create_port(caps={bind})              — must succeed
//   2. ack(handle | (1 << 63))               — must return E_INVAL
//      (reserved bit 63 of [1] set; low 12 bits hold a valid id)
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: ack with reserved bit 63 of [1] returned something other than
//      E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Reserved bit 63 of [1] set; low 12 bits hold a valid id. Bypass
    // the typed wrapper since `syscall.ack` takes u12 and would
    // truncate the reserved bit before it reaches the kernel.
    const handle_with_reserved: u64 = @as(u64, port_handle) | (@as(u64, 1) << 63);
    const r = syscall.issueReg(.ack, 0, .{ .v1 = handle_with_reserved });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
