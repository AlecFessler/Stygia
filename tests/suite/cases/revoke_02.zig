// Spec §[capabilities] revoke — test 02.
//
// "[test 02] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] handle word carries the 12-bit handle id in bits 0-11
//   with bits 12-63 _reserved. Setting any bit outside the id field
//   is a spec violation that must surface E_INVAL.
//
//   To isolate the reserved-bit check we make every other check
//   pass: the handle id must be valid (so no E_BADCAP, test 01).
//   That leaves the reserved-bit check as the only spec-mandated
//   failure path.
//
//   The setup creates a port handle with caps {bind}; revoke does
//   not require any specific cap on the target handle.
//
// Action
//   1. create_port(caps={bind})            — must succeed
//   2. revoke(handle | (1 << 12))          — must return E_INVAL
//      (reserved bit 12 of [1] set; low 12 bits hold the valid id)
//
//   The libz `syscall.revoke` wrapper takes `handle: u12`, which
//   cannot carry reserved bits in [1]. We bypass that wrapper and
//   dispatch through `syscall.issueReg` directly so we can stuff
//   bit 12 into vreg 1.
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: revoke with reserved bit 12 of [1] returned something other
//      than E_INVAL

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

    // Reserved bit 12 of [1] set; low 12 bits hold the valid id.
    // Bypass the typed wrapper since it takes u12 and would
    // truncate the reserved bit before it reaches the kernel.
    const handle_with_reserved: u64 = @as(u64, port_handle) | (@as(u64, 1) << 12);
    const r = syscall.issueReg(.revoke, 0, .{ .v1 = handle_with_reserved });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
