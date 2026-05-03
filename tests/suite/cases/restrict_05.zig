// Spec §[capabilities] restrict — test 05.
//
// "[test 05] returns E_INVAL if any reserved bits are set in [1] or [2]."
//
// Strategy
//   The [1] handle word carries the 12-bit handle id in bits 0-11 with
//   bits 12-63 _reserved. The [2] caps word carries the new caps in
//   bits 0-15 with bits 16-63 _reserved. Setting any bit outside the
//   defined fields is a spec violation that must surface E_INVAL.
//
//   To isolate the reserved-bit check we must make every other check
//   pass:
//     - handle id must be valid (so no E_BADCAP, test 01)
//     - new caps must be a true subset of current caps under the
//       semantics of test 02-04 (so no E_PERM)
//   That leaves the reserved-bit check as the only spec-mandated
//   failure path.
//
//   The setup uses a port handle with caps {bind, recv}, then
//   restricts to the strict subset {bind}. Port caps use only bitwise
//   subset semantics; there is no restart_policy field in play, so the
//   check from tests 03/04 cannot fire.
//
// Action
//   1. create_port(caps={bind, recv})            — must succeed
//   2. restrict(handle | (1 << 12), caps={bind}) — must return E_INVAL
//      (reserved bit 12 of [1] set; low 12 bits hold the valid id)
//   3. restrict(handle, caps={bind} | (1 << 16)) — must return E_INVAL
//      (reserved bit 16 of [2] set; low 16 bits hold a valid subset)
//
//   The libz `syscall.restrict` wrapper takes `handle: u12`, which
//   cannot carry reserved bits in [1]. We bypass that wrapper for
//   step 2 and dispatch through `syscall.issueReg` directly so we can
//   stuff bit 12 into vreg 1.
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: restrict with reserved bit 12 of [1] returned something other
//      than E_INVAL
//   3: restrict with reserved bit 16 of [2] returned something other
//      than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const subset = caps.PortCap{ .bind = true };
    const subset_word: u64 = @as(u64, subset.toU16());

    // Branch A: reserved bit 12 of [1] set, [2] clean and a strict
    // subset. Bypass the typed wrapper since it takes u12 and would
    // truncate the reserved bit before it reaches the kernel.
    const handle_with_reserved: u64 = @as(u64, port_handle) | (@as(u64, 1) << 12);
    const a = syscall.issueReg(.restrict, 0, .{
        .v1 = handle_with_reserved,
        .v2 = subset_word,
    });
    if (a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    // Branch B: [1] clean and valid, reserved bit 16 of [2] set on top
    // of a strict subset.
    const caps_with_reserved: u64 = subset_word | (@as(u64, 1) << 16);
    const b = syscall.restrict(port_handle, caps_with_reserved);
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
