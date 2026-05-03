// Spec §[snapshot] — test 06.
//
// "[test 06] returns E_INVAL if any reserved bits are set in [1] or [2]."
//
// Strategy
//   §[snapshot] takes two VAR handles. Per §[handle_layout], a handle
//   argument carries only the 12-bit handle id in bits 0-11; bits 12-63
//   are _reserved. Setting any bit in that reserved range on either [1]
//   or [2] must surface E_INVAL at the syscall ABI layer regardless of
//   whether the rest of the call would otherwise have succeeded
//   (§[syscall_abi]).
//
//   To isolate the reserved-bit check we drive every other §[snapshot]
//   prelude check past inert:
//     - tests 01/02 (handle is not a valid VAR) — pass freshly-minted
//                                                  VAR handles.
//     - test 03 ([1].caps.restart_policy != 3)  — target is created with
//                                                  restart_policy = 3.
//     - test 04 ([2].caps.restart_policy != 2)  — source is created with
//                                                  restart_policy = 2.
//     - test 05 (size mismatch)                  — both VARs have sz = 0
//                                                  and pages = 1.
//   We then dial in a single reserved bit on top of an otherwise-valid
//   handle id. Bit 63 sits at the top of the bits 12-63 reserved range
//   and cannot be mistaken for any defined field.
//
//   The libz `syscall.snapshot` wrapper takes `target_var: u12` and
//   `source_var: u12`, which cannot carry reserved bits. We bypass that
//   wrapper via `syscall.issueReg` directly so we can stuff bit 63 into
//   vreg 1 (case A) or vreg 2 (case B).
//
// Action
//   1. createVar(caps={r, w, restart_policy=3}, props=0b011, pages=1)
//      — must succeed, gives a snapshot-policy target VAR.
//   2. createVar(caps={r, w, restart_policy=2}, props=0b011, pages=1)
//      — must succeed, gives a preserve-policy source VAR with the
//      same size.
//   3. snapshot(target | (1 << 63), source) — must return E_INVAL.
//   4. snapshot(target, source | (1 << 63)) — must return E_INVAL.
//
// Assertions
//   1: reserved bit set in [1] did not return E_INVAL.
//   2: reserved bit set in [2] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: snapshot-policy target VAR. restart_policy = 3 makes
    // §[snapshot] test 03 inert. caps.r/w match the props' cur_rwx so
    // create_var's own subset checks don't fire.
    const target_caps = caps.VarCap{ .r = true, .w = true, .restart_policy = 3 };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const ct = syscall.createVar(
        @as(u64, target_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(ct.v1)) {
        // Prelude broke; we cannot exercise the reserved-bit gate
        // without a valid target VAR. Surface as test 1 failure.
        testing.fail(1);
        return;
    }
    const target_handle: caps.HandleId = @truncate(ct.v1 & 0xFFF);

    // Step 2: preserve-policy source VAR with the same size as the
    // target. restart_policy = 2 makes §[snapshot] test 04 inert; the
    // matching pages × sz makes test 05 inert.
    const source_caps = caps.VarCap{ .r = true, .w = true, .restart_policy = 2 };
    const cs = syscall.createVar(
        @as(u64, source_caps.toU16()),
        props,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cs.v1)) {
        testing.fail(1);
        return;
    }
    const source_handle: caps.HandleId = @truncate(cs.v1 & 0xFFF);

    // Case A: reserved bit 63 of [1] set on top of a valid target id.
    // Bypass the typed wrapper since it takes u12 and would truncate
    // the reserved bit before it reaches the kernel.
    const target_with_reserved: u64 = @as(u64, target_handle) | (@as(u64, 1) << 63);
    const a = syscall.issueReg(.snapshot, 0, .{
        .v1 = target_with_reserved,
        .v2 = @as(u64, source_handle),
    });
    if (a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case B: [1] clean and valid, reserved bit 63 of [2] set on top
    // of a valid source id.
    const source_with_reserved: u64 = @as(u64, source_handle) | (@as(u64, 1) << 63);
    const b = syscall.issueReg(.snapshot, 0, .{
        .v1 = @as(u64, target_handle),
        .v2 = source_with_reserved,
    });
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
