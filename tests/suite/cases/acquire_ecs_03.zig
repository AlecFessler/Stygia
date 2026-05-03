// Spec §[capabilities] acquire_ecs — test 03.
//
// "[test 03] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] handle word for `acquire_ecs` carries the 12-bit IDC handle
//   id in bits 0-11 with bits 12-63 _reserved. Setting any bit outside
//   the id field is a spec violation that must surface E_INVAL.
//
//   To isolate the reserved-bit check we must make every other check
//   pass:
//     - [1] must be a valid IDC handle (else test 01 would fire with
//       E_BADCAP).
//     - [1] must hold the `aqec` cap (else test 02 would fire with
//       E_PERM).
//   Slot 2 of every freshly-spawned domain (caps.SLOT_SELF_IDC) is the
//   self-IDC handle minted by `create_capability_domain` with caps =
//   the parent's `cridc_ceiling`. The runner's `cridc_ceiling` sets
//   IDC bits 0-5 = 0x3F, which includes `aqec` (bit 3). That makes the
//   self-IDC a valid IDC handle with `aqec`, leaving the reserved-bit
//   check as the only spec-mandated failure path.
//
//   The libz `syscall.acquireEcs` wrapper takes `target: u12`, which
//   cannot carry reserved bits in [1]. We bypass that wrapper and
//   dispatch through `syscall.issueReg` directly so we can stuff bit
//   12 into vreg 1.
//
// Action
//   1. acquire_ecs(SLOT_SELF_IDC | (1 << 12)) — must return E_INVAL
//      (reserved bit 12 of [1] set; low 12 bits hold the valid id of
//      the self-IDC handle, which carries `aqec`)
//
// Assertions
//   1: acquire_ecs with reserved bit 12 of [1] returned something
//      other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 2 is the self-IDC, minted with caps = parent's
    // cridc_ceiling (which the runner configures to include `aqec`).
    // Setting reserved bit 12 of [1] on top of that valid id isolates
    // the reserved-bit check (test 03) from the BADCAP check (test 01)
    // and the PERM check (test 02). Bypass the typed wrapper since
    // `syscall.acquireEcs` takes u12 and would truncate the reserved
    // bit before it reaches the kernel.
    const target_with_reserved: u64 =
        @as(u64, caps.SLOT_SELF_IDC) | (@as(u64, 1) << 12);
    const result = syscall.issueReg(.acquire_ecs, 0, .{
        .v1 = target_with_reserved,
    });
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
