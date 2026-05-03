// Spec §[capability_domain] acquire_vars — test 03.
//
// "[test 03] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] IDC handle word carries the 12-bit handle id in bits 0-11
//   with bits 12-63 _reserved. Setting any bit outside the handle id
//   field is a spec violation that must surface E_INVAL.
//
//   To isolate the reserved-bit check from the BADCAP check (test 01)
//   and the PERM check (test 02), the low 12 bits must hold a valid
//   IDC handle id, and that handle must carry the `aqvr` cap. Slot 2
//   of every freshly-created capability domain is the self-IDC handle
//   (§[create_capability_domain]); the runner spawns each test child
//   with `cridc_ceiling = 0x3F`, which sets every defined IDC cap bit
//   including `aqvr` (bit 4). Using `SLOT_SELF_IDC` as the base id
//   therefore satisfies both the validity check and the cap check.
//
//   The libz `syscall.acquireVars` wrapper takes `target: u12`, which
//   cannot carry reserved bits in [1]. We bypass that wrapper and
//   dispatch through `syscall.issueReg` directly so we can stuff bit
//   12 into vreg 1.
//
// Action
//   1. acquire_vars(SLOT_SELF_IDC | (1 << 12)) — must return E_INVAL
//      (reserved bit 12 of [1] set; low 12 bits hold the valid id)
//
// Assertions
//   1: acquire_vars with reserved bit 12 of [1] returned something
//      other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Reserved bit 12 of [1] set, low 12 bits hold a valid IDC handle
    // id (the self-IDC at slot 2). Bypass the typed wrapper since
    // `syscall.acquireVars` takes u12 and would truncate the reserved
    // bit before it reaches the kernel.
    const handle_with_reserved: u64 =
        @as(u64, caps.SLOT_SELF_IDC) | (@as(u64, 1) << 12);
    const result = syscall.issueReg(.acquire_vars, 0, .{
        .v1 = handle_with_reserved,
    });
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
