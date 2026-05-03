// Spec §[capabilities] acquire_ecs — test 04.
//
// "[test 04] returns E_FULL if the caller's handle table cannot
//  accommodate all returned handles."
//
// Strategy
//   acquire_ecs mints a new handle in the caller's table for every
//   non-vCPU EC bound to the target domain (§[acquire_ecs] test 06).
//   To trigger E_FULL the caller's table must have fewer free slots
//   than the count of ECs the syscall would otherwise return.
//
//   The simplest faithful trigger is to fill the caller's table to
//   the brim: when zero slots are free, even returning a single EC
//   handle is impossible. The IDC at SLOT_SELF_IDC targets the
//   caller's own capability domain, which contains exactly one
//   non-vCPU EC at boot (the initial EC at SLOT_INITIAL_EC). The
//   self-IDC's caps are the parent's `cridc_ceiling`; the runner
//   primary mints it with all six IDC bits set including `aqec`,
//   so the cap and BADCAP/PERM checks (tests 01-02) cannot fire.
//   No reserved bits are set in [1] either (tests 03 clean), leaving
//   E_FULL as the only spec-mandated failure path.
//
//   Filling the table is done by creating ports in a tight loop. The
//   handle id is u12, with HANDLE_TABLE_MAX = 4096 total slots; the
//   kernel pre-populates slots 0..3 (self, initial EC, self-IDC,
//   result port). The remaining 4092 slots are created by repeated
//   `create_port` until the next call returns E_FULL — at which
//   point the table is provably saturated.
//
// Action
//   1. Saturate the caller's handle table by repeated `create_port`
//      until E_FULL is returned, confirming zero free slots remain.
//   2. acquire_ecs(SLOT_SELF_IDC) — must return E_FULL.
//
// Assertions
//   1: handle table did not saturate before HANDLE_TABLE_MAX
//      iterations (loop bound exceeded with no E_FULL returned)
//   2: acquire_ecs returned something other than E_FULL
//
// Notes on degraded execution
//   The v3 kernel is not yet implemented; this test is gated on
//   compile-and-link only. With a working kernel the saturation
//   loop is bounded by the 12-bit handle id space; without one the
//   ELF still links because every helper used here lives in libz
//   and is statically resolved at link time.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Drive the table to saturation. Use a port handle for the filler:
    // create_port has no side effects beyond minting a slot, and a
    // port with no caps is the smallest possible new entry. We bound
    // the loop at HANDLE_TABLE_MAX so a misbehaving kernel cannot
    // hang the test.
    const port_caps_word: u64 = @as(u64, (caps.PortCap{}).toU16());
    var saturated: bool = false;
    var i: u32 = 0;
    while (i < caps.HANDLE_TABLE_MAX) {
        const cp = syscall.createPort(port_caps_word);
        if (cp.v1 == @intFromEnum(errors.Error.E_FULL)) {
            saturated = true;
            break;
        }
        i += 1;
    }

    if (!saturated) {
        testing.fail(1);
        return;
    }

    const result = syscall.acquireEcs(caps.SLOT_SELF_IDC);
    if (result.regs.v1 != @intFromEnum(errors.Error.E_FULL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
