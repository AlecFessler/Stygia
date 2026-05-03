// Spec §[affinity] affinity — test 03.
//
// "[test 03] returns E_INVAL if any bit set in [2] corresponds to a
//  core the system does not have."
//
// Strategy
//   The CI runner boots QEMU with `-smp cores=4`, so the system has
//   exactly 4 cores; bits 0-3 of the affinity mask are the only valid
//   bits. Setting any bit at position >= 4 should surface E_INVAL.
//
//   To isolate the out-of-range-core check we must make every other
//   spec-mandated failure path pass:
//     - [1] must be a valid EC handle (so test 01 BADCAP does not fire)
//     - [1] must carry the `saff` cap (so test 02 PERM does not fire)
//     - [1] must have clean reserved bits (so test 04 INVAL does not
//       fire on the [1] reserved-bit check)
//   That leaves the [2]-out-of-range check as the only assertion the
//   call can trigger.
//
//   Mint a fresh self-domain EC carrying `saff` (and `term`, `susp` for
//   shape parity with other EC tests) using a clean in-bounds initial
//   affinity. The runner's child ec_inner_ceiling is 0xFF, which
//   covers bits {move, copy, saff, spri, term, susp, read, write} — so
//   `saff` lives inside the ceiling and create_execution_context's
//   subset checks are satisfied.
//
//   For the affinity call itself, pick mask 0b1_0000 (bit 4 only). On
//   a 4-core system bit 4 corresponds to a core that does not exist,
//   so the call must fail with E_INVAL. The libz wrapper takes the
//   handle as `u12`, so [1]'s reserved bits 12-63 are guaranteed
//   zero — the test 04 reserved-bit check cannot fire.
//
// Action
//   1. create_execution_context(caps={saff,susp,term,rp=0},
//      entry=&dummyEntry, stack_pages=1, target=0,
//      affinity=0b0001)               — must succeed
//   2. affinity(ec_handle, 0b1_0000)  — must return E_INVAL
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: affinity returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const ec_caps = caps.EcCap{
        .saff = true,
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // Initial affinity = bit 0 only — well within the 4-core CI
    // config, so create_execution_context's [5]-affinity bounds check
    // (its own test 09) does not fire here.
    const initial_affinity: u64 = 0b0001;

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        initial_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Bit 4 names a core the 4-core system does not have. Bits 0-3
    // are the only valid positions; bit 4 is in-range as a u64 but
    // out-of-range as a core index, so spec test 03 fires.
    const out_of_range_mask: u64 = @as(u64, 1) << 4;

    const result = syscall.affinity(ec_handle, out_of_range_mask);
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
