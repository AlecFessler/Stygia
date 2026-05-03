// Spec §[acquire_ecs] acquire_ecs — test 05.
//
// "[test 05] on success, the syscall word's count field equals the
//  number of non-vCPU ECs bound to the target domain."
//
// Strategy
//   The runner spawns each test as a fresh capability domain. By
//   construction the new domain is born with exactly one execution
//   context — the initial EC at slot 1 — and no vCPUs (the runner
//   never calls create_vcpu on the test domains). The slot-2 self-IDC
//   handle targets the test's own domain, so calling acquire_ecs on
//   that handle asks the kernel to enumerate the test domain's own
//   ECs.
//
//   The runner provisions slot 2 with `cridc_ceiling = 0x3F`, which
//   sets all six IDC cap bits including `aqec` (§[capability_domain]).
//   That avoids the test 02 E_PERM gate. The slot is valid (test 01),
//   reserved bits in [1] are zero (test 03), and the caller's handle
//   table has plenty of free slots for the single returned handle so
//   E_FULL (test 04) does not fire.
//
//   With every other gate cleared, the call succeeds. The kernel
//   sets the syscall word's count field (bits 12-19) to N, the number
//   of non-vCPU ECs in the target domain. For a freshly-spawned test
//   domain that count is 1 (the initial EC, which is the EC issuing
//   the call).
//
// Action
//   1. acquire_ecs(SLOT_SELF_IDC) — must succeed
//   2. extract count from the returned syscall word (bits 12-19)
//   3. assert count == 1
//
// Assertions
//   1: acquire_ecs returned an error in vreg 1
//   2: the returned syscall word's count field is not 1

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const self_idc: u12 = caps.SLOT_SELF_IDC;

    const result = syscall.acquireEcs(self_idc);

    // On success, v1 is either OK (count == 0) or a packed handle
    // word; only error codes 1..15 indicate failure per §[error_codes].
    if (testing.isHandleError(result.regs.v1)) {
        testing.fail(1);
        return;
    }

    // §[syscall_abi] / §[acquire_ecs]: count occupies bits 12-19 of
    // the syscall word on return.
    const count: u64 = (result.word >> 12) & 0xFF;
    if (count != 1) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
