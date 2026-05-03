// Spec §[affinity] affinity — test 05.
//
// "[test 05] on success, the target EC's affinity is set to [2]."
//
// Strategy
//   §[execution_context] field layout: field1 bits 0-63 carry the EC's
//   current 64-bit affinity mask. The `affinity` syscall mutates that
//   kernel-authoritative state, and per §[capabilities] the syscall
//   itself implicitly refreshes the [1] handle's field0/field1 snapshot
//   (also formalized as test 06 of this section). To be defensive
//   against any reordering of that side-effect, we additionally call
//   `sync` before reading the snapshot.
//
//   Mint a fresh EC with target=self so the handle lands directly in
//   our own table (slot returned by create_execution_context). Grant
//   the EC handle the `saff` cap so the affinity call's own cap check
//   (test 02) does not fire. Use an initial affinity mask of 0b0001
//   at create time, then call `affinity` with a different multi-bit
//   mask 0b0011 so the post-condition compare against the requested
//   mask is non-trivial (proves the kernel actually wrote the new
//   value rather than leaving the original in place).
//
//   Neutralize every other failure path so test 05 is the only spec
//   assertion exercised:
//     - target is a valid EC handle (just minted), so test 01 (BADCAP)
//       does not fire.
//     - target's caps include `saff`, so test 02 (PERM) does not fire.
//     - new_affinity bits 0-1 are inside the 4-core CI runner config,
//       so test 03 (out-of-range core) does not fire.
//     - reserved bits in [1] are clean (we pass a u12 through the
//       typed wrapper), so test 04 does not fire.
//
//   Pre-conditions on EC creation that must also pass:
//     - Caller already has `crec` on its self-handle (granted by the
//       runner via SelfCap.crec = true).
//     - caps = {saff, susp, term, restart_policy=0}, all within the
//       runner's child ec_inner_ceiling (0xFF, see runner/primary.zig
//       ceilings_inner).
//     - priority = 0, well under the runner's child priority ceiling
//       of 3.
//     - stack_pages = 1 (nonzero).
//     - create-time affinity 0b0001 is inside the 4-core system.
//     - reserved bits in the create caps word are clean.
//
// Action
//   1. create_execution_context(caps={saff,susp,term,rp=0},
//      entry=&dummyEntry, stack_pages=1, target=0,
//      affinity=0b0001)                                  — must succeed
//   2. affinity(ec_handle, 0b0011)                       — must succeed
//   3. sync(ec_handle)                                   — refresh field1
//   4. readCap(cap_table_base, ec_handle).field1 == 0b0011
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: affinity itself returned non-OK
//   3: sync returned non-OK
//   4: post-sync field1 does not equal the requested affinity mask

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
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

    // Cores 0-1 are inside the 4-core CI runner config so neither the
    // create-time test 09 nor the affinity-syscall test 03 can fire.
    const initial_affinity: u64 = 0b0001;
    const new_affinity: u64 = 0b0011;

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

    const aff_result = syscall.affinity(ec_handle, new_affinity);
    if (aff_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Force a fresh kernel-authoritative refresh of the handle's
    // field0/field1 snapshot before reading. The affinity call itself
    // is spec'd to refresh per test 06, but `sync` is the explicit,
    // spec-blessed path that does not depend on the side-effect of
    // another op having taken effect first.
    const sync_result = syscall.sync(ec_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    const cap = caps.readCap(cap_table_base, ec_handle);
    if (cap.field1 != new_affinity) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
