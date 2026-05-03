// Spec §[suspend] — test 12.
//
// "[test 12] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   The spec requires that whenever `suspend` sees a valid EC handle
//   in [1], the kernel writes back [1]'s field0/field1 from
//   authoritative state — even when the call fails. The cleanest
//   proof is the same shape used by map_mmio_09: drive a failure
//   path that errors *after* [1] has been validated but *before*
//   any kernel-side mutation of the EC's authoritative state. If the
//   authoritative state never moved, then the spec-mandated refresh
//   must leave the cap-table slot bit-identical to the pre-call
//   snapshot.
//
//   The calling EC's own self handle (`SLOT_INITIAL_EC`) is a valid
//   EC handle by construction (the runner installs it at slot 1 with
//   caps = the child domain's `ec_inner_ceiling` per
//   §[capability_domain] / §[create_capability_domain] test 21). The
//   runner sets `ec_inner_ceiling = 0xFF` (primary.zig), so the slot-1
//   handle carries the `susp` cap (EcCap bit 5) — that means the [1]
//   gates (test 01 BADCAP and test 03 PERM `susp`) cannot fire.
//
//   To trigger an error after [1] passes, we pass an empty cap-table
//   slot as [2]. Slot 4095 is guaranteed empty by the
//   create_capability_domain table layout (slots 0/1/2 = self /
//   initial EC / self-IDC; passed_handles begin at slot 3, and the
//   primary passes only one — the result port — at slot 3). The
//   suspend syscall then returns E_BADCAP on the [2] gate (test 02).
//   The spec's "[1] is a valid handle" precondition for test 12 is
//   met, so the refresh requirement applies.
//
//   The EC's authoritative field0 / field1 (per §[execution_context]):
//     field0 bits 0-1 = `pri` (current scheduling priority)
//     field1 bits 0-63 = `affinity` (current core affinity mask)
//   are kernel-mutable but only mutated by the `priority` and
//   `affinity` syscalls (see §[execution_context] field-layout note).
//   This test calls neither between the snapshot and the failing
//   `suspend`, so the kernel's authoritative state for the calling
//   EC is unchanged across the call. A faithful refresh on
//   E_BADCAP must therefore leave field0 and field1 bit-identical to
//   the pre-call read.
//
//   SPEC AMBIGUITY: spec §[suspend] does not explicitly pin the
//   ordering of the [1] BADCAP gate vs. the [2] BADCAP gate. The
//   listed order (test 01 then test 02) and the parallel construction
//   in §[map_mmio] test 09 (which the kernel-test corpus already
//   relies on for the same refresh shape) imply the [1] gate fires
//   before the [2] gate. If the kernel orders them in the opposite
//   direction, [1] is never validated on this path and test 12's
//   precondition does not hold — a different failure path would be
//   needed. The test is written assuming the spec-listed order.
//
//   SPEC AMBIGUITY: §[suspend] does not pin whether the refresh is
//   visible in the cap-table slot before the syscall returns to the
//   caller. The §[capabilities] note that field0/field1 are
//   "kernel-mutable snapshots" that are "refreshed by the implicit
//   sync side effect of any syscall that takes the handle" implies
//   that the cap-table slot is updated as part of syscall
//   bookkeeping, so a post-call read sees the refreshed value. This
//   test assumes that visibility model.
//
// Action
//   1. readCap(SLOT_INITIAL_EC) → snapshot field0 and field1.
//      — must report handleType = execution_context (precondition).
//   2. issueReg(.@"suspend", 0, .{ v1 = SLOT_INITIAL_EC, v2 = 4095 })
//      — direct syscall, bypassing libz's `suspendEc` wrapper which
//      panics on attachments-N>0; here N=0 so a wrapper call would
//      also work, but using `issueReg` directly keeps this test
//      independent of the wrapper's signature.
//   3. assert v1 = E_BADCAP (precondition for the test 12 path —
//      [1] valid, [2] invalid).
//   4. readCap(SLOT_INITIAL_EC) → re-read field0 and field1.
//   5. assert post-call field0 == pre-call field0 AND post-call
//      field1 == pre-call field1.
//
// Assertions
//   1: precondition broken — slot 1 was not an execution_context
//      handle. The runner contract is violated; cannot evaluate the
//      spec assertion.
//   2: the failing `suspend` did not return E_BADCAP — either the
//      kernel ordered the gates differently or some earlier gate
//      fired, so the test 12 precondition ("[1] is a valid handle")
//      may not hold.
//   3: post-call field0 differs from the pre-call snapshot — the
//      cap-table slot is no longer a faithful reflection of kernel
//      state across an error return.
//   4: post-call field1 differs from the pre-call snapshot — same
//      shape as assertion 3 but for field1.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Precondition: SLOT_INITIAL_EC must be an EC handle. The runner
    // installs the child's initial EC at slot 1 with the
    // `ec_inner_ceiling` caps (§[create_capability_domain] test 21);
    // the child's `ec_inner_ceiling` is 0xFF in primary.zig so the
    // slot carries `susp` (EcCap bit 5). If this read disagrees, the
    // runner contract has shifted out from under the test.
    const cap_pre = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    if (cap_pre.handleType() != caps.HandleType.execution_context) {
        testing.fail(1);
        return;
    }
    const field0_pre = cap_pre.field0;
    const field1_pre = cap_pre.field1;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout, so the [2] BADCAP gate must fire. The [1] gate
    // has already passed (slot 1 is a valid EC), which is the
    // precondition for the spec's test 12 refresh requirement.
    const empty_slot: u64 = caps.HANDLE_TABLE_MAX - 1;
    const result = syscall.issueReg(.@"suspend", 0, .{
        .v1 = @as(u64, caps.SLOT_INITIAL_EC),
        .v2 = empty_slot,
    });
    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(2);
        return;
    }

    // The kernel never mutated the calling EC's priority or affinity
    // (no `priority` / `affinity` syscall ran between the snapshot
    // and this point), so the authoritative field0 / field1 are
    // unchanged. A spec-conformant refresh must therefore leave the
    // cap-table slot bit-identical to the pre-call snapshot.
    const cap_post = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    if (cap_post.field0 != field0_pre) {
        testing.fail(3);
        return;
    }
    if (cap_post.field1 != field1_pre) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
