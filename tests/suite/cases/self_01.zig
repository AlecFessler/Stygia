// Spec §[self] self — test 01.
//
// "[test 01] returns E_NOENT if no handle in the caller's table
//  references the calling execution context."
//
// Strategy
//   At test entry the child capability domain's table has the initial
//   EC handle at slot 1 — and that EC is the caller. By the spec's
//   at-most-one invariant there is exactly one handle to the calling
//   EC in the table. To exercise the E_NOENT path we drop that
//   handle by calling `delete(SLOT_INITIAL_EC)` first. Per
//   §[capabilities] delete table: ECs have capability-domain
//   lifetime, so deleting the handle releases it from the table
//   without destroying the EC itself.
//
//   After the delete, no handle in the caller's table references
//   the calling EC. `self()` must return E_NOENT.
//
//   To report the result we still need an EC handle for `suspend`.
//   The slot-2 self-IDC, minted with the domain's `cridc_ceiling`,
//   carries the `aqec` cap by construction in the runner setup
//   (§[capability_domain] cridc_ceiling = 0x3F = move|copy|crec|
//   aqec|aqvr|restart_policy). After self() has been observed,
//   `acquire_ecs(SLOT_SELF_IDC)` re-mints a handle to the calling
//   EC into a fresh table slot; we then issue suspend with that
//   slot directly rather than going through `testing.pass()` (which
//   hardcodes SLOT_INITIAL_EC).
//
// Action
//   1. delete(SLOT_INITIAL_EC)         — release self-EC handle
//   2. self()                          — must return E_NOENT
//   3. acquire_ecs(SLOT_SELF_IDC)      — re-mint a self-EC handle
//   4. suspend(new_slot, port, code, id) — report via the result port
//
// Assertions
//   1: delete of the initial EC handle failed
//   2: self() returned something other than E_NOENT
//   3: acquire_ecs failed (cannot report via the standard path)
//
// Spec ambiguity: the slot-2 self-IDC's `ec_cap_ceiling` field is
// not pinned by the spec at create_capability_domain time; the
// returned EC handle's caps come from `target.ec_outer_ceiling` ∩
// IDC's `ec_cap_ceiling`. The runner's `ceilings_outer` sets
// ec_outer_ceiling = 0xFF (all EC caps including `susp`); we
// assume the kernel mints the self-IDC with a permissive
// ec_cap_ceiling such that the intersection includes `susp` and
// `bind`, otherwise the report path returns and the test ELF still
// terminates without producing an event — the runner records that
// as a missing/timed-out result rather than a spurious pass.

const lib = @import("lib");
const test_tag = @import("test_tag");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Local report variant — mirrors `lib.testing.report` but takes the
// EC slot as a parameter (the standard helper hardcodes
// SLOT_INITIAL_EC, which this test deletes before reporting). Must
// still load `test_tag.TAG` into vreg 5 so the runner attributes the
// result to this test rather than dropping the event for missing magic.
fn report(ec_slot: u12, code: u64, assertion_id: u64) void {
    _ = syscall.issueReg(.@"suspend", 0, .{
        .v1 = ec_slot,
        .v2 = caps.SLOT_FIRST_PASSED,
        .v3 = code,
        .v4 = assertion_id,
        .v5 = test_tag.TAG,
    });
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const del = syscall.delete(caps.SLOT_INITIAL_EC);
    if (del.v1 != @intFromEnum(errors.Error.OK)) {
        // Cannot report via standard path — slot 1 is still valid,
        // so testing.fail uses the live initial-EC handle.
        testing.fail(1);
        return;
    }

    const result = syscall.self();
    const observed = result.v1;

    const aq = syscall.acquireEcs(caps.SLOT_SELF_IDC);
    if (errors.isError(aq.regs.v1) and aq.regs.v1 < 16) {
        // No way to suspend without a self-EC handle — fall through
        // to start.zig's delete(SLOT_SELF), which cleans up the
        // domain. The runner records no result for this slot.
        return;
    }
    const new_ec_slot: u12 = @truncate(aq.regs.v1 & 0xFFF);

    if (observed != @intFromEnum(errors.Error.E_NOENT)) {
        report(new_ec_slot, testing.FAIL_CODE, 2);
        return;
    }

    report(new_ec_slot, testing.PASS_CODE, 0);
}
