// Spec §[perfmon_stop] perfmon_stop — test 06.
//
// "[test 06] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   §[capabilities]: any syscall that takes a handle whose state can
//   drift implicitly refreshes the holder's field0/field1 snapshot
//   from the authoritative kernel state. For an EC handle (§[execution_
//   context]) field0 carries the priority (bits 0-1) and field1 carries
//   the 64-bit affinity mask. perfmon_stop takes [1] as an EC handle,
//   so the implicit-sync rule applies, and the spec restates that the
//   side effect fires regardless of return code.
//
//   The strong-form spec assertion needs two distinguishing snapshots:
//   one taken before the implicit refresh and one taken after, with
//   the kernel's authoritative state having drifted in between. As
//   noted in priority_08, that requires two cap-table slots aliasing
//   the same EC across sibling capability domains, which the current
//   single-domain test runner does not yet provide.
//
//   Within those constraints, the property we can pin locally is that
//   the implicit-sync side effect on the failure path agrees with the
//   explicit `sync` syscall: after perfmon_stop returns, the snapshot
//   the holder sees in its cap table must equal the snapshot a
//   subsequent `sync` produces from the authoritative kernel state.
//   An implementation that clobbered the snapshot on the error path
//   (e.g. zeroed field0/field1 before the start-state check) would be
//   visibly inconsistent with the post-`sync` view.
//
// Variant choice: error path
//   The spec offers two viable observation points for test 06:
//
//     A) success path — perfmon_start then perfmon_stop. perfmon_start
//        depends on the host PMU exposing supported events (the
//        runner's perfmon_info_03 already concedes this is not
//        guaranteed in CI), so neither call is reliably success on
//        every platform.
//     B) error path — call perfmon_stop on an EC that has no perfmon
//        state. §[perfmon_stop] test 03 mandates E_INVAL in that case.
//        SLOT_INITIAL_EC is the test child's own initial EC; the runner
//        does not call perfmon_start on it, so perfmon_stop on it must
//        return E_INVAL on every platform regardless of PMU presence.
//
//   Picking B keeps the test platform-agnostic and on the path the
//   spec explicitly asks us to cover ("regardless of whether the call
//   returns success or another error code").
//
//   Neutralize every other failure path so test 03 (and only test 03)
//   is the path the kernel takes:
//     - Self-handle holds `pmu` (runner/primary.zig grants it on the
//       child_self), so test 01 (E_PERM) does not fire.
//     - SLOT_INITIAL_EC is a valid EC handle minted by the kernel as
//       part of capability-domain creation, so test 02 (E_BADCAP) does
//       not fire.
//     - SLOT_INITIAL_EC is the calling EC, so the "[1] is not the
//       calling EC and not currently suspended" precondition for test
//       04 (E_BUSY) does not apply.
//
// Action
//   1. perfmon_stop(SLOT_INITIAL_EC)    — must return E_INVAL (test 03)
//   2. read field0/field1 from the post-call snapshot
//   3. sync(SLOT_INITIAL_EC)            — must return OK
//   4. read field0/field1 from the post-sync snapshot
//   5. assert the two snapshots agree on both fields
//
// Assertions
//   1: perfmon_stop on a target with no perfmon state did not return
//      E_INVAL (test 03 contract broken or some other error fired
//      first, leaving us off the test-06 path)
//   2: explicit sync after the failed call returned non-OK
//   3: field0 after perfmon_stop disagrees with field0 after sync —
//      the implicit-sync side effect did not refresh the holder's
//      snapshot to match the authoritative kernel state on the error
//      return path
//   4: field1 after perfmon_stop disagrees with field1 after sync —
//      same failure mode, observed on the affinity-mask half of the
//      EC handle's snapshot

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[perfmon_stop] test 03: target EC has no perfmon state, so
    // the spec mandates E_INVAL. SLOT_INITIAL_EC is the calling EC
    // and the runner never calls perfmon_start on it, so this is the
    // canonical "not started" condition.
    const stop_result = syscall.perfmonStop(caps.SLOT_INITIAL_EC);
    if (stop_result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Snapshot of field0/field1 after perfmon_stop's implicit-sync
    // side effect. The cap table is read-only mapped, so this read
    // observes whatever the kernel wrote (or chose not to write)
    // during the failed perfmon_stop call.
    const post_stop = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);

    // Force an explicit refresh of the same handle's snapshot from
    // the authoritative kernel state. §[sync] test 03 guarantees the
    // post-call snapshot matches the kernel's authoritative state.
    const sync_result = syscall.sync(caps.SLOT_INITIAL_EC);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const post_sync = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);

    // The implicit-sync side effect of perfmon_stop must have left
    // the snapshot equal to what an explicit sync produces. If the
    // kernel skipped the refresh on the error path (or actively
    // clobbered the fields), post_stop and post_sync diverge on at
    // least one of field0/field1.
    if (post_stop.field0 != post_sync.field0) {
        testing.fail(3);
        return;
    }
    if (post_stop.field1 != post_sync.field1) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
