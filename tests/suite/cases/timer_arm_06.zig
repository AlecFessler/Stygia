// Spec §[timer_arm] — test 06.
//
// "[test 06] on success, [1].field0 = 0, [1].field1.arm = 1, and
//  [1].field1.pd = [3].periodic."
//
// Strategy
//   §[timer] field layout: field0 bits 0-63 carry the u64 counter.
//   field1 bit 0 is `arm`, bit 1 is `pd` (periodic). A successful
//   `timer_arm` returns a fresh timer handle whose snapshot must show
//   counter = 0, armed, and pd matching the caller's [3].periodic.
//
//   Use [3].periodic = 1 so the post-condition compare against
//   field1.pd is non-trivial (a kernel that hard-coded pd = 0 would
//   pass with periodic = 0 but fail here). Use a nonzero deadline_ns
//   to avoid test 03's E_INVAL gate. Set [1].caps = no bits (just a
//   plain handle; later tests cover restart_policy / arm / cancel
//   plumbing).
//
//   Neutralize every other failure path so test 06 is the only spec
//   assertion exercised:
//     - test 01 (E_PERM if self lacks `timer`): the runner grants
//       `timer = true` on the test domain's self-handle (see
//       runner/primary.zig: `child_self.timer = true`).
//     - test 02 (E_PERM if caps.restart_policy = 1 and the caller's
//       restart_policy_ceiling.tm_restart_max = 0): we leave
//       restart_policy = 0.
//     - test 03 (E_INVAL if deadline_ns = 0): we use a nonzero value.
//     - test 04 (E_INVAL if reserved bits set in [1] or [3]): only
//       low bits of caps and bit 0 of flags are set; everything else
//       is zero.
//
//   After the call, force a fresh kernel-authoritative snapshot via
//   `sync` before reading field0/field1. Per §[capabilities] the
//   syscall itself refreshes its own returned snapshot, but `sync`
//   is the explicit, spec-blessed refresh path.
//
// Action
//   1. timer_arm(caps = 0, deadline_ns = arbitrary nonzero,
//      flags = periodic=1)                          — must succeed
//   2. sync(timer_handle)                           — refresh snapshot
//   3. readCap(cap_table_base, timer_handle):
//        field0 == 0
//        field1 bit 0 (arm) == 1
//        field1 bit 1 (pd)  == 1
//
// Assertions
//   1: timer_arm returned an error code instead of a handle word.
//   2: sync returned non-OK.
//   3: post-sync field0 != 0 (counter pre-incremented or stale).
//   4: post-sync field1 bit 0 (arm) is not 1.
//   5: post-sync field1 bit 1 (pd) does not match requested periodic.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const ARM_BIT: u64 = 1 << 0;
const PD_BIT: u64 = 1 << 1;
const PERIODIC_FLAG: u64 = 1 << 0;

pub fn main(cap_table_base: u64) void {
    // Plain handle: no extra cap bits, restart_policy = 0 so test 02's
    // ceiling gate cannot fire.
    const timer_caps: u64 = 0;
    const deadline_ns: u64 = 1_000_000_000;
    const flags: u64 = PERIODIC_FLAG;

    const result = syscall.timerArm(timer_caps, deadline_ns, flags);
    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(result.v1 & 0xFFF);

    const sync_result = syscall.sync(timer_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, timer_handle);
    if (cap.field0 != 0) {
        testing.fail(3);
        return;
    }
    if ((cap.field1 & ARM_BIT) != ARM_BIT) {
        testing.fail(4);
        return;
    }
    if ((cap.field1 & PD_BIT) != PD_BIT) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
