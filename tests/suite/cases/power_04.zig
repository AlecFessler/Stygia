// Spec §[power] / power_sleep — test 04.
//
// "[test 04] returns E_INVAL if [1] is not 1, 3, or 4."
//
// Strategy
//   The spec defines `[1] depth` as one of {1, 3, 4} (sleep / deep
//   sleep / hibernate). Any depth outside that set is structurally
//   out of range and must surface E_INVAL regardless of permissions.
//
//   The runner's primary intentionally withholds `power` from every
//   spawned test domain (see runner/primary.zig: `power` and `restart`
//   are not set on `child_self`) so a test can't put the suite to
//   sleep mid-run. We rely on the same convention priority_04 codified:
//   structural validation runs before rights validation, so a
//   spec-invalid depth surfaces E_INVAL rather than the E_PERM that
//   test 03 covers.
//
//   That ordering is the only reading consistent with both tests being
//   independently asserted: a kernel that returned E_PERM for an
//   out-of-range depth value would make test 04 untestable from any
//   caller that lacks `power`, which — given the runner contract — is
//   the only caller the suite can spawn. Conversely, a caller that
//   held `power` and passed an invalid depth must hit E_INVAL before
//   any platform action (such as actually sleeping) is taken.
//
//   We also read the self-handle caps to sanity-check that `power` is
//   still cleared. If the runner ever leaks `power` onto child_self,
//   an invalid-depth call is still spec-mandated to return E_INVAL
//   without performing a sleep — but the precondition for the test 04
//   isolation logic is the same as test 03's: a power-less caller
//   means E_INVAL is the only outcome the spec admits.
//
// Action
//   power_sleep(0) — must return E_INVAL.
//
//   0 is the smallest depth value strictly outside the spec's valid
//   set {1, 3, 4}, so the failure mode isn't masked by an unrelated
//   overflow or by the upper bound of any internal encoding the kernel
//   might use for the depth field.
//
// Assertion
//   1: power_sleep(depth = 0) returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const invalid_depth: u64 = 0;
    const result = syscall.powerSleep(invalid_depth);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
