// Spec §[power] power_screen_off — test 06.
//
// "[test 06] returns E_PERM if the caller's self-handle lacks `power`."
//
// Strategy
//   `power_screen_off` is the §[power] section's fourth syscall
//   (syscall_num = 55) and, like every other `power_*` entry point,
//   gates on the caller's self-handle carrying the `power` cap. The
//   spec test for this syscall is a permission-only check: no [1]
//   handle arg, no parameters, no other failure paths to neutralize.
//
//   The runner (tests/suite/runner/primary.zig) deliberately withholds
//   `power` from `child_self` when constructing each test domain — see
//   the comment "`power` and `restart` are intentionally withheld so a
//   test can't shut the runner down or mask its own faults via
//   domain-restart fallback." The slot-0 self-handle visible to this
//   test therefore never has the `power` bit set, and the kernel must
//   reject the call with E_PERM before any side effect (turning the
//   primary display off) can occur.
//
// Action
//   power_screen_off()  — must return E_PERM.
//
// Assertion
//   1: power_screen_off returned something other than E_PERM.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const result = syscall.powerScreenOff();

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
