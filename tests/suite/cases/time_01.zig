// Spec §[time] time_monotonic — test 01.
//
// "[test 01] on success, [1] is a u64 nanosecond count strictly greater
//  than the value returned by any prior call to `time_monotonic`."
//
// Strategy
//   `time_monotonic` requires no caps and takes no inputs, so the
//   straightforward observable is: two back-to-back calls from the
//   same EC must return strictly increasing nanosecond values. The
//   second call necessarily executes after the first returns, so the
//   monotonic clock — which is required to advance — must report a
//   later instant.
//
//   No setup is needed. Both calls are issued directly from the test
//   EC; the syscall path itself takes well over 0 ns of work, and the
//   spec promises strict monotonicity rather than mere non-decrease.
//
// Action
//   1. t0 = time_monotonic()
//   2. t1 = time_monotonic()
//
// Assertions
//   1: the second call returned a value <= the first call (monotonic
//      clock failed to advance strictly between back-to-back calls).

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const first = syscall.timeMonotonic();
    const second = syscall.timeMonotonic();

    if (second.v1 <= first.v1) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
