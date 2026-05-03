// Spec §[time] time_setwall — test 05.
//
// "[test 05] on success, a subsequent `time_getwall` returns a value
//  within a small bounded delta of [1]."
//
// Strategy
//   §[time_setwall] requires the caller's self-handle to hold the
//   `setwall` cap (test 03). The runner grants `setwall = true` on
//   each child's self-handle, so this test can call `time_setwall`
//   directly on its own self-handle without any setup.
//
//   Pick a fixed nanoseconds-since-epoch value `X` that is not zero
//   and is reasonable (a recent Unix-epoch ns). Call `time_setwall(X)`
//   and verify it returns success (vreg 1 == 0). Then immediately call
//   `time_getwall` and verify the returned value `Y` lies in
//   `[X, X + DELTA_NS]`, where `DELTA_NS` is a generous upper bound
//   for the elapsed wall-clock time between the two syscalls. Wall
//   time advances monotonically with monotonic time on a healthy
//   kernel, so `Y < X` would imply the kernel either failed to apply
//   the new wall-clock or rolled back. `Y > X + DELTA_NS` would imply
//   the set value was ignored or off by a large constant.
//
//   `DELTA_NS` is set to 1 second (1e9 ns) — orders of magnitude
//   larger than any realistic syscall round-trip on the test rig
//   (microseconds at most), but small enough that "off by hours/days"
//   bugs (e.g., the kernel applying a unit conversion, or treating
//   the input as something other than ns) are detected.
//
// Action
//   1. time_setwall(X)              — must return success (vreg1 = 0)
//   2. time_getwall()               — must return Y with X <= Y <= X + DELTA_NS
//
// Assertions
//   1: time_setwall returned a nonzero error code
//   2: time_getwall returned Y < X (rolled backwards)
//   3: time_getwall returned Y > X + DELTA_NS (set value not applied)

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 2026-01-01T00:00:00Z in nanoseconds since the Unix epoch. The
    // exact value is not load-bearing — any nonzero, well-formed
    // ns_since_epoch works for the spec assertion.
    const x: u64 = 1_767_225_600_000_000_000;

    const set_result = syscall.timeSetwall(x);
    if (errors.isError(set_result.v1)) {
        testing.fail(1);
        return;
    }

    const get_result = syscall.timeGetwall();
    const y: u64 = get_result.v1;

    if (y < x) {
        testing.fail(2);
        return;
    }

    const delta_ns: u64 = 1_000_000_000; // 1 second
    if (y - x > delta_ns) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
