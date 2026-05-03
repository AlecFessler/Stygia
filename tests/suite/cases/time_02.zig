// Spec §[time] time_getwall — test 02.
//
// "[test 02] after `time_setwall(X)` succeeds, a subsequent
//  `time_getwall` returns a value within a small bounded delta of X."
//
// Strategy
//   The wall-clock pair is observable as a round-trip: `time_setwall`
//   moves the kernel's wall-time origin to a caller-chosen value X
//   (nanoseconds since the Unix epoch); the very next `time_getwall`
//   must observe that value, modulo the small amount of real time
//   that elapses between the two syscalls returning. The spec bounds
//   the residue as "small" without pinning a number — anything below
//   a wall-clock second is comfortably above any plausible
//   QEMU-induced jitter while remaining tight enough to catch a
//   broken set/get pair (e.g., a write that drops nanosecond bits or
//   a read that returns the unmodified prior value).
//
//   `time_setwall` requires the `setwall` cap on the caller's
//   self-handle. The test runner grants `setwall = true` in
//   `child_self` (see runner/primary.zig spawnOne). `time_getwall`
//   takes no caps. X is chosen to be a recognizable epoch nanosecond
//   value distinct from any plausible default ("now-ish"): mid-2025
//   in ns. Picking a future value also avoids ambiguity if the
//   getwall return were to predate the setwall call due to a buggy
//   write.
//
// Action
//   1. ret = time_setwall(X)
//   2. now = time_getwall()
//
// Assertions
//   1: time_setwall returned a non-zero value (it should signal
//      success with vreg1 = OK = 0 per §[error_codes]).
//   2: time_getwall returned a value below X (the wall clock did not
//      observe the just-written value at all, so the read is stale).
//   3: time_getwall returned a value more than 1 second beyond X
//      (the kernel either stored a wrong value or the clock
//      advanced impossibly far between two back-to-back syscalls).

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Mid-2025 in nanoseconds since the Unix epoch:
// 2025-07-01 00:00:00 UTC = 1_751_328_000 seconds since epoch.
const X_NS: u64 = 1_751_328_000 * 1_000_000_000;

// Bounded delta the spec describes as "small". One wall-clock second
// is generous enough to absorb scheduler/QEMU jitter between the two
// back-to-back syscalls and tight enough to catch a broken set/get
// pair.
const DELTA_NS: u64 = 1_000_000_000;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const set_result = syscall.timeSetwall(X_NS);
    if (set_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const got = syscall.timeGetwall();

    if (got.v1 < X_NS) {
        testing.fail(2);
        return;
    }
    if (got.v1 - X_NS > DELTA_NS) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
