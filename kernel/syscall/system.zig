const stygia = @import("stygia");

const time = stygia.arch.dispatch.time;

/// Returns nanoseconds since boot.
///
/// ```
/// time_monotonic() -> [1] ns
///   syscall_num = 46
/// ```
///
/// No cap required.
///
/// [test 01] on success, [1] is a u64 nanosecond count strictly greater than the value returned by any prior call to `time_monotonic`.
pub fn timeMonotonic(caller: *anyopaque) i64 {
    _ = caller;
    return @bitCast(time.currentMonotonicNs());
}
