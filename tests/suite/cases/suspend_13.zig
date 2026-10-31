// Spec §[suspend] test 13: termination wins before a suspension attempt.
// A terminated thread handle must return E_TERM on the first suspend,
// and that call must remove the stale handle. The second use therefore
// returns E_BADCAP. The target has all caps needed for a live suspend.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const port_caps = caps.PortCap{ .recv = true, .bind = true, .@"suspend" = true };
    const port_result = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(port_result.v1)) return testing.fail(1);
    const port_handle: caps.HandleId = @truncate(port_result.v1 & 0xFFF);

    const thread_caps = caps.ThreadCap{ .term = true, .susp = true };
    const thread_result = syscall.createThread(
        @as(u64, thread_caps.toU16()),
        @intFromPtr(&testing.dummyEntry),
        1,
        0,
        0,
    );
    if (testing.isHandleError(thread_result.v1)) return testing.fail(2);
    const thread_handle: caps.HandleId = @truncate(thread_result.v1 & 0xFFF);

    if (syscall.terminate(thread_handle).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(3);
    if (syscall.suspendThread(thread_handle, port_handle, &.{}).v1 != @intFromEnum(errors.Error.E_TERM)) return testing.fail(4);
    if (syscall.suspendThread(thread_handle, port_handle, &.{}).v1 != @intFromEnum(errors.Error.E_BADCAP)) return testing.fail(5);

    testing.pass();
}
