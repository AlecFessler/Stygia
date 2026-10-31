// §[restart_semantics]: reply_policy keep across a child fault.
pub fn main(base: u64) void {
    @import("reply_restart_observer.zig").run(true, base);
}
