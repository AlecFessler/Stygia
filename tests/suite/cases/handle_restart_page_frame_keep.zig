// §[restart_semantics]: page_frame policy keep across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.page_frame, true, base);
}
