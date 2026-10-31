// §[restart_semantics]: page_frame policy drop across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.page_frame, false, base);
}
