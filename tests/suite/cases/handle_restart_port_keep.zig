// §[restart_semantics]: port policy keep across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.port, true, base);
}
