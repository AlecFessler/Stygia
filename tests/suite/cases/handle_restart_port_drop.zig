// §[restart_semantics]: port policy drop across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.port, false, base);
}
