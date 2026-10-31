// §[restart_semantics]: device_region policy drop across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.device_region, false, base);
}
