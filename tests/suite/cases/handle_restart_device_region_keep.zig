// §[restart_semantics]: device_region policy keep across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.device_region, true, base);
}
