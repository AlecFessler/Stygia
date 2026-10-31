// §[restart_semantics]: virtual_machine policy keep across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.virtual_machine, true, base);
}
