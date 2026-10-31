// §[restart_semantics]: virtual_machine policy drop across process restart.
pub fn main(base: u64) void {
    @import("handle_restart_observer.zig").run(.virtual_machine, false, base);
}
