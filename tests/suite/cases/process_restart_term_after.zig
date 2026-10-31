// Restart relaunches the worker before the foreign terminate attempts it.
pub fn main(cap_table_base: u64) void {
    @import("terminate_restart_observer.zig").run(false, cap_table_base);
}
