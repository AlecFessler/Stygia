// Foreign terminate wins the worker before the child triggers restart.
pub fn main(cap_table_base: u64) void {
    @import("terminate_restart_observer.zig").run(true, cap_table_base);
}
