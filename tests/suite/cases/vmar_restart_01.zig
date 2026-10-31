// Spec §[restart_semantics] / §[snapshot]: parent-observed decommit case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.decommit, cap_table_base);
}
