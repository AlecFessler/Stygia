// Spec §[restart_semantics] / §[snapshot]: parent-observed snapshot_copy case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_copy, cap_table_base);
}
