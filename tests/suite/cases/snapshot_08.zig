// Spec §[restart_semantics] / §[snapshot]: parent-observed snapshot_missing case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_missing, cap_table_base);
}
