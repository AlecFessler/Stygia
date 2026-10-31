// Spec §[restart_semantics] / §[snapshot]: parent-observed snapshot_replace case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_replace, cap_table_base);
}
