// Spec §[restart_semantics] / §[snapshot]: parent-observed snapshot_demand_write case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_demand_write, cap_table_base);
}
