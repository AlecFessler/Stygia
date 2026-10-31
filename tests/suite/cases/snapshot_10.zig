// Spec §[restart_semantics] / §[snapshot]: parent-observed snapshot_pf_write case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_pf_write, cap_table_base);
}
