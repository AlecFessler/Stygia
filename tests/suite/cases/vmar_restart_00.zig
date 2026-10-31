// Spec §[restart_semantics] / §[snapshot]: parent-observed free case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.free, cap_table_base);
}
