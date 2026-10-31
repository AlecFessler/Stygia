// Spec §[restart_semantics] / §[snapshot]: parent-observed preserve case.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.preserve, cap_table_base);
}
