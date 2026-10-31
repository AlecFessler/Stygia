// Observer for §[snapshot] test 09: one two-page PF mapping must copy both pages.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_multi_page_pf, cap_table_base);
}
