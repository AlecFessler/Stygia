// Spec §[snapshot] test 09: a 2 MiB PF source copies into 512 4 KiB pages.
pub fn main(cap_table_base: u64) void {
    @import("vmar_restart_observer.zig").run(.snapshot_mixed_page_sizes, cap_table_base);
}
