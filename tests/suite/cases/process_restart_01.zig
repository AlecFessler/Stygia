// §[restart_semantics]: an unhandled user fault restarts a process whose
// self-handle carries restart, and its restart_at_entry worker re-enters.
pub fn main(cap_table_base: u64) void {
    @import("restart_observer.zig").run(.fault, cap_table_base);
}
