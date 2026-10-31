// §[restart_semantics]: voluntary delete(SLOT_SELF) restarts a process
// whose self-handle carries restart, and its restart_at_entry worker re-enters.
pub fn main(cap_table_base: u64) void {
    @import("restart_observer.zig").run(.self_delete, cap_table_base);
}
