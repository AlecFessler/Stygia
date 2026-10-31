// §[restart_semantics]: policy 1 resets a suspended worker to its entry.
pub fn main(cap_table_base: u64) void {
    @import("thread_restart_policy.zig").run(.restart_at_entry, cap_table_base);
}
