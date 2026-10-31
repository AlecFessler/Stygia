// §[restart_semantics]: policy 0 kills a suspended worker after restart.
pub fn main(cap_table_base: u64) void {
    @import("thread_restart_policy.zig").run(.kill, cap_table_base);
}
