// §[restart_semantics]: policy 1 re-enters when reply races restart.
pub fn main(cap_table_base: u64) void {
    @import("thread_restart_policy.zig").runReplyRace(cap_table_base);
}
