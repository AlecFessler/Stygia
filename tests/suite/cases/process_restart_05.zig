// §[restart_semantics]: policy 2 preserves blocked frame and stack.
pub fn main(cap_table_base: u64) void {
    @import("thread_restart_policy.zig").run(.persist, cap_table_base);
}
