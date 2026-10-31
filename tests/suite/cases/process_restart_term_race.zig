// Concurrent foreign terminate and child fault; accepts only the observed winner.
pub fn main(cap_table_base: u64) void {
    @import("terminate_restart_observer.zig").runRace(cap_table_base);
}
