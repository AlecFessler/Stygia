// EXPECT: entries=1 sources=1 async_sources=1
//
// ISR → generic helper → tryClaimWake. The wake source is the helper (the
// first non-arch/ function on the path), not the handler.
const interrupts = @import("interrupts.zig");
const expiry = @import("../../sched/expiry.zig");

fn timerHandler(ctx: *u64) void {
    _ = ctx;
    expiry.expireDeadlines();
}

pub fn ecPath() void {}

pub fn init() void {
    interrupts.registerVector(0x21, timerHandler, .external);
}
