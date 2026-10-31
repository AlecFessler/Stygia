// EXPECT: entries=1 sources=1 async_sources=0
//
// A synchronous `.exception` vector reaching a wake. It is a wake source,
// but not an *asynchronous* one — it runs in the faulting thread's own context.
// This is the distinction that keeps aarch64's SVC path from being counted
// as an interrupt-context wake.
const interrupts = @import("interrupts.zig");
const expiry = @import("../../sched/expiry.zig");

fn faultHandler(ctx: *u64) void {
    _ = ctx;
    expiry.expireDeadlines();
}

pub fn ecPath() void {}

pub fn init() void {
    interrupts.registerVector(0x0e, faultHandler, .exception);
}
