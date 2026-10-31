// EXPECT: entries=1 sources=0 async_sources=0 claim_sites=0
//
// A registered async vector whose handler touches nothing wake-related.
// The seed must be discovered (entries=1) and the closure must stay empty.
const interrupts = @import("interrupts.zig");

var counter: u64 = 0;

fn spuriousHandler(ctx: *u64) void {
    _ = ctx;
    counter += 1;
}

pub fn ecPath() void {}

pub fn init() void {
    interrupts.registerVector(0x20, spuriousHandler, .external);
}
