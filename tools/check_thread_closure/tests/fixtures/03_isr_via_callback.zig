// EXPECT: entries=1 sources=1 async_sources=1
//
// The generic-callback hole. `forEachAlive` is a monomorphized generic, so
// no IR edge reaches the visitor; the analyzer must jump the gap on the
// address-taken function reference `wakeVisitor` instead. Without the
// syn-ref overlay this fixture reports sources=0.
const interrupts = @import("interrupts.zig");
const propagate = @import("../../sched/propagate.zig");

fn wheelHandler(ctx: *u64) void {
    _ = ctx;
    propagate.propagateAndWake();
}

pub fn ecPath() void {}

pub fn init() void {
    interrupts.registerVector(0x22, wheelHandler, .external);
}
