// EXPECT: classes=1 plain_ec_classes=0 unresolved=0
//
// A plain acquire that only IRQ-context code reaches. IRQs are already off
// by hardware there, so it is not an EC-context preemption hazard and must
// not be reported as one.
const interrupts = @import("interrupts.zig");
const sync = @import("../../utils/sync/spin_lock.zig");
const SpinLock = sync.SpinLock;

var isr_lock: SpinLock = .{ .class = "fixture.isr_lock" };
var value: u64 = 0;

fn isrOnly() void {
    isr_lock.lock(0);
    value += 1;
    isr_lock.unlock();
}

fn irqHandler(ctx: *u64) void {
    _ = ctx;
    isrOnly();
}

pub fn ecPath() void {}

pub fn init() void {
    interrupts.registerVector(0x25, irqHandler, .external);
}
