// EXPECT: classes=1 plain_thread_classes=0 mixed_classes=0 unresolved=0
//
// One declared class, IRQ-masked at every acquire, reached from thread context.
const interrupts = @import("interrupts.zig");
const sync = @import("../../utils/sync/spin_lock.zig");
const SpinLock = sync.SpinLock;

var table_lock: SpinLock = .{ .class = "fixture.table_lock" };
var value: u64 = 0;

pub fn ecPath() void {
    const irq = table_lock.lockIrqSave(0);
    value += 1;
    table_lock.unlockIrqRestore(irq);
}

fn noopHandler(ctx: *u64) void {
    _ = ctx;
}

pub fn init() void {
    interrupts.registerVector(0x23, noopHandler, .external);
}
