// EXPECT: classes=1 plain_ec_classes=1 plain_ec_sites=1 mixed_classes=1 unresolved=0
//
// Same class acquired both ways. The plain acquire sits on a syscall-
// reachable path, so the class is preemptible while held.
const interrupts = @import("interrupts.zig");
const sync = @import("../../utils/sync/spin_lock.zig");
const SpinLock = sync.SpinLock;

var freelist_lock: SpinLock = .{ .class = "fixture.freelist_lock" };
var value: u64 = 0;

pub fn ecPath() void {
    freelist_lock.lock(0);
    value += 1;
    freelist_lock.unlock();
}

pub fn maskedPath() void {
    const irq = freelist_lock.lockIrqSave(0);
    value += 1;
    freelist_lock.unlockIrqRestore(irq);
}

fn noopHandler(ctx: *u64) void {
    _ = ctx;
    maskedPath();
}

pub fn init() void {
    interrupts.registerVector(0x24, noopHandler, .external);
}
