// EXPECT: classes=1 plain_thread_classes=0 unresolved=0
//
// Per-core lock arrays are never acquired through their declared name —
// always through `const l = &locks[i]` or a `for (&locks) |*l|` capture.
// Both alias forms must resolve, or the acquires vanish into UNRESOLVED
// and the class silently reads as clean.
const interrupts = @import("interrupts.zig");
const sync = @import("../../utils/sync/spin_lock.zig");
const SpinLock = sync.SpinLock;

pub var core_locks: [4]SpinLock = [_]SpinLock{.{ .class = "fixture.core_lock" }} ** 4;
var value: u64 = 0;

pub fn ecPath() void {
    const lock = &core_locks[1];
    const irq = lock.lockIrqSave(0);
    value += 1;
    lock.unlockIrqRestore(irq);

    for (&core_locks) |*l| {
        const s = l.lockIrqSave(0);
        l.unlockIrqRestore(s);
    }
}

fn noopHandler(ctx: *u64) void {
    _ = ctx;
}

pub fn init() void {
    interrupts.registerVector(0x26, noopHandler, .external);
}
