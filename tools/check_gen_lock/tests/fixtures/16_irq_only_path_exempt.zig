// EXPECT: clean
// The other half of the rule-(a) contract: an acquire that really IS
// only reachable from a masked-on-entry interrupt stays exempt.
//
// The sidecar's `irqOnlyHelper` is called from `myIrqOnlyHandler` and
// from nothing else — no syscall entry here reaches it — so the CPU has
// already masked interrupts by the time its plain `lock()` runs and
// there is nothing to save. Tightening rule (a) from "reachable from an
// IRQ" to "ONLY reachable from an IRQ" must not turn this into a
// finding; if it does, the check was made strict rather than correct.
//
// Paired with fixture 15, which shares the identical shape except that
// a syscall entry also reaches the helper.

const slab = @import("../slab.zig");

pub fn sysUnrelated(caller: *anyopaque) u64 {
    _ = caller;
    return 0;
}

pub fn unusedSlabRef2(f: *slab.Foo) u64 {
    return f.value;
}
