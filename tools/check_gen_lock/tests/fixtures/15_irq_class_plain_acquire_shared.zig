// EXPECT: errors=1
// Regression test for the escape hatch that made check 6 vacuous.
//
// The lock, the shared helper and the interrupt handler live in this
// fixture's `.aux.zig` sidecar (under `arch/x64/`, so the indexer's
// no-IR syscall-entry fallback cannot claim the handler). Here we only
// supply the PROCESS-CONTEXT reach: `sysDoThing` is a syscall entry and
// calls the same helper the timer handler calls.
//
// So `touchShared` is reachable from an interrupt entry AND from a
// syscall entry, and takes `shared_lock` with a plain `lock()`. A core
// holding it in syscall context with IRQs enabled can take the timer
// interrupt and spin forever on a lock its own core already holds —
// the exact shape of the live `stack.freelist_lock` defect.
//
// The pre-modernization analyzer reported nothing here, for two
// independent reasons: `myTimerHandler` was not one of the nine
// hardcoded `IRQ_ENTRY_DECLS` names, and rule (a) exempted any fn
// merely REACHABLE from an IRQ entry rather than only-reachable.

const slab = @import("../slab.zig");
const aux = @import("../arch/x64/15_irq_class_plain_acquire_shared_aux.zig");

pub fn sysDoThing(caller: *anyopaque) void {
    _ = caller;
    aux.touchShared();
}

pub fn unusedSlabRef(f: *slab.Foo) u64 {
    return f.value;
}
