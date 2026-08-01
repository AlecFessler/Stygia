// EXPECT: clean
// The `catch`/`orelse` branch attached to an acquire is the acquire-
// FAILED path: the lock was never taken, so returning from it is not a
// leak (and releasing there would be a bug — an unlock of a lock we
// never held). `GenLock.lockWithGenIrqSaveOrdered` restores interrupts
// and returns `error.StaleHandle` without holding the lock.
//
// Real-kernel shape: `pmiHandler` in arch/x64/intel/pmu.zig and
// arch/x64/amd/pmu.zig, whose `catch` bodies run the defensive PMU
// cleanup and then `return;`.

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn SlabRef(comptime T: type) type {
    return extern struct {
        ptr: *T,
        gen: u64 = 0,
        pub fn lock(_: @This()) ?*T { return null; }
        pub fn lockIrqSave(_: @This(), _: anytype) error{StaleHandle}!*T { return error.StaleHandle; }
        pub fn unlock(_: @This()) void {}
        pub fn unlockIrqRestore(_: @This()) void {}
    };
}

// Multi-line `catch` block ending in `return` — the pmiHandler shape.
pub fn sysCatchBlockReturn(ref: SlabRef(Foo), cond: u64) i64 {
    const p = ref.lockIrqSave(@src()) catch {
        // Acquire failed: nothing is held on this path.
        if (cond != 0) return -3;
        return -2;
    };
    _ = p;
    ref.unlockIrqRestore();
    return 0;
}

// `catch |e|` payload capture form.
pub fn sysCatchPayloadReturn(ref: SlabRef(Foo)) i64 {
    const p = ref.lockIrqSave(@src()) catch |e| {
        _ = e;
        return -2;
    };
    _ = p;
    ref.unlockIrqRestore();
    return 0;
}

// Same rule for a multi-line `orelse` failure branch.
pub fn sysOrelseBlockReturn(ref: SlabRef(Foo)) i64 {
    const p = ref.lock() orelse {
        return -2;
    };
    _ = p;
    ref.unlock();
    return 0;
}
