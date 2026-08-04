// EXPECT: errors=3
// The acquire-failure-branch exemption (fixture 13) must not blunt the
// leak detector. Each fn below leaks exactly one lock:
//
//   sysCatchThenLeak      — clean catch branch, then a genuine
//                           post-acquire early return holding the lock.
//   sysOtherLockAcrossCatch — a DIFFERENT lock is live across a second
//                           acquire's catch branch, and its `return`
//                           drops it on the floor.
//   sysCatchSwallowThenLeak — `catch {}` falls through, so the lock IS
//                           held afterwards; the later return leaks it.

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

pub fn sysCatchThenLeak(ref: SlabRef(Foo), cond: u64) i64 {
    const p = ref.lockIrqSave(@src()) catch {
        return -2; // not a leak: acquire failed
    };
    _ = p;
    if (cond != 0) return -1; // <- LEAK: held, no unlock, no defer
    ref.unlockIrqRestore();
    return 0;
}

pub fn sysOtherLockAcrossCatch(a: SlabRef(Foo), b: SlabRef(Foo)) i64 {
    _ = a.lock() orelse return -2;
    const p = b.lockIrqSave(@src()) catch {
        return -3; // <- LEAK: `b` was never taken, but `a` is held
    };
    _ = p;
    b.unlockIrqRestore();
    a.unlock();
    return 0;
}

pub fn sysCatchSwallowThenLeak(ref: SlabRef(Foo)) i64 {
    _ = ref.lockIrqSave(@src()) catch {
        // Swallowed: control falls through still holding the lock.
    };
    return -1; // <- LEAK: no unlock on this exit
}
