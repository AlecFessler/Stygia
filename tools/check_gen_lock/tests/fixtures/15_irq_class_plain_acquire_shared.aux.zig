// Sidecar for 15_irq_class_plain_acquire_shared — materialized at
// `kernel/arch/x64/15_irq_class_plain_acquire_shared_aux.zig`, outside
// the syscall-entry fallback's reach. Not a fixture itself.

const SrcLoc = struct { line: u32 = 0 };

pub const SpinLock = struct {
    state: u32 = 0,

    pub fn lock(self: *SpinLock, src: SrcLoc) void {
        _ = self;
        _ = src;
    }
    pub fn unlock(self: *SpinLock) void {
        _ = self;
    }
    pub fn lockIrqSave(self: *SpinLock, src: SrcLoc) u64 {
        _ = self;
        _ = src;
        return 0;
    }
    pub fn unlockIrqRestore(self: *SpinLock, prior: u64) void {
        _ = self;
        _ = prior;
    }
};

const interrupts = struct {
    pub const VectorKind = enum { external, exception };
    pub fn registerVector(vec: u8, handler: *const fn () void, kind: VectorKind) void {
        _ = vec;
        _ = handler;
        _ = kind;
    }
};

var shared_lock: SpinLock = .{};

// Reachable from BOTH `myTimerHandler` (an interrupt entry) and
// `sysDoThing` (a syscall entry), and takes the lock plainly.
pub fn touchShared() void {
    shared_lock.lock(.{});
    defer shared_lock.unlock();
}

pub fn myTimerHandler() void {
    touchShared();
}

pub fn wireVectors() void {
    interrupts.registerVector(0x20, myTimerHandler, .external);
}
