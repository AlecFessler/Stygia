// Sidecar for 16_irq_only_path_exempt — materialized at
// `kernel/arch/x64/16_irq_only_path_exempt_aux.zig`. Not a fixture.

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

var irq_only_lock: SpinLock = .{};

// Deliberately NOT called from anything the syscall fixture reaches:
// `myIrqOnlyHandler` is its only caller, so every execution of this
// plain `lock()` already has interrupts masked by the CPU.
fn irqOnlyHelper() void {
    irq_only_lock.lock(.{});
    defer irq_only_lock.unlock();
}

pub fn myIrqOnlyHandler() void {
    irqOnlyHelper();
}

pub fn wireIrqOnlyVectors() void {
    interrupts.registerVector(0x21, myIrqOnlyHandler, .external);
}
