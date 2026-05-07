const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug = zag.utils.sync.debug;

const SrcLoc = debug.SrcLoc;

pub const SpinLock = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    class: [*:0]const u8 = "@unclassified",

    pub fn lock(self: *SpinLock, src: SrcLoc) void {
        self.lockOrdered(src, 0);
    }

    /// `lock` variant that tags the lockdep entry with a non-zero
    /// `ordered_group`. The tag opts out of two checks: same-class
    /// overlap (lockdep treats every instance in the same group as
    /// disjoint for the duration of the held window) and pair-edge
    /// cycle detection (lockdep skips registry-edge insertion when
    /// either side of the (held, acquiring) pair is ordered, so the
    /// ordered acquisition does not seed a phantom inverse cycle on
    /// some other path that legitimately holds the inverse pair).
    /// Mirrors `lockIrqSaveOrdered` for the non-IRQ-save case.
    /// Caller must enforce a fixed acquisition order across every
    /// instance sharing this group; otherwise the escape hides real
    /// AB-BA deadlocks.
    pub fn lockOrdered(self: *SpinLock, src: SrcLoc, ordered_group: u32) void {
        debug.acquire(self, self.class, ordered_group, src);
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        debug.release(self);
        std.debug.assert(self.state.load(.monotonic) == 1);
        self.state.store(0, .release);
    }

    pub fn lockIrqSave(self: *SpinLock, src: SrcLoc) u64 {
        const state = arch.cpu.saveAndDisableInterrupts();
        self.lock(src);
        return state;
    }

    /// `lockIrqSave` variant that tags the lockdep entry with a
    /// non-zero `ordered_group`. The tag opts out of two checks:
    /// same-class overlap, and pair-edge cycle detection (lockdep
    /// skips registry-edge insertion when either side of the
    /// (held, acquiring) pair is ordered). Caller must enforce a
    /// fixed acquisition order across every instance sharing this
    /// group; otherwise the escape hides real AB-BA deadlocks.
    pub fn lockIrqSaveOrdered(self: *SpinLock, src: SrcLoc, ordered_group: u32) u64 {
        const state = arch.cpu.saveAndDisableInterrupts();
        debug.acquire(self, self.class, ordered_group, src);
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        return state;
    }

    pub fn unlockIrqRestore(self: *SpinLock, state: u64) void {
        self.unlock();
        arch.cpu.restoreInterrupts(state);
    }
};

