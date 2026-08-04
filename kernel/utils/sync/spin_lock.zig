const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const debug = stygia.utils.sync.debug;

const SrcLoc = debug.SrcLoc;


/// Bounded spin: a deadlocked core names its own lock instead of hanging
/// silently until the watchdog resets the board. Every SMP wedge found so
/// far has been invisible — no panic, no `[HANG]` dump — because all cores
/// spin with IRQs masked, so no IRQ-driven detector can fire. A spinning
/// core CAN still drive the polled UART, so the report comes from here.
///
/// This is load-bearing for debuggability, not scaffolding: it converted a
/// wedge that had survived four blind hardware cycles into a named
/// holder/waiter graph in a single run (stygia-9yp). The bound is far above
/// any legitimate hold time, so the fast path cost is one predictable
/// branch. See `debug.reportStuckLock` / `debug.dumpWaitTableRaw`.
fn spinAcquire(self: *SpinLock, src: SrcLoc) void {
    // Fast path: an uncontended acquire publishes nothing, so the
    // wait table stays a pure record of cores that are actually stuck.
    if (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) == null) return;

    debug.publishWaiting(self, self.class, src);
    defer debug.clearWaiting();

    var iters: u64 = 0;
    while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        // Ack-while-spinning (stygia-rs6 mechanism 9).
        arch.paging.serviceTlbMaintenanceWhileSpinning();
        std.atomic.spinLoopHint();
        iters +%= 1;
        if (iters == debug.SPIN_PANIC_ITERS) {
            debug.reportStuckLock(self, self.class, self.state.load(.monotonic), src);
        }
    }
}

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
        spinAcquire(self, src);
    }

    /// Single non-blocking acquisition attempt; registers with
    /// lockdep only on success. For contenders that must stay
    /// responsive while waiting — e.g. an IRQs-masked path spinning
    /// on `shootdown_lock` must service pending TLB sync arms between
    /// attempts, or the current holder's `waitForShootdownAcks` can
    /// be waiting on THIS core's ack (deadlock observed live,
    /// stygia-rs6; see arch/x64/paging.zig
    /// `lockShootdownServicingArms`).
    pub fn tryLock(self: *SpinLock, src: SrcLoc) bool {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
            debug.acquire(self, self.class, 0, src);
            return true;
        }
        return false;
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
        spinAcquire(self, src);
        return state;
    }

    pub fn unlockIrqRestore(self: *SpinLock, state: u64) void {
        self.unlock();
        arch.cpu.restoreInterrupts(state);
    }
};

