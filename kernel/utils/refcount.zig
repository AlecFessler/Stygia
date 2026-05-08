//! Atomic refcount with a sticky observed-zero marker.
//!
//! The counter is a 32-bit signed word. Bit 31 is reserved as a sticky
//! "observed zero" marker:
//!
//!     state             | binary                              | i32
//!     ------------------|-------------------------------------|-----------
//!     unacquired        | 0000_0000_0000_0000_0000_0000_0000_0000 |  0
//!     count == N (>0)   | 0000_0000_0000_0000_0000_0000_0000_NNNN |  N
//!     dead              | 1000_0000_0000_0000_0000_0000_0000_0000 |  INT_MIN
//!
//! `dec` that transitions 1 → 0 atomically writes `Sticky` (sign bit set,
//! magnitude bits zero — the `signed -0` pattern) instead of plain zero.
//! `inc` checks the sign bit before bumping; an inc that observes Sticky
//! FAILS — the caller raced a freeing dec and must not proceed as if it
//! holds a reference.
//!
//! This protects the canonical handle-table race:
//!
//!     T_drop:  observed last ref, dec → Sticky, beginning destroy
//!     T_lookup: SlabRef chase, finds the object, calls inc
//!
//! Without the marker T_lookup's inc could resurrect a doomed object.
//! With it, T_lookup's inc returns `.observed_zero`, the caller treats
//! it as E_BADCAP / stale, and the destroy-owner runs cleanup unraced.
//!
//! Used wherever the spec says "refcount lifetime" — Port, PageFrame,
//! DeviceRegion, Timer.

const std = @import("std");

pub const Refcount = extern struct {
    raw: i32 = 0,

    /// Sign bit set, magnitude zero. `dec` writes this in place of
    /// plain 0 on the last decrement.
    pub const Sticky: i32 = std.math.minInt(i32);

    pub const IncResult = enum {
        /// Reference acquired; count incremented.
        ok,
        /// A concurrent `dec` already set Sticky. Caller did NOT
        /// acquire a reference and MUST NOT proceed as if it had.
        observed_zero,
    };

    pub const DecResult = enum {
        /// Decremented; count is still positive.
        nonzero,
        /// Transitioned 1 → Sticky. Caller owns destruction. Returned
        /// exactly once across all concurrent decrementers.
        observed_zero,
    };

    /// Bump the count by 1 via a single fetch-add, then check the
    /// sign bit on the pre-increment value. If `prev < 0` a concurrent
    /// `dec` already set Sticky — our add perturbed the magnitude but
    /// the sign bit stays set, and any further inc/dec on this counter
    /// will also observe Sticky. The caller must NOT proceed as if it
    /// holds a reference. (At 2^31 racing inc-after-dead the magnitude
    /// would wrap back to a non-Sticky value; unreachable in practice
    /// for kernel objects.)
    pub fn inc(self: *Refcount) IncResult {
        const prev = @atomicRmw(i32, &self.raw, .Add, 1, .acq_rel);
        return if (prev < 0) .observed_zero else .ok;
    }

    /// Drop one reference. The thread that transitions 1 → Sticky
    /// receives `.observed_zero` exactly once and owns destruction.
    /// All other decrementers see `.nonzero`. dec on a dead or
    /// already-zero count is a programming error.
    pub fn dec(self: *Refcount) DecResult {
        var cur = @atomicLoad(i32, &self.raw, .acquire);
        while (true) {
            std.debug.assert(cur > 0);
            const next = if (cur == 1) Sticky else cur - 1;
            const cas_res = @cmpxchgWeak(i32, &self.raw, cur, next, .acq_rel, .acquire);
            if (cas_res == null) {
                return if (cur == 1) .observed_zero else .nonzero;
            }
            cur = cas_res.?;
        }
    }

    /// True iff Sticky has been set on this counter.
    pub fn isDead(self: *const Refcount) bool {
        return @atomicLoad(i32, @constCast(&self.raw), .acquire) < 0;
    }

    /// Snapshot of the live count. Returns 0 if dead. Snapshot may be
    /// stale by the time the caller reads it — only useful for
    /// invariant assertions and diagnostics, not for branching.
    pub fn snapshot(self: *const Refcount) u31 {
        const v = @atomicLoad(i32, @constCast(&self.raw), .acquire);
        if (v < 0) return 0;
        return @intCast(v);
    }
};

test "Refcount: fresh" {
    var rc: Refcount = .{};
    try std.testing.expect(!rc.isDead());
    try std.testing.expectEqual(@as(u31, 0), rc.snapshot());
}

test "Refcount: inc from zero" {
    var rc: Refcount = .{};
    try std.testing.expectEqual(Refcount.IncResult.ok, rc.inc());
    try std.testing.expectEqual(@as(u31, 1), rc.snapshot());
    try std.testing.expect(!rc.isDead());
}

test "Refcount: dec last ref sets Sticky" {
    var rc: Refcount = .{};
    _ = rc.inc();
    try std.testing.expectEqual(Refcount.DecResult.observed_zero, rc.dec());
    try std.testing.expect(rc.isDead());
    try std.testing.expectEqual(@as(u31, 0), rc.snapshot());
    try std.testing.expectEqual(Refcount.Sticky, rc.raw);
}

test "Refcount: inc after dead returns observed_zero" {
    var rc: Refcount = .{};
    _ = rc.inc();
    _ = rc.dec();
    try std.testing.expectEqual(Refcount.IncResult.observed_zero, rc.inc());
    try std.testing.expect(rc.isDead());
}

test "Refcount: middle decs are nonzero, last is observed_zero" {
    var rc: Refcount = .{};
    try std.testing.expectEqual(Refcount.IncResult.ok, rc.inc());
    try std.testing.expectEqual(Refcount.IncResult.ok, rc.inc());
    try std.testing.expectEqual(Refcount.IncResult.ok, rc.inc());
    try std.testing.expectEqual(@as(u31, 3), rc.snapshot());
    try std.testing.expectEqual(Refcount.DecResult.nonzero, rc.dec());
    try std.testing.expectEqual(Refcount.DecResult.nonzero, rc.dec());
    try std.testing.expectEqual(Refcount.DecResult.observed_zero, rc.dec());
    try std.testing.expect(rc.isDead());
}

test "Refcount: only one dec returns observed_zero across many inc/dec" {
    var rc: Refcount = .{};
    var i: u32 = 0;
    while (i < 100) : (i += 1) _ = rc.inc();
    try std.testing.expectEqual(@as(u31, 100), rc.snapshot());

    var observed_zeros: u32 = 0;
    i = 0;
    while (i < 100) : (i += 1) {
        switch (rc.dec()) {
            .observed_zero => observed_zeros += 1,
            .nonzero => {},
        }
    }
    try std.testing.expectEqual(@as(u32, 1), observed_zeros);
}
