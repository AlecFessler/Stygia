const slab = @import("slab.zig");

pub const Ctx = struct { value: u64 = 0 };

pub var instance: slab.SecureSlab(Ctx, 256) = .{};

/// wheelExpireDue → onFire → propagateAndWake → [generic forEachAlive]
/// → visitor → wake. The middle hop is the one that used to be missing
/// from ir_call, which silently truncated every reachability query that
/// crossed a generic.
pub fn wheelExpireDue() void {
    onFire();
}

pub fn onFire() void {
    propagateAndWake();
}

pub fn propagateAndWake() void {
    instance.forEachAlive(undefined, visitor);
}

pub fn visitor(_: *anyopaque, _: *Ctx) bool {
    wake();
    return true;
}

pub fn wake() void {}
