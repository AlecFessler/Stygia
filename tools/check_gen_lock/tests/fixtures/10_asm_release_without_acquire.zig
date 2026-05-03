// EXPECT: errors=1
// Fully-naked-asm fn that releases Foo._gen_lock without ever acquiring
// it. Analyzer should flag the dangling release.

const std = @import("std");

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn asmStrayRelease() callconv(.naked) void {
    asm volatile (std.fmt.comptimePrint(
            \\andq $-2, {[lock_off]d}(%%rcx)
            \\ret
            \\
        ,
            .{ .lock_off = @offsetOf(Foo, "_gen_lock") },
        ));
}
