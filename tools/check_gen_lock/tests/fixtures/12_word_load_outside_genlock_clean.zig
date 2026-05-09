// EXPECT: clean
// Reads of `_gen_lock.word` (non-mutating `.load`) outside `GenLock`'s
// own methods are allowed — the proof's TSO model is concerned only
// with WRITES to the gen-lock word. `currentGen()`-equivalent reads
// are unflagged.

const std = @import("std");

pub const GenLock = extern struct {
    word: std.atomic.Value(u64) align(8) = .{ .raw = 0 },
};

pub const Foo = extern struct {
    _gen_lock: GenLock = .{},
    value: u64 = 0,
};

pub fn snapshotGen(ptr: *const Foo) u64 {
    return ptr._gen_lock.word.load(.monotonic) >> 1;
}
