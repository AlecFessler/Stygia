// EXPECT: errors=1
// Mutating `_gen_lock.word` from outside `GenLock`'s own methods is
// forbidden by the proof's TSO action grammar (see assumption A4 in
// `slab_proof/SlabProof.lean`). The analyzer flags every
// `<chain>._gen_lock.word.<mut>(...)` site outside
// `kernel/memory/allocators/secure_slab.zig`.

const std = @import("std");

pub const GenLock = extern struct {
    word: std.atomic.Value(u64) align(8) = .{ .raw = 0 },
};

pub const Foo = extern struct {
    _gen_lock: GenLock = .{},
    value: u64 = 0,
};

pub fn forbiddenStore(ptr: *Foo) void {
    // <- flagged: only `GenLock.setGenRelease` may issue this store.
    ptr._gen_lock.word.store(0x42, .release);
}
