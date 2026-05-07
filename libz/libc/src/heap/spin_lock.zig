// Userspace single-threaded spinlock shim for libc. libc is built
// single_threaded; the heap allocator's lock-acquire/release calls
// reduce to no-ops. Multi-threaded libc would swap this for a real
// atomic test-and-set without changing the heap allocator API.

const std = @import("std");

pub const SpinLock = struct {
    pub fn lock(_: *SpinLock) void {}
    pub fn unlock(_: *SpinLock) void {}
};
