// errno — global int + accessor.
//
// First-cut single-threaded: errno is a plain global. When we add
// real threading (kernel set_tls syscall or wrfsbase) errno moves
// into TLS and the global goes away. Until then __errno_location
// just returns its address.
//
// Errno values match Linux numerics — that's what the patched
// stdlib's lib/std/os/stygia.zig re-exports through `linux.E`, and
// what the libc-shaped consumers (LLVM, libc++) compare against.

var errno_storage: c_int = 0;

export fn __errno_location() callconv(.c) *c_int {
    return &errno_storage;
}
